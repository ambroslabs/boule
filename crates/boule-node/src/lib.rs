pub mod admin_api;
pub mod consensus_node;
pub mod demo_staking;

#[cfg(feature = "reth")]
pub mod eth_public;
pub mod observability;
pub mod rotatable_signer;
pub mod rotation_handle;
pub mod testnet;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;

use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{info, warn};

use crate::consensus_node::{ConsensusNode, NodeConfigForConsensus};
use boule_consensus::replication::application::Application;
use boule_consensus::replication::impls::InMemoryMempool;
use boule_consensus::replication::mempool::Mempool;
use boule_consensus::status::ConsensusStatus;
use boule_consensus::validator_set::ValidatorSet;
use boule_core::clock::{Clock, TokioClock};
use boule_core::config::{
    ApplicationConfig, BlsIdentityConfig, Config, ConsensusConfig, OverlayConfig, OverlayMode,
};
use boule_core::crypto::signed::{NodeSigner, Signer};
use boule_core::identity::NodeIdentity;
use boule_core::identity::{NodeId, base58_to_node_id, node_id_to_base58};
use boule_core::storage::{DiskStorage, DiskWal, MemoryStorage, MemoryWal, Storage, Wal};
use boule_core::transport::overlay as overlay_traits;
use boule_core::transport::overlay::{Broadcaster, Discovery};

pub struct ApplicationContext {
    pub self_id: NodeId,

    pub genesis_state_commitment: [u8; 32],

    pub genesis_stake: Vec<([u8; 32], u64)>,

    pub mempool: Arc<dyn Mempool>,
}

pub type BoxFutureUnit = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>;

pub type ApplicationFactory = Box<
    dyn FnOnce(
            ApplicationContext,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = anyhow::Result<Arc<dyn Application>>> + Send>,
        > + Send,
>;

#[derive(Default)]
pub struct ApplicationOverride {
    pub factory: Option<ApplicationFactory>,

    pub shutdown: Option<BoxFutureUnit>,
}

pub async fn run(
    config: Config,
    network_identity: NodeIdentity,
    validator_identity: Option<NodeIdentity>,
) -> anyhow::Result<()> {
    run_with_application(
        config,
        network_identity,
        validator_identity,
        ApplicationOverride::default(),
    )
    .await
}

pub async fn run_with_application(
    config: Config,
    network_identity: NodeIdentity,
    validator_identity: Option<NodeIdentity>,
    app_override: ApplicationOverride,
) -> anyhow::Result<()> {
    let ApplicationOverride {
        factory: injected_factory,
        shutdown: external_shutdown,
    } = app_override;
    let network_node_id = network_identity.node_id()?;

    config.validate(&network_node_id)?;

    let consensus_signer = match validator_identity {
        Some(ref val_id) => Arc::new(NodeSigner::from_identity(val_id)?),
        None => {
            if config.consensus.is_some() {
                warn!(
                    "[node.validator_identity] is unset — reusing the network identity for \
                     consensus signing. Configure [node.validator_identity] to enable \
                     independent rotation of the TLS key; this fallback will be removed \
                     in a future release."
                );
            }
            Arc::new(NodeSigner::from_identity(&network_identity)?)
        }
    };

    let overlay_is_libp2p = matches!(config.overlay.mode, OverlayMode::Libp2p);

    let libp2p_overlay_active = overlay_is_libp2p && config.consensus.is_some();
    let libp2p_keypair = if libp2p_overlay_active {
        Some(
            boule_transport_libp2p::identity::keypair_from_pkcs8_der(&network_identity.pkcs8_der)
                .context("derive libp2p transport keypair from network identity")?,
        )
    } else {
        None
    };

    let libp2p_limits = boule_transport_libp2p::swarm::Limits {
        max_established_incoming: config
            .p2p
            .limits
            .as_ref()
            .map(|l| l.max_inbound_connections as u32),
        max_established_outgoing: config
            .p2p
            .limits
            .as_ref()
            .map(|l| l.max_outbound_connections as u32),
    };
    drop(network_identity);
    drop(validator_identity);

    info!("network node ID: {}", node_id_to_base58(&network_node_id));
    let validator_node_id = consensus_signer.node_id();
    if validator_node_id != network_node_id {
        info!(
            "validator node ID: {}",
            node_id_to_base58(&validator_node_id)
        );
        if config.consensus.is_some() {
            warn!(
                "validator pubkey differs from network pubkey — consensus dispatch routes \
                 messages by validator pubkey, but the live p2p layer addresses peers by \
                 their TLS pubkey. Until validator-set reconfiguration (issue #140) lands \
                 and registers a (validator pubkey → network address) mapping, the cluster \
                 cannot route consensus traffic across the split."
            );
        }
    }

    let clock: Arc<dyn Clock> = Arc::new(TokioClock::new());

    let private_peers: std::collections::HashSet<NodeId> = config
        .peers
        .iter()
        .filter(|p| p.private)
        .filter_map(|p| p.node_id.as_deref().and_then(|s| base58_to_node_id(s).ok()))
        .collect();
    let persistent_peers: std::collections::HashSet<NodeId> = config
        .peers
        .iter()
        .filter(|p| p.persistent)
        .filter_map(|p| p.node_id.as_deref().and_then(|s| base58_to_node_id(s).ok()))
        .collect();
    if !private_peers.is_empty() || !persistent_peers.is_empty() {
        info!(
            "sentry topology: {} private (non-gossiped) peer(s), {} persistent \
             (unconditional) peer(s)",
            private_peers.len(),
            persistent_peers.len(),
        );
    }

    let inbound_disabled = config.p2p.inbound_disabled;

    let p2p_actual_addr = if inbound_disabled {
        info!(
            "P2P inbound disabled (outbound-only mode); libp2p dials out only ({})",
            config.node.listen_addr
        );
        config.node.listen_addr
    } else {
        let probe = TcpListener::bind(config.node.listen_addr).await?;
        let addr = probe.local_addr()?;
        drop(probe);
        info!("overlay=libp2p will bind {addr}");
        addr
    };

    if injected_factory.is_some() && config.consensus.is_none() {
        anyhow::bail!(
            "an in-process execution backend was injected (bundled runtime) but the config has \
             no [consensus] section; the bundled node must run consensus"
        );
    }

    let consensus_runtime = if let Some(cons_cfg) = config.consensus.as_ref() {
        let rate_limiter = config.p2p.limits.as_ref().map(|l| {
            Arc::new(boule_consensus::rate_limit::MessageRateLimiter::new(
                boule_consensus::rate_limit::message_rate_limits(l),
                Arc::clone(&clock),
            ))
        });
        Some(
            start_consensus(
                cons_cfg,
                &config.overlay,
                &validator_node_id,
                &consensus_signer,
                config.node.bls_validator_identity.as_ref(),
                Arc::clone(&clock),
                p2p_actual_addr,
                inbound_disabled,
                rate_limiter,
                private_peers,
                persistent_peers,
                libp2p_keypair,
                libp2p_limits,
                injected_factory,
            )
            .await?,
        )
    } else {
        info!("consensus: disabled (no [consensus] section in config)");
        None
    };

    let api_listener = TcpListener::bind(config.api.listen_addr).await?;
    let api_actual_addr = api_listener.local_addr()?;

    let peer_count: Arc<dyn crate::observability::PeerCount> = match consensus_runtime.as_ref() {
        Some(rc) => Arc::new(OverlayPeerCount(Arc::clone(&rc.discovery))),
        None => Arc::new(ZeroPeerCount),
    };
    let api_handle = {
        let obs_state = crate::observability::ObservabilityState {
            status_rx: consensus_runtime.as_ref().map(|rc| rc.status_rx.clone()),
            peer_count: Arc::clone(&peer_count),
        };
        let app = axum::Router::new().merge(crate::observability::router(obs_state));
        tokio::spawn(async move {
            info!("public HTTP API listening on {api_actual_addr}");
            axum::serve(api_listener, app).await.unwrap();
        })
    };

    let (admin_handle, admin_actual_addr) = if let Some(admin_addr) = config.api.admin.listen_addr {
        let token = config.api.admin.resolve_auth_token()?;
        let admin_listener = TcpListener::bind(admin_addr).await?;
        let admin_actual_addr = admin_listener.local_addr()?;

        let app = match consensus_runtime.as_ref() {
            Some(rc) => crate::admin_api::router(
                Arc::clone(&rc.rotation),
                Arc::clone(&rc.mempool),
                Some(rc.status_rx.clone()),
                Arc::clone(&rc.discovery),
                token.clone(),
            ),
            None => {
                warn!(
                    "[api.admin] listen_addr is set but consensus is disabled; the admin \
                     listener binds but exposes no routes (a node without an overlay has no \
                     peer source and no consensus-privileged routes)."
                );

                let mut r = axum::Router::new();
                if let Some(t) = token.clone() {
                    r = r.layer(axum::middleware::from_fn_with_state(
                        Arc::new(t),
                        crate::admin_api::require_bearer,
                    ));
                }
                r
            }
        };
        let authed = token.is_some();
        let handle = tokio::spawn(async move {
            info!(
                "admin HTTP API listening on {admin_actual_addr} (auth: {})",
                if authed {
                    "bearer-token"
                } else {
                    "none (network-isolated)"
                }
            );
            axum::serve(admin_listener, app).await.unwrap();
        });
        (Some(handle), Some(admin_actual_addr))
    } else {
        info!(
            "admin API disabled (no [api.admin] listen_addr); privileged routes are not \
             reachable on any listener."
        );
        (None, None)
    };

    if let Some(ref path) = config.node.addr_file {
        let mut content = serde_json::json!({
            "p2p_addr": p2p_actual_addr.to_string(),
            "api_addr": api_actual_addr.to_string(),
            "node_id": node_id_to_base58(&network_node_id),
        });
        if let Some(admin_addr) = admin_actual_addr {
            content["admin_addr"] = serde_json::Value::String(admin_addr.to_string());
        }
        std::fs::write(path, content.to_string())?;
    }

    match external_shutdown {
        Some(exit) => {
            tokio::select! {
                r = tokio::signal::ctrl_c() => { r?; info!("ctrl-c received, shutting down..."); }
                () = exit => { info!("reth node exited, shutting down consensus..."); }
            }
        }
        None => {
            tokio::signal::ctrl_c().await?;
            info!("shutting down...");
        }
    }

    let (consensus_join, overlay_joins) = match consensus_runtime {
        Some(rc) => {
            let _ = rc.consensus_shutdown.send(());
            if let Some(overlay_sd) = rc.overlay_shutdown {
                let _ = overlay_sd.send(());
            }
            (Some(rc.join), rc.overlay_joins)
        }
        None => (None, Vec::new()),
    };

    api_handle.abort();
    if let Some(h) = admin_handle.as_ref() {
        h.abort();
    }

    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        let _ = api_handle.await;
        if let Some(h) = admin_handle {
            let _ = h.await;
        }
        if let Some(h) = consensus_join {
            let _ = h.await;
        }
        for h in overlay_joins {
            let _ = h.await;
        }
    })
    .await;

    Ok(())
}

struct OverlayPeerCount(Arc<dyn Discovery>);

impl crate::observability::PeerCount for OverlayPeerCount {
    fn count(&self) -> futures_util::future::BoxFuture<'static, usize> {
        let n = self.0.known_peers().len();
        Box::pin(async move { n })
    }
}

struct ZeroPeerCount;

impl crate::observability::PeerCount for ZeroPeerCount {
    fn count(&self) -> futures_util::future::BoxFuture<'static, usize> {
        Box::pin(async move { 0 })
    }
}

struct RunningConsensus {
    join: tokio::task::JoinHandle<anyhow::Result<()>>,

    consensus_shutdown: oneshot::Sender<()>,

    status_rx: watch::Receiver<Arc<ConsensusStatus>>,

    mempool: Arc<dyn Mempool>,

    rotation: Arc<crate::rotation_handle::RotationHandle>,

    overlay_shutdown: Option<oneshot::Sender<()>>,

    overlay_joins: Vec<tokio::task::JoinHandle<()>>,

    discovery: Arc<dyn Discovery>,
}

#[cfg(feature = "reth")]
async fn reth_application(
    cfg: &ApplicationConfig,
    self_id: NodeId,
    genesis_state_commitment: [u8; 32],
    genesis_stake: Vec<([u8; 32], u64)>,
    mempool: Arc<dyn Mempool>,
) -> anyhow::Result<Arc<dyn boule_consensus::replication::application::Application>> {
    let ApplicationConfig::Reth {
        engine_url,
        eth_url,
        jwt_secret_path,
        fee_recipient,
        build_wait_ms,
        reth_peers,
    } = cfg
    else {
        anyhow::bail!(
            "[consensus.application] backend = \"reth-inprocess\" selects the bundled \
             single-process node; run it with `boule node -c <config>` (the bundle binary), \
             not `boule start`. For the standalone two-process mode set backend = \"reth\"."
        );
    };

    boule_reth::peer_reths(eth_url, reth_peers).await?;
    let (reth_genesis_hash, reth_genesis_root) = boule_reth::fetch_genesis(eth_url)
        .await
        .context("querying reth genesis over eth_url (is reth reachable?)")?;
    if reth_genesis_root != genesis_state_commitment {
        anyhow::bail!(
            "consensus genesis state_commitment {} does not match reth's genesis state root {}; \
             set [consensus] genesis_seed_hex = \"{}\"",
            hex::encode(genesis_state_commitment),
            hex::encode(reth_genesis_root),
            hex::encode(reth_genesis_root),
        );
    }
    let secret = boule_reth::jwt::load_secret(jwt_secret_path)?;
    let transport =
        boule_reth::HttpTransport::new(engine_url.clone(), eth_url.clone(), secret, None);
    info!(target: "boule::node", %engine_url, %eth_url, "reth execution backend enabled");

    let stake_source: Box<dyn boule_consensus::replication::stake_source::StakeSource> = Box::new(
        boule_consensus::replication::stake_source::BondedStakeLedger::seeded_from(genesis_stake),
    );
    let app = boule_reth::RethApplication::new(
        Box::new(transport),
        self_id,
        fee_recipient.clone(),
        reth_genesis_hash,
        reth_genesis_root,
        Duration::from_millis(*build_wait_ms),
        stake_source,
        mempool,
    );

    if let Some((height, state_root)) = boule_reth::fetch_finalized_head(eth_url)
        .await
        .context("querying reth finalized head over eth_url")?
    {
        app.recover_frontier(boule_consensus::Height(height), state_root);
        info!(
            target: "boule::node",
            height,
            "recovered reth committed frontier from finalized head on restart",
        );
    }
    Ok(Arc::new(app))
}

#[cfg(not(feature = "reth"))]
async fn reth_application(
    _cfg: &ApplicationConfig,
    _self_id: NodeId,
    _genesis_state_commitment: [u8; 32],
    _genesis_stake: Vec<([u8; 32], u64)>,
    _mempool: Arc<dyn Mempool>,
) -> anyhow::Result<Arc<dyn boule_consensus::replication::application::Application>> {
    anyhow::bail!(
        "config selects [consensus.application] backend = \"reth\", but this binary was built \
         without the `reth` cargo feature (rebuild the node with `--features reth`)"
    )
}

#[allow(clippy::too_many_arguments)]
async fn start_consensus(
    cons_cfg: &ConsensusConfig,
    overlay_cfg: &OverlayConfig,
    self_id: &NodeId,
    signer: &Arc<NodeSigner>,
    bls_identity_config: Option<&BlsIdentityConfig>,
    clock: Arc<dyn Clock>,
    self_listen_addr: std::net::SocketAddr,
    inbound_disabled: bool,
    rate_limiter: Option<Arc<boule_consensus::rate_limit::MessageRateLimiter>>,
    private_peers: std::collections::HashSet<NodeId>,
    persistent_peers: std::collections::HashSet<NodeId>,
    libp2p_keypair: Option<boule_transport_libp2p::identity::Keypair>,
    libp2p_limits: boule_transport_libp2p::swarm::Limits,
    injected_factory: Option<ApplicationFactory>,
) -> anyhow::Result<RunningConsensus> {
    let validator_set = build_validator_set(cons_cfg, self_id)?;

    let node_role = if cons_cfg.full_node {
        boule_consensus::node_role::NodeRole::Full
    } else {
        boule_consensus::node_role::NodeRole::Validator
    };
    info!(
        role = node_role.as_str(),
        "consensus: validator_set has {} members; this node's role is {}",
        validator_set.len(),
        node_role.as_str(),
    );

    let genesis_stake: Vec<([u8; 32], u64)> = validator_set
        .iter_weighted()
        .map(|(id, w)| (*id.as_node_id(), w))
        .collect();

    let genesis_bls_full = cons_cfg
        .resolve_genesis_bls_keys()
        .context("validating genesis BLS validator table")?;

    let genesis_bls: Vec<(NodeId, boule_core::crypto::sig_scheme::BlsPublicKey)> = genesis_bls_full
        .iter()
        .map(|(nid, pk, _pop)| (*nid, *pk))
        .collect();

    let genesis = boule_consensus::genesis::build_genesis(cons_cfg, &validator_set, &genesis_bls)?;
    info!("consensus: genesis hash = {:?}", genesis.hash());

    let genesis_state_commitment = genesis.header.state_commitment;

    let chain_id = boule_core::crypto::signed::ChainId::from_genesis_hash(genesis.hash());
    cons_cfg
        .verify_genesis_bls_pops(&genesis_bls_full, &chain_id)
        .context("verifying genesis BLS proof-of-possession against chain_id")?;

    let (storage, wal): (Arc<dyn Storage>, Arc<dyn Wal>) = match &cons_cfg.storage_dir {
        Some(dir) => {
            std::fs::create_dir_all(dir).map_err(|e| {
                anyhow::anyhow!("creating consensus storage_dir {}: {e}", dir.display())
            })?;
            let storage = Arc::new(DiskStorage::open(dir.join("kv.redb"))?);
            let wal = Arc::new(DiskWal::open(dir.join("wal.redb"))?);
            info!("consensus: durable storage at {}", dir.display());
            (storage, wal)
        }
        None => {
            warn!("consensus: storage_dir unset — using in-memory storage (no crash recovery)");
            (Arc::new(MemoryStorage::new()), Arc::new(MemoryWal::new()))
        }
    };

    let node_cfg = NodeConfigForConsensus {
        validator_set,
        genesis,
        propose_limit: cons_cfg.propose_limit,
        timeout_base: Duration::from_millis(cons_cfg.timeout_base_ms),
        timeout_max: Duration::from_millis(cons_cfg.timeout_max_ms),
        limits: boule_consensus::limits::CacheLimits::from_config(&cons_cfg.limits),
        snapshot_policy: boule_consensus::replication::snapshot::SnapshotPolicy {
            interval_blocks: cons_cfg.snapshot_interval_blocks,
            retention_count: cons_cfg.snapshot_retention_count,
            chunk_size_bytes: cons_cfg.snapshot_chunk_size_bytes,
        },
        min_v_eff_delay: boule_consensus::reconfig::MIN_V_EFF_DELAY,
        block_retention_window: cons_cfg.block_retention_window,
        min_block_interval: Duration::from_millis(cons_cfg.min_block_interval_ms),

        weak_subjectivity_checkpoint: cons_cfg
            .weak_subjectivity_checkpoint
            .as_ref()
            .map(|cp| {
                let h = cp.hash.strip_prefix("0x").unwrap_or(&cp.hash);
                let bytes = hex::decode(h)
                    .context("[consensus.weak_subjectivity_checkpoint].hash is not valid hex")?;
                let hash: boule_consensus::replication::block::BlockHash = bytes
                    .as_slice()
                    .try_into()
                    .context("[consensus.weak_subjectivity_checkpoint].hash must be 32 bytes")?;
                anyhow::Ok((boule_consensus::Height(cp.height), hash))
            })
            .transpose()?,

        operator_keys: cons_cfg
            .resolve_genesis_operator_keys()
            .context("validating genesis operator-key table")?,

        max_endpoint_list_length: cons_cfg.max_endpoint_list_length,
    };

    let mempool: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(cons_cfg.mempool_capacity));

    let OverlayWiring {
        broadcaster,
        discovery,
        event_rx,
        overlay_shutdown,
        overlay_joins,
        gossip_sink_overflows,
        peer_outbound_overflows,
    } = build_overlay_wiring(
        overlay_cfg,
        *self_id,
        self_listen_addr,
        inbound_disabled,
        clock,
        private_peers,
        persistent_peers,
        libp2p_keypair,
        libp2p_limits,
    )
    .await?;

    let bls_setup = reconcile_bls_identity(
        cons_cfg,
        bls_identity_config,
        self_id,
        &genesis_bls,
        storage.as_ref(),
    )?;

    let mut node = ConsensusNode::recover(*self_id, node_cfg, Arc::clone(&mempool), storage, wal)?;
    if let Some(BlsBootstrap { history, identity }) = bls_setup {
        node = node.with_bls_key_history(history);

        if let Some(identity) = identity {
            let bls_signer: Arc<
                dyn boule_core::crypto::signed::PartialSigner<
                        boule_core::crypto::sig_scheme::BlsAggregated,
                    >,
            > = Arc::new(
                boule_core::crypto::bls_key::BlsPartialSignerImpl::from_identity(identity),
            );
            node = node.with_bls_signer(bls_signer);
        }
    }

    match (injected_factory, cons_cfg.application.as_ref()) {
        (Some(factory), _) => {
            info!(
                target: "boule::node",
                "building injected in-process execution backend (bundled runtime)",
            );
            let app = factory(ApplicationContext {
                self_id: *self_id,
                genesis_state_commitment,
                genesis_stake,
                mempool: Arc::clone(&mempool),
            })
            .await
            .context("building injected in-process execution backend")?;
            node = node.with_application(app);
        }
        (None, Some(reth_cfg)) => {
            let app = reth_application(
                reth_cfg,
                *self_id,
                genesis_state_commitment,
                genesis_stake,
                std::sync::Arc::clone(&mempool),
            )
            .await?;
            node = node.with_application(app);
        }
        (None, None) => {
            anyhow::bail!(
                "[consensus] is configured but no execution backend is set: a node must declare \
                 [consensus.application] with backend = \"reth\". reth is the only supported \
                 execution layer (#881/#883); the in-process counter state machine is no longer \
                 a production backend.",
            );
        }
    }

    node.verify_persisted_history_consistency()
        .context("verifying persisted validator histories against committed chain (#325 PR B)")?;

    if let Some(counter) = gossip_sink_overflows {
        node = node.with_gossip_sink_overflow_counter(counter);
    }
    node = node.with_peer_outbound_overflow_counter(peer_outbound_overflows);

    let initial_status = Arc::new(node.build_status());
    let (status_tx, status_rx) = watch::channel(initial_status);
    let mut node = node.with_status_publisher(status_tx);
    if let Some(limiter) = rate_limiter {
        node = node.with_rate_limiter(limiter);
    }

    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let genesis_signer = Arc::clone(signer) as Arc<dyn boule_core::crypto::signed::Signer>;
    let signing_view = node.signing_view_handle();
    let rotatable_signer = Arc::new(crate::rotatable_signer::RotatableSigner::new(
        genesis_signer,
        Arc::clone(&signing_view),
    ));
    let rotation = Arc::new(crate::rotation_handle::RotationHandle::new(
        *self_id,
        boule_consensus::genesis::derive_chain_id(cons_cfg)?,
        signing_view,
        Arc::clone(&mempool),
        Arc::clone(&rotatable_signer),
    ));
    let signer: Arc<dyn boule_core::crypto::signed::Signer> = rotatable_signer;

    let discovery_for_api = Arc::clone(&discovery);
    let join = tokio::spawn(async move {
        node.run(broadcaster, discovery, event_rx, signer, shutdown_rx)
            .await
    });
    info!("consensus: event loop spawned");
    Ok(RunningConsensus {
        join,
        consensus_shutdown: shutdown_tx,
        status_rx,
        mempool,
        rotation,
        overlay_shutdown,
        overlay_joins,
        discovery: discovery_for_api,
    })
}

#[derive(Debug)]
struct BlsBootstrap {
    history: boule_consensus::bls_key_history::BlsKeyHistory,
    identity: Option<boule_core::crypto::bls_key::BlsValidatorIdentity>,
}

fn reconcile_bls_identity(
    cons_cfg: &ConsensusConfig,
    bls_identity_config: Option<&BlsIdentityConfig>,
    self_id: &NodeId,
    genesis_bls: &[(NodeId, boule_core::crypto::sig_scheme::BlsPublicKey)],
    storage: &dyn boule_core::storage::Storage,
) -> anyhow::Result<Option<BlsBootstrap>> {
    use crate::consensus_node::STORAGE_KEY_BLS_KEY_HISTORY;
    use boule_consensus::bls_key_history::PersistedBlsKeyHistory;

    let identity = if cons_cfg.full_node {
        if bls_identity_config.is_some() {
            info!(
                "consensus: full node — [node.bls_validator_identity] is present but unused \
                 (a full node verifies QCs but never signs partials)",
            );
        }
        None
    } else {
        let bls_cfg = bls_identity_config.ok_or_else(|| {
            anyhow::anyhow!(
                "[node.bls_validator_identity] must be set so the node can produce QC \
                 partials. Configure a BLS key path before booting against this chain \
                 (or set [consensus] full_node = true for a non-validating node).",
            )
        })?;
        let provider = boule_core::config::build_bls_provider(bls_cfg)
            .context("building BLS validator-key provider from config")?;
        let identity = provider
            .load_or_init()
            .context("loading BLS validator key from configured backend")?;

        let expected = genesis_bls.iter().find(|(nid, _)| nid == self_id);
        match expected {
            Some((_, expected_pk)) if expected_pk == &identity.public => {
                info!(
                    backend = provider.name(),
                    bls_pubkey = %hex::encode(identity.public),
                    "consensus: BLS validator identity reconciled with genesis",
                );
            }
            Some((_, expected_pk)) => {
                anyhow::bail!(
                    "consensus: loaded BLS pubkey {} does not match the genesis BLS \
                     pubkey {} for this node ({}). The on-disk BLS key was generated \
                     for a different validator slot.",
                    hex::encode(identity.public),
                    hex::encode(expected_pk),
                    node_id_to_base58(self_id),
                );
            }
            None => {
                anyhow::bail!(
                    "consensus: this node ({}) is not a BLS-genesis validator. Either add this \
                     node to consensus.validators_bls in genesis, set [consensus] \
                     full_node = true to follow as a non-validating node, or boot \
                     against a chain on which it is a member.",
                    node_id_to_base58(self_id),
                );
            }
        }
        Some(identity)
    };

    let history = match storage
        .get(STORAGE_KEY_BLS_KEY_HISTORY)
        .context("read bls_key_history from storage")?
    {
        Some(raw) => {
            let persisted: PersistedBlsKeyHistory =
                postcard::from_bytes(&raw).context("decode persisted bls_key_history")?;
            boule_consensus::bls_key_history::BlsKeyHistory::from_persisted(persisted)
                .context("rebuild BlsKeyHistory from persisted form")?
        }
        None => boule_consensus::bls_key_history::BlsKeyHistory::with_genesis(
            genesis_bls.iter().copied(),
        ),
    };
    Ok(Some(BlsBootstrap { history, identity }))
}

const LIBP2P_IDLE_CONNECTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

struct OverlayWiring {
    broadcaster: Arc<dyn Broadcaster>,
    discovery: Arc<dyn Discovery>,
    event_rx: mpsc::Receiver<overlay_traits::ProtocolEvent>,
    overlay_shutdown: Option<oneshot::Sender<()>>,
    overlay_joins: Vec<tokio::task::JoinHandle<()>>,

    gossip_sink_overflows: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,

    peer_outbound_overflows: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

#[allow(clippy::too_many_arguments)]
async fn build_overlay_wiring(
    overlay_cfg: &OverlayConfig,
    self_id: NodeId,
    self_listen_addr: std::net::SocketAddr,
    inbound_disabled: bool,
    clock: Arc<dyn Clock>,
    private_peers: std::collections::HashSet<NodeId>,
    persistent_peers: std::collections::HashSet<NodeId>,
    libp2p_keypair: Option<boule_transport_libp2p::identity::Keypair>,
    libp2p_limits: boule_transport_libp2p::swarm::Limits,
) -> anyhow::Result<OverlayWiring> {
    let _ = (self_id, clock, private_peers, persistent_peers);
    {
        {
            let keypair = libp2p_keypair.context(
                "internal wiring error: libp2p overlay selected but no keypair was derived",
            )?;

            let listen_addr = if inbound_disabled {
                None
            } else {
                Some(self_listen_addr)
            };

            let allowed_peers = if overlay_cfg.allowed_peers.is_empty() {
                None
            } else {
                let mut ids = Vec::with_capacity(overlay_cfg.allowed_peers.len());
                for raw in &overlay_cfg.allowed_peers {
                    ids.push(base58_to_node_id(raw).map_err(|e| {
                        anyhow::anyhow!("decoding [overlay] allowed_peers entry {raw:?}: {e}")
                    })?);
                }
                Some(ids)
            };
            let handles = boule_transport_libp2p::overlay::spawn(
                boule_transport_libp2p::overlay::SpawnConfig {
                    keypair,
                    listen_addr,
                    bootstrap_addrs: overlay_cfg.bootstrap_addrs.clone(),
                    idle_connection_timeout: LIBP2P_IDLE_CONNECTION_TIMEOUT,
                    allowed_peers,
                    limits: libp2p_limits,
                },
            )
            .context("spawn libp2p overlay")?;

            info!(
                "overlay: libp2p (listen={}, bootstrap_addrs={})",
                if inbound_disabled {
                    "disabled (outbound-only)".to_string()
                } else {
                    self_listen_addr.to_string()
                },
                overlay_cfg.bootstrap_addrs.len()
            );

            let broadcaster: Arc<dyn Broadcaster> = handles.broadcaster;
            let discovery: Arc<dyn overlay_traits::Discovery> = handles.discovery;
            Ok(OverlayWiring {
                broadcaster,
                discovery,
                event_rx: handles.event_rx,
                overlay_shutdown: Some(handles.shutdown),
                overlay_joins: vec![handles.join],

                gossip_sink_overflows: None,
                peer_outbound_overflows: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            })
        }
    }
}

fn build_validator_set(cfg: &ConsensusConfig, self_id: &NodeId) -> anyhow::Result<ValidatorSet> {
    if cfg.validators.is_empty() {
        anyhow::bail!("[consensus.validators] must list at least one node");
    }
    let mut ids: Vec<NodeId> = Vec::with_capacity(cfg.validators.len());
    for raw in &cfg.validators {
        let id = base58_to_node_id(raw)
            .map_err(|e| anyhow::anyhow!("decoding validator NodeId {raw:?}: {e}"))?;
        ids.push(id);
    }
    let self_in_set = ids.iter().any(|id| id == self_id);

    if cfg.full_node {
        if self_in_set {
            anyhow::bail!(
                "[consensus] full_node = true but [consensus.validators] includes \
                 this node's own ID {}; a full node must not be in the committee",
                node_id_to_base58(self_id),
            );
        }
    } else if !self_in_set {
        anyhow::bail!(
            "[consensus.validators] does not include this node's own ID {} \
             (set [consensus] full_node = true to run as a non-validating node)",
            node_id_to_base58(self_id),
        );
    }

    let validator_ids: Vec<boule_consensus::validator_set::ValidatorId> = ids
        .into_iter()
        .map(boule_consensus::validator_set::ValidatorId::from_genesis_pubkey)
        .collect();
    Ok(ValidatorSet::new(validator_ids))
}
