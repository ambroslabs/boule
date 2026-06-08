//! Top-level node runtime: wires the transport and optional HotStuff
//! consensus into a single ctrl-c-driven process.
//!
//! Lives in the library (rather than `main.rs`) so the integration
//! tests and the `start` subcommand share one definition of "what a
//! running node looks like".

pub mod admin_api;
pub mod consensus_node;
pub mod demo_staking;
/// Public eth-facing HTTP services (faucet + RPC proxy); reth-only (#806).
#[cfg(feature = "reth")]
pub mod eth_public;
pub mod observability;
pub mod rotatable_signer;
pub mod rotation_handle;
pub mod testnet;

#[cfg(test)]
pub mod sim;
#[cfg(test)]
mod sim_byzantine;
#[cfg(test)]
mod sim_crashpoint;
#[cfg(test)]
mod wire_fuzz;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;

use parking_lot::Mutex;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{info, warn};

use crate::consensus_node::{ConsensusNode, NodeConfigForConsensus};
use boule_consensus::replication::impls::{CounterStateMachine, InMemoryMempool};
use boule_consensus::replication::mempool::Mempool;
use boule_consensus::replication::state_machine::StateMachine;
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

/// Run a node from a fully-resolved configuration plus the network and
/// (optional) validator identities. When `validator_identity` is `None`,
/// the network identity is reused for consensus signing — the historical
/// single-key behavior — with a deprecation warning if consensus is
/// enabled. Blocks until ctrl-c, then drains tasks and returns.
pub async fn run(
    config: Config,
    network_identity: NodeIdentity,
    validator_identity: Option<NodeIdentity>,
) -> anyhow::Result<()> {
    let network_node_id = network_identity.node_id()?;

    // Reject configurations that would self-dial: a static [[peers]]
    // entry whose `node_id` matches the local node identity surfaces in
    // /peers as a real peer. Done here (rather than at parse time) so the
    // check can compare against the loaded local NodeId. TOFU
    // bootstrap_addrs are checked instead by the overlay handshake guards.
    config.validate(&network_node_id)?;

    // Resolve the consensus-signing key. When `[node.validator_identity]`
    // is configured, build a separate `NodeSigner` from that key.
    // Otherwise reuse the network identity and warn loudly if consensus
    // is actually enabled (gossip-only nodes never use the signer, so
    // the warning would be noise there).
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

    // Derive the libp2p transport keypair from the network identity's PKCS#8
    // key *before* it is dropped, so the libp2p backend reuses the consensus
    // key (its PeerId == this node's NodeId). Only built when the libp2p
    // overlay is selected.
    let overlay_is_libp2p = matches!(config.overlay.mode, OverlayMode::Libp2p);
    // The libp2p overlay (which owns its own listener) is only built when
    // consensus is enabled. A non-consensus node is just the TCP manager even
    // in libp2p mode, so it must still bind the TCP listener.
    let libp2p_overlay_active = overlay_is_libp2p && config.consensus.is_some();
    let libp2p_keypair = if libp2p_overlay_active {
        Some(
            boule_transport_libp2p::identity::keypair_from_pkcs8_der(&network_identity.pkcs8_der)
                .context("derive libp2p transport keypair from network identity")?,
        )
    } else {
        None
    };
    // Connection-count caps for the libp2p backend (#544), mapped from
    // `[p2p.limits]` (absent -> unbounded).
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

    // Sentry-topology peer sets (#827), decoded from `[[peers]]`.
    // `config.validate` above guarantees every `private`/`persistent`
    // entry carries a well-formed `node_id`, so these decodes cannot
    // fail. `private` peers are never relayed in PeerList gossip;
    // `persistent` peers are never trimmed by maintenance and are
    // admitted past the inbound cap (the unconditional set).
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
    // libp2p owns its own TCP listener (the Swarm binds `node.listen_addr`).
    // When inbound is enabled we probe-bind the configured address to resolve
    // a port-0 into a concrete address for `addr_file`, then free it so libp2p
    // can bind it (the testnet relies on this bind-then-rebind). A validator in
    // outbound-only mode (#138) dials out only and binds nothing. A node with
    // no [consensus] section has no overlay and binds nothing.
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

    // Optionally start consensus. When the [consensus] section is
    // present, the protocol is registered, the ConsensusNode is
    // constructed (with disk storage if configured, otherwise in-memory)
    // and its `run` loop is spawned. The gossip overlay's
    // bootstrap_addrs are dialed at boot via `Discovery::add_bootstrap`.
    let consensus_runtime = if let Some(cons_cfg) = config.consensus.as_ref() {
        // Build the rate limiter alongside consensus when `[p2p.limits]`
        // is present in the config; the limiter is plumbed into the
        // ConsensusNode below so ingress is gated before
        // `dispatch::ingress` ever runs.
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
            )
            .await?,
        )
    } else {
        info!("consensus: disabled (no [consensus] section in config)");
        None
    };

    // Bind the API listener here so we know the actual port before writing addr_file.
    let api_listener = TcpListener::bind(config.api.listen_addr).await?;
    let api_actual_addr = api_listener.local_addr()?;
    // Live peer-count probe shared by `/metrics` and `/ready`, read from the
    // active overlay's discovery (the same source `/peers` reports). A node
    // without consensus has no overlay, so it reports zero peers.
    let peer_count: Arc<dyn crate::observability::PeerCount> = match consensus_runtime.as_ref() {
        Some(rc) => Arc::new(OverlayPeerCount(Arc::clone(&rc.discovery))),
        None => Arc::new(ZeroPeerCount),
    };
    let api_handle = {
        // The PUBLIC listener exposes only observability endpoints
        // (`/health`, `/ready`, `/metrics`). Privileged routes (key rotation,
        // mempool submit) and the internal-state reads `/consensus/status` +
        // `/peers` (#823) are never mounted here — they live on the separate
        // admin listener below (#807), which gates them behind bearer auth.
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

    // Bind the separate ADMIN listener when configured (#807). It carries the
    // privileged routes (`POST /admin/rotate-key`, `POST /mempool/submit`),
    // optionally behind a bearer token. When `[api.admin] listen_addr` is
    // unset, the privileged surface is not served anywhere — default-safe.
    let (admin_handle, admin_actual_addr) = if let Some(admin_addr) = config.api.admin.listen_addr {
        let token = config.api.admin.resolve_auth_token()?;
        let admin_listener = TcpListener::bind(admin_addr).await?;
        let admin_actual_addr = admin_listener.local_addr()?;
        // The privileged rotate-key/mempool routes need the rotation handle +
        // mempool, which only exist with consensus; the internal-state reads
        // (`/consensus/status`, `/peers`) moved here too (#823). On a
        // gossip-only node we still bind the listener and serve `/peers` (the
        // only thing meaningful there) but mount no consensus-privileged
        // routes.
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
                // No overlay without consensus and no legacy peer manager — the
                // admin surface is empty. Still apply the bearer layer for
                // consistency so the listener behaves uniformly.
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

    // Write bound addresses + node ID to addr_file if configured.
    // Tests use this to discover actual ports when listen_addr uses port 0.
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

    tokio::signal::ctrl_c().await?;
    info!("shutting down...");

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

    // The HTTP servers run until their listeners close (axum::serve never
    // returns on its own), so abort them rather than awaiting indefinitely.
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

/// [`observability::PeerCount`] backed by the active overlay's discovery —
/// the same live peer set `/peers` reports.
struct OverlayPeerCount(Arc<dyn Discovery>);

impl crate::observability::PeerCount for OverlayPeerCount {
    fn count(&self) -> futures_util::future::BoxFuture<'static, usize> {
        let n = self.0.known_peers().len();
        Box::pin(async move { n })
    }
}

/// [`observability::PeerCount`] for a node with no `[consensus]` section (and
/// therefore no overlay): it has no peers, so it reports zero.
struct ZeroPeerCount;

impl crate::observability::PeerCount for ZeroPeerCount {
    fn count(&self) -> futures_util::future::BoxFuture<'static, usize> {
        Box::pin(async move { 0 })
    }
}

/// Bundle returned by [`start_consensus`].
struct RunningConsensus {
    /// Consensus event-loop join handle.
    join: tokio::task::JoinHandle<anyhow::Result<()>>,
    /// Oneshot signal that gracefully stops the consensus event loop.
    consensus_shutdown: oneshot::Sender<()>,
    /// Snapshot of the consensus status, served by the HTTP API.
    status_rx: watch::Receiver<Arc<ConsensusStatus>>,
    /// The node's mempool, shared with the HTTP API so `POST
    /// /mempool/submit` can admit transactions into the same pool the
    /// block builder draws from.
    mempool: Arc<dyn Mempool>,
    /// #707: runtime hot-rotation trigger, retaining the live
    /// `RotatableSigner` handle so an operator can rotate the consensus
    /// signing key without restarting. Shared with the `POST
    /// /admin/rotate-key` admin router (see [`crate::admin_api`]).
    rotation: Arc<crate::rotation_handle::RotationHandle>,
    /// Oneshot that gracefully stops the gossip overlay (the
    /// orchestrator + publisher + partial-mesh maintenance tasks).
    overlay_shutdown: Option<oneshot::Sender<()>>,
    /// Overlay sub-task joins (orchestrator + publisher + partial-mesh
    /// maintenance).
    overlay_joins: Vec<tokio::task::JoinHandle<()>>,
    /// The active overlay's discovery handle, exposed to `node::run` so the
    /// admin `/peers` endpoint and the `/metrics` peer-count probe read the
    /// live peer set directly (no separate peer manager).
    discovery: Arc<dyn Discovery>,
}

/// Build the reth-backed
/// [`Application`](boule_consensus::replication::application::Application)
/// from `[consensus.application] backend = "reth"`, bridging the consensus
/// genesis to reth's: the configured genesis `state_commitment` must equal
/// reth's genesis state root, or replicas would diverge on the first block.
/// Compiled only with the `reth` feature.
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
        unreachable!("reth_application called for a non-reth backend");
    };
    // Connect the local reth to the other validators' reths (best-effort) so
    // tx-pool gossip and EL self-sync work across the cluster.
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
    // CL-native stake ledger (#654) seeded from the genesis validator set;
    // the reth application feeds it the staking predeploy's events (#655).
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
    // On restart, reth (its own persistent DB) is already at the finalized head
    // while `new` reset the in-memory frontier to genesis. Reconcile the two so
    // the first post-restart proposal stamps the correct lagged
    // `committed_state_root` (#630); a fresh node has no finalized head and
    // keeps the genesis frontier.
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

/// Stub for builds without the `reth` feature: selecting the reth backend
/// in config is a clear startup error rather than a silent fallback.
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

/// Start the HotStuff consensus protocol alongside gossip + ping.
///
/// Registers the consensus protocol with the overlay, spawns a
/// `GossipOverlay` over the handle, ingests `overlay_cfg.bootstrap_addrs`
/// via `Discovery::add_bootstrap`, and wires consensus to the overlay's
/// `GossipBroadcaster` / `GossipDiscovery`.
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
) -> anyhow::Result<RunningConsensus> {
    let validator_set = build_validator_set(cons_cfg, self_id)?;
    // #803: surface the participation role at boot so an operator (and the
    // multi-validator e2e harness) can confirm a non-validating node is running
    // in the follow-only role and will never cast a vote.
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
    // Genesis stake (= genesis weight) per validator, captured before
    // `validator_set` is moved into the node config. Seeds the reth backend's
    // stake ledger (#655) so a post-genesis unbond computes the right delta;
    // unused by the counter backend.
    let genesis_stake: Vec<([u8; 32], u64)> = validator_set
        .iter_weighted()
        .map(|(id, w)| (*id.as_node_id(), w))
        .collect();

    // Resolve genesis BLS keys + reconcile this node's local BLS
    // identity with the chain's scheme (#335). This catches three
    // misconfigurations at startup, before any wire traffic flows:
    //
    //   - BLS chain with no `[node.bls_validator_identity]` configured
    //   - BLS chain whose loaded BLS pubkey is not a genesis validator
    //   - Ed25519 chain with `[node.bls_validator_identity]` set
    //     (BLS keys have no role on an Ed25519 chain)
    //
    // Resolved *before* `build_genesis` so the genesis block can carry
    // a real `validator_history_commitment` (#325 PR B), computed over
    // the genesis-time `(set_history, key_history, bls_key_history?)`
    // triple.
    let genesis_bls_full = cons_cfg
        .resolve_genesis_bls_keys()
        .context("validating genesis BLS validator table")?;
    // Pubkey-only projection used by genesis-block construction and by
    // `reconcile_bls_identity`. PoPs are split off and verified
    // *after* the chain_id is known (#410), since the PoP pre-image
    // binds to chain_id.
    let genesis_bls: Vec<(NodeId, boule_core::crypto::sig_scheme::BlsPublicKey)> = genesis_bls_full
        .iter()
        .map(|(nid, pk, _pop)| (*nid, *pk))
        .collect();

    let genesis = boule_consensus::genesis::build_genesis(cons_cfg, &validator_set, &genesis_bls)?;
    info!("consensus: genesis hash = {:?}", genesis.hash());
    // Captured before `genesis` is moved into the node config; the reth
    // backend bridges this against reth's genesis state root.
    let genesis_state_commitment = genesis.header.state_commitment;

    // Now the chain_id is known: verify the operator-supplied
    // proof-of-possession bytes bind to *this* deployment's chain_id
    // (#410, audit finding 7-2). Without this check, an attacker who
    // operates the same validator BLS key on two deployments could
    // cross-replay a genesis-time PoP across them.
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
        signature_scheme: cons_cfg.signature_scheme,
        block_retention_window: cons_cfg.block_retention_window,
        min_block_interval: Duration::from_millis(cons_cfg.min_block_interval_ms),
        // Decode the optional weak-subjectivity checkpoint (#642). The hex/height
        // are already format-validated in `preflight_validate`; decode to the
        // wire types here so the node can enforce it at commit/recover.
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
        // #549: genesis operator keys (already format-validated in
        // preflight). Empty if the optional table is absent.
        operator_keys: cons_cfg
            .resolve_genesis_operator_keys()
            .context("validating genesis operator-key table")?,
        // #546: per-validator endpoint-list cap.
        max_endpoint_list_length: cons_cfg.max_endpoint_list_length,
    };

    let state_machine: Arc<Mutex<Box<dyn StateMachine>>> =
        Arc::new(Mutex::new(Box::new(CounterStateMachine::new())));
    let mempool: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(cons_cfg.mempool_capacity));

    // Wire the broadcaster + discovery + upstream event channel
    // according to the configured overlay mode.
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

    // Resolve the BLS key history *and* signer. On Ed25519 chains:
    // both `None`. On BLS chains: the BLS pubkey table (preferred
    // from persistence per #339, falling back to a fresh genesis
    // seed) plus the loaded validator identity wrapped in a
    // `BlsPartialSignerImpl` so the dispatch layer can sign Vote
    // partials (#354 step 2). Both branches re-validate the local
    // node's BLS identity against the canonical genesis pubkey for
    // that NodeId (#335).
    let bls_setup = reconcile_bls_identity(
        cons_cfg,
        bls_identity_config,
        self_id,
        &genesis_bls,
        storage.as_ref(),
    )?;

    let mut node = ConsensusNode::recover(
        *self_id,
        node_cfg,
        state_machine,
        Arc::clone(&mempool),
        storage,
        wal,
    )?;
    if let Some(BlsBootstrap { history, identity }) = bls_setup {
        node = node.with_bls_key_history(history);
        // A validator wires its BLS partial signer; a full node (#803) has no
        // signing identity — it verifies inbound QCs via the history above but
        // never produces partials, so it leaves the signer unset.
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

    // Select the execution backend (`[consensus.application]`). Absent or
    // `counter` keeps the in-process counter application the constructor
    // wired; `reth` swaps in the Engine-API-backed application after
    // bridging the consensus genesis to reth's.
    match cons_cfg.application.as_ref() {
        None | Some(ApplicationConfig::Counter) => {}
        Some(reth_cfg) => {
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
    }

    // #325 PR B: gate startup on rebuild-from-chain validation. The
    // BLS history (if any) has been wired in immediately above, so
    // every history table the commitment covers is in place — the
    // walk can compare each block's stamped commitment against the
    // rebuilt triple and assert end-of-walk equality with what was
    // loaded from storage. A divergence here means the persisted
    // blob was tampered with or rolled back, and we refuse to start.
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
        // The limiter's `Disconnect` decisions are routed through the active
        // overlay's discovery inside `run` (libp2p tears the connection down).
        node = node.with_rate_limiter(limiter);
    }

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    // #312: sign through a RotatableSigner sharing the node's current-view
    // handle, so a committed signing-key rotation can take effect at its
    // `v_eff` without restarting. #707: the same `Arc<RotatableSigner>` is
    // retained in a `RotationHandle` so an operator can trigger a hot
    // rotation at runtime (build the dual-signed tx, admit it, schedule the
    // swap) — without it, the wrapper is behaviourally identical to signing
    // with the genesis key.
    let genesis_signer = Arc::clone(signer) as Arc<dyn boule_core::crypto::signed::Signer>;
    let signing_view = node.signing_view_handle();
    let rotatable_signer = Arc::new(crate::rotatable_signer::RotatableSigner::new(
        genesis_signer,
        Arc::clone(&signing_view),
    ));
    let rotation = Arc::new(crate::rotation_handle::RotationHandle::new(
        *self_id,
        boule_consensus::genesis::derive_chain_id(cons_cfg)?,
        cons_cfg.signature_scheme,
        signing_view,
        Arc::clone(&mempool),
        Arc::clone(&rotatable_signer),
    ));
    let signer: Arc<dyn boule_core::crypto::signed::Signer> = rotatable_signer;
    // Keep a handle to the discovery for the admin /peers + /metrics surface
    // before `run` takes ownership of its copy.
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

/// Bundle returned by [`reconcile_bls_identity`] on `bls_aggregated`
/// chains: the per-historical-view pubkey table (consumed by the
/// dispatch verifier on inbound QCs) plus — for a **validator** — the
/// loaded validator identity (consumed by the dispatch signer on
/// outbound votes, wrapped in `BlsPartialSignerImpl` in the caller).
///
/// A [full node](boule_consensus::node_role::NodeRole::Full) (#802/#803)
/// gets the history (it still verifies inbound QCs) but **no** `identity`:
/// it is not in the committee and never produces QC partials, so it must
/// not be required to carry a BLS signing key. `identity` is therefore
/// `None` for a full node and `Some` for a validator.
#[derive(Debug)]
struct BlsBootstrap {
    history: boule_consensus::bls_key_history::BlsKeyHistory,
    identity: Option<boule_core::crypto::bls_key::BlsValidatorIdentity>,
}

/// Reconcile the node's local BLS identity with the chain's signature
/// scheme (#335). Refuses to start in any of:
///
/// - BLS chain whose `[node.bls_validator_identity]` table is missing.
/// - BLS chain whose configured BLS key isn't a genesis validator.
/// - Ed25519 chain with `[node.bls_validator_identity]` set.
///
/// On a BLS chain that passes the checks, returns a [`BlsBootstrap`]
/// carrying both the seeded
/// [`boule_consensus::bls_key_history::BlsKeyHistory`] (for QC
/// verification at ingress) and the loaded
/// [`boule_core::crypto::bls_key::BlsValidatorIdentity`] (for partial
/// signing at egress). On an Ed25519 chain, returns `None`.
fn reconcile_bls_identity(
    cons_cfg: &ConsensusConfig,
    bls_identity_config: Option<&BlsIdentityConfig>,
    self_id: &NodeId,
    genesis_bls: &[(NodeId, boule_core::crypto::sig_scheme::BlsPublicKey)],
    storage: &dyn boule_core::storage::Storage,
) -> anyhow::Result<Option<BlsBootstrap>> {
    use crate::consensus_node::STORAGE_KEY_BLS_KEY_HISTORY;
    use boule_consensus::bls_key_history::PersistedBlsKeyHistory;
    use boule_core::crypto::sig_scheme::SignatureSchemeChoice;

    match cons_cfg.signature_scheme {
        SignatureSchemeChoice::Ed25519Collected => {
            if bls_identity_config.is_some() {
                anyhow::bail!(
                    "[node.bls_validator_identity] is set but consensus.signature_scheme = \
                     \"ed25519_collected\" — Ed25519 chains have no use for a BLS key. \
                     Remove the bls_validator_identity table or switch the chain's \
                     signature_scheme to \"bls_aggregated\".",
                );
            }
            Ok(None)
        }
        SignatureSchemeChoice::BlsAggregated => {
            // #803: a full (non-validating) node on a BLS chain still needs the
            // genesis BLS pubkey *history* to verify inbound QCs, but it never
            // produces QC partials — so it must NOT be required to carry a BLS
            // signing key. Load + cross-check the local identity only for a
            // validator; a full node gets `identity = None` (and may set or omit
            // `[node.bls_validator_identity]` freely).
            let identity = if cons_cfg.full_node {
                if bls_identity_config.is_some() {
                    info!(
                        "consensus: full node on a bls_aggregated chain — \
                         [node.bls_validator_identity] is present but unused (a full node \
                         verifies QCs but never signs partials)",
                    );
                }
                None
            } else {
                let bls_cfg = bls_identity_config.ok_or_else(|| {
                    anyhow::anyhow!(
                        "consensus.signature_scheme = \"bls_aggregated\" requires \
                         [node.bls_validator_identity] to be set so the node can produce QC \
                         partials. Configure a BLS key path before booting against this chain \
                         (or set [consensus] full_node = true for a non-validating node).",
                    )
                })?;
                let provider = boule_core::config::build_bls_provider(bls_cfg)
                    .context("building BLS validator-key provider from config")?;
                let identity = provider
                    .load_or_init()
                    .context("loading BLS validator key from configured backend")?;
                // Cross-check that the loaded BLS pubkey appears in the
                // genesis BLS table for THIS node's NodeId. Catches both
                // the "wrong key file" case (BLS key on disk doesn't match
                // the one in genesis) and the "wrong node" case (this
                // NodeId isn't a genesis BLS validator at all).
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
                            "consensus: this node ({}) is not a BLS-genesis validator but the \
                             chain's signature_scheme = \"bls_aggregated\". Either add this \
                             node to consensus.validators_bls in genesis, set [consensus] \
                             full_node = true to follow as a non-validating node, or boot \
                             against a chain on which it is a member.",
                            node_id_to_base58(self_id),
                        );
                    }
                }
                Some(identity)
            };
            // Prefer the persisted form (#339) so reconfig-added
            // validators and post-genesis rotations survive restart.
            // Fall back to a fresh genesis seed when storage has
            // nothing yet (first boot, or in-memory storage).
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
    }
}

/// Result of [`build_overlay_wiring`]: the broadcaster + discovery +
/// event-receiver triple consensus consumes, plus the overlay-side
/// shutdown / joins.
///
/// Idle-connection timeout for the libp2p backend. Consensus broadcasts at
/// least once per block interval (~1s), so 60s keeps connections warm between
/// rounds without holding dead ones indefinitely. (No `[overlay]` knob yet —
/// add one if operators need to tune it.)
const LIBP2P_IDLE_CONNECTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

struct OverlayWiring {
    broadcaster: Arc<dyn Broadcaster>,
    discovery: Arc<dyn Discovery>,
    event_rx: mpsc::Receiver<overlay_traits::ProtocolEvent>,
    overlay_shutdown: Option<oneshot::Sender<()>>,
    overlay_joins: Vec<tokio::task::JoinHandle<()>>,
    /// Shared overflow counter from the gossip `OverlaySink` (removed).
    /// Plumbed into [`ConsensusNode::with_gossip_sink_overflow_counter`]
    /// so [`boule_consensus::status::BackpressureStatus`] surfaces the
    /// running drop count.
    gossip_sink_overflows: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
    /// Shared overflow counter from the p2p manager — clones of the
    /// same `Arc<AtomicU64>` carried in every `ProtocolHandle` returned
    /// by `PeerCommand::RegisterProtocol`. Plumbed into
    /// [`ConsensusNode::with_peer_outbound_overflow_counter`] so the
    /// status field reflects every per-peer outbound `try_send` `Full`.
    peer_outbound_overflows: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

/// Branch on `overlay_cfg.mode` and assemble the consensus-facing
/// overlay seam.
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
    // libp2p (#840) is the only overlay backend. It owns its own
    // Swarm/transport; the consensus seam never names the concrete overlay.
    let _ = (self_id, clock, private_peers, persistent_peers);
    {
        {
            let keypair = libp2p_keypair.context(
                "internal wiring error: libp2p overlay selected but no keypair was derived",
            )?;
            // Inbound-disabled validators dial out only (no listener); others
            // bind the configured address.
            let listen_addr = if inbound_disabled {
                None
            } else {
                Some(self_listen_addr)
            };
            // Connection-gating allow-list (#844/#836): non-empty → validator
            // isolation (refuse all but these peers); empty → open node.
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
                // No libp2p analog for these manager/gossip-sink counters —
                // they feed status reporting only. A peerless zero counter is
                // correct (gossipsub manages its own queues).
                gossip_sink_overflows: None,
                peer_outbound_overflows: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            })
        }
    }
}

/// Build a [`ValidatorSet`] from base58-encoded NodeIds in the config,
/// validating that this node's own ID is present.
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
    // #802: a full (non-validating) node deliberately runs outside the
    // committee — it follows the chain without proposing or voting — so the
    // "must include self_id" rule is relaxed for it. The two membership /
    // role combinations that are *not* a coherent configuration are
    // rejected here at startup:
    //   - a validating node whose ID is absent from the set (it could never
    //     propose or vote), and
    //   - a full node whose ID *is* in the set (the role flag contradicts
    //     committee membership; the node would be expected to vote but is
    //     configured not to, stalling liveness for its share of views).
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
    // Genesis-time seeding: at config-load time, the validator's
    // stable id is its initial signing pubkey (#328 / audit finding
    // 5-F1). This is the single legitimate site for promoting raw
    // bytes to a `ValidatorId` without going through the key history's
    // reverse-index lookup.
    let validator_ids: Vec<boule_consensus::validator_set::ValidatorId> = ids
        .into_iter()
        .map(boule_consensus::validator_set::ValidatorId::from_genesis_pubkey)
        .collect();
    Ok(ValidatorSet::new(validator_ids))
}

#[cfg(test)]
mod tests {
    use super::*;
    use boule_core::config::ConsensusLimits;
    use boule_core::config::DEFAULT_VOTE_BUCKET_CAPACITY;
    use boule_core::crypto::bls_key::{BlsKeyFile, BlsKeyProvider as _};
    use boule_core::crypto::sig_scheme::{BlsAggregated, BlsPublicKey, SignatureSchemeChoice};
    use boule_core::storage::MemoryStorage;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tempfile::TempDir;

    /// Empty in-memory storage — all reconcile_bls_identity tests
    /// below run without persisted history (first-boot scenarios).
    /// The persisted-form-survives-restart case is exercised by the
    /// integration test in `reload_bls_history_from_storage`.
    fn empty_storage() -> Arc<MemoryStorage> {
        Arc::new(MemoryStorage::new())
    }

    fn cons_cfg(scheme: SignatureSchemeChoice) -> ConsensusConfig {
        ConsensusConfig {
            validators: vec![],
            full_node: false,
            genesis_seed_hex: None,
            weak_subjectivity_checkpoint: None,
            application: None,
            propose_limit: 64,
            mempool_capacity: 1024,
            max_endpoint_list_length: 8,
            timeout_base_ms: 200,
            timeout_max_ms: 10_000,
            storage_dir: None,
            limits: ConsensusLimits {
                vote_bucket_capacity: DEFAULT_VOTE_BUCKET_CAPACITY,
                ..Default::default()
            },
            snapshot_interval_blocks: 0,
            snapshot_retention_count: 0,
            snapshot_chunk_size_bytes: 1024,
            signature_scheme: scheme,
            validators_bls: vec![],
            validators_operator_keys: vec![],
            block_retention_window: 0,
            min_block_interval_ms: 0,
        }
    }

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    // ── #802: build_validator_set + full_node flag ────────────────────────────

    /// A validating node whose own id is in `validators` builds the set.
    #[test]
    fn build_validator_set_validator_in_set_ok() {
        let mut cfg = cons_cfg(SignatureSchemeChoice::default());
        cfg.validators = vec![
            node_id_to_base58(&nid(1)),
            node_id_to_base58(&nid(2)),
            node_id_to_base58(&nid(3)),
            node_id_to_base58(&nid(4)),
        ];
        let vs = build_validator_set(&cfg, &nid(2)).expect("self in set is valid");
        assert_eq!(vs.len(), 4);
    }

    /// A validating node (full_node = false) whose id is absent is
    /// rejected — today's behaviour, now with a hint about the flag.
    #[test]
    fn build_validator_set_validator_not_in_set_rejected() {
        let mut cfg = cons_cfg(SignatureSchemeChoice::default());
        cfg.validators = vec![node_id_to_base58(&nid(1)), node_id_to_base58(&nid(2))];
        let err = build_validator_set(&cfg, &nid(9)).expect_err("self absent must fail");
        assert!(
            err.to_string()
                .contains("does not include this node's own ID")
        );
    }

    /// A full node (full_node = true) whose id is absent builds the set —
    /// the relaxed requirement that enables follow-only mode (#802).
    #[test]
    fn build_validator_set_full_node_not_in_set_ok() {
        let mut cfg = cons_cfg(SignatureSchemeChoice::default());
        cfg.full_node = true;
        cfg.validators = vec![
            node_id_to_base58(&nid(1)),
            node_id_to_base58(&nid(2)),
            node_id_to_base58(&nid(3)),
            node_id_to_base58(&nid(4)),
        ];
        let vs = build_validator_set(&cfg, &nid(9)).expect("full node outside the set is valid");
        // It carries the committee (so it can verify) but is not a member.
        assert_eq!(vs.len(), 4);
    }

    /// A full node whose id IS in the committee is a contradiction and is
    /// rejected at startup.
    #[test]
    fn build_validator_set_full_node_in_set_rejected() {
        let mut cfg = cons_cfg(SignatureSchemeChoice::default());
        cfg.full_node = true;
        cfg.validators = vec![node_id_to_base58(&nid(1)), node_id_to_base58(&nid(2))];
        let err = build_validator_set(&cfg, &nid(1)).expect_err("full node in set must fail");
        assert!(err.to_string().contains("must not be in the committee"));
    }

    /// Provision a fresh BLS key file in `dir` and return its path
    /// plus the loaded pubkey.
    fn provision_bls_key(dir: &TempDir, name: &str) -> (PathBuf, BlsPublicKey) {
        let path = dir.path().join(name);
        let provider = BlsKeyFile::new(path.clone());
        let id = provider.load_or_init().unwrap();
        (path, id.public)
    }

    #[test]
    fn bls_chain_with_no_bls_config_is_rejected() {
        let cfg = cons_cfg(SignatureSchemeChoice::BlsAggregated);
        let storage = empty_storage();
        let err = reconcile_bls_identity(&cfg, None, &nid(1), &[], storage.as_ref()).unwrap_err();
        assert!(
            err.to_string().contains("[node.bls_validator_identity]"),
            "{err}",
        );
    }

    #[test]
    fn bls_chain_with_matching_genesis_pubkey_returns_history() {
        let dir = TempDir::new().unwrap();
        let self_id = nid(7);
        let (path, pk) = provision_bls_key(&dir, "self.key");
        let bls_cfg = BlsIdentityConfig::File {
            path,
            allow_insecure_perms: false,
        };
        let cfg = cons_cfg(SignatureSchemeChoice::BlsAggregated);
        let genesis = vec![(self_id, pk), (nid(8), [0xAB; 48])];
        let storage = empty_storage();
        let bootstrap =
            reconcile_bls_identity(&cfg, Some(&bls_cfg), &self_id, &genesis, storage.as_ref())
                .expect("must succeed")
                .expect("BLS chain must seed a history + identity");
        assert_eq!(bootstrap.history.len(), 2);
        assert_eq!(bootstrap.history.key_at(&self_id, 0), Some(pk));
        assert_eq!(
            bootstrap
                .identity
                .expect("validator has a signing identity")
                .public,
            pk
        );
    }

    #[test]
    fn bls_chain_with_mismatched_genesis_pubkey_is_rejected() {
        let dir = TempDir::new().unwrap();
        let self_id = nid(7);
        let (path, _pk) = provision_bls_key(&dir, "self.key");
        // Generate an unrelated pubkey to put in genesis under self_id.
        let mut ikm = [0u8; 32];
        ikm[0] = 0xCC;
        let (_sk, other_pk) = BlsAggregated::keygen(&ikm).unwrap();

        let bls_cfg = BlsIdentityConfig::File {
            path,
            allow_insecure_perms: false,
        };
        let cfg = cons_cfg(SignatureSchemeChoice::BlsAggregated);
        let genesis = vec![(self_id, other_pk)];
        let storage = empty_storage();
        let err =
            reconcile_bls_identity(&cfg, Some(&bls_cfg), &self_id, &genesis, storage.as_ref())
                .unwrap_err();
        assert!(err.to_string().contains("does not match"), "{err}");
    }

    #[test]
    fn bls_chain_with_node_id_not_in_genesis_is_rejected() {
        let dir = TempDir::new().unwrap();
        let self_id = nid(7);
        let stranger = nid(99);
        let (path, pk) = provision_bls_key(&dir, "self.key");
        let bls_cfg = BlsIdentityConfig::File {
            path,
            allow_insecure_perms: false,
        };
        let cfg = cons_cfg(SignatureSchemeChoice::BlsAggregated);
        // Genesis has stranger, not self_id.
        let genesis = vec![(stranger, pk)];
        let storage = empty_storage();
        let err =
            reconcile_bls_identity(&cfg, Some(&bls_cfg), &self_id, &genesis, storage.as_ref())
                .unwrap_err();
        assert!(
            err.to_string().contains("not a BLS-genesis validator"),
            "{err}"
        );
    }

    #[test]
    fn reload_bls_history_from_storage() {
        // Persist a non-trivial history (genesis + a rotation), then
        // confirm reconcile_bls_identity reloads it instead of
        // re-seeding from genesis.
        use crate::consensus_node::STORAGE_KEY_BLS_KEY_HISTORY;
        use boule_consensus::bls_key_history::BlsKeyHistory;
        use boule_core::storage::Storage as _;

        let dir = TempDir::new().unwrap();
        let self_id = nid(7);
        let (path, pk) = provision_bls_key(&dir, "self.key");
        let bls_cfg = BlsIdentityConfig::File {
            path,
            allow_insecure_perms: false,
        };
        let cfg = cons_cfg(SignatureSchemeChoice::BlsAggregated);
        let genesis = vec![(self_id, pk)];

        // Build a history with a rotation past genesis and persist it.
        let mut h = BlsKeyHistory::with_genesis(genesis.iter().copied());
        h.apply_rotation(self_id, 100, [0xCC; 48]).unwrap();
        let bytes = postcard::to_stdvec(&h.to_persisted()).unwrap();
        let storage = empty_storage();
        storage.put(STORAGE_KEY_BLS_KEY_HISTORY, &bytes).unwrap();

        let reloaded =
            reconcile_bls_identity(&cfg, Some(&bls_cfg), &self_id, &genesis, storage.as_ref())
                .expect("must succeed")
                .expect("BLS chain seeds a history + identity");
        // The post-rotation pubkey survived the persist/reload cycle.
        assert_eq!(reloaded.history.key_at(&self_id, 100), Some([0xCC; 48]));
        // And the genesis pubkey is still there for older views.
        assert_eq!(reloaded.history.key_at(&self_id, 0), Some(pk));
        // The loaded identity is wired through alongside the history so
        // the dispatch signer can produce real BLS partials on Vote
        // frames (#354 step 2 — without this the production startup
        // would silently boot a BLS validator that can't sign votes).
        assert_eq!(
            reloaded
                .identity
                .expect("validator has a signing identity")
                .public,
            pk
        );
    }

    /// #803: a full node on a `bls_aggregated` chain boots WITHOUT a local BLS
    /// signing key. It must still get the genesis BLS history (to verify inbound
    /// QCs) but `identity` is `None` — it never produces partials. Before the
    /// fix, `reconcile_bls_identity` hard-failed startup demanding a BLS key for
    /// every node, so a full node could not join a BLS chain at all.
    #[test]
    fn full_node_on_bls_chain_needs_no_signing_key() {
        let mut cfg = cons_cfg(SignatureSchemeChoice::BlsAggregated);
        cfg.full_node = true;
        let self_id = nid(9); // NOT in the genesis BLS set — a follower
        // A genesis BLS set that does NOT contain this node.
        let genesis = vec![(nid(1), [0x11; 48]), (nid(2), [0x22; 48])];
        let storage = empty_storage();
        // No bls_identity_config at all — a full node need not configure one.
        let bootstrap = reconcile_bls_identity(&cfg, None, &self_id, &genesis, storage.as_ref())
            .expect("full node on a BLS chain must boot")
            .expect("BLS chain still seeds a verification history");
        assert!(
            bootstrap.identity.is_none(),
            "a full node has no BLS signing identity",
        );
        // It carries the genesis history so it can verify QCs from the committee.
        assert_eq!(bootstrap.history.len(), 2);
        assert_eq!(bootstrap.history.key_at(&nid(1), 0), Some([0x11; 48]));
    }
}
