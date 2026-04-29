//! Top-level node runtime: wires the transport, gossip, ping RPC and
//! optional HotStuff consensus into a single ctrl-c-driven process.
//!
//! Lives in the library (rather than `main.rs`) so the integration
//! tests and the `start` subcommand share one definition of "what a
//! running node looks like".

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;

use parking_lot::Mutex;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tracing::{info, warn};

use crate::clock::{Clock, TokioClock};
use crate::config::{BlsIdentityConfig, Config, ConsensusConfig, OverlayConfig, OverlayMode};
use crate::consensus::node::{ConsensusNode, NodeConfigForConsensus};
use crate::consensus::status::ConsensusStatus;
use crate::consensus::validator_set::ValidatorSet;
use crate::crypto::signed::{NodeSigner, Signer};
use crate::gossip;
use crate::p2p::dialer::DialerCtx;
use crate::p2p::identity::NodeIdentity;
use crate::p2p::manager::ManagerMsg;
use crate::p2p::overlay::gossip::overlay::{
    DialerCtxAdapter, GossipOverlay, GossipOverlayConfig, SpawnArgs,
};
use crate::p2p::overlay::gossip::sink::OverlaySink;
use crate::p2p::overlay::{self as overlay_traits};
use crate::p2p::overlay::{Broadcaster, Discovery, DiscoveryEvent, MeshBroadcaster, MeshDiscovery};
use crate::p2p::tls::{NodeId, TlsIdentity, base58_to_node_id, node_id_to_base58};
use crate::p2p::tls_protocol::TlsConnectionProtocol;
use crate::p2p::{self, ConnectionProtocol};
use crate::ping;
use crate::replication::block::Block;
use crate::replication::impls::{CounterStateMachine, InMemoryMempool};
use crate::replication::state_machine::StateMachine;
use crate::storage::{DiskStorage, DiskWal, MemoryStorage, MemoryWal, Storage, Wal};

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
    let identity = Arc::new(TlsIdentity::from_identity(&network_identity)?);

    // Reject configurations that would self-dial: a static [[peers]]
    // entry whose `node_id` matches the local TLS identity loops the
    // dialer back into our own listener and surfaces in /peers as a
    // real peer. Done here (rather than at parse time) so the check
    // can compare against the loaded local NodeId. TOFU bootstrap_addrs
    // are checked instead by the dialer / listener handshake guards.
    config.validate(&identity.node_id)?;

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
    drop(network_identity);
    drop(validator_identity);

    info!("network node ID: {}", node_id_to_base58(&identity.node_id));
    let validator_node_id = consensus_signer.node_id();
    if validator_node_id != identity.node_id {
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
    let store = Arc::new(gossip::store::GossipStore::new());

    let (p2p_cmd_tx, p2p_cmd_rx) = mpsc::channel::<p2p::PeerCommand>(256);
    let (internal_tx, internal_rx) = mpsc::channel::<ManagerMsg>(256);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (peer_gone_tx, _) = broadcast::channel::<p2p::NodeId>(64);
    // Discovery deltas (`PeerAdded`/`PeerRemoved`) feed `MeshDiscovery`
    // and any other consumer that wants a topology-change event stream.
    let (discovery_tx, _) = broadcast::channel::<DiscoveryEvent>(64);

    let manager_handle = {
        let itx = internal_tx.clone();
        let pgt = peer_gone_tx.clone();
        let dtx = discovery_tx.clone();
        let our_id = identity.node_id;
        let connection_limiter = config
            .p2p
            .limits
            .as_ref()
            .map(|l| Arc::new(p2p::limits::ConnectionLimiter::new(l.connection_limits())));
        tokio::spawn(p2p::manager::run(
            our_id,
            p2p_cmd_rx,
            internal_rx,
            itx,
            pgt,
            dtx,
            connection_limiter,
        ))
    };

    // Register the gossip protocol before spawning TlsConnectionProtocol so
    // PeerConnected events are never missed. Gossip is retained as a
    // best-effort overlay alongside consensus — the integration tests
    // exercise it as the simplest available consumer of the multiplex
    // layer, and operators use `/messages` and `/peers` for ad-hoc
    // mesh introspection.
    let (reg_tx, reg_rx) = oneshot::channel();
    p2p_cmd_tx
        .send(p2p::PeerCommand::RegisterProtocol {
            id: gossip::PROTOCOL_ID,
            max_frame_bytes: Some(gossip::MAX_FRAME_BYTES),
            reply: reg_tx,
        })
        .await?;
    let gossip_handle = reg_rx.await?;
    let gossip_send_tx = gossip_handle.send_tx.clone();

    let engine_handle = {
        let store = Arc::clone(&store);
        let clock = Arc::clone(&clock);
        tokio::spawn(gossip::engine::run(gossip_handle, store, clock))
    };

    // Register the ping RPC protocol on its own ID and build an Rpc client
    // with the echo handler registered for incoming calls. Useful for
    // measuring per-hop RPC latency without spinning up consensus.
    let (ping_reg_tx, ping_reg_rx) = oneshot::channel();
    p2p_cmd_tx
        .send(p2p::PeerCommand::RegisterProtocol {
            id: ping::PROTOCOL_ID,
            max_frame_bytes: Some(ping::MAX_FRAME_BYTES),
            reply: ping_reg_tx,
        })
        .await?;
    let ping_handle = ping_reg_rx.await?;
    let ping_rpc = p2p::rpc::RpcBuilder::new()
        .handler(ping::METHOD_PING, ping::echo)
        .spawn(ping_handle, Arc::clone(&clock));

    // The gossip overlay needs an outbound dialer for both
    // `Discovery::add_bootstrap` (TOFU dials of operator-supplied
    // bootstrap addresses) and the partial-mesh maintenance loop
    // (verified dials when the table has unconnected candidates).
    // `DialerCtx` bundles everything `reconnect_loop` needs; we
    // construct it once here and clone into the overlay.
    let dialer_ctx = DialerCtx {
        identity: Arc::clone(&identity),
        internal_tx: internal_tx.clone(),
        peer_gone_tx: peer_gone_tx.clone(),
        peer_cmd_tx: Some(p2p_cmd_tx.clone()),
        clock: Arc::clone(&clock),
    };

    // Bind the P2P listener up front so the gossip overlay can
    // self-advertise the actual bound address (the publisher injects
    // a `(self_id, listen_addr)` self-entry into every peer-list
    // push so receivers can dial us back). Listener is consumed
    // later when `TlsConnectionProtocol` is constructed.
    //
    // Outbound-only mode (issue #138): when `[p2p] inbound_disabled =
    // true` we skip the bind entirely. The overlay's self-advertise
    // then carries `reachable = false` so peers know not to attempt
    // to dial back; consensus traffic flows over connections we
    // initiated.
    let inbound_disabled = config.p2p.inbound_disabled;
    let (p2p_listener, p2p_actual_addr) = if inbound_disabled {
        info!(
            "P2P inbound disabled (outbound-only mode); skipping listener bind on {}",
            config.node.listen_addr
        );
        (None, config.node.listen_addr)
    } else {
        let listener = TcpListener::bind(config.node.listen_addr).await?;
        let addr = listener.local_addr()?;
        info!("P2P listening on {addr}");
        (Some(listener), addr)
    };

    // Optionally start consensus. When the [consensus] section is
    // present, the protocol is registered, the ConsensusNode is
    // constructed (with disk storage if configured, otherwise in-memory)
    // and its `run` loop is spawned. The active overlay (mesh or gossip)
    // is selected from `config.overlay.mode`; for gossip mode the
    // bootstrap_addrs are dialed at boot via `Discovery::add_bootstrap`.
    let consensus_runtime = if let Some(cons_cfg) = config.consensus.as_ref() {
        // Build the rate limiter alongside consensus when `[p2p.limits]`
        // is present in the config; the limiter is plumbed into the
        // ConsensusNode below so ingress is gated before
        // `dispatch::ingress` ever runs.
        let rate_limiter = config.p2p.limits.as_ref().map(|l| {
            Arc::new(p2p::limits::RateLimiter::new(
                l.rate_limits(),
                Arc::clone(&clock),
            ))
        });
        Some(
            start_consensus(
                cons_cfg,
                &config.overlay,
                &p2p_cmd_tx,
                &discovery_tx,
                &validator_node_id,
                &consensus_signer,
                config.node.bls_validator_identity.as_ref(),
                dialer_ctx,
                Arc::clone(&clock),
                p2p_actual_addr,
                inbound_disabled,
                rate_limiter,
            )
            .await?,
        )
    } else {
        info!("consensus: disabled (no [consensus] section in config)");
        None
    };

    let cleanup_handle = {
        let store = Arc::clone(&store);
        let interval = config.api.cleanup_interval_secs;
        let srx = shutdown_rx.clone();
        let clock = Arc::clone(&clock);
        tokio::spawn(gossip::cleanup::run(store, interval, srx, clock))
    };

    // Bind the API listener here so we know the actual port before writing addr_file.
    let api_listener = TcpListener::bind(config.api.listen_addr).await?;
    let api_actual_addr = api_listener.local_addr()?;
    let api_handle = {
        let mut app = axum::Router::new()
            .merge(p2p::api::router(p2p_cmd_tx.clone()))
            .merge(gossip::api::router(
                Arc::clone(&store),
                gossip_send_tx,
                Arc::clone(&clock),
            ))
            .merge(ping::router(ping_rpc));
        if let Some(rc) = consensus_runtime.as_ref() {
            app = app.merge(crate::consensus::api::router(rc.status_rx.clone()));
        }
        tokio::spawn(async move {
            info!("HTTP API listening on {api_actual_addr}");
            axum::serve(api_listener, app).await.unwrap();
        })
    };

    // Write bound addresses + node ID to addr_file if configured.
    // Tests use this to discover actual ports when listen_addr uses port 0.
    if let Some(ref path) = config.node.addr_file {
        let content = serde_json::json!({
            "p2p_addr": p2p_actual_addr.to_string(),
            "api_addr": api_actual_addr.to_string(),
            "node_id": node_id_to_base58(&identity.node_id),
        });
        std::fs::write(path, content.to_string())?;
    }

    let protocol = TlsConnectionProtocol {
        identity: Arc::clone(&identity),
        peers: config.peers.clone(),
        listener: p2p_listener,
        clock: Arc::clone(&clock),
        peer_cmd_tx: Some(p2p_cmd_tx.clone()),
    };
    let protocol_handle = tokio::spawn(protocol.run(internal_tx.clone(), peer_gone_tx.clone()));

    tokio::signal::ctrl_c().await?;
    info!("shutting down...");
    let _ = shutdown_tx.send(true);
    drop(p2p_cmd_tx);

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

    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        let _ = manager_handle.await;
        let _ = engine_handle.await;
        let _ = cleanup_handle.await;
        let _ = api_handle.await;
        let _ = protocol_handle.await;
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

/// Bundle returned by [`start_consensus`]. The overlay-related fields
/// are populated when `[overlay] mode = "gossip"`; in mesh mode they
/// are `None` / empty.
struct RunningConsensus {
    /// Consensus event-loop join handle.
    join: tokio::task::JoinHandle<anyhow::Result<()>>,
    /// Oneshot signal that gracefully stops the consensus event loop.
    consensus_shutdown: oneshot::Sender<()>,
    /// Snapshot of the consensus status, served by the HTTP API.
    status_rx: watch::Receiver<Arc<ConsensusStatus>>,
    /// Oneshot that gracefully stops the gossip overlay (the
    /// orchestrator + publisher + maintenance tasks). `None` in mesh
    /// mode.
    overlay_shutdown: Option<oneshot::Sender<()>>,
    /// Overlay sub-task joins (orchestrator + publisher + mesh
    /// maintenance). Empty in mesh mode.
    overlay_joins: Vec<tokio::task::JoinHandle<()>>,
}

/// Start the HotStuff consensus protocol alongside gossip + ping.
///
/// Branches on `overlay_cfg.mode`. In `Mesh` mode, registers
/// `consensus::node::PROTOCOL_ID` and wraps the handle in
/// [`MeshBroadcaster`] + [`MeshDiscovery`]. In `Gossip` mode,
/// registers `crate::p2p::overlay::gossip::PROTOCOL_ID`, spawns a
/// `GossipOverlay` over the handle, ingests
/// `overlay_cfg.bootstrap_addrs` via `Discovery::add_bootstrap`, and
/// uses `GossipBroadcaster` / `GossipDiscovery` in place of the mesh
/// equivalents.
#[allow(clippy::too_many_arguments)]
async fn start_consensus(
    cons_cfg: &ConsensusConfig,
    overlay_cfg: &OverlayConfig,
    p2p_cmd_tx: &mpsc::Sender<p2p::PeerCommand>,
    discovery_tx: &broadcast::Sender<DiscoveryEvent>,
    self_id: &NodeId,
    signer: &Arc<NodeSigner>,
    bls_identity_config: Option<&BlsIdentityConfig>,
    dialer_ctx: DialerCtx,
    clock: Arc<dyn Clock>,
    self_listen_addr: std::net::SocketAddr,
    inbound_disabled: bool,
    rate_limiter: Option<Arc<p2p::limits::RateLimiter>>,
) -> anyhow::Result<RunningConsensus> {
    let validator_set = build_validator_set(cons_cfg, self_id)?;
    info!(
        "consensus: validator_set has {} members",
        validator_set.len()
    );

    let genesis = build_genesis(cons_cfg)?;
    info!("consensus: genesis hash = {:?}", genesis.hash());

    // Resolve genesis BLS keys + reconcile this node's local BLS
    // identity with the chain's scheme (#335). This catches three
    // misconfigurations at startup, before any wire traffic flows:
    //
    //   - BLS chain with no `[node.bls_validator_identity]` configured
    //   - BLS chain whose loaded BLS pubkey is not a genesis validator
    //   - Ed25519 chain with `[node.bls_validator_identity]` set
    //     (BLS keys have no role on an Ed25519 chain)
    let genesis_bls = cons_cfg
        .resolve_genesis_bls_keys()
        .context("validating genesis BLS validator table")?;

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
        limits: cons_cfg.limits.to_cache_limits(),
        snapshot_policy: crate::replication::snapshot::SnapshotPolicy {
            interval_blocks: cons_cfg.snapshot_interval_blocks,
            retention_count: cons_cfg.snapshot_retention_count,
            chunk_size_bytes: cons_cfg.snapshot_chunk_size_bytes,
        },
        min_v_eff_delay: crate::consensus::reconfig::MIN_V_EFF_DELAY,
        signature_scheme: cons_cfg.signature_scheme,
    };

    let state_machine: Arc<Mutex<Box<dyn StateMachine>>> =
        Arc::new(Mutex::new(Box::new(CounterStateMachine::new())));
    let mempool = Arc::new(InMemoryMempool::new(cons_cfg.limits.mempool_capacity));

    // Wire the broadcaster + discovery + upstream event channel
    // according to the configured overlay mode.
    let OverlayWiring {
        broadcaster,
        discovery,
        event_rx,
        overlay_shutdown,
        overlay_joins,
    } = build_overlay_wiring(
        overlay_cfg,
        p2p_cmd_tx,
        discovery_tx,
        *self_id,
        self_listen_addr,
        inbound_disabled,
        dialer_ctx,
        clock,
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

    let mut node =
        ConsensusNode::recover(*self_id, node_cfg, state_machine, mempool, storage, wal)?;
    if let Some(BlsBootstrap { history, identity }) = bls_setup {
        node = node.with_bls_key_history(history);
        let bls_signer: Arc<
            dyn crate::crypto::signed::PartialSigner<crate::crypto::sig_scheme::BlsAggregated>,
        > = Arc::new(crate::crypto::bls_key::BlsPartialSignerImpl::from_identity(
            identity,
        ));
        node = node.with_bls_signer(bls_signer);
    }

    let initial_status = Arc::new(node.build_status());
    let (status_tx, status_rx) = watch::channel(initial_status);
    let mut node = node.with_status_publisher(status_tx);
    if let Some(limiter) = rate_limiter {
        node = node.with_rate_limiter(limiter, Some(p2p_cmd_tx.clone()));
    }

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let signer = Arc::clone(signer) as Arc<dyn crate::crypto::signed::Signer>;
    let join = tokio::spawn(async move {
        node.run(broadcaster, discovery, event_rx, signer, shutdown_rx)
            .await
    });
    info!("consensus: event loop spawned");
    Ok(RunningConsensus {
        join,
        consensus_shutdown: shutdown_tx,
        status_rx,
        overlay_shutdown,
        overlay_joins,
    })
}

/// Bundle returned by [`reconcile_bls_identity`] on `bls_aggregated`
/// chains: the per-historical-view pubkey table (consumed by the
/// dispatch verifier on inbound QCs) plus the loaded validator
/// identity (consumed by the dispatch signer on outbound votes,
/// wrapped in `BlsPartialSignerImpl` in the caller).
#[derive(Debug)]
struct BlsBootstrap {
    history: crate::consensus::bls_key_history::BlsKeyHistory,
    identity: crate::crypto::bls_key::BlsValidatorIdentity,
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
/// [`crate::consensus::bls_key_history::BlsKeyHistory`] (for QC
/// verification at ingress) and the loaded
/// [`crate::crypto::bls_key::BlsValidatorIdentity`] (for partial
/// signing at egress). On an Ed25519 chain, returns `None`.
fn reconcile_bls_identity(
    cons_cfg: &ConsensusConfig,
    bls_identity_config: Option<&BlsIdentityConfig>,
    self_id: &NodeId,
    genesis_bls: &[(NodeId, crate::crypto::sig_scheme::BlsPublicKey)],
    storage: &dyn crate::storage::Storage,
) -> anyhow::Result<Option<BlsBootstrap>> {
    use crate::consensus::bls_key_history::PersistedBlsKeyHistory;
    use crate::consensus::node::STORAGE_KEY_BLS_KEY_HISTORY;
    use crate::crypto::sig_scheme::SignatureSchemeChoice;

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
            let bls_cfg = bls_identity_config.ok_or_else(|| {
                anyhow::anyhow!(
                    "consensus.signature_scheme = \"bls_aggregated\" requires \
                     [node.bls_validator_identity] to be set so the node can produce QC \
                     partials. Configure a BLS key path before booting against this chain.",
                )
            })?;
            let provider = crate::config::build_bls_provider(bls_cfg)
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
                        "consensus: loaded BLS pubkey {} does not match the genesis BLS pubkey \
                         {} for this node ({}). The on-disk BLS key was generated for a \
                         different validator slot.",
                        hex::encode(identity.public),
                        hex::encode(expected_pk),
                        node_id_to_base58(self_id),
                    );
                }
                None => {
                    anyhow::bail!(
                        "consensus: this node ({}) is not a BLS-genesis validator but the \
                         chain's signature_scheme = \"bls_aggregated\". Either add this node \
                         to consensus.validators_bls in genesis, or boot against a chain on \
                         which it is a member.",
                        node_id_to_base58(self_id),
                    );
                }
            }
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
                    crate::consensus::bls_key_history::BlsKeyHistory::from_persisted(persisted)
                        .context("rebuild BlsKeyHistory from persisted form")?
                }
                None => crate::consensus::bls_key_history::BlsKeyHistory::with_genesis(
                    genesis_bls.iter().copied(),
                ),
            };
            Ok(Some(BlsBootstrap { history, identity }))
        }
    }
}

/// Result of [`build_overlay_wiring`]: the broadcaster + discovery +
/// event-receiver triple consensus consumes, plus the overlay-side
/// shutdown / joins (only populated in gossip mode).
struct OverlayWiring {
    broadcaster: Arc<dyn Broadcaster>,
    discovery: Arc<dyn Discovery>,
    event_rx: mpsc::Receiver<p2p::ProtocolEvent>,
    overlay_shutdown: Option<oneshot::Sender<()>>,
    overlay_joins: Vec<tokio::task::JoinHandle<()>>,
}

/// Branch on `overlay_cfg.mode` and assemble the consensus-facing
/// overlay seam.
#[allow(clippy::too_many_arguments)]
async fn build_overlay_wiring(
    overlay_cfg: &OverlayConfig,
    p2p_cmd_tx: &mpsc::Sender<p2p::PeerCommand>,
    discovery_tx: &broadcast::Sender<DiscoveryEvent>,
    self_id: NodeId,
    self_listen_addr: std::net::SocketAddr,
    inbound_disabled: bool,
    dialer_ctx: DialerCtx,
    clock: Arc<dyn Clock>,
) -> anyhow::Result<OverlayWiring> {
    match overlay_cfg.mode {
        OverlayMode::Mesh => {
            // Register the consensus protocol on its own ID; the mesh
            // overlay routes consensus traffic through this channel
            // directly.
            let (reg_tx, reg_rx) = oneshot::channel();
            p2p_cmd_tx
                .send(p2p::PeerCommand::RegisterProtocol {
                    id: crate::consensus::node::PROTOCOL_ID,
                    max_frame_bytes: Some(crate::consensus::node::MAX_FRAME_BYTES),
                    reply: reg_tx,
                })
                .await?;
            let handle = reg_rx.await?;
            info!("overlay: mesh");
            Ok(OverlayWiring {
                broadcaster: Arc::new(MeshBroadcaster::new(handle.send_tx)),
                discovery: MeshDiscovery::spawn(discovery_tx.subscribe()),
                event_rx: handle.event_rx,
                overlay_shutdown: None,
                overlay_joins: Vec::new(),
            })
        }
        OverlayMode::Gossip => {
            // Register the gossip overlay's protocol. Consensus
            // traffic + overlay control frames share this channel
            // (`OverlayFrame::Forward { .. }` vs
            // `OverlayFrame::PeerList(..)`).
            let (reg_tx, reg_rx) = oneshot::channel();
            p2p_cmd_tx
                .send(p2p::PeerCommand::RegisterProtocol {
                    id: crate::p2p::overlay::gossip::PROTOCOL_ID,
                    max_frame_bytes: Some(crate::p2p::overlay::gossip::MAX_FRAME_BYTES),
                    reply: reg_tx,
                })
                .await?;
            let handle = reg_rx.await?;

            let sink = Arc::new(OverlaySink::new(handle.send_tx));
            let dialer = Arc::new(DialerCtxAdapter::new(dialer_ctx));

            // Mix self_id into the rng_seed so each node's RNG draws
            // a different sequence. Take the first 8 bytes of the
            // pubkey — sufficient entropy at validator-set scale.
            let mut seed_bytes = [0u8; 8];
            seed_bytes.copy_from_slice(&self_id[0..8]);
            let rng_seed = u64::from_le_bytes(seed_bytes);
            let cfg = GossipOverlayConfig::from_config(overlay_cfg, rng_seed);

            // In outbound-only mode (issue #138) the listener was
            // never bound, so there is no advertisable listen address.
            // Pass `None` so the publisher omits the self-entry —
            // peers learn about us only through whichever connection
            // we initiated, and our `reachable = false` advertisement
            // is carried by the publisher's `self_reachable` flag.
            let advertise_addr = if inbound_disabled {
                None
            } else {
                Some(self_listen_addr)
            };
            let handles = GossipOverlay::spawn(SpawnArgs {
                self_id,
                self_listen_addr: advertise_addr,
                self_reachable: !inbound_disabled,
                event_rx: handle.event_rx,
                sink,
                dialer,
                clock,
                config: cfg,
            });

            // Boot-time bootstrap ingestion. Each `add_bootstrap`
            // call triggers a TOFU dial via the Dialer plumbed into
            // `GossipDiscovery`.
            for addr in &overlay_cfg.bootstrap_addrs {
                handles.discovery.add_bootstrap(*addr);
            }

            info!(
                "overlay: gossip (target_degree={}, bootstrap_addrs={})",
                overlay_cfg.target_degree,
                overlay_cfg.bootstrap_addrs.len()
            );

            let broadcaster: Arc<dyn Broadcaster> = Arc::new(handles.broadcaster);
            let discovery: Arc<dyn overlay_traits::Discovery> = handles.discovery;
            Ok(OverlayWiring {
                broadcaster,
                discovery,
                event_rx: handles.event_rx,
                overlay_shutdown: Some(handles.shutdown),
                overlay_joins: vec![
                    handles.overlay_join,
                    handles.publisher_join,
                    handles.maintenance_join,
                ],
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
    if !ids.iter().any(|id| id == self_id) {
        anyhow::bail!(
            "[consensus.validators] does not include this node's own ID {}",
            node_id_to_base58(self_id),
        );
    }
    Ok(ValidatorSet::new(ids))
}

/// Build the genesis block from the optional `genesis_seed_hex` config
/// field. Defaults to all-zeros when unset.
fn build_genesis(cfg: &ConsensusConfig) -> anyhow::Result<Block> {
    let mut seed = [0u8; 32];
    if let Some(hex) = &cfg.genesis_seed_hex {
        let bytes = decode_hex32(hex)
            .ok_or_else(|| anyhow::anyhow!("genesis_seed_hex must be 64 hex chars (32 bytes)"))?;
        seed = bytes;
    }
    Ok(Block::genesis(seed))
}

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_nibble(s.as_bytes()[2 * i])?;
        let lo = hex_nibble(s.as_bytes()[2 * i + 1])?;
        *byte = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConsensusLimits;
    use crate::consensus::limits::DEFAULT_VOTE_BUCKET_CAPACITY;
    use crate::crypto::bls_key::{BlsKeyFile, BlsKeyProvider as _};
    use crate::crypto::sig_scheme::{BlsAggregated, BlsPublicKey, SignatureSchemeChoice};
    use crate::storage::MemoryStorage;
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
            genesis_seed_hex: None,
            propose_limit: 64,
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
        }
    }

    fn nid(b: u8) -> NodeId {
        [b; 32]
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
    fn ed25519_chain_with_no_bls_config_returns_none() {
        let cfg = cons_cfg(SignatureSchemeChoice::Ed25519Collected);
        let storage = empty_storage();
        let res = reconcile_bls_identity(&cfg, None, &nid(1), &[], storage.as_ref()).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn ed25519_chain_with_bls_config_is_rejected() {
        let cfg = cons_cfg(SignatureSchemeChoice::Ed25519Collected);
        let bls_cfg = BlsIdentityConfig::File {
            path: PathBuf::from("/tmp/unused.key"),
            allow_insecure_perms: false,
        };
        let storage = empty_storage();
        let err = reconcile_bls_identity(&cfg, Some(&bls_cfg), &nid(1), &[], storage.as_ref())
            .unwrap_err();
        assert!(err.to_string().contains("ed25519_collected"), "{err}");
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
        assert_eq!(bootstrap.identity.public, pk);
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
        use crate::consensus::bls_key_history::BlsKeyHistory;
        use crate::consensus::node::STORAGE_KEY_BLS_KEY_HISTORY;
        use crate::storage::Storage as _;

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
        assert_eq!(reloaded.identity.public, pk);
    }
}
