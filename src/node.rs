//! Top-level node runtime: wires the transport, gossip, ping RPC and
//! optional HotStuff consensus into a single ctrl-c-driven process.
//!
//! Lives in the library (rather than `main.rs`) so the integration
//! tests and the `start` subcommand share one definition of "what a
//! running node looks like".

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tracing::{info, warn};

use crate::clock::{Clock, TokioClock};
use crate::config::{Config, ConsensusConfig};
use crate::consensus::node::{ConsensusNode, NodeConfigForConsensus};
use crate::consensus::status::ConsensusStatus;
use crate::consensus::validator_set::ValidatorSet;
use crate::crypto::signed::NodeSigner;
use crate::gossip;
use crate::p2p::identity::NodeIdentity;
use crate::p2p::manager::ManagerMsg;
use crate::p2p::tls::{NodeId, TlsIdentity, base58_to_node_id, node_id_to_base58};
use crate::p2p::tls_protocol::TlsConnectionProtocol;
use crate::p2p::{self, ConnectionProtocol};
use crate::ping;
use crate::replication::block::Block;
use crate::replication::impls::{CounterStateMachine, InMemoryMempool};
use crate::replication::state_machine::StateMachine;
use crate::storage::{DiskStorage, DiskWal, MemoryStorage, MemoryWal, Storage, Wal};

/// Run a node from a fully-resolved configuration and an already-loaded
/// identity. Blocks until ctrl-c, then drains tasks and returns.
pub async fn run(config: Config, node_identity: NodeIdentity) -> anyhow::Result<()> {
    let identity = Arc::new(TlsIdentity::from_identity(&node_identity)?);
    let consensus_signer = Arc::new(NodeSigner::from_identity(&node_identity)?);
    drop(node_identity);

    info!("node ID: {}", node_id_to_base58(&identity.node_id));

    let clock: Arc<dyn Clock> = Arc::new(TokioClock::new());
    let store = Arc::new(gossip::store::GossipStore::new());

    let (p2p_cmd_tx, p2p_cmd_rx) = mpsc::channel::<p2p::PeerCommand>(256);
    let (internal_tx, internal_rx) = mpsc::channel::<ManagerMsg>(256);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (peer_gone_tx, _) = broadcast::channel::<p2p::NodeId>(64);

    let manager_handle = {
        let itx = internal_tx.clone();
        let pgt = peer_gone_tx.clone();
        let our_id = identity.node_id;
        tokio::spawn(p2p::manager::run(our_id, p2p_cmd_rx, internal_rx, itx, pgt))
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

    // Optionally start consensus. When the [consensus] section is
    // present, the protocol is registered, the ConsensusNode is
    // constructed (with disk storage if configured, otherwise in-memory)
    // and its `run` loop is spawned. A oneshot shutdown sender is kept
    // so we can stop the loop gracefully on ctrl-c.
    let consensus_runtime = if let Some(cons_cfg) = config.consensus.as_ref() {
        Some(start_consensus(cons_cfg, &p2p_cmd_tx, &identity.node_id, &consensus_signer).await?)
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
        if let Some((_, _, ref status_rx)) = consensus_runtime {
            app = app.merge(crate::consensus::api::router(status_rx.clone()));
        }
        tokio::spawn(async move {
            info!("HTTP API listening on {api_actual_addr}");
            axum::serve(api_listener, app).await.unwrap();
        })
    };

    // Bind the P2P listener before spawning the protocol so the actual port is
    // known before we write addr_file.
    let p2p_listener = TcpListener::bind(config.node.listen_addr).await?;
    let p2p_actual_addr = p2p_listener.local_addr()?;
    info!("P2P listening on {p2p_actual_addr}");

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

    let consensus_join = consensus_runtime.map(|(handle, sd, _status_rx)| {
        let _ = sd.send(());
        handle
    });

    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        let _ = manager_handle.await;
        let _ = engine_handle.await;
        let _ = cleanup_handle.await;
        let _ = api_handle.await;
        let _ = protocol_handle.await;
        if let Some(h) = consensus_join {
            let _ = h.await;
        }
    })
    .await;

    Ok(())
}

/// Start the HotStuff consensus protocol alongside gossip + ping.
///
/// Returns the run-loop join handle and the oneshot shutdown sender; the
/// caller fires the sender on ctrl-c and awaits the handle for graceful
/// exit.
async fn start_consensus(
    cons_cfg: &ConsensusConfig,
    p2p_cmd_tx: &mpsc::Sender<p2p::PeerCommand>,
    self_id: &NodeId,
    signer: &Arc<NodeSigner>,
) -> anyhow::Result<(
    tokio::task::JoinHandle<anyhow::Result<()>>,
    oneshot::Sender<()>,
    watch::Receiver<Arc<ConsensusStatus>>,
)> {
    let validator_set = build_validator_set(cons_cfg, self_id)?;
    info!(
        "consensus: validator_set has {} members",
        validator_set.len()
    );

    let genesis = build_genesis(cons_cfg)?;
    info!("consensus: genesis hash = {:?}", genesis.hash());

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
    };

    let state_machine: Arc<Mutex<Box<dyn StateMachine>>> =
        Arc::new(Mutex::new(Box::new(CounterStateMachine::new())));
    let mempool = Arc::new(InMemoryMempool::new(1024));

    let (reg_tx, reg_rx) = oneshot::channel();
    p2p_cmd_tx
        .send(p2p::PeerCommand::RegisterProtocol {
            id: crate::consensus::node::PROTOCOL_ID,
            max_frame_bytes: Some(crate::consensus::node::MAX_FRAME_BYTES),
            reply: reg_tx,
        })
        .await?;
    let consensus_handle = reg_rx.await?;

    let node = ConsensusNode::recover(*self_id, node_cfg, state_machine, mempool, storage, wal)?;

    let initial_status = Arc::new(node.build_status());
    let (status_tx, status_rx) = watch::channel(initial_status);
    let node = node.with_status_publisher(status_tx);

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let signer = Arc::clone(signer) as Arc<dyn crate::crypto::signed::Signer>;
    let join = tokio::spawn(async move { node.run(consensus_handle, signer, shutdown_rx).await });
    info!("consensus: event loop spawned");
    Ok((join, shutdown_tx, status_rx))
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
