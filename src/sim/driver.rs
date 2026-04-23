//! [`SimDriver`]: builds N nodes, wires them into a fully-connected mesh
//! through in-memory duplex pipes, and exposes test-facing controls
//! (inject gossip, advance time, run-until-quiescent, inspect stores).
//!
//! Tests using the driver must run on a `current_thread` runtime started
//! with `start_paused = true` so the [`SimClock`] cooperates with tokio's
//! virtual timer.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::clock::Clock;
use crate::gossip::{self, GossipMessage, store::GossipStore, wire::WireMessage};
use crate::p2p::manager::{AnyStream, ManagerMsg};
use crate::p2p::{ConnectionProtocol, NodeId, PeerCommand, ProtocolOutbound};

use super::SimClock;
use super::network::SimNetwork;
use super::transport::SimConnectionProtocol;

/// Default duplex pipe buffer size. Generous enough that test-scale gossip
/// won't block in [`tokio::io::AsyncWrite::poll_write`].
const DUPLEX_BUF: usize = 64 * 1024;

/// One sim node — manager + gossip engine + send handle for injecting messages.
pub struct SimNode {
    pub node_id: NodeId,
    pub store: Arc<GossipStore>,
    gossip_send_tx: mpsc::Sender<ProtocolOutbound>,
    /// Held to keep the manager alive; dropped on [`SimDriver`] drop.
    _cmd_tx: mpsc::Sender<PeerCommand>,
    /// Background tasks; held so they're cancelled on drop.
    _tasks: Vec<JoinHandle<()>>,
}

impl SimNode {
    /// Inject a gossip message at this node as if a local API client had
    /// posted it. Inserts into the local store and broadcasts to peers.
    pub async fn inject_gossip(&self, msg: GossipMessage, clock: &dyn Clock) {
        // Mirror the API path: try_insert + broadcast.
        match self.store.try_insert(msg.clone(), clock.now_wall()) {
            gossip::InsertResult::Inserted => {
                let encoded = serde_json::to_vec(&WireMessage::Gossip(msg))
                    .expect("WireMessage serialization cannot fail");
                let _ = self
                    .gossip_send_tx
                    .send(ProtocolOutbound::Broadcast(Bytes::from(encoded)))
                    .await;
            }
            gossip::InsertResult::AlreadySeen | gossip::InsertResult::Expired => {}
        }
    }

    /// Snapshot of currently-live messages in this node's store.
    pub fn messages(&self, now: DateTime<Utc>) -> Vec<GossipMessage> {
        self.store.list_live(now)
    }
}

pub struct SimDriver {
    pub clock: Arc<SimClock>,
    nodes: Vec<SimNode>,
    #[allow(dead_code)] // Held for sub-task #30 (fault injection) to consume.
    network: Arc<SimNetwork>,
}

impl SimDriver {
    /// Build a fully-connected mesh of `n` nodes. Must be called from inside
    /// a tokio `current_thread` runtime with `start_paused = true`.
    pub async fn new(n: usize, seed: u64) -> Self {
        let clock = Arc::new(SimClock::new(Utc::now()));
        let network = SimNetwork::new(seed);

        // Generate distinct deterministic NodeIds. We seed from `n` so a
        // larger mesh doesn't reuse a smaller one's IDs across tests.
        let node_ids: Vec<NodeId> = (0..n).map(deterministic_node_id).collect();

        // For each unordered pair (i, j) with i < j, create a duplex pipe.
        // node `i` gets the `a` half mapped to peer `j`; node `j` gets the
        // `b` half mapped to peer `i`.
        let mut per_node_streams: Vec<Vec<(NodeId, SocketAddr, AnyStream)>> =
            (0..n).map(|_| Vec::new()).collect();
        for i in 0..n {
            for j in (i + 1)..n {
                let (a, b) = tokio::io::duplex(DUPLEX_BUF);
                per_node_streams[i].push((node_ids[j], sim_addr(j), Box::new(a)));
                per_node_streams[j].push((node_ids[i], sim_addr(i), Box::new(b)));
            }
        }

        let mut nodes = Vec::with_capacity(n);
        for (idx, peer_streams) in per_node_streams.into_iter().enumerate() {
            let node = build_node(node_ids[idx], peer_streams, Arc::clone(&clock) as _).await;
            nodes.push(node);
        }

        Self {
            clock,
            nodes,
            network,
        }
    }

    pub fn node(&self, idx: usize) -> &SimNode {
        &self.nodes[idx]
    }

    pub fn nodes(&self) -> &[SimNode] {
        &self.nodes
    }

    /// Advance both the virtual wall clock and tokio's paused timer by `dur`.
    /// After this returns, any tokio sleep or interval scheduled to fire
    /// within the elapsed window will be ready to make progress.
    pub async fn advance(&self, dur: Duration) {
        self.clock.advance_wall(dur);
        tokio::time::advance(dur).await;
    }

    /// Yield repeatedly until no node makes observable progress for
    /// `quiescent_passes` consecutive yields, or the wall-clock budget
    /// `max_real_wait` is exhausted.
    ///
    /// "Observable progress" is measured as the sum of stored message
    /// counts across nodes. This is a coarse proxy that's good enough for
    /// the gossip-flood test; later sub-issues will replace it with an
    /// event-queue-aware drain once the central scheduler exists.
    pub async fn run_until_quiescent(&self) {
        const QUIESCENT_PASSES: usize = 8;
        const MAX_PASSES: usize = 10_000;

        let mut last_total = self.total_messages();
        let mut stable = 0usize;
        for _ in 0..MAX_PASSES {
            tokio::task::yield_now().await;
            let now_total = self.total_messages();
            if now_total == last_total {
                stable += 1;
                if stable >= QUIESCENT_PASSES {
                    return;
                }
            } else {
                stable = 0;
                last_total = now_total;
            }
        }
    }

    fn total_messages(&self) -> usize {
        let now = self.clock.now_wall();
        self.nodes
            .iter()
            .map(|n| n.store.list_live(now).len())
            .sum()
    }
}

fn sim_addr(idx: usize) -> SocketAddr {
    // Loopback in the documentation/test range. Only used for log lines.
    SocketAddr::from(([127, 0, 0, 1], 65000 + idx as u16))
}

fn deterministic_node_id(idx: usize) -> NodeId {
    // Distinct, deterministic, easy to read in logs. NodeId is `[u8; 32]`.
    let mut id = [0u8; 32];
    id[31] = idx as u8;
    id[30] = (idx >> 8) as u8;
    // Avoid the all-zero ID, which the manager treats specially in some
    // log lines and which is reserved as a "no peer" sentinel by tests.
    id[0] = 0xA1;
    id
}

async fn build_node(
    our_id: NodeId,
    peer_streams: Vec<(NodeId, SocketAddr, AnyStream)>,
    clock: Arc<dyn Clock>,
) -> SimNode {
    let (cmd_tx, cmd_rx) = mpsc::channel::<PeerCommand>(256);
    let (internal_tx, internal_rx) = mpsc::channel::<ManagerMsg>(256);
    let (peer_gone_tx, _) = broadcast::channel::<NodeId>(64);

    let manager_handle = {
        let itx = internal_tx.clone();
        let pgt = peer_gone_tx.clone();
        tokio::spawn(crate::p2p::manager::run(
            our_id,
            cmd_rx,
            internal_rx,
            itx,
            pgt,
        ))
    };

    let store = Arc::new(GossipStore::new());

    // Register the gossip protocol BEFORE the connection protocol fires
    // NewConnection events, so PeerConnected isn't lost.
    let (reg_tx, reg_rx) = oneshot::channel();
    cmd_tx
        .send(PeerCommand::RegisterProtocol {
            id: gossip::PROTOCOL_ID,
            reply: reg_tx,
        })
        .await
        .expect("manager alive");
    let gossip_handle = reg_rx.await.expect("manager replies");
    let gossip_send_tx = gossip_handle.send_tx.clone();

    let engine_handle = {
        let store = Arc::clone(&store);
        let clock = Arc::clone(&clock);
        tokio::spawn(gossip::engine::run(gossip_handle, store, clock))
    };

    // Hand pre-established peer streams to the manager via the
    // SimConnectionProtocol shim.
    let protocol = SimConnectionProtocol {
        peers: peer_streams,
    };
    let protocol_handle = tokio::spawn(protocol.run(internal_tx, peer_gone_tx));

    SimNode {
        node_id: our_id,
        store,
        gossip_send_tx,
        _cmd_tx: cmd_tx,
        _tasks: vec![manager_handle, engine_handle, protocol_handle],
    }
}
