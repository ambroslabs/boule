//! [`SimDriver`]: builds N nodes, wires them into a fully-connected mesh
//! through scheduler-driven [`SimStream`] pairs, and exposes test-facing
//! controls (inject gossip, advance time, run-until-quiescent, configure
//! per-link faults, partition/heal).
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
use super::network::{EventId, InFlightEvent, LinkConfig, SimNetwork, TraceEntry};
use super::stream::{Inbox, SimStream};
use super::transport::SimConnectionProtocol;

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
    pub network: Arc<SimNetwork>,
}

impl SimDriver {
    /// Build a fully-connected mesh of `n` nodes. Must be called from inside
    /// a tokio `current_thread` runtime with `start_paused = true`.
    pub async fn new(n: usize, seed: u64) -> Self {
        Self::new_with_start(n, seed, Utc::now()).await
    }

    /// Like [`new`] but uses an explicit virtual wall-clock starting
    /// instant. Useful for determinism tests that want byte-identical
    /// traces across runs.
    ///
    /// [`new`]: Self::new
    pub async fn new_with_start(n: usize, seed: u64, start_now: DateTime<Utc>) -> Self {
        let clock = Arc::new(SimClock::new(start_now));
        let network = SimNetwork::new(seed, start_now);

        let node_ids: Vec<NodeId> = (0..n).map(deterministic_node_id).collect();

        // For each unordered pair (i, j) with i < j, create two scheduler-
        // driven streams (one per direction). Each side gets a SimStream
        // configured with its outbound (from, to) and the inbound inbox the
        // network will deliver to.
        let mut per_node_streams: Vec<Vec<(NodeId, SocketAddr, AnyStream)>> =
            (0..n).map(|_| Vec::new()).collect();
        for i in 0..n {
            for j in (i + 1)..n {
                let ai = node_ids[i];
                let aj = node_ids[j];

                // Inboxes: where bytes get delivered for each direction.
                let inbox_to_i = Inbox::new(); // bytes flowing j → i land here
                let inbox_to_j = Inbox::new(); // bytes flowing i → j land here

                network.register_inbox(aj, ai, Arc::clone(&inbox_to_i));
                network.register_inbox(ai, aj, Arc::clone(&inbox_to_j));

                // i's stream: writes go i → j; reads pull from inbox_to_i.
                let s_i = SimStream::new(Arc::clone(&network), ai, aj, inbox_to_i);
                // j's stream: writes go j → i; reads pull from inbox_to_j.
                let s_j = SimStream::new(Arc::clone(&network), aj, ai, inbox_to_j);

                per_node_streams[i].push((aj, sim_addr(j), Box::new(s_i) as AnyStream));
                per_node_streams[j].push((ai, sim_addr(i), Box::new(s_j) as AnyStream));
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

    pub fn node_id(&self, idx: usize) -> NodeId {
        self.nodes[idx].node_id
    }

    /// Configure both directions of the link between two nodes to the given
    /// config. For asymmetric links use [`set_link_directional`].
    pub fn set_link(&self, a_idx: usize, b_idx: usize, config: LinkConfig) {
        let a = self.node_id(a_idx);
        let b = self.node_id(b_idx);
        self.network.set_link(a, b, config.clone());
        self.network.set_link(b, a, config);
    }

    pub fn set_link_directional(&self, from_idx: usize, to_idx: usize, config: LinkConfig) {
        self.network
            .set_link(self.node_id(from_idx), self.node_id(to_idx), config);
    }

    /// Take down both directions of the link between two nodes.
    pub fn partition_pair(&self, a_idx: usize, b_idx: usize) {
        self.network
            .partition(self.node_id(a_idx), self.node_id(b_idx));
    }

    /// Re-enable both directions of the link between two nodes.
    pub fn heal_pair(&self, a_idx: usize, b_idx: usize) {
        self.network.heal(self.node_id(a_idx), self.node_id(b_idx));
    }

    /// Cut every link between the two groups (bidirectional). Links inside
    /// each group are untouched.
    pub fn partition_groups(&self, group_a: &[usize], group_b: &[usize]) {
        for &i in group_a {
            for &j in group_b {
                if i != j {
                    self.partition_pair(i, j);
                }
            }
        }
    }

    /// Re-enable every link between the two groups.
    pub fn heal_groups(&self, group_a: &[usize], group_b: &[usize]) {
        for &i in group_a {
            for &j in group_b {
                if i != j {
                    self.heal_pair(i, j);
                }
            }
        }
    }

    // ---- Adversary API ----

    /// Freeze a node: inbound bytes accumulate in its inboxes but its reader
    /// is not woken; outbound writes from this node are dropped. Use
    /// [`resume_node`] to release.
    ///
    /// [`resume_node`]: Self::resume_node
    pub fn pause_node(&self, idx: usize) {
        self.network.pause(self.node_id(idx));
    }

    /// Un-freeze a node and wake its inbox readers so bytes buffered during
    /// the pause can be consumed.
    pub fn resume_node(&self, idx: usize) {
        self.network.resume(self.node_id(idx));
    }

    /// Permanently take `idx` offline. Aborts its background tasks, closes
    /// every inbox it owns or writes to so peers see EOF on connection
    /// reads, and refuses any further writes from or to this node.
    ///
    /// Restarting a killed node (persistent-state recovery) is follow-up
    /// work that needs milestone-4 state to be meaningful.
    pub fn kill_node(&self, idx: usize) {
        let id = self.node_id(idx);
        self.network.kill(id);
        for handle in &self.nodes[idx]._tasks {
            handle.abort();
        }
    }

    /// Non-destructive snapshot of events currently in the main heap.
    pub fn in_flight_events(&self) -> Vec<InFlightEvent> {
        self.network.in_flight_events()
    }

    /// Pop the scheduled event with `id` and deliver it immediately,
    /// bypassing its scheduled time. Returns `false` if `id` was not found
    /// (already delivered or never enqueued).
    pub fn deliver_next(&self, id: EventId) -> bool {
        self.network.deliver_event_now(id)
    }

    /// Enqueue a copy of the event with `id` at the same scheduled time.
    /// The duplicate gets a fresh [`EventId`], returned to the caller.
    pub fn duplicate_event(&self, id: EventId) -> Option<EventId> {
        self.network.duplicate_event(id)
    }

    // ---- Determinism trace ----

    /// Non-destructive snapshot of the delivery trace so far.
    pub fn trace(&self) -> Vec<TraceEntry> {
        self.network.trace_snapshot()
    }

    /// Consume the delivery trace and return it.
    pub fn drain_trace(&self) -> Vec<TraceEntry> {
        self.network.drain_trace()
    }

    // ---- Convergence assertion helpers ----

    /// Collect every node's live-message content sets (sorted) at the
    /// driver's current virtual wall time.
    pub fn per_node_contents(&self) -> Vec<Vec<String>> {
        let now = self.clock.now_wall();
        self.nodes
            .iter()
            .map(|n| {
                let mut contents: Vec<String> =
                    n.messages(now).into_iter().map(|m| m.content).collect();
                contents.sort();
                contents
            })
            .collect()
    }

    /// Assert every node's live-message contents match `expected` (as a
    /// sorted set). Panics with a diff on mismatch.
    pub fn assert_all_converged_to(&self, expected: &[&str]) {
        let mut expected_sorted: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
        expected_sorted.sort();
        let actual = self.per_node_contents();
        for (i, contents) in actual.iter().enumerate() {
            assert_eq!(
                contents, &expected_sorted,
                "node {i} did not converge to {expected_sorted:?}, saw {contents:?}",
            );
        }
    }

    /// Assert every node has seen `content`.
    pub fn assert_all_have(&self, content: &str) {
        let per_node = self.per_node_contents();
        for (i, contents) in per_node.iter().enumerate() {
            assert!(
                contents.iter().any(|c| c == content),
                "node {i} missing message {content:?}, saw {contents:?}",
            );
        }
    }

    /// Assert no node has seen `content`.
    pub fn assert_none_have(&self, content: &str) {
        let per_node = self.per_node_contents();
        for (i, contents) in per_node.iter().enumerate() {
            assert!(
                !contents.iter().any(|c| c == content),
                "node {i} unexpectedly has message {content:?}, saw {contents:?}",
            );
        }
    }

    /// Advance both the virtual wall clock and tokio's paused timer by `dur`.
    pub async fn advance(&self, dur: Duration) {
        self.clock.advance_wall(dur);
        self.network.set_now(self.clock.now_wall());
        tokio::time::advance(dur).await;
    }

    /// Drive the simulation until no scheduled events remain and tasks have
    /// stopped emitting new ones for several consecutive yield rounds.
    ///
    /// Algorithm:
    /// 1. Yield to let writer tasks push fresh events into the network.
    /// 2. Flush reorder buffers (so partial windows aren't stranded).
    /// 3. While the queue is non-empty, pop the next event, advance virtual
    ///    time to its scheduled instant (in lockstep with tokio's paused
    ///    timer), deliver bytes, yield to let the reader task consume.
    /// 4. Repeat until N consecutive idle passes show no new events.
    pub async fn run_until_quiescent(&self) {
        const QUIESCENT_PASSES: usize = 8;
        const MAX_PASSES: usize = 100_000;

        let mut idle = 0usize;
        for _ in 0..MAX_PASSES {
            // Let writer tasks push.
            tokio::task::yield_now().await;

            self.network.flush_reorder_buffers();

            let mut delivered_any = false;
            while let Some(target_time) = self.network.try_deliver_one() {
                self.advance_clock_to(target_time).await;
                delivered_any = true;
                // Let the reader task consume the bytes before the next pop.
                tokio::task::yield_now().await;
            }

            if delivered_any {
                idle = 0;
            } else {
                idle += 1;
                if idle >= QUIESCENT_PASSES {
                    return;
                }
            }
        }
    }

    /// Advance the virtual wall clock and tokio's paused timer to `target`.
    /// No-op if `target` is in the past.
    async fn advance_clock_to(&self, target: DateTime<Utc>) {
        let now = self.clock.now_wall();
        if target <= now {
            return;
        }
        let delta = target
            .signed_duration_since(now)
            .to_std()
            .unwrap_or_default();
        if delta.is_zero() {
            return;
        }
        self.advance(delta).await;
    }
}

fn sim_addr(idx: usize) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 65000 + idx as u16))
}

fn deterministic_node_id(idx: usize) -> NodeId {
    let mut id = [0u8; 32];
    id[31] = idx as u8;
    id[30] = (idx >> 8) as u8;
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
