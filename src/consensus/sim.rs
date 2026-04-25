//! In-memory simulation cluster for consensus integration testing.
//!
//! [`SimCluster::spawn`] wires `n` [`ConsensusNode`] instances together
//! using channel-backed [`ProtocolHandle`]s and a per-node routing task
//! that translates each outbound [`ProtocolOutbound`] into an inbound
//! [`ProtocolEvent`] on the target node(s).
//!
//! # Bootstrap
//!
//! [`ConsensusNode::new`] seeds every node with the cluster-agreed
//! genesis QC on construction (see
//! [`crate::consensus::hotstuff::genesis_qc`]). With the genesis QC in
//! place the view-1 leader proposes immediately on boot, and the cluster
//! makes progress through message passing alone — no view-timer fires
//! are required for the happy path.
//!
//! # Topology
//!
//! `Broadcast` is delivered to every node **except** the sender and
//! `SendTo` is delivered exactly to the named peer — matching production
//! p2p semantics (`src/p2p/manager.rs`). Self-addressed consensus
//! actions are looped back inside the integration layer itself (see
//! [`ConsensusNode`] / issue #118); delivering them here as well would
//! double-feed the safety core and mask regressions of the loopback.
//! Messages are delivered in-order per sender (channels are FIFO).
//!
//! # Fault injection
//!
//! [`SimCluster::partition_node`] / [`heal_node`] toggle a shared
//! "partitioned" set that the routing tasks check before forwarding any
//! frame; a partitioned node neither sends nor receives. [`kill_node`]
//! sends a shutdown signal to the node's run loop, permanently removes
//! the killed peer from routing, and dispatches `PeerDisconnected` to
//! every surviving node — matching the production peer-crash semantics
//! established by `src/p2p/manager.rs` when a TLS peer drops.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::{mpsc, oneshot};

use crate::consensus::node::{ConsensusNode, NodeConfigForConsensus};
use crate::consensus::validator_set::ValidatorSet;
use crate::crypto::signed::{NodeSigner, Signer};
use crate::p2p::identity::NodeIdentity;
use crate::p2p::{NodeId, ProtocolEvent, ProtocolHandle, ProtocolOutbound};
use crate::replication::block::{Block, BlockHash};
use crate::replication::impls::{CounterStateMachine, InMemoryMempool};
use crate::replication::state_machine::StateMachine;
use crate::storage::{MemoryStorage, MemoryWal};
use rcgen::{KeyPair as RcgenKeyPair, PKCS_ED25519};
use zeroize::Zeroizing;

/// A directed edge `(from, to)` on which all messages are silently dropped
/// by the routing layer, regardless of the partition set.
///
/// Used to simulate one-way link failures such as vote-withholding
/// (outbound links from a Byzantine replica cut, inbound intact).
type LinkCut = (NodeId, NodeId);

/// An in-memory cluster of N consensus nodes connected by channel-backed
/// protocol handles.
///
/// Obtain via [`SimCluster::spawn`]. The caller drives time with
/// `tokio::time::pause()` + `advance()` or with `yield_now()` loops.
///
/// Dropping the cluster sends shutdown to all still-running nodes.
pub struct SimCluster {
    /// Per-node commit receivers, in ascending [`NodeId`] (sorted) order.
    pub commit_rxs: Vec<mpsc::UnboundedReceiver<Block>>,
    /// Node IDs in the same sorted order as `commit_rxs`.
    pub node_ids: Vec<NodeId>,
    /// Set of partitioned nodes. Routing tasks drop all messages to/from
    /// any node whose ID is in this set.
    pub partitioned: Arc<Mutex<HashSet<NodeId>>>,
    /// Directed link cuts `(from, to)`. The routing task for `from` will
    /// not deliver any frame to `to` while the pair is present, even if
    /// neither node is in the global partition set. Used to simulate
    /// one-way faults (e.g. vote-withholding without full isolation).
    pub link_cuts: Arc<Mutex<HashSet<LinkCut>>>,
    /// Set of permanently killed nodes. Routing tasks drop every frame
    /// targeting a dead node (matching production, where the TLS peer
    /// is absent from `manager.rs`'s `peers` map). Unlike `partitioned`
    /// this set is append-only — `kill_node` is irreversible.
    pub dead_nodes: Arc<Mutex<HashSet<NodeId>>>,
    /// Inbound event senders, one per node, shared with the routing
    /// tasks. `kill_node` uses this map to dispatch `PeerDisconnected`
    /// to every survivor at kill time.
    event_txs: Arc<HashMap<NodeId, mpsc::Sender<ProtocolEvent>>>,
    /// Commits buffered by [`SimCluster::peek_commit_heights`] so that
    /// non-destructive height snapshots do not steal blocks from the
    /// next [`SimCluster::drain_commits`] call. `drain_commits` takes
    /// and resets this buffer in the same call that flushes the
    /// `commit_rxs`.
    commit_cache: Vec<Vec<Block>>,
    /// Shutdown senders; `None` after `kill_node` has been called for that slot.
    shutdown_txs: Vec<Option<oneshot::Sender<()>>>,
}

impl SimCluster {
    /// Spawn `n` honest nodes wired together over in-memory channels.
    ///
    /// Each node gets a fresh Ed25519 key, an empty
    /// [`CounterStateMachine`], an empty [`InMemoryMempool`], and a
    /// pre-seeded genesis QC so the view-1 leader can propose on first
    /// boot.
    ///
    /// `timeout_base` is the view-timer base duration. Set it short
    /// (e.g. `50ms`) for tests that need timer-driven view changes.
    ///
    /// # Panics
    ///
    /// Panics if `n < 4` (minimum BFT cluster size for `f = 1`).
    pub async fn spawn(n: usize, timeout_base: Duration) -> Self {
        assert!(n >= 4, "BFT requires at least 4 nodes (3f+1 with f=1)");

        // Create N fresh signers and collect their node IDs.
        let signers: Vec<NodeSigner> = (0..n).map(|_| fresh_signer()).collect();
        let node_ids_unsorted: Vec<NodeId> = signers.iter().map(|s| s.node_id()).collect();

        // ValidatorSet sorts IDs ascending, establishing leader-rotation order.
        let vs = ValidatorSet::new(node_ids_unsorted);
        let genesis = Block::genesis([0u8; 32]);

        // Build a signer lookup by NodeId.
        let signer_map: HashMap<NodeId, Arc<dyn Signer>> = signers
            .into_iter()
            .map(|s| (s.node_id(), Arc::new(s) as Arc<dyn Signer>))
            .collect();

        // Shared partition set: routing tasks check this before forwarding.
        let partitioned: Arc<Mutex<HashSet<NodeId>>> = Arc::new(Mutex::new(HashSet::new()));
        // Directed link cuts: messages from `src` to `dst` are dropped.
        let link_cuts: Arc<Mutex<HashSet<LinkCut>>> = Arc::new(Mutex::new(HashSet::new()));
        // Shared dead-node set: routing tasks drop every frame targeting
        // a dead node and also short-circuit outbound frames from a node
        // that has already been killed.
        let dead_nodes: Arc<Mutex<HashSet<NodeId>>> = Arc::new(Mutex::new(HashSet::new()));

        // Per-node event channel: routing tasks write here; each node's
        // run() loop reads from its receiver.
        let mut event_txs: HashMap<NodeId, mpsc::Sender<ProtocolEvent>> = HashMap::new();
        let mut event_rxs: Vec<(NodeId, mpsc::Receiver<ProtocolEvent>)> = Vec::new();
        for &nid in vs.iter() {
            let (tx, rx) = mpsc::channel(1024);
            event_txs.insert(nid, tx);
            event_rxs.push((nid, rx));
        }
        let event_txs = Arc::new(event_txs);

        let node_ids: Vec<NodeId> = vs.iter().copied().collect();
        let mut commit_rxs: Vec<mpsc::UnboundedReceiver<Block>> = Vec::new();
        let mut shutdown_txs: Vec<Option<oneshot::Sender<()>>> = Vec::new();

        for (nid, event_rx) in event_rxs {
            let signer = signer_map[&nid].clone();

            let config = NodeConfigForConsensus {
                validator_set: vs.clone(),
                genesis: genesis.clone(),
                propose_limit: 16,
                timeout_base,
                timeout_max: Duration::from_secs(30),
            };

            let sm: Arc<Mutex<Box<dyn StateMachine>>> =
                Arc::new(Mutex::new(Box::new(CounterStateMachine::new())));
            let mempool = Arc::new(InMemoryMempool::new(256));
            let storage = Arc::new(MemoryStorage::new());
            let wal = Arc::new(MemoryWal::new());

            let (commit_tx, commit_rx) = mpsc::unbounded_channel::<Block>();
            commit_rxs.push(commit_rx);

            // ConsensusNode::new already auto-seeds the cluster-agreed
            // genesis QC; no explicit with_genesis_qc override here.
            let node = ConsensusNode::new(nid, config, sm, mempool, storage, wal)
                .with_commit_observer(commit_tx);

            // Per-node outbound channel: node writes here; routing task reads.
            let (send_tx, send_rx) = mpsc::channel::<ProtocolOutbound>(1024);
            let handle = ProtocolHandle { send_tx, event_rx };

            spawn_route_task(
                nid,
                send_rx,
                Arc::clone(&event_txs),
                Arc::clone(&partitioned),
                Arc::clone(&link_cuts),
                Arc::clone(&dead_nodes),
            );

            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            shutdown_txs.push(Some(shutdown_tx));

            tokio::spawn(async move {
                let _ = node.run(handle, signer, shutdown_rx).await;
            });
        }

        let commit_cache: Vec<Vec<Block>> = (0..n).map(|_| Vec::new()).collect();

        SimCluster {
            commit_rxs,
            node_ids,
            partitioned,
            link_cuts,
            dead_nodes,
            event_txs,
            commit_cache,
            shutdown_txs,
        }
    }

    /// Add node `idx` to the partition set. The routing tasks will drop all
    /// messages to and from this node until [`heal_node`] is called.
    ///
    /// [`heal_node`]: SimCluster::heal_node
    pub fn partition_node(&self, idx: usize) {
        self.partitioned.lock().insert(self.node_ids[idx]);
    }

    /// Remove node `idx` from the partition set, restoring full connectivity.
    pub fn heal_node(&self, idx: usize) {
        self.partitioned.lock().remove(&self.node_ids[idx]);
    }

    /// Permanently kill node `idx`, matching the production peer-crash
    /// semantics established by `src/p2p/manager.rs`:
    ///
    /// 1. Signals shutdown to the node's run loop (stopping its event loop).
    /// 2. Inserts the killed peer into `dead_nodes` so subsequent
    ///    `Broadcast` / `SendTo` from live nodes are dropped by the
    ///    routing tasks (the killed node's mailbox is never written
    ///    again after this call returns).
    /// 3. Fans out `ProtocolEvent::PeerDisconnected { node_id: killed_id }`
    ///    to every surviving node's inbound `event_rx`, iterating in
    ///    sorted-[`NodeId`] order for deterministic replay.
    ///
    /// Fan-out is fire-and-forget via `try_send`: if a survivor's
    /// inbound channel is full we log and continue rather than block
    /// the kill.
    ///
    /// Contrast with [`partition_node`]: partitioning keeps the node
    /// alive but cuts its wire (and is reversible via [`heal_node`]),
    /// while kill is permanent and the node's run loop exits.
    ///
    /// Subsequent calls for the same `idx` are no-ops (gated by
    /// `shutdown_txs[idx].take()`), so `PeerDisconnected` is dispatched
    /// exactly once per kill.
    ///
    /// [`partition_node`]: SimCluster::partition_node
    /// [`heal_node`]: SimCluster::heal_node
    pub fn kill_node(&mut self, idx: usize) {
        let Some(tx) = self.shutdown_txs[idx].take() else {
            return;
        };
        let killed = self.node_ids[idx];

        // Mark dead BEFORE signalling shutdown so any frame that races
        // through the routing task between now and the run loop's exit
        // is consistently dropped under the new dead-node semantics.
        self.dead_nodes.lock().insert(killed);
        let _ = tx.send(());

        // Fan out `PeerDisconnected` to every surviving node. Iterate
        // `node_ids` (sorted ascending) rather than the `HashMap` so
        // delivery order is deterministic across runs — `sim_adversary`
        // and proptest suites rely on byte-identical traces under the
        // same seed.
        for &nid in &self.node_ids {
            if nid == killed {
                continue;
            }
            let Some(event_tx) = self.event_txs.get(&nid) else {
                continue;
            };
            if event_tx
                .try_send(ProtocolEvent::PeerDisconnected { node_id: killed })
                .is_err()
            {
                // Fire-and-forget: the survivor's mailbox is full or
                // its receiver is closed. Log and continue — don't
                // block the kill on a slow survivor.
                tracing::warn!(
                    "sim: failed to dispatch PeerDisconnected({killed:?}) to survivor {nid:?}: \
                     channel full or closed",
                );
            }
        }
    }

    /// Drop all frames sent by node `from_idx` to node `to_idx`.
    ///
    /// Unlike [`partition_node`] this is a *directed* cut: `from_idx`
    /// still receives messages from the rest of the cluster, and
    /// `to_idx` still receives messages from everyone except `from_idx`.
    /// Use it to model a Byzantine replica that withholds votes
    /// (outbound links cut) while continuing to receive proposals.
    ///
    /// [`partition_node`]: SimCluster::partition_node
    pub fn cut_link(&self, from_idx: usize, to_idx: usize) {
        self.link_cuts
            .lock()
            .insert((self.node_ids[from_idx], self.node_ids[to_idx]));
    }

    /// Restore a previously cut directed link, re-enabling message delivery
    /// from node `from_idx` to node `to_idx`.
    pub fn restore_link(&self, from_idx: usize, to_idx: usize) {
        self.link_cuts
            .lock()
            .remove(&(self.node_ids[from_idx], self.node_ids[to_idx]));
    }

    /// Drain all blocks currently buffered in every `commit_rx` — plus
    /// any blocks previously cached by
    /// [`SimCluster::peek_commit_heights`] — and return them grouped by
    /// node (in the same order as `node_ids`).
    ///
    /// After this call the per-node cache is empty, so a subsequent
    /// `drain_commits` only returns blocks that have arrived since.
    pub fn drain_commits(&mut self) -> Vec<Vec<Block>> {
        self.flush_into_cache();
        let n = self.node_ids.len();
        std::mem::replace(&mut self.commit_cache, (0..n).map(|_| Vec::new()).collect())
    }

    /// Non-destructively report the highest committed [`Block`] height
    /// observed by each node so far (or `0` if the node has yet to
    /// commit anything).
    ///
    /// Idempotent: it drains whatever is currently buffered in the
    /// `commit_rx`s into an internal per-node cache, returns max
    /// heights from the cache, and leaves the cache in place so a
    /// later [`SimCluster::drain_commits`] still sees those blocks.
    ///
    /// Order matches [`SimCluster::node_ids`].
    pub fn peek_commit_heights(&mut self) -> Vec<u64> {
        self.flush_into_cache();
        self.commit_cache
            .iter()
            .map(|blocks| blocks.iter().map(|b| b.header.height).max().unwrap_or(0))
            .collect()
    }

    /// Advance tokio's paused virtual clock by `total`, yielding the
    /// task scheduler between small advance steps so timer-driven work
    /// (view-timer fires, pacemaker backoff) and the message-pump tasks
    /// they wake actually get a chance to run.
    ///
    /// `tokio::time::advance` by itself only fires timers; it doesn't
    /// re-enter the scheduler enough times for the downstream
    /// broadcast → ingress → safety-core → outbound chain to run to
    /// quiescence. Without the inter-step yield loop, tests can
    /// advance 5s of virtual time but only execute the work of the
    /// first 50ms — a silent source of false-green liveness
    /// assertions.
    ///
    /// Requires an active [`tokio::time::pause`].
    pub async fn advance_and_yield(&self, total: Duration) {
        // Advance in 50ms chunks: short enough to interleave pacemaker
        // timer fires with message delivery at common `timeout_base`
        // settings, long enough to finish a multi-second advance
        // without thousands of iterations.
        let chunk = Duration::from_millis(50);
        let mut remaining = total;
        while !remaining.is_zero() {
            let step = remaining.min(chunk);
            tokio::time::advance(step).await;
            remaining -= step;
            // Yield batch: large enough to drain a full
            // broadcast/vote/QC ingress round across n=4 nodes, which
            // is typically ~20–40 task wake-ups.
            for _ in 0..16 {
                tokio::task::yield_now().await;
            }
        }
    }

    /// Drain both receivers into the per-node cache. Shared by
    /// [`SimCluster::drain_commits`] and [`SimCluster::peek_commit_heights`].
    fn flush_into_cache(&mut self) {
        for (rx, cache) in self.commit_rxs.iter_mut().zip(self.commit_cache.iter_mut()) {
            while let Ok(b) = rx.try_recv() {
                cache.push(b);
            }
        }
    }
}

impl Drop for SimCluster {
    fn drop(&mut self) {
        for opt in &mut self.shutdown_txs {
            if let Some(tx) = opt.take() {
                let _ = tx.send(());
            }
        }
    }
}

/// Spawn the per-node routing task that translates each outbound frame
/// from `send_rx` into inbound [`ProtocolEvent::Message`]s on the target
/// node(s), honouring the `partitioned`, `link_cuts`, and `dead_nodes`
/// fault-injection sets.
///
/// Self-delivery is suppressed in both broadcast and send-to paths so
/// the sim matches the production p2p semantics (`src/p2p/manager.rs`).
/// The integration layer loops self-addressed consensus actions back
/// into the local safety core inside
/// `ConsensusNode::apply_safety_actions`; duplicating the delivery here
/// would double-feed the core and hide regressions of that loopback.
fn spawn_route_task(
    my_id: NodeId,
    mut send_rx: mpsc::Receiver<ProtocolOutbound>,
    route_txs: Arc<HashMap<NodeId, mpsc::Sender<ProtocolEvent>>>,
    partitioned: Arc<Mutex<HashSet<NodeId>>>,
    link_cuts: Arc<Mutex<HashSet<LinkCut>>>,
    dead_nodes: Arc<Mutex<HashSet<NodeId>>>,
) {
    tokio::spawn(async move {
        while let Some(outbound) = send_rx.recv().await {
            if partitioned.lock().contains(&my_id) {
                // This node is partitioned — drop all outbound frames.
                continue;
            }
            if dead_nodes.lock().contains(&my_id) {
                // This node has been killed — drop any in-flight outbound
                // that was queued before shutdown took effect.
                continue;
            }
            match outbound {
                ProtocolOutbound::Broadcast(payload) => {
                    for (target, tx) in route_txs.iter() {
                        if *target == my_id {
                            continue;
                        }
                        if partitioned.lock().contains(target) {
                            continue;
                        }
                        if dead_nodes.lock().contains(target) {
                            continue;
                        }
                        if link_cuts.lock().contains(&(my_id, *target)) {
                            continue;
                        }
                        let _ = tx
                            .send(ProtocolEvent::Message {
                                from: my_id,
                                payload: payload.clone(),
                            })
                            .await;
                    }
                }
                ProtocolOutbound::SendTo { node_id, payload } => {
                    if node_id == my_id {
                        continue;
                    }
                    if partitioned.lock().contains(&node_id) {
                        continue;
                    }
                    if dead_nodes.lock().contains(&node_id) {
                        continue;
                    }
                    if link_cuts.lock().contains(&(my_id, node_id)) {
                        continue;
                    }
                    if let Some(tx) = route_txs.get(&node_id) {
                        let _ = tx
                            .send(ProtocolEvent::Message {
                                from: my_id,
                                payload,
                            })
                            .await;
                    }
                }
            }
        }
    });
}

/// Produce a fresh [`NodeSigner`] from a newly-generated Ed25519 key pair.
fn fresh_signer() -> NodeSigner {
    let kp = RcgenKeyPair::generate_for(&PKCS_ED25519).unwrap();
    let identity = NodeIdentity {
        pkcs8_der: Zeroizing::new(kp.serialize_der()),
    };
    NodeSigner::from_identity(&identity).unwrap()
}

/// Check that all blocks committed across all nodes are consistent:
/// every height must map to exactly one block hash. Panics on violation.
fn assert_no_conflicts(all_committed: &[Vec<Block>]) {
    let mut canonical: HashMap<u64, BlockHash> = HashMap::new();
    for node_commits in all_committed {
        for block in node_commits {
            let h = block.header.height;
            let hash = block.hash();
            let prev = canonical.entry(h).or_insert(hash);
            assert_eq!(
                *prev, hash,
                "safety violation: nodes committed different blocks at height {h}",
            );
        }
    }
}

// ── Integration tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;
    use std::time::Duration;

    use bytes::Bytes;
    use parking_lot::Mutex;
    use tokio::sync::mpsc;
    use tokio::task::yield_now;

    use super::{LinkCut, SimCluster, assert_no_conflicts, fresh_signer, spawn_route_task};
    use crate::consensus::validator_set::ValidatorSet;
    use crate::crypto::signed::Signer;
    use crate::p2p::{NodeId, ProtocolEvent, ProtocolOutbound};

    /// Bare routing harness: spawns only the per-node routing tasks and
    /// hands the caller the outbound sender + inbound receiver for each
    /// node (no `ConsensusNode`). Used by the kill-semantics tests to
    /// directly inject outbound frames and drain inbound events.
    struct BareRouting {
        node_ids: Vec<NodeId>,
        send_txs: Vec<mpsc::Sender<ProtocolOutbound>>,
        event_rxs: Vec<mpsc::Receiver<ProtocolEvent>>,
        event_txs: Arc<HashMap<NodeId, mpsc::Sender<ProtocolEvent>>>,
        dead_nodes: Arc<Mutex<HashSet<NodeId>>>,
        #[allow(dead_code)]
        partitioned: Arc<Mutex<HashSet<NodeId>>>,
        #[allow(dead_code)]
        link_cuts: Arc<Mutex<HashSet<LinkCut>>>,
    }

    impl BareRouting {
        fn new(n: usize) -> Self {
            let signers: Vec<_> = (0..n).map(|_| fresh_signer()).collect();
            let unsorted: Vec<NodeId> = signers.iter().map(|s| s.node_id()).collect();
            let vs = ValidatorSet::new(unsorted);
            let node_ids: Vec<NodeId> = vs.iter().copied().collect();

            let partitioned = Arc::new(Mutex::new(HashSet::new()));
            let link_cuts = Arc::new(Mutex::new(HashSet::new()));
            let dead_nodes = Arc::new(Mutex::new(HashSet::new()));

            let mut event_tx_map: HashMap<NodeId, mpsc::Sender<ProtocolEvent>> = HashMap::new();
            let mut event_rxs: Vec<mpsc::Receiver<ProtocolEvent>> = Vec::new();
            for &nid in &node_ids {
                let (tx, rx) = mpsc::channel(1024);
                event_tx_map.insert(nid, tx);
                event_rxs.push(rx);
            }
            let event_txs = Arc::new(event_tx_map);

            let mut send_txs = Vec::new();
            for &nid in &node_ids {
                let (send_tx, send_rx) = mpsc::channel::<ProtocolOutbound>(1024);
                send_txs.push(send_tx);
                spawn_route_task(
                    nid,
                    send_rx,
                    Arc::clone(&event_txs),
                    Arc::clone(&partitioned),
                    Arc::clone(&link_cuts),
                    Arc::clone(&dead_nodes),
                );
            }

            BareRouting {
                node_ids,
                send_txs,
                event_rxs,
                event_txs,
                dead_nodes,
                partitioned,
                link_cuts,
            }
        }

        /// Mirror of [`SimCluster::kill_node`]'s state-level actions
        /// (without a run-loop shutdown signal, since there is no run
        /// loop in the bare harness). The same `dead_nodes` insert +
        /// sorted-order `PeerDisconnected` fan-out is exercised.
        fn kill_node(&self, idx: usize) {
            let killed = self.node_ids[idx];
            if !self.dead_nodes.lock().insert(killed) {
                return;
            }
            for &nid in &self.node_ids {
                if nid == killed {
                    continue;
                }
                if let Some(event_tx) = self.event_txs.get(&nid) {
                    let _ = event_tx.try_send(ProtocolEvent::PeerDisconnected { node_id: killed });
                }
            }
        }
    }

    /// Drain every currently-buffered event from a receiver without
    /// blocking. The routing tasks push asynchronously, so callers yield
    /// beforehand to give sends a chance to land.
    fn drain_events(rx: &mut mpsc::Receiver<ProtocolEvent>) -> Vec<ProtocolEvent> {
        let mut out = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            out.push(ev);
        }
        out
    }

    // ── F-series: happy path (PR5) ────────────────────────────────────────────

    /// Four honest nodes should commit at least one block through message
    /// passing alone (no timer fires needed in the happy path).
    ///
    /// With broadcast-to-self enabled, the view-1 leader votes on its own
    /// proposal. This means all 4 nodes can reach quorum independently of
    /// which node is the leader for each view — and all 4 commit genesis
    /// when they receive B3's justify.
    #[tokio::test]
    async fn four_honest_nodes_commit_at_least_one_block() {
        tokio::time::pause();

        let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

        // Drain the task queue without advancing the clock. The happy-path
        // chain (B1 → B2 → B3 → B4) requires ~5 rounds of message exchange;
        // poll commit heights so we stop as soon as ≥ 3 nodes have committed
        // a block, with a generous max-yield budget as a safety net.
        for _ in 0..500 {
            yield_now().await;
            let heights = cluster.peek_commit_heights();
            if heights.iter().filter(|&&h| h > 0).count() >= 3 {
                break;
            }
        }

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);

        let num_committed = committed.iter().filter(|c| !c.is_empty()).count();
        assert!(
            num_committed >= 3,
            "expected >= 3 nodes to have committed, got {num_committed}",
        );
    }

    // ── G1: crash safety ─────────────────────────────────────────────────────

    /// Killing one node (below-quorum loss = 1 of 4) must not cause the
    /// surviving three to commit conflicting blocks.
    ///
    /// With broadcast-to-self, quorum = 3 votes and the leader always
    /// contributes its own vote, so n-1 = 3 surviving nodes can still
    /// reach quorum when one is crashed.
    #[tokio::test]
    async fn crash_of_minority_does_not_violate_safety() {
        tokio::time::pause();

        let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

        // Let the cluster warm up and produce its first commits.
        for _ in 0..200 {
            yield_now().await;
        }

        // Kill one node (sorted index 0). The remaining 3 still have quorum.
        cluster.kill_node(0);

        // Let the surviving three nodes continue committing.
        for _ in 0..500 {
            yield_now().await;
        }

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);

        // The three survivors must have made (additional) progress.
        let survivor_commits: usize = committed[1..].iter().map(|c| c.len()).sum();
        assert!(
            survivor_commits > 0,
            "survivors must commit at least one block after minority crash",
        );
    }

    // ── G2: partition-heal safety ─────────────────────────────────────────────

    /// Partitioning one node (dropping all messages to/from it) must not
    /// cause the remaining three to diverge, and healing must restore
    /// full cluster participation without safety violations.
    #[tokio::test]
    async fn partition_and_heal_does_not_violate_safety() {
        tokio::time::pause();

        let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

        // Let nodes boot and exchange their first messages.
        for _ in 0..50 {
            yield_now().await;
        }

        // Partition node 0: its messages are dropped in both directions.
        cluster.partition_node(0);

        // Three connected nodes make progress (they still form a quorum of 3).
        for _ in 0..400 {
            yield_now().await;
        }

        // Heal the partition — node 0 rejoins the network.
        cluster.heal_node(0);

        // Give all four nodes time to exchange messages after healing.
        for _ in 0..300 {
            yield_now().await;
        }

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);

        // The three non-partitioned nodes must have committed while partitioned.
        let connected_commits: usize = committed[1..].iter().map(|c| c.len()).sum();
        assert!(
            connected_commits > 0,
            "connected nodes must commit while one is partitioned",
        );
    }

    // ── G3: no quorum → no progress ───────────────────────────────────────────

    /// With only 2 of 4 nodes active the system cannot form a quorum (3)
    /// and must make no commits — even if the surviving pair includes the
    /// view-1 leader.
    ///
    /// Concretely: the view-1 leader proposes B1, but the view-2 leader
    /// (sorted index 2) is killed and cannot accumulate votes. The
    /// surviving pair each vote for B1 but their votes go to the dead
    /// view-2 leader's channel, which silently drops them.
    #[tokio::test]
    async fn below_quorum_makes_no_progress() {
        tokio::time::pause();

        let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

        // Kill nodes at sorted indices 2 and 3, leaving indices 0 and 1.
        // Index 1 is the view-1 leader and will try to propose; index 2
        // (the view-2 leader that would accumulate votes) is killed.
        cluster.kill_node(2);
        cluster.kill_node(3);

        // Give remaining nodes time to run — they cannot commit without quorum.
        for _ in 0..500 {
            yield_now().await;
        }

        let committed = cluster.drain_commits();

        let total_commits: usize = committed.iter().map(|c| c.len()).sum();
        assert_eq!(
            total_commits, 0,
            "no commits must occur when quorum is unreachable: got {total_commits}",
        );
    }

    // ── G4: sustained liveness with f=1 crash ────────────────────────────────

    /// With f=1 crash, the surviving three nodes must continue committing
    /// blocks after the crash, demonstrating sustained liveness.
    ///
    /// Node 0 is the view-4 vote-aggregator in a 4-node round-robin
    /// cluster. We let the cluster warm up for 100 yields so that views
    /// 1–4 complete while all four nodes are alive, then kill node 0.
    /// The survivors have quorum (3 of 4) and can continue through the
    /// next window of views (5, 6, 7) before the chain stalls again at
    /// view 8 (the next node-0 aggregation slot). Within that window,
    /// at least one additional block must be committed by each survivor.
    #[tokio::test]
    async fn sustained_liveness_with_f1_crash() {
        tokio::time::pause();

        let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

        // Warmup: let all four nodes, including node 0 (view-4 aggregator),
        // participate so the chain advances past view 4.
        for _ in 0..100 {
            yield_now().await;
        }
        let initial = cluster.drain_commits();
        assert_no_conflicts(&initial);
        let initial_total: usize = initial.iter().map(|c| c.len()).sum();
        assert!(
            initial_total > 0,
            "warmup must produce at least one commit before the kill",
        );

        // Kill node 0. Its next aggregation slot is view 8; views 5–7
        // can still complete because nodes 1, 2, 3 hold quorum = 3.
        cluster.kill_node(0);

        for _ in 0..1500 {
            yield_now().await;
        }

        let post_kill = cluster.drain_commits();
        assert_no_conflicts(&post_kill);

        // Each surviving node must have committed at least one additional
        // block during the views-5–7 window.
        for (idx, commits) in post_kill[1..].iter().enumerate() {
            assert!(
                !commits.is_empty(),
                "survivor {} must commit >= 1 block after the crash, got 0",
                idx + 1,
            );
        }
    }

    // ── G5: vote-withholding does not stall liveness ──────────────────────────

    /// A Byzantine replica that receives proposals but withholds every vote
    /// (all its outbound links are cut) must not prevent the remaining
    /// honest nodes from forming quorum and committing.
    ///
    /// Mechanically: node 0's outbound directed links to nodes 1, 2, and 3
    /// are cut. Node 0 still receives proposals (inbound intact) and will
    /// itself observe three-chain commits. But its `SendTo(next_leader, Vote)`
    /// frames are silently dropped.
    ///
    /// With n=4 / quorum=3: the view-K leader's self-vote (via
    /// broadcast-to-self) plus two votes from the other honest nodes = 3 =
    /// quorum, so every view completes despite the withheld vote.
    #[tokio::test]
    async fn vote_withholding_does_not_stall_liveness() {
        tokio::time::pause();

        let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

        // Cut all outbound links from node 0 to every other node. Node 0
        // continues receiving broadcasts but its votes never reach the
        // next-view leader. The remaining three nodes still form quorum.
        cluster.cut_link(0, 1);
        cluster.cut_link(0, 2);
        cluster.cut_link(0, 3);

        for _ in 0..1000 {
            yield_now().await;
        }

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);

        // All four nodes should observe commits: nodes 1–3 via normal QC
        // formation, node 0 via receiving proposals and observing the
        // three-chain rule (it still receives broadcasts intact).
        let num_committed = committed.iter().filter(|c| !c.is_empty()).count();
        assert!(
            num_committed >= 3,
            "expected >= 3 nodes to have committed despite withheld votes, got {num_committed}",
        );
    }

    // ── G6: sequential crashes transition from liveness to stall ─────────────

    /// Crashing nodes one at a time shows the smooth boundary between the
    /// fault-tolerant region (n-f ≥ quorum) and the below-quorum stall
    /// (n-f < quorum), all without safety violations.
    ///
    /// Phase 1 — 4 nodes active: all four commit.
    /// Phase 2 — 3 nodes (node 0 crashed): survivors commit; no conflicts.
    /// Phase 3 — 2 nodes (nodes 0 and 1 crashed): quorum unreachable, no
    ///   new commits; all previously committed blocks remain consistent.
    #[tokio::test]
    async fn sequential_crashes_transition_to_stall_without_safety_violation() {
        tokio::time::pause();

        let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

        // Phase 1: all four nodes run until the cluster has made progress.
        for _ in 0..300 {
            yield_now().await;
        }

        // Phase 2: crash node 0 (minority crash — still quorum of 3).
        cluster.kill_node(0);
        for _ in 0..500 {
            yield_now().await;
        }

        let phase12_commits = cluster.drain_commits();
        assert_no_conflicts(&phase12_commits);

        // At least two of the three surviving nodes must have committed.
        let survivors_committed: usize = phase12_commits[1..]
            .iter()
            .filter(|c| !c.is_empty())
            .count();
        assert!(
            survivors_committed >= 2,
            "at least 2 survivors must commit in phase 2, got {survivors_committed}",
        );

        // Phase 3: crash node 1 — now only 2 of 4 nodes are alive (below quorum).
        cluster.kill_node(1);
        for _ in 0..500 {
            yield_now().await;
        }

        let phase3_commits = cluster.drain_commits();
        assert_no_conflicts(&phase3_commits);

        let new_commits: usize = phase3_commits.iter().map(|c| c.len()).sum();
        assert_eq!(
            new_commits, 0,
            "no new commits must occur after dropping below quorum, got {new_commits}",
        );
    }

    // ── H: multi-seed crash-schedule fuzz ────────────────────────────────────

    /// Run the same adversarial scenario for five deterministic seeds, each
    /// choosing a different crash timing and victim node. No seed may
    /// produce a safety violation (conflicting commits).
    ///
    /// This is a lightweight fuzz driver: it doesn't use proptest
    /// shrinking, but it covers a range of crash timings (early/mid/late)
    /// and crash targets (all four node indices). A failing seed is
    /// reproducible by extracting it into its own test.
    #[tokio::test]
    async fn fuzz_random_crash_schedules_no_safety_violation() {
        // Call pause() once for the entire test — calling it inside the loop
        // panics ("time is already frozen") since we're in one tokio::test.
        tokio::time::pause();

        // Each entry is (seed, victim_index). The warmup loop below polls
        // commit heights so we stop as soon as a non-victim has committed,
        // rather than burning a fixed 200–300 yields. `seed` is preserved
        // for error-message readability — it doesn't seed RNG today.
        let scenarios: &[(u64, usize)] = &[(0, 0), (1, 1), (2, 2), (3, 3), (4, 0)];

        // Generous yield ceilings — early-exit usually fires well before.
        const WARMUP_BUDGET: usize = 400;
        const POST_KILL_DRAIN: usize = 100;

        for &(seed, victim) in scenarios {
            let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

            let mut warmed = false;
            for _ in 0..WARMUP_BUDGET {
                tokio::task::yield_now().await;
                let heights = cluster.peek_commit_heights();
                if heights
                    .iter()
                    .enumerate()
                    .any(|(i, &h)| i != victim && h > 0)
                {
                    warmed = true;
                    break;
                }
            }
            assert!(
                warmed,
                "seed {seed}: warmup did not produce any non-victim commit within {WARMUP_BUDGET} yields",
            );

            cluster.kill_node(victim);

            // Drain in-flight messages. Time is paused, so no new view
            // timers fire — this is just runtime cleanup, not progress.
            for _ in 0..POST_KILL_DRAIN {
                tokio::task::yield_now().await;
            }

            let committed = cluster.drain_commits();
            assert_no_conflicts(&committed);

            let progress: usize = committed
                .iter()
                .enumerate()
                .filter(|&(i, _)| i != victim)
                .map(|(_, c)| c.len())
                .sum();
            assert!(
                progress > 0,
                "seed {seed}: non-victim nodes must have committed at least one block",
            );
        }
    }

    // ── I: timeout-certificate liveness escape hatch (#116) ───────────────────

    /// Kill the view-1 leader BEFORE the cluster has exchanged any
    /// messages. The surviving three replicas cannot form a normal QC
    /// (nobody proposed view-1), so the only way out is a timeout
    /// certificate: each replica's view timer fires, they all broadcast
    /// `TimeoutVote { view: 1 }`, and on quorum every replica advances
    /// to view 2 where a new leader proposes. The cluster must commit
    /// at least one block without ever receiving a view-1 proposal.
    ///
    /// This is the pure Fix-B regression test for #116: with
    /// `PacemakerAction::SendTimeout` as a no-op the cluster deadlocks
    /// in view 1 forever.
    #[tokio::test]
    async fn timeout_certificate_advances_view_when_leader_is_dead() {
        tokio::time::pause();

        // Very short timeout so the test completes quickly in sim time.
        let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

        // Let the survivors' run loops start and post-kill the view-1
        // leader only after every node has observed the empty view and
        // armed its timer. Without this yield, `kill_node` races the
        // runtime's first schedule — under #120's stricter sim, the
        // killed node's boot proposal is (correctly) dropped by the
        // routing layer, and the test needs the survivors to have
        // actually booted their pacemakers before we advance the clock.
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }

        // Kill the view-1 leader: the round-robin selector picks
        // `validators[1 % 4] = index 1` as the view-1 leader (since
        // validators are sorted ascending). With #120's dead-node
        // routing, no proposal from node 1 reaches the survivors —
        // progress must come from the timeout-certificate path.
        cluster.kill_node(1);

        // Advance the virtual clock past several timeout intervals so
        // the view timer fires on every surviving node. With base=50ms
        // and exponential backoff, a few seconds of simulated time is
        // ample for the cluster to form a TC for view 1 and proceed.
        for _ in 0..12 {
            tokio::time::advance(Duration::from_millis(500)).await;
            for _ in 0..100 {
                tokio::task::yield_now().await;
            }
        }

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);

        let survivor_commits: usize = committed
            .iter()
            .enumerate()
            .filter(|&(i, _)| i != 1)
            .map(|(_, c)| c.len())
            .sum();
        assert!(
            survivor_commits > 0,
            "the TC liveness path must let the cluster make progress when the \
             view-1 leader is dead; survivors committed {survivor_commits} blocks",
        );
    }

    // ── J-series: kill-node routing semantics (#120) ──────────────────────────

    /// After `kill_node(idx)`, the killed peer is removed from routing:
    /// any `SendTo(node_ids[idx], _)` or `Broadcast` from a live node
    /// must not enqueue into the killed node's inbound mailbox.
    ///
    /// Drains everything that landed before the kill, then fires a
    /// direct `SendTo(killed)` and a `Broadcast` from every survivor,
    /// yields to let the routing tasks run, and asserts the killed
    /// mailbox stays empty of `Message` events after the kill.
    #[tokio::test]
    async fn kill_node_removes_peer_from_routing() {
        let mut routing = BareRouting::new(4);
        let killed_idx = 0;
        let killed_id = routing.node_ids[killed_idx];

        // Drain any pre-kill chatter (there shouldn't be any — nobody
        // has sent yet — but be defensive).
        for _ in 0..10 {
            yield_now().await;
        }
        let pre_kill = drain_events(&mut routing.event_rxs[killed_idx]);
        assert!(
            pre_kill.is_empty(),
            "bare harness must have no pre-kill traffic, got {} events",
            pre_kill.len(),
        );

        routing.kill_node(killed_idx);

        // Every survivor both `SendTo(killed, …)` and `Broadcast(…)`
        // after the kill. Under the new semantics neither should land
        // in the killed node's inbound mailbox.
        let payload = Bytes::from_static(b"post-kill ping");
        for (idx, send_tx) in routing.send_txs.iter().enumerate() {
            if idx == killed_idx {
                continue;
            }
            send_tx
                .send(ProtocolOutbound::SendTo {
                    node_id: killed_id,
                    payload: payload.clone(),
                })
                .await
                .expect("survivor send_tx must still be open");
            send_tx
                .send(ProtocolOutbound::Broadcast(payload.clone()))
                .await
                .expect("survivor send_tx must still be open");
        }

        // Let the routing tasks process every outbound frame above.
        for _ in 0..50 {
            yield_now().await;
        }

        let killed_inbound = drain_events(&mut routing.event_rxs[killed_idx]);
        let message_count = killed_inbound
            .iter()
            .filter(|ev| matches!(ev, ProtocolEvent::Message { .. }))
            .count();
        assert_eq!(
            message_count, 0,
            "killed node's mailbox must not receive any Message events after \
             kill_node; got {message_count} messages (full events: {killed_inbound:?})",
        );
    }

    /// After `kill_node(idx)`, every surviving node's `event_rx` must
    /// receive exactly one `PeerDisconnected { node_id: node_ids[idx] }`,
    /// and delivery order across survivors must follow sorted-`NodeId`
    /// order (matching the `sim_adversary` / proptest determinism
    /// requirement called out in the issue).
    #[tokio::test]
    async fn kill_node_dispatches_peer_disconnected_to_survivors() {
        let mut routing = BareRouting::new(4);
        let killed_idx = 2;
        let killed_id = routing.node_ids[killed_idx];

        routing.kill_node(killed_idx);

        // `try_send` runs synchronously, but yield once anyway so the
        // receivers observe the sent events as buffered.
        yield_now().await;

        for (idx, rx) in routing.event_rxs.iter_mut().enumerate() {
            let events = drain_events(rx);
            if idx == killed_idx {
                // The killed node itself must not observe a
                // `PeerDisconnected` for itself.
                let self_disc = events
                    .iter()
                    .filter(|ev| {
                        matches!(
                            ev,
                            ProtocolEvent::PeerDisconnected { node_id } if *node_id == killed_id
                        )
                    })
                    .count();
                assert_eq!(
                    self_disc, 0,
                    "killed node must not receive PeerDisconnected for itself",
                );
                continue;
            }

            let disc_events: Vec<_> = events
                .iter()
                .filter_map(|ev| match ev {
                    ProtocolEvent::PeerDisconnected { node_id } => Some(*node_id),
                    _ => None,
                })
                .collect();
            assert_eq!(
                disc_events.len(),
                1,
                "survivor {idx} must receive exactly one PeerDisconnected, got {disc_events:?}",
            );
            assert_eq!(
                disc_events[0], killed_id,
                "survivor {idx}'s PeerDisconnected must carry the killed node's id",
            );
        }
    }

    /// `kill_node` is idempotent: calling it twice on the same index
    /// must not emit a second `PeerDisconnected` to any survivor. The
    /// existing `shutdown_txs[idx].take()` guard is what makes the
    /// second call a no-op.
    #[tokio::test]
    async fn kill_node_double_kill_is_idempotent() {
        let mut routing = BareRouting::new(4);
        let killed_idx = 1;

        routing.kill_node(killed_idx);
        yield_now().await;

        // Drain the first kill's PeerDisconnected from every survivor.
        for (idx, rx) in routing.event_rxs.iter_mut().enumerate() {
            if idx == killed_idx {
                continue;
            }
            let first = drain_events(rx);
            assert_eq!(
                first.len(),
                1,
                "first kill must deliver exactly one event to survivor {idx}",
            );
        }

        // Second kill: under the `dead_nodes` guard, no new event fires.
        routing.kill_node(killed_idx);
        yield_now().await;

        for (idx, rx) in routing.event_rxs.iter_mut().enumerate() {
            if idx == killed_idx {
                continue;
            }
            let second = drain_events(rx);
            assert!(
                second.is_empty(),
                "double-kill must not re-dispatch PeerDisconnected to survivor {idx}; \
                 got {second:?}",
            );
        }
    }

    /// Full end-to-end variant running against `SimCluster` (the real
    /// spawn path with `ConsensusNode` consumers): after `kill_node`,
    /// the killed peer must appear in `dead_nodes` and the routing
    /// tasks must continue to drop frames targeting it — survivors
    /// keep making progress despite the outage.
    #[tokio::test]
    async fn simcluster_kill_node_marks_dead_nodes_set() {
        tokio::time::pause();
        let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;
        let killed_idx = 3;
        let killed_id = cluster.node_ids[killed_idx];

        // Warm-up so the cluster has exchanged at least one round.
        for _ in 0..200 {
            yield_now().await;
        }

        assert!(
            !cluster.dead_nodes.lock().contains(&killed_id),
            "dead_nodes must be empty before kill_node",
        );

        cluster.kill_node(killed_idx);

        assert!(
            cluster.dead_nodes.lock().contains(&killed_id),
            "kill_node must insert the killed peer into dead_nodes",
        );

        // Survivors continue to make progress after the kill.
        for _ in 0..500 {
            yield_now().await;
        }
        let commits = cluster.drain_commits();
        assert_no_conflicts(&commits);
        let survivor_commits: usize = commits
            .iter()
            .enumerate()
            .filter(|&(i, _)| i != killed_idx)
            .map(|(_, c)| c.len())
            .sum();
        assert!(
            survivor_commits > 0,
            "survivors must keep committing after kill_node; got {survivor_commits}",
        );
    }

    // ── K-series: post-crash liveness regression guards (#121) ────────────────
    //
    // The older crash/partition tests above use `tokio::time::pause()` +
    // `yield_now()` loops without virtual-time advancement. That pattern
    // yields the scheduler but never fires the pacemaker's view timer
    // (a `tokio::time::Sleep`), so consensus progress is entirely at
    // the mercy of whatever messages happened to be in flight at kill
    // time. Combined with weak `> 0` commit assertions, those tests can
    // pass even when the cluster deadlocks milliseconds after a kill —
    // which is exactly the class of production regression #124 was
    // filed for.
    //
    // The K-series below drive virtual time forward via
    // `SimCluster::advance_and_yield` and assert concrete commit-gain
    // floors via `SimCluster::peek_commit_heights`, so a post-crash
    // stall is visible to the suite.

    /// Per-node gained-commits assertion: after `before` → `after` the
    /// blocks committed by each indexed node must have grown by at
    /// least `floor` heights. `exclude` lets the caller skip nodes
    /// that are crashed/partitioned and not expected to keep up.
    fn assert_each_gained_at_least(
        before: &[u64],
        after: &[u64],
        floor: u64,
        exclude: &[usize],
        label: &str,
    ) {
        for (idx, (b, a)) in before.iter().zip(after.iter()).enumerate() {
            if exclude.contains(&idx) {
                continue;
            }
            let gained = a.saturating_sub(*b);
            assert!(
                gained >= floor,
                "{label}: node {idx} gained only {gained} commits \
                 (height {b} → {a}); expected ≥ {floor}",
            );
        }
    }

    /// Crash of a minority (one of four) must not stall steady-state
    /// liveness: after a healthy warm-up the cluster is committing
    /// blocks; after `kill_node(idx)` on a non-leader the surviving
    /// three must continue committing many additional blocks within a
    /// few simulated seconds.
    ///
    /// This is the primary post-crash liveness regression guard called
    /// out in #121. Unlike the older
    /// `crash_of_minority_does_not_violate_safety`, this test:
    ///
    /// 1. Advances virtual time (`advance_and_yield`) so the view
    ///    timer actually fires and the pacemaker can drive TC
    ///    formation when the dead node's turn to lead comes around.
    /// 2. Snapshots per-node committed height before and after the
    ///    kill and asserts each survivor gained a concrete minimum
    ///    number of commits — floor = 10, chosen to comfortably rule
    ///    out "deadlock + a handful of stragglers" while leaving
    ///    ample headroom above the expected commit rate (~50ms per
    ///    view, 3-chain commit ⇒ dozens of commits per 5s).
    ///
    /// The #124 fix (broadcast-and-aggregate votes) is what makes
    /// this pass: under a permanent crash of one of four validators,
    /// round-robin leadership means one in four views' next-leader
    /// is dead, and point-to-point vote routing would drop every
    /// such vote, starving the 3-chain commit rule forever.
    #[tokio::test]
    async fn crash_of_minority_preserves_liveness() {
        tokio::time::pause();

        let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

        // Warm up to steady state: advance ~500ms so several views
        // complete and the cluster has produced real commits.
        cluster.advance_and_yield(Duration::from_millis(500)).await;

        let heights_before = cluster.peek_commit_heights();
        let warm_total: u64 = heights_before.iter().sum();
        assert!(
            warm_total > 0,
            "warmup must produce at least one commit across the cluster; heights={heights_before:?}",
        );

        // Kill a non-leader: with 4 sorted validators the view-1
        // leader is index 1, so index 0 is a convenient non-view-1
        // leader. It will still be the leader for views 4, 8, 12, …
        // which is precisely why this test is meaningful — survivors
        // must TC past those views.
        let killed_idx = 0;
        cluster.kill_node(killed_idx);

        // Drive ~5 simulated seconds of post-crash execution.
        cluster.advance_and_yield(Duration::from_secs(5)).await;

        let heights_after = cluster.peek_commit_heights();

        // Safety: no conflicting commits across all nodes.
        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);

        // Liveness: every survivor gained at least 10 commits. The
        // killed node is excluded from the floor check because its
        // run loop is gone.
        assert_each_gained_at_least(
            &heights_before,
            &heights_after,
            10,
            &[killed_idx],
            "crash_of_minority",
        );
    }

    /// Crash of the view-1 leader at steady state must not stall
    /// liveness: the surviving three replicas must advance past every
    /// view the crashed node would have led (views 1, 5, 9, …) via
    /// the TC path and continue committing.
    ///
    /// Complements `crash_of_minority_preserves_liveness` by proving
    /// the liveness property holds even when the crashed node is the
    /// one that proposes first on the most common rotation slot.
    #[tokio::test]
    async fn crash_of_leader_preserves_liveness() {
        tokio::time::pause();

        let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

        cluster.advance_and_yield(Duration::from_millis(500)).await;
        let heights_before = cluster.peek_commit_heights();

        // View-1 leader under round-robin is validators[1 % 4] =
        // sorted index 1.
        let killed_idx = 1;
        cluster.kill_node(killed_idx);

        cluster.advance_and_yield(Duration::from_secs(5)).await;

        let heights_after = cluster.peek_commit_heights();
        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);

        assert_each_gained_at_least(
            &heights_before,
            &heights_after,
            10,
            &[killed_idx],
            "crash_of_leader",
        );
    }

    /// Partitioning a node must not stall the remaining three, and
    /// healing must restore full participation: after a partition of
    /// node 0 the three connected replicas must commit ≥ 10 additional
    /// blocks in 2 simulated seconds; after healing, every replica
    /// (including the previously partitioned one) must commit ≥ 5
    /// further blocks in another 2 simulated seconds.
    ///
    /// The catch-up floor on the previously partitioned node is the
    /// whole point: a weak `> 0` assertion would pass even if the
    /// healed node permanently lagged, which is exactly the regression
    /// #121 flags.
    #[tokio::test]
    async fn partition_and_heal_preserves_liveness() {
        tokio::time::pause();

        let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

        cluster.advance_and_yield(Duration::from_millis(500)).await;

        // Partition node 0. Its messages are dropped in both
        // directions (full partition, unlike the directed `cut_link`).
        let partitioned_idx = 0;
        cluster.partition_node(partitioned_idx);

        let heights_before_partition = cluster.peek_commit_heights();

        // 2 simulated seconds with one node partitioned.
        cluster.advance_and_yield(Duration::from_secs(2)).await;

        let heights_mid = cluster.peek_commit_heights();
        assert_each_gained_at_least(
            &heights_before_partition,
            &heights_mid,
            10,
            &[partitioned_idx],
            "partition_phase",
        );

        // Heal and give the cluster another 2 simulated seconds so
        // the previously partitioned node catches up on the chain via
        // post-heal proposal/justify propagation.
        cluster.heal_node(partitioned_idx);
        cluster.advance_and_yield(Duration::from_secs(2)).await;

        let heights_after_heal = cluster.peek_commit_heights();
        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);

        // Now the healed node must gain too — ≥ 5 additional commits
        // since the mid-point. Connected nodes keep going at the same
        // rate, so they should also gain ≥ 5.
        assert_each_gained_at_least(&heights_mid, &heights_after_heal, 5, &[], "post_heal_phase");
    }
}
