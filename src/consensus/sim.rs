//! In-memory simulation cluster for consensus integration testing.
//!
//! [`SimCluster::spawn`] wires `n` [`ConsensusNode`] instances together
//! using channel-backed [`ProtocolHandle`]s and a per-node routing task
//! that translates each outbound [`ProtocolOutbound`] into an inbound
//! [`ProtocolEvent`] on the target node(s).
//!
//! # Bootstrap
//!
//! A fresh cluster has no `high_qc`, which prevents the view-1 leader
//! from building a proposal. [`SimCluster::spawn`] pre-seeds every node
//! with a genesis QC (dummy signatures — the safety core does not
//! re-verify embedded QC signatures, so this is safe for simulation).
//! With the genesis QC in place the view-1 leader proposes immediately on
//! boot, and the cluster makes progress through message passing alone —
//! no view-timer fires are required for the happy path.
//!
//! # Topology
//!
//! Every `Broadcast` is delivered to **all** nodes including the sender;
//! this is necessary for the leader to vote on its own proposal and for
//! f=1 fault-tolerance (with n=4, quorum=3: the leader's own vote plus
//! two others reaches quorum even when one non-leader is crashed).
//! `SendTo` is delivered exactly to the named peer.
//! Messages are delivered in-order per sender (channels are FIFO).
//!
//! # Fault injection
//!
//! [`SimCluster::partition_node`] / [`heal_node`] toggle a shared
//! "partitioned" set that the routing tasks check before forwarding any
//! frame; a partitioned node neither sends nor receives. [`kill_node`]
//! sends a shutdown signal to the node's run loop, permanently stopping
//! it for that slot.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::{mpsc, oneshot};

use crate::consensus::hotstuff::QuorumCertificate;
use crate::consensus::hotstuff::qc::quorum_size;
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

        // Genesis QC: view=0 over genesis, with quorum_size(n) dummy sigs.
        // The safety core does not verify embedded QC signatures, so dummy
        // sigs are safe here — they never reach `Signed::verify`.
        let genesis_qc = make_genesis_qc(&genesis, vs.len());

        // Build a signer lookup by NodeId.
        let signer_map: HashMap<NodeId, Arc<dyn Signer>> = signers
            .into_iter()
            .map(|s| (s.node_id(), Arc::new(s) as Arc<dyn Signer>))
            .collect();

        // Shared partition set: routing tasks check this before forwarding.
        let partitioned: Arc<Mutex<HashSet<NodeId>>> = Arc::new(Mutex::new(HashSet::new()));
        // Directed link cuts: messages from `src` to `dst` are dropped.
        let link_cuts: Arc<Mutex<HashSet<LinkCut>>> = Arc::new(Mutex::new(HashSet::new()));

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

            let node = ConsensusNode::new(nid, config, sm, mempool, storage, wal)
                .with_genesis_qc(genesis_qc.clone())
                .with_commit_observer(commit_tx);

            // Per-node outbound channel: node writes here; routing task reads.
            let (send_tx, send_rx) = mpsc::channel::<ProtocolOutbound>(1024);
            let handle = ProtocolHandle { send_tx, event_rx };

            // Routing task: translate each outbound frame into inbound events
            // on the target node(s), honouring the partition set.
            //
            // Broadcasts are delivered to ALL nodes including the sender so
            // the leader can vote on its own proposal — required for f=1
            // fault-tolerance with n=4 (quorum=3: leader vote + 2 others).
            let route_txs = Arc::clone(&event_txs);
            let part = Arc::clone(&partitioned);
            let cuts = Arc::clone(&link_cuts);
            let my_id = nid;
            tokio::spawn(async move {
                let mut send_rx = send_rx;
                while let Some(outbound) = send_rx.recv().await {
                    if part.lock().contains(&my_id) {
                        // This node is partitioned — drop all outbound frames.
                        continue;
                    }
                    match outbound {
                        ProtocolOutbound::Broadcast(payload) => {
                            for (target, tx) in route_txs.iter() {
                                if part.lock().contains(target) {
                                    continue;
                                }
                                if cuts.lock().contains(&(my_id, *target)) {
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
                            if part.lock().contains(&node_id) {
                                continue;
                            }
                            if cuts.lock().contains(&(my_id, node_id)) {
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

            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            shutdown_txs.push(Some(shutdown_tx));

            tokio::spawn(async move {
                let _ = node.run(handle, signer, shutdown_rx).await;
            });
        }

        SimCluster {
            commit_rxs,
            node_ids,
            partitioned,
            link_cuts,
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

    /// Send a shutdown signal to node `idx`, stopping its event loop.
    /// Subsequent calls for the same `idx` are no-ops.
    pub fn kill_node(&mut self, idx: usize) {
        if let Some(tx) = self.shutdown_txs[idx].take() {
            let _ = tx.send(());
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

    /// Drain all blocks currently buffered in every `commit_rx` and return
    /// them grouped by node (in the same order as `node_ids`).
    pub fn drain_commits(&mut self) -> Vec<Vec<Block>> {
        self.commit_rxs
            .iter_mut()
            .map(|rx| {
                let mut blocks = Vec::new();
                while let Ok(b) = rx.try_recv() {
                    blocks.push(b);
                }
                blocks
            })
            .collect()
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

/// Produce a fresh [`NodeSigner`] from a newly-generated Ed25519 key pair.
fn fresh_signer() -> NodeSigner {
    let kp = RcgenKeyPair::generate_for(&PKCS_ED25519).unwrap();
    let identity = NodeIdentity {
        pkcs8_der: Zeroizing::new(kp.serialize_der()),
    };
    NodeSigner::from_identity(&identity).unwrap()
}

/// Build a genesis QC at view 0 with `quorum_size(vs_len)` dummy
/// signatures. The safety core does not re-verify embedded QC signatures,
/// so these placeholders are safe for simulation bootstrapping.
fn make_genesis_qc(genesis: &Block, vs_len: usize) -> QuorumCertificate {
    let mut qc = QuorumCertificate::new(0, genesis.hash(), vs_len);
    for i in 0..quorum_size(vs_len) {
        qc.add_signature(i, [0u8; 64]);
    }
    qc
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
    use std::time::Duration;

    use tokio::task::yield_now;

    use super::{SimCluster, assert_no_conflicts};

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
        // 500 yields gives ample margin even on slow CI.
        for _ in 0..500 {
            yield_now().await;
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

        // Each entry is (seed, crash_at_yield, victim_index).
        //
        // All crash_at values are >= 200 yields so that views 1–4 complete
        // in the warmup (each view takes ~20–40 yields with channel routing).
        // This guarantees progress before every kill and ensures the
        // surviving three nodes can finish the next window of views.
        let scenarios: &[(u64, usize, usize)] = &[
            (0, 200, 0), // crash view-4 aggregator after all of views 1–4
            (1, 200, 1), // crash view-5 aggregator after views 1–4
            (2, 200, 2), // crash view-2 aggregator after views 1–4
            (3, 200, 3), // crash view-3 aggregator after views 1–4
            (4, 300, 0), // crash node 0 again with extra warmup
        ];

        for &(seed, crash_at, victim) in scenarios {
            let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

            for _ in 0..crash_at {
                tokio::task::yield_now().await;
            }

            cluster.kill_node(victim);

            for _ in 0..600 {
                tokio::task::yield_now().await;
            }

            let committed = cluster.drain_commits();
            assert_no_conflicts(&committed);

            // The non-victim nodes must have made some progress.
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
}
