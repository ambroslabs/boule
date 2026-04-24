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
}
