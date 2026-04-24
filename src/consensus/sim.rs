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
//! Every `Broadcast` is delivered to all peers except the sender.
//! `SendTo` is delivered exactly to the named peer. Messages are
//! delivered in-order per sender (channels are FIFO). No artificial
//! network delay is introduced; tests that need delay should extend this
//! module.

use std::collections::HashMap;
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
use crate::replication::block::Block;
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
pub struct SimCluster {
    /// Per-node commit receivers, in ascending [`NodeId`] (sorted) order.
    pub commit_rxs: Vec<mpsc::UnboundedReceiver<Block>>,
    /// Shutdown senders for each node's `run()` loop, same order.
    pub shutdown_txs: Vec<oneshot::Sender<()>>,
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
        let node_ids: Vec<NodeId> = signers.iter().map(|s| s.node_id()).collect();

        // ValidatorSet sorts IDs ascending, establishing leader-rotation order.
        let vs = ValidatorSet::new(node_ids);
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

        let mut commit_rxs: Vec<mpsc::UnboundedReceiver<Block>> = Vec::new();
        let mut shutdown_txs: Vec<oneshot::Sender<()>> = Vec::new();

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

            // Routing task: translate each outbound frame into one or more
            // inbound events on the target node(s).
            let route_txs = Arc::clone(&event_txs);
            let my_id = nid;
            tokio::spawn(async move {
                let mut send_rx = send_rx;
                while let Some(outbound) = send_rx.recv().await {
                    match outbound {
                        ProtocolOutbound::Broadcast(payload) => {
                            for (target, tx) in route_txs.iter() {
                                if *target != my_id {
                                    let _ = tx
                                        .send(ProtocolEvent::Message {
                                            from: my_id,
                                            payload: payload.clone(),
                                        })
                                        .await;
                                }
                            }
                        }
                        ProtocolOutbound::SendTo { node_id, payload } => {
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
            shutdown_txs.push(shutdown_tx);

            tokio::spawn(async move {
                let _ = node.run(handle, signer, shutdown_rx).await;
            });
        }

        SimCluster {
            commit_rxs,
            shutdown_txs,
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

// ── Integration tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::task::yield_now;

    use super::SimCluster;

    /// Four honest nodes should commit at least one block through message
    /// passing alone (no timer fires needed in the happy path).
    ///
    /// The test pauses the clock so the view timer never fires; progress
    /// is driven entirely by proposals → votes → QC formation → proposals.
    ///
    /// Commit sequence (round-robin leaders N[0..3] in sorted-key order):
    ///   - View 1 (leader N[1]): proposes B1 using genesis_qc as justify.
    ///   - View 2 (leader N[2]): collects 3 votes for B1 → QC_1 → proposes B2.
    ///   - View 3 (leader N[3]): collects 3 votes for B2 → QC_2 → proposes B3.
    ///   - View 4 (leader N[0]): collects 3 votes for B3 → QC_3 → proposes B4.
    ///   - Nodes receiving B3 call three_chain_commit(QC_2) → commit genesis.
    ///   - Nodes receiving B4 call three_chain_commit(QC_3) → commit B1.
    ///
    /// After the first round of commits, at least 3 of 4 nodes should have
    /// received a committed block on their `commit_rx`.
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

        let num_committed = {
            let mut n = 0usize;
            for rx in &mut cluster.commit_rxs {
                if rx.try_recv().is_ok() {
                    n += 1;
                }
            }
            n
        };

        // 3 of 4 nodes receive each broadcast (the broadcaster excluded).
        // After B3 all 3 recipients commit genesis; after B4 all 3 recipients
        // of B4 commit B1. The broadcaster of each round commits on the next
        // round, so ≥ 3 nodes should have committed by this point.
        assert!(
            num_committed >= 3,
            "expected >= 3 nodes to have committed, got {num_committed}",
        );

        for tx in cluster.shutdown_txs {
            let _ = tx.send(());
        }
    }
}
