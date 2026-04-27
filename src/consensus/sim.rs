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
//!
//! [`partition_into_groups`] / [`partition_into_two`] / [`partition_one_way`]
//! install directed link cuts in a separate `partition_blocks` set so
//! that group-level partitions can be cleared with [`heal_partition`]
//! without disturbing application-level cuts (such as vote-withholding
//! installed via [`cut_link`]). Partition cuts compose with the older
//! `partitioned` and `link_cuts` sets; routing drops a frame if any of
//! them blocks it.
//!
//! [`partition_into_groups`]: SimCluster::partition_into_groups
//! [`partition_into_two`]: SimCluster::partition_into_two
//! [`partition_one_way`]: SimCluster::partition_one_way
//! [`heal_partition`]: SimCluster::heal_partition
//! [`cut_link`]: SimCluster::cut_link

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tokio::sync::{mpsc, oneshot};

use crate::clock::{Clock, TokioClock};
use crate::consensus::limits::CacheLimits;
use crate::consensus::node::{ConsensusNode, NodeConfigForConsensus};
use crate::consensus::validator_set::ValidatorSet;
use crate::crypto::signed::{NodeSigner, Signer};
use crate::p2p::identity::NodeIdentity;
use crate::p2p::overlay::gossip::maintenance::{Dialer, MeshMaintenanceConfig};
use crate::p2p::overlay::gossip::overlay::{
    GossipOverlay, GossipOverlayConfig, GossipOverlayHandles, SpawnArgs,
};
use crate::p2p::overlay::gossip::peer_list_task::{OverlayUnicast, PeerListGossipConfig};
use crate::p2p::overlay::gossip::sink::OverlaySink;
use crate::p2p::overlay::{Broadcaster, Discovery, DiscoveryEvent, MeshBroadcaster, MeshDiscovery};
use crate::p2p::{NodeId, ProtocolEvent, ProtocolOutbound};
use crate::replication::block::{Block, BlockHash};
use crate::replication::impls::{CounterStateMachine, InMemoryMempool};
use crate::replication::state_machine::StateMachine;
use crate::storage::{MemoryStorage, MemoryWal, Storage, Wal};
use bytes::Bytes;
use rand::Rng;
use rcgen::{KeyPair as RcgenKeyPair, PKCS_ED25519};
use zeroize::Zeroizing;

/// A directed edge `(from, to)` on which all messages are silently dropped
/// by the routing layer, regardless of the partition set.
///
/// Used to simulate one-way link failures such as vote-withholding
/// (outbound links from a Byzantine replica cut, inbound intact).
type LinkCut = (NodeId, NodeId);

// ── Byzantine adversary hook (issue #132) ────────────────────────────────────

/// Per-node context handed to an [`Adversary`] on every intercept call.
///
/// The signer is the same `Arc<dyn Signer>` that the node's own
/// `ConsensusNode::run` uses, so any [`crate::crypto::signed::Signed`]
/// envelope the adversary crafts will pass the cluster's signature
/// checks (the point of issue #132 is to test that honest replicas
/// reject *protocol-level* misbehaviour, not that they detect crypto
/// forgery — that's covered by the wire-fuzz suite, #198).
#[derive(Clone)]
pub struct AdversaryCtx {
    pub my_id: NodeId,
    /// Validator set in sorted ascending order — same order as
    /// [`SimCluster::node_ids`] and the round-robin leader rotation.
    pub validators: Arc<Vec<NodeId>>,
    pub signer: Arc<dyn Signer>,
    /// Cluster-agreed genesis block. Useful for adversaries that
    /// craft synthetic blocks and need a stable parent reference
    /// (e.g. the equivocator's fork blocks share the genesis hash
    /// as their initial parent).
    pub genesis: Block,
}

/// Hook installed on a single node's routing task that lets a Byzantine
/// implementation intercept every [`ProtocolOutbound`] the consensus
/// core would emit and replace it with arbitrary wire frames. Returning
/// `vec![outbound]` preserves honest semantics; returning `vec![]` drops
/// the frame; returning multiple frames replaces or augments.
///
/// The returned frames pass through the same partition / dead-node /
/// link-cut filters as honest frames, so the adversary cannot bypass
/// the sim's network controls.
///
/// Adversaries use [`AdversaryCtx::signer`] to produce signed payloads
/// that look authentic to the rest of the cluster — the point of the
/// suite is to verify that honest replicas reject malicious *content*
/// (equivocation, stale replays, forged certificates, …) not that they
/// detect crypto forgery.
pub trait Adversary: Send + Sync {
    fn intercept(&self, ctx: &AdversaryCtx, outbound: ProtocolOutbound) -> Vec<ProtocolOutbound>;
}

/// Internal bundle of optional features for [`SimCluster::spawn_inner`]
/// so the public callers stay flat.
#[derive(Default)]
struct SpawnExtras {
    rate_limits: Option<crate::p2p::limits::RateLimitsConfig>,
    /// Per-node adversary hooks (issue #132). Indexed by sorted node
    /// order; `None` slots run the honest protocol unchanged.
    adversaries: Option<Vec<Option<Arc<dyn Adversary>>>>,
}

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
    /// Directed link cuts installed by the group-partition API
    /// ([`SimCluster::partition_into_groups`],
    /// [`SimCluster::partition_into_two`],
    /// [`SimCluster::partition_one_way`]). Stored separately from
    /// [`SimCluster::link_cuts`] so [`SimCluster::heal_partition`] can
    /// clear partition-induced cuts without touching application-level
    /// cuts such as vote-withholding.
    pub partition_blocks: Arc<Mutex<HashSet<LinkCut>>>,
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
    /// Per-orchestrator shutdown senders (gossip-mode clusters only).
    /// Held for the lifetime of the cluster so the orchestrator's
    /// `select!` shutdown arm stays pending; dropped together on
    /// [`SimCluster::drop`]. Empty for mesh-mode clusters.
    overlay_shutdowns: Vec<oneshot::Sender<()>>,
    /// Per-node signers, captured so [`SimCluster::restart_all_with_recover`]
    /// can re-spawn the cluster with the same identities. In the same
    /// `node_ids` order. `None` for clusters that don't support
    /// restart (e.g. the gossip-mode cluster).
    signers: Option<Vec<Arc<dyn Signer>>>,
    /// Per-node durable storage handles, captured so
    /// [`SimCluster::restart_all_with_recover`] can resume against the
    /// same on-disk state. Same order as [`Self::signers`].
    storages: Option<Vec<Arc<dyn Storage>>>,
    /// Per-node WAL handles, captured for the same reason as
    /// [`Self::storages`].
    wals: Option<Vec<Arc<dyn Wal>>>,
    /// Captured `ValidatorSet`. Stable across restarts (issue #23 has
    /// not landed yet).
    validator_set: ValidatorSet,
    /// Captured genesis block. Stable across restarts.
    genesis: Block,
    /// Captured view-timer base, re-used by restart so the post-restart
    /// behaviour matches the pre-restart cadence.
    timeout_base: Duration,
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
        Self::spawn_inner(n, timeout_base, SpawnExtras::default())
            .await
            .0
    }

    /// Spawn `n` honest nodes plus a per-node Byzantine [`Adversary`]
    /// hook (issue #132). `adversaries` must have length `n`; entries
    /// indexed in [`SimCluster::node_ids`] order. `None` slots run the
    /// honest protocol unchanged.
    ///
    /// The hook intercepts every [`ProtocolOutbound`] emitted by the
    /// node's consensus core and may drop it, replace it, or emit
    /// additional frames. See [`Adversary`] for the contract.
    ///
    /// # Panics
    ///
    /// Panics if `adversaries.len() != n` or `n < 4`.
    pub async fn spawn_with_adversaries(
        n: usize,
        timeout_base: Duration,
        adversaries: Vec<Option<Arc<dyn Adversary>>>,
    ) -> Self {
        assert_eq!(
            adversaries.len(),
            n,
            "spawn_with_adversaries: adversaries.len() must equal n",
        );
        Self::spawn_inner(
            n,
            timeout_base,
            SpawnExtras {
                rate_limits: None,
                adversaries: Some(adversaries),
            },
        )
        .await
        .0
    }

    /// Same as [`SimCluster::spawn`] but installs a per-node rate
    /// limiter (issue #134) built from `rate_limits`. The returned
    /// `Vec<Arc<RateLimiter>>` is in the same order as
    /// [`SimCluster::node_ids`], so a test can read each peer's
    /// drop / disconnect counters independently. Uses a [`TokioClock`]
    /// for the limiter — sufficient for honest-traffic acceptance
    /// tests because the production-default per-second rates leave
    /// orders of magnitude of wall-time headroom for any sim that
    /// finishes in seconds.
    pub async fn spawn_with_rate_limits(
        n: usize,
        timeout_base: Duration,
        rate_limits: crate::p2p::limits::RateLimitsConfig,
    ) -> (Self, Vec<Arc<crate::p2p::limits::RateLimiter>>) {
        Self::spawn_inner(
            n,
            timeout_base,
            SpawnExtras {
                rate_limits: Some(rate_limits),
                adversaries: None,
            },
        )
        .await
    }

    async fn spawn_inner(
        n: usize,
        timeout_base: Duration,
        extras: SpawnExtras,
    ) -> (Self, Vec<Arc<crate::p2p::limits::RateLimiter>>) {
        let SpawnExtras {
            rate_limits,
            adversaries,
        } = extras;
        if let Some(adv) = adversaries.as_ref() {
            assert_eq!(adv.len(), n, "adversary slots must equal n");
        }
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
        // Directed cuts installed by the group-partition API. Distinct
        // from `link_cuts` so `heal_partition` can clear only its own
        // cuts without disturbing app-level cuts such as vote-withholding.
        let partition_blocks: Arc<Mutex<HashSet<LinkCut>>> = Arc::new(Mutex::new(HashSet::new()));
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
        let node_ids_arc: Arc<Vec<NodeId>> = Arc::new(node_ids.clone());
        let mut commit_rxs: Vec<mpsc::UnboundedReceiver<Block>> = Vec::new();
        let mut shutdown_txs: Vec<Option<oneshot::Sender<()>>> = Vec::new();
        let mut limiters: Vec<Arc<crate::p2p::limits::RateLimiter>> = Vec::new();
        // Captured for [`SimCluster::restart_all_with_recover`] (#206).
        // Each Vec is in the same `node_ids` (sorted ascending) order
        // as `commit_rxs` / `shutdown_txs`, so a `take`/`recover`
        // round-trip stays index-consistent.
        let mut signers_for_restart: Vec<Arc<dyn Signer>> = Vec::new();
        let mut storages_for_restart: Vec<Arc<dyn Storage>> = Vec::new();
        let mut wals_for_restart: Vec<Arc<dyn Wal>> = Vec::new();

        for (idx, (nid, event_rx)) in event_rxs.into_iter().enumerate() {
            let signer = signer_map[&nid].clone();
            let adversary_for_node: Option<Arc<dyn Adversary>> = adversaries
                .as_ref()
                .and_then(|slots| slots.get(idx).cloned().flatten());
            signers_for_restart.push(Arc::clone(&signer));

            let config = NodeConfigForConsensus {
                validator_set: vs.clone(),
                genesis: genesis.clone(),
                propose_limit: 16,
                timeout_base,
                timeout_max: Duration::from_secs(30),
                limits: CacheLimits::unbounded_for_tests(),
                snapshot_policy: crate::replication::snapshot::SnapshotPolicy::disabled(),
            };

            let sm: Arc<Mutex<Box<dyn StateMachine>>> =
                Arc::new(Mutex::new(Box::new(CounterStateMachine::new())));
            let mempool = Arc::new(InMemoryMempool::new(256));
            let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
            let wal: Arc<dyn Wal> = Arc::new(MemoryWal::new());
            storages_for_restart.push(Arc::clone(&storage));
            wals_for_restart.push(Arc::clone(&wal));

            let (commit_tx, commit_rx) = mpsc::unbounded_channel::<Block>();
            commit_rxs.push(commit_rx);

            // ConsensusNode::new already auto-seeds the cluster-agreed
            // genesis QC; no explicit with_genesis_qc override here.
            let mut node = ConsensusNode::new(nid, config, sm, mempool, storage, wal)
                .with_commit_observer(commit_tx);

            // Optional rate-limiter (issue #134). The sim has no real
            // peer manager so we plumb `peer_cmd_tx = None`; tests
            // observe the disconnect-decision via the limiter's own
            // counters. The cluster's clock here is a TokioClock —
            // sufficient under tokio::time::pause + advance because
            // wall time still ticks for the limiter and the production
            // defaults leave orders-of-magnitude of headroom.
            if let Some(rl_cfg) = rate_limits.as_ref() {
                let clock: Arc<dyn Clock> = Arc::new(TokioClock::new());
                let limiter = Arc::new(crate::p2p::limits::RateLimiter::new(rl_cfg.clone(), clock));
                limiters.push(Arc::clone(&limiter));
                node = node.with_rate_limiter(limiter, None);
            }

            // Per-node outbound channel: node writes here through its
            // `Broadcaster`; the routing task reads on the other side.
            let (send_tx, send_rx) = mpsc::channel::<ProtocolOutbound>(1024);
            let broadcaster: Arc<dyn Broadcaster> = Arc::new(MeshBroadcaster::new(send_tx));
            // The sim's existing topology never published PeerConnected
            // / PeerDisconnected events into ProtocolEvent for ordinary
            // mesh edges (only `kill_node` did, for survivors). Mirroring
            // that for the new `Discovery` trait keeps the sim's
            // observable behavior identical: consensus's `peers_connected`
            // stays empty in the sim, just as it did before this seam
            // existed. A future sim PR can publish PeerAdded for the
            // initial topology if status-snapshot fidelity matters.
            let (_disco_src_tx, disco_src_rx) =
                tokio::sync::broadcast::channel::<DiscoveryEvent>(8);
            let discovery: Arc<dyn Discovery> = MeshDiscovery::spawn(disco_src_rx);

            let route_adv = adversary_for_node.map(|adv| {
                let ctx = AdversaryCtx {
                    my_id: nid,
                    validators: Arc::clone(&node_ids_arc),
                    signer: Arc::clone(&signer),
                    genesis: genesis.clone(),
                };
                (adv, ctx)
            });
            spawn_route_task(
                nid,
                send_rx,
                Arc::clone(&event_txs),
                Arc::clone(&partitioned),
                Arc::clone(&link_cuts),
                Arc::clone(&partition_blocks),
                Arc::clone(&dead_nodes),
                route_adv,
            );

            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            shutdown_txs.push(Some(shutdown_tx));

            tokio::spawn(async move {
                let _ = node
                    .run(broadcaster, discovery, event_rx, signer, shutdown_rx)
                    .await;
            });
        }

        let commit_cache: Vec<Vec<Block>> = (0..n).map(|_| Vec::new()).collect();

        let cluster = SimCluster {
            commit_rxs,
            node_ids,
            partitioned,
            link_cuts,
            partition_blocks,
            dead_nodes,
            event_txs,
            commit_cache,
            shutdown_txs,
            overlay_shutdowns: Vec::new(),
            signers: Some(signers_for_restart),
            storages: Some(storages_for_restart),
            wals: Some(wals_for_restart),
            validator_set: vs,
            genesis,
            timeout_base,
        };
        (cluster, limiters)
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

    /// Split the cluster into disjoint connectivity groups. Messages
    /// flow normally between nodes in the same group; messages whose
    /// `(from, to)` pair straddles a group boundary are dropped in
    /// both directions.
    ///
    /// Each inner slice is a group of node indices. Indices that do
    /// not appear in any group are placed in a final "rest" group, so
    /// `partition_into_groups(&[&[0]])` on a 4-node cluster splits
    /// `[0]` from `[1,2,3]`.
    ///
    /// Replaces any prior partition state installed by this API. To
    /// undo the partition entirely, call [`SimCluster::heal_partition`].
    /// Application-level cuts installed via [`SimCluster::cut_link`]
    /// are preserved across partition / heal cycles.
    ///
    /// # Panics
    ///
    /// Panics if any index is repeated (within or across groups) or
    /// is out of range for `node_ids`.
    pub fn partition_into_groups(&self, groups: &[&[usize]]) {
        let n = self.node_ids.len();
        let mut group_id: HashMap<usize, usize> = HashMap::new();
        for (gid, group) in groups.iter().enumerate() {
            for &idx in *group {
                assert!(idx < n, "partition index {idx} out of range for n={n}");
                let prev = group_id.insert(idx, gid);
                assert!(prev.is_none(), "partition index {idx} repeated");
            }
        }
        // Anyone not explicitly grouped joins the implicit "rest" group.
        let rest_gid = groups.len();
        for idx in 0..n {
            group_id.entry(idx).or_insert(rest_gid);
        }

        let mut blocks: HashSet<LinkCut> = HashSet::new();
        for from in 0..n {
            for to in 0..n {
                if from == to {
                    continue;
                }
                if group_id[&from] != group_id[&to] {
                    blocks.insert((self.node_ids[from], self.node_ids[to]));
                }
            }
        }
        *self.partition_blocks.lock() = blocks;
    }

    /// Convenience: split the cluster into two groups — the indices in
    /// `group_a` versus everyone else. See
    /// [`SimCluster::partition_into_groups`] for semantics.
    pub fn partition_into_two(&self, group_a: &[usize]) {
        self.partition_into_groups(&[group_a]);
    }

    /// Asymmetric (one-way) partition: drop every frame whose sender is
    /// in `from_indices` and whose receiver is in `to_indices`. Frames
    /// in the reverse direction continue to flow.
    ///
    /// Adds to the partition-blocks set without clearing existing
    /// entries, so successive calls compose. Cleared by
    /// [`SimCluster::heal_partition`].
    pub fn partition_one_way(&self, from_indices: &[usize], to_indices: &[usize]) {
        let n = self.node_ids.len();
        let mut blocks = self.partition_blocks.lock();
        for &from in from_indices {
            assert!(from < n, "from index {from} out of range for n={n}");
            for &to in to_indices {
                assert!(to < n, "to index {to} out of range for n={n}");
                if from == to {
                    continue;
                }
                blocks.insert((self.node_ids[from], self.node_ids[to]));
            }
        }
    }

    /// Clear every partition cut installed by
    /// [`SimCluster::partition_into_groups`],
    /// [`SimCluster::partition_into_two`], or
    /// [`SimCluster::partition_one_way`]. Application-level cuts
    /// installed via [`SimCluster::cut_link`] and per-node partitions
    /// installed via [`SimCluster::partition_node`] are unaffected.
    pub fn heal_partition(&self) {
        self.partition_blocks.lock().clear();
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

    /// Like [`advance_and_yield`], but stops as soon as `done(self)`
    /// returns `true` — typically a check on `peek_commit_heights`. Use
    /// this in liveness tests whose assertion is "every survivor gained
    /// at least N commits": once the floor is met, more simulated time
    /// just inflates wall-clock without exercising the invariant.
    ///
    /// Returns `true` if the predicate fired, `false` if the full
    /// `max_total` budget was exhausted (the caller usually asserts the
    /// return value).
    ///
    /// Prefer [`advance_and_yield`] for negative-space tests that must
    /// observe a quiet window for its full duration (e.g. "no commits
    /// happened in the next 2s").
    ///
    /// [`advance_and_yield`]: SimCluster::advance_and_yield
    pub async fn advance_and_yield_until(
        &mut self,
        max_total: Duration,
        mut done: impl FnMut(&mut Self) -> bool,
    ) -> bool {
        let chunk = Duration::from_millis(50);
        let mut remaining = max_total;
        while !remaining.is_zero() {
            let step = remaining.min(chunk);
            tokio::time::advance(step).await;
            remaining -= step;
            for _ in 0..16 {
                tokio::task::yield_now().await;
                if done(self) {
                    return true;
                }
            }
        }
        false
    }

    /// Tear down every live node and re-spawn the cluster against the
    /// same on-disk state via [`ConsensusNode::recover`].
    ///
    /// This is the SimCluster analog of `kill -9` + restart on every
    /// replica simultaneously: each node's `(signer, storage, wal)`
    /// triple is preserved across the call, so recovery sees the
    /// previous session's `last_voted_view`, `locked`, `high_qc`, the
    /// committed-block store, and (post-#206) the locked / high_qc
    /// blocks too. Pacemaker, mempool, state-machine, partition state,
    /// and dead-node set are *not* preserved — they're re-created
    /// fresh, mirroring what happens when a real replica's process
    /// restarts.
    ///
    /// Used by issue #206's regression test: a 4-node cluster that
    /// committed a few blocks then restarted all replicas would
    /// permanently stall, because every leader's
    /// [`HotStuffCore::become_leader`] returned an empty action set
    /// when the high_qc's parent block was missing from
    /// `pending_blocks`. The fix landed in `persist_updates` /
    /// `recover_state`; this helper exists so the regression test can
    /// exercise the post-restart liveness end-to-end.
    ///
    /// # Panics
    ///
    /// Panics if the cluster doesn't carry the per-node state required
    /// to restart (currently only the mesh-mode constructors do —
    /// see [`SimCluster::spawn`]). Gossip-mode clusters
    /// ([`SimCluster::spawn_gossip`]) cannot be restarted today.
    pub async fn restart_all_with_recover(&mut self) {
        let signers = self
            .signers
            .clone()
            .expect("restart_all_with_recover requires a mesh-mode SimCluster");
        let storages = self
            .storages
            .clone()
            .expect("restart_all_with_recover requires captured storages");
        let wals = self
            .wals
            .clone()
            .expect("restart_all_with_recover requires captured WALs");
        let n = self.node_ids.len();
        assert_eq!(signers.len(), n);
        assert_eq!(storages.len(), n);
        assert_eq!(wals.len(), n);

        // Phase 1: shutdown every live node. Drop the existing
        // broadcaster/discovery channels by signalling shutdown — the
        // run loop exits, the broadcaster's send half drops, the
        // routing task's `send_rx.recv()` returns `None`, and the task
        // ends. Old commit_rx senders die with the nodes.
        for opt in &mut self.shutdown_txs {
            if let Some(tx) = opt.take() {
                let _ = tx.send(());
            }
        }
        // Yield enough rounds for each run loop to observe shutdown,
        // emit any final actions, and drop its broadcaster (which lets
        // the routing task see send_rx close and exit). 32 yields is
        // comfortably more than the longest action-flush chain in the
        // current code.
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }

        // Phase 2: rebuild routing. Reset partition / dead-node sets
        // so post-restart wiring is "all four nodes alive, no cuts" —
        // matching how production would come back up after a fleet
        // restart.
        self.dead_nodes.lock().clear();
        self.partitioned.lock().clear();
        self.link_cuts.lock().clear();
        self.partition_blocks.lock().clear();

        let mut new_event_txs: HashMap<NodeId, mpsc::Sender<ProtocolEvent>> = HashMap::new();
        let mut new_event_rxs: Vec<(NodeId, mpsc::Receiver<ProtocolEvent>)> = Vec::new();
        for &nid in &self.node_ids {
            let (tx, rx) = mpsc::channel::<ProtocolEvent>(1024);
            new_event_txs.insert(nid, tx);
            new_event_rxs.push((nid, rx));
        }
        let new_event_txs = Arc::new(new_event_txs);
        // Replace the public-facing event_txs handle so any test that
        // dispatches via it after the restart hits the live nodes,
        // not the dead ones.
        self.event_txs = Arc::clone(&new_event_txs);

        // Phase 3: re-spawn each node via `recover`. Same per-index
        // order as the captured signers / storages / wals so node N
        // post-restart inherits node N's pre-restart on-disk state.
        let mut new_commit_rxs: Vec<mpsc::UnboundedReceiver<Block>> = Vec::new();
        let mut new_shutdown_txs: Vec<Option<oneshot::Sender<()>>> = Vec::new();

        for ((nid, event_rx), idx) in new_event_rxs.into_iter().zip(0..n) {
            let signer = Arc::clone(&signers[idx]);
            let storage = Arc::clone(&storages[idx]);
            let wal = Arc::clone(&wals[idx]);

            let config = NodeConfigForConsensus {
                validator_set: self.validator_set.clone(),
                genesis: self.genesis.clone(),
                propose_limit: 16,
                timeout_base: self.timeout_base,
                timeout_max: Duration::from_secs(30),
                limits: CacheLimits::unbounded_for_tests(),
                snapshot_policy: crate::replication::snapshot::SnapshotPolicy::disabled(),
            };
            // Fresh state machine and mempool — the previous session's
            // state machine doesn't survive a process restart in
            // production either; what survives is the durable
            // `(last_voted_view, locked, high_qc, committed-blocks)`
            // tuple in storage, which `recover` consumes below.
            let sm: Arc<Mutex<Box<dyn StateMachine>>> =
                Arc::new(Mutex::new(Box::new(CounterStateMachine::new())));
            let mempool = Arc::new(InMemoryMempool::new(256));

            let (commit_tx, commit_rx) = mpsc::unbounded_channel::<Block>();
            new_commit_rxs.push(commit_rx);

            let node = ConsensusNode::recover(nid, config, sm, mempool, storage, wal)
                .expect("recover must succeed against the same storage that just persisted")
                .with_commit_observer(commit_tx);

            let (send_tx, send_rx) = mpsc::channel::<ProtocolOutbound>(1024);
            let broadcaster: Arc<dyn Broadcaster> = Arc::new(MeshBroadcaster::new(send_tx));
            let (_disco_src_tx, disco_src_rx) =
                tokio::sync::broadcast::channel::<DiscoveryEvent>(8);
            let discovery: Arc<dyn Discovery> = MeshDiscovery::spawn(disco_src_rx);

            // No adversary on restart: the adversary trait binds to a
            // single session's `AdversaryCtx`; replaying it across a
            // restart is out of scope for the issue #206 scenario,
            // which is about honest-only liveness recovery.
            spawn_route_task(
                nid,
                send_rx,
                Arc::clone(&new_event_txs),
                Arc::clone(&self.partitioned),
                Arc::clone(&self.link_cuts),
                Arc::clone(&self.partition_blocks),
                Arc::clone(&self.dead_nodes),
                None,
            );

            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            new_shutdown_txs.push(Some(shutdown_tx));

            tokio::spawn(async move {
                let _ = node
                    .run(broadcaster, discovery, event_rx, signer, shutdown_rx)
                    .await;
            });
        }

        self.commit_rxs = new_commit_rxs;
        self.shutdown_txs = new_shutdown_txs;
        // Reset the per-node commit cache since the new commit_rxs
        // replace the old ones; any blocks not yet drained from the
        // pre-restart receivers are intentionally lost — this matches
        // the production semantics where in-flight commit observers
        // also disappear on restart.
        self.commit_cache = (0..n).map(|_| Vec::new()).collect();
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
/// node(s), honouring the `partitioned`, `link_cuts`, `partition_blocks`,
/// and `dead_nodes` fault-injection sets.
///
/// Self-delivery is suppressed in both broadcast and send-to paths so
/// the sim matches the production p2p semantics (`src/p2p/manager.rs`).
/// The integration layer loops self-addressed consensus actions back
/// into the local safety core inside
/// `ConsensusNode::apply_safety_actions`; duplicating the delivery here
/// would double-feed the core and hide regressions of that loopback.
#[allow(clippy::too_many_arguments)]
fn spawn_route_task(
    my_id: NodeId,
    mut send_rx: mpsc::Receiver<ProtocolOutbound>,
    route_txs: Arc<HashMap<NodeId, mpsc::Sender<ProtocolEvent>>>,
    partitioned: Arc<Mutex<HashSet<NodeId>>>,
    link_cuts: Arc<Mutex<HashSet<LinkCut>>>,
    partition_blocks: Arc<Mutex<HashSet<LinkCut>>>,
    dead_nodes: Arc<Mutex<HashSet<NodeId>>>,
    adversary: Option<(Arc<dyn Adversary>, AdversaryCtx)>,
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

            // Apply the per-node Byzantine adversary hook (issue #132)
            // *after* the my_id partition / dead checks: a Byzantine
            // node that's been partitioned still doesn't get its frames
            // out, matching honest semantics.
            let frames: Vec<ProtocolOutbound> = match &adversary {
                Some((adv, ctx)) => adv.intercept(ctx, outbound),
                None => vec![outbound],
            };

            for outbound in frames {
                route_one_frame(
                    my_id,
                    outbound,
                    &route_txs,
                    &partitioned,
                    &link_cuts,
                    &partition_blocks,
                    &dead_nodes,
                )
                .await;
            }
        }
    });
}

/// Deliver a single `ProtocolOutbound` (either as Broadcast or SendTo)
/// honouring the partition / link-cut / dead-node sets. Extracted from
/// [`spawn_route_task`]'s match so that the adversary's possibly-multi
/// frame return value can be looped over without nesting `match` blocks
/// inside the channel-recv loop.
#[allow(clippy::too_many_arguments)]
async fn route_one_frame(
    my_id: NodeId,
    outbound: ProtocolOutbound,
    route_txs: &HashMap<NodeId, mpsc::Sender<ProtocolEvent>>,
    partitioned: &Mutex<HashSet<NodeId>>,
    link_cuts: &Mutex<HashSet<LinkCut>>,
    partition_blocks: &Mutex<HashSet<LinkCut>>,
    dead_nodes: &Mutex<HashSet<NodeId>>,
) {
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
                if partition_blocks.lock().contains(&(my_id, *target)) {
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
                return;
            }
            if partitioned.lock().contains(&node_id) {
                return;
            }
            if dead_nodes.lock().contains(&node_id) {
                return;
            }
            if link_cuts.lock().contains(&(my_id, node_id)) {
                return;
            }
            if partition_blocks.lock().contains(&(my_id, node_id)) {
                return;
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

// ── Gossip-overlay sim mode (issue #137) ─────────────────────────────────────

/// Build adjacency lists for an undirected K-regular circulant ring on
/// `n` vertices.
///
/// Each vertex `i` is connected to `i ± 1, i ± 2, …, i ± k/2` (mod
/// `n`). For the gossip-overlay sim this is a cheap way to get a
/// connected K-regular graph without rolling a random regular graph.
///
/// # Panics
///
/// Panics if `k` is odd (circulant rings are even-degree only) or if
/// `k >= n` (would self-loop).
pub fn circulant_neighbors(n: usize, k: usize) -> Vec<Vec<usize>> {
    assert!(k % 2 == 0, "circulant K must be even (got {k})");
    assert!(k < n, "K ({k}) must be < n ({n}) for a simple graph");

    let half = k / 2;
    let mut out = vec![Vec::with_capacity(k); n];
    for (i, slot) in out.iter_mut().enumerate() {
        for j in 1..=half {
            let lo = (i + n - j) % n;
            let hi = (i + j) % n;
            slot.push(lo);
            slot.push(hi);
        }
    }
    out
}

/// Synthetic socket address used as the gossip overlay's
/// `self_listen_addr` for sim-cluster node `idx`. The publisher
/// embeds it in self-advertised peer-list entries; receivers merge
/// it into their `PeerTable` (they never actually dial these
/// addresses in the sim — the topology is fixed at construction).
fn sim_addr_for(idx: usize) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 7000_u16.saturating_add(idx as u16)))
}

/// Per-frame loss configuration installed by [`SimCluster::set_frame_loss`].
struct LossConfig {
    /// Probability in `[0.0, 1.0]` that any given delivery is dropped.
    rate: f64,
}

/// `Dialer` impl that records calls but never opens a connection.
///
/// In the sim, the partial-mesh topology is fixed at construction
/// (every node receives `PeerConnected` events for its topological
/// neighbours and only those). The maintenance loop's dial requests
/// — driven by entries the peer-list gossip eventually populates in
/// `PeerTable` — would otherwise try to expand the mesh; the no-op
/// dialer keeps the topology stable and lets us assert the partial
/// mesh's behaviour deterministically.
struct SimNoopDialer;

impl Dialer for SimNoopDialer {
    fn dial(&self, _addr: SocketAddr, _expected: Option<NodeId>) {}
}

/// `OverlayUnicast` wrapper that drops a fraction of outbound frames
/// before forwarding to the inner sink. The underlying RNG is seeded
/// per-instance for deterministic replay.
///
/// Used by [`SimCluster::set_frame_loss`] to model the random-loss
/// liveness scenario from the issue #137 acceptance criteria.
struct LossySink {
    inner: Arc<dyn OverlayUnicast>,
    rng: Mutex<ChaCha20Rng>,
    rate: f64,
}

impl LossySink {
    fn new(inner: Arc<dyn OverlayUnicast>, rate: f64, seed: u64) -> Self {
        Self {
            inner,
            rng: Mutex::new(ChaCha20Rng::seed_from_u64(seed)),
            rate,
        }
    }
}

impl OverlayUnicast for LossySink {
    fn send_to(&self, target: NodeId, payload: Bytes) {
        let drop = {
            let mut rng = self.rng.lock();
            rng.random::<f64>() < self.rate
        };
        if drop {
            return;
        }
        self.inner.send_to(target, payload);
    }
}

impl SimCluster {
    /// Spawn `n` honest nodes wired together with a per-node
    /// [`GossipOverlay`] so consensus traffic flows through
    /// `OverlayFrame::Forward` framing instead of the legacy mesh.
    /// The topology is a `target_degree`-regular circulant ring (each
    /// node has exactly `target_degree` direct neighbours); the
    /// orchestrator's `direct` set is seeded by dispatching
    /// [`ProtocolEvent::PeerConnected`] to each neighbour at boot,
    /// matching how the production `PeerCommand::RegisterProtocol`
    /// path would feed real handshake events.
    ///
    /// The maintenance dialer is a no-op
    /// ([`SimNoopDialer`]), so the topology stays exactly as
    /// constructed — peer-list gossip still propagates self-entries,
    /// but no new direct connections are formed in the sim.
    ///
    /// `frame_loss_rate` is applied via a [`LossySink`] wrapper around
    /// each node's [`OverlaySink`]; pass `0.0` to disable loss.
    /// `loss_seed` seeds the ChaCha RNG that decides per-frame drops.
    ///
    /// # Panics
    ///
    /// Panics if `n < 4`, if `target_degree` is odd, or if
    /// `target_degree >= n`.
    pub async fn spawn_gossip(
        n: usize,
        timeout_base: Duration,
        target_degree: usize,
        frame_loss_rate: f64,
        loss_seed: u64,
    ) -> Self {
        assert!(n >= 4, "BFT requires at least 4 nodes (3f+1 with f=1)");
        let topology = circulant_neighbors(n, target_degree);

        let signers: Vec<NodeSigner> = (0..n).map(|_| fresh_signer()).collect();
        let node_ids_unsorted: Vec<NodeId> = signers.iter().map(|s| s.node_id()).collect();
        let vs = ValidatorSet::new(node_ids_unsorted);
        let genesis = Block::genesis([0u8; 32]);

        let mut signer_map: HashMap<NodeId, Arc<dyn Signer>> = HashMap::new();
        for s in signers {
            signer_map.insert(s.node_id(), Arc::new(s) as Arc<dyn Signer>);
        }

        let partitioned: Arc<Mutex<HashSet<NodeId>>> = Arc::new(Mutex::new(HashSet::new()));
        let link_cuts: Arc<Mutex<HashSet<LinkCut>>> = Arc::new(Mutex::new(HashSet::new()));
        let partition_blocks: Arc<Mutex<HashSet<LinkCut>>> = Arc::new(Mutex::new(HashSet::new()));
        let dead_nodes: Arc<Mutex<HashSet<NodeId>>> = Arc::new(Mutex::new(HashSet::new()));

        // Per-node raw event channels — sim's route tasks deliver
        // `ProtocolEvent`s to the orchestrator's input here.
        let mut event_txs: HashMap<NodeId, mpsc::Sender<ProtocolEvent>> = HashMap::new();
        let mut event_rxs: Vec<(NodeId, mpsc::Receiver<ProtocolEvent>)> = Vec::new();
        for &nid in vs.iter() {
            let (tx, rx) = mpsc::channel(1024);
            event_txs.insert(nid, tx);
            event_rxs.push((nid, rx));
        }
        let event_txs = Arc::new(event_txs);

        // Resolve sorted-index ordering so we can map NodeId → topology
        // index. ValidatorSet sorts ascending; circulant_neighbors uses
        // those indices directly.
        let node_ids: Vec<NodeId> = vs.iter().copied().collect();

        let mut commit_rxs: Vec<mpsc::UnboundedReceiver<Block>> = Vec::new();
        let mut shutdown_txs: Vec<Option<oneshot::Sender<()>>> = Vec::new();
        // Hold the overlay shutdown senders for the lifetime of the
        // SimCluster — dropping them eagerly wakes the orchestrator's
        // `_ = &mut self.shutdown` select arm and tears the run loop
        // down before the test even starts. We leak them via the
        // returned cluster so the orchestrators stay alive; on
        // `SimCluster::drop` they're released and the orchestrators
        // exit through their normal shutdown path.
        let mut overlay_shutdowns: Vec<oneshot::Sender<()>> = Vec::with_capacity(n);

        let clock: Arc<dyn Clock> = Arc::new(TokioClock::new());

        // Phase A: spawn orchestrators only. We delay `ConsensusNode::run`
        // until the topology has been seeded (otherwise the view-1
        // leader broadcasts to an empty `direct` set on first boot).
        struct PendingNode {
            nid: NodeId,
            broadcaster: Arc<dyn Broadcaster>,
            discovery: Arc<dyn Discovery>,
            consensus_event_rx: mpsc::Receiver<ProtocolEvent>,
            signer: Arc<dyn Signer>,
            node: ConsensusNode,
        }
        let mut pending: Vec<PendingNode> = Vec::with_capacity(n);

        for (idx, (nid, raw_event_rx)) in event_rxs.into_iter().enumerate() {
            let signer = signer_map[&nid].clone();
            let config = NodeConfigForConsensus {
                validator_set: vs.clone(),
                genesis: genesis.clone(),
                propose_limit: 16,
                timeout_base,
                timeout_max: Duration::from_secs(30),
                limits: CacheLimits::unbounded_for_tests(),
                snapshot_policy: crate::replication::snapshot::SnapshotPolicy::disabled(),
            };
            let sm: Arc<Mutex<Box<dyn StateMachine>>> =
                Arc::new(Mutex::new(Box::new(CounterStateMachine::new())));
            let mempool = Arc::new(InMemoryMempool::new(256));
            let storage = Arc::new(MemoryStorage::new());
            let wal = Arc::new(MemoryWal::new());

            let (commit_tx, commit_rx) = mpsc::unbounded_channel::<Block>();
            commit_rxs.push(commit_rx);

            let node = ConsensusNode::new(nid, config, sm, mempool, storage, wal)
                .with_commit_observer(commit_tx);

            // Per-node outbound channel: orchestrator's OverlaySink writes
            // here; the route task reads on the other side.
            let (send_tx, send_rx) = mpsc::channel::<ProtocolOutbound>(1024);

            // Wrap in `LossySink` if frame-loss is enabled. The inner
            // `OverlaySink` is what touches the per-node send channel;
            // the wrapper short-circuits a fraction of frames before
            // they reach it.
            let base_sink: Arc<dyn OverlayUnicast> = Arc::new(OverlaySink::new(send_tx));
            let sink: Arc<dyn OverlayUnicast> = if frame_loss_rate > 0.0 {
                let per_node_seed = loss_seed.wrapping_mul(31).wrapping_add(idx as u64);
                Arc::new(LossySink::new(base_sink, frame_loss_rate, per_node_seed))
            } else {
                base_sink
            };

            // Tighter knobs than production defaults so sim convergence
            // is fast in paused-time runs.
            let overlay_cfg = GossipOverlayConfig {
                peer_list: PeerListGossipConfig {
                    interval: Duration::from_millis(50),
                    fanout: target_degree,
                    max_entries: None,
                },
                maintenance: MeshMaintenanceConfig {
                    interval: Duration::from_secs(1),
                    target_degree,
                },
                dedup_capacity: 4096,
                dedup_ttl: Duration::from_secs(60),
                peer_table_capacity: 256,
                cmd_channel_depth: 256,
                event_channel_depth: 1024,
                rng_seed: idx as u64,
            };

            let GossipOverlayHandles {
                broadcaster,
                discovery,
                event_rx: consensus_event_rx,
                shutdown: overlay_shutdown,
                ..
            } = GossipOverlay::spawn(SpawnArgs {
                self_id: nid,
                self_listen_addr: Some(sim_addr_for(idx)),
                event_rx: raw_event_rx,
                sink,
                dialer: Arc::new(SimNoopDialer),
                clock: Arc::clone(&clock),
                config: overlay_cfg,
            });
            // Hold the overlay shutdown sender; dropping it now
            // would wake `_ = &mut self.shutdown` in the orchestrator
            // and tear it down before the topology is seeded. Stored
            // in `overlay_shutdowns`; dropped on `SimCluster::drop`.
            overlay_shutdowns.push(overlay_shutdown);

            let broadcaster: Arc<dyn Broadcaster> = Arc::new(broadcaster);
            let discovery: Arc<dyn Discovery> = discovery;

            spawn_route_task(
                nid,
                send_rx,
                Arc::clone(&event_txs),
                Arc::clone(&partitioned),
                Arc::clone(&link_cuts),
                Arc::clone(&partition_blocks),
                Arc::clone(&dead_nodes),
                None,
            );

            pending.push(PendingNode {
                nid,
                broadcaster,
                discovery,
                consensus_event_rx,
                signer,
                node,
            });
        }

        // Phase B: seed the partial-mesh topology by dispatching
        // `ProtocolEvent::PeerConnected` for each (node, neighbour)
        // pair listed in `topology`. This populates each
        // orchestrator's `direct` set; outbound traffic from consensus
        // (started in phase C below) naturally flows along these
        // edges.
        for (i, neighbours) in topology.iter().enumerate() {
            let nid_i = node_ids[i];
            let event_tx_i = &event_txs[&nid_i];
            for &j in neighbours {
                let nid_j = node_ids[j];
                if event_tx_i
                    .try_send(ProtocolEvent::PeerConnected {
                        node_id: nid_j,
                        addr: sim_addr_for(j),
                    })
                    .is_err()
                {
                    panic!("sim_gossip: PeerConnected dispatch failed for {i} → {j}");
                }
            }
        }

        // Yield enough to give every orchestrator's run loop a
        // chance to pull all PeerConnected events out of its
        // raw `event_rx` and into the `direct` set. Without this
        // the view-1 leader spawned in phase C would broadcast to
        // an empty direct set on its first boot tick.
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }

        // Phase C: spawn consensus.run for each node. The view-1
        // leader's first broadcast now has a populated direct set.
        for pn in pending {
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            shutdown_txs.push(Some(shutdown_tx));
            let PendingNode {
                broadcaster,
                discovery,
                consensus_event_rx,
                signer,
                node,
                ..
            } = pn;
            tokio::spawn(async move {
                let _ = node
                    .run(
                        broadcaster,
                        discovery,
                        consensus_event_rx,
                        signer,
                        shutdown_rx,
                    )
                    .await;
            });
        }

        let commit_cache: Vec<Vec<Block>> = (0..n).map(|_| Vec::new()).collect();

        SimCluster {
            commit_rxs,
            node_ids,
            partitioned,
            link_cuts,
            partition_blocks,
            dead_nodes,
            event_txs,
            commit_cache,
            shutdown_txs,
            overlay_shutdowns,
            // Restart-from-disk is mesh-cluster only for now; the
            // gossip overlay's orchestrator wiring isn't trivially
            // re-spawnable.
            signers: None,
            storages: None,
            wals: None,
            validator_set: vs,
            genesis,
            timeout_base,
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

/// Check that all blocks committed across all nodes are consistent:
/// every height must map to exactly one block hash. Panics on violation.
pub fn assert_no_conflicts(all_committed: &[Vec<Block>]) {
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
        #[allow(dead_code)]
        partition_blocks: Arc<Mutex<HashSet<LinkCut>>>,
    }

    impl BareRouting {
        fn new(n: usize) -> Self {
            let signers: Vec<_> = (0..n).map(|_| fresh_signer()).collect();
            let unsorted: Vec<NodeId> = signers.iter().map(|s| s.node_id()).collect();
            let vs = ValidatorSet::new(unsorted);
            let node_ids: Vec<NodeId> = vs.iter().copied().collect();

            let partitioned = Arc::new(Mutex::new(HashSet::new()));
            let link_cuts = Arc::new(Mutex::new(HashSet::new()));
            let partition_blocks = Arc::new(Mutex::new(HashSet::new()));
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
                    Arc::clone(&partition_blocks),
                    Arc::clone(&dead_nodes),
                    None,
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
                partition_blocks,
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

        // Drive simulated time until each survivor has gained at least
        // 10 commits, with a 5s simulated cap as a safety net.
        let baseline = heights_before_partition.clone();
        let n = baseline.len();
        let satisfied = cluster
            .advance_and_yield_until(Duration::from_secs(5), |c| {
                let h = c.peek_commit_heights();
                (0..n)
                    .filter(|&i| i != partitioned_idx)
                    .all(|i| h[i] >= baseline[i] + 10)
            })
            .await;
        assert!(
            satisfied,
            "partition phase: survivors did not all gain >= 10 commits within 5s simulated"
        );

        let heights_mid = cluster.peek_commit_heights();
        assert_each_gained_at_least(
            &heights_before_partition,
            &heights_mid,
            10,
            &[partitioned_idx],
            "partition_phase",
        );

        // Heal and give the cluster simulated time so the previously
        // partitioned node catches up on the chain via post-heal
        // proposal/justify propagation. Stop as soon as every node
        // (including the healed one) has gained >= 5 commits.
        cluster.heal_node(partitioned_idx);
        let mid = heights_mid.clone();
        let satisfied = cluster
            .advance_and_yield_until(Duration::from_secs(5), |c| {
                let h = c.peek_commit_heights();
                (0..n).all(|i| h[i] >= mid[i] + 5)
            })
            .await;
        assert!(
            satisfied,
            "post-heal phase: not every node gained >= 5 commits within 5s simulated"
        );

        let heights_after_heal = cluster.peek_commit_heights();
        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);

        // Connected nodes keep going at the same rate, so they should
        // also gain ≥ 5.
        assert_each_gained_at_least(&heights_mid, &heights_after_heal, 5, &[], "post_heal_phase");
    }

    // ── #206: divergent on-disk state recovery ───────────────────────────────
    //
    // Pre-#206, a 4-node cluster that committed a few blocks then
    // restarted every replica simultaneously (or with `last_committed`
    // diverging across replicas) would permanently stall: each
    // replica's recovered `high_qc` referenced a block that was no
    // longer in `pending_blocks` (the in-memory cache resets to
    // genesis-only on restart, and uncommitted blocks weren't on disk
    // either), so every leader's `become_leader` returned an empty
    // action set and no proposal — and therefore no block-sync
    // request — ever fired. The fix pairs each persisted
    // `Locked` / `HighQc` with the block it references so
    // `recover_state` can re-seed `pending_blocks` enough for the
    // post-restart leader to propose. These tests pin that behaviour
    // end-to-end.

    /// Restarting every replica from disk after a few commits must
    /// resume liveness: the post-restart cluster must commit at least
    /// 10 additional blocks within 5s of simulated time.
    ///
    /// Pre-#206, this test would hang forever — `current_view` kept
    /// climbing via timeouts but no proposal was ever broadcast and
    /// `block_sync_request_emitted` stayed at zero on every replica.
    #[tokio::test]
    async fn restart_all_with_recover_resumes_liveness() {
        tokio::time::pause();

        let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

        // Phase 1: warm up so each replica persists a real
        // `(last_voted_view, locked, high_qc)` and the on-disk block
        // store contains at least one committed block.
        let satisfied = cluster
            .advance_and_yield_until(Duration::from_secs(2), |c| {
                let h = c.peek_commit_heights();
                h.iter().all(|&v| v >= 3)
            })
            .await;
        assert!(
            satisfied,
            "warm-up: every replica must commit at least 3 blocks before the restart test \
             is meaningful (heights: {:?})",
            cluster.peek_commit_heights(),
        );

        let heights_before_restart = cluster.peek_commit_heights();

        // Phase 2: simulate `kill -9` + restart on every replica.
        // The same on-disk storage is handed to `ConsensusNode::recover`
        // for each node, so the post-restart cluster sees exactly what a
        // fleet-wide reboot would have seen.
        cluster.restart_all_with_recover().await;

        // Phase 3: drive simulated time until every replica has
        // committed at least 10 more blocks. With the issue #206 fix
        // in place this completes well within seconds; without the fix
        // the cluster never makes progress.
        let baseline = heights_before_restart.clone();
        let n = baseline.len();
        let satisfied = cluster
            .advance_and_yield_until(Duration::from_secs(5), |c| {
                let h = c.peek_commit_heights();
                (0..n).all(|i| h[i] >= baseline[i] + 10)
            })
            .await;
        assert!(
            satisfied,
            "post-restart: cluster did not commit 10 more blocks per replica within 5s \
             simulated. heights={:?}, baseline={:?}",
            cluster.peek_commit_heights(),
            baseline,
        );

        let heights_after_restart = cluster.peek_commit_heights();
        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);
        assert_each_gained_at_least(
            &heights_before_restart,
            &heights_after_restart,
            10,
            &[],
            "restart_all_with_recover",
        );
    }

    /// Divergent restart: kill one replica early so its on-disk state
    /// lags far behind the survivors, let the survivors progress
    /// further, then restart every replica from disk and assert the
    /// reunified cluster makes progress. This is the issue #206
    /// reproducer in its strongest form — the `last_committed_height`
    /// values across the four replicas span a wide distribution at
    /// the moment of the global restart.
    ///
    /// The lagging replica catches up via the existing block-sync
    /// path once the post-restart leader (who now has the high_qc's
    /// parent block in `pending_blocks` thanks to #206) starts
    /// proposing again.
    #[tokio::test]
    async fn divergent_restart_with_lagging_replica_resumes_liveness() {
        tokio::time::pause();

        let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

        // Warm up just enough that node 0 persists a non-trivial
        // `(last_voted_view, locked, high_qc)` triple before we
        // partition it.
        let satisfied = cluster
            .advance_and_yield_until(Duration::from_secs(2), |c| {
                let h = c.peek_commit_heights();
                h.iter().all(|&v| v >= 2)
            })
            .await;
        assert!(
            satisfied,
            "warm-up: every replica must commit at least 2 blocks before partition. \
             heights: {:?}",
            cluster.peek_commit_heights(),
        );

        // Isolate node 0 so it stops advancing — its on-disk state
        // freezes while the surviving three keep committing.
        let lagging_idx = 0;
        cluster.partition_node(lagging_idx);

        let heights_after_partition = cluster.peek_commit_heights();
        let baseline_for_survivors = heights_after_partition.clone();
        let n = baseline_for_survivors.len();
        let satisfied = cluster
            .advance_and_yield_until(Duration::from_secs(5), |c| {
                let h = c.peek_commit_heights();
                (0..n)
                    .filter(|&i| i != lagging_idx)
                    .all(|i| h[i] >= baseline_for_survivors[i] + 8)
            })
            .await;
        assert!(
            satisfied,
            "survivors did not gain >= 8 commits while node {lagging_idx} was isolated. \
             heights={:?}, baseline={:?}",
            cluster.peek_commit_heights(),
            baseline_for_survivors,
        );

        let heights_before_restart = cluster.peek_commit_heights();
        // Sanity: the lagging replica's persisted height is strictly
        // below at least one survivor, otherwise the test isn't
        // exercising divergent on-disk state.
        let max_survivor = (0..n)
            .filter(|&i| i != lagging_idx)
            .map(|i| heights_before_restart[i])
            .max()
            .unwrap();
        assert!(
            heights_before_restart[lagging_idx] < max_survivor,
            "divergent setup failed: lagging={}, survivors max={}",
            heights_before_restart[lagging_idx],
            max_survivor,
        );

        // Restart every replica from disk. This also clears the
        // partition (the helper resets every fault set so the
        // post-restart wiring matches a real fleet reboot).
        cluster.restart_all_with_recover().await;

        // Assert progress: every replica — including the previously
        // lagging one — must commit at least 10 more blocks within
        // 10s of simulated time. The lagging replica catches up via
        // block-sync once its peers' post-restart leader proposes.
        let baseline = heights_before_restart.clone();
        let satisfied = cluster
            .advance_and_yield_until(Duration::from_secs(10), |c| {
                let h = c.peek_commit_heights();
                (0..n).all(|i| h[i] >= baseline[i] + 10)
            })
            .await;
        assert!(
            satisfied,
            "post-restart: not every replica gained >= 10 commits within 10s simulated. \
             heights={:?}, baseline={:?}",
            cluster.peek_commit_heights(),
            baseline,
        );

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);
    }

    /// Stress variant of the divergent restart: open a much wider
    /// `last_committed_height` gap (lagging replica at <10, survivors
    /// at >40) before restarting every replica from disk. Mirrors the
    /// wire reproducer in #206 where node2's pre-kill state lagged
    /// the survivors by ~40 blocks and the post-restart cluster
    /// permanently stalled.
    ///
    /// PR #215 made `pending_blocks` re-seed from disk on resume.
    /// PR #218's `OnRoundSync` follow-up also keeps the post-restart
    /// view-skew from wedging the wire repro. With both landed, this
    /// test passes deterministically in the in-memory model and
    /// passes 17/17 testnet seeds with the rotating-failure scenario.
    #[tokio::test]
    async fn divergent_restart_wide_gap_resumes_liveness() {
        tokio::time::pause();

        let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

        // Warm up so node 0 has a non-trivial pre-partition state.
        let satisfied = cluster
            .advance_and_yield_until(Duration::from_secs(2), |c| {
                let h = c.peek_commit_heights();
                h.iter().all(|&v| v >= 2)
            })
            .await;
        assert!(
            satisfied,
            "warm-up: heights={:?}",
            cluster.peek_commit_heights()
        );

        let lagging_idx = 0;
        cluster.partition_node(lagging_idx);

        let baseline = cluster.peek_commit_heights();
        let n = baseline.len();
        // Open a deep gap: survivors must gain 30+ commits while
        // node 0 stays frozen at its pre-partition height.
        let satisfied = cluster
            .advance_and_yield_until(Duration::from_secs(15), |c| {
                let h = c.peek_commit_heights();
                (0..n)
                    .filter(|&i| i != lagging_idx)
                    .all(|i| h[i] >= baseline[i] + 30)
            })
            .await;
        assert!(
            satisfied,
            "survivors did not gain >= 30 commits in 15s simulated. heights={:?}",
            cluster.peek_commit_heights(),
        );

        let heights_before_restart = cluster.peek_commit_heights();
        let max_survivor = (0..n)
            .filter(|&i| i != lagging_idx)
            .map(|i| heights_before_restart[i])
            .max()
            .unwrap();
        let gap = max_survivor - heights_before_restart[lagging_idx];
        assert!(
            gap >= 25,
            "test setup expects >= 25-block gap; got lagging={} survivors_max={}",
            heights_before_restart[lagging_idx],
            max_survivor,
        );

        cluster.restart_all_with_recover().await;

        // Demand each replica gains ≥ 10 commits within a generous
        // simulated window. Per reviewer comment on #215, this is
        // exactly the "post-restart liveness must resume" assertion
        // the testnet `wait --all-reach-height 50` is checking on
        // the wire path.
        let baseline = heights_before_restart.clone();
        let satisfied = cluster
            .advance_and_yield_until(Duration::from_secs(15), |c| {
                let h = c.peek_commit_heights();
                (0..n).all(|i| h[i] >= baseline[i] + 10)
            })
            .await;
        assert!(
            satisfied,
            "post-restart wide-gap: not every replica gained >= 10 commits in 15s simulated. \
             heights={:?}, baseline={:?}",
            cluster.peek_commit_heights(),
            baseline,
        );

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);
    }

    // ── L-series: network partition + heal proptests (#133) ──────────────────
    //
    // The K-series above use fixed scenarios (one node partitioned for a
    // fixed window, then healed). This series uses proptest to randomise
    // the partition target, the partition duration, and — for property L2
    // — which 2-of-4 split is applied. The assertions are deliberately
    // narrower than K's: each property checks the invariant called out
    // in the issue's acceptance criteria, with no extra commits-floor
    // guards that would re-derive K's territory under proptest churn.
    //
    // Each case spawns its own `current_thread` runtime under
    // `start_paused = true` so virtual time is fully under our control —
    // a paused runtime lets the entire scenario complete in milliseconds
    // of wall clock per case, which is what keeps the per-test budget
    // (CLAUDE.md: ≤ 15s wall) safe across the configured case counts.

    use proptest::prelude::*;

    /// Run an async sim scenario on a fresh `current_thread` Tokio
    /// runtime with virtual time paused. Each proptest case spins up
    /// its own runtime so cases are independent and run in milliseconds
    /// of wall clock under paused virtual time.
    fn run_paused<Fut, T>(fut: impl FnOnce() -> Fut) -> T
    where
        Fut: std::future::Future<Output = T>,
    {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap()
            .block_on(fut())
    }

    /// Build the unique 2-of-4 group for property L2 from a
    /// `0..6` selector, mapping to `C(4,2) = 6` two-element subsets.
    /// Returns the two indices in `group_a`. Everyone else is in
    /// `group_b`, which the partition API derives implicitly.
    fn group_a_two_of_four(selector: usize) -> [usize; 2] {
        // Lex order: (0,1) (0,2) (0,3) (1,2) (1,3) (2,3).
        match selector % 6 {
            0 => [0, 1],
            1 => [0, 2],
            2 => [0, 3],
            3 => [1, 2],
            4 => [1, 3],
            _ => [2, 3],
        }
    }

    /// Yield-budget for `advance_and_yield_until`'s safety-net cap.
    /// Each phase early-exits as soon as its observable condition is
    /// met, so this is a wall-clock ceiling rather than the typical
    /// duration: 1.5s simulated is well above the ~250ms-per-phase
    /// each property actually uses to satisfy its predicate.
    const PHASE_CAP: Duration = Duration::from_millis(1_500);

    proptest! {
        // 6 cases per property is enough to randomise victims /
        // splits / flip rates while keeping wall-clock comfortably
        // under the 15s/test budget called out in CLAUDE.md. Each
        // case uses `advance_and_yield_until` to exit each phase as
        // soon as its observable condition is satisfied — so the
        // dominant cost is cluster setup (Ed25519 key-gen × 4) and
        // not simulated time.
        #![proptest_config(ProptestConfig {
            cases: 6,
            // Fixed seed — randomisation comes from the strategy
            // values, not the proptest RNG, so a fixed seed is enough
            // to keep failure shrinks reproducible.
            failure_persistence: None,
            ..Default::default()
        })]

        /// **L1 — minority partition pause + heal.** With `n = 3f + 1 = 4`,
        /// partition off ≤ f = 1 node. The connected majority must keep
        /// committing while the minority is offline; on heal, the
        /// rejoining node must catch up — committing at least one block
        /// post-heal — and no node may have committed a conflicting
        /// block at any point.
        ///
        /// This is the core acceptance criterion #1 in the issue:
        /// majority makes progress, minority does not commit
        /// conflicting blocks, and on heal the minority catches up via
        /// the post-heal proposal/justify-QC chain. The whole scenario
        /// fits in ≤ 5s simulated time.
        #[test]
        fn proptest_minority_partition_then_heal(
            victim in 0usize..4,
        ) {
            run_paused(|| async move {
                let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

                // Warm-up: drive simulated time until at least one
                // node has committed a block — covers the cold start
                // from genesis through B1 → B2 → B3 → first commit.
                let warmed = cluster
                    .advance_and_yield_until(PHASE_CAP, |c| {
                        c.peek_commit_heights().iter().any(|&h| h > 0)
                    })
                    .await;
                prop_assert!(warmed, "L1: warm-up did not produce any commit");

                // Partition the minority off using the new 2-group API.
                cluster.partition_into_two(&[victim]);

                let heights_pre_partition = cluster.peek_commit_heights();

                // Liveness during partition: stop as soon as some
                // majority node has gained at least one commit, with
                // a generous simulated cap as a safety net.
                let majority_committed = cluster
                    .advance_and_yield_until(PHASE_CAP, |c| {
                        let h = c.peek_commit_heights();
                        (0..4)
                            .filter(|i| *i != victim)
                            .any(|i| h[i] > heights_pre_partition[i])
                    })
                    .await;
                prop_assert!(
                    majority_committed,
                    "L1: majority gained 0 commits while minority partitioned (victim={victim})",
                );

                let heights_during_partition = cluster.peek_commit_heights();

                // Heal and let the rejoining node catch up: stop as
                // soon as the previously partitioned node has gained
                // at least one new commit.
                cluster.heal_partition();
                let victim_caught_up = cluster
                    .advance_and_yield_until(PHASE_CAP, |c| {
                        c.peek_commit_heights()[victim] > heights_during_partition[victim]
                    })
                    .await;
                prop_assert!(
                    victim_caught_up,
                    "L1: victim {victim} did not gain any commits after heal",
                );

                // Safety throughout: no conflicting commits across
                // any node, including the rejoining minority.
                let committed = cluster.drain_commits();
                assert_no_conflicts(&committed);

                Ok(())
            })?;
        }

        /// **L2 — majority partition liveness stall + convergence.** Partition
        /// off > f nodes by splitting `n = 4` into a 2-of-4 / 2-of-4 group.
        /// Neither side has quorum (= 3), so no new commits may occur on
        /// either side of the partition. On heal, the cluster must
        /// converge: at least one previously-partitioned node resumes
        /// committing, and no node has committed a conflicting block at
        /// any point.
        ///
        /// `selector` enumerates the 6 unique 2-of-4 splits.
        #[test]
        fn proptest_majority_partition_stalls_then_converges(
            selector in 0usize..6,
        ) {
            run_paused(|| async move {
                let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

                let warmed = cluster
                    .advance_and_yield_until(PHASE_CAP, |c| {
                        c.peek_commit_heights().iter().any(|&h| h > 0)
                    })
                    .await;
                prop_assert!(warmed, "L2: warm-up did not produce any commit");

                let group_a = group_a_two_of_four(selector);
                cluster.partition_into_two(&group_a);

                // Settling window: let any in-flight pre-partition
                // QC + 3-chain commits land before snapshotting the
                // "during partition" baseline. 200ms is plenty under
                // paused virtual time for channel-pump quiescence.
                cluster.advance_and_yield(Duration::from_millis(200)).await;
                let heights_partitioned = cluster.peek_commit_heights();

                // Run for a fixed window with the partition in place.
                // Neither 2-node side has quorum, so we want to
                // observe a quiet period — there's nothing to early-
                // exit on for a negative-space assertion. 500ms is
                // enough simulated time to cross multiple view-timer
                // intervals at `timeout_base = 50ms`.
                cluster.advance_and_yield(Duration::from_millis(500)).await;

                let heights_after_partition_window = cluster.peek_commit_heights();
                for i in 0..4 {
                    let gained = heights_after_partition_window[i]
                        .saturating_sub(heights_partitioned[i]);
                    prop_assert!(
                        gained == 0,
                        "L2: node {i} gained {gained} commits inside a 2v2 \
                         partition (selector={selector}, group_a={group_a:?}); \
                         neither side has quorum so no progress is possible",
                    );
                }

                cluster.heal_partition();
                let converged = cluster
                    .advance_and_yield_until(PHASE_CAP, |c| {
                        let h = c.peek_commit_heights();
                        (0..4).any(|i| h[i] > heights_after_partition_window[i])
                    })
                    .await;
                prop_assert!(
                    converged,
                    "L2: cluster gained 0 commits after healing 2v2 partition \
                     (selector={selector}, group_a={group_a:?})",
                );

                let committed = cluster.drain_commits();
                assert_no_conflicts(&committed);

                Ok(())
            })?;
        }

        /// **L3 — flip-flop partition.** Alternate
        /// `partition_into_two([0])` and `heal_partition()` for K
        /// cycles. Safety must hold across every flip; liveness must
        /// recover after each heal so the cluster continues making
        /// progress overall.
        #[test]
        fn proptest_flipflop_partition_preserves_safety_and_liveness(
            flips in 2u32..=3,
        ) {
            run_paused(|| async move {
                let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

                let warmed = cluster
                    .advance_and_yield_until(PHASE_CAP, |c| {
                        c.peek_commit_heights().iter().any(|&h| h > 0)
                    })
                    .await;
                prop_assert!(warmed, "L3: warm-up did not produce any commit");
                let heights_initial = cluster.peek_commit_heights();

                // Flip-flop loop. Each iteration partitions node 0
                // off, runs until majority has gained a commit, heals,
                // and runs until everyone (including the previously
                // partitioned node) gains a commit. Even when
                // partitioned, the connected three retain quorum so
                // progress continues end-to-end.
                for cycle in 0..flips {
                    cluster.partition_into_two(&[0]);
                    let pre = cluster.peek_commit_heights();
                    let made_progress = cluster
                        .advance_and_yield_until(PHASE_CAP, |c| {
                            let h = c.peek_commit_heights();
                            (1..4).any(|i| h[i] > pre[i])
                        })
                        .await;
                    prop_assert!(
                        made_progress,
                        "L3: cycle {cycle} partition phase: majority did not commit",
                    );

                    cluster.heal_partition();
                    let mid = cluster.peek_commit_heights();
                    let healed_progress = cluster
                        .advance_and_yield_until(PHASE_CAP, |c| {
                            c.peek_commit_heights()[0] > mid[0]
                        })
                        .await;
                    prop_assert!(
                        healed_progress,
                        "L3: cycle {cycle} heal phase: previously-partitioned node 0 \
                         did not catch up",
                    );
                }

                let heights_final = cluster.peek_commit_heights();
                let total_gained: u64 = (0..4)
                    .map(|i| heights_final[i].saturating_sub(heights_initial[i]))
                    .sum();
                prop_assert!(
                    total_gained > 0,
                    "L3: cluster gained 0 commits across {flips} flip-flop cycles",
                );

                let committed = cluster.drain_commits();
                assert_no_conflicts(&committed);

                Ok(())
            })?;
        }
    }

    // ── L-fixed: deterministic regression sentinels for the L-series ─────────
    //
    // The proptest cases above randomise inputs but the property
    // failure modes are different per property. These three
    // single-input tests pin the canonical scenario for each property
    // — they reproduce instantly when something regresses and serve
    // as readable documentation of the partition API contract. They
    // also let us satisfy the issue's "≤ 5s simulated" acceptance
    // criterion with an explicit measurement.

    /// Canonical L1 scenario: partition node 0 (a non-leader of view 1
    /// under the round-robin rotation, but the leader of views 4, 8,
    /// …), let majority make progress, heal, let node 0 catch up.
    /// Demonstrates that the new partition primitive matches
    /// `partition_node` for the single-node case and produces
    /// catch-up behaviour identical to the K-series partition test.
    #[tokio::test]
    async fn partition_into_two_matches_partition_node_for_single_minority() {
        tokio::time::pause();
        let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

        let warmed = cluster
            .advance_and_yield_until(PHASE_CAP, |c| {
                c.peek_commit_heights().iter().any(|&h| h > 0)
            })
            .await;
        assert!(warmed, "warm-up must produce a commit");
        let heights_warm = cluster.peek_commit_heights();

        cluster.partition_into_two(&[0]);
        let majority_committed = cluster
            .advance_and_yield_until(PHASE_CAP, |c| {
                let h = c.peek_commit_heights();
                (1..4).any(|i| h[i] > heights_warm[i])
            })
            .await;
        assert!(
            majority_committed,
            "majority must commit while the minority is partitioned"
        );
        let heights_during = cluster.peek_commit_heights();

        cluster.heal_partition();
        let caught_up = cluster
            .advance_and_yield_until(PHASE_CAP, |c| {
                c.peek_commit_heights()[0] > heights_during[0]
            })
            .await;
        assert!(
            caught_up,
            "previously-partitioned node 0 must gain commits after heal"
        );

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);
    }

    /// Canonical L2 scenario: 2v2 majority partition stalls progress
    /// on both sides, then heals to convergence — the
    /// "majority-partition liveness" property from the issue.
    #[tokio::test]
    async fn partition_into_two_2v2_stalls_progress_until_heal() {
        tokio::time::pause();
        let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

        let warmed = cluster
            .advance_and_yield_until(PHASE_CAP, |c| {
                c.peek_commit_heights().iter().any(|&h| h > 0)
            })
            .await;
        assert!(warmed);

        cluster.partition_into_two(&[0, 1]);
        cluster.advance_and_yield(Duration::from_millis(200)).await;

        let heights_partitioned = cluster.peek_commit_heights();
        cluster.advance_and_yield(Duration::from_millis(500)).await;
        let heights_after_window = cluster.peek_commit_heights();

        for (idx, (&before, &after)) in heights_partitioned
            .iter()
            .zip(heights_after_window.iter())
            .enumerate()
        {
            assert_eq!(
                before, after,
                "node {idx}: 2v2 partition must stall progress; before={before}, after={after}",
            );
        }

        cluster.heal_partition();
        let converged = cluster
            .advance_and_yield_until(PHASE_CAP, |c| {
                let h = c.peek_commit_heights();
                (0..4).any(|i| h[i] > heights_after_window[i])
            })
            .await;
        assert!(
            converged,
            "cluster must converge after healing 2v2 partition"
        );

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);
    }

    /// Canonical L3 scenario: a one-way (asymmetric) partition where
    /// node 0 cannot send to nodes 1–3 but still receives their
    /// proposals — equivalent to the existing vote-withholding
    /// scenario (`vote_withholding_does_not_stall_liveness`) routed
    /// through the new `partition_one_way` API. The connected three
    /// retain quorum and continue committing.
    #[tokio::test]
    async fn partition_one_way_does_not_block_majority_progress() {
        tokio::time::pause();
        let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

        let warmed = cluster
            .advance_and_yield_until(PHASE_CAP, |c| {
                c.peek_commit_heights().iter().any(|&h| h > 0)
            })
            .await;
        assert!(warmed);
        let heights_warm = cluster.peek_commit_heights();

        // Asymmetric partition: 0 can hear 1/2/3 but cannot send to
        // any of them. Reverse direction is intact.
        cluster.partition_one_way(&[0], &[1, 2, 3]);
        let majority_committed = cluster
            .advance_and_yield_until(PHASE_CAP, |c| {
                let h = c.peek_commit_heights();
                (1..4).any(|i| h[i] > heights_warm[i])
            })
            .await;
        assert!(
            majority_committed,
            "majority must keep committing under one-way partition",
        );

        cluster.heal_partition();
        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);
    }

    // ── G-series: gossip-overlay scenarios (issue #137 stack 8) ──────────────

    /// Smallest viable gossip-overlay sim test. 4 nodes, K=2 ring, no
    /// loss. If this fails the larger 25-node convergence is doomed —
    /// useful as an isolation step when debugging scale issues.
    #[tokio::test]
    async fn gossip_4_node_basic_cluster_commits() {
        tokio::time::pause();
        let mut cluster = SimCluster::spawn_gossip(
            4,
            Duration::from_millis(50),
            /* target_degree */ 2,
            /* loss_rate     */ 0.0,
            /* loss_seed     */ 0,
        )
        .await;
        let committed = cluster
            .advance_and_yield_until(Duration::from_secs(5), |c| {
                c.peek_commit_heights().iter().all(|&h| h > 0)
            })
            .await;
        assert!(
            committed,
            "4-node K=2 gossip cluster did not commit: heights = {:?}",
            cluster.peek_commit_heights()
        );
    }

    /// Issue #137 acceptance criterion: a 25-node cluster running the
    /// partial-mesh gossip overlay with `target_degree = 8` reaches
    /// steady-state consensus commits. Validates the orchestrator
    /// scales to validator-set size and that consensus traffic flows
    /// correctly through `OverlayFrame::Forward` framing + dedup +
    /// re-fanout.
    #[tokio::test]
    async fn gossip_25_node_cluster_commits_at_steady_state() {
        tokio::time::pause();
        const N: usize = 25;
        const K: usize = 8;
        let mut cluster = SimCluster::spawn_gossip(
            N,
            Duration::from_millis(50),
            K,
            /* frame_loss_rate */ 0.0,
            /* loss_seed       */ 0,
        )
        .await;

        // Generous budget — first commit must land within 5 s of
        // virtual time. In practice it lands in well under 1 s; the
        // wider cap absorbs the extra channel overhead at N=25 vs
        // the existing 4-node tests.
        const COMMIT_CAP: Duration = Duration::from_secs(5);
        let everyone_commits = cluster
            .advance_and_yield_until(COMMIT_CAP, |c| {
                c.peek_commit_heights().iter().all(|&h| h > 0)
            })
            .await;
        assert!(
            everyone_commits,
            "every node must commit at least one block under gossip overlay; heights: {:?}",
            cluster.peek_commit_heights()
        );

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);
    }

    /// Issue #137 acceptance criterion: liveness holds under random
    /// gossip-layer message loss. Drops 20% of overlay sink writes
    /// (split roughly evenly across `Forward` and `PeerList` frames
    /// — the wrapper drops indiscriminately) and asserts every node
    /// still commits within the budget. With consensus's pacemaker
    /// timeouts a few hundred milliseconds of view duration absorb
    /// occasional message loss.
    #[tokio::test]
    async fn gossip_25_node_cluster_preserves_liveness_under_random_loss() {
        tokio::time::pause();
        const N: usize = 25;
        const K: usize = 8;
        let mut cluster = SimCluster::spawn_gossip(
            N,
            Duration::from_millis(50),
            K,
            /* frame_loss_rate */ 0.20,
            /* loss_seed       */ 17,
        )
        .await;

        // Wider cap than the no-loss test: ChaCha-driven 20% drop
        // forces multi-round vote/proposal retries, so first
        // cluster-wide commit takes longer in virtual time.
        const COMMIT_CAP: Duration = Duration::from_secs(15);
        let everyone_commits = cluster
            .advance_and_yield_until(COMMIT_CAP, |c| {
                c.peek_commit_heights().iter().all(|&h| h > 0)
            })
            .await;
        assert!(
            everyone_commits,
            "liveness must hold under 20% frame loss; heights: {:?}",
            cluster.peek_commit_heights()
        );

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);
    }

    /// Issue #137 acceptance criterion: partition-and-heal preserves
    /// liveness. Splits 25 nodes into [13, 12] (neither half holds a
    /// `2f+1 = 17` quorum, so neither commits during the partition),
    /// holds for several views, heals, and asserts both halves catch
    /// up to fresh post-heal commits.
    #[tokio::test]
    async fn gossip_25_node_cluster_partition_and_heal_resumes_commits() {
        tokio::time::pause();
        const N: usize = 25;
        const K: usize = 8;
        let mut cluster = SimCluster::spawn_gossip(
            N,
            Duration::from_millis(50),
            K,
            /* frame_loss_rate */ 0.0,
            /* loss_seed       */ 0,
        )
        .await;

        // Phase 1: warm up — all 25 nodes commit at least one block
        // before we partition.
        const WARM_CAP: Duration = Duration::from_secs(5);
        let warmed = cluster
            .advance_and_yield_until(WARM_CAP, |c| c.peek_commit_heights().iter().all(|&h| h > 0))
            .await;
        assert!(
            warmed,
            "warm-up phase failed: heights = {:?}",
            cluster.peek_commit_heights()
        );
        let heights_pre = cluster.peek_commit_heights();

        // Phase 2: split [0..13] from [13..25]. Each half is below
        // the 2f+1 = 17 quorum so neither side can advance.
        let group_a: Vec<usize> = (0..13).collect();
        cluster.partition_into_two(&group_a);

        // Hold the partition for a few views — long enough that any
        // mid-flight quorum opportunities are flushed.
        cluster.advance_and_yield(Duration::from_millis(500)).await;

        // Phase 3: heal and require every node to advance past its
        // pre-partition commit height. We don't care which post-heal
        // height each node lands on; only that it's strictly past
        // `heights_pre` (proves consensus resumed after the heal).
        cluster.heal_partition();
        const HEAL_CAP: Duration = Duration::from_secs(10);
        let resumed = cluster
            .advance_and_yield_until(HEAL_CAP, |c| {
                let h = c.peek_commit_heights();
                (0..N).all(|i| h[i] > heights_pre[i])
            })
            .await;
        assert!(
            resumed,
            "every node must advance after heal; pre = {:?}, post = {:?}",
            heights_pre,
            cluster.peek_commit_heights()
        );

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);
    }

    /// Issue #178 regression. A node isolated from the cluster while
    /// it's running on a sparse-mesh gossip overlay (`target_degree`
    /// well below `n - 1`) loses sync — the live cluster commits
    /// several blocks past the isolated node's high water mark while
    /// it is partitioned. After healing, the previously-isolated node
    /// must catch up via block-sync rather than wedging at its old
    /// height.
    ///
    /// This is the in-sim analogue of `docs/testnet-local.md` §9b's
    /// rotating-failure scenario: a partitioned node mirrors the
    /// "behind the cluster" state of a freshly-restarted node, since
    /// in both cases the lagger sees fresh proposals whose parents
    /// it has never processed.
    ///
    /// The non-zero `frame_loss_rate` is the key knob that exercises
    /// the issue #178 fix (re-emit `Action::RequestBlock` for still-
    /// parked proposals on every `PacemakerAdvance`). Without lossy
    /// frames the sim's first probe always succeeds and the retry
    /// branch is never reached; with 25% loss a non-trivial fraction
    /// of `BlockRequest`s and `BlockResponse`s drop, so liveness
    /// depends on the safety core re-emitting requests for proposals
    /// whose parent never arrived. Matches the real-world symptom:
    /// the gossip-fallback unicast had no built-in retry, so a single
    /// dropped probe wedged the lagger.
    #[tokio::test]
    async fn gossip_sparse_mesh_isolated_node_catches_up_via_block_sync() {
        tokio::time::pause();
        const N: usize = 7;
        const K: usize = 4; // sparse-mesh ring (well below `N - 1 = 6`).
        let mut cluster = SimCluster::spawn_gossip(
            N,
            Duration::from_millis(50),
            K,
            /* frame_loss_rate */ 0.25,
            /* loss_seed       */ 0xD7B2,
        )
        .await;

        // Phase 1 — warm-up. Every node commits at least one block so
        // each has a non-trivial `pending_blocks` cache and a recovered
        // `high_qc` to extend off of.
        const WARM_CAP: Duration = Duration::from_secs(5);
        let warmed = cluster
            .advance_and_yield_until(WARM_CAP, |c| c.peek_commit_heights().iter().all(|&h| h > 0))
            .await;
        assert!(
            warmed,
            "warm-up failed: heights = {:?}",
            cluster.peek_commit_heights()
        );

        // Phase 2 — partition node 0. The remaining 6 nodes still hold
        // the n=7 quorum (5 of 7), so they continue committing blocks
        // while node 0 sits silent. We hold the partition long enough
        // for the live cluster to advance well past node 0's
        // pre-partition height so the post-heal catch-up actually
        // exercises the block-sync path (rather than just resuming
        // off the same pending_blocks).
        cluster.partition_node(0);
        let height_before_partition = cluster.peek_commit_heights()[0];
        const PARTITION_HOLD: Duration = Duration::from_secs(2);
        cluster
            .advance_and_yield_until(PARTITION_HOLD, |c| {
                let h = c.peek_commit_heights();
                // Wait until *some* live node has gained ≥ 5 commits
                // past the partition point. The exact gap doesn't
                // matter; the goal is that node 0 is provably behind.
                (1..N).any(|i| h[i] >= height_before_partition + 5)
            })
            .await;

        // Snapshot heights mid-partition. Node 0 must not have moved.
        let heights_mid = cluster.peek_commit_heights();
        assert_eq!(
            heights_mid[0], height_before_partition,
            "isolated node 0 must not advance while partitioned: heights = {heights_mid:?}",
        );
        assert!(
            (1..N).any(|i| heights_mid[i] > height_before_partition),
            "live cluster must keep committing while node 0 is partitioned: heights = {heights_mid:?}",
        );

        // Phase 3 — heal. Node 0 reconnects and must catch up via
        // block-sync (its `pending_blocks` is missing every proposal
        // committed during the partition, so each fresh proposal
        // arriving at node 0 will park and emit `RequestBlock`).
        cluster.heal_node(0);
        const HEAL_CAP: Duration = Duration::from_secs(15);
        let caught_up = cluster
            .advance_and_yield_until(HEAL_CAP, |c| c.peek_commit_heights()[0] > heights_mid[0])
            .await;
        assert!(
            caught_up,
            "previously-isolated node 0 must catch up via block-sync after heal; \
             heights = {:?}",
            cluster.peek_commit_heights()
        );

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);
    }

    /// `circulant_neighbors` produces a connected K-regular graph for
    /// the parameters the gossip-overlay sim uses.
    #[test]
    fn circulant_neighbors_is_k_regular_and_symmetric() {
        let n = 25usize;
        let k = 8usize;
        let adj = super::circulant_neighbors(n, k);
        assert_eq!(adj.len(), n);
        for nbrs in &adj {
            assert_eq!(nbrs.len(), k, "every vertex must have degree {k}");
            let mut sorted = nbrs.clone();
            sorted.sort();
            sorted.dedup();
            assert_eq!(
                sorted.len(),
                k,
                "neighbours must be distinct and not contain self"
            );
            assert!(!sorted.contains(&n), "neighbour index out of range");
        }
        // Symmetry: i ∈ adj[j] iff j ∈ adj[i].
        for i in 0..n {
            for &j in &adj[i] {
                assert!(
                    adj[j].contains(&i),
                    "circulant ring must be symmetric: {i} → {j} but not back"
                );
            }
        }
    }

    // ── Rate-limit acceptance (issue #134) ──────────────────────────────────

    /// Issue #134 acceptance: a healthy 4-node cluster running with
    /// the production-default `[p2p.limits]` rates must never drop a
    /// frame and must never trigger a disconnect-decision. The issue
    /// text calls for "1k blocks honest sim → zero drops"; we run a
    /// scaled-down version that gains at least 50 commits per node
    /// inside the 15s test budget while still exercising every
    /// per-kind bucket (Proposal, Vote, NewView via the boot flurry,
    /// and TimeoutVote on any view rotation).
    #[tokio::test]
    async fn honest_steady_state_does_not_drop_under_default_rates() {
        tokio::time::pause();

        let (mut cluster, limiters) = SimCluster::spawn_with_rate_limits(
            4,
            Duration::from_millis(50),
            crate::p2p::limits::RateLimitsConfig::production_defaults(),
        )
        .await;

        // Floor of 50 commits per node — well below the per-kind
        // caps (vote: 256/s × 1.0s burst → 256 tokens) but enough
        // to exercise repeated proposal/vote/QC cycles.
        const TARGET_COMMITS: u64 = 50;
        let satisfied = cluster
            .advance_and_yield_until(Duration::from_secs(10), |c| {
                c.peek_commit_heights().iter().all(|&h| h >= TARGET_COMMITS)
            })
            .await;
        assert!(
            satisfied,
            "honest cluster must reach {TARGET_COMMITS} commits per node within 10s simulated; \
             heights = {:?}",
            cluster.peek_commit_heights()
        );

        // No drops, no disconnects on any node's limiter. Use a
        // structured assertion so a regression points at the
        // offending kind directly.
        for (idx, limiter) in limiters.iter().enumerate() {
            let counters = limiter.counters();
            assert_eq!(
                counters.total_drops(),
                0,
                "node {idx} unexpectedly dropped frames; per-kind: \
                 Proposal={} Vote={} NewView={} TimeoutVote={} \
                 RequestBlock={} ReceiveBlock={} bytes={}",
                counters.drops(crate::p2p::limits::MessageKind::Proposal),
                counters.drops(crate::p2p::limits::MessageKind::Vote),
                counters.drops(crate::p2p::limits::MessageKind::NewView),
                counters.drops(crate::p2p::limits::MessageKind::TimeoutVote),
                counters.drops(crate::p2p::limits::MessageKind::RequestBlock),
                counters.drops(crate::p2p::limits::MessageKind::ReceiveBlock),
                counters.bytes_drops(),
            );
            assert_eq!(
                counters.disconnects(),
                0,
                "node {idx} unexpectedly issued a disconnect-decision",
            );
        }
    }
}
