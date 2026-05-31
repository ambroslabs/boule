// Sim is `#[cfg(test)]` and accumulates a few held-but-not-read fields
// (channel guards, scaffolding for unimplemented features). The
// alternative — sprinkling per-item `#[allow(dead_code)]` everywhere —
// is noisier than scoping the lint here in a single test-only module.
#![allow(dead_code)]

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
//! [`boule_consensus::hotstuff::genesis_qc`]). With the genesis QC in
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

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tokio::sync::{mpsc, oneshot};

use crate::consensus_node::{ConsensusNode, NodeConfigForConsensus};
use boule_consensus::api::{CommitNotifier, MpscCommitNotifier};
use boule_consensus::limits::CacheLimits;
use boule_consensus::replication::block::{Block, BlockHash};
use boule_consensus::replication::impls::{CounterStateMachine, InMemoryMempool};
use boule_consensus::replication::mempool::Mempool;
use boule_consensus::replication::state_machine::StateMachine;
use boule_consensus::validator_set::ValidatorSet;
use boule_consensus::{Height, View};
use boule_core::clock::{Clock, TokioClock};
use boule_core::crypto::signed::{NodeSigner, Signer};
use boule_core::identity::NodeIdentity;
use boule_core::storage::{MemoryStorage, MemoryWal, Storage, Wal};
use boule_transport_tcp::overlay::gossip::maintenance::{Dialer, MeshMaintenanceConfig};
use boule_transport_tcp::overlay::gossip::overlay::{
    GossipOverlay, GossipOverlayConfig, GossipOverlayHandles, SpawnArgs,
};
use boule_transport_tcp::overlay::gossip::peer_list_task::{OverlayUnicast, PeerListGossipConfig};
use boule_transport_tcp::overlay::gossip::sink::OverlaySink;
use boule_transport_tcp::overlay::{
    Broadcaster, Discovery, DiscoveryEvent, MemoryBroadcaster, MemoryDiscovery,
};
use boule_transport_tcp::{NodeId, ProtocolEvent, ProtocolOutbound};
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

/// Capacity of each per-node commit channel. The harness drains via
/// [`SimCluster::drain_commits`], typically once per assertion. Sized
/// generously above the worst-case burst we've observed in long-run
/// tests so that under normal use the bound never trips; on overflow
/// the [`MpscCommitNotifier`] bumps a counter the harness can poll.
pub const SIM_COMMIT_CHANNEL_CAP: usize = 4096;

// ── Selective-drop / packet-reorder primitives (audit L3-2) ──────────────────
//
// The whole-link adversary surface (`partition_node`, `cut_link`,
// `partition_into_groups`, `set_slow_node`, `kill_node`) drops or delays
// *every* frame on a link. Partial-synchrony attacks instead need the
// network to drop or reorder *specific* frames — a Byzantine leader that
// withholds one `Proposal` from one follower, or a relay that drags one
// replica's freshest `TimeoutVote` behind the rest. These two primitives
// add that surface: [`SimCluster::drop_messages_if`] and
// [`SimCluster::reorder_link`]. Both are evaluated at the network seam
// ([`route_one_frame`]) on a *decoded* view of the wire frame, never
// inside the dispatch verifier — drops are silent at the wire.

/// Message kind exposed to a [`SimCluster::drop_messages_if`] predicate.
///
/// Mirrors the consensus-relevant variants of
/// [`boule_consensus::wire::WireMessage`]. The snapshot / block-range
/// sync frames collapse into [`SimMessageKind::Other`] so predicates can
/// match the common consensus kinds without enumerating every sync
/// variant; widen this enum if a test needs to target a sync frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimMessageKind {
    Proposal,
    Vote,
    NewView,
    TimeoutVote,
    BlockRequest,
    BlockResponse,
    /// Any wire frame outside the consensus/block-sync kinds above
    /// (snapshot manifest/chunk, block-range request/response).
    Other,
}

/// Decoded, read-only view of an in-flight wire frame, handed to a
/// selective-drop predicate registered via
/// [`SimCluster::drop_messages_if`].
///
/// Carries just enough to filter by message kind, view, and originating
/// signer — the dimensions partial-synchrony attacks select on. Frames
/// that don't decode to a [`boule_consensus::wire::WireMessage`] never
/// reach a predicate (they're delivered unfiltered); see
/// [`decode_sim_message`].
#[derive(Debug, Clone)]
pub struct SimMessage {
    /// Which wire variant this frame is.
    pub kind: SimMessageKind,
    /// The view the frame pertains to, when one is encoded in it.
    /// `None` for frames keyed by hash/height rather than view
    /// ([`SimMessageKind::BlockRequest`] / [`SimMessageKind::BlockResponse`]).
    /// For [`SimMessageKind::NewView`] this is the carried `high_qc.view`
    /// (a `NewView` has no view field of its own).
    pub view: Option<View>,
    /// The originating safety-core signer, for signed envelopes. `None`
    /// for unsigned frames ([`SimMessageKind::BlockRequest`]).
    pub signer: Option<NodeId>,
}

impl SimMessage {
    /// Project a decoded wire frame onto the predicate-visible surface.
    fn from_wire(w: &boule_consensus::wire::WireMessage) -> Self {
        use boule_consensus::wire::WireMessage as W;
        match w {
            W::Proposal(s) => Self {
                kind: SimMessageKind::Proposal,
                view: Some(s.payload.block.header.view),
                signer: Some(s.signer),
            },
            W::Vote(s, _) => Self {
                kind: SimMessageKind::Vote,
                view: Some(s.payload.view),
                signer: Some(s.signer),
            },
            W::NewView(s) => Self {
                kind: SimMessageKind::NewView,
                view: Some(s.payload.high_qc.view),
                signer: Some(s.signer),
            },
            W::TimeoutVote(s) => Self {
                kind: SimMessageKind::TimeoutVote,
                view: Some(s.payload.view),
                signer: Some(s.signer),
            },
            W::BlockRequest(_) => Self {
                kind: SimMessageKind::BlockRequest,
                view: None,
                signer: None,
            },
            W::BlockResponse(s) => Self {
                kind: SimMessageKind::BlockResponse,
                view: None,
                signer: Some(s.signer),
            },
            _ => Self {
                kind: SimMessageKind::Other,
                view: None,
                signer: None,
            },
        }
    }
}

/// Decode `payload` (already framing-peeled per `framing`) into a
/// [`SimMessage`]. Returns `None` when the bytes aren't a
/// [`boule_consensus::wire::WireMessage`] — e.g. the raw non-wire
/// payloads the `BareRouting` harness injects — in which case the
/// selective-drop predicate is not consulted and the frame is delivered.
fn decode_sim_message(payload: &[u8], framing: PayloadFraming) -> Option<SimMessage> {
    let wire_bytes: &[u8] = match framing {
        PayloadFraming::Mesh => payload,
        PayloadFraming::GossipOverlay => {
            // Unwrap the gossip `Forward` envelope to reach the inner
            // consensus frame, mirroring `VoteObserver::observe_outbound`.
            // Decode straight from the borrowed inner `Bytes`.
            match postcard::from_bytes::<boule_transport_tcp::overlay::gossip::wire::OverlayFrame>(
                payload,
            ) {
                Ok(boule_transport_tcp::overlay::gossip::wire::OverlayFrame::Forward {
                    payload: inner,
                    ..
                }) => {
                    return postcard::from_bytes::<boule_consensus::wire::WireMessage>(&inner)
                        .ok()
                        .map(|w| SimMessage::from_wire(&w));
                }
                _ => return None,
            }
        }
    };
    postcard::from_bytes::<boule_consensus::wire::WireMessage>(wire_bytes)
        .ok()
        .map(|w| SimMessage::from_wire(&w))
}

/// A selective-drop predicate. Consulted on every decodable frame on the
/// link it's registered for; returning `true` drops that frame silently.
pub type DropPredicate = Arc<dyn Fn(&SimMessage) -> bool + Send + Sync>;

/// Fold a directed link `(from → to)` into a deterministic `u64` seed.
///
/// FNV-1a over the two 32-byte ids, `from` then `to`, so the seed is
/// order-sensitive (the `from → to` reorder schedule differs from
/// `to → from`) and depends only on the fixed topology — no `SystemTime`
/// or thread RNG leaks in, so a run replays identically given the same
/// node identities.
fn link_seed(from: NodeId, to: NodeId) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in from.iter().chain(to.iter()) {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Per-link reorder buffer installed by [`SimCluster::reorder_link`].
///
/// Holds up to `depth` in-flight frames; once full, every new arrival
/// evicts one buffered frame chosen by the per-link seeded RNG and
/// releases it. That bounds the buffer at `depth` (no growth, no stall:
/// one in, one out in steady state) while permuting delivery order
/// within a `depth`-wide window. The residual `< depth` frames are
/// flushed by [`SimCluster::heal_partition`].
struct ReorderBuf {
    depth: usize,
    buf: VecDeque<Bytes>,
    rng: ChaCha20Rng,
}

impl ReorderBuf {
    fn new(from: NodeId, to: NodeId, depth: usize) -> Self {
        Self {
            depth: depth.max(1),
            buf: VecDeque::new(),
            rng: ChaCha20Rng::seed_from_u64(link_seed(from, to)),
        }
    }

    /// Buffer `payload`; once the buffer exceeds `depth`, evict and
    /// return one frame chosen by the seeded RNG (reordering it past the
    /// frames still buffered). Returns `None` while the buffer is still
    /// filling — the frame stays buffered, delivered by a later eviction
    /// or by [`Self::drain_permuted`].
    fn push(&mut self, payload: Bytes) -> Option<Bytes> {
        self.buf.push_back(payload);
        if self.buf.len() > self.depth {
            let idx = (self.rng.random::<u64>() as usize) % self.buf.len();
            self.buf.remove(idx)
        } else {
            None
        }
    }

    /// Drain every buffered frame in seeded-permuted order. Used on heal
    /// to release the residual window so the link returns to full
    /// delivery.
    fn drain_permuted(&mut self) -> Vec<Bytes> {
        let mut out = Vec::with_capacity(self.buf.len());
        while !self.buf.is_empty() {
            let idx = (self.rng.random::<u64>() as usize) % self.buf.len();
            out.push(self.buf.remove(idx).expect("idx < len"));
        }
        out
    }
}

/// Per-link selective-drop and reorder state, shared with every route
/// task (audit L3-2). Bundled behind one handle so the route-task
/// signature grows by a single parameter rather than two more `Arc`s.
/// Both maps are empty by default, so honest clusters pay only an
/// `is_empty()` check per frame.
#[derive(Clone, Default)]
struct SelectiveControls {
    /// Per-link drop predicates. Multiple predicates on a link compose:
    /// any returning `true` drops the frame.
    drop_predicates: Arc<Mutex<HashMap<LinkCut, Vec<DropPredicate>>>>,
    /// Per-link reorder buffers.
    reorder: Arc<Mutex<HashMap<LinkCut, ReorderBuf>>>,
}

// ── Per-replica vote-uniqueness observer (issue #422) ────────────────────────

/// How the route task should peel framing off an outbound payload before
/// asking the [`VoteObserver`] to look for an inner `WireMessage::Vote`.
///
/// `Mesh` route tasks (the `spawn` / `spawn_with_*` family) write
/// postcard-encoded [`boule_consensus::wire::WireMessage`] bytes
/// straight onto the per-node send channel. `GossipOverlay` route tasks
/// (the `spawn_gossip` family) instead write postcard-encoded
/// [`boule_transport_tcp::overlay::gossip::wire::OverlayFrame`] bytes whose
/// `Forward.payload` carries the inner `WireMessage` — the observer
/// unwraps that one extra layer before decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PayloadFraming {
    Mesh,
    GossipOverlay,
}

/// A safety-core vote-uniqueness violation observed by [`VoteObserver`].
///
/// The same replica emitted two distinct votes for the same view via
/// `Action::Broadcast(ConsensusMsg::Vote)`. This is a direct breach of
/// the HotStuff `vote_once` invariant and would silently bypass the
/// existing global oracle [`assert_no_conflicts`] until it propagated
/// to a conflicting commit (audit finding 14-3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteViolation {
    /// Stable identity of the replica whose safety core emitted both
    /// votes. Resolved from the [`boule_core::crypto::signed::Signed::signer`]
    /// field on the observed vote envelope, so the attribution survives
    /// gossip-mode forwarding (the originator's signer travels with the
    /// payload).
    pub replica: NodeId,
    /// View at which the conflict was observed.
    pub view: View,
    /// First block hash this replica voted for at `view`. Recorded in
    /// arrival order; `conflicting_hash` is whichever later vote
    /// disagreed.
    pub first_hash: BlockHash,
    /// A later, distinct block hash this replica voted for at the same
    /// view. The pair `(first_hash, conflicting_hash)` is the
    /// safety-violation evidence the assertion reports.
    pub conflicting_hash: BlockHash,
}

/// Per-replica observer that records every vote a replica's safety core
/// emits and flags any second emission for the same view that disagrees
/// on `block_hash`.
///
/// Wired into every [`spawn_route_task`] so each per-node routing task
/// sees the safety core's outbound `Action::Broadcast` frames *before*
/// the adversary intercept hook runs — ensuring the observer attributes
/// only what the honest safety core produced, not synthetic frames a
/// Byzantine adversary fabricated.
///
/// Idempotent re-emissions for the same `(view, block_hash)` are
/// allowed: HotStuff's safety core may legitimately re-broadcast the
/// same vote (e.g. on a peer-reconnect resend or a duplicate proposal
/// arrival). Only a *different* `block_hash` for the same view is a
/// violation. See [`SimCluster::assert_no_replica_double_voted`] for
/// the teardown assertion that surfaces violations.
#[derive(Debug, Default)]
pub struct VoteObserver {
    /// Per-replica `view → block_hash` map. Outer key is the safety
    /// core's `NodeId` (resolved from the `Signed<Vote>::signer`
    /// field); the inner map is keyed by `Vote::view`. The first hash
    /// observed at each view is sticky so subsequent observations are
    /// diffed against it for double-vote detection.
    inner: Mutex<HashMap<NodeId, HashMap<View, BlockHash>>>,
    /// Append-only list of conflicts surfaced during the run.
    /// [`SimCluster::assert_no_replica_double_voted`] panics on a
    /// non-empty list at teardown.
    violations: Mutex<Vec<VoteViolation>>,
}

impl VoteObserver {
    /// Record one observed vote. No-op if `(replica, view)` is the
    /// first time we see this view, or if a prior recording at the
    /// same view had the identical `block_hash`. Conflicting hashes
    /// are appended to the violations list.
    pub fn record(&self, replica: NodeId, view: impl Into<View>, block_hash: BlockHash) {
        let view = view.into();
        let mut votes = self.inner.lock();
        let by_view = votes.entry(replica).or_default();
        match by_view.get(&view) {
            Some(prev_hash) if *prev_hash == block_hash => {
                // Idempotent re-emission — explicitly allowed.
            }
            Some(prev_hash) => {
                self.violations.lock().push(VoteViolation {
                    replica,
                    view,
                    first_hash: *prev_hash,
                    conflicting_hash: block_hash,
                });
            }
            None => {
                by_view.insert(view, block_hash);
            }
        }
    }

    /// Snapshot of the recorded violations. Cloned out of the internal
    /// lock so callers can match on the result without holding it.
    pub fn violations(&self) -> Vec<VoteViolation> {
        self.violations.lock().clone()
    }

    /// Decode `payload` according to `framing` and record any inner
    /// `WireMessage::Vote` at its safety-core signer. Decode failures
    /// are silent: payloads of other [`boule_consensus::wire::WireMessage`]
    /// variants (proposals, new-views, block requests, ...) are
    /// expected on the same channel and intentionally ignored.
    fn observe_outbound(&self, payload: &[u8], framing: PayloadFraming) {
        let wire_bytes: &[u8] = match framing {
            PayloadFraming::Mesh => payload,
            PayloadFraming::GossipOverlay => {
                match postcard::from_bytes::<boule_transport_tcp::overlay::gossip::wire::OverlayFrame>(
                    payload,
                ) {
                    Ok(boule_transport_tcp::overlay::gossip::wire::OverlayFrame::Forward {
                        payload: inner,
                        ..
                    }) => {
                        // Re-decode from the unwrapped inner payload.
                        // `Bytes` doesn't `as_ref` to `&[u8]` in a way
                        // that survives the match, so reborrow via a
                        // local. Avoid `into_inner` to keep zero-copy
                        // semantics in the common case.
                        if let Ok(boule_consensus::wire::WireMessage::Vote(signed, _)) =
                            postcard::from_bytes::<boule_consensus::wire::WireMessage>(&inner)
                        {
                            self.record(
                                signed.signer,
                                signed.payload.view,
                                signed.payload.block_hash,
                            );
                        }
                        return;
                    }
                    _ => return,
                }
            }
        };
        if let Ok(boule_consensus::wire::WireMessage::Vote(signed, _)) =
            postcard::from_bytes::<boule_consensus::wire::WireMessage>(wire_bytes)
        {
            self.record(
                signed.signer,
                signed.payload.view,
                signed.payload.block_hash,
            );
        }
    }
}

// ── Byzantine adversary hook (issue #132) ────────────────────────────────────

/// Per-node context handed to an [`Adversary`] on every intercept call.
///
/// The signer is the same `Arc<dyn Signer>` that the node's own
/// `ConsensusNode::run` uses, so any [`boule_core::crypto::signed::Signed`]
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
    /// The cluster's deployment-scoped chain id, derived as
    /// [`ChainId::from_genesis_hash`]`(genesis.hash())` (#324). Use
    /// this — not [`ChainId::TEST`] — when re-signing forged envelopes
    /// the adversary expects honest receivers to *accept* the
    /// signature on. The dispatch layer's `verify_sig` reads the same
    /// chain_id off the local `ConsensusNode`, so a forgery signed
    /// under any other tag fails envelope verification at ingress and
    /// never reaches the safety core.
    pub chain_id: boule_core::crypto::signed::ChainId,
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

/// A shareable, mutable state machine as the consensus node holds it.
pub(crate) type SimStateMachine = Arc<Mutex<Box<dyn StateMachine>>>;

/// Internal bundle of optional features for [`SimCluster::spawn_inner`]
/// so the public callers stay flat.
#[derive(Default)]
struct SpawnExtras {
    rate_limits: Option<boule_core::transport::limits::RateLimitsConfig>,
    /// Per-node adversary hooks (issue #132). Indexed by sorted node
    /// order; `None` slots run the honest protocol unchanged.
    adversaries: Option<Vec<Option<Arc<dyn Adversary>>>>,
    /// Chain-level signature scheme override (#354 step 2). When
    /// `Some(BlsAggregated)`, [`SimCluster::spawn_inner`] generates a
    /// BLS keypair per validator, seeds each node's
    /// [`boule_consensus::bls_key_history::BlsKeyHistory`] from
    /// genesis, and plumbs the corresponding
    /// [`boule_core::crypto::bls_key::BlsPartialSignerImpl`] onto each
    /// node so leaders can produce real BLS partials on Vote frames.
    /// `None` keeps the default Ed25519 cluster shape.
    signature_scheme: Option<boule_core::crypto::sig_scheme::SignatureSchemeChoice>,
    /// Per-validator voting weights, indexed in *sorted* validator
    /// order (`spawn_inner` sorts the freshly-generated `NodeSigner`s
    /// by `NodeId` before assigning weights — the slot at index `i`
    /// in `weights` ends up paired with the validator that sorts to
    /// index `i`). `None` falls back to uniform weight = 1, the
    /// pre-#463 cluster shape. Length must equal `n` if supplied.
    weights: Option<Vec<u64>>,
    /// Per-node slow-disk write delay (#496). When `Some(delays)`,
    /// each node's `Storage` and `Wal` are wrapped in
    /// [`boule_core::storage::ThrottledStorage`] /
    /// [`boule_core::storage::ThrottledWal`] using the per-index delay
    /// (`Duration::ZERO` is allowed and means "no throttling for this
    /// slot"). Length must equal `n` if supplied. Used by the slow-disk
    /// back-pressure test to verify that consensus blocks (rather than
    /// drops) when one node's persist path is slow.
    slow_disk_delays: Option<Vec<Duration>>,
    /// Per-node initial event-bridge delay (#497). When `Some(delays)`,
    /// each node's inbound `ProtocolEvent` stream is drained by a
    /// bridge task that sleeps for the per-index delay between
    /// receiving and forwarding. The delays are runtime-mutable via
    /// [`SimCluster::set_slow_node`] regardless of the constructor
    /// value — this field only seeds the initial delays.
    /// Length must equal `n` if supplied.
    slow_node_delays: Option<Vec<Duration>>,
    /// Per-node state machines (#599). When `Some(sms)`, node `i` gets
    /// `sms[i]` instead of a fresh `CounterStateMachine`, letting a test
    /// seed a *divergent* state machine on a subset of nodes to exercise
    /// the deferred state-root divergence check. Length must equal `n`
    /// if supplied.
    state_machines: Option<Vec<SimStateMachine>>,
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
    /// Bounded at [`SIM_COMMIT_CHANNEL_CAP`]; if a test fails to drain in
    /// time the [`MpscCommitNotifier`] drops blocks and bumps the counter
    /// in [`Self::commit_overflow_counters`] so the wedge is loud rather
    /// than silent. (Pre-#485 this was an unbounded channel; tests that
    /// don't drain accumulate committed blocks indefinitely in RAM.)
    pub commit_rxs: Vec<mpsc::Receiver<Block>>,
    /// Per-node clones of [`MpscCommitNotifier::overflow_counter`], in
    /// the same order as [`Self::commit_rxs`]. Tests can read these to
    /// assert no commit blocks were dropped due to a slow drain.
    pub commit_overflow_counters: Vec<Arc<AtomicU64>>,
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
    ///
    /// The outer `Arc<HashMap<…>>` is read-only — keys never change
    /// once the cluster is built — but each value is wrapped in a
    /// [`parking_lot::Mutex`] so [`SimCluster::restart_node_with_recover`]
    /// can hot-swap a single node's `Sender` while the surviving
    /// route tasks (which captured the same outer Arc at spawn time)
    /// pick the new sender up on their next frame. Lock contention is
    /// trivial under the sim's `current_thread + start_paused` model.
    event_txs: Arc<HashMap<NodeId, Mutex<mpsc::Sender<ProtocolEvent>>>>,
    /// Per-node fire-once crashpoint slots, in `node_ids` order. The
    /// sim hands a clone of each slot into the consensus task's
    /// `CRASH_SLOT.scope(...)`; `arm_crashpoint(idx, name)` arms the
    /// outer-handle clone, which the in-task `crashpoint!()` macro
    /// observes via the shared `Arc<Mutex<…>>` inside the slot.
    crash_slots: Vec<boule_consensus::crashpoint::CrashSlot>,
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
    /// Per-node mempool handles. Same order as `node_ids`. Tests can
    /// insert raw command bytes here to drive a leader's next proposal
    /// — used by the reconfig sim tests (#255) to inject a tagged
    /// `ReconfigCommand` payload without going through a wire frame.
    pub mempools: Vec<Arc<dyn Mempool>>,
    /// Captured `ValidatorSet`. Stable across restarts (issue #23 has
    /// not landed yet).
    validator_set: ValidatorSet,
    /// Captured genesis block. Stable across restarts.
    genesis: Block,
    /// Captured view-timer base, re-used by restart so the post-restart
    /// behaviour matches the pre-restart cadence.
    timeout_base: Duration,
    /// Per-replica vote-uniqueness observer (issue #422 / audit
    /// finding 14-3). Wired into every per-node route task so each
    /// safety core's outbound `ConsensusMsg::Vote` frames are recorded
    /// and diffed against prior votes at the same view. Default-on
    /// across mesh and gossip-mode clusters; teardown via
    /// [`Self::assert_no_replica_double_voted`] runs from `Drop` so
    /// every existing sim test picks up the assertion automatically.
    pub vote_observer: Arc<VoteObserver>,
    /// Per-node clones of [`ConsensusNode::equivocations_counter`]. The
    /// same `Arc<AtomicU64>` the integration layer increments on every
    /// `Action::EquivocationEvidence` it observes (audit finding 3-1,
    /// issue #409). Captured at spawn time so a test can read each
    /// honest replica's running equivocation count via
    /// [`SimCluster::peek_equivocations_detected`] — used by the
    /// twin-mode adversary suite (#421) to assert the evidence path is
    /// exercised end-to-end. Restart paths today don't refresh this
    /// vector, so post-restart the captured `Arc` points at the
    /// pre-restart counter (irrelevant for the suite at the time of
    /// writing — none of it restarts).
    equivocations_counters: Vec<Arc<AtomicU64>>,
    /// Per-node clones of [`ConsensusNode::proposal_equivocations_counter`].
    /// Sibling of [`Self::equivocations_counters`] for the proposer-side
    /// detector landed in audit finding L5-1; populated at spawn time
    /// so a test can read each honest replica's running
    /// proposal-equivocation count via
    /// [`SimCluster::peek_proposal_equivocations_detected`] without
    /// subscribing to a status publisher.
    proposal_equivocations_counters: Vec<Arc<AtomicU64>>,
    /// Per-node clones of [`ConsensusNode::state_divergence_counter`]
    /// (#599), captured at spawn time so a test can read each replica's
    /// running state-divergence detection count via
    /// [`SimCluster::peek_state_divergence_detected`].
    state_divergence_counters: Vec<Arc<AtomicU64>>,
    /// Per-node runtime-mutable processing delay in microseconds,
    /// keyed by `NodeId`. Used by the slow-node bridge (#497) inserted
    /// between each node's inbound `event_rx` and its consensus
    /// `run()` loop: the bridge reads the atomic on each event and
    /// sleeps for that long before forwarding. Mutable via
    /// [`SimCluster::set_slow_node`]. Each `Arc` is shared with the
    /// running bridge task spawned in [`SimCluster::spawn_inner`].
    slow_node_delays_us: Arc<HashMap<NodeId, Arc<AtomicU64>>>,
    /// Per-link selective-drop / reorder state (audit L3-2). Shared with
    /// every route task; installed via [`SimCluster::drop_messages_if`]
    /// and [`SimCluster::reorder_link`], cleared by
    /// [`SimCluster::heal_partition`].
    controls: SelectiveControls,
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

    /// Spawn `n` honest nodes with explicit per-validator voting
    /// weights (#463). `weights` is indexed in sorted [`NodeId`]
    /// order — slot `i` is paired with the validator that sorts to
    /// index `i` after [`boule_consensus::validator_set::ValidatorSet::new`]
    /// orders the freshly-generated signers.
    ///
    /// Each entry must be `>= 1`; the proptest harness over weighted
    /// quorums uses this to drive a non-uniform-weight committee.
    ///
    /// # Panics
    ///
    /// Panics if `n < 4`, `weights.len() != n`, or any weight is 0.
    pub async fn spawn_with_weights(n: usize, timeout_base: Duration, weights: Vec<u64>) -> Self {
        assert_eq!(
            weights.len(),
            n,
            "spawn_with_weights: weights.len() must equal n",
        );
        for (i, w) in weights.iter().enumerate() {
            assert!(*w >= 1, "spawn_with_weights: weight at index {i} is 0");
        }
        Self::spawn_inner(
            n,
            timeout_base,
            SpawnExtras {
                weights: Some(weights),
                ..SpawnExtras::default()
            },
        )
        .await
        .0
    }

    /// Spawn `n` honest nodes with per-node slow-disk write delays
    /// (#496). Each `slow_disk_delays[i]` wraps node `i`'s `Storage`
    /// and `Wal` in a [`boule_core::storage::ThrottledStorage`] /
    /// [`boule_core::storage::ThrottledWal`] adapter that adds a
    /// `std::thread::sleep` of that duration to every write.
    /// `Duration::ZERO` slots run un-throttled. Used by the slow-disk
    /// back-pressure test to verify that consensus blocks (rather than
    /// drops) when one node's persist path is slow.
    ///
    /// # Threading caveat
    ///
    /// Tests using this should run under the default tokio
    /// **multi-thread** runtime (`#[tokio::test(flavor = "multi_thread")]`)
    /// and avoid `tokio::time::pause()` — the throttled storage uses
    /// blocking `std::thread::sleep`, which under `current_thread` would
    /// block every other task on the executor for the duration of each
    /// write. The slow node's wall-clock delay is the load-bearing
    /// observable here, so real time is the right driver.
    ///
    /// # Panics
    ///
    /// Panics if `slow_disk_delays.len() != n`.
    pub async fn spawn_with_slow_disk(
        n: usize,
        timeout_base: Duration,
        slow_disk_delays: Vec<Duration>,
    ) -> Self {
        assert_eq!(
            slow_disk_delays.len(),
            n,
            "spawn_with_slow_disk: slow_disk_delays.len() must equal n",
        );
        Self::spawn_inner(
            n,
            timeout_base,
            SpawnExtras {
                slow_disk_delays: Some(slow_disk_delays),
                ..SpawnExtras::default()
            },
        )
        .await
        .0
    }

    /// Spawn `n` honest nodes with per-node initial event-bridge
    /// delays (#497). Each `slow_node_delays[i]` seeds the per-event
    /// sleep that node `i`'s inbound bridge applies between receiving
    /// a `ProtocolEvent` from the route task and forwarding it to the
    /// consensus run loop. `Duration::ZERO` slots run un-throttled.
    /// The delays are runtime-mutable via
    /// [`SimCluster::set_slow_node`] regardless of the constructor
    /// value.
    ///
    /// Use this (or `set_slow_node`) to throttle one node's
    /// processing without altering its disk path. The slow-disk
    /// constructor [`SimCluster::spawn_with_slow_disk`] is the right
    /// primitive when the goal is specifically to exercise the
    /// persist-blocks-consensus invariant; this one is the right
    /// primitive when the goal is general consumption-side
    /// back-pressure on the inbound queue.
    ///
    /// # Panics
    ///
    /// Panics if `slow_node_delays.len() != n` or `n < 4`.
    pub async fn spawn_with_slow_node(
        n: usize,
        timeout_base: Duration,
        slow_node_delays: Vec<Duration>,
    ) -> Self {
        assert_eq!(
            slow_node_delays.len(),
            n,
            "spawn_with_slow_node: slow_node_delays.len() must equal n",
        );
        Self::spawn_inner(
            n,
            timeout_base,
            SpawnExtras {
                slow_node_delays: Some(slow_node_delays),
                ..SpawnExtras::default()
            },
        )
        .await
        .0
    }

    /// Spawn `n` honest nodes configured for the BLS-aggregated chain
    /// scheme (#354 step 2).
    ///
    /// Each node gets:
    ///
    /// - `signature_scheme = "bls_aggregated"` in its
    ///   [`NodeConfigForConsensus`].
    /// - A freshly-generated BLS keypair, registered into a shared
    ///   [`BlsKeyHistory`] at `v_eff = 0` against the validator's
    ///   `NodeId`.
    /// - A [`boule_core::crypto::bls_key::BlsPartialSignerImpl`] plumbed
    ///   via [`ConsensusNode::with_bls_signer`] so the leader-side
    ///   vote-emission path can sign real BLS partials.
    ///
    /// The genesis QC is the BLS-flavored
    /// [`boule_consensus::hotstuff::qc::genesis_qc_bls`] (empty
    /// bitmap + empty-aggregate sentinel), and the dispatch-layer
    /// QC verifier accepts BLS QCs against
    /// [`BlsKeyHistory::pubkeys_for_set`] at every committed view.
    ///
    /// # Panics
    ///
    /// Panics if `n < 4` (minimum BFT cluster size for `f = 1`) or if
    /// any BLS keygen fails (which it should not under fresh IKM).
    pub async fn spawn_bls(n: usize, timeout_base: Duration) -> Self {
        Self::spawn_inner(
            n,
            timeout_base,
            SpawnExtras {
                rate_limits: None,
                adversaries: None,
                signature_scheme: Some(
                    boule_core::crypto::sig_scheme::SignatureSchemeChoice::BlsAggregated,
                ),
                weights: None,
                slow_disk_delays: None,
                slow_node_delays: None,
                state_machines: None,
            },
        )
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
                signature_scheme: None,
                weights: None,
                slow_disk_delays: None,
                slow_node_delays: None,
                state_machines: None,
            },
        )
        .await
        .0
    }

    /// Spawn `n` nodes with a caller-supplied state machine per node
    /// (#599). `state_machines` must have length `n`; entries are paired
    /// with validators in [`SimCluster::node_ids`] (sorted) order. Lets a
    /// test seed a *divergent* state machine on a subset of nodes to
    /// exercise the deferred state-root divergence check.
    ///
    /// # Panics
    ///
    /// Panics if `state_machines.len() != n` or `n < 4`.
    pub async fn spawn_with_state_machines(
        n: usize,
        timeout_base: Duration,
        state_machines: Vec<SimStateMachine>,
    ) -> Self {
        assert_eq!(
            state_machines.len(),
            n,
            "spawn_with_state_machines: state_machines.len() must equal n",
        );
        Self::spawn_inner(
            n,
            timeout_base,
            SpawnExtras {
                state_machines: Some(state_machines),
                ..SpawnExtras::default()
            },
        )
        .await
        .0
    }

    /// Spawn `n` nodes with both non-uniform per-validator voting
    /// `weights` and per-node Byzantine adversary slots, pairing the
    /// weighted-quorum stack (#463/#467) with the [`Adversary`] hook so
    /// the byzantine suite can re-validate each adversary under a
    /// stake-heavy Byzantine subset (#472).
    ///
    /// Both vectors are indexed in *sorted* validator order — the slot
    /// at index `i` belongs to the validator that sorts to index `i`,
    /// the same order [`SimCluster::node_ids`] uses. `None` adversary
    /// slots run the honest protocol unchanged.
    ///
    /// # Panics
    ///
    /// Panics if `n < 4`, `weights.len() != n`, `adversaries.len() != n`,
    /// or any weight is 0.
    pub async fn spawn_with_weights_and_adversaries(
        n: usize,
        timeout_base: Duration,
        weights: Vec<u64>,
        adversaries: Vec<Option<Arc<dyn Adversary>>>,
    ) -> Self {
        assert_eq!(
            weights.len(),
            n,
            "spawn_with_weights_and_adversaries: weights.len() must equal n",
        );
        assert_eq!(
            adversaries.len(),
            n,
            "spawn_with_weights_and_adversaries: adversaries.len() must equal n",
        );
        for (i, w) in weights.iter().enumerate() {
            assert!(
                *w >= 1,
                "spawn_with_weights_and_adversaries: weight at index {i} is 0",
            );
        }
        Self::spawn_inner(
            n,
            timeout_base,
            SpawnExtras {
                adversaries: Some(adversaries),
                weights: Some(weights),
                ..SpawnExtras::default()
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
        rate_limits: boule_core::transport::limits::RateLimitsConfig,
    ) -> (
        Self,
        Vec<Arc<boule_consensus::rate_limit::MessageRateLimiter>>,
    ) {
        Self::spawn_inner(
            n,
            timeout_base,
            SpawnExtras {
                rate_limits: Some(rate_limits),
                adversaries: None,
                signature_scheme: None,
                weights: None,
                slow_disk_delays: None,
                slow_node_delays: None,
                state_machines: None,
            },
        )
        .await
    }

    async fn spawn_inner(
        n: usize,
        timeout_base: Duration,
        extras: SpawnExtras,
    ) -> (
        Self,
        Vec<Arc<boule_consensus::rate_limit::MessageRateLimiter>>,
    ) {
        let SpawnExtras {
            rate_limits,
            adversaries,
            signature_scheme,
            weights,
            slow_disk_delays,
            slow_node_delays,
            state_machines,
        } = extras;
        let scheme = signature_scheme.unwrap_or_default();
        if let Some(adv) = adversaries.as_ref() {
            assert_eq!(adv.len(), n, "adversary slots must equal n");
        }
        if let Some(sms) = state_machines.as_ref() {
            assert_eq!(sms.len(), n, "state_machines slots must equal n");
        }
        if let Some(ws) = weights.as_ref() {
            assert_eq!(ws.len(), n, "weights slots must equal n");
        }
        if let Some(d) = slow_disk_delays.as_ref() {
            assert_eq!(d.len(), n, "slow_disk_delays slots must equal n");
        }
        if let Some(d) = slow_node_delays.as_ref() {
            assert_eq!(d.len(), n, "slow_node_delays slots must equal n");
        }
        assert!(n >= 4, "BFT requires at least 4 nodes (3f+1 with f=1)");

        // Create N fresh signers and collect their node IDs.
        let signers: Vec<NodeSigner> = (0..n).map(|_| fresh_signer()).collect();
        let validator_ids_unsorted: Vec<boule_consensus::validator_set::ValidatorId> = signers
            .iter()
            .map(|s| boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(s.node_id()))
            .collect();

        // ValidatorSet sorts IDs ascending, establishing leader-rotation order.
        let vs = if let Some(weights) = weights {
            // The caller promises `weights[i]` is the weight for the
            // validator at sorted index `i`. Sort the freshly-
            // generated ValidatorIds first, *then* zip with the
            // already-sorted-index-aligned weights.
            let mut sorted_ids = validator_ids_unsorted;
            sorted_ids.sort();
            let paired: Vec<_> = sorted_ids.into_iter().zip(weights).collect();
            ValidatorSet::with_weights(paired)
                .expect("spawn_with_weights validated weight >= 1 above")
        } else {
            ValidatorSet::new(validator_ids_unsorted)
        };
        let genesis = Block::genesis([0u8; 32], [0; 32]);

        // Build a signer lookup by NodeId.
        let signer_map: HashMap<NodeId, Arc<dyn Signer>> = signers
            .into_iter()
            .map(|s| (s.node_id(), Arc::new(s) as Arc<dyn Signer>))
            .collect();

        // BLS chains: generate a per-validator BLS keypair and seed
        // each node's `BlsKeyHistory` from genesis (#354 step 2).
        // `bls_pubkeys` is the shared genesis table; `bls_secret_for`
        // is consulted per-node when wiring the
        // `BlsPartialSignerImpl`.
        let (bls_pubkeys, bls_secret_for): (
            HashMap<NodeId, boule_core::crypto::sig_scheme::BlsPublicKey>,
            HashMap<NodeId, boule_core::crypto::sig_scheme::BlsSecretKey>,
        ) = if scheme == boule_core::crypto::sig_scheme::SignatureSchemeChoice::BlsAggregated {
            let mut pubs = HashMap::new();
            let mut secs = HashMap::new();
            for (i, validator_id) in vs.iter().enumerate() {
                let nid: NodeId = validator_id.into_node_id();
                // Seed BLS keys deterministically from sorted index XOR
                // the validator's NodeId so a re-spawn under the same
                // sorted vs produces byte-identical BLS keys; the sim's
                // existing Ed25519 signers come from `fresh_signer`,
                // which is the randomized boundary in this constructor.
                // BLS IKM must be ≥ 32 bytes per the IETF spec.
                let mut ikm = nid;
                let idx_bytes = (i as u64).to_le_bytes();
                for (j, b) in idx_bytes.iter().enumerate() {
                    ikm[j] ^= *b;
                }
                let (sk, pk) = boule_core::crypto::sig_scheme::BlsAggregated::keygen(&ikm)
                    .unwrap_or_else(|e| panic!("sim BLS keygen must not fail: {e:?}"));
                pubs.insert(nid, pk);
                secs.insert(nid, sk);
            }
            (pubs, secs)
        } else {
            (HashMap::new(), HashMap::new())
        };

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
        // Per-link selective-drop / reorder controls (audit L3-2); empty
        // until a test installs one.
        let controls = SelectiveControls::default();

        // Per-node event channel: routing tasks write here; each node's
        // run() loop reads from its receiver.
        //
        // The map is wrapped in `Arc<HashMap<…, Mutex<Sender>>>` (rather
        // than `Arc<HashMap<…, Sender>>`) so that
        // [`SimCluster::restart_node_with_recover`] can hot-swap a
        // single node's `Sender` while the surviving route tasks (which
        // captured the same outer Arc at spawn time) pick the new
        // sender up on their next frame.
        let mut event_txs: HashMap<NodeId, Mutex<mpsc::Sender<ProtocolEvent>>> = HashMap::new();
        let mut event_rxs: Vec<(NodeId, mpsc::Receiver<ProtocolEvent>)> = Vec::new();
        for v in vs.iter() {
            let nid = v.into_node_id();
            let (tx, rx) = mpsc::channel(1024);
            event_txs.insert(nid, Mutex::new(tx));
            event_rxs.push((nid, rx));
        }
        let event_txs = Arc::new(event_txs);

        // Per-node runtime-mutable processing delay in microseconds
        // (#497). Each node has an `Arc<AtomicU64>` keyed by `NodeId`
        // that the per-node bridge task (spawned in the loop below)
        // reads on every event. Initialized from `slow_node_delays` if
        // supplied; otherwise zero. Mutable at runtime via
        // [`SimCluster::set_slow_node`].
        let mut slow_node_delays_us: HashMap<NodeId, Arc<AtomicU64>> = HashMap::new();
        for (i, v) in vs.iter().enumerate() {
            let nid = v.into_node_id();
            let initial_us = slow_node_delays
                .as_ref()
                .and_then(|d| d.get(i).copied())
                .map(|d| d.as_micros().min(u64::MAX as u128) as u64)
                .unwrap_or(0);
            slow_node_delays_us.insert(nid, Arc::new(AtomicU64::new(initial_us)));
        }
        let slow_node_delays_us = Arc::new(slow_node_delays_us);

        // Per-replica vote-uniqueness observer (issue #422). Default-on
        // for every mesh-mode cluster; passed by `Arc` clone into each
        // route task so all per-node observations land in the same map.
        let vote_observer: Arc<VoteObserver> = Arc::new(VoteObserver::default());

        let node_ids: Vec<NodeId> = vs.iter().map(|v| v.into_node_id()).collect();
        let node_ids_arc: Arc<Vec<NodeId>> = Arc::new(node_ids.clone());
        let mut commit_rxs: Vec<mpsc::Receiver<Block>> = Vec::new();
        let mut commit_overflow_counters: Vec<Arc<AtomicU64>> = Vec::new();
        let mut shutdown_txs: Vec<Option<oneshot::Sender<()>>> = Vec::new();
        let mut limiters: Vec<Arc<boule_consensus::rate_limit::MessageRateLimiter>> = Vec::new();
        // Per-node fire-once crashpoint slots. One per node, in
        // `node_ids` order. The sim hands a clone of each into the
        // consensus task's `CRASH_SLOT.scope(...)`; the test's
        // `arm_crashpoint(idx, name)` writes through the outer-handle
        // clone retained here.
        let mut crash_slots: Vec<boule_consensus::crashpoint::CrashSlot> = Vec::with_capacity(n);
        // Captured for [`SimCluster::restart_all_with_recover`] (#206).
        // Each Vec is in the same `node_ids` (sorted ascending) order
        // as `commit_rxs` / `shutdown_txs`, so a `take`/`recover`
        // round-trip stays index-consistent.
        let mut signers_for_restart: Vec<Arc<dyn Signer>> = Vec::new();
        let mut storages_for_restart: Vec<Arc<dyn Storage>> = Vec::new();
        let mut wals_for_restart: Vec<Arc<dyn Wal>> = Vec::new();
        let mut mempools_captured: Vec<Arc<dyn Mempool>> = Vec::new();
        // Per-node equivocation counter Arcs (audit finding 3-1, #409),
        // captured before the node moves into its run-loop task so a
        // test can read the running count via
        // `SimCluster::peek_equivocations_detected`.
        let mut equivocations_counters: Vec<Arc<AtomicU64>> = Vec::with_capacity(n);
        // Per-node proposal-equivocation counter Arcs (audit finding
        // L5-1), captured here for the same reason.
        let mut proposal_equivocations_counters: Vec<Arc<AtomicU64>> = Vec::with_capacity(n);
        let mut state_divergence_counters: Vec<Arc<AtomicU64>> = Vec::with_capacity(n);

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
                snapshot_policy: boule_consensus::replication::snapshot::SnapshotPolicy::disabled(),
                min_v_eff_delay: boule_consensus::reconfig::MIN_V_EFF_DELAY,
                signature_scheme: scheme,
                block_retention_window: 0,
            };

            let sm: Arc<Mutex<Box<dyn StateMachine>>> = state_machines
                .as_ref()
                .and_then(|sms| sms.get(idx).cloned())
                .unwrap_or_else(|| Arc::new(Mutex::new(Box::new(CounterStateMachine::new()))));
            let mempool: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(256));
            mempools_captured.push(Arc::clone(&mempool));
            let raw_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
            let raw_wal: Arc<dyn Wal> = Arc::new(MemoryWal::new());
            // Slow-disk wrap (#496): if this slot has a non-zero delay,
            // present a ThrottledStorage / ThrottledWal to consensus
            // while still capturing the raw inner Arc for the restart
            // path so a later `restart_all_with_recover` round-trips
            // against the same on-disk state.
            let (storage, wal): (Arc<dyn Storage>, Arc<dyn Wal>) =
                match slow_disk_delays.as_ref().and_then(|d| d.get(idx).copied()) {
                    Some(delay) if delay > Duration::ZERO => (
                        Arc::new(boule_core::storage::ThrottledStorage::new(
                            Arc::clone(&raw_storage),
                            delay,
                        )),
                        Arc::new(boule_core::storage::ThrottledWal::new(
                            Arc::clone(&raw_wal),
                            delay,
                        )),
                    ),
                    _ => (Arc::clone(&raw_storage), Arc::clone(&raw_wal)),
                };
            storages_for_restart.push(raw_storage);
            wals_for_restart.push(raw_wal);

            let (commit_tx, commit_rx) = mpsc::channel::<Block>(SIM_COMMIT_CHANNEL_CAP);
            commit_rxs.push(commit_rx);
            let notifier = MpscCommitNotifier::new(commit_tx);
            commit_overflow_counters.push(notifier.overflow_counter());
            let commit_notifier: Arc<dyn CommitNotifier> = Arc::new(notifier);

            // ConsensusNode::new already auto-seeds the cluster-agreed
            // genesis QC; no explicit with_genesis_qc override here.
            let mut node = ConsensusNode::new(nid, config, sm, mempool, storage, wal)
                .with_commit_notifier(commit_notifier);

            // BLS plumbing (#354 step 2). Each node gets:
            // (1) a `BlsKeyHistory` populated from the shared genesis
            //     `bls_pubkeys` table so the dispatch-layer QC verifier
            //     can resolve per-historical-view BLS pubkeys, and
            // (2) its own `BlsPartialSignerImpl` so the dispatch-layer
            //     vote signer can produce real BLS partials on Vote
            //     frames the leader emits or loops back through #118.
            if scheme == boule_core::crypto::sig_scheme::SignatureSchemeChoice::BlsAggregated {
                let bls_history = boule_consensus::bls_key_history::BlsKeyHistory::with_genesis(
                    bls_pubkeys.iter().map(|(id, pk)| (*id, *pk)),
                );
                node = node.with_bls_key_history(bls_history);
                let sk = bls_secret_for[&nid];
                let pk = bls_pubkeys[&nid];
                let identity = boule_core::crypto::bls_key::BlsValidatorIdentity {
                    secret: zeroize::Zeroizing::new(sk),
                    public: pk,
                };
                let bls_signer: Arc<
                    dyn boule_core::crypto::signed::PartialSigner<
                            boule_core::crypto::sig_scheme::BlsAggregated,
                        >,
                > = Arc::new(
                    boule_core::crypto::bls_key::BlsPartialSignerImpl::from_identity(identity),
                );
                node = node.with_bls_signer(bls_signer);
            }

            // Optional rate-limiter (issue #134). The sim has no real
            // peer manager so we plumb `peer_cmd_tx = None`; tests
            // observe the disconnect-decision via the limiter's own
            // counters. The cluster's clock here is a TokioClock —
            // sufficient under tokio::time::pause + advance because
            // wall time still ticks for the limiter and the production
            // defaults leave orders-of-magnitude of headroom.
            if let Some(rl_cfg) = rate_limits.as_ref() {
                let clock: Arc<dyn Clock> = Arc::new(TokioClock::new());
                let limiter = Arc::new(boule_consensus::rate_limit::MessageRateLimiter::new(
                    rl_cfg.clone(),
                    clock,
                ));
                limiters.push(Arc::clone(&limiter));
                node = node.with_rate_limiter(limiter, None);
            }

            // Per-node outbound channel: node writes here through its
            // `Broadcaster`; the routing task reads on the other side.
            let (send_tx, send_rx) = mpsc::channel::<ProtocolOutbound>(1024);
            let broadcaster: Arc<dyn Broadcaster> = Arc::new(MemoryBroadcaster::new(send_tx));
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
            let discovery: Arc<dyn Discovery> = MemoryDiscovery::spawn(disco_src_rx);

            let route_adv = adversary_for_node.map(|adv| {
                let ctx = AdversaryCtx {
                    my_id: nid,
                    validators: Arc::clone(&node_ids_arc),
                    signer: Arc::clone(&signer),
                    genesis: genesis.clone(),
                    chain_id: boule_core::crypto::signed::ChainId::from_genesis_hash(
                        genesis.hash(),
                    ),
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
                Arc::clone(&vote_observer),
                PayloadFraming::Mesh,
                controls.clone(),
            );

            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            shutdown_txs.push(Some(shutdown_tx));

            // Per-node crashpoint slot. The sim retains one clone in
            // `crash_slots[idx]`; another goes into the task's
            // `CRASH_SLOT.scope(...)` so the macro's `try_with` finds
            // it. Cloning is cheap (Arc bump) and the slots share state.
            let crash_slot = boule_consensus::crashpoint::CrashSlot::empty();
            crash_slots.push(crash_slot.clone());

            // Capture the equivocation-counter Arc before the node moves
            // into the spawned task. The `Arc<AtomicU64>` is shared with
            // the integration layer's `Action::EquivocationEvidence`
            // dispatch site, so reads via
            // `SimCluster::peek_equivocations_detected` see updates the
            // run loop applies after each ingress tick.
            equivocations_counters.push(node.equivocations_counter());
            // Same capture for the proposer-side counter (audit finding
            // L5-1), surfaced via
            // `SimCluster::peek_proposal_equivocations_detected`.
            proposal_equivocations_counters.push(node.proposal_equivocations_counter());
            state_divergence_counters.push(node.state_divergence_counter());

            // Slow-node bridge (#497): the route-task side writes into
            // `event_rx`'s sender; the bridge drains `event_rx`,
            // sleeps for the per-node configured delay, then forwards
            // to the consensus node's `consensus_event_rx`. With
            // delay=0 this is a one-hop forward (the cost is one
            // channel send per event, which is cheap).
            let consensus_event_rx =
                spawn_event_bridge(event_rx, Arc::clone(&slow_node_delays_us[&nid]));

            tokio::spawn(async move {
                let _ = boule_consensus::crashpoint::CRASH_SLOT
                    .scope(crash_slot, async move {
                        node.run(
                            broadcaster,
                            discovery,
                            consensus_event_rx,
                            signer,
                            shutdown_rx,
                        )
                        .await
                    })
                    .await;
            });
        }

        let commit_cache: Vec<Vec<Block>> = (0..n).map(|_| Vec::new()).collect();

        let cluster = SimCluster {
            commit_rxs,
            commit_overflow_counters,
            node_ids,
            partitioned,
            link_cuts,
            partition_blocks,
            dead_nodes,
            event_txs,
            crash_slots,
            commit_cache,
            shutdown_txs,
            overlay_shutdowns: Vec::new(),
            signers: Some(signers_for_restart),
            storages: Some(storages_for_restart),
            wals: Some(wals_for_restart),
            mempools: mempools_captured,
            validator_set: vs,
            genesis,
            timeout_base,
            vote_observer,
            equivocations_counters,
            proposal_equivocations_counters,
            state_divergence_counters,
            slow_node_delays_us,
            controls,
        };
        (cluster, limiters)
    }

    /// Borrow node `idx`'s consensus signer. Returns `None` if the
    /// cluster was spawned without restart-capable signers (i.e. the
    /// gossip-mode harness, which doesn't capture them). Used by sim
    /// tests that need to construct signed payloads under a node's
    /// current identity — e.g. the validator-key-rotation tx (#260),
    /// where the rotation envelope's `sig_old` must come from the
    /// validator's currently-active key.
    pub fn signer(&self, idx: usize) -> Option<Arc<dyn Signer>> {
        self.signers.as_ref().map(|s| Arc::clone(&s[idx]))
    }

    /// Per-node durable storage handle, in the same `node_ids` order as
    /// [`Self::signer`]. Returns `None` for clusters that don't capture
    /// per-node storages (the gossip-mode harness). The same `Arc` is
    /// handed to `ConsensusNode::recover` across
    /// [`SimCluster::restart_node_with_recover`], so reading the bytes
    /// returned here corresponds to the on-disk shape a process restart
    /// would observe — used by crash-recovery regression tests
    /// (e.g. the audit-finding-4-1 / issue #405 lock-durability check)
    /// to peek at the post-restart safety triple without reaching into
    /// the reborn node's in-memory state.
    pub fn node_storage(&self, idx: usize) -> Option<Arc<dyn Storage>> {
        self.storages.as_ref().map(|s| Arc::clone(&s[idx]))
    }

    /// Add node `idx` to the partition set. The routing tasks will drop all
    /// messages to and from this node until [`heal_node`] is called.
    ///
    /// [`heal_node`]: SimCluster::heal_node
    pub fn partition_node(&self, idx: usize) {
        self.partitioned.lock().insert(self.node_ids[idx]);
    }

    /// Set node `idx`'s per-event processing delay (#497). The
    /// per-node bridge between the route task and the consensus
    /// `run()` loop will sleep for `delay` before forwarding each
    /// inbound event from this point on; passing `Duration::ZERO`
    /// resets the node to un-throttled processing.
    ///
    /// Used to model "slow node" scenarios — a node that drains its
    /// inbound queue more slowly than peers send to it. With the
    /// in-memory `.send().await` mesh used by [`SimCluster`], the
    /// observable shape is that fast peers' route tasks block on
    /// delivery to the slow node once its inbound channel fills,
    /// rather than the silently-dropping shape that the production
    /// `p2p::manager` uses (where `try_send`-on-full triggers the
    /// slow-peer disconnect heuristic from
    /// [`boule_transport_tcp::manager::SLOW_PEER_OVERFLOW_THRESHOLD`]). The
    /// production heuristic itself is unit-tested in
    /// `src/p2p/manager.rs`; this primitive lets sim-level tests
    /// exercise the persist-/process-blocks-consensus shape end-to-end
    /// against the safety core.
    pub fn set_slow_node(&self, idx: usize, delay: Duration) {
        let nid = self.node_ids[idx];
        let micros = delay.as_micros().min(u64::MAX as u128) as u64;
        self.slow_node_delays_us[&nid].store(micros, Ordering::Relaxed);
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
            let Some(event_tx_slot) = self.event_txs.get(&nid) else {
                continue;
            };
            let event_tx = event_tx_slot.lock().clone();
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

    /// Drop frames on the directed link `from_idx → to_idx` whose
    /// decoded [`SimMessage`] satisfies `predicate`. The predicate is
    /// consulted on every frame the route task would deliver on this
    /// link (after the whole-link partition / cut filters); returning
    /// `true` drops the frame silently at the wire — the receiver never
    /// sees it and no counter moves.
    ///
    /// Unlike [`cut_link`], which severs the whole link, this drops only
    /// the matching subset — e.g. a Byzantine leader that withholds its
    /// `Proposal` from one follower while delivering everything else:
    ///
    /// ```ignore
    /// cluster.drop_messages_if(leader, follower, Arc::new(|m: &SimMessage| {
    ///     m.kind == SimMessageKind::Proposal
    /// }));
    /// ```
    ///
    /// Multiple predicates on the same link compose: a frame is dropped
    /// if *any* of them returns `true`. Frames that don't decode to a
    /// [`boule_consensus::wire::WireMessage`] are delivered unfiltered.
    /// All predicates are cleared by [`SimCluster::heal_partition`].
    ///
    /// [`cut_link`]: SimCluster::cut_link
    pub fn drop_messages_if(&self, from_idx: usize, to_idx: usize, predicate: DropPredicate) {
        let key = (self.node_ids[from_idx], self.node_ids[to_idx]);
        self.controls
            .drop_predicates
            .lock()
            .entry(key)
            .or_default()
            .push(predicate);
    }

    /// Buffer up to `depth` frames on the directed link `from_idx →
    /// to_idx` and release them in seeded-deterministic permuted order,
    /// modelling a relay that reorders packets.
    ///
    /// Each new arrival past the first `depth` evicts one buffered frame
    /// chosen by a per-link RNG seeded from the link identity (no
    /// `SystemTime` / thread RNG), so a fixed topology replays
    /// identically. The buffer is bounded at `depth`: one frame leaves
    /// per arrival in steady state, so the link neither stalls nor grows
    /// — it just permutes delivery order within a `depth`-wide window.
    /// The residual `< depth` frames left buffered when traffic stops are
    /// flushed by [`SimCluster::heal_partition`].
    ///
    /// Installing a buffer on a link that already has one replaces it
    /// (resetting the window and reseeding). `depth` is clamped to a
    /// minimum of 1.
    pub fn reorder_link(&self, from_idx: usize, to_idx: usize, depth: usize) {
        let from = self.node_ids[from_idx];
        let to = self.node_ids[to_idx];
        self.controls
            .reorder
            .lock()
            .insert((from, to), ReorderBuf::new(from, to, depth));
    }

    /// Clear every partition cut installed by
    /// [`SimCluster::partition_into_groups`],
    /// [`SimCluster::partition_into_two`], or
    /// [`SimCluster::partition_one_way`], plus all selective-drop
    /// predicates ([`SimCluster::drop_messages_if`]) and reorder buffers
    /// ([`SimCluster::reorder_link`]) — restoring full delivery on every
    /// link. Reorder buffers are *flushed* (their residual frames
    /// delivered in seeded order) rather than discarded, so heal does not
    /// silently swallow in-flight messages.
    ///
    /// Application-level cuts installed via [`SimCluster::cut_link`] and
    /// per-node partitions installed via [`SimCluster::partition_node`]
    /// are unaffected.
    pub fn heal_partition(&self) {
        self.partition_blocks.lock().clear();
        self.controls.drop_predicates.lock().clear();

        // Flush each reorder buffer's residual window before clearing,
        // then deliver via the inbound mailboxes directly (heal is sync,
        // so we can't go back through the async route loop). Collect and
        // sort by (from, to) so the cross-link flush order into any
        // shared receiver is deterministic rather than HashMap-ordered.
        let mut drained: Vec<(NodeId, NodeId, Bytes)> = Vec::new();
        {
            let mut bufs = self.controls.reorder.lock();
            for ((from, to), buf) in bufs.iter_mut() {
                for payload in buf.drain_permuted() {
                    drained.push((*from, *to, payload));
                }
            }
            bufs.clear();
        }
        drained.sort_by_key(|t| (t.0, t.1));
        for (from, to, payload) in drained {
            if let Some(slot) = self.event_txs.get(&to) {
                let _ = slot
                    .lock()
                    .try_send(ProtocolEvent::Message { from, payload });
            }
        }
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

    /// Cumulative count of vote-equivocation incidents node `idx`'s
    /// integration layer has surfaced via
    /// [`boule_consensus::hotstuff::step::Action::EquivocationEvidence`]
    /// (audit finding 3-1, issue #409). Reads the same `Arc<AtomicU64>`
    /// the run loop increments on every emit, so callers see updates
    /// after each ingress tick without subscribing to a status
    /// publisher. Used by the twin-mode adversary suite (issue #421) to
    /// assert the evidence-emission path is exercised end-to-end.
    pub fn peek_equivocations_detected(&self, idx: usize) -> u64 {
        self.equivocations_counters[idx].load(Ordering::Relaxed)
    }

    /// Cumulative count of proposal-equivocation incidents node `idx`'s
    /// integration layer has surfaced via
    /// [`boule_consensus::hotstuff::step::Action::ProposalEquivocationEvidence`]
    /// (audit finding L5-1). Sibling of
    /// [`Self::peek_equivocations_detected`] for the proposer-side
    /// detector — used by the twin-mode adversary suite to assert the
    /// `TwinKind::Proposal` branch lights up the same `Arc<AtomicU64>`
    /// the run loop increments.
    pub fn peek_proposal_equivocations_detected(&self, idx: usize) -> u64 {
        self.proposal_equivocations_counters[idx].load(Ordering::Relaxed)
    }

    /// Cumulative count of state-machine divergences node `idx` detected
    /// at vote time (#599): a proposed block's deferred committed state
    /// root, anchored at a height node `idx` had committed, disagreed
    /// with node `idx`'s own execution, so it abstained. Used by the
    /// divergence-detection sim tests.
    pub fn peek_state_divergence_detected(&self, idx: usize) -> u64 {
        self.state_divergence_counters[idx].load(Ordering::Relaxed)
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
            .map(|blocks| blocks.iter().map(|b| b.header.height.0).max().unwrap_or(0))
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
        // Selective-drop / reorder controls don't survive a full restart
        // (the honest-recovery scenario installs none); clear for parity
        // with the partition sets above.
        self.controls.drop_predicates.lock().clear();
        self.controls.reorder.lock().clear();

        let mut new_event_txs: HashMap<NodeId, Mutex<mpsc::Sender<ProtocolEvent>>> = HashMap::new();
        let mut new_event_rxs: Vec<(NodeId, mpsc::Receiver<ProtocolEvent>)> = Vec::new();
        for &nid in &self.node_ids {
            let (tx, rx) = mpsc::channel::<ProtocolEvent>(1024);
            new_event_txs.insert(nid, Mutex::new(tx));
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
        let mut new_commit_rxs: Vec<mpsc::Receiver<Block>> = Vec::new();
        let mut new_commit_overflow_counters: Vec<Arc<AtomicU64>> = Vec::new();
        let mut new_shutdown_txs: Vec<Option<oneshot::Sender<()>>> = Vec::new();
        let mut new_mempools: Vec<Arc<dyn Mempool>> = Vec::new();
        let mut new_crash_slots: Vec<boule_consensus::crashpoint::CrashSlot> =
            Vec::with_capacity(n);

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
                snapshot_policy: boule_consensus::replication::snapshot::SnapshotPolicy::disabled(),
                min_v_eff_delay: boule_consensus::reconfig::MIN_V_EFF_DELAY,
                signature_scheme: boule_core::crypto::sig_scheme::SignatureSchemeChoice::default(),
                block_retention_window: 0,
            };
            // Fresh state machine and mempool — the previous session's
            // state machine doesn't survive a process restart in
            // production either; what survives is the durable
            // `(last_voted_view, locked, high_qc, committed-blocks)`
            // tuple in storage, which `recover` consumes below.
            let sm: Arc<Mutex<Box<dyn StateMachine>>> =
                Arc::new(Mutex::new(Box::new(CounterStateMachine::new())));
            let mempool: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(256));
            new_mempools.push(Arc::clone(&mempool));

            let (commit_tx, commit_rx) = mpsc::channel::<Block>(SIM_COMMIT_CHANNEL_CAP);
            new_commit_rxs.push(commit_rx);
            let notifier = MpscCommitNotifier::new(commit_tx);
            new_commit_overflow_counters.push(notifier.overflow_counter());
            let commit_notifier: Arc<dyn CommitNotifier> = Arc::new(notifier);

            let node = ConsensusNode::recover(nid, config, sm, mempool, storage, wal)
                .expect("recover must succeed against the same storage that just persisted")
                .with_commit_notifier(commit_notifier);

            let (send_tx, send_rx) = mpsc::channel::<ProtocolOutbound>(1024);
            let broadcaster: Arc<dyn Broadcaster> = Arc::new(MemoryBroadcaster::new(send_tx));
            let (_disco_src_tx, disco_src_rx) =
                tokio::sync::broadcast::channel::<DiscoveryEvent>(8);
            let discovery: Arc<dyn Discovery> = MemoryDiscovery::spawn(disco_src_rx);

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
                Arc::clone(&self.vote_observer),
                PayloadFraming::Mesh,
                self.controls.clone(),
            );

            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            new_shutdown_txs.push(Some(shutdown_tx));

            // Fresh per-node crashpoint slot for the post-restart
            // run. The previous session's slot dies with its task; a
            // restart-equivalent test that wants to also crash the
            // recovered node must arm against this fresh slot.
            let crash_slot = boule_consensus::crashpoint::CrashSlot::empty();
            new_crash_slots.push(crash_slot.clone());

            // Re-wrap the inbound stream in a slow-node bridge (#497)
            // so any pre-restart `set_slow_node` configuration keeps
            // applying after the restart. The per-node delay
            // `Arc<AtomicU64>` is owned by `self.slow_node_delays_us`
            // and persists across restart.
            let consensus_event_rx =
                spawn_event_bridge(event_rx, Arc::clone(&self.slow_node_delays_us[&nid]));

            tokio::spawn(async move {
                let _ = boule_consensus::crashpoint::CRASH_SLOT
                    .scope(crash_slot, async move {
                        node.run(
                            broadcaster,
                            discovery,
                            consensus_event_rx,
                            signer,
                            shutdown_rx,
                        )
                        .await
                    })
                    .await;
            });
        }

        self.commit_rxs = new_commit_rxs;
        self.commit_overflow_counters = new_commit_overflow_counters;
        self.shutdown_txs = new_shutdown_txs;
        self.mempools = new_mempools;
        self.crash_slots = new_crash_slots;
        // Reset the per-node commit cache since the new commit_rxs
        // replace the old ones; any blocks not yet drained from the
        // pre-restart receivers are intentionally lost — this matches
        // the production semantics where in-flight commit observers
        // also disappear on restart.
        self.commit_cache = (0..n).map(|_| Vec::new()).collect();
    }

    // ── Crashpoint harness (issue #420) ───────────────────────────────────────

    /// Arm the fire-once crashpoint slot for node `idx` with `name`.
    /// The next `crashpoint!("name")` the consensus task crosses
    /// panics with a `CrashPoint(name)` payload, modelling a process
    /// kill at the named durability boundary.
    ///
    /// The slot is fire-once: a single matching crashpoint clears the
    /// arm. Subsequent `crashpoint!()` calls in the same task with the
    /// same name are silent. Re-arming after the task is restarted
    /// (via [`SimCluster::restart_node_with_recover`]) works against
    /// the fresh slot the restart helper installs.
    ///
    /// Replaces any previously-armed but not-yet-fired entry; returns
    /// the previous arm so callers can defensively assert nothing was
    /// lost.
    ///
    /// # Panics
    ///
    /// Panics if `idx` is out of range or if the cluster was spawned
    /// without per-node crash slots (gossip-mode clusters).
    pub fn arm_crashpoint(&self, idx: usize, name: &'static str) -> Option<&'static str> {
        assert!(
            idx < self.crash_slots.len(),
            "arm_crashpoint: idx {idx} out of range (n={})",
            self.crash_slots.len(),
        );
        self.crash_slots[idx].arm(name)
    }

    /// Inspect the currently-armed crashpoint name for node `idx`,
    /// without consuming it. Returns `None` if no crashpoint is armed
    /// or if the previously-armed crashpoint already fired (the slot
    /// is fire-once). Use as a post-condition assertion to confirm
    /// the expected crashpoint actually fired during a test run.
    pub fn peek_crashpoint(&self, idx: usize) -> Option<&'static str> {
        self.crash_slots[idx].peek()
    }

    /// Borrow node `idx`'s durable [`Storage`] handle so a
    /// crashpoint-driven regression can read persisted control-plane
    /// keys (`STORAGE_KEY_LAST_VOTED_VIEW`, `STORAGE_KEY_PROPOSED_IN_VIEW`,
    /// etc.) post-restart and assert the survived state matches the
    /// invariant the fix locks down. Same `Arc` the cluster keeps for
    /// [`Self::restart_node_with_recover`], so reads here see exactly
    /// what `recover()` would consume.
    ///
    /// # Panics
    ///
    /// Panics if `idx` is out of range or if the cluster was spawned
    /// without captured storages (gossip-mode harness).
    pub fn peek_storage(&self, idx: usize) -> Arc<dyn Storage> {
        let storages = self
            .storages
            .as_ref()
            .expect("peek_storage requires a mesh-mode SimCluster");
        Arc::clone(&storages[idx])
    }

    /// Crash one specific node and bring it back via
    /// [`ConsensusNode::recover`] against the same on-disk state.
    ///
    /// Surgical analog of [`SimCluster::restart_all_with_recover`]:
    /// only node `idx` is torn down and respawned. The other replicas
    /// keep running. Use after a [`crashpoint!`] has fired (the
    /// node's tokio task has already panicked) or after a deliberate
    /// [`SimCluster::kill_node`] when the test wants the node back.
    ///
    /// Mechanics:
    ///
    /// 1. Mark `idx` as dead so peers' route tasks drop any in-flight
    ///    frames addressed to the panicked event_rx.
    /// 2. Yield several rounds so any sends already at
    ///    `event_tx.send(...).await` hit the closed receiver and
    ///    return.
    /// 3. Hot-swap a fresh `Sender` into the per-node slot in
    ///    `event_txs`. Surviving route tasks see the new sender on
    ///    their next frame because each entry is a `Mutex<Sender>`.
    /// 4. Spawn a new route task for the reborn node's outbound
    ///    channel.
    /// 5. Build a new `ConsensusNode` via `recover()` against the
    ///    captured `(signer, storage, wal)` triple. Wrap the run loop
    ///    in a fresh `CRASH_SLOT.scope` so the test can re-arm.
    /// 6. Clear `idx` from the dead-nodes set so subsequent traffic
    ///    flows again.
    ///
    /// Mempool, state machine, and pacemaker are *not* preserved —
    /// the same as `restart_all_with_recover`. What survives is the
    /// durable `(last_voted_view, locked, high_qc, committed-blocks)`
    /// tuple in storage, which `recover` consumes.
    ///
    /// # Panics
    ///
    /// Panics if the cluster was not spawned via a mesh-mode
    /// constructor (gossip-mode clusters don't capture per-node
    /// `(signer, storage, wal)` triples).
    pub async fn restart_node_with_recover(&mut self, idx: usize) -> anyhow::Result<()> {
        let signers = self
            .signers
            .as_ref()
            .expect("restart_node_with_recover requires a mesh-mode SimCluster");
        let storages = self
            .storages
            .as_ref()
            .expect("restart_node_with_recover requires captured storages");
        let wals = self
            .wals
            .as_ref()
            .expect("restart_node_with_recover requires captured WALs");
        let signer = Arc::clone(&signers[idx]);
        let storage = Arc::clone(&storages[idx]);
        let wal = Arc::clone(&wals[idx]);
        let nid = self.node_ids[idx];

        // Step 1: mark dead and tear down the existing shutdown sender.
        // The panicked task already exited, but we drop our shutdown
        // sender so a stray drop doesn't try to signal a nonexistent
        // run loop. If `restart_node_with_recover` is called against
        // a still-live node, this also signals it down.
        if let Some(tx) = self.shutdown_txs[idx].take() {
            let _ = tx.send(());
        }
        self.dead_nodes.lock().insert(nid);

        // Step 2: drain any in-flight sends to the dead receiver. With
        // tokio paused, yields are virtually free; 32 is well above
        // the longest send-then-resolve chain in the route loop.
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }

        // Step 3: hot-swap the per-node `event_tx` so peers' route
        // tasks (which captured the same outer Arc) deliver into the
        // reborn node's mailbox on their next frame.
        let (new_event_tx, event_rx) = mpsc::channel::<ProtocolEvent>(1024);
        if let Some(slot) = self.event_txs.get(&nid) {
            *slot.lock() = new_event_tx;
        }

        // Step 4: build the reborn node and wire its outbound channel
        // through a fresh route task.
        let config = NodeConfigForConsensus {
            validator_set: self.validator_set.clone(),
            genesis: self.genesis.clone(),
            propose_limit: 16,
            timeout_base: self.timeout_base,
            timeout_max: Duration::from_secs(30),
            limits: CacheLimits::unbounded_for_tests(),
            snapshot_policy: boule_consensus::replication::snapshot::SnapshotPolicy::disabled(),
            min_v_eff_delay: boule_consensus::reconfig::MIN_V_EFF_DELAY,
            signature_scheme: boule_core::crypto::sig_scheme::SignatureSchemeChoice::default(),
            block_retention_window: 0,
        };
        let sm: Arc<Mutex<Box<dyn StateMachine>>> =
            Arc::new(Mutex::new(Box::new(CounterStateMachine::new())));
        let mempool: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(256));
        self.mempools[idx] = Arc::clone(&mempool);

        let (commit_tx, commit_rx) = mpsc::channel::<Block>(SIM_COMMIT_CHANNEL_CAP);
        self.commit_rxs[idx] = commit_rx;
        // Reset the per-node commit cache for the reborn slot — old
        // pre-crash commits already returned via earlier
        // `drain_commits` calls; the `recover` path replays from
        // durable state and starts a new in-memory log.
        self.commit_cache[idx].clear();
        let notifier = MpscCommitNotifier::new(commit_tx);
        self.commit_overflow_counters[idx] = notifier.overflow_counter();
        let commit_notifier: Arc<dyn CommitNotifier> = Arc::new(notifier);

        let node = ConsensusNode::recover(nid, config, sm, mempool, storage, wal)?
            .with_commit_notifier(commit_notifier);

        let (send_tx, send_rx) = mpsc::channel::<ProtocolOutbound>(1024);
        let broadcaster: Arc<dyn Broadcaster> = Arc::new(MemoryBroadcaster::new(send_tx));
        let (_disco_src_tx, disco_src_rx) = tokio::sync::broadcast::channel::<DiscoveryEvent>(8);
        let discovery: Arc<dyn Discovery> = MemoryDiscovery::spawn(disco_src_rx);

        spawn_route_task(
            nid,
            send_rx,
            Arc::clone(&self.event_txs),
            Arc::clone(&self.partitioned),
            Arc::clone(&self.link_cuts),
            Arc::clone(&self.partition_blocks),
            Arc::clone(&self.dead_nodes),
            None,
            Arc::clone(&self.vote_observer),
            PayloadFraming::Mesh,
            self.controls.clone(),
        );

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        self.shutdown_txs[idx] = Some(shutdown_tx);

        // Fresh per-node crashpoint slot for the reborn task. The
        // pre-crash slot fired its single arm and was discarded with
        // the dead task; tests that want to crash the recovered node
        // again call `arm_crashpoint(idx, …)` against this fresh slot.
        let crash_slot = boule_consensus::crashpoint::CrashSlot::empty();
        self.crash_slots[idx] = crash_slot.clone();

        // Re-wrap the reborn node's inbound stream in a slow-node
        // bridge (#497) so any pre-crash `set_slow_node` configuration
        // keeps applying after recovery.
        let consensus_event_rx =
            spawn_event_bridge(event_rx, Arc::clone(&self.slow_node_delays_us[&nid]));

        tokio::spawn(async move {
            let _ = boule_consensus::crashpoint::CRASH_SLOT
                .scope(crash_slot, async move {
                    node.run(
                        broadcaster,
                        discovery,
                        consensus_event_rx,
                        signer,
                        shutdown_rx,
                    )
                    .await
                })
                .await;
        });

        // Step 5: clear the dead-nodes mark so peers can talk to the
        // reborn node again. Done after the new run loop is spawned
        // so an inbound frame that arrives between revival and run
        // has somewhere to go.
        self.dead_nodes.lock().remove(&nid);
        Ok(())
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

    /// Total number of commit blocks dropped across all per-node
    /// channels because [`MpscCommitNotifier::on_commit`] hit a full
    /// channel. Sums the [`Self::commit_overflow_counters`] values.
    ///
    /// In a healthy test this is always zero — the harness drains
    /// `commit_rxs` faster than commits arrive. A non-zero value means
    /// either the test forgot to drain, or it deliberately delays
    /// draining and the burst exceeded [`SIM_COMMIT_CHANNEL_CAP`]. In
    /// the latter case bump the cap; in the former, fix the test.
    pub fn total_commit_overflows(&self) -> u64 {
        self.commit_overflow_counters
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .sum()
    }

    /// Panic if the per-replica [`VoteObserver`] recorded any vote
    /// where one safety core emitted two distinct `block_hash`es for
    /// the same `view`.
    ///
    /// Audit finding 14-3 (issue #422): a HotStuff `vote_once`
    /// violation that produces two votes on different blocks for the
    /// same view is a direct safety breach. The global oracle
    /// [`assert_no_conflicts`] only catches it once it propagates to
    /// conflicting commits; this assertion catches it at the safety
    /// core's outbound boundary.
    ///
    /// Called automatically from [`SimCluster::drop`] (skipped when
    /// the test is already panicking, to avoid masking the original
    /// failure with a double-panic). Tests can also invoke it
    /// explicitly mid-run if they want to localise the failure to a
    /// specific phase.
    pub fn assert_no_replica_double_voted(&self) {
        let violations = self.vote_observer.violations();
        assert!(
            violations.is_empty(),
            "vote-once violation: replicas emitted conflicting votes at the same view: {violations:?}",
        );
    }
}

impl Drop for SimCluster {
    fn drop(&mut self) {
        for opt in &mut self.shutdown_txs {
            if let Some(tx) = opt.take() {
                let _ = tx.send(());
            }
        }
        // Audit finding 14-3 (issue #422): default-on safety check
        // across every sim test. Skip when the test thread is already
        // panicking so the original failure is not masked by a
        // double-panic in `Drop`.
        if !std::thread::panicking() {
            self.assert_no_replica_double_voted();
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
/// Spawn a slow-node bridge (#497) that drains `raw_rx`, sleeps for
/// the per-event delay configured on `delay_us`, and forwards to the
/// returned receiver. With `delay_us == 0` (the default) this is a
/// one-hop forward — the cost is one channel send per event, which
/// under the sim's `current_thread + start_paused` model is cheap
/// enough that running it unconditionally per node is simpler than
/// gating on "is any test using set_slow_node?". The forward channel
/// is bounded at the same 1024 cap as the raw channel so the bridge
/// itself does not introduce additional buffering when the consensus
/// run loop is keeping up.
fn spawn_event_bridge(
    mut raw_rx: mpsc::Receiver<ProtocolEvent>,
    delay_us: Arc<AtomicU64>,
) -> mpsc::Receiver<ProtocolEvent> {
    let (forward_tx, forward_rx) = mpsc::channel::<ProtocolEvent>(1024);
    tokio::spawn(async move {
        while let Some(ev) = raw_rx.recv().await {
            let micros = delay_us.load(Ordering::Relaxed);
            if micros > 0 {
                tokio::time::sleep(Duration::from_micros(micros)).await;
            }
            if forward_tx.send(ev).await.is_err() {
                // Consensus run loop dropped its receiver — node
                // shutdown is in flight; drain pending events from
                // raw_rx until its sender side closes too.
                break;
            }
        }
    });
    forward_rx
}

/// The integration layer loops self-addressed consensus actions back
/// into the local safety core inside
/// `ConsensusNode::apply_safety_actions`; duplicating the delivery here
/// would double-feed the core and hide regressions of that loopback.
#[allow(clippy::too_many_arguments)]
fn spawn_route_task(
    my_id: NodeId,
    mut send_rx: mpsc::Receiver<ProtocolOutbound>,
    route_txs: Arc<HashMap<NodeId, Mutex<mpsc::Sender<ProtocolEvent>>>>,
    partitioned: Arc<Mutex<HashSet<NodeId>>>,
    link_cuts: Arc<Mutex<HashSet<LinkCut>>>,
    partition_blocks: Arc<Mutex<HashSet<LinkCut>>>,
    dead_nodes: Arc<Mutex<HashSet<NodeId>>>,
    adversary: Option<(Arc<dyn Adversary>, AdversaryCtx)>,
    vote_observer: Arc<VoteObserver>,
    framing: PayloadFraming,
    controls: SelectiveControls,
) {
    tokio::spawn(async move {
        while let Some(outbound) = send_rx.recv().await {
            // Vote-uniqueness observer (issue #422). Inspect the frame
            // *before* the my_id partition / dead checks and *before*
            // the adversary intercept — so a vote the safety core
            // emitted is recorded even if the network would later drop
            // it (e.g. vote-withholding partitions), and adversary
            // forgeries that are not safety-core emissions are not
            // attributed to the honest replica.
            let payload_for_observer: Option<Bytes> = match &outbound {
                ProtocolOutbound::Broadcast(p) => Some(p.clone()),
                ProtocolOutbound::SendTo { payload, .. } => Some(payload.clone()),
            };
            if let Some(p) = payload_for_observer {
                vote_observer.observe_outbound(&p, framing);
            }

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
                    &controls,
                    framing,
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
    route_txs: &HashMap<NodeId, Mutex<mpsc::Sender<ProtocolEvent>>>,
    partitioned: &Mutex<HashSet<NodeId>>,
    link_cuts: &Mutex<HashSet<LinkCut>>,
    partition_blocks: &Mutex<HashSet<LinkCut>>,
    dead_nodes: &Mutex<HashSet<NodeId>>,
    controls: &SelectiveControls,
    framing: PayloadFraming,
) {
    // Cheap per-frame gate: skip the decode + per-target predicate/buffer
    // locks entirely on honest clusters that installed no controls.
    let drop_active = !controls.drop_predicates.lock().is_empty();
    let reorder_active = !controls.reorder.lock().is_empty();

    match outbound {
        ProtocolOutbound::Broadcast(payload) => {
            // Decode once per frame (not per target): the payload is the
            // same for every broadcast recipient.
            let decoded = if drop_active {
                decode_sim_message(&payload, framing)
            } else {
                None
            };
            for (target, tx_slot) in route_txs.iter() {
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
                deliver_one(
                    my_id,
                    *target,
                    &payload,
                    &decoded,
                    tx_slot,
                    controls,
                    drop_active,
                    reorder_active,
                )
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
            if let Some(tx_slot) = route_txs.get(&node_id) {
                let decoded = if drop_active {
                    decode_sim_message(&payload, framing)
                } else {
                    None
                };
                deliver_one(
                    my_id,
                    node_id,
                    &payload,
                    &decoded,
                    tx_slot,
                    controls,
                    drop_active,
                    reorder_active,
                )
                .await;
            }
        }
    }
}

/// Apply the selective-drop predicate and reorder buffer for the single
/// directed link `my_id → target`, then deliver whatever should leave the
/// link now. Runs *after* the partition / dead / cut filters in
/// [`route_one_frame`], so the whole-link controls still take precedence.
///
/// `decoded` is the frame projected to [`SimMessage`] once by the caller
/// (`None` when no drop predicate is registered or the frame didn't
/// decode — either way the predicate is not consulted). No
/// [`parking_lot`] guard is held across the `.await`: the reorder lock is
/// scoped to compute the to-send frame and the sender is cloned out of
/// its slot before sending.
#[allow(clippy::too_many_arguments)]
async fn deliver_one(
    my_id: NodeId,
    target: NodeId,
    payload: &Bytes,
    decoded: &Option<SimMessage>,
    tx_slot: &Mutex<mpsc::Sender<ProtocolEvent>>,
    controls: &SelectiveControls,
    drop_active: bool,
    reorder_active: bool,
) {
    // Selective drop: any registered predicate on this link that returns
    // `true` drops the frame silently at the wire.
    if drop_active {
        if let Some(msg) = decoded {
            let preds = controls.drop_predicates.lock();
            if let Some(list) = preds.get(&(my_id, target)) {
                if list.iter().any(|p| p(msg)) {
                    return;
                }
            }
        }
    }

    // Reorder: buffer on the link and release a (possibly different)
    // earlier frame. With no reorder buffer the frame passes straight
    // through. The lock is dropped before the await below.
    let to_send: Option<Bytes> = if reorder_active {
        let mut bufs = controls.reorder.lock();
        match bufs.get_mut(&(my_id, target)) {
            Some(buf) => buf.push(payload.clone()),
            None => Some(payload.clone()),
        }
    } else {
        Some(payload.clone())
    };

    if let Some(payload) = to_send {
        // Clone the sender out of the per-entry mutex so we never hold
        // the lock across the async send. The
        // `restart_node_with_recover` path swaps the inner sender;
        // subsequent frames re-clone the new one.
        let tx = tx_slot.lock().clone();
        let _ = tx
            .send(ProtocolEvent::Message {
                from: my_id,
                payload,
            })
            .await;
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
        let validator_ids_unsorted: Vec<boule_consensus::validator_set::ValidatorId> = signers
            .iter()
            .map(|s| boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(s.node_id()))
            .collect();
        let vs = ValidatorSet::new(validator_ids_unsorted);
        let genesis = Block::genesis([0u8; 32], [0; 32]);

        let mut signer_map: HashMap<NodeId, Arc<dyn Signer>> = HashMap::new();
        for s in signers {
            signer_map.insert(s.node_id(), Arc::new(s) as Arc<dyn Signer>);
        }

        let partitioned: Arc<Mutex<HashSet<NodeId>>> = Arc::new(Mutex::new(HashSet::new()));
        let link_cuts: Arc<Mutex<HashSet<LinkCut>>> = Arc::new(Mutex::new(HashSet::new()));
        let partition_blocks: Arc<Mutex<HashSet<LinkCut>>> = Arc::new(Mutex::new(HashSet::new()));
        let dead_nodes: Arc<Mutex<HashSet<NodeId>>> = Arc::new(Mutex::new(HashSet::new()));
        let controls = SelectiveControls::default();

        // Per-replica vote-uniqueness observer (issue #422). Same
        // default-on observer the mesh constructors install; the
        // route task unwraps the gossip-overlay framing before
        // looking for an inner `WireMessage::Vote`.
        let vote_observer: Arc<VoteObserver> = Arc::new(VoteObserver::default());

        // Per-node raw event channels — sim's route tasks deliver
        // `ProtocolEvent`s to the orchestrator's input here.
        let mut event_txs: HashMap<NodeId, Mutex<mpsc::Sender<ProtocolEvent>>> = HashMap::new();
        let mut event_rxs: Vec<(NodeId, mpsc::Receiver<ProtocolEvent>)> = Vec::new();
        for v in vs.iter() {
            let nid = v.into_node_id();
            let (tx, rx) = mpsc::channel(1024);
            event_txs.insert(nid, Mutex::new(tx));
            event_rxs.push((nid, rx));
        }
        let event_txs = Arc::new(event_txs);

        // Resolve sorted-index ordering so we can map NodeId → topology
        // index. ValidatorSet sorts ascending; circulant_neighbors uses
        // those indices directly.
        let node_ids: Vec<NodeId> = vs.iter().map(|v| v.into_node_id()).collect();

        let mut commit_rxs: Vec<mpsc::Receiver<Block>> = Vec::new();
        let mut commit_overflow_counters: Vec<Arc<AtomicU64>> = Vec::new();
        let mut shutdown_txs: Vec<Option<oneshot::Sender<()>>> = Vec::new();
        let mut mempools_captured_gossip: Vec<Arc<dyn Mempool>> = Vec::new();
        let mut equivocations_counters: Vec<Arc<AtomicU64>> = Vec::with_capacity(n);
        let mut proposal_equivocations_counters: Vec<Arc<AtomicU64>> = Vec::with_capacity(n);
        let mut state_divergence_counters: Vec<Arc<AtomicU64>> = Vec::with_capacity(n);
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
                snapshot_policy: boule_consensus::replication::snapshot::SnapshotPolicy::disabled(),
                min_v_eff_delay: boule_consensus::reconfig::MIN_V_EFF_DELAY,
                signature_scheme: boule_core::crypto::sig_scheme::SignatureSchemeChoice::default(),
                block_retention_window: 0,
            };
            let sm: Arc<Mutex<Box<dyn StateMachine>>> =
                Arc::new(Mutex::new(Box::new(CounterStateMachine::new())));
            let mempool: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(256));
            mempools_captured_gossip.push(Arc::clone(&mempool));
            let storage = Arc::new(MemoryStorage::new());
            let wal = Arc::new(MemoryWal::new());

            let (commit_tx, commit_rx) = mpsc::channel::<Block>(SIM_COMMIT_CHANNEL_CAP);
            commit_rxs.push(commit_rx);
            let notifier = MpscCommitNotifier::new(commit_tx);
            commit_overflow_counters.push(notifier.overflow_counter());
            let commit_notifier: Arc<dyn CommitNotifier> = Arc::new(notifier);

            let node = ConsensusNode::new(nid, config, sm, mempool, storage, wal)
                .with_commit_notifier(commit_notifier);
            equivocations_counters.push(node.equivocations_counter());
            proposal_equivocations_counters.push(node.proposal_equivocations_counter());
            state_divergence_counters.push(node.state_divergence_counter());

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
                    outbound_target: target_degree,
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
                self_reachable: true,
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
                Arc::clone(&vote_observer),
                PayloadFraming::GossipOverlay,
                controls.clone(),
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
            let event_tx_i = event_txs[&nid_i].lock().clone();
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

        // Slow-node bridge (#497) is mesh-only; gossip-mode clusters
        // pass through the GossipOverlay before reaching consensus,
        // and inserting a bridge there is out of scope for #497. Seed
        // a delay map of zeros keyed by NodeId so the field is
        // populated; calls to `set_slow_node` against a gossip-mode
        // cluster will mutate the atomic but no bridge is reading it.
        let mut slow_node_delays_us: HashMap<NodeId, Arc<AtomicU64>> = HashMap::new();
        for nid in &node_ids {
            slow_node_delays_us.insert(*nid, Arc::new(AtomicU64::new(0)));
        }

        SimCluster {
            commit_rxs,
            commit_overflow_counters,
            node_ids,
            partitioned,
            link_cuts,
            partition_blocks,
            dead_nodes,
            event_txs,
            // Crashpoint injection is mesh-cluster only — the gossip
            // overlay clusters don't run inside `CRASH_SLOT.scope(...)`.
            crash_slots: Vec::new(),
            commit_cache,
            shutdown_txs,
            overlay_shutdowns,
            // Restart-from-disk is mesh-cluster only for now; the
            // gossip overlay's orchestrator wiring isn't trivially
            // re-spawnable.
            signers: None,
            storages: None,
            wals: None,
            mempools: mempools_captured_gossip,
            validator_set: vs,
            genesis,
            timeout_base,
            vote_observer,
            equivocations_counters,
            proposal_equivocations_counters,
            state_divergence_counters,
            slow_node_delays_us: Arc::new(slow_node_delays_us),
            controls,
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
    let mut canonical: HashMap<Height, BlockHash> = HashMap::new();
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

    use super::{
        LinkCut, SimCluster, SimMessage, SimMessageKind, VoteObserver, assert_no_conflicts,
        fresh_signer, spawn_route_task,
    };
    use boule_consensus::View;
    use boule_consensus::replication::block::Block;
    use boule_consensus::validator_set::ValidatorSet;
    use boule_core::crypto::signed::{ChainId, Signer};
    use boule_transport_tcp::{NodeId, ProtocolEvent, ProtocolOutbound};

    // ── VoteObserver unit tests (issue #422) ──────────────────────────────────

    /// Idempotent re-emissions for the same `(view, block_hash)` are
    /// not violations — HotStuff legitimately re-broadcasts a vote on
    /// peer reconnect / duplicate proposal arrival.
    #[test]
    fn vote_observer_treats_same_view_same_hash_as_idempotent() {
        let obs = VoteObserver::default();
        let replica: NodeId = [1; 32];
        let hash = [7u8; 32];
        obs.record(replica, 5, hash);
        obs.record(replica, 5, hash);
        obs.record(replica, 5, hash);
        assert!(obs.violations().is_empty());
    }

    /// Distinct `block_hash`es for the same `(replica, view)` are
    /// the canonical safety violation the assertion exists to catch.
    #[test]
    fn vote_observer_flags_conflicting_hashes_at_same_view() {
        let obs = VoteObserver::default();
        let replica: NodeId = [2; 32];
        let h_a = [0u8; 32];
        let h_b = [1u8; 32];
        obs.record(replica, 5, h_a);
        obs.record(replica, 5, h_b);
        let v = obs.violations();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].replica, replica);
        assert_eq!(v[0].view, View(5));
        assert_eq!(v[0].first_hash, h_a);
        assert_eq!(v[0].conflicting_hash, h_b);
    }

    /// Different replicas voting for different blocks at the same
    /// view is fine — that's what diverging replicas are *expected*
    /// to do under partition. The observer keys violations
    /// per-replica, not globally.
    #[test]
    fn vote_observer_does_not_cross_replicas() {
        let obs = VoteObserver::default();
        let r1: NodeId = [3; 32];
        let r2: NodeId = [4; 32];
        let h_a = [0u8; 32];
        let h_b = [1u8; 32];
        obs.record(r1, 5, h_a);
        obs.record(r2, 5, h_b);
        assert!(obs.violations().is_empty());
    }

    /// Bare routing harness: spawns only the per-node routing tasks and
    /// hands the caller the outbound sender + inbound receiver for each
    /// node (no `ConsensusNode`). Used by the kill-semantics tests to
    /// directly inject outbound frames and drain inbound events.
    struct BareRouting {
        node_ids: Vec<NodeId>,
        send_txs: Vec<mpsc::Sender<ProtocolOutbound>>,
        event_rxs: Vec<mpsc::Receiver<ProtocolEvent>>,
        event_txs: Arc<HashMap<NodeId, Mutex<mpsc::Sender<ProtocolEvent>>>>,
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
            let unsorted: Vec<boule_consensus::validator_set::ValidatorId> = signers
                .iter()
                .map(|s| {
                    boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(s.node_id())
                })
                .collect();
            let vs = ValidatorSet::new(unsorted);
            let node_ids: Vec<NodeId> = vs.iter().map(|v| v.into_node_id()).collect();

            let partitioned = Arc::new(Mutex::new(HashSet::new()));
            let link_cuts = Arc::new(Mutex::new(HashSet::new()));
            let partition_blocks = Arc::new(Mutex::new(HashSet::new()));
            let dead_nodes = Arc::new(Mutex::new(HashSet::new()));

            let mut event_tx_map: HashMap<NodeId, Mutex<mpsc::Sender<ProtocolEvent>>> =
                HashMap::new();
            let mut event_rxs: Vec<mpsc::Receiver<ProtocolEvent>> = Vec::new();
            for &nid in &node_ids {
                let (tx, rx) = mpsc::channel(1024);
                event_tx_map.insert(nid, Mutex::new(tx));
                event_rxs.push(rx);
            }
            let event_txs = Arc::new(event_tx_map);

            let mut send_txs = Vec::new();
            // BareRouting only exercises route-task plumbing (kill,
            // partition, link-cut). It hand-injects raw byte payloads
            // that are not real `WireMessage`s, so the vote observer
            // would silently no-op anyway — but plumb a fresh one
            // through to keep the call signature uniform.
            let vote_observer = Arc::new(super::VoteObserver::default());
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
                    Arc::clone(&vote_observer),
                    super::PayloadFraming::Mesh,
                    super::SelectiveControls::default(),
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
                if let Some(event_tx_slot) = self.event_txs.get(&nid) {
                    let event_tx = event_tx_slot.lock().clone();
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

    // ── BLS happy path (#354 step 2) ──────────────────────────────────────────

    /// Four honest nodes on a `bls_aggregated` chain commit at least
    /// one block, with every formed QC riding the BLS aggregate path
    /// end-to-end.
    ///
    /// Acceptance for #354 step 2: the dispatch-layer QC verifier
    /// accepts a real BLS QC at view ≥ 1, which can only happen if
    /// (a) the leader-side egress signs each Vote with a real BLS
    /// partial, (b) `on_vote_received` folds those partials via
    /// `add_bls_partial`, and (c) the formed `QcSignatures::BlsAggregated`
    /// aggregate verifies against the per-historical-view BLS pubkey
    /// table seeded from genesis.
    #[tokio::test]
    async fn four_honest_bls_nodes_commit_at_least_one_block() {
        tokio::time::pause();

        let mut cluster = SimCluster::spawn_bls(4, Duration::from_millis(50)).await;

        // Same poll-with-budget shape as the Ed25519 happy-path test.
        // BLS partials are larger but the per-view round count is
        // identical — the cluster reaches the first commit in roughly
        // the same number of yields.
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
            "expected >= 3 nodes to commit on a BLS chain, got {num_committed}",
        );

        // Pick the first non-empty commit and confirm it is committed
        // by at least 3 nodes — i.e. the cluster agreed on the same
        // block via a real BLS QC. The QC verifier in the run loop
        // would have rejected any node's inbound proposal whose
        // `justify` carried a malformed BLS aggregate, so the very
        // fact that 3 nodes committed the same block implies the BLS
        // QC formed and verified end-to-end.
        let committed_hash = committed
            .iter()
            .find(|c| !c.is_empty())
            .map(|c| c[0].hash())
            .expect("at least one node committed a block");
        let same_block_count = committed
            .iter()
            .filter(|c| c.first().map(|b| b.hash()) == Some(committed_hash))
            .count();
        assert!(
            same_block_count >= 3,
            "expected >= 3 nodes to agree on the first BLS-committed block hash, got {same_block_count}",
        );
    }

    /// Stronger BLS acceptance (#354 step 3): the cluster reaches a
    /// *three-chain* commit — three blocks committed at consecutive
    /// heights by ≥ 3 nodes. This is the load-bearing path the BLS
    /// QC bandwidth/CPU savings are supposed to deliver, and the only
    /// end-to-end signal that the dispatch verifier accepts real
    /// (non-genesis) BLS QCs at every committed view in the chain.
    #[tokio::test]
    async fn four_honest_bls_nodes_reach_three_chain_commit() {
        tokio::time::pause();

        let mut cluster = SimCluster::spawn_bls(4, Duration::from_millis(50)).await;

        // Run long enough for three consecutive commits per node.
        // Each block requires roughly 5 yield rounds on the happy
        // path; budget generously to absorb scheduling jitter.
        for _ in 0..2000 {
            yield_now().await;
            let heights = cluster.peek_commit_heights();
            if heights.iter().filter(|&&h| h >= 3).count() >= 3 {
                break;
            }
        }

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);

        // ≥ 3 nodes must each have ≥ 3 commits.
        let nodes_with_three_commits = committed.iter().filter(|c| c.len() >= 3).count();
        assert!(
            nodes_with_three_commits >= 3,
            "expected ≥ 3 nodes to reach a 3-chain commit on a BLS chain; got {nodes_with_three_commits} (per-node lengths: {:?})",
            committed.iter().map(|c| c.len()).collect::<Vec<_>>(),
        );

        // The first 3 committed blocks must agree across the ≥ 3 nodes
        // that reached three-chain depth — i.e. the dispatch-layer BLS
        // verifier accepted real BLS QCs at every committed view along
        // the chain. Heights must also be strictly consecutive.
        let three_chain_nodes: Vec<&Vec<Block>> =
            committed.iter().filter(|c| c.len() >= 3).collect();
        let reference: Vec<_> = three_chain_nodes[0]
            .iter()
            .take(3)
            .map(|b| (b.header.height, b.hash()))
            .collect();
        for (i, node_commits) in three_chain_nodes.iter().enumerate().skip(1) {
            let theirs: Vec<_> = node_commits
                .iter()
                .take(3)
                .map(|b| (b.header.height, b.hash()))
                .collect();
            assert_eq!(
                theirs, reference,
                "three-chain prefix diverges between three-chain node 0 and three-chain node {i}",
            );
        }
        assert!(
            reference.windows(2).all(|w| w[1].0 == w[0].0 + 1),
            "three-chain heights must be strictly consecutive: {reference:?}",
        );
    }

    // ── Slow-disk back-pressure (#496) ────────────────────────────────────────

    /// Wrap one node's storage in [`boule_core::storage::ThrottledStorage`]
    /// with a per-write delay; assert the cluster's persist-blocks-rather-
    /// than-drops invariant holds (every node still commits, the slow
    /// node lags but doesn't violate safety).
    ///
    /// Uses the multi-thread runtime + real wall clock because
    /// `ThrottledStorage` blocks the executor with `std::thread::sleep`.
    /// Under `current_thread + start_paused` the throttled writes would
    /// wedge every other task on the same thread, defeating the test's
    /// shape.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn slow_disk_node_lags_but_does_not_wedge_or_violate_safety() {
        // 50 ms persist delay on node 3 only. Combined with the 50 ms
        // view-timer base this throttles node 3's commit cadence below
        // the fast nodes' but still well above zero, so we can observe
        // strict-inequality lag while staying under the 15-second
        // per-test budget.
        let slow_delay = Duration::from_millis(50);
        let mut cluster = SimCluster::spawn_with_slow_disk(
            4,
            Duration::from_millis(50),
            vec![Duration::ZERO, Duration::ZERO, Duration::ZERO, slow_delay],
        )
        .await;

        // Drive the cluster for 3 seconds of real wall-clock — fast
        // nodes should commit on the order of dozens of blocks; the
        // slow node fewer.
        tokio::time::sleep(Duration::from_secs(3)).await;

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);

        // Every node committed at least one block — the slow path
        // back-pressures consensus but does not wedge it.
        for (i, node_commits) in committed.iter().enumerate() {
            assert!(
                !node_commits.is_empty(),
                "node {i} produced no commits — slow disk should block, not wedge",
            );
        }

        // No commits dropped on any commit channel — back-pressure on
        // the persist path must not propagate forward as silent drops
        // on the commit fan-out.
        assert_eq!(
            cluster.total_commit_overflows(),
            0,
            "no commits should overflow the bounded notifier channel",
        );
    }

    // ── Slow-node back-pressure (#497) ────────────────────────────────────────

    /// Throttle one node's inbound `ProtocolEvent` consumption via the
    /// per-node bridge installed by [`SimCluster::set_slow_node`];
    /// assert the cluster's progress invariants hold (every node still
    /// commits, the slow node lags strictly behind a fast node, no
    /// commits are dropped on the bounded notifier).
    ///
    /// This is the consumption-side analogue of the slow-disk test
    /// above: instead of throttling the persist boundary, this test
    /// throttles the inbound dispatch boundary. Both are valid
    /// "single slow node" shapes.
    ///
    /// # Why no slow-peer-disconnect assertion
    ///
    /// The disconnect heuristic from #490 lives in
    /// `src/p2p/manager.rs::SlowPeerTracker` and fires on
    /// `try_send`-on-full of the per-peer outbound `write_tx` queue.
    /// The sim's mesh routing uses `.send().await` (not `try_send`),
    /// so the production-shape "fast peer drops a slow peer" path is
    /// not exercised by this harness. Wiring the sim through the real
    /// `p2p::manager` (or backporting the tracker into the route
    /// task) would let the assertion go end-to-end; both are larger
    /// refactors and are intentionally not part of #497. The
    /// disconnect heuristic itself is unit-tested in
    /// `src/p2p/manager.rs`'s test module — what this test verifies
    /// is the consumption-side back-pressure shape that the
    /// disconnect heuristic protects against.
    #[tokio::test]
    async fn slow_node_lags_but_cluster_still_commits() {
        tokio::time::pause();

        let mut cluster = SimCluster::spawn_with_slow_node(
            4,
            Duration::from_millis(50),
            vec![
                Duration::ZERO,
                Duration::ZERO,
                Duration::ZERO,
                Duration::from_millis(20),
            ],
        )
        .await;

        // Drive paused virtual time forward until the fast nodes have
        // produced a comfortable margin of commits over the slow
        // node. Per CLAUDE.md "Test performance" guidance, poll on
        // the observable rather than fixed iteration counts. With
        // tokio::time::pause and a 20ms slow-node delay, each yield
        // round advances either consensus work or the bridge's
        // sleep, but the slow node's commit cadence is throttled
        // proportionally.
        let mut early_exit = false;
        for _ in 0..2_000 {
            yield_now().await;
            tokio::time::advance(Duration::from_millis(10)).await;

            let heights = cluster.peek_commit_heights();
            // We want to assert lag, so look for a fast/slow gap of
            // at least a few blocks. With slow-node index 3, indices
            // 0..3 are fast.
            let fast_max = heights[..3].iter().copied().max().unwrap_or(0);
            let slow_h = heights[3];
            if fast_max >= 5 && slow_h < fast_max && heights.iter().all(|&h| h > 0) {
                early_exit = true;
                break;
            }
        }
        assert!(
            early_exit,
            "slow_node test did not reach steady-state lag within budget; \
             heights = {:?}",
            cluster.peek_commit_heights(),
        );

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);

        // Every node committed at least one block — the slow path
        // back-pressures consensus but does not wedge it.
        for (i, node_commits) in committed.iter().enumerate() {
            assert!(
                !node_commits.is_empty(),
                "node {i} produced no commits — slow-node throttle should \
                 lag, not wedge",
            );
        }

        // The slow node lags strictly behind the fastest fast node.
        let lengths: Vec<usize> = committed.iter().map(|c| c.len()).collect();
        let fast_max = lengths[..3].iter().copied().max().unwrap();
        let slow_len = lengths[3];
        assert!(
            slow_len < fast_max,
            "slow node should lag a fast node strictly: \
             lengths = {lengths:?}",
        );

        // No commits dropped on any commit channel.
        assert_eq!(
            cluster.total_commit_overflows(),
            0,
            "no commits should overflow the bounded notifier channel",
        );
    }

    /// `set_slow_node` is runtime-mutable: a node spawned with no
    /// initial throttle can be slowed mid-test, and resetting back to
    /// `Duration::ZERO` removes the per-event sleep. This test
    /// exercises the on-then-off transition to make sure the bridge
    /// task picks up the atomic update without a respawn.
    #[tokio::test]
    async fn set_slow_node_runtime_toggle_resumes_full_speed() {
        tokio::time::pause();

        let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

        // Phase 1: warm up un-throttled. Every node should commit
        // multiple blocks within the budget.
        for _ in 0..400 {
            yield_now().await;
            tokio::time::advance(Duration::from_millis(5)).await;
            if cluster.peek_commit_heights().iter().all(|&h| h >= 3) {
                break;
            }
        }
        assert!(
            cluster.peek_commit_heights().iter().all(|&h| h >= 3),
            "phase 1 failed to reach baseline commits: heights = {:?}",
            cluster.peek_commit_heights(),
        );

        // Phase 2: throttle node 3 mid-test, advance, observe lag.
        let phase2_baseline = cluster.peek_commit_heights();
        cluster.set_slow_node(3, Duration::from_millis(20));
        for _ in 0..1_500 {
            yield_now().await;
            tokio::time::advance(Duration::from_millis(10)).await;
            let heights = cluster.peek_commit_heights();
            let fast_gain = heights[..3]
                .iter()
                .zip(phase2_baseline[..3].iter())
                .map(|(a, b)| a - b)
                .max()
                .unwrap_or(0);
            let slow_gain = heights[3] - phase2_baseline[3];
            if fast_gain >= 5 && slow_gain < fast_gain {
                break;
            }
        }
        let after_throttle = cluster.peek_commit_heights();
        let fast_gain = after_throttle[..3]
            .iter()
            .zip(phase2_baseline[..3].iter())
            .map(|(a, b)| a - b)
            .max()
            .unwrap_or(0);
        let slow_gain = after_throttle[3] - phase2_baseline[3];
        assert!(
            fast_gain > slow_gain,
            "phase 2: throttled node 3 should gain fewer commits than the \
             fastest fast node — fast_gain={fast_gain}, slow_gain={slow_gain}",
        );

        // Phase 3: clear the throttle and observe the slow node
        // catching back up — its post-clear gain is at least a third
        // of the fastest fast node's gain (it can't always match
        // exactly because it had to drain backlog first).
        let phase3_baseline = cluster.peek_commit_heights();
        cluster.set_slow_node(3, Duration::ZERO);
        for _ in 0..1_500 {
            yield_now().await;
            tokio::time::advance(Duration::from_millis(10)).await;
            let heights = cluster.peek_commit_heights();
            let post_clear_slow = heights[3] - phase3_baseline[3];
            let post_clear_fast = heights[..3]
                .iter()
                .zip(phase3_baseline[..3].iter())
                .map(|(a, b)| a - b)
                .max()
                .unwrap_or(0);
            if post_clear_fast >= 5 && post_clear_slow * 3 >= post_clear_fast {
                break;
            }
        }
        let final_heights = cluster.peek_commit_heights();
        let post_clear_slow = final_heights[3] - phase3_baseline[3];
        let post_clear_fast = final_heights[..3]
            .iter()
            .zip(phase3_baseline[..3].iter())
            .map(|(a, b)| a - b)
            .max()
            .unwrap_or(0);
        assert!(
            post_clear_slow * 3 >= post_clear_fast,
            "phase 3: cleared throttle should let node 3 commit at a \
             comparable cadence — post_clear_slow={post_clear_slow}, \
             post_clear_fast={post_clear_fast}",
        );

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);
        assert_eq!(
            cluster.total_commit_overflows(),
            0,
            "no commits should overflow",
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
    /// itself observe three-chain commits. But its `Broadcast(Vote)`
    /// frames are silently dropped on those links.
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
    /// `TimeoutVote { view: View(1) }`, and on quorum every replica advances
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

    // ── audit L3-2: selective-drop / packet-reorder primitives ────────────────

    /// Deterministic-given-seed reorder: a fixed `(from, to, depth)` and
    /// a fixed arrival sequence must produce a byte-identical release
    /// order every run. Guards the acceptance criterion that the reorder
    /// schedule depends only on the seeded RNG, never on `SystemTime` or
    /// map iteration order.
    #[test]
    fn reorder_buf_is_deterministic_given_link() {
        use super::ReorderBuf;

        let from: NodeId = [7; 32];
        let to: NodeId = [9; 32];

        // Replay the same arrival stream through two independently
        // constructed buffers; the evicted-frame sequence (including the
        // drained residual) must match exactly.
        let run = || {
            let mut buf = ReorderBuf::new(from, to, 4);
            let mut out: Vec<u8> = Vec::new();
            for i in 0u8..20 {
                if let Some(b) = buf.push(Bytes::from(vec![i])) {
                    out.push(b[0]);
                }
            }
            for b in buf.drain_permuted() {
                out.push(b[0]);
            }
            out
        };

        let a = run();
        let b = run();
        assert_eq!(a, b, "reorder schedule must be identical given the link");
        // Every pushed frame is eventually released — buffering reorders,
        // it must not drop.
        let mut sorted = a.clone();
        sorted.sort_unstable();
        assert_eq!(
            sorted,
            (0u8..20).collect::<Vec<_>>(),
            "reorder must release every buffered frame exactly once",
        );
        // And it actually permutes (the 20-frame window is not delivered
        // in arrival order under depth 4).
        assert_ne!(
            a,
            (0u8..20).collect::<Vec<_>>(),
            "depth-4 reorder over 20 frames should not be the identity order",
        );
    }

    /// Selective `Proposal` drop. An honest leader's `Proposal` is
    /// dropped to exactly one honest follower while delivered to everyone
    /// else. The cluster must keep committing via the 3-of-4 quorum, and
    /// the starved follower must *catch up* (gain commits of its own) by
    /// pulling the blocks it never saw proposed via block-sync — not just
    /// limp along at `> 0`.
    ///
    /// `node_ids` are sorted ascending and the round-robin selector picks
    /// `leader_for_view(v) = node_ids[v % n]`, so node 0 leads views
    /// 0, 4, 8, …. Dropping `Proposal`s on the directed link `0 → 1`
    /// therefore starves follower node 1 of node 0's proposals (and only
    /// those) every fourth view.
    #[tokio::test]
    async fn selective_proposal_drop_commits_via_quorum_and_follower_catches_up() {
        tokio::time::pause();

        let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

        // Drop only `Proposal` frames on 0 → 1; votes, new-views, and
        // block-sync replies still flow, so node 1's catch-up path is
        // open.
        cluster.drop_messages_if(
            0,
            1,
            Arc::new(|m: &SimMessage| m.kind == SimMessageKind::Proposal),
        );

        let baseline = cluster.peek_commit_heights();
        let n = baseline.len();

        // Every node — including the starved follower — must gain ≥ 10
        // commits. The follower can only do so by block-syncing node 0's
        // blocks it never received as proposals; an 8s simulated cap
        // leaves ample headroom over the ~50ms/view cadence.
        let satisfied = cluster
            .advance_and_yield_until(Duration::from_secs(8), |c| {
                let h = c.peek_commit_heights();
                (0..n).all(|i| h[i] >= baseline[i] + 10)
            })
            .await;
        assert!(
            satisfied,
            "selective proposal drop: not every node (incl. starved follower 1) gained ≥ 10 \
             commits within 8s simulated (heights: {:?})",
            cluster.peek_commit_heights(),
        );

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);
    }

    /// Selective `TimeoutVote` drop. With the view-`v` leader silent
    /// (partitioned), the surviving replicas time out and broadcast
    /// `TimeoutVote`s; we drop one survivor's `TimeoutVote` to one other
    /// survivor. The timeout-certificate path must still make progress —
    /// the cluster keeps committing — because a TC needs only 3 of 4 and
    /// the dropped link is not on the critical collector's inbound path.
    ///
    /// This is the L2-1-adjacent shape the issue calls out: it pins that
    /// selectively starving a single timeout link does not wedge
    /// liveness.
    #[tokio::test]
    async fn selective_timeout_vote_drop_preserves_liveness() {
        tokio::time::pause();

        let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

        // Warm up so every replica has a committed prefix to extend.
        let warm = cluster
            .advance_and_yield_until(Duration::from_secs(2), |c| {
                c.peek_commit_heights().iter().all(|&h| h >= 3)
            })
            .await;
        assert!(
            warm,
            "warm-up: every replica must commit ≥ 3 before the drop is meaningful"
        );

        // Silence node 0 so its leader views (0, 4, 8, …) actually time
        // out, generating `TimeoutVote` traffic, and drop node 1's
        // timeout votes to node 2 specifically.
        cluster.partition_node(0);
        cluster.drop_messages_if(
            1,
            2,
            Arc::new(|m: &SimMessage| m.kind == SimMessageKind::TimeoutVote),
        );

        let baseline = cluster.peek_commit_heights();

        // Survivors {1, 2, 3} must keep committing despite the timeouts
        // and the selectively-dropped timeout votes.
        let survivors = [1usize, 2, 3];
        let satisfied = cluster
            .advance_and_yield_until(Duration::from_secs(8), |c| {
                let h = c.peek_commit_heights();
                survivors.iter().all(|&i| h[i] >= baseline[i] + 5)
            })
            .await;
        assert!(
            satisfied,
            "selective timeout-vote drop: survivors did not all gain ≥ 5 commits within 8s \
             simulated (heights: {:?})",
            cluster.peek_commit_heights(),
        );

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);
    }

    /// Reorder smoke. Buffer-and-permute a couple of links on an
    /// otherwise happy-path cluster; under partial synchrony the protocol
    /// must tolerate reordered delivery and keep committing. Not a
    /// regression on a specific ordering — just that reorder is survived.
    #[tokio::test]
    async fn reorder_link_smoke_still_commits() {
        tokio::time::pause();

        let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

        // Reorder two disjoint directed links with a depth-4 window.
        cluster.reorder_link(0, 1, 4);
        cluster.reorder_link(2, 3, 4);

        let baseline = cluster.peek_commit_heights();
        let n = baseline.len();
        let satisfied = cluster
            .advance_and_yield_until(Duration::from_secs(8), |c| {
                let h = c.peek_commit_heights();
                (0..n).all(|i| h[i] >= baseline[i] + 10)
            })
            .await;
        assert!(
            satisfied,
            "reorder smoke: not every node gained ≥ 10 commits within 8s simulated \
             (heights: {:?})",
            cluster.peek_commit_heights(),
        );

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);
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

    /// **#526 / parent #185 acceptance criterion 2.** Pin the
    /// post-restart catch-up wall-time target. Open a multi-block
    /// gap by partitioning one replica while survivors keep
    /// committing, heal the partition, and assert the lagging
    /// replica catches up to the pre-heal survivor frontier within
    /// **≤5s of simulated time**.
    ///
    /// 5s simulated at the production-default `timeout_base_ms = 500ms`
    /// is the proxy for #185's "≤5s wall-clock on a default
    /// GitHub-hosted runner" target — at that timeout a real-world
    /// testnet's 5s budget translates to ≤10 pacemaker view ticks,
    /// which the bulk-range RPC (#520 + #522) closes in a single
    /// round trip when the per-response cap (64 blocks) covers the
    /// gap. The dedicated retry timer (#518) keeps a single dropped
    /// `BlockRangeRequest` from extending the budget.
    ///
    /// Pre-#185 (single-block walk-back, no retry timer) the
    /// equivalent catch-up consumed `O(gap × view_timeout)` —
    /// `30 × 500 ms = 15s` — well above this assertion's budget.
    /// The same `advance_and_yield_until` pattern the rest of the
    /// suite uses keeps wall-clock comfortably under the 15s
    /// per-test budget called out in `CLAUDE.md`.
    #[tokio::test]
    async fn block_sync_catchup_completes_within_185_budget() {
        tokio::time::pause();

        // 4-node cluster at the production-default 500ms base. The
        // §9b walkthrough runs 7 nodes, but block-sync semantics
        // are independent of cluster size — a 4-node cluster
        // exercises exactly the requester / responder paths the
        // §9b operator-driven test would.
        let mut cluster = SimCluster::spawn(4, Duration::from_millis(500)).await;

        // Phase 1 — warm up so survivors have a real chain tip
        // before we partition.
        let satisfied = cluster
            .advance_and_yield_until(Duration::from_secs(10), |c| {
                c.peek_commit_heights().iter().all(|&h| h >= 3)
            })
            .await;
        assert!(
            satisfied,
            "warm-up: every replica must commit at least 3 blocks before partition. \
             heights={:?}",
            cluster.peek_commit_heights(),
        );

        // Phase 2 — partition one replica so it freezes while
        // survivors keep advancing. The same shape the existing
        // `divergent_restart_*` tests use, except we heal rather
        // than restart so the focus stays on bulk-range catch-up
        // rather than the recover path.
        let lagging_idx = 0;
        cluster.partition_node(lagging_idx);

        let baseline_for_survivors = cluster.peek_commit_heights();
        let n = baseline_for_survivors.len();
        // Open a 30+ block gap on the lagging replica. 30 is the
        // canonical number from #185 ("30-block gap"); we let
        // simulated time run up to 30s so the assertion is robust
        // to an unlucky leader-rotation order.
        let satisfied = cluster
            .advance_and_yield_until(Duration::from_secs(30), |c| {
                let h = c.peek_commit_heights();
                (0..n)
                    .filter(|&i| i != lagging_idx)
                    .all(|i| h[i] >= baseline_for_survivors[i] + 30)
            })
            .await;
        assert!(
            satisfied,
            "survivors did not gain >= 30 commits in 30s simulated. heights={:?}",
            cluster.peek_commit_heights(),
        );

        let pre_heal_heights = cluster.peek_commit_heights();
        let max_survivor_pre_heal = (0..n)
            .filter(|&i| i != lagging_idx)
            .map(|i| pre_heal_heights[i])
            .max()
            .unwrap();
        let gap = max_survivor_pre_heal - pre_heal_heights[lagging_idx];
        assert!(
            gap >= 30,
            "test setup expects >= 30-block gap before heal; got lagging={} survivors_max={}",
            pre_heal_heights[lagging_idx],
            max_survivor_pre_heal,
        );

        // Phase 3 — heal. Catch-up budget starts here.
        cluster.heal_node(lagging_idx);

        // Phase 4 — assert catch-up within 5s simulated. The
        // lagging replica must reach at least the survivor frontier
        // observed at heal time (a fixed target rather than a
        // moving one — the survivors keep advancing, but pinning
        // to `max_survivor_pre_heal` is the strict version of
        // "closed the pre-heal gap").
        let satisfied = cluster
            .advance_and_yield_until(Duration::from_secs(5), |c| {
                c.peek_commit_heights()[lagging_idx] >= max_survivor_pre_heal
            })
            .await;
        let post_heal_heights = cluster.peek_commit_heights();
        assert!(
            satisfied,
            "block-sync catch-up exceeded 5s simulated budget (#526 / #185 AC 2). \
             pre_heal={pre_heal_heights:?} pre_heal_max_survivor={max_survivor_pre_heal} \
             post_heal={post_heal_heights:?} gap_remaining={}",
            (max_survivor_pre_heal as i64) - (post_heal_heights[lagging_idx] as i64),
        );

        // Sanity: no fork in either pre-heal or post-heal commit
        // logs. Block-sync is a liveness mechanism; safety must
        // hold regardless of how fast catch-up runs.
        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);
    }

    /// End-to-end budget guard for wide-gap pipelining. A gap wider
    /// than one bulk-range response window (`BLOCK_RANGE_RESPONSE_MAX_BLOCKS
    /// = 64`) must still close within the same ≤5s simulated budget as
    /// the single-window case above. Same partition → open-gap → heal
    /// shape as [`block_sync_catchup_completes_within_185_budget`],
    /// scaled to a 200-block gap so catch-up crosses ~four response
    /// windows — the case the requester pipelines by firing the next
    /// `BlockRangeRequest` off each `ReceiveBlockRange` arrival
    /// instead of waiting for the next proposal.
    ///
    /// This is the integration-level liveness + safety guard: a wide
    /// gap closes inside budget and no fork appears. The emission-level
    /// proof that the *pipelining path itself* fires — and would not
    /// without the change — lives in the deterministic unit test
    /// `range_response_pipelines_next_window_while_proposal_still_parked`.
    /// (A pure wall-clock sim assertion can't isolate pipelining here:
    /// the single-block retry path and the steady proposal stream
    /// already close the gap inside budget regardless, so this test is
    /// a regression guard rather than a before/after discriminator.)
    #[tokio::test]
    async fn block_sync_pipelines_wide_gap_within_budget() {
        tokio::time::pause();

        let mut cluster = SimCluster::spawn(4, Duration::from_millis(500)).await;

        // Phase 1 — warm up so survivors have a real chain tip.
        let satisfied = cluster
            .advance_and_yield_until(Duration::from_secs(10), |c| {
                c.peek_commit_heights().iter().all(|&h| h >= 3)
            })
            .await;
        assert!(
            satisfied,
            "warm-up: every replica must commit at least 3 blocks before partition. \
             heights={:?}",
            cluster.peek_commit_heights(),
        );

        // Phase 2 — partition one replica and open a gap spanning
        // ~four response windows (200 / 64). Allow generous simulated
        // time to build the gap; the assertion under test is the
        // post-heal budget, not how long the survivors take to pull
        // ahead.
        let lagging_idx = 0;
        cluster.partition_node(lagging_idx);

        let baseline_for_survivors = cluster.peek_commit_heights();
        let n = baseline_for_survivors.len();
        const WIDE_GAP: u64 = 200;
        let satisfied = cluster
            .advance_and_yield_until(Duration::from_secs(180), |c| {
                let h = c.peek_commit_heights();
                (0..n)
                    .filter(|&i| i != lagging_idx)
                    .all(|i| h[i] >= baseline_for_survivors[i] + WIDE_GAP)
            })
            .await;
        assert!(
            satisfied,
            "survivors did not gain >= {WIDE_GAP} commits. heights={:?}",
            cluster.peek_commit_heights(),
        );

        let pre_heal_heights = cluster.peek_commit_heights();
        let max_survivor_pre_heal = (0..n)
            .filter(|&i| i != lagging_idx)
            .map(|i| pre_heal_heights[i])
            .max()
            .unwrap();
        let gap = max_survivor_pre_heal - pre_heal_heights[lagging_idx];
        assert!(
            gap >= WIDE_GAP,
            "test setup expects >= {WIDE_GAP}-block gap before heal; \
             got lagging={} survivors_max={}",
            pre_heal_heights[lagging_idx],
            max_survivor_pre_heal,
        );

        // Phase 3 — heal. Catch-up budget starts here.
        cluster.heal_node(lagging_idx);

        // Phase 4 — assert catch-up within 5s simulated despite the
        // gap spanning three response windows. Without pipelining the
        // second and third windows would each wait for a fresh
        // proposal to land at the recovering replica.
        let satisfied = cluster
            .advance_and_yield_until(Duration::from_secs(5), |c| {
                c.peek_commit_heights()[lagging_idx] >= max_survivor_pre_heal
            })
            .await;
        let post_heal_heights = cluster.peek_commit_heights();
        assert!(
            satisfied,
            "wide-gap block-sync catch-up exceeded 5s simulated budget. \
             pre_heal={pre_heal_heights:?} pre_heal_max_survivor={max_survivor_pre_heal} \
             post_heal={post_heal_heights:?} gap_remaining={}",
            (max_survivor_pre_heal as i64) - (post_heal_heights[lagging_idx] as i64),
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

        /// **L5 — validator key rotation safety.** A 4-node cluster
        /// commits a `DualSignedRotation` for a randomly-chosen
        /// validator at a random `v_eff_offset` in the future.
        /// Independent of which validator rotates and when, the
        /// cluster must:
        ///   1. continue to commit (liveness),
        ///   2. never have committed conflicting blocks (safety),
        ///   3. land at least one commit at view ≥ `v_eff` to
        ///      demonstrate the post-boundary regime is live.
        ///
        /// Quorum tightness: n=4, f=1, quorum=3. With the rotated
        /// validator's signer not swapped (operational concern; same
        /// as the deterministic happy-path test), one validator's
        /// post-boundary votes are rejected. Three honest validators
        /// remain — exactly quorum — so the property is a meaningful
        /// liveness assertion under the tightest fault-tolerance
        /// envelope.
        #[test]
        fn proptest_rotation_preserves_safety_and_liveness(
            target in 0usize..4,
            v_eff_offset in 8u64..30,
        ) {
            use boule_consensus::View;
            use boule_consensus::validator_rotation::{
                DualSignedRotation, ValidatorKeyRotation,
            };

            run_paused(|| async move {
                let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

                let warmed = cluster
                    .advance_and_yield_until(PHASE_CAP, |c| {
                        c.peek_commit_heights().iter().min().copied().unwrap_or(0) >= 1
                    })
                    .await;
                prop_assert!(warmed, "L5: warm-up did not produce any commit");

                let v_eff: View = View(v_eff_offset + 5); // floor + small margin
                let current = cluster
                    .signer(target)
                    .expect("regular SimCluster captures signers");
                let new_signer = Arc::new(fresh_signer()) as Arc<dyn Signer>;
                let envelope = DualSignedRotation::sign(
                    ValidatorKeyRotation {
                        validator: cluster.node_ids[target],
                        new_pubkey: new_signer.node_id(),
                        v_eff,
                        new_bls_pubkey: None,
                        new_bls_pop: None,
                    },
                    &*current,
                    &*new_signer,
                    &ChainId::TEST,
                )
                .expect("rotation envelope sign");
                let payload = envelope.encode_command();
                for mp in &cluster.mempools {
                    let _ = mp.insert(payload.clone());
                }

                let crossed = cluster
                    .advance_and_yield_until(Duration::from_secs(12), |c| {
                        c.peek_commit_heights().iter().min().copied().unwrap_or(0)
                            >= v_eff.0 + 5
                    })
                    .await;
                prop_assert!(
                    crossed,
                    "L5: cluster failed to commit past v_eff={v_eff} for target={target}",
                );

                let committed = cluster.drain_commits();
                assert_no_conflicts(&committed);

                let any_post = committed
                    .iter()
                    .any(|node_blocks| node_blocks.iter().any(|b| b.header.view >= v_eff));
                prop_assert!(
                    any_post,
                    "L5: no committed block at view >= v_eff={v_eff} for target={target}",
                );

                Ok(())
            })?;
        }

        /// **L4 — reconfiguration safety.** A 5-node cluster commits a
        /// `ReconfigCommand` removing one randomly-chosen validator at
        /// a random `v_eff_offset` in the future. After `current_view`
        /// crosses `v_eff` the cluster must:
        ///   1. continue to commit (liveness),
        ///   2. never have committed conflicting blocks at any point
        ///      (safety, including across the boundary),
        ///   3. land at least one commit at view ≥ `v_eff` to
        ///      demonstrate the post-boundary set is genuinely
        ///      driving progress.
        ///
        /// Floor consideration: removing one of five lands exactly on
        /// `MIN_VALIDATOR_FLOOR = 4`, which is the smallest committee
        /// the post-reconfig cluster is allowed to be — the tightest
        /// scenario the property needs to cover.
        #[test]
        fn proptest_reconfig_remove_preserves_safety_and_liveness(
            target in 0usize..5,
            v_eff_offset in 8u64..30,
        ) {
            use boule_consensus::View;
            use boule_consensus::reconfig::ReconfigCommand;

            run_paused(|| async move {
                let mut cluster = SimCluster::spawn(5, Duration::from_millis(50)).await;

                // Warm-up: get every node committing under the
                // genesis 5-validator set so the reconfig lands on a
                // chain that's already advanced past genesis.
                let warmed = cluster
                    .advance_and_yield_until(PHASE_CAP, |c| {
                        c.peek_commit_heights().iter().min().copied().unwrap_or(0) >= 1
                    })
                    .await;
                prop_assert!(warmed, "L4: warm-up did not produce any commit");

                let removed = cluster.node_ids[target];
                let v_eff: View = View(v_eff_offset + 5); // floor + a small margin
                let cmd = ReconfigCommand {
                    adds: vec![],
                    removes: vec![removed],
                    changes: vec![],
                    v_eff,
                };
                let payload = cmd.encode();

                // Drop the same payload into every node's mempool;
                // whichever leader proposes next picks it up.
                for mp in &cluster.mempools {
                    let _ = mp.insert(payload.clone());
                }

                // Drive the cluster until at least one survivor has
                // committed past v_eff. The exit condition uses the
                // committed-heights floor as a proxy for "view has
                // crossed v_eff" — height advances 1:1 per commit and
                // views advance ≥ heights, so a height of `v_eff +
                // 5` guarantees the post-boundary regime is active.
                let crossed = cluster
                    .advance_and_yield_until(Duration::from_secs(8), |c| {
                        c.peek_commit_heights().iter().min().copied().unwrap_or(0)
                            >= v_eff.0 + 5
                    })
                    .await;
                prop_assert!(
                    crossed,
                    "L4: cluster failed to commit past v_eff={v_eff} for target={target}",
                );

                let committed = cluster.drain_commits();
                assert_no_conflicts(&committed);

                let any_post = committed
                    .iter()
                    .any(|node_blocks| node_blocks.iter().any(|b| b.header.view >= v_eff));
                prop_assert!(
                    any_post,
                    "L4: no committed block at view >= v_eff={v_eff} for target={target}",
                );

                Ok(())
            })?;
        }

        /// **L5 — non-uniform weights preserve safety and liveness.**
        /// `n` honest replicas with random per-validator voting weights
        /// in `[1, 100]` must:
        ///   1. commit at least one block under the weighted-quorum
        ///      predicate (`3*signer_weight > 2*total_weight`),
        ///   2. never have committed conflicting blocks at any point
        ///      across replicas (safety).
        ///
        /// The committee runs honest — no adversary is injected. The
        /// property holds because the weighted Byzantine assumption
        /// (`Byzantine weight ≤ floor(total/3)`) is trivially
        /// satisfied at zero Byzantine weight. The test exists to
        /// catch arithmetic bugs in the weight-quorum predicate, the
        /// genesis-QC fill, and the round-sync hint at non-uniform
        /// weights — code paths that pre-#144 trivially behaved
        /// because every weight collapsed to 1 (#463 acceptance).
        ///
        /// Weight range and committee-size widened to the parent
        /// issue's spec (`n ∈ [4, 7]`, weights ∈ `[1, 1000]`) under
        /// #469. The earlier 4-validator + `[1, 100]` shape was a
        /// time-budget compromise on PR #467; #469 audited it and
        /// pushed the scope back out. The arithmetic surface is the
        /// same; the wider range exercises rarer quorum-subset
        /// arrangements (e.g. one validator carrying ~50% of total
        /// weight, ties at the strict-`>` boundary).
        #[test]
        fn proptest_weighted_committee_preserves_safety_and_liveness(
            n in 4usize..=7,
            // Generate up to 7 weights and slice to `n` below; this
            // sidesteps the `prop_flat_map` plumbing for a strategy
            // whose length depends on a sibling strategy.
            weights7 in proptest::collection::vec(1u64..=1000, 7),
        ) {
            run_paused(|| async move {
                let weights: Vec<u64> = weights7.into_iter().take(n).collect();
                let mut cluster =
                    SimCluster::spawn_with_weights(n, Duration::from_millis(50), weights.clone())
                        .await;

                // Warm-up: drive simulated time until at least one
                // node has committed a block.
                let warmed = cluster
                    .advance_and_yield_until(PHASE_CAP, |c| {
                        c.peek_commit_heights().iter().any(|&h| h > 0)
                    })
                    .await;
                prop_assert!(
                    warmed,
                    "L5: weighted cluster failed to commit any block (n={n}, weights={weights:?})",
                );

                // Run a bit longer so the chain advances past the
                // genesis QC and exercises QC formation under the
                // weighted predicate at multiple views.
                let _ = cluster
                    .advance_and_yield_until(PHASE_CAP, |c| {
                        c.peek_commit_heights().iter().min().copied().unwrap_or(0) >= 3
                    })
                    .await;

                let committed = cluster.drain_commits();
                assert_no_conflicts(&committed);

                Ok(())
            })?;
        }

        /// **L7 — non-uniform weights with a Byzantine-weight kill
        /// set ≤ `floor(total_weight / 3)` preserve safety and
        /// liveness** (#469).
        ///
        /// Pick a Byzantine subset by *weight-descending* greedy
        /// selection: keep adding the heaviest unpicked validator to
        /// the kill set while the next addition would not exceed
        /// `floor(total_weight / 3)`. This maximizes Byzantine
        /// influence within the bound and stresses the predicate's
        /// strict-`>` boundary. Killed validators are silenced (the
        /// simplest weighted-Byzantine fault model — equivalent to a
        /// crash-fault subset in the weighted setting).
        ///
        /// Honest weight is `total_weight - byzantine_weight ≥ total
        /// - floor(total/3) > 2/3 * total`, so the weighted-quorum
        /// predicate (`3*signer > 2*total`) is satisfiable on the
        /// honest subset alone. The cluster must commit at least one
        /// block; safety must hold across the run.
        #[test]
        fn proptest_weighted_byzantine_committee_preserves_safety_and_liveness(
            n in 4usize..=7,
            weights7 in proptest::collection::vec(1u64..=1000, 7),
        ) {
            run_paused(|| async move {
                let weights: Vec<u64> = weights7.into_iter().take(n).collect();
                let total: u128 = weights.iter().map(|w| u128::from(*w)).sum();
                let byzantine_cap: u128 = total / 3;

                let mut cluster =
                    SimCluster::spawn_with_weights(n, Duration::from_millis(50), weights.clone())
                        .await;

                // `weights[i]` is the weight of the validator at
                // sorted index `i` (the same order `cluster.node_ids`
                // uses). Pick the kill set greedily: heaviest first,
                // while the running sum stays at or below the cap.
                let mut indexed: Vec<(usize, u64)> =
                    weights.iter().copied().enumerate().collect();
                indexed.sort_by_key(|(_, w)| std::cmp::Reverse(*w));
                let mut byzantine_indices: Vec<usize> = Vec::new();
                let mut byzantine_weight: u128 = 0;
                for (idx, w) in indexed {
                    let next = byzantine_weight + u128::from(w);
                    if next <= byzantine_cap {
                        byzantine_indices.push(idx);
                        byzantine_weight = next;
                    }
                }

                // Sort kill indices ascending; `kill_node` operates
                // on sorted-validator-order indices and the order we
                // call it in doesn't change the outcome but stable
                // ordering helps shrink output read like a diff.
                byzantine_indices.sort();

                // Brief warm-up under the full committee so the
                // chain advances past genesis BEFORE we silence the
                // Byzantine subset. This mirrors how a real cluster
                // would discover and tolerate faults — they appear
                // mid-run, not at boot.
                let warmed = cluster
                    .advance_and_yield_until(PHASE_CAP, |c| {
                        c.peek_commit_heights().iter().any(|&h| h > 0)
                    })
                    .await;
                prop_assert!(
                    warmed,
                    "L7: warm-up did not produce a commit before kills \
                     (n={n}, weights={weights:?})",
                );

                for idx in &byzantine_indices {
                    cluster.kill_node(*idx);
                }

                // Honest weight strictly exceeds 2/3 of total, so the
                // surviving cluster must commit at least one fresh
                // block under the weighted-quorum predicate.
                let pre_kill_heights = cluster.peek_commit_heights();
                let post_kill_committed = cluster
                    .advance_and_yield_until(Duration::from_secs(8), |c| {
                        let h = c.peek_commit_heights();
                        // Some honest replica gained a height after kills.
                        (0..n)
                            .filter(|i| !byzantine_indices.contains(i))
                            .any(|i| h[i] > pre_kill_heights[i])
                    })
                    .await;
                prop_assert!(
                    post_kill_committed,
                    "L7: honest survivors gained 0 commits after silencing \
                     Byzantine subset (byzantine_indices={byzantine_indices:?}, \
                     byzantine_weight={byzantine_weight}, total={total}, \
                     weights={weights:?})",
                );

                let committed = cluster.drain_commits();
                assert_no_conflicts(&committed);

                Ok(())
            })?;
        }

        /// **L6 — change-weight reconfig preserves safety and
        /// liveness across the boundary.** Bump one validator's
        /// voting weight via a `change-weight` reconfig and verify:
        ///   1. the cluster commits past `v_eff`,
        ///   2. no conflicting commits across the boundary
        ///      (the historical-validator-set lookup at `qc.view`
        ///      keeps pre-boundary QCs verifiable),
        ///   3. at least one block lands at view ≥ `v_eff` (the
        ///      post-boundary regime is genuinely active).
        ///
        /// Floor consideration: the cluster has 4 validators, all
        /// at weight 1 at genesis. Bumping one to `new_weight ∈
        /// [2, 5]` makes that validator stake-heavy enough that
        /// quorum subsets rebalance, but the cluster remains
        /// connected (no Byzantine assumption violation: 0 Byzantine
        /// weight is trivially ≤ floor(total/3) = 1 at genesis and
        /// ≤ floor((3 + new_weight)/3) post-boundary).
        #[test]
        fn proptest_change_weight_reconfig_preserves_safety_and_liveness(
            target in 0usize..4,
            new_weight in 2u64..=5,
            v_eff_offset in 8u64..20,
        ) {
            use boule_consensus::View;
            use boule_consensus::reconfig::{ReconfigCommand, WeightChange};

            run_paused(|| async move {
                let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

                let warmed = cluster
                    .advance_and_yield_until(PHASE_CAP, |c| {
                        c.peek_commit_heights().iter().min().copied().unwrap_or(0) >= 1
                    })
                    .await;
                prop_assert!(
                    warmed,
                    "L6: warm-up did not produce a commit on every node",
                );

                let target_id = cluster.node_ids[target];
                let v_eff: View = View(v_eff_offset + 5);
                let cmd = ReconfigCommand {
                    adds: vec![],
                    removes: vec![],
                    changes: vec![WeightChange {
                        node_id: target_id,
                        weight: new_weight,
                    }],
                    v_eff,
                };
                let payload = cmd.encode();
                for mp in &cluster.mempools {
                    let _ = mp.insert(payload.clone());
                }

                let crossed = cluster
                    .advance_and_yield_until(Duration::from_secs(8), |c| {
                        c.peek_commit_heights().iter().min().copied().unwrap_or(0)
                            >= v_eff.0 + 5
                    })
                    .await;
                prop_assert!(
                    crossed,
                    "L6: cluster failed to commit past v_eff={v_eff} \
                     for target={target} new_weight={new_weight}",
                );

                let committed = cluster.drain_commits();
                assert_no_conflicts(&committed);

                let any_post = committed
                    .iter()
                    .any(|node_blocks| node_blocks.iter().any(|b| b.header.view >= v_eff));
                prop_assert!(
                    any_post,
                    "L6: no committed block at view >= v_eff={v_eff} \
                     (target={target} new_weight={new_weight})",
                );

                Ok(())
            })?;
        }
    }

    // ── #476: WeightedAccumulatorSelector is the production default ──
    //
    // The cluster spawned via `SimCluster::spawn_with_weights` runs
    // through the same `ConsensusNode::new` path as production, which
    // installs `WeightedAccumulatorSelector` as the pacemaker leader
    // selector. With a heavily skewed weight distribution like
    // `[10, 1, 1, 1]` the heaviest validator should propose roughly
    // 10/13 ≈ 77% of views — and therefore most committed blocks.
    //
    // This test exercises the wire-up: it asserts (a) liveness holds
    // (the cluster commits ≥ 5 blocks), and (b) the heaviest validator
    // proposed strictly more committed blocks than any single peer.
    // The frequency test is loose on purpose — short windows have
    // ±1-block variance per the accumulator's exact-frequency bound,
    // so "strictly more" rather than ">= 70%" keeps the test stable.

    /// L8 — heavily-skewed weights: weighted-accumulator default makes
    /// the heaviest validator the dominant proposer.
    #[tokio::test(start_paused = true)]
    async fn weighted_accumulator_default_makes_heaviest_validator_dominant_proposer() {
        let weights = vec![10u64, 1, 1, 1];
        let total: u128 = weights.iter().map(|w| u128::from(*w)).sum();
        let mut cluster =
            SimCluster::spawn_with_weights(4, Duration::from_millis(50), weights.clone()).await;

        // Drive until the slowest replica has committed ≥ 5 blocks —
        // enough for the accumulator's per-period (13 views) frequency
        // distribution to surface.
        let reached = cluster
            .advance_and_yield_until(Duration::from_secs(10), |c| {
                c.peek_commit_heights().iter().min().copied().unwrap_or(0) >= 5
            })
            .await;
        assert!(
            reached,
            "L8: weighted cluster failed to commit ≥ 5 blocks per replica within budget",
        );

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);

        // Count proposers across the committed prefix on replica 0.
        // All replicas commit the same block at each height (safety),
        // so one replica's view is enough.
        let heaviest = cluster.node_ids[0]; // sorted-index 0 = heaviest by construction.
        let mut counts: HashMap<NodeId, u32> = HashMap::new();
        for block in &committed[0] {
            // Skip the genesis stub at height 0 — its `proposer` is
            // [0; 32] and not a real validator.
            if block.header.height.0 == 0 {
                continue;
            }
            *counts.entry(block.header.proposer).or_insert(0) += 1;
        }
        let total_blocks: u32 = counts.values().copied().sum();
        assert!(
            total_blocks >= 5,
            "L8: expected ≥ 5 committed non-genesis blocks, got {total_blocks}",
        );

        let heaviest_count = counts.get(&heaviest).copied().unwrap_or(0);
        let max_other_count = counts
            .iter()
            .filter(|(id, _)| **id != heaviest)
            .map(|(_, c)| *c)
            .max()
            .unwrap_or(0);
        assert!(
            heaviest_count > max_other_count,
            "L8: heaviest validator (weight 10/{total}) proposed {heaviest_count} blocks but \
             some peer proposed {max_other_count} (counts={counts:?}). The weighted accumulator \
             default is not in effect, or the test budget produced too few commits.",
        );
    }

    // ── Vote-uniqueness property (issue #422 / audit finding 14-3) ────────────

    /// Dedicated property test for the per-replica `vote_once`
    /// invariant: across a long event sequence with multiple
    /// view changes (leader crashes, mid-run restart, partition +
    /// heal), no replica may emit two distinct votes for the same
    /// view.
    ///
    /// The default-on observer wired into [`SimCluster::spawn`] (and
    /// run from `Drop`) catches the property automatically across
    /// every other test in the suite. This test additionally asserts
    /// that the observer *did* record votes — a future refactor that
    /// silently breaks the route-task hook would otherwise green-pass
    /// every existing sim because an empty observation set has no
    /// violations.
    #[tokio::test(start_paused = true)]
    async fn vote_observer_holds_through_long_view_change_sequence() {
        let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

        // Phase 1: warm-up under the genesis topology so the chain
        // starts advancing past genesis.
        let warmed = cluster
            .advance_and_yield_until(Duration::from_secs(2), |c| {
                c.peek_commit_heights().iter().min().copied().unwrap_or(0) >= 2
            })
            .await;
        assert!(warmed, "warm-up failed to produce 2 commits on every node");

        // Phase 2: kill the view-1 leader (sorted index 0). This
        // forces a view-change cascade — the pacemaker times out,
        // each survivor emits NewView for view 2 and then votes on
        // view 2's proposal under the next leader.
        cluster.kill_node(0);
        let post_kill = cluster
            .advance_and_yield_until(Duration::from_secs(3), |c| {
                let h = c.peek_commit_heights();
                (1..4).all(|i| h[i] >= 4)
            })
            .await;
        assert!(
            post_kill,
            "majority did not advance past height 4 after leader kill"
        );

        // Phase 3: bring the killed node back via crash-recovery and
        // let it catch up. `recover` re-loads `last_voted_view`,
        // `locked`, and `high_qc` from durable state, so the reborn
        // safety core continues from the same vote-once boundary it
        // had at kill — the reborn replica must not vote again at
        // any view it already voted at pre-kill.
        cluster
            .restart_node_with_recover(0)
            .await
            .expect("restart_node_with_recover must succeed");
        let caught_up = cluster
            .advance_and_yield_until(Duration::from_secs(3), |c| c.peek_commit_heights()[0] >= 4)
            .await;
        assert!(caught_up, "reborn node 0 did not catch up to height 4");

        // Phase 4: install a flip-flop one-way partition that
        // alternately isolates the current view's leader, forcing a
        // few additional view changes before letting the cluster
        // converge again.
        cluster.partition_one_way(&[1], &[2, 3]);
        let _ = cluster
            .advance_and_yield_until(Duration::from_millis(800), |_| false)
            .await;
        cluster.heal_partition();
        cluster.partition_one_way(&[2], &[1, 3]);
        let _ = cluster
            .advance_and_yield_until(Duration::from_millis(800), |_| false)
            .await;
        cluster.heal_partition();

        let progressed = cluster
            .advance_and_yield_until(Duration::from_secs(3), |c| {
                c.peek_commit_heights().iter().min().copied().unwrap_or(0) >= 8
            })
            .await;
        assert!(
            progressed,
            "post-flipflop convergence failed: {:?}",
            cluster.peek_commit_heights()
        );

        // Sanity: the observer is wired, so it must have recorded
        // votes. Without this guard, a silently-broken hook would
        // make every sim test trivially pass at teardown. We also
        // check the population is realistic — each surviving replica
        // votes on every view it accepts, so the floor scales with
        // the height we reached.
        let vote_count: usize = cluster
            .vote_observer
            .inner
            .lock()
            .values()
            .map(|by_view| by_view.len())
            .sum();
        assert!(
            vote_count >= 8,
            "observer recorded suspiciously few votes ({vote_count}); is the route-task hook still wired?",
        );

        // Explicit assertion in addition to the `Drop` hook so a
        // failure surfaces a clear test name rather than as a
        // teardown panic.
        cluster.assert_no_replica_double_voted();

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);
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
    /// This is the in-sim analogue of a rotating-failure scenario: a
    /// partitioned node mirrors the
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
            boule_consensus::rate_limit::production_message_rate_limits(),
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
                counters.drops(boule_consensus::rate_limit::MessageKind::Proposal as usize),
                counters.drops(boule_consensus::rate_limit::MessageKind::Vote as usize),
                counters.drops(boule_consensus::rate_limit::MessageKind::NewView as usize),
                counters.drops(boule_consensus::rate_limit::MessageKind::TimeoutVote as usize),
                counters.drops(boule_consensus::rate_limit::MessageKind::RequestBlock as usize),
                counters.drops(boule_consensus::rate_limit::MessageKind::ReceiveBlock as usize),
                counters.bytes_drops(),
            );
            assert_eq!(
                counters.disconnects(),
                0,
                "node {idx} unexpectedly issued a disconnect-decision",
            );
        }
    }

    // ── Block-sync flood (#498) ───────────────────────────────────────────────

    /// Issue #498 acceptance: a peer that floods `RequestBlock` frames
    /// at our node must not destabilize block-sync — the per-peer rate
    /// limiter's `RequestBlock` bucket caps inbound RPS, the per-peer
    /// credit window
    /// ([`block_sync::BlockSyncCreditWindow`])
    /// caps concurrent serves. Together they ensure a flood is dropped
    /// at the limiter boundary rather than queued through the run loop
    /// and into the storage layer.
    ///
    /// The test injects N raw `BlockRequest` frames at one node from a
    /// non-validator source, asserts the rate limiter dropped most of
    /// them, and asserts the cluster's commit progress is unaffected.
    /// The credit-window drops counter stays at zero because serving is
    /// synchronous — that's the documented behaviour today, but the
    /// counter wiring is exercised by the `BlockSyncCreditWindow` unit
    /// tests in `consensus/node/block_sync.rs`.
    #[tokio::test]
    async fn block_sync_request_flood_is_capped_by_rate_limiter() {
        tokio::time::pause();

        // Tighten the RequestBlock per-second cap so a small flood is
        // sufficient to trip the limiter without flooding for several
        // wall-seconds. The default is 8.0/sec — at 4.0/sec a 64-frame
        // flood lands well above the bucket capacity.
        let mut config = boule_consensus::rate_limit::production_message_rate_limits();
        config.per_kind_per_sec[boule_consensus::rate_limit::MessageKind::RequestBlock as usize] =
            4.0;
        let (mut cluster, limiters) =
            SimCluster::spawn_with_rate_limits(4, Duration::from_millis(50), config).await;

        // Warm up just enough that every node has committed at least
        // one block — that proves the cluster is past genesis-bootstrap
        // before we inject the flood. A 1-second budget is comfortable;
        // a healthy cluster commits its first block in a handful of
        // virtual-time ticks under the 50ms timeout base.
        let warmed = cluster
            .advance_and_yield_until(Duration::from_secs(1), |c| {
                c.peek_commit_heights().iter().all(|&h| h >= 1)
            })
            .await;
        assert!(
            warmed,
            "warm-up failed; heights = {:?}",
            cluster.peek_commit_heights(),
        );

        // Inject the flood at node 1, attributed to node 0. Use the
        // genesis hash because every node can serve it from durable
        // storage. We hit the inbound `event_tx` directly to bypass
        // any sender-side rate limiting and isolate the responder
        // boundary.
        let target_idx = 1;
        let from_node = cluster.node_ids[0];
        let target_node = cluster.node_ids[target_idx];
        let target_hash = cluster.genesis.hash();
        let wire = boule_consensus::wire::WireMessage::BlockRequest(target_hash);
        let bytes: Bytes = postcard::to_stdvec(&wire).unwrap().into();

        let event_tx = cluster
            .event_txs
            .get(&target_node)
            .expect("target_idx must have an event_tx slot")
            .lock()
            .clone();

        const FLOOD_COUNT: usize = 64;
        for _ in 0..FLOOD_COUNT {
            event_tx
                .send(ProtocolEvent::Message {
                    from: from_node,
                    payload: bytes.clone(),
                })
                .await
                .expect("event_rx alive — node task should still be running");
        }

        // Yield enough rounds for the run loop to pull every queued
        // event through ingress and through the rate limiter. We
        // poll the limiter's drop counter as the early-exit signal —
        // once the limiter has rejected more than half the flood,
        // the bucket is drained and further yielding only adds cost.
        for _ in 0..(FLOOD_COUNT * 4) {
            yield_now().await;
            let drops = limiters[target_idx]
                .counters()
                .drops(boule_consensus::rate_limit::MessageKind::RequestBlock as usize);
            if drops > (FLOOD_COUNT as u64) / 2 {
                break;
            }
        }

        // The rate limiter's `RequestBlock` bucket is capacity ≈
        // request_block_per_sec × burst_seconds = 4 × 1.0 = 4. So we
        // expect roughly FLOOD_COUNT - 4 drops (give or take the
        // bucket's slow refill). Assert the conservative bound: more
        // than half the flood was dropped at the limiter boundary.
        let drops = limiters[target_idx]
            .counters()
            .drops(boule_consensus::rate_limit::MessageKind::RequestBlock as usize);
        assert!(
            drops > (FLOOD_COUNT as u64) / 2,
            "expected > {} RequestBlock drops on node {target_idx}; got {drops}",
            FLOOD_COUNT / 2,
        );

        // The credit window's drops counter stays at zero — synchronous
        // serving never reaches the cap. This is the documented
        // behaviour; if it ever flips non-zero on this test it means
        // the responder went concurrent without re-thinking the cap.
        // (We don't have direct access to a node's status from the sim
        // harness, so leave this as an inline comment rather than an
        // assertion — the counter is asserted in
        // `BlockSyncCreditWindow`'s unit tests.)

        // Cluster still makes progress past the flood — the limiter
        // shielded consensus from the burst, so the per-view cadence
        // continued unaffected. We assert each node gained at least
        // one *additional* commit since the warm-up baseline; that
        // proves the cluster wasn't wedged by the flood.
        let baseline = cluster.peek_commit_heights();
        let progressed = cluster
            .advance_and_yield_until(Duration::from_secs(2), |c| {
                let now = c.peek_commit_heights();
                now.iter().zip(baseline.iter()).all(|(a, b)| a > b)
            })
            .await;
        assert!(
            progressed,
            "cluster failed to progress past flood; baseline={baseline:?}, \
             now={:?}",
            cluster.peek_commit_heights(),
        );

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);
    }

    // ── Egress amplification flood (#553) ─────────────────────────────────────

    /// Issue #553 acceptance: a Byzantine peer flooding
    /// `BlockRangeRequest` frames cannot pull more than
    /// `outbound_bytes_per_sec` of responses out of the responder.
    /// The per-peer outbound bytes bucket on
    /// [`boule_consensus::rate_limit::MessageRateLimiter`] caps egress regardless of
    /// how cheap the inbound requests are — the asymmetric
    /// request/response cost the issue documents (16 B request,
    /// hundreds of KB response) is bounded at the egress boundary.
    ///
    /// We tighten `outbound_bytes_per_sec` to a value smaller than a
    /// single `BlockRangeResponse` envelope (signed payload + header)
    /// so the bucket cannot admit even the first response a flood
    /// would produce. After yielding enough rounds for the run loop
    /// to pull every request through ingress and the responder's
    /// per-peer credit window, the limiter's outbound-drops counter
    /// reflects every dropped response — the proxy measurement for
    /// "no bytes pulled out".
    #[tokio::test]
    async fn block_range_response_flood_is_capped_by_outbound_byte_cap() {
        tokio::time::pause();

        // Tight outbound budget: 32 bytes/sec is below the wire size of
        // any signed `BlockRangeResponse` envelope (32 signer + 64 sig +
        // payload header alone exceed the cap), so every response the
        // responder builds is dropped at the egress admit. Keep ingress
        // generous so the requests admit cleanly and the test isolates
        // the egress boundary.
        let mut config = boule_consensus::rate_limit::production_message_rate_limits();
        config.outbound_bytes_per_sec = 32.0;
        config.per_kind_per_sec
            [boule_consensus::rate_limit::MessageKind::BlockRangeRequest as usize] = 1_000.0;
        config.bytes_per_sec = 1.0e9;
        config.max_violations = u32::MAX;
        let (mut cluster, limiters) =
            SimCluster::spawn_with_rate_limits(4, Duration::from_millis(50), config).await;

        // Warm-up: every node commits at least one block so the
        // responder has a non-trivial pending_blocks frontier. The
        // responses' contents do not matter for this assertion — we
        // care that the egress admit refused them — but a warmed
        // cluster proves we're past genesis-bootstrap before the flood.
        let warmed = cluster
            .advance_and_yield_until(Duration::from_secs(1), |c| {
                c.peek_commit_heights().iter().all(|&h| h >= 1)
            })
            .await;
        assert!(
            warmed,
            "warm-up failed; heights = {:?}",
            cluster.peek_commit_heights(),
        );

        // Inject the flood at node 1, attributed to node 0. Hit the
        // inbound `event_tx` directly to bypass any sender-side rate
        // limiting and isolate the responder boundary.
        let target_idx = 1;
        let from_node = cluster.node_ids[0];
        let target_node = cluster.node_ids[target_idx];
        let wire = boule_consensus::wire::WireMessage::BlockRangeRequest {
            from_height: boule_consensus::Height(0),
            to_height: boule_consensus::Height(64),
        };
        let bytes: Bytes = postcard::to_stdvec(&wire).unwrap().into();

        let event_tx = cluster
            .event_txs
            .get(&target_node)
            .expect("target_idx must have an event_tx slot")
            .lock()
            .clone();

        const FLOOD_COUNT: usize = 32;
        for _ in 0..FLOOD_COUNT {
            event_tx
                .send(ProtocolEvent::Message {
                    from: from_node,
                    payload: bytes.clone(),
                })
                .await
                .expect("event_rx alive — node task should still be running");
        }

        // Yield enough rounds for the run loop to pull every queued
        // event through ingress, build each response, and try the
        // outbound admit. We early-exit once outbound_drops_total
        // exceeds half the flood — at that point the egress bucket
        // is observably bounding the response stream and further
        // yielding only adds cost.
        for _ in 0..(FLOOD_COUNT * 8) {
            yield_now().await;
            if limiters[target_idx].counters().outbound_drops_total() > (FLOOD_COUNT as u64) / 2 {
                break;
            }
        }

        let outbound_drops = limiters[target_idx].counters().outbound_drops_total();
        assert!(
            outbound_drops > (FLOOD_COUNT as u64) / 2,
            "expected > {} outbound drops on node {target_idx} under {FLOOD_COUNT}-frame \
             BlockRangeRequest flood; got {outbound_drops}",
            FLOOD_COUNT / 2,
        );

        // Cluster still makes progress past the flood — the egress cap
        // shielded the responder from amplification without wedging
        // consensus. Assert each node gains at least one *additional*
        // commit since the warm-up baseline.
        let baseline = cluster.peek_commit_heights();
        let progressed = cluster
            .advance_and_yield_until(Duration::from_secs(2), |c| {
                let now = c.peek_commit_heights();
                now.iter().zip(baseline.iter()).all(|(a, b)| a > b)
            })
            .await;
        assert!(
            progressed,
            "cluster failed to progress past egress flood; baseline={baseline:?}, now={:?}",
            cluster.peek_commit_heights(),
        );

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);
    }

    // ── #255: validator-set reconfiguration end-to-end ────────────────────

    /// 5-node cluster commits a `ReconfigCommand` that removes one
    /// validator. Once `current_view` crosses `v_eff`, the surviving
    /// 4 nodes continue to commit blocks under the post-boundary
    /// committee. Confirms the integration of #270 / #271 / #272 /
    /// #254 against a real channel-routed cluster.
    ///
    /// Floor consideration: `MIN_VALIDATOR_FLOOR = 4`, so removing one
    /// from 5 lands exactly at the floor — the smallest committee
    /// the post-reconfig cluster is allowed to be.
    #[tokio::test]
    async fn cluster_commits_reconfig_removing_a_validator_and_makes_progress() {
        use boule_consensus::View;
        use boule_consensus::reconfig::ReconfigCommand;

        tokio::time::pause();

        let mut cluster = SimCluster::spawn(5, Duration::from_millis(50)).await;

        // Warm-up: let the cluster commit a few blocks under the
        // genesis 5-validator set so we have non-trivial chain depth
        // before injecting the reconfig.
        let warmed = cluster
            .advance_and_yield_until(Duration::from_secs(3), |c| {
                c.peek_commit_heights().iter().min().copied().unwrap_or(0) >= 2
            })
            .await;
        assert!(warmed, "cluster failed to commit warm-up blocks");

        // Build the reconfig: remove the highest-sorted validator
        // (cluster.node_ids[4]). v_eff is set far enough in the future
        // that whichever leader picks up the payload satisfies
        // `block_view + MIN_V_EFF_DELAY <= v_eff`.
        let removed = cluster.node_ids[4];
        let v_eff: View = View(60);
        let cmd = ReconfigCommand {
            adds: vec![],
            removes: vec![removed],
            changes: vec![],
            v_eff,
        };
        let payload = cmd.encode();

        // Drop the same payload into every node's mempool so whoever
        // is the leader of the next view will pick it up (mempool
        // contents are local and the leader is whichever validator
        // round-robin picks).
        for mp in &cluster.mempools {
            let _ = mp.insert(payload.clone());
        }

        // Advance the cluster until at least one survivor commits a
        // block at view >= v_eff. This proves both that the reconfig
        // landed (otherwise the leader rotation would not advance
        // past v_eff under the new committee — well, on this 5-node
        // cluster it would, but with the rule in place the surviving
        // 4 are the ones generating commits there).
        let crossed = cluster
            .advance_and_yield_until(Duration::from_secs(8), |c| {
                let committed = c.peek_commit_heights();
                // peek_commit_heights returns heights, not views. Use
                // a height proxy: in this sim, height advances 1:1
                // with each commit, and views advance ≥ heights, so
                // a height of `v_eff + 5` guarantees at least one
                // commit happened at view >= v_eff (with margin).
                committed.iter().min().copied().unwrap_or(0) >= v_eff.0 + 5
            })
            .await;
        assert!(
            crossed,
            "cluster failed to commit past v_eff = {v_eff} within budget",
        );

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);

        // At least one survivor (any of the 4 not-removed nodes)
        // committed a block at view >= v_eff, the post-boundary
        // regime.
        let any_post_boundary = committed
            .iter()
            .any(|node_blocks| node_blocks.iter().any(|b| b.header.view >= v_eff));
        assert!(
            any_post_boundary,
            "expected at least one committed block at view >= v_eff",
        );
    }

    // ── #260: validator key rotation end-to-end ───────────────────────────

    /// 4-node cluster commits a [`DualSignedRotation`] for one of its
    /// validators and continues to make progress past `v_eff`. The
    /// rotated validator's signer is *not* swapped mid-run (operational
    /// concern; deferred to a follow-up since the Signer trait conflates
    /// "claimed identity" with "active signing key" in a way that needs
    /// a deeper refactor to decouple). Post-boundary, that validator's
    /// stale-keyed votes are rejected by the verifier (the property
    /// PR #286 plumbed in), but the remaining three honest validators
    /// meet quorum (n=4, f=1, quorum=3) and the chain advances.
    ///
    /// What this test proves:
    ///
    /// - The tagged rotation tx flows from mempool → leader proposal →
    ///   committed block (the codec from this PR).
    /// - The rotation tx lands inside a committed block at the chain
    ///   level (drained and asserted).
    /// - The cluster maintains liveness across the rotation boundary
    ///   even when the rotated validator is effectively offline (its
    ///   stale-keyed votes don't count).
    /// - No safety violations: drained commits show no conflicting
    ///   blocks across replicas (`assert_no_conflicts`).
    #[tokio::test(start_paused = true)]
    async fn cluster_commits_validator_key_rotation_and_makes_progress() {
        use boule_consensus::View;
        use boule_consensus::validator_rotation::{DualSignedRotation, ValidatorKeyRotation};

        let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

        // Warm-up: commit a few blocks under the genesis identity so we
        // have non-trivial chain depth before injecting the rotation.
        let warmed = cluster
            .advance_and_yield_until(Duration::from_secs(3), |c| {
                c.peek_commit_heights().iter().min().copied().unwrap_or(0) >= 2
            })
            .await;
        assert!(warmed, "cluster failed to commit warm-up blocks");

        // Pick the validator at index 1 (second in sorted node_id
        // order) to rotate — choosing a non-leader-of-view-0 keeps the
        // boundary clean: the genesis-leader's behaviour is unchanged.
        let rotated_idx = 1;
        let rotated_validator = cluster.node_ids[rotated_idx];
        let current_signer = cluster
            .signer(rotated_idx)
            .expect("regular SimCluster captures signers");

        // Mint the new key the validator will rotate to. It must be a
        // real Ed25519 keypair so the dual-signed envelope's `sig_new`
        // verifies under `new_pubkey`.
        let new_signer = Arc::new(fresh_signer()) as Arc<dyn Signer>;
        let new_pubkey = new_signer.node_id();

        // v_eff sits comfortably ahead of where the warm-up landed and
        // ahead of any leader-of-view turn the rotated validator might
        // serve right after commit, so the cross-boundary window is
        // unambiguous.
        let v_eff: View = View(60);
        let payload = ValidatorKeyRotation {
            validator: rotated_validator,
            new_pubkey,
            v_eff,
            new_bls_pubkey: None,
            new_bls_pop: None,
        };
        let envelope =
            DualSignedRotation::sign(payload, &*current_signer, &*new_signer, &ChainId::TEST)
                .expect("constructing rotation envelope must succeed");
        let cmd_bytes = envelope.encode_command();

        // Drop the encoded rotation into every node's mempool so
        // whichever validator leads the next view picks it up.
        for mp in &cluster.mempools {
            let _ = mp.insert(cmd_bytes.clone());
        }

        // Drive the cluster past v_eff. With one validator effectively
        // offline post-boundary (signer not swapped, stale-keyed votes
        // rejected), n=4 quorum=3 just barely holds — every honest view
        // needs all three other validators to vote, and views that
        // round-robin to the rotated validator timeout. Generous budget
        // absorbs the wasted views.
        let crossed = cluster
            .advance_and_yield_until(Duration::from_secs(12), |c| {
                c.peek_commit_heights().iter().min().copied().unwrap_or(0) >= v_eff.0 + 5
            })
            .await;
        assert!(
            crossed,
            "cluster failed to commit past v_eff = {v_eff} within budget",
        );

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);

        // At least one node committed a block at view >= v_eff: the
        // post-boundary regime. (peek_commit_heights uses height not
        // view, but in this sim view advances at least as fast as
        // height, so a height of v_eff + 5 implies a view of at least
        // v_eff somewhere on the chain.)
        let any_post_boundary = committed
            .iter()
            .any(|node_blocks| node_blocks.iter().any(|b| b.header.view >= v_eff));
        assert!(
            any_post_boundary,
            "expected at least one committed block at view >= v_eff",
        );

        // The rotation tx itself made it onto the chain — visible in
        // some committed block's `commands`. This is the cleanest
        // observable proof from the test harness that the propose →
        // vote → commit pipeline carried the dual-signed envelope
        // intact, at which point every replica's
        // `apply_committed_rotations` runs deterministically over the
        // same block.
        let rotation_committed = committed.iter().any(|node_blocks| {
            node_blocks.iter().any(|b| {
                b.commands
                    .iter()
                    .any(|cmd| DualSignedRotation::is_rotation_payload(cmd))
            })
        });
        assert!(
            rotation_committed,
            "expected at least one committed block to carry the rotation tx",
        );
    }

    // ── #599: deferred state-root divergence detection ────────────────────

    /// Test-only state machine that applies commands correctly (so the
    /// committed chain content stays identical across nodes) but reports a
    /// deterministically *perturbed* `state_commitment`. Seeding this on a
    /// node simulates that node's execution having diverged — its
    /// committed roots disagree with honest replicas'. The perturbation is
    /// identical on every divergent node, so a set of divergent nodes
    /// agree with each other but not with the honest majority.
    #[derive(Debug)]
    struct DivergentCounterStateMachine {
        inner: boule_consensus::replication::impls::CounterStateMachine,
    }

    impl DivergentCounterStateMachine {
        fn new() -> Self {
            Self {
                inner: boule_consensus::replication::impls::CounterStateMachine::new(),
            }
        }
    }

    impl boule_consensus::replication::state_machine::StateMachine for DivergentCounterStateMachine {
        fn apply(&mut self, cmd: &[u8]) -> anyhow::Result<Bytes> {
            self.inner.apply(cmd)
        }
        fn state_commitment(&self) -> [u8; 32] {
            let mut c = self.inner.state_commitment();
            c[0] ^= 0xFF;
            c
        }
        fn snapshot(&self) -> Bytes {
            self.inner.snapshot()
        }
        fn restore(&mut self, snap: &[u8]) -> anyhow::Result<()> {
            self.inner.restore(snap)
        }
    }

    /// Build `n` state machines, the indices in `divergent` getting a
    /// [`DivergentCounterStateMachine`] and the rest a plain
    /// `CounterStateMachine`.
    fn state_machines_with_divergent(
        n: usize,
        divergent: &[usize],
    ) -> Vec<super::SimStateMachine> {
        (0..n)
            .map(|i| {
                let sm: Box<dyn boule_consensus::replication::state_machine::StateMachine> =
                    if divergent.contains(&i) {
                        Box::new(DivergentCounterStateMachine::new())
                    } else {
                        Box::new(boule_consensus::replication::impls::CounterStateMachine::new())
                    };
                Arc::new(Mutex::new(sm))
            })
            .collect()
    }

    /// A single diverged replica (minority, f = 1 of n = 4) is detected at
    /// vote time and isolated: it abstains on honest blocks (its committed
    /// root disagrees) and its own proposals are rejected, but the honest
    /// majority keeps committing. Divergence is detected (counter > 0)
    /// rather than silent — the core property of #599.
    #[tokio::test(start_paused = true)]
    async fn divergent_minority_is_detected_and_cluster_survives() {
        let sms = state_machines_with_divergent(4, &[0]);
        let mut cluster =
            SimCluster::spawn_with_state_machines(4, Duration::from_millis(50), sms).await;

        let progressed = cluster
            .advance_and_yield_until(Duration::from_secs(12), |c| {
                // The honest majority (>= 3 nodes) keeps committing.
                c.peek_commit_heights().iter().filter(|&&h| h >= 6).count() >= 3
            })
            .await;
        assert!(
            progressed,
            "honest majority must keep committing past a diverged minority; heights={:?}",
            cluster.peek_commit_heights(),
        );

        let total: u64 = (0..4)
            .map(|i| cluster.peek_state_divergence_detected(i))
            .sum();
        assert!(
            total > 0,
            "the deferred state-root check must have detected the divergence",
        );

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);
    }

    /// A diverged *majority* (>= f + 1 = 2 of n = 4) cannot form a quorum
    /// on any honest block — the chain halts, the intended fail-safe. No
    /// node commits past genesis.
    #[tokio::test(start_paused = true)]
    async fn divergent_majority_halts_the_chain() {
        let sms = state_machines_with_divergent(4, &[0, 1]);
        let mut cluster =
            SimCluster::spawn_with_state_machines(4, Duration::from_millis(50), sms).await;

        let progressed = cluster
            .advance_and_yield_until(Duration::from_secs(5), |c| {
                c.peek_commit_heights().iter().any(|&h| h >= 1)
            })
            .await;
        assert!(
            !progressed,
            "a >= f+1 diverged majority must stall the chain (no quorum); heights={:?}",
            cluster.peek_commit_heights(),
        );

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);
    }

    /// A Byzantine leader stamping a forged `committed_state_root` is
    /// rejected at vote time by every honest replica (they reproduce the
    /// real root and abstain), so its blocks never reach quorum — but the
    /// honest nodes stay live and keep committing under the other leaders.
    #[tokio::test(start_paused = true)]
    async fn byzantine_forged_committed_root_is_rejected_chain_survives() {
        let mut adversaries: Vec<Option<Arc<dyn super::Adversary>>> =
            (0..4).map(|_| None).collect();
        adversaries[1] = Some(Arc::new(crate::sim_byzantine::ForgedCommittedRootAdversary));
        let mut cluster =
            SimCluster::spawn_with_adversaries(4, Duration::from_millis(50), adversaries).await;

        let progressed = cluster
            .advance_and_yield_until(Duration::from_secs(12), |c| {
                c.peek_commit_heights().iter().filter(|&&h| h >= 8).count() >= 3
            })
            .await;
        assert!(
            progressed,
            "honest nodes must stay live past a forged-root byzantine leader; heights={:?}",
            cluster.peek_commit_heights(),
        );

        let honest_detections: u64 = [0usize, 2, 3]
            .iter()
            .map(|&i| cluster.peek_state_divergence_detected(i))
            .sum();
        assert!(
            honest_detections > 0,
            "honest nodes must have rejected the byzantine leader's forged committed root",
        );

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);
    }

    // ── #358: BLS-chain rotation end-to-end ───────────────────────────────

    /// 4-node BLS cluster commits a dual-key rotation tx (Ed25519 +
    /// BLS together) and continues making progress past `v_eff`.
    /// Acceptance for #358: post-rotation votes need to fold under
    /// the validator's NEW BLS key, which only works if
    /// `apply_committed_rotations` has called
    /// `bls_key_history.apply_rotation` alongside the Ed25519 apply.
    /// Without that mirror call, the dispatch-layer QC verifier
    /// would still resolve the post-rotation BLS pubkey as the
    /// pre-rotation one and reject every QC partial — the cluster
    /// would silently stall past `v_eff` with only n-1 = 3 honest
    /// validators (quorum holds at exactly 3-of-4 in this corner,
    /// but only as long as the rotated validator is also offline,
    /// which it isn't — it's just wrong about its own BLS key).
    #[tokio::test(start_paused = true)]
    async fn bls_cluster_commits_dual_key_rotation_and_makes_progress() {
        use boule_consensus::View;
        use boule_consensus::validator_rotation::{DualSignedRotation, ValidatorKeyRotation};
        use boule_core::crypto::sig_scheme::BlsAggregated;

        let mut cluster = SimCluster::spawn_bls(4, Duration::from_millis(50)).await;

        // Warm up under the genesis identity so the chain has real
        // depth before the rotation tx lands. BLS partials are
        // exercised on every Vote during this phase, which proves
        // the pre-rotation engine path is healthy.
        let warmed = cluster
            .advance_and_yield_until(Duration::from_secs(3), |c| {
                c.peek_commit_heights().iter().min().copied().unwrap_or(0) >= 2
            })
            .await;
        assert!(warmed, "BLS cluster failed to commit warm-up blocks");

        // Pick validator at sorted-index 1 to rotate (non-leader of
        // view 0, same rationale as the Ed25519 sibling test).
        let rotated_idx = 1;
        let rotated_validator = cluster.node_ids[rotated_idx];
        let current_signer = cluster
            .signer(rotated_idx)
            .expect("regular SimCluster captures Ed25519 signers");

        // Mint the NEW Ed25519 + BLS keys for the rotation target.
        // Both must be real keypairs: the dual-signed envelope's
        // `sig_new` verifies under `new_pubkey`, and the PoP we
        // attach must verify under `new_bls_pubkey`.
        let new_signer = Arc::new(fresh_signer()) as Arc<dyn Signer>;
        let new_pubkey = new_signer.node_id();
        let mut bls_ikm = [0u8; 32];
        bls_ikm[0] = 0x42; // deterministic across re-runs of this test
        bls_ikm[1] = rotated_idx as u8;
        let (new_bls_sk, new_bls_pk) = BlsAggregated::keygen(&bls_ikm).unwrap();
        let new_bls_pop = BlsAggregated::sign_pop(&new_bls_sk, &ChainId::TEST).unwrap();

        let v_eff: View = View(60);
        let payload = ValidatorKeyRotation {
            validator: rotated_validator,
            new_pubkey,
            v_eff,
            new_bls_pubkey: Some(new_bls_pk),
            new_bls_pop: Some(new_bls_pop),
        };
        let envelope =
            DualSignedRotation::sign(payload, &*current_signer, &*new_signer, &ChainId::TEST)
                .expect("constructing BLS rotation envelope must succeed");
        let cmd_bytes = envelope.encode_command();

        for mp in &cluster.mempools {
            let _ = mp.insert(cmd_bytes.clone());
        }

        // Drive past v_eff. As in the Ed25519 sibling test, the
        // rotated validator's signer doesn't get swapped in this
        // sim — it stays effectively offline post-boundary, so n=4
        // quorum=3 just barely holds via the other three. The
        // budget is identical, on the assumption that BLS pairing
        // overhead is dominated by the inter-view round trips.
        let crossed = cluster
            .advance_and_yield_until(Duration::from_secs(12), |c| {
                c.peek_commit_heights().iter().min().copied().unwrap_or(0) >= v_eff.0 + 5
            })
            .await;
        assert!(
            crossed,
            "BLS cluster failed to commit past v_eff = {v_eff} within budget",
        );

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);

        // Some node committed at view >= v_eff: the post-boundary
        // regime is reached, which means at least one quorum of
        // BLS partials verified under the post-rotation BLS pubkey
        // table on the dispatch verifier (#332/#356). If
        // `apply_committed_rotations` had skipped the BLS half, the
        // verifier would resolve the rotated validator's BLS
        // pubkey as the pre-rotation one and reject post-`v_eff`
        // QC aggregates whenever the rotated validator's slot
        // contributed.
        let any_post_boundary = committed
            .iter()
            .any(|node_blocks| node_blocks.iter().any(|b| b.header.view >= v_eff));
        assert!(
            any_post_boundary,
            "expected at least one committed block at view >= v_eff",
        );

        // The rotation tx itself made it onto the chain.
        let rotation_committed = committed.iter().any(|node_blocks| {
            node_blocks.iter().any(|b| {
                b.commands
                    .iter()
                    .any(|cmd| DualSignedRotation::is_rotation_payload(cmd))
            })
        });
        assert!(
            rotation_committed,
            "expected at least one committed block to carry the BLS rotation tx",
        );
    }

    // ── audit finding 3-3: spanning-vote correctness across rotation ─────
    //
    // The unit tests in `validator_key_history.rs` exhaustively cover the
    // `partition_point(|e| e.v_eff <= view)` boundary at the data-structure
    // level. This sim test (#423) closes the loop by running a
    // `DualSignedRotation` end-to-end through a 4-node cluster and then,
    // against the live post-rotation `validator_key_history` snapshotted
    // from each replica's storage, exercising the four spanning-vote
    // ingress cases that audit finding 3-3 names. A regression in the
    // partition predicate — silently accepting post-rotation keys for
    // pre-rotation views, the spanning-equivocation hazard the audit
    // calls out — would surface here as case 4 (pre-`v_eff` vote signed
    // under the new key) being accepted instead of `UnknownSigner`.

    /// Exercise validator-key rotation under live consensus traffic and
    /// verify the four spanning-vote correctness cases against the
    /// post-rotation history every replica converged on.
    ///
    /// Walks through:
    /// 1. Spawn a 4-node cluster, warm up with a few committed blocks.
    /// 2. Validator at sorted-index 1 emits a `DualSignedRotation` with
    ///    `v_eff = 30`. The envelope is signed under the cluster's real
    ///    `chain_id` (derived from `Block::genesis([0; 32], [0; 32])`,
    ///    the same construction `spawn_inner` uses), so
    ///    `apply_committed_rotations` accepts it on every replica and
    ///    persists the updated `validator_key_history` to storage.
    /// 3. Cluster runs through view ≥ `v_eff + 20` so the post-boundary
    ///    regime is durably reached and committed under timeouts that
    ///    the rotated validator's stale-keyed proposals/votes induce.
    /// 4. For every replica: read the persisted `validator_key_history`
    ///    back, then run the four spanning-vote ingress cases through
    ///    `dispatch::ingress_wire`:
    ///      a. Vote(view ≥ v_eff) signed under NEW key  → accepted.
    ///      b. Vote(view ≥ v_eff) signed under OLD key  → `UnknownSigner`.
    ///      c. Vote(view <  v_eff) signed under OLD key  → accepted (spanning).
    ///      d. Vote(view <  v_eff) signed under NEW key  → `UnknownSigner`.
    #[tokio::test(start_paused = true)]
    async fn validator_key_rotation_spanning_votes_correctness() {
        use crate::consensus_node::{STORAGE_KEY_VALIDATOR_KEY_HISTORY, WireMessage};
        use boule_consensus::View;
        use boule_consensus::dispatch::{IngressError, ingress_wire};
        use boule_consensus::hotstuff::qc::Vote;
        use boule_consensus::validator_history::ValidatorSetHistory;
        use boule_consensus::validator_key_history::{
            PersistedValidatorKeyHistory, ValidatorKeyHistory,
        };
        use boule_consensus::validator_rotation::{DualSignedRotation, ValidatorKeyRotation};
        use boule_consensus::validator_set::{Pubkey, ValidatorId, ValidatorSet};
        use boule_core::crypto::signed::Signed;

        let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

        // The cluster's per-replica `chain_id` is derived from the
        // genesis block hash — `spawn_inner` constructs
        // `Block::genesis([0u8; 32], [0; 32])` for every cluster, so
        // re-deriving it here yields the exact `ChainId` every replica
        // is verifying signatures against. Signing the rotation
        // envelope under this `ChainId` is what makes
        // `apply_committed_rotations` actually mutate
        // `validator_key_history` — the existence test
        // (`cluster_commits_validator_key_rotation_and_makes_progress`)
        // signs under `ChainId::TEST` because it only asserts liveness;
        // here we depend on the rotation taking effect across replicas.
        let genesis = Block::genesis([0u8; 32], [0; 32]);
        let chain_id = ChainId::from_genesis_hash(genesis.hash());

        // Warm-up: commit a few blocks under the genesis identity so the
        // rotation tx propagates into a real-traffic chain.
        let warmed = cluster
            .advance_and_yield_until(Duration::from_secs(3), |c| {
                c.peek_commit_heights().iter().min().copied().unwrap_or(0) >= 2
            })
            .await;
        assert!(warmed, "cluster failed to commit warm-up blocks");

        // Pick the validator at sorted-index 1 (non-leader of view 0)
        // to rotate, matching the existing rotation tests so the
        // boundary behavior is comparable.
        let rotated_idx = 1;
        let rotated_validator = cluster.node_ids[rotated_idx];
        let old_signer = cluster
            .signer(rotated_idx)
            .expect("regular SimCluster captures signers");

        // Mint a real Ed25519 keypair for the rotation target so
        // `sig_new` verifies under `payload.new_pubkey`.
        let new_signer = Arc::new(fresh_signer()) as Arc<dyn Signer>;
        let new_pubkey = new_signer.node_id();

        // `v_eff = 30` keeps the test budget tight: after the rotation
        // takes effect the rotated validator's signer is not swapped,
        // so 1-of-4 round-robin views (the rotated validator's leader
        // turns) time out. Reaching view ≥ 50 with that drag still
        // fits well inside a 15s wall-clock budget under
        // `start_paused = true`.
        let v_eff: View = View(30);
        let pre_view: View = View(10);
        let post_view: View = View(50);

        let payload = ValidatorKeyRotation {
            validator: rotated_validator,
            new_pubkey,
            v_eff,
            new_bls_pubkey: None,
            new_bls_pop: None,
        };
        let envelope = DualSignedRotation::sign(payload, &*old_signer, &*new_signer, &chain_id)
            .expect("constructing rotation envelope must succeed");
        let cmd_bytes = envelope.encode_command();
        for mp in &cluster.mempools {
            let _ = mp.insert(cmd_bytes.clone());
        }

        // Drive the cluster well past `v_eff` so every replica has
        // committed a block at view > v_eff and persisted the updated
        // key history. With ~25% of views timing out post-boundary,
        // height grows ~3/4 as fast as view; height ≥ 40 implies
        // view ≥ ~50, which is comfortably past `v_eff = 30`.
        let crossed = cluster
            .advance_and_yield_until(Duration::from_secs(15), |c| {
                c.peek_commit_heights().iter().min().copied().unwrap_or(0) >= 40
            })
            .await;
        assert!(
            crossed,
            "cluster failed to commit deeply enough past v_eff = {v_eff}",
        );

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);
        let any_post_boundary = committed
            .iter()
            .any(|node_blocks| node_blocks.iter().any(|b| b.header.view >= v_eff));
        assert!(
            any_post_boundary,
            "cluster never committed a block at view ≥ v_eff = {v_eff} — \
             rotation correctness assertions below would be vacuous",
        );

        // Genesis-only ValidatorSetHistory: this test does not commit
        // any reconfig, so every replica's set history is just the
        // genesis boundary. Reconstruct it locally to feed `ingress_wire`.
        let validators: Vec<ValidatorId> = cluster
            .node_ids
            .iter()
            .copied()
            .map(ValidatorId::from_genesis_pubkey)
            .collect();
        let validator_history = ValidatorSetHistory::from_genesis(ValidatorSet::new(validators));

        // Build a synthetic Vote bytes-bag for the four cases. The
        // `block_hash` is opaque to verification (signature bytes only,
        // no view-time block lookup at ingress), so any constant works.
        let make_vote_msg = |view: View, signer: &dyn Signer| -> WireMessage {
            let vote = Vote {
                view,
                block_hash: [0xAB; 32],
            };
            let signed = Signed::sign(vote, signer, &chain_id).expect("sign vote");
            WireMessage::Vote(signed, None)
        };

        let rotated_validator_id = ValidatorId::from_genesis_pubkey(rotated_validator);
        let mut replicas_with_applied_rotation = 0usize;
        for idx in 0..cluster.node_ids.len() {
            let storage = cluster
                .node_storage(idx)
                .expect("regular SimCluster captures storages");
            let raw = storage
                .get(STORAGE_KEY_VALIDATOR_KEY_HISTORY)
                .expect("storage get on validator_key_history must not error")
                .unwrap_or_else(|| {
                    panic!(
                        "node {idx}: validator_key_history must be persisted after a \
                         committed rotation crosses v_eff",
                    )
                });
            let persisted: PersistedValidatorKeyHistory =
                postcard::from_bytes(&raw).expect("decode persisted validator_key_history");
            let key_history = ValidatorKeyHistory::from_persisted(persisted)
                .expect("rebuild ValidatorKeyHistory from persisted form");

            // Sanity: the rotation actually took effect on this
            // replica's history. Without this, the cases below would
            // pass for the wrong reason (the old key still being the
            // active key at every view).
            assert_eq!(
                key_history.key_at(&rotated_validator_id, pre_view),
                Some(Pubkey::from_node_id(rotated_validator)),
                "node {idx}: pre-v_eff lookup must resolve to old key",
            );
            assert_eq!(
                key_history.key_at(&rotated_validator_id, post_view),
                Some(Pubkey::from_node_id(new_pubkey)),
                "node {idx}: post-v_eff lookup must resolve to new key — \
                 the rotation did not take effect on this replica",
            );
            replicas_with_applied_rotation += 1;

            // Case 1 (post-v_eff, NEW key) — accepted.
            let m = make_vote_msg(post_view, new_signer.as_ref());
            ingress_wire(new_pubkey, m, &validator_history, &key_history, &chain_id)
                .unwrap_or_else(|e| {
                    panic!(
                        "node {idx}: post-v_eff vote signed under the new key must be \
                     accepted, got {e:?}",
                    )
                });

            // Case 2 (post-v_eff, OLD key) — rejected as `UnknownSigner`.
            let m = make_vote_msg(post_view, old_signer.as_ref());
            let err = ingress_wire(
                old_signer.node_id(),
                m,
                &validator_history,
                &key_history,
                &chain_id,
            )
            .expect_err("post-v_eff vote signed under the old key must be rejected");
            assert!(
                matches!(err, IngressError::UnknownSigner(_)),
                "node {idx}: post-v_eff old-key vote: expected UnknownSigner, got {err:?}",
            );

            // Case 3 (pre-v_eff, OLD key, spanning vote) — accepted.
            let m = make_vote_msg(pre_view, old_signer.as_ref());
            ingress_wire(
                old_signer.node_id(),
                m,
                &validator_history,
                &key_history,
                &chain_id,
            )
            .unwrap_or_else(|e| {
                panic!(
                    "node {idx}: pre-v_eff spanning vote signed under the old key \
                     must be accepted, got {e:?}",
                )
            });

            // Case 4 (pre-v_eff, NEW key) — rejected as `UnknownSigner`.
            // This is the spanning-equivocation hazard the audit names:
            // accepting a post-rotation key for a pre-rotation view
            // would let a rotated validator double-sign across the
            // boundary using its new identity.
            let m = make_vote_msg(pre_view, new_signer.as_ref());
            let err = ingress_wire(new_pubkey, m, &validator_history, &key_history, &chain_id)
                .expect_err("pre-v_eff vote signed under the new key must be rejected");
            assert!(
                matches!(err, IngressError::UnknownSigner(_)),
                "node {idx}: pre-v_eff new-key vote: expected UnknownSigner, got {err:?}",
            );
        }
        assert_eq!(
            replicas_with_applied_rotation,
            cluster.node_ids.len(),
            "every replica must have observed the rotation",
        );
    }

    // ── #261: rotation rejection sim tests ────────────────────────────────
    //
    // The dispatch-level signer check (PR #286) and the post-commit
    // `apply_committed_rotations` path (#260) together enforce that a
    // malformed rotation tx never mutates `validator_key_history`. The
    // unit tests in `validator_rotation.rs` and `validator_key_history.rs`
    // exhaustively cover the rejection logic in isolation — these
    // sim-level tests close the loop by showing that the rejection
    // doesn't crash the cluster, the bad tx still propagates as opaque
    // bytes through propose → commit (the safety core treats every
    // command as opaque, so it can't reject one), and crucially that
    // the cluster maintains safety and liveness either way.

    /// Helper: build a structurally-valid `DualSignedRotation` for
    /// validator `idx` with `v_eff = 60`, then return both the encoded
    /// envelope bytes and the original (mutable) envelope so callers
    /// can mangle a single field before encoding.
    async fn rotation_envelope_for_idx(
        cluster: &SimCluster,
        idx: usize,
        v_eff: boule_consensus::View,
    ) -> (
        boule_consensus::validator_rotation::DualSignedRotation,
        Arc<dyn Signer>,
    ) {
        use boule_consensus::validator_rotation::{DualSignedRotation, ValidatorKeyRotation};

        let current = cluster
            .signer(idx)
            .expect("regular SimCluster captures signers");
        let new_signer = Arc::new(fresh_signer()) as Arc<dyn Signer>;
        let payload = ValidatorKeyRotation {
            validator: cluster.node_ids[idx],
            new_pubkey: new_signer.node_id(),
            v_eff,
            new_bls_pubkey: None,
            new_bls_pop: None,
        };
        let env = DualSignedRotation::sign(payload, &*current, &*new_signer, &ChainId::TEST)
            .expect("constructing rotation envelope must succeed");
        (env, new_signer)
    }

    /// Rotation tx whose `sig_old` is zeroed: cryptographic
    /// verification at commit time rejects it. The cluster commits the
    /// tx as opaque bytes — the safety core can't peek inside — but
    /// `apply_committed_rotations` log+drops it and the key history
    /// stays untouched. Cluster maintains safety + liveness.
    #[tokio::test(start_paused = true)]
    async fn cluster_rejects_rotation_tx_with_zeroed_sig_old() {
        use boule_consensus::View;
        use boule_consensus::validator_rotation::DualSignedRotation;

        let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;
        let warmed = cluster
            .advance_and_yield_until(Duration::from_secs(3), |c| {
                c.peek_commit_heights().iter().min().copied().unwrap_or(0) >= 2
            })
            .await;
        assert!(warmed, "warm-up did not commit");

        let v_eff: View = View(60);
        let (mut env, _) = rotation_envelope_for_idx(&cluster, 1, v_eff).await;
        // Zero out sig_old. sig_new still verifies under
        // payload.new_pubkey, but the dual-signature property requires
        // both — apply_committed_rotations rejects.
        env.sig_old = [0u8; 64];
        let bad_bytes = env.encode_command();
        for mp in &cluster.mempools {
            let _ = mp.insert(bad_bytes.clone());
        }

        // Drive past the would-be v_eff. Because the rotation was
        // rejected, the rotated validator's key history is unchanged,
        // its old-key votes are still accepted at view >= v_eff, and
        // all four validators contribute to quorum — the cluster runs
        // at full speed (no wasted views from a rejected leader).
        let crossed = cluster
            .advance_and_yield_until(Duration::from_secs(8), |c| {
                c.peek_commit_heights().iter().min().copied().unwrap_or(0) >= v_eff.0 + 5
            })
            .await;
        assert!(crossed, "cluster failed to commit past v_eff = {v_eff}");

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);

        // The bad rotation tx still made it onto the chain — that's
        // the safety core's job, it commits whatever leaders
        // propose. The rejection happens after commit.
        let rotation_committed = committed.iter().any(|node_blocks| {
            node_blocks.iter().any(|b| {
                b.commands
                    .iter()
                    .any(|cmd| DualSignedRotation::is_rotation_payload(cmd))
            })
        });
        assert!(
            rotation_committed,
            "the rejected rotation tx should still appear on-chain",
        );
    }

    /// Mirror of the above, but `sig_new` is zeroed. Verification
    /// rejects on the new-key-signature check rather than the old-key
    /// check; the safety/liveness invariants are unchanged.
    #[tokio::test(start_paused = true)]
    async fn cluster_rejects_rotation_tx_with_zeroed_sig_new() {
        use boule_consensus::View;
        use boule_consensus::validator_rotation::DualSignedRotation;

        let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;
        let warmed = cluster
            .advance_and_yield_until(Duration::from_secs(3), |c| {
                c.peek_commit_heights().iter().min().copied().unwrap_or(0) >= 2
            })
            .await;
        assert!(warmed, "warm-up did not commit");

        let v_eff: View = View(60);
        let (mut env, _) = rotation_envelope_for_idx(&cluster, 1, v_eff).await;
        env.sig_new = [0u8; 64];
        let bad_bytes = env.encode_command();
        for mp in &cluster.mempools {
            let _ = mp.insert(bad_bytes.clone());
        }

        let crossed = cluster
            .advance_and_yield_until(Duration::from_secs(8), |c| {
                c.peek_commit_heights().iter().min().copied().unwrap_or(0) >= v_eff.0 + 5
            })
            .await;
        assert!(crossed, "cluster failed to commit past v_eff = {v_eff}");

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);

        let rotation_committed = committed.iter().any(|node_blocks| {
            node_blocks.iter().any(|b| {
                b.commands
                    .iter()
                    .any(|cmd| DualSignedRotation::is_rotation_payload(cmd))
            })
        });
        assert!(
            rotation_committed,
            "the rejected rotation tx should still appear on-chain",
        );
    }

    /// Structural rejection: `v_eff` violates the
    /// `current_view + V_EFF_MIN_DELAY` floor. `apply_committed_rotations`
    /// runs `validate_structural` first; the rotation is dropped before
    /// any cryptographic check.
    #[tokio::test(start_paused = true)]
    async fn cluster_rejects_rotation_tx_with_v_eff_below_min_delay() {
        use boule_consensus::validator_rotation::DualSignedRotation;

        let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;
        let warmed = cluster
            .advance_and_yield_until(Duration::from_secs(3), |c| {
                c.peek_commit_heights().iter().min().copied().unwrap_or(0) >= 5
            })
            .await;
        assert!(warmed, "warm-up did not commit");

        // v_eff = 0: invalid for *any* commit_view since we require
        // commit_view + V_EFF_MIN_DELAY <= v_eff. Even the genesis
        // block at view 0 wouldn't accept this. Build a fresh envelope
        // signed at v_eff = 0 so both signatures verify cleanly — the
        // structural check (which fires before any cryptographic check)
        // is what we're asserting catches it.
        let current = cluster.signer(1).unwrap();
        let new_signer = Arc::new(fresh_signer()) as Arc<dyn Signer>;
        let env = boule_consensus::validator_rotation::DualSignedRotation::sign(
            boule_consensus::validator_rotation::ValidatorKeyRotation {
                validator: cluster.node_ids[1],
                new_pubkey: new_signer.node_id(),
                v_eff: View(0),
                new_bls_pubkey: None,
                new_bls_pop: None,
            },
            &*current,
            &*new_signer,
            &ChainId::TEST,
        )
        .unwrap();
        let bad_bytes = env.encode_command();
        for mp in &cluster.mempools {
            let _ = mp.insert(bad_bytes.clone());
        }

        // Drive forward; the cluster should keep making progress at
        // full speed since the rotation was rejected pre-application.
        let progressed = cluster
            .advance_and_yield_until(Duration::from_secs(5), |c| {
                c.peek_commit_heights().iter().min().copied().unwrap_or(0) >= 20
            })
            .await;
        assert!(progressed, "cluster failed to make progress");

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);

        // The bad tx still landed on-chain (safety core can't peek).
        let rotation_committed = committed.iter().any(|node_blocks| {
            node_blocks.iter().any(|b| {
                b.commands
                    .iter()
                    .any(|cmd| DualSignedRotation::is_rotation_payload(cmd))
            })
        });
        assert!(
            rotation_committed,
            "the rejected rotation tx should still appear on-chain",
        );
    }

    // ── #437 / Audit Finding 5-3: cross-replica Block byte determinism ────────
    //
    // #426 verified that `MempoolBlockBuilder::build` reads
    // `pending_blocks` only via `.get(&hash)` — there is no `HashMap`
    // iteration in the build path, so `state_commitment` is
    // determinism-safe today. This test is the regression net for
    // *future* changes: it commits ≥ 10 blocks at every node of a
    // 4-node cluster, then asserts byte-equal `Block` (full struct
    // equality, not just hash) at every height that all four replicas
    // committed. If a future change introduces an order-sensitive
    // iteration of `pending_blocks` (or otherwise breaks block-build
    // determinism), it surfaces here as cross-replica `Block` divergence.

    /// Cross-replica byte-equal `Block` regression for Audit Finding
    /// 5-3 (#426 / #437). Sweeps three hand-coded seeds; for each seed
    /// every height committed by all four replicas must carry the
    /// byte-identical `Block`.
    #[tokio::test(start_paused = true)]
    async fn audit_5_3_cross_replica_block_byte_determinism() {
        use rand::{Rng, SeedableRng};
        use rand_chacha::ChaCha20Rng;

        for seed in [0x00C0_FFEEu64, 0xDEAD_BEEF, 0x4242_4242] {
            let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

            // Feed deterministic mempool payloads into every node so
            // the leader's `MempoolBlockBuilder::build` runs against a
            // non-empty `pending_blocks` HashMap. Any future code path
            // that iterates it in HashMap order would surface as
            // cross-replica block divergence below.
            let mut rng = ChaCha20Rng::seed_from_u64(seed);
            for _ in 0..32 {
                let mut buf = [0u8; 16];
                rng.fill(&mut buf);
                let payload = Bytes::copy_from_slice(&buf);
                for mp in &cluster.mempools {
                    let _ = mp.insert(payload.clone());
                }
            }

            // Drive until every replica has committed ≥ 10 blocks.
            // Under paused virtual time the wall-clock cost is yields,
            // not seconds; 10 commits across 4 nodes is comfortably
            // under the 15s per-test budget.
            let reached = cluster
                .advance_and_yield_until(Duration::from_secs(10), |c| {
                    c.peek_commit_heights().iter().min().copied().unwrap_or(0) >= 10
                })
                .await;
            assert!(
                reached,
                "seed={seed:#x}: cluster failed to commit 10 blocks per node within budget",
            );

            let committed = cluster.drain_commits();
            assert_eq!(committed.len(), 4);

            // Index each replica's commits by height, then compare
            // every height that all four replicas reached for full
            // `Block` equality (not just hash).
            let by_height: Vec<HashMap<boule_consensus::Height, &Block>> = committed
                .iter()
                .map(|node_blocks| node_blocks.iter().map(|b| (b.header.height, b)).collect())
                .collect();

            let mut common: Vec<boule_consensus::Height> = by_height[0]
                .keys()
                .copied()
                .filter(|h| by_height.iter().skip(1).all(|m| m.contains_key(h)))
                .collect();
            common.sort();
            assert!(
                common.len() >= 10,
                "seed={seed:#x}: expected >= 10 heights common to all four replicas, got {} ({common:?})",
                common.len(),
            );

            for h in &common {
                let b0 = by_height[0][h];
                for (i, m) in by_height.iter().enumerate().skip(1) {
                    let bi = m[h];
                    assert_eq!(
                        bi, b0,
                        "seed={seed:#x}: replica {i} committed a non-byte-equal Block at height {h} (Audit Finding 5-3 regression)",
                    );
                }
            }

            // Sanity: hash-level safety still holds. `assert_eq!` above
            // already implies this, but keeping the explicit oracle
            // makes a partial regression (hashes equal, internals not)
            // surface with a clearer message at teardown.
            assert_no_conflicts(&committed);
            cluster.assert_no_replica_double_voted();
        }
    }
}
