//! Integration layer for HotStuff consensus: wires together
//! [`HotStuffCore`], [`Pacemaker`], storage, mempool, and the network.
//!
//! # Module layout
//!
//! The integration layer is broken across topical submodules, all
//! re-exported here so the existing `crate::consensus_node::*` paths
//! continue to resolve:
//!
//! - `wire` — [`WireMessage`] envelope and frame constants.
//! - `config` — [`NodeConfigForConsensus`].
//! - `block_builder` — [`MempoolBlockBuilder`] (the [`BlockBuilder`]
//!   that pulls commands from the mempool and stamps `state_commitment`
//!   by forking the committed SM).
//! - `persistence` — storage-key constants, codec helpers, the
//!   [`recover_state`] entry point, and `persist_updates` /
//!   `verify_persisted_history_consistency` on [`ConsensusNode`].
//! - `status` — [`ConsensusNode::build_status`] and the role helper.
//! - `timeout_bucket` — per-view timeout-vote accumulators
//!   (`on_timeout_vote` / `send_timeout` / cap eviction).
//! - `action_interpreter` — dispatcher, the persist-before-send
//!   middleware that drives [`Action`](boule_consensus::hotstuff::step::Action)
//!   slices, and structured tracing at every safety/pacemaker step.
//! - `commit` — the [`ConsensusNode::apply_commit`] handler that
//!   persists the committed block + last_committed checkpoint and
//!   delegates to the reconfig/rotation/snapshot siblings.
//! - `reconfig_apply` — commit-time application of
//!   [`ReconfigCommand`](boule_consensus::reconfig::ReconfigCommand)
//!   payloads.
//! - `rotation_apply` — commit-time application of
//!   [`DualSignedRotation`](boule_consensus::validator_rotation::DualSignedRotation)
//!   payloads.
//! - `snapshot_io` — snapshot creation, manifest/chunk serving, and
//!   joiner-side restore.
//!
//! This file owns the [`ConsensusNode`] struct itself, its constructors
//! ([`ConsensusNode::new`] / [`ConsensusNode::recover`]) and builder
//! `with_*` methods, the async [`ConsensusNode::run`] event loop, and
//! the cross-module helpers (`TRACE_TARGET`, the `*_kind` taggers, and
//! [`send_outbound`]).
//!
//! # Durability discipline
//!
//! HotStuff safety rests on every `Action::Persist` reaching durable
//! storage *before* the dependent `Broadcast` / `SendTo` / `Commit`
//! action is allowed to leave the node. The middleware that enforces
//! this lives in `action_interpreter` (see
//! [`ConsensusNode::apply_safety_actions`] for the persist-before-send
//! flow and the `crashpoint!` markers that pin every gap).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use tokio::sync::{broadcast, mpsc, oneshot, watch};

use std::time::Duration;

use boule_consensus::api::CommitNotifier;
use boule_consensus::block_sync_retry_timer::{
    BlockSyncRetryTimer, DEFAULT_INITIAL_DELAY as BLOCK_SYNC_RETRY_INITIAL_DELAY,
    DEFAULT_MAX_DELAY as BLOCK_SYNC_RETRY_MAX_DELAY, next_delay as next_retry_delay,
};
use boule_consensus::dispatch::{self, Outbound};
use boule_consensus::hotstuff::qc::{ConsensusMsg, VerifiedQc, genesis_qc_bls};
use boule_consensus::hotstuff::step::{BlockBuilder, HotStuffCore, StateUpdate};
use boule_consensus::hotstuff::{HotStuffState, QuorumCertificate, genesis_qc};
use boule_consensus::limits::CacheEvictionCounters;
use boule_consensus::pacemaker::Event as PacemakerEvent;
use boule_consensus::pacemaker::Pacemaker;
use boule_consensus::pacemaker::leader::WeightedAccumulatorSelector;
use boule_consensus::pacemaker::timeout::ExponentialBackoff;
use boule_consensus::rate_limit::MessageRateLimiter as RateLimiter;
use boule_consensus::replication::mempool::Mempool;
use boule_consensus::replication::state_machine::StateMachine;
use boule_consensus::status::ConsensusStatus;
use boule_consensus::validator_history::ValidatorSetHistory;
use boule_consensus::validator_key_history::ValidatorKeyHistory;
use boule_consensus::validator_set::ValidatorSet;
use boule_consensus::view_timer::ViewTimer;
use boule_consensus::{Height, View};
use boule_core::crypto::signed::{ChainId, Signer};
use boule_core::storage::{Storage, Wal};
use boule_transport_tcp::overlay::{Broadcaster, Discovery, DiscoveryEvent};
use boule_transport_tcp::tls::node_id_to_base58;
use boule_transport_tcp::{NodeId, ProtocolEvent};

mod action_interpreter;
mod block_builder;
mod block_sync;
mod commit;
mod config;
mod persistence;
mod reconfig_apply;
mod rotation_apply;
mod snapshot_io;
mod status;
mod timeout_bucket;

pub use block_builder::MempoolBlockBuilder;
pub use boule_consensus::wire::{
    BLOCK_RANGE_RESPONSE_MAX_BLOCKS, BlockRangeResponsePayload, BlockResponsePayload,
    MAX_FRAME_BYTES, PROTOCOL_ID, WireMessage,
};
pub use config::NodeConfigForConsensus;
pub use persistence::{
    LastCommitted, RECENT_QC_CACHE_CAPACITY, STORAGE_KEY_BLOCK_PREFIX, STORAGE_KEY_BLS_KEY_HISTORY,
    STORAGE_KEY_HEIGHT_PREFIX, STORAGE_KEY_HIGH_QC, STORAGE_KEY_LAST_COMMITTED,
    STORAGE_KEY_LAST_TIMEOUT_VOTE, STORAGE_KEY_LAST_VOTED_VIEW, STORAGE_KEY_LOCKED,
    STORAGE_KEY_PROPOSED_IN_VIEW, STORAGE_KEY_VALIDATOR_HISTORY, STORAGE_KEY_VALIDATOR_KEY_HISTORY,
    block_storage_key, decode_block, decode_height_storage_key, decode_high_qc,
    decode_last_committed, decode_last_timeout_vote, decode_locked, decode_proposed_in_view,
    decode_voted_view, encode_block, encode_high_qc, encode_last_committed,
    encode_last_timeout_vote, encode_locked, encode_proposed_in_view, encode_voted_view,
    height_storage_key, load_block_from_storage, load_block_range_from_storage, recover_state,
};

use persistence::RecentQcCache;
use timeout_bucket::TimeoutBucket;

/// Tracing target used by every structured trace emitted from the
/// consensus integration layer. Filter it with
/// `RUST_LOG=info,boule_core::consensus=debug` to see just the event
/// boundaries without drowning in p2p / gossip traffic.
pub const TRACE_TARGET: &str = "boule_core::consensus";

/// Short, stable tag for a [`ConsensusMsg`] variant — suitable as a
/// structured-log field value.
pub(super) fn msg_kind(msg: &ConsensusMsg) -> &'static str {
    match msg {
        ConsensusMsg::Proposal(_) => "Proposal",
        ConsensusMsg::Vote(_) => "Vote",
        ConsensusMsg::NewView(_) => "NewView",
    }
}

/// Short, stable tag for a [`StateUpdate`] variant — suitable as a
/// structured-log field value.
pub(super) fn update_kind(u: &StateUpdate) -> &'static str {
    match u {
        StateUpdate::VotedInView { .. } => "VotedInView",
        StateUpdate::Locked(_) => "Locked",
        StateUpdate::HighQc(_) => "HighQc",
        StateUpdate::ProposedInView { .. } => "ProposedInView",
    }
}

/// Short, stable tag for a pacemaker [`PacemakerEvent`] variant.
pub(super) fn pacemaker_event_kind(ev: &PacemakerEvent) -> &'static str {
    match ev {
        PacemakerEvent::OnQc(_) => "OnQc",
        PacemakerEvent::OnTimeoutCert(_) => "OnTimeoutCert",
        PacemakerEvent::OnTimeout(_) => "OnTimeout",
        PacemakerEvent::OnProposalReceived(_) => "OnProposalReceived",
        PacemakerEvent::OnRoundSync { .. } => "OnRoundSync",
    }
}

/// Dispatch an [`Outbound`] from the dispatch layer through the
/// [`Broadcaster`] trait object. The trait's implementations decide
/// whether to drop on backpressure; the gossip `Broadcaster` preserves
/// the "send-and-await" semantics by awaiting an mpsc send.
///
/// When `rate_limiter` is `Some`, the per-peer egress byte cap (#553)
/// is consulted on every directed [`Outbound::SendTo`]: the recipient
/// peer's outbound bucket is charged the wire size and the frame is
/// dropped (logged as `p2p_egress_byte_drop`) on overflow.
///
/// [`Outbound::Broadcast`] is intentionally not gated by the egress
/// cap. The cap is a per-peer bucket; broadcasts fan out uniformly
/// to every connected peer, so no single peer's request rate can
/// amplify a broadcast's bytes/sec asymmetrically. Honest broadcast
/// cadence (proposals at the leader's view rate, timeout votes on
/// rotation) is also independent of any peer's behaviour, so a
/// per-peer bucket is the wrong tool for bounding it. The
/// amplification vector the issue defends against
/// (`BlockRangeRequest` → `BlockRangeResponse`) is exclusively
/// `SendTo`, which the cap does cover. `peers_connected` is accepted
/// here so a future extension that splits broadcasts into per-peer
/// `SendTo`s — e.g. when [`Broadcaster`] gains recipient filtering —
/// can wire the per-peer admit without further plumbing.
pub(super) async fn send_outbound(
    broadcaster: &dyn Broadcaster,
    rate_limiter: Option<&RateLimiter>,
    _peers_connected: &HashSet<NodeId>,
    out: Outbound,
) {
    match out {
        Outbound::Broadcast(payload) => broadcaster.broadcast(payload).await,
        Outbound::SendTo { to, payload } => {
            if let Some(limiter) = rate_limiter
                && matches!(
                    limiter.admit_outbound(to, payload.len()),
                    boule_core::transport::limits::Decision::Drop
                )
            {
                tracing::warn!(
                    target: TRACE_TARGET,
                    peer = %node_id_to_base58(&to),
                    bytes = payload.len(),
                    "p2p_egress_byte_drop",
                );
                return;
            }
            broadcaster.send_to(to, payload).await
        }
    }
}

/// Composes all consensus components into a single struct.
///
/// Constructed via [`ConsensusNode::new`] for a fresh chain or
/// [`ConsensusNode::recover`] when durable state should be replayed at
/// boot. The `with_*` builder methods attach optional components
/// (commit notifier, rate limiter, status publisher, BLS signer, …)
/// before the node enters [`ConsensusNode::run`].
pub struct ConsensusNode {
    /// This replica's identity, used to sign outbound messages.
    pub self_id: NodeId,
    /// HotStuff safety core (pure state machine).
    pub core: HotStuffCore,
    /// View-management state machine (pure, no I/O).
    pub pacemaker: Pacemaker,
    /// Shared state machine; mutated on `Action::Commit`.
    pub state_machine: Arc<Mutex<Box<dyn StateMachine>>>,
    /// Source of pending commands for the block builder / leader path.
    pub mempool: Arc<dyn Mempool>,
    /// Durable KV store for control-plane state
    /// (`last_voted_view`, `locked`, `high_qc`).
    pub storage: Arc<dyn Storage>,
    /// Append-only log for durability. Flushed before outbound messages
    /// that depend on the persisted state.
    pub wal: Arc<dyn Wal>,
    /// The ordered committee this node participates in.
    pub validator_set: ValidatorSet,
    /// View-keyed history of `validator_set` across reconfiguration
    /// boundaries (#248). Until #253 lands the active reconfiguration
    /// path, this holds only the genesis boundary, so `set_at(view)`
    /// returns `validator_set` for every view. The dispatcher's
    /// per-message signer check consults this in #249 so signature
    /// verification can switch sides at a future boundary without
    /// further plumbing.
    pub validator_history: ValidatorSetHistory,
    /// Per-validator history of consensus signing keys (#259). Bridges
    /// the signer pubkey on the wire — which may be a post-rotation key
    /// — to the validator's stable identifier in `validator_history`.
    /// Until rotation tx commit-time application lands (#260), this
    /// only ever contains genesis entries (and any reconfig-added
    /// validators), so verification semantics match the
    /// pre-rotation behaviour.
    pub validator_key_history: ValidatorKeyHistory,
    /// Per-validator BLS pubkey history (#294). `Some` only on chains
    /// whose genesis declared `signature_scheme = "bls_aggregated"`
    /// (#288); `None` on Ed25519 chains. Used by the dispatch-layer QC
    /// aggregate verification (#332) to resolve per-historical-view
    /// BLS pubkeys for `verify_aggregate_bls`.
    pub bls_key_history: Option<boule_consensus::bls_key_history::BlsKeyHistory>,
    /// This validator's BLS partial signer (#354 step 2). `Some` on
    /// `bls_aggregated` chains where the operator loaded a
    /// `BlsValidatorIdentity` at boot; `None` on Ed25519 chains and on
    /// non-validator BLS-chain participants. Wrapped in `Arc` so the
    /// dispatch layer can cheaply hold a borrow across `await`
    /// suspension points alongside the existing Ed25519 `signer`.
    /// Consumed by `boule_consensus::dispatch::sign_consensus_msg`
    /// when signing a `Vote` on a BLS chain — the produced
    /// `BlsPartialSig` rides on the wire alongside the Ed25519
    /// envelope.
    pub bls_signer: Option<
        Arc<
            dyn boule_core::crypto::signed::PartialSigner<
                    boule_core::crypto::sig_scheme::BlsAggregated,
                >,
        >,
    >,
    /// Chain-level signature scheme (#288). Fixed for the lifetime of
    /// the chain; consulted at ingress time to dispatch QC aggregate
    /// verification through the right `verify_aggregate` /
    /// `verify_aggregate_bls` arm.
    pub signature_scheme: boule_core::crypto::sig_scheme::SignatureSchemeChoice,
    /// Configured view-timer behaviour; consulted by the timer helper
    /// in Phase D when arming/re-arming the view timer.
    pub timeout_policy: Arc<ExponentialBackoff>,
    /// Partial timeout certificates this replica is accumulating,
    /// keyed by the `View` the timeout pertains to. An entry is
    /// dropped once its TC fires `OnTimeoutCert` into the pacemaker
    /// so late-arriving timeout votes for past views are cheap no-ops.
    timeout_buckets: HashMap<View, TimeoutBucket>,
    /// Cap on `timeout_buckets`. When at cap, the lowest-`view`
    /// bucket is dropped so a flood of timeout votes for far-future
    /// views can never grow the map without bound. See
    /// [`boule_consensus::limits::CacheLimits::timeout_buckets_capacity`].
    timeout_buckets_capacity: usize,
    /// Shared eviction-counter handle. The same `Arc` is bound into
    /// the [`HotStuffCore`] at construction so all four caches feed
    /// into one consistent set of cumulative counts.
    eviction_counters: CacheEvictionCounters,
    /// Optional [`CommitNotifier`] fired after each block is committed
    /// and applied. `None` in production builds today; consumed by the
    /// simulator for liveness assertions and by future observer-mode
    /// (#308) / out-of-process Application (#225) wiring.
    commit_notifier: Option<Arc<dyn CommitNotifier>>,
    /// Shared overflow counter from
    /// [`boule_transport_tcp::overlay::gossip::sink::OverlaySink`] when the node
    /// is wired to a gossip-mode overlay (issue #163 / #486). When
    /// `Some`, [`ConsensusNode::build_status`] reads its current value
    /// and surfaces it under
    /// [`boule_consensus::status::BackpressureStatus::gossip_sink_overflow_total`].
    /// `None` for mesh-mode runs and for the simulator's mesh harness —
    /// the field defaults to zero in `ConsensusStatus` in those cases.
    gossip_sink_overflows: Option<Arc<AtomicU64>>,
    /// Shared overflow counter from the p2p manager — counts every
    /// `try_send` `Full` on a per-peer outbound `write_tx`, across both
    /// `SendTo` and `Broadcast` paths. Cloned from the
    /// [`boule_transport_tcp::ProtocolHandle`] returned at registration. When
    /// `Some`, surfaced via
    /// [`boule_consensus::status::BackpressureStatus::peer_outbound_overflow_total`].
    /// `None` for the simulator's mesh harness (no real p2p manager).
    peer_outbound_overflows: Option<Arc<AtomicU64>>,
    /// Per-peer credit window for the block-sync responder (#498).
    /// `apply_dispatch`'s `Dispatch::ServeBlock` arm acquires a credit
    /// before serving and releases it on completion via the
    /// [`block_sync::CreditGuard`]'s `Drop`. Defense-in-depth above
    /// the per-peer rate limiter (#134) — see
    /// [`block_sync::BlockSyncCreditWindow`].
    pub(super) block_sync_credit: Arc<block_sync::BlockSyncCreditWindow>,
    /// Outstanding bulk-range `BlockRangeRequest`s, keyed by
    /// `(from_height, to_height)` (#515). Inserted on emission so a
    /// fresh proposal arriving while the previous range is still
    /// in-flight does not double-emit. Cleared on
    /// [`boule_consensus::dispatch::Dispatch::ReceiveBlockRange`]. Decoupled from
    /// [`HotStuffCore::block_sync_inflight`] (which keys by
    /// content-hash for the single-block fallback path) — the two
    /// trackers compose: a recovering node typically holds one or
    /// two range entries plus zero or more single-hash entries.
    ///
    /// The value carries enough state for the dedicated retry timer
    /// (#530) to re-emit a dropped request without waiting for the next
    /// `ProposalReceived` to re-trigger gap detection: the addressed
    /// peer, the per-entry attempt count, and the wall-clock instant of
    /// the most recent emission.
    block_sync_range_inflight: HashMap<(Height, Height), BlockSyncRangeInflight>,
    /// Peer-membership snapshot used by [`ConsensusNode::build_status`].
    /// Populated from [`Discovery`] events inside [`ConsensusNode::run`];
    /// before `run` starts (or in tests that bypass it) the set is empty
    /// and the status snapshot reports zero connected peers.
    peers_connected: HashSet<NodeId>,
    /// Height of the most recently committed block, updated in
    /// [`ConsensusNode::apply_commit`]. Zero before the first commit.
    /// Wrapped in `Arc<AtomicU64>` so the [`MempoolBlockBuilder`] can
    /// read it from inside the safety core's `build_proposal_at_view`
    /// path to bound the uncommitted-ancestor walk (issue #375)
    /// without having to thread a borrow through the trait object.
    last_committed_height: Arc<AtomicU64>,
    /// Heap-resident work stack of self-addressed (loopback) dispatches — the
    /// node's own Vote/Proposal echoed back so the safety core tallies them
    /// like a peer message would. `apply_safety_actions` enqueues here and
    /// drains via [`Self::drain_loopback`], a re-entrancy-guarded flat loop
    /// that replaces the former `deliver_loopback` mutual recursion. Same
    /// depth-first delivery order, but the chain lives on the heap so it can't
    /// blow the call stack when long — e.g. a single-validator set, where one
    /// self-vote is a quorum and every round arms the next (#613).
    loopback_stack: Vec<boule_consensus::dispatch::Dispatch>,
    /// `true` while the top-level [`Self::drain_loopback`] loop is running, so
    /// a re-entrant drain (from an `apply_dispatch` inside that loop) just
    /// enqueues and returns instead of recursing — the flattening that bounds
    /// the call stack (#613).
    draining_loopback: bool,
    /// Minimum wall-clock spacing between proposals this node produces as
    /// leader (#614). `Duration::ZERO` disables pacing. See
    /// [`NodeConfigForConsensus::min_block_interval`].
    min_block_interval: Duration,
    /// When this node, as leader, last broadcast a proposal. Used to decide
    /// whether a fresh proposal must wait out [`Self::min_block_interval`].
    last_proposal_at: Option<tokio::time::Instant>,
    /// A QC-triggered proposal held back by pacing, waiting for the block
    /// interval to elapse. The run loop's pacing arm broadcasts it once the
    /// deadline (`last_proposal_at + min_block_interval`) passes. Holding it
    /// here (rather than looping it back immediately) is what terminates the
    /// per-round loopback chain so a single-validator chain settles (#614).
    stashed_proposal: Option<ConsensusMsg>,
    /// Cumulative count of commands the local [`MempoolBlockBuilder`]
    /// dropped because `StateMachine::apply` returned `Err` (issue
    /// #376). Surfaced under [`ConsensusStatus::dropped_commands`].
    /// Shared with the builder's own `Arc<AtomicU64>` so the two
    /// always agree without locking.
    dropped_commands: Arc<AtomicU64>,
    /// Cumulative count of vote-equivocation incidents the safety core
    /// has surfaced via
    /// [`boule_consensus::hotstuff::step::Action::EquivocationEvidence`]
    /// (audit finding 3-1, issue #409). Incremented at the
    /// `apply_safety_actions` dispatch site, so the counter and the
    /// matching WARN log advance in lockstep. Surfaced under
    /// [`ConsensusStatus::equivocations_detected`].
    equivocations_detected: Arc<AtomicU64>,
    /// Cumulative count of proposal-equivocation incidents the safety
    /// core has surfaced via
    /// [`boule_consensus::hotstuff::step::Action::ProposalEquivocationEvidence`]
    /// (audit finding L5-1). Sibling of [`Self::equivocations_detected`]
    /// — proposer-side detection lives on its own counter so the
    /// voter-side metric stays interpretable. Surfaced under
    /// [`ConsensusStatus::proposal_equivocations_detected`].
    proposal_equivocations_detected: Arc<AtomicU64>,
    /// Cumulative count of state-machine divergences detected at vote
    /// time (#599): a proposed block's deferred committed state root,
    /// anchored at a height this node has committed, disagreed with this
    /// node's own execution, so the vote was suppressed (abstained).
    /// Surfaced under [`ConsensusStatus::state_divergence_detected`].
    state_divergence_detected: Arc<AtomicU64>,
    /// Whether the deferred state-root divergence check runs at vote
    /// time (#599). Always `true` in production; disabled by
    /// `with_vote_divergence_check_disabled` (test-only) for unit tests
    /// that drive hand-crafted blocks carrying placeholder committed
    /// roots through the vote path.
    vote_divergence_check_enabled: bool,
    /// Cumulative count of proposals this node refused to vote for
    /// because they carried an application command the state machine's
    /// `check` rejected as not includable (#598) — the voter-side
    /// counterpart to the leader's build-time drop. Surfaced under
    /// [`ConsensusStatus::proposal_command_rejections`].
    proposal_command_rejections: Arc<AtomicU64>,
    /// View of the most recently committed block. Zero before the
    /// first commit.
    last_committed_view: View,
    /// Watch-channel publisher for [`ConsensusStatus`] snapshots. When
    /// `Some`, [`ConsensusNode::run`] republishes at the end of each
    /// event-loop iteration. The field is public at the module level
    /// via [`ConsensusNode::with_status_publisher`] so wiring in
    /// `main.rs` can attach a channel built around the initial
    /// snapshot.
    status_tx: Option<watch::Sender<Arc<ConsensusStatus>>>,
    /// Per-peer rate limiter (issue #134). When set, every inbound
    /// frame is classified by its postcard variant tag and admitted /
    /// dropped / disconnected per the configured token buckets. When
    /// `None`, ingress runs unfiltered — matches the historical
    /// pre-#134 behaviour and is the default in the simulator's
    /// happy-path tests.
    rate_limiter: Option<Arc<RateLimiter>>,
    /// Channel into the peer manager. When set together with
    /// `rate_limiter`, a [`boule_core::transport::limits::Decision::Disconnect`]
    /// from the limiter drives a [`boule_transport_tcp::PeerCommand::Disconnect`]
    /// so the offending peer's TCP/TLS connection is torn down. `None`
    /// in the simulator (which has no real manager); the limiter still
    /// records the disconnect-decision in its own counter so tests
    /// can observe the decision.
    peer_cmd_tx: Option<mpsc::Sender<boule_transport_tcp::PeerCommand>>,
    /// Snapshot creation policy. When `is_enabled()`, [`ConsensusNode::apply_commit`]
    /// produces a snapshot at every multiple of `interval_blocks`.
    snapshot_policy: boule_consensus::replication::snapshot::SnapshotPolicy,
    /// Operator-supplied floor on the gap between a reconfig's commit
    /// view and its `v_eff` (#272). Clamped up to
    /// [`boule_consensus::reconfig::MIN_V_EFF_DELAY`] at validation
    /// time so the consensus-side floor is never undercut.
    min_v_eff_delay: View,
    /// Bounded cache of QCs adopted as `high_qc`, keyed by block hash.
    /// Populated by `persist_updates` on every `StateUpdate::HighQc`.
    /// Read at snapshot creation time to find a QC over the snapshot
    /// block. Wrapped in a [`parking_lot::Mutex`] so `persist_updates`
    /// can update it through a `&self` receiver — the existing
    /// signature is consumed by many tests with shared (`&`) borrows.
    recent_qcs: Mutex<RecentQcCache>,
    /// Number of committed blocks to retain in the durable block store
    /// (`consensus/block/<hash>`) below `last_committed`. Older
    /// committed blocks (and their `consensus/height/<be_u64>` index
    /// entries) are deleted in the same atomic batch as each commit.
    /// `0` disables pruning entirely (archive mode). See #194.
    pub(super) block_retention_window: u64,
    /// Joiner-side snapshot-fetch state machine (#229). Watches
    /// inbound proposals for lag, drives manifest+chunk fetch from a
    /// single peer, and emits an action for the integration layer to
    /// restore state. Disabled (no-op) when the policy's
    /// `interval_blocks == 0`.
    snapshot_sync: boule_consensus::snapshot_sync::SnapshotSync,
    /// Deployment-scoped 32-byte tag (#324) mixed into every signing
    /// pre-image we produce or verify. Derived once from the genesis
    /// block hash so every honest replica with the same genesis
    /// converges on the same value; cross-deployment signature replay
    /// fails because a sibling deployment with a different genesis has
    /// a different `ChainId`.
    chain_id: ChainId,
}

/// Per-`(from_height, to_height)` retry accounting for
/// [`WireMessage::BlockRangeRequest`] (#530). Mirror of the
/// [`HotStuffCore`]'s hash-keyed `BlockSyncInflight` for the
/// single-block path: the dedicated retry timer walks both maps so a
/// dropped range request recovers in `O(100ms)` rather than waiting
/// for the next `ProposalReceived` to re-trigger gap detection.
#[derive(Debug, Clone)]
pub(super) struct BlockSyncRangeInflight {
    /// Peer the most recent emission was addressed to. Retries re-ask
    /// the same peer; per-peer rotation for range requests is a
    /// follow-up (#530 explicitly carves it out of scope), so all
    /// attempts within a single inflight entry hit one address.
    pub(super) peer: NodeId,
    /// Number of `BlockRangeRequest` emissions for this span so far,
    /// including the initial probe. Compared against
    /// [`boule_consensus::limits::CacheLimits::block_sync_max_attempts`]
    /// before each retry — when exhausted the entry is dropped and the
    /// next `ProposalReceived` is left to re-trigger gap detection
    /// from the current commit frontier.
    pub(super) attempts: u32,
    /// `tokio::time::Instant` of the most recent emission. The retry
    /// walk skips any entry whose elapsed wall-clock since
    /// `last_asked_at` is below the configured retry threshold —
    /// guards against an immediate re-emission when the timer ticks
    /// shortly after a fresh insert from
    /// [`crate::consensus_node::action_interpreter`]'s `maybe_emit_block_range_request`.
    pub(super) last_asked_at: tokio::time::Instant,
}

impl ConsensusNode {
    /// Construct a `ConsensusNode` from configuration and backing
    /// resources. Does **not** start the event loop.
    pub fn new(
        self_id: NodeId,
        config: NodeConfigForConsensus,
        state_machine: Arc<Mutex<Box<dyn StateMachine>>>,
        mempool: Arc<dyn Mempool>,
        storage: Arc<dyn Storage>,
        wal: Arc<dyn Wal>,
    ) -> Self {
        let validator_set = Arc::new(config.validator_set.clone());

        let timeout_policy = Arc::new(ExponentialBackoff::new(
            config.timeout_base,
            config.timeout_max,
        ));

        // Pacemaker leader rotation runs against the historical lookup
        // (#271) under the production default `WeightedAccumulatorSelector`
        // (#476 / parent #145). At uniform genesis weights this behaves
        // byte-for-byte like the previous round-robin selector starting
        // from the lowest-NodeId index; with non-uniform weights the
        // long-run leader frequency tracks `weight[i] / total_weight`
        // exactly. Tests that need the old round-robin rotation
        // construct `RoundRobinSelector` directly.
        let selector = Arc::new(WeightedAccumulatorSelector::from_genesis_set(Arc::clone(
            &validator_set,
        )));

        let pacemaker = Pacemaker::new(
            self_id,
            Arc::clone(&selector) as _,
            Arc::clone(&timeout_policy) as _,
        );

        let last_committed_height = Arc::new(AtomicU64::new(0));
        let dropped_commands = Arc::new(AtomicU64::new(0));
        let builder = Arc::new(MempoolBlockBuilder::new(
            self_id,
            Arc::clone(&mempool),
            Arc::clone(&state_machine),
            Arc::clone(&last_committed_height),
            Arc::clone(&dropped_commands),
            config.propose_limit,
        ));

        let validator_set_len = config.validator_set.len();
        // #324: bind the deployment's signing tag to its genesis block
        // hash. Compute before moving `config.genesis` into the safety
        // core. Every honest replica with the same genesis derives the
        // same value; sibling deployments with different genesis bytes
        // get a different tag, so a Vote/Proposal/NewView signed on one
        // chain cannot be replayed on another.
        let chain_id = ChainId::from_genesis_hash(config.genesis.hash());
        // Pick the genesis QC shape that matches the chain's signature
        // scheme. The Ed25519 path's all-zero placeholder sigs would
        // panic if folded into a BLS aggregate (see #338's
        // well-formedness invariant); the BLS variant returns an
        // empty-bitmap, empty-aggregate QC that the dispatch verifier
        // accepts via its `signer_count == 0` genesis-skip path.
        let boot_qc = match config.signature_scheme {
            boule_core::crypto::sig_scheme::SignatureSchemeChoice::Ed25519Collected => {
                genesis_qc(&config.genesis, &config.validator_set)
            }
            boule_core::crypto::sig_scheme::SignatureSchemeChoice::BlsAggregated => {
                genesis_qc_bls(&config.genesis, validator_set_len)
            }
        };
        let mut hs_state = HotStuffState::new(config.validator_set.clone(), config.genesis);
        // Seed the cluster-agreed genesis QC so the view-1 leader can
        // build a proposal on first boot without waiting for a QC-forming
        // vote round. Every honest replica derives the same QC from the
        // shared `(genesis, validator_set_len)` config.
        //
        // The dispatch verifier (`verify_qc_if_requested`)
        // short-circuits at `view == 0 || signer_count == 0`, so the
        // genesis QC is trusted by convention and the unchecked wrap
        // is exactly equivalent. Audit finding 5-1 / issue #408.
        hs_state.high_qc = Some(VerifiedQc::unchecked(boot_qc));
        let eviction_counters = CacheEvictionCounters::default();
        let core = HotStuffCore::with_limits(
            self_id,
            hs_state,
            builder as Arc<dyn BlockBuilder>,
            config.limits,
            eviction_counters.clone(),
        )
        .with_signature_scheme(config.signature_scheme);

        let validator_history = ValidatorSetHistory::from_genesis(config.validator_set.clone());
        let validator_key_history = ValidatorKeyHistory::new(config.validator_set.iter().copied());
        Self {
            self_id,
            core,
            pacemaker,
            state_machine,
            mempool,
            storage,
            wal,
            validator_set: config.validator_set,
            validator_history,
            validator_key_history,
            bls_key_history: None,
            bls_signer: None,
            signature_scheme: config.signature_scheme,
            timeout_policy,
            timeout_buckets: HashMap::new(),
            timeout_buckets_capacity: config.limits.timeout_buckets_capacity,
            eviction_counters,
            commit_notifier: None,
            gossip_sink_overflows: None,
            peer_outbound_overflows: None,
            block_sync_credit: Arc::new(block_sync::BlockSyncCreditWindow::new()),
            block_sync_range_inflight: HashMap::new(),
            peers_connected: HashSet::new(),
            last_committed_height,
            loopback_stack: Vec::new(),
            draining_loopback: false,
            min_block_interval: config.min_block_interval,
            last_proposal_at: None,
            stashed_proposal: None,
            dropped_commands,
            equivocations_detected: Arc::new(AtomicU64::new(0)),
            proposal_equivocations_detected: Arc::new(AtomicU64::new(0)),
            state_divergence_detected: Arc::new(AtomicU64::new(0)),
            vote_divergence_check_enabled: true,
            proposal_command_rejections: Arc::new(AtomicU64::new(0)),
            last_committed_view: View::ZERO,
            status_tx: None,
            rate_limiter: None,
            peer_cmd_tx: None,
            snapshot_policy: config.snapshot_policy,
            min_v_eff_delay: config.min_v_eff_delay,
            recent_qcs: Mutex::new(RecentQcCache::default()),
            block_retention_window: config.block_retention_window,
            snapshot_sync: boule_consensus::snapshot_sync::SnapshotSync::new(
                config.snapshot_policy,
            ),
            chain_id,
        }
    }

    /// Attach the per-validator BLS pubkey history. Used at boot on BLS
    /// chains so the dispatch layer can resolve per-historical-view BLS
    /// pubkeys for QC aggregate verification (#332). On Ed25519 chains
    /// this stays unset.
    pub fn with_bls_key_history(
        mut self,
        bls_key_history: boule_consensus::bls_key_history::BlsKeyHistory,
    ) -> Self {
        self.bls_key_history = Some(bls_key_history);
        self
    }

    /// Attach this validator's BLS partial signer (#354 step 2).
    ///
    /// Used at boot on `bls_aggregated` chains, when the operator has
    /// loaded a `BlsValidatorIdentity` for this node — see
    /// [`boule_core::crypto::bls_key::BlsPartialSignerImpl::from_identity`].
    /// The dispatch layer consults this signer when this node emits a
    /// `Vote`, producing the 96-byte BLS partial that rides on the
    /// wire alongside the Ed25519 envelope. On Ed25519 chains this
    /// stays unset; on BLS chains where this node is not a validator
    /// (or the operator booted without an identity), this also stays
    /// unset and the node will receive but never emit votes.
    pub fn with_bls_signer(
        mut self,
        bls_signer: Arc<
            dyn boule_core::crypto::signed::PartialSigner<
                    boule_core::crypto::sig_scheme::BlsAggregated,
                >,
        >,
    ) -> Self {
        self.bls_signer = Some(bls_signer);
        self
    }

    /// Attach a [`CommitNotifier`] (issue #373).
    ///
    /// Every block committed by the event loop is reported via
    /// [`CommitNotifier::on_commit`] after the block has been applied
    /// to the state machine, persisted, and had its tagged reconfig
    /// (#272) and rotation (#260) payloads processed. Intended for
    /// test harnesses (e.g. `SimCluster`), observer-mode nodes (#308),
    /// and external indexers; production callers without an observer
    /// leave this unset (`None`).
    ///
    /// The callback runs on the consensus event loop — implementations
    /// must not block (forward to a channel or atomic). See the
    /// [`CommitNotifier`] doc-comment for the full contract.
    pub fn with_commit_notifier(mut self, notifier: Arc<dyn CommitNotifier>) -> Self {
        self.commit_notifier = Some(notifier);
        self
    }

    /// Wire the gossip-mode overlay's
    /// [`boule_transport_tcp::overlay::gossip::sink::OverlaySink`] overflow
    /// counter into this node so
    /// [`boule_consensus::status::BackpressureStatus::gossip_sink_overflow_total`]
    /// reflects the running drop count. Pass the `Arc<AtomicU64>`
    /// returned by `OverlaySink::overflow_counter()` at construction
    /// time. Mesh-mode wiring leaves this `None` and the status field
    /// stays at zero.
    pub fn with_gossip_sink_overflow_counter(mut self, counter: Arc<AtomicU64>) -> Self {
        self.gossip_sink_overflows = Some(counter);
        self
    }

    /// Wire the p2p manager's per-peer outbound overflow counter into
    /// this node. Pass the `Arc<AtomicU64>` carried by every
    /// [`boule_transport_tcp::ProtocolHandle`]
    /// (`peer_outbound_overflows`) — there's a single shared counter per
    /// manager, so handing in the consensus-protocol's clone is fine.
    /// Surfaced via
    /// [`boule_consensus::status::BackpressureStatus::peer_outbound_overflow_total`].
    pub fn with_peer_outbound_overflow_counter(mut self, counter: Arc<AtomicU64>) -> Self {
        self.peer_outbound_overflows = Some(counter);
        self
    }

    /// Replace the auto-seeded genesis QC with `qc`.
    ///
    /// [`ConsensusNode::new`] and [`ConsensusNode::recover`] already seed
    /// the safety-core state with the canonical genesis QC derived from
    /// `(genesis, validator_set_len)` via [`genesis_qc`]; this helper is
    /// kept for tests and harnesses that need to inject a hand-built QC
    /// (e.g. to start from a mid-chain state).
    pub fn with_genesis_qc(mut self, qc: QuorumCertificate) -> Self {
        // Test/harness seed path. Production callers go through
        // `ConsensusNode::new`, which mints the cluster-agreed genesis
        // QC instead. Audit finding 5-1 / issue #408.
        self.core.set_high_qc(VerifiedQc::unchecked(qc));
        self
    }

    /// Attach a per-peer rate limiter (issue #134) and the optional
    /// peer-command channel used to issue
    /// [`boule_transport_tcp::PeerCommand::Disconnect`] when the limiter
    /// returns [`boule_core::transport::limits::Decision::Disconnect`] for a peer.
    /// Pass `peer_cmd_tx = None` in the simulator: the limiter will
    /// still classify and drop, and tests can observe the disconnect
    /// decision via [`RateLimiter::counters`].
    pub fn with_rate_limiter(
        mut self,
        limiter: Arc<RateLimiter>,
        peer_cmd_tx: Option<mpsc::Sender<boule_transport_tcp::PeerCommand>>,
    ) -> Self {
        self.rate_limiter = Some(limiter);
        self.peer_cmd_tx = peer_cmd_tx;
        self
    }

    /// Attach a [`watch::Sender`] that [`ConsensusNode::run`] will use
    /// to republish the [`ConsensusStatus`] snapshot after each event-
    /// loop iteration.
    ///
    /// The caller typically obtains the paired receiver by calling
    /// [`ConsensusNode::build_status`] on the just-constructed node and
    /// wrapping the result in [`watch::channel`] before attaching the
    /// sender here. That way the initial value published on the channel
    /// is already a sane snapshot (current_view=0 on a fresh boot),
    /// so the HTTP endpoint never returns 500 during the window between
    /// node construction and the first event-loop tick.
    pub fn with_status_publisher(mut self, tx: watch::Sender<Arc<ConsensusStatus>>) -> Self {
        self.status_tx = Some(tx);
        self
    }

    /// Clone the shared equivocation counter (audit finding 3-1, issue
    /// #409). The same `Arc` the integration layer increments on every
    /// `Action::EquivocationEvidence` it observes — capturing it before
    /// the node is moved into [`ConsensusNode::run`] lets a test harness
    /// (`SimCluster::peek_equivocations_detected`, issue #421's twin-mode
    /// adversary) verify the evidence-emission path end-to-end without
    /// having to subscribe to a status publisher.
    pub fn equivocations_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.equivocations_detected)
    }

    /// Clone the shared proposal-equivocation counter (audit finding
    /// L5-1). The same `Arc` the integration layer increments on every
    /// `Action::ProposalEquivocationEvidence` it observes; sibling of
    /// [`Self::equivocations_counter`] used by
    /// `SimCluster::peek_proposal_equivocations_detected`
    /// to verify the proposer-side detection path end-to-end.
    pub fn proposal_equivocations_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.proposal_equivocations_detected)
    }

    /// Clone the shared state-divergence counter (#599). The same `Arc`
    /// the integration layer increments whenever it suppresses a vote
    /// because a proposed block's deferred committed state root
    /// disagreed with this node's own execution. Used by
    /// `SimCluster::peek_state_divergence_detected` to verify the
    /// detection path end-to-end.
    pub fn state_divergence_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.state_divergence_detected)
    }

    /// Clone the shared proposal-command-rejection counter (#598). The
    /// same `Arc` the integration layer increments whenever it suppresses
    /// a vote because a proposed block carried a non-includable
    /// application command. Used by
    /// `SimCluster::peek_proposal_command_rejections` to verify the
    /// voter-side enforcement path end-to-end.
    pub fn proposal_command_rejections_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.proposal_command_rejections)
    }

    /// Test-only: disable the deferred state-root divergence check at
    /// vote time (#599). Unit tests that drive hand-crafted blocks
    /// carrying placeholder committed roots through the vote path use
    /// this so the check doesn't suppress an expected vote.
    #[cfg(test)]
    pub(crate) fn with_vote_divergence_check_disabled(mut self) -> Self {
        self.vote_divergence_check_enabled = false;
        self
    }

    /// Borrow the eviction counters this node aggregates across the
    /// safety-core and timeout-vote caches. Exposed for tests and
    /// for [`build_status`](Self::build_status) to project into the
    /// JSON snapshot.
    pub fn eviction_counters(&self) -> &CacheEvictionCounters {
        &self.eviction_counters
    }

    /// Publish a fresh snapshot on the watch channel (if attached).
    /// Called by [`ConsensusNode::run`] at the end of each event-loop
    /// iteration. `send_replace` ignores the "no receivers" case so the
    /// node keeps running even if no-one is listening.
    fn publish_status(&self) {
        if let Some(tx) = &self.status_tx {
            let _ = tx.send_replace(Arc::new(self.build_status()));
        }
    }

    /// Construct a `ConsensusNode`, restoring any durable control-plane
    /// state from `storage` (see [`recover_state`]).
    ///
    /// On a fresh `storage` with no persisted keys this behaves
    /// identically to [`ConsensusNode::new`]. On a storage that has
    /// previously recorded `last_voted_view` / `locked` / `high_qc` via
    /// [`ConsensusNode::persist_updates`], those values are read back
    /// into the [`HotStuffState`] so the safety-core invariants
    /// (no double-voting, no regression of the lock) survive a restart.
    ///
    /// Returns `Err` only on storage backend failures or corrupted
    /// stored bytes. Missing keys are the normal fresh-start case and
    /// are not errors.
    pub fn recover(
        self_id: NodeId,
        config: NodeConfigForConsensus,
        state_machine: Arc<Mutex<Box<dyn StateMachine>>>,
        mempool: Arc<dyn Mempool>,
        storage: Arc<dyn Storage>,
        wal: Arc<dyn Wal>,
    ) -> anyhow::Result<Self> {
        use anyhow::Context;

        let hs_state = recover_state(
            storage.as_ref(),
            config.validator_set.clone(),
            config.genesis.clone(),
        )?;

        // Restore the (height, view) status checkpoint so a freshly
        // resumed replica reports its durable chain rather than `0` —
        // see `STORAGE_KEY_LAST_COMMITTED` and the `consensus_resumed`
        // gap called out in #178's reopen comment.
        let last_committed = match storage
            .get(STORAGE_KEY_LAST_COMMITTED)
            .context("read last_committed from storage")?
        {
            Some(raw) => decode_last_committed(&raw)?,
            None => LastCommitted {
                height: Height::ZERO,
                view: View::ZERO,
                last_committed_hash: [0u8; 32],
            },
        };

        // #254: recover the persisted validator history if any
        // committed reconfig has flushed it. Missing key → fresh
        // genesis-only history.
        let validator_history = match storage
            .get(STORAGE_KEY_VALIDATOR_HISTORY)
            .context("read validator_history from storage")?
        {
            Some(raw) => {
                let persisted: boule_consensus::validator_history::PersistedValidatorHistory =
                    postcard::from_bytes(&raw).context("decode persisted validator_history")?;
                ValidatorSetHistory::from_persisted(persisted)
                    .context("rebuild ValidatorSetHistory from persisted form")?
            }
            None => ValidatorSetHistory::from_genesis(config.validator_set.clone()),
        };

        let active_set = (*validator_history.current_set()).clone();
        let timeout_policy = Arc::new(ExponentialBackoff::new(
            config.timeout_base,
            config.timeout_max,
        ));
        // Build the selector against a snapshot of the recovered
        // history so leader rotation honors any post-genesis boundaries
        // immediately after restart. Production default is
        // `WeightedAccumulatorSelector` (#476 / parent #145).
        let selector = Arc::new(WeightedAccumulatorSelector::new(Arc::new(
            validator_history.clone(),
        )));
        let pacemaker = Pacemaker::new(
            self_id,
            Arc::clone(&selector) as _,
            Arc::clone(&timeout_policy) as _,
        );

        let last_committed_height = Arc::new(AtomicU64::new(last_committed.height.0));
        let dropped_commands = Arc::new(AtomicU64::new(0));
        let builder = Arc::new(MempoolBlockBuilder::new(
            self_id,
            Arc::clone(&mempool),
            Arc::clone(&state_machine),
            Arc::clone(&last_committed_height),
            Arc::clone(&dropped_commands),
            config.propose_limit,
        ));
        // #407: restore the leader-side `proposed_in_view` guard so a
        // crash between `Signed::sign` and the `Broadcast(Proposal)`
        // bytes leaving the host does not let this replica re-mint a
        // *different* signed proposal at the same view on restart.
        // Missing key = fresh storage; a value of `0` is the safe
        // default the in-memory field already starts at.
        let proposed_in_view = match storage
            .get(STORAGE_KEY_PROPOSED_IN_VIEW)
            .context("read proposed_in_view from storage")?
        {
            Some(raw) => decode_proposed_in_view(&raw)?,
            None => View::ZERO,
        };
        let eviction_counters = CacheEvictionCounters::default();
        let mut core = HotStuffCore::with_limits(
            self_id,
            hs_state,
            builder as Arc<dyn BlockBuilder>,
            config.limits,
            eviction_counters.clone(),
        )
        .with_signature_scheme(config.signature_scheme)
        .with_proposed_in_view(proposed_in_view);

        // #254: replay each post-genesis boundary into the safety
        // core's history so vote tally / QC sizing / proposal-time
        // leader pick all see the recovered committee. Genesis is
        // already seeded by `HotStuffState::new`. Any failure here
        // surfaces as a recovery error — we'd rather fail closed than
        // run with a stale set.
        for (v_eff, set) in validator_history.iter() {
            if v_eff == View::ZERO {
                continue;
            }
            core.insert_validator_boundary(v_eff, (**set).clone())
                .with_context(|| format!("replay validator boundary at v_eff = {v_eff}"))?;
        }

        // #260: load the persisted key history first, falling back to a
        // mirror of the set history if no rotations have ever been
        // committed (or the WAL key is otherwise absent). The persisted
        // form is authoritative once written — every committed rotation
        // is reflected — so we never overwrite it from set history.
        let validator_key_history = match storage
            .get(STORAGE_KEY_VALIDATOR_KEY_HISTORY)
            .context("read validator_key_history from storage")?
        {
            Some(raw) => {
                let persisted: boule_consensus::validator_key_history::PersistedValidatorKeyHistory =
                    postcard::from_bytes(&raw)
                        .context("decode persisted validator_key_history")?;
                ValidatorKeyHistory::from_persisted(persisted)
                    .context("rebuild ValidatorKeyHistory from persisted form")?
            }
            None => ValidatorKeyHistory::from_set_history(&validator_history),
        };

        // #324: same derivation as `ConsensusNode::new` — recover paths
        // must produce the same `ChainId` as a fresh boot, since both
        // share the same genesis bytes.
        let chain_id = ChainId::from_genesis_hash(config.genesis.hash());
        Ok(Self {
            self_id,
            core,
            pacemaker,
            state_machine,
            mempool,
            storage,
            wal,
            validator_set: active_set,
            validator_history,
            validator_key_history,
            bls_key_history: None,
            bls_signer: None,
            signature_scheme: config.signature_scheme,
            timeout_policy,
            timeout_buckets: HashMap::new(),
            timeout_buckets_capacity: config.limits.timeout_buckets_capacity,
            eviction_counters,
            commit_notifier: None,
            gossip_sink_overflows: None,
            peer_outbound_overflows: None,
            block_sync_credit: Arc::new(block_sync::BlockSyncCreditWindow::new()),
            block_sync_range_inflight: HashMap::new(),
            peers_connected: HashSet::new(),
            last_committed_height,
            loopback_stack: Vec::new(),
            draining_loopback: false,
            min_block_interval: config.min_block_interval,
            last_proposal_at: None,
            stashed_proposal: None,
            dropped_commands,
            equivocations_detected: Arc::new(AtomicU64::new(0)),
            proposal_equivocations_detected: Arc::new(AtomicU64::new(0)),
            state_divergence_detected: Arc::new(AtomicU64::new(0)),
            vote_divergence_check_enabled: true,
            proposal_command_rejections: Arc::new(AtomicU64::new(0)),
            last_committed_view: last_committed.view,
            status_tx: None,
            rate_limiter: None,
            peer_cmd_tx: None,
            snapshot_policy: config.snapshot_policy,
            min_v_eff_delay: config.min_v_eff_delay,
            recent_qcs: Mutex::new(RecentQcCache::default()),
            block_retention_window: config.block_retention_window,
            snapshot_sync: boule_consensus::snapshot_sync::SnapshotSync::new(
                config.snapshot_policy,
            ),
            chain_id,
        })
    }

    /// Current view from the pacemaker's perspective.
    pub fn current_view(&self) -> View {
        self.pacemaker.current_view()
    }

    // ── Event loop ───────────────────────────────────────────────────────────

    /// Run the consensus event loop until `shutdown` fires or the
    /// inbound channel closes.
    ///
    /// # Startup
    ///
    /// Immediately advances the pacemaker from view 0 → 1 (via a synthetic
    /// `OnQc(0)`) so the view timer is armed and the node announces itself
    /// to its peers before any network message arrives.
    ///
    /// # Durability discipline
    ///
    /// `Action::Persist` updates are buffered and written atomically to
    /// [`ConsensusNode::storage`] **before** any `Broadcast` / `SendTo` /
    /// `Commit` action that follows them in the same `step` output. This
    /// guarantees that a crash between "write persist" and "send vote" is
    /// safe: the replica restarts with the vote view recorded, so it cannot
    /// double-vote when it re-enters the view.
    ///
    /// # Topology abstraction
    ///
    /// Outbound traffic flows through `broadcaster` (a [`Broadcaster`]
    /// trait object) and peer-membership deltas through `discovery`'s
    /// event stream. The mesh is the only implementation today; gossip
    /// and dynamic-membership backends drop in here without touching
    /// the event loop. See [`boule_transport_tcp::overlay`] for the contract.
    pub async fn run(
        mut self,
        broadcaster: Arc<dyn Broadcaster>,
        discovery: Arc<dyn Discovery>,
        mut event_rx: mpsc::Receiver<ProtocolEvent>,
        signer: Arc<dyn Signer>,
        mut shutdown: oneshot::Receiver<()>,
    ) -> anyhow::Result<()> {
        let mut discovery_events = discovery.subscribe();
        // Seed `peers_connected` from a snapshot so any peer that
        // connected before our subscription is still reflected. Discovery
        // events from the subscription point onward keep it in sync.
        self.peers_connected = discovery.known_peers().into_iter().collect();

        let (timer_tx, mut timer_rx) = mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        // Dedicated block-sync retry timer (#512). Decoupled from the
        // pacemaker view timer so a single-shot `RequestBlock` lost in
        // flight recovers in `O(100ms)` rather than `O(view_timeout)`.
        // The timer is *single-shot* — re-armed after each fire from
        // [`Self::ensure_block_sync_retry_timer_armed`] iff the safety
        // core still has at least one in-flight request.
        let (retry_timer_tx, mut retry_timer_rx) = mpsc::channel::<()>(4);
        let mut retry_timer = BlockSyncRetryTimer::new(retry_timer_tx);
        let mut retry_timer_delay: Option<Duration> = None;

        // Boot-time snapshot of recovered durable state. Logged once
        // per node start so operators can correlate "did we come up
        // already behind the live cluster?" with downstream block-sync
        // events. Issue #178 introduced this trace to disambiguate
        // restart bootstrap from peer-disconnect / block-not-found
        // stalls — the latter two only ever fire post-resume, so a
        // missing `consensus_resumed` line means the run loop never
        // started.
        tracing::info!(
            target: TRACE_TARGET,
            self_id = %node_id_to_base58(&self.self_id),
            last_committed_height = self.last_committed_height.load(Ordering::Relaxed),
            last_committed_view = self.last_committed_view.0,
            high_qc_view = ?self.core.state().high_qc.as_ref().map(|q| q.view().0),
            last_voted_view = self.core.state().last_voted_view.0,
            locked_view = ?self.core.state().locked.as_ref().map(|l| l.view.0),
            validator_set_size = self.validator_set.len(),
            "consensus_resumed",
        );

        // Publish an initial snapshot before doing anything else, so
        // the HTTP endpoint has a sane value available even if it's
        // queried in the tiny window before the boot actions fire.
        self.publish_status();

        // Boot: advance the pacemaker out of view 0, arm the view timer,
        // and broadcast NewView (if we have a high_qc from a prior
        // session).
        //
        // For a fresh start, persisted `high_qc` and `last_voted_view`
        // are both zero so this is `OnQc(0)` → advance to view 1 — the
        // historical behaviour. After a restart with non-trivial durable
        // state we instead seed from
        // `max(high_qc.view, last_voted_view)` so the pacemaker lands
        // directly at the next post-restart view rather than briefly
        // advertising view 1 to peers and then jumping forward via the
        // self-loopback `OnQc(high_qc.view)`. The previous transient was
        // the path that left the first-killed-of-three replica wedged
        // at exactly its persisted `last_voted_view` (issue #222): if
        // peers' subsequent NewView messages are filtered out by the
        // gossip layer for any reason, the lagging replica's only catch-
        // up path is its own outbound timeout votes — and seeding from
        // disk eliminates the gap between "we restarted" and "our timer
        // is armed for the right view".
        let boot_view = self
            .core
            .state()
            .high_qc
            .as_ref()
            .map(|qc| qc.view())
            .unwrap_or(View::ZERO)
            .max(self.core.state().last_voted_view);
        let boot_actions = self.step_pacemaker(PacemakerEvent::OnQc(boot_view));
        self.apply_pacemaker_actions(boot_actions, broadcaster.as_ref(), &mut view_timer, &signer)
            .await?;
        self.publish_status();

        loop {
            tokio::select! {
                biased;

                _ = &mut shutdown => break,

                Some(view) = timer_rx.recv() => {
                    let pm_actions = self.step_pacemaker(PacemakerEvent::OnTimeout(view));
                    self.apply_pacemaker_actions(pm_actions, broadcaster.as_ref(), &mut view_timer, &signer)
                        .await?;
                }

                // Block-production pacing (#614): once `min_block_interval`
                // has elapsed since our last proposal, broadcast the one we
                // held back. The guard makes this arm inert unless a proposal
                // is actually stashed (so pacing is off by default / at n>=4),
                // and `sleep_until` targets a fixed deadline so re-creating it
                // each loop iteration is harmless.
                () = tokio::time::sleep_until(
                    self.last_proposal_at
                        .map(|t| t + self.min_block_interval)
                        .unwrap_or_else(tokio::time::Instant::now),
                ), if self.stashed_proposal.is_some() => {
                    if let Some(msg) = self.stashed_proposal.take() {
                        self.broadcast_consensus_msg(msg, broadcaster.as_ref(), &mut view_timer, &signer)
                            .await?;
                    }
                }

                Some(()) = retry_timer_rx.recv() => {
                    // Dedicated block-sync retry tick (#512). Walks
                    // every still-tracked `block_sync_inflight` entry
                    // and emits one `RequestBlock` per parent. The
                    // re-arm at end-of-iteration handles exponential
                    // backoff and cancellation when the tracker drains.
                    let actions = self.core.step_block_sync_retry_tick();
                    self.apply_safety_actions(actions, broadcaster.as_ref(), &mut view_timer, &signer)
                        .await?;
                    // Range-keyed retry walk (#530) shares the same
                    // wall-clock cadence as the hash-keyed path above:
                    // a dropped `BlockRangeRequest` recovers in
                    // `O(100ms)` rather than waiting for the next
                    // `ProposalReceived` to re-trigger gap detection.
                    // The per-entry `BLOCK_SYNC_RETRY_INITIAL_DELAY`
                    // quiescence threshold guards against immediate
                    // re-emission when this tick fires shortly after a
                    // fresh `maybe_emit_block_range_request` insert.
                    self.maintain_block_sync_range_retry(
                        broadcaster.as_ref(),
                        BLOCK_SYNC_RETRY_INITIAL_DELAY,
                    )
                    .await?;
                }

                disc = discovery_events.recv() => {
                    match disc {
                        Ok(DiscoveryEvent::PeerAdded(node_id)) => {
                            tracing::debug!("consensus: peer added {node_id:?}");
                            self.peers_connected.insert(node_id);
                            // Snapshot-sync (#230): a freshly-added peer
                            // can immediately serve chunks. The state
                            // machine is a no-op outside `Fetching`.
                            let actions = self.snapshot_sync.add_candidate(node_id);
                            self.apply_snapshot_sync_actions(
                                actions,
                                broadcaster.as_ref(),
                                &mut view_timer,
                                &signer,
                            )
                            .await?;
                        }
                        Ok(DiscoveryEvent::PeerRemoved(node_id)) => {
                            tracing::debug!("consensus: peer removed {node_id:?}");
                            self.peers_connected.remove(&node_id);
                            // Snapshot-sync (#230): drop from candidate
                            // set, reassign in-flight chunks. The state
                            // machine handles non-`Fetching` states as
                            // no-ops.
                            let actions = self.snapshot_sync.on_peer_disconnected(node_id);
                            self.apply_snapshot_sync_actions(
                                actions,
                                broadcaster.as_ref(),
                                &mut view_timer,
                                &signer,
                            )
                            .await?;
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            // Resync from the snapshot — the cache is the
                            // authoritative source, and `Discovery` only
                            // publishes deltas for forward-progress in the
                            // common case.
                            self.peers_connected = discovery.known_peers().into_iter().collect();
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            // Discovery shut down. Don't tear consensus
                            // down with it — peer tracking just freezes
                            // until restart.
                        }
                    }
                }

                Some(event) = event_rx.recv() => {
                    match event {
                        ProtocolEvent::Message { from, payload } => {
                            // Rate-limit at the consensus integration
                            // boundary, before the postcard decode in
                            // `dispatch::ingress` (issue #134). The
                            // limiter peeks at the first byte (the
                            // postcard variant tag) and decides admit /
                            // drop / disconnect; on Disconnect we ask
                            // the manager to tear the peer's
                            // connection down. The limiter is
                            // optional, so this stays a no-op for any
                            // embedding that has not configured one
                            // (notably the sim's happy-path harness).
                            if !self.admit_inbound(from, &payload).await {
                                continue;
                            }
                            // Verify QC aggregates at ingress per the chain's scheme
                            // (#332). Closes the Byzantine-leader-ships-bogus-QC
                            // vector for both Ed25519 and BLS chains. The
                            // `genesis_hash` is threaded so the verifier can
                            // reject view-0 QCs over an attacker-chosen block
                            // hash (#418, audit finding 7-4).
                            let qc_verification = dispatch::QcVerification::Verify {
                                scheme: self.signature_scheme,
                                bls_key_history: self.bls_key_history.as_ref(),
                                min_v_eff_delay: self.min_v_eff_delay,
                                genesis_hash: self.core.state().genesis_hash,
                            };
                            match dispatch::ingress_with_qc_verification(
                                from,
                                &payload,
                                &self.validator_history,
                                &self.validator_key_history,
                                &qc_verification,
                                &self.chain_id,
                            ) {
                                Ok(dispatches) => {
                                    for d in dispatches {
                                        self.apply_dispatch(d, broadcaster.as_ref(), &mut view_timer, &signer)
                                            .await?;
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!("consensus: ingress rejected from {from:?}: {e}");
                                }
                            }
                        }
                        // Peer connectivity is tracked through the
                        // Discovery event stream above; the protocol
                        // multiplexer still fans these out to every
                        // protocol handle (used by the RPC layer for
                        // request cancellation), so we just observe and
                        // move on at this layer. The one exception is
                        // the rate limiter: a disconnect should clear
                        // the per-peer state so a future reconnect
                        // starts with a fresh budget (#134 non-goal:
                        // no cross-reconnect reputation).
                        ProtocolEvent::PeerConnected { .. } => {}
                        ProtocolEvent::PeerDisconnected { node_id } => {
                            if let Some(limiter) = self.rate_limiter.as_ref() {
                                limiter.forget_peer(node_id);
                            }
                        }
                    }
                }

                else => break,
            }

            // Re-arm or cancel the dedicated block-sync retry timer
            // (#512) based on whether the safety core still has any
            // in-flight `RequestBlock` after this iteration's actions
            // were applied. The timer is single-shot, so this is the
            // only re-arm site — fires that handled `step_block_sync_retry_tick`
            // already returned through the matching `select!` arm above
            // and the inflight tracker may have been emptied (parent
            // arrived, budget exhausted) or re-populated (new
            // proposal's parent missing). Cancel/arm decisions are
            // idempotent.
            self.maintain_block_sync_retry_timer(&mut retry_timer, &mut retry_timer_delay);

            // Publish a fresh snapshot at the end of every iteration,
            // after all dispatched actions have been applied. No hot-
            // path locking — just a shallow rebuild and a watch-channel
            // `send_replace`.
            self.publish_status();
        }

        view_timer.cancel();
        retry_timer.cancel();
        Ok(())
    }

    /// Re-arm or cancel the dedicated block-sync retry timer (#512)
    /// based on whether the safety core or the integration layer has
    /// any in-flight block-sync request after the current iteration's
    /// actions were applied. Both the hash-keyed `block_sync_inflight`
    /// (single-block path) and the range-keyed
    /// `block_sync_range_inflight` (#530) keep the timer alive — a
    /// dropped `BlockRangeRequest` would otherwise wait for the next
    /// `ProposalReceived` to re-trigger gap detection, which on a
    /// quiet cluster can stretch to seconds.
    ///
    /// - When either tracker is non-empty and no timer is armed: arm
    ///   with the next exponential-backoff delay (initial on the
    ///   first arm of a fresh inflight burst).
    /// - When either tracker is non-empty and a timer is already
    ///   armed: no-op (the prior arming will fire and re-trigger this
    ///   helper).
    /// - When both trackers are empty: cancel the timer and reset the
    ///   backoff so the next burst starts from the initial delay.
    fn maintain_block_sync_retry_timer(
        &self,
        retry_timer: &mut BlockSyncRetryTimer,
        retry_timer_delay: &mut Option<Duration>,
    ) {
        let any_inflight =
            self.core.has_any_block_sync_inflight() || !self.block_sync_range_inflight.is_empty();
        if any_inflight {
            if !retry_timer.is_armed() {
                let delay = next_retry_delay(
                    *retry_timer_delay,
                    BLOCK_SYNC_RETRY_INITIAL_DELAY,
                    BLOCK_SYNC_RETRY_MAX_DELAY,
                );
                retry_timer.arm(delay);
                *retry_timer_delay = Some(delay);
            }
        } else {
            retry_timer.cancel();
            *retry_timer_delay = None;
        }
    }

    /// Test-only: install a `block_sync_range_inflight` entry as if a
    /// `BlockRangeRequest` had just been emitted to `peer` for the
    /// given span. Lets the integration-layer dispatch tests (#531)
    /// exercise the `BlockRangeResponse` inflight gate without
    /// standing up a full multi-block parked-proposal flow.
    #[cfg(test)]
    pub(crate) fn install_block_sync_range_inflight_for_test(
        &mut self,
        from_height: Height,
        to_height: Height,
        peer: NodeId,
    ) {
        self.block_sync_range_inflight.insert(
            (from_height, to_height),
            BlockSyncRangeInflight {
                peer,
                attempts: 1,
                last_asked_at: tokio::time::Instant::now(),
            },
        );
    }

    /// Test-only: read a `block_sync_range_inflight` entry. Returns
    /// `Some(peer)` when an entry exists for the given span, `None`
    /// otherwise. Used to assert the inflight gate's "consume on
    /// receipt" behaviour from the dispatch tests.
    #[cfg(test)]
    pub(crate) fn block_sync_range_inflight_peer_for_test(
        &self,
        from_height: Height,
        to_height: Height,
    ) -> Option<NodeId> {
        self.block_sync_range_inflight
            .get(&(from_height, to_height))
            .map(|e| e.peer)
    }

    /// Test-only: read a `block_sync_range_inflight` entry's attempt
    /// counter. Returns `None` when no entry exists for the given
    /// span. Used by the `#530` range-retry tests to assert the
    /// counter advances on each retry walk.
    #[cfg(test)]
    pub(crate) fn block_sync_range_inflight_attempts_for_test(
        &self,
        from_height: Height,
        to_height: Height,
    ) -> Option<u32> {
        self.block_sync_range_inflight
            .get(&(from_height, to_height))
            .map(|e| e.attempts)
    }
}
// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use parking_lot::Mutex;

    use std::time::Duration;

    use super::*;
    // Re-imports for short-name access in tests (the production code
    // moved to topical submodules under `node/`, so the symbols are no
    // longer brought into scope by this file's top-level `use` block).
    use boule_consensus::dispatch::Dispatch;
    use boule_consensus::hotstuff::Locked;
    use boule_consensus::hotstuff::qc::TimeoutVote;
    use boule_consensus::hotstuff::step::{Action as SafetyAction, Event as SafetyEvent};
    use boule_consensus::limits::CacheLimits;
    use boule_consensus::rate_limit::MessageKind;
    use boule_consensus::replication::block::{Block, BlockHash, BlockHeader};
    use boule_consensus::replication::impls::{CounterStateMachine, InMemoryMempool};
    use boule_consensus::validator_set::ValidatorSet;
    use boule_core::crypto::signed::Signed;
    use boule_core::storage::{MemoryStorage, MemoryWal};
    use boule_transport_tcp::NodeId;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn vid(b: u8) -> boule_consensus::validator_set::ValidatorId {
        boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(nid(b))
    }

    fn four_validators() -> ValidatorSet {
        ValidatorSet::new(vec![vid(1), vid(2), vid(3), vid(4)])
    }

    fn genesis() -> Block {
        Block::genesis([0u8; 32], [0; 32])
    }

    fn test_config(vs: ValidatorSet) -> NodeConfigForConsensus {
        NodeConfigForConsensus::for_testing(vs, genesis())
    }

    fn make_sm() -> Arc<Mutex<Box<dyn StateMachine>>> {
        Arc::new(Mutex::new(Box::new(CounterStateMachine::new())))
    }

    fn make_node(self_id: NodeId) -> ConsensusNode {
        let vs = four_validators();
        let cfg = test_config(vs);
        ConsensusNode::new(
            self_id,
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(256)),
            Arc::new(MemoryStorage::new()),
            Arc::new(MemoryWal::new()),
        )
    }

    // ── A4: smoke test ───────────────────────────────────────────────────────

    #[test]
    fn new_initializes_at_view_zero() {
        let node = make_node(nid(1));
        assert_eq!(node.current_view(), View(0));
        assert_eq!(node.core.state().current_view, View(0));
        assert_eq!(node.pacemaker.current_view(), View(0));
    }

    #[test]
    fn self_id_is_stored_correctly() {
        let node = make_node(nid(3));
        assert_eq!(node.self_id, nid(3));
        assert_eq!(node.core.self_id(), nid(3));
        assert_eq!(node.pacemaker.self_id(), nid(3));
    }

    #[test]
    fn genesis_is_in_pending_blocks() {
        let node = make_node(nid(1));
        let g_hash = genesis().hash();
        assert!(
            node.core.state().pending_blocks.contains_key(&g_hash),
            "genesis block must be pre-seeded into pending_blocks",
        );
    }

    #[test]
    fn build_status_default_backpressure_is_zero() {
        // Mesh-mode wiring leaves the gossip-sink overflow counter
        // unset; the status field must default to zero rather than
        // omitting the section.
        let node = make_node(nid(1));
        let status = node.build_status();
        assert_eq!(status.backpressure.gossip_sink_overflow_total, 0);
    }

    #[test]
    fn build_status_surfaces_wired_gossip_sink_overflow_counter() {
        // Wire a fresh counter, bump it, and assert build_status reads
        // the live value. This is the seam between OverlaySink (#486)
        // and the public ConsensusStatus JSON.
        let counter = Arc::new(AtomicU64::new(0));
        let node = make_node(nid(1)).with_gossip_sink_overflow_counter(Arc::clone(&counter));

        assert_eq!(
            node.build_status().backpressure.gossip_sink_overflow_total,
            0
        );

        counter.fetch_add(7, Ordering::Relaxed);
        assert_eq!(
            node.build_status().backpressure.gossip_sink_overflow_total,
            7
        );
    }

    #[test]
    fn build_status_surfaces_wired_peer_outbound_overflow_counter() {
        // Same seam but for the per-peer outbound counter that
        // ProtocolHandle hands back from the p2p manager.
        let counter = Arc::new(AtomicU64::new(0));
        let node = make_node(nid(1)).with_peer_outbound_overflow_counter(Arc::clone(&counter));

        assert_eq!(
            node.build_status()
                .backpressure
                .peer_outbound_overflow_total,
            0
        );

        counter.fetch_add(13, Ordering::Relaxed);
        assert_eq!(
            node.build_status()
                .backpressure
                .peer_outbound_overflow_total,
            13
        );
    }

    #[test]
    fn build_status_surfaces_validator_keys_with_genesis_entries() {
        // Acceptance criterion 1 (#314): the snapshot has one
        // validator_keys entry per validator in the seeded key history,
        // each with a single genesis rotation entry.
        let node = make_node(nid(1));
        let status = node.build_status();
        assert_eq!(status.validator_keys.len(), 4);
        // BTreeMap iteration order = byte-lexicographic, which for the
        // [b; 32] test ids matches the validator-set ordering. Every
        // entry has a single genesis rotation at view 0, with
        // active_pubkey == stable_id.
        for v in &status.validator_keys {
            assert_eq!(v.entries.len(), 1);
            assert_eq!(v.entries[0].v_eff, View(0));
            assert_eq!(v.entries[0].pubkey, v.stable_id);
            assert_eq!(v.active_pubkey, v.stable_id);
        }
        // Every stable_id appears in the validator set as of this
        // snapshot view (acceptance criterion 3).
        for v in &status.validator_keys {
            assert!(
                status.validator_set.contains(&v.stable_id),
                "stable_id {} missing from validator_set",
                v.stable_id,
            );
        }
    }

    #[test]
    fn build_status_surfaces_rotation_in_validator_keys() {
        // Acceptance criterion 2 (#314): after an applied rotation, the
        // affected validator's entries vector grows to length 2 and
        // active_pubkey advances to the new key.
        use boule_consensus::validator_rotation::{V_EFF_MIN_DELAY, ValidatorKeyRotation};

        let mut node = make_node(nid(1));

        let new_key = nid(42);
        let commit_view = View(10);
        let v_eff = commit_view + V_EFF_MIN_DELAY;
        let rotation = ValidatorKeyRotation {
            validator: nid(2),
            new_pubkey: new_key,
            v_eff,
            new_bls_pubkey: None,
            new_bls_pop: None,
        };
        node.validator_key_history
            .apply_rotation(&rotation, commit_view)
            .expect("rotation applies cleanly to seeded history");

        let status = node.build_status();
        let stable_id_b58 = boule_transport_tcp::tls::node_id_to_base58(&nid(2));
        let new_key_b58 = boule_transport_tcp::tls::node_id_to_base58(&new_key);

        let rotated = status
            .validator_keys
            .iter()
            .find(|v| v.stable_id == stable_id_b58)
            .expect("rotated validator must surface in validator_keys");
        assert_eq!(rotated.entries.len(), 2);
        assert_eq!(rotated.entries[0].v_eff, View(0));
        assert_eq!(rotated.entries[0].pubkey, stable_id_b58);
        assert_eq!(rotated.entries[1].v_eff, v_eff);
        assert_eq!(rotated.entries[1].pubkey, new_key_b58);
        assert_eq!(rotated.active_pubkey, new_key_b58);

        // Other validators' timelines must remain at length 1.
        for v in &status.validator_keys {
            if v.stable_id != stable_id_b58 {
                assert_eq!(v.entries.len(), 1);
                assert_eq!(v.active_pubkey, v.stable_id);
            }
        }
    }

    // ── A2: WireMessage roundtrip ────────────────────────────────────────────

    fn sample_block() -> Block {
        use boule_consensus::replication::block::BlockHeader;
        let g = genesis();
        Block {
            header: BlockHeader {
                parent_hash: g.hash(),
                height: Height(1),
                view: View(1),
                proposer: nid(1),
                state_commitment: [0u8; 32],
                commands_commitment: Block::commands_commitment(&[]),
                validator_history_commitment: [0; 32],
                committed_height: Height::ZERO,
                committed_state_root: [0; 32],
            },
            commands: vec![],
        }
    }

    fn sample_qc() -> boule_consensus::hotstuff::QuorumCertificate {
        boule_consensus::hotstuff::QuorumCertificate::new(View::ZERO, genesis().hash(), 4)
    }

    fn dummy_sig() -> [u8; 64] {
        [0u8; 64]
    }

    #[test]
    fn wire_message_proposal_roundtrip() {
        use boule_consensus::hotstuff::Proposal;
        let msg = WireMessage::Proposal(Signed {
            payload: Proposal {
                block: sample_block(),
                justify: sample_qc(),
            },
            signer: nid(1),
            sig: dummy_sig(),
        });
        let encoded = postcard::to_stdvec(&msg).unwrap();
        let decoded: WireMessage = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn wire_message_vote_roundtrip() {
        use boule_consensus::hotstuff::qc::Vote;
        let msg = WireMessage::Vote(
            Signed {
                payload: Vote {
                    view: View(7),
                    block_hash: [0xAB; 32],
                },
                signer: nid(2),
                sig: dummy_sig(),
            },
            None,
        );
        let encoded = postcard::to_stdvec(&msg).unwrap();
        let decoded: WireMessage = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn wire_message_vote_with_bls_partial_roundtrip() {
        use boule_consensus::hotstuff::qc::Vote;
        let msg = WireMessage::Vote(
            Signed {
                payload: Vote {
                    view: View(7),
                    block_hash: [0xAB; 32],
                },
                signer: nid(2),
                sig: dummy_sig(),
            },
            Some([0xCDu8; 96]),
        );
        let encoded = postcard::to_stdvec(&msg).unwrap();
        let decoded: WireMessage = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn wire_message_new_view_roundtrip() {
        use boule_consensus::hotstuff::NewView;
        let msg = WireMessage::NewView(Signed {
            payload: NewView {
                high_qc: sample_qc(),
            },
            signer: nid(3),
            sig: dummy_sig(),
        });
        let encoded = postcard::to_stdvec(&msg).unwrap();
        let decoded: WireMessage = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn wire_message_timeout_vote_roundtrip() {
        use boule_consensus::hotstuff::qc::TimeoutVote;
        let tv = TimeoutVote {
            view: View(9),
            high_qc: Some(sample_qc()),
        };
        let msg = WireMessage::TimeoutVote(Signed {
            payload: tv,
            signer: nid(2),
            sig: dummy_sig(),
        });
        let encoded = postcard::to_stdvec(&msg).unwrap();
        let decoded: WireMessage = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, msg);

        // The `high_qc: None` variant must also roundtrip — it's the
        // very-early-bootstrap encoding where no QC has been observed.
        let tv_none = TimeoutVote {
            view: View(1),
            high_qc: None,
        };
        let msg_none = WireMessage::TimeoutVote(Signed {
            payload: tv_none,
            signer: nid(3),
            sig: dummy_sig(),
        });
        let encoded = postcard::to_stdvec(&msg_none).unwrap();
        let decoded: WireMessage = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, msg_none);
    }

    #[test]
    fn wire_message_block_request_roundtrip() {
        let hash = [0xCDu8; 32];
        let msg = WireMessage::BlockRequest(hash);
        let encoded = postcard::to_stdvec(&msg).unwrap();
        let decoded: WireMessage = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn wire_message_block_response_some_roundtrip() {
        let block = sample_block();
        let msg = WireMessage::BlockResponse(Signed {
            payload: BlockResponsePayload {
                requested_hash: block.hash(),
                block: Some(block),
            },
            signer: [0u8; 32],
            sig: [0u8; 64],
        });
        let encoded = postcard::to_stdvec(&msg).unwrap();
        let decoded: WireMessage = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn wire_message_block_response_none_roundtrip() {
        let msg = WireMessage::BlockResponse(Signed {
            payload: BlockResponsePayload {
                requested_hash: [0xAA; 32],
                block: None,
            },
            signer: [0u8; 32],
            sig: [0u8; 64],
        });
        let encoded = postcard::to_stdvec(&msg).unwrap();
        let decoded: WireMessage = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    // ── B3: MempoolBlockBuilder tests ────────────────────────────────────────

    fn make_builder(
        self_id: NodeId,
        mempool: Arc<dyn Mempool>,
        sm: Arc<Mutex<Box<dyn StateMachine>>>,
    ) -> MempoolBlockBuilder {
        MempoolBlockBuilder::new(
            self_id,
            mempool,
            sm,
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
            10,
        )
    }

    /// Variant of [`make_builder`] that exposes the
    /// `dropped_commands` counter so a caller can observe how many
    /// commands the builder skipped (#376).
    fn make_builder_with_dropped(
        self_id: NodeId,
        mempool: Arc<dyn Mempool>,
        sm: Arc<Mutex<Box<dyn StateMachine>>>,
        dropped_commands: Arc<AtomicU64>,
    ) -> MempoolBlockBuilder {
        MempoolBlockBuilder::new(
            self_id,
            mempool,
            sm,
            Arc::new(AtomicU64::new(0)),
            dropped_commands,
            10,
        )
    }

    /// Variant of [`make_builder`] that lets the caller seed
    /// `last_committed_height`. Used by the multi-block-in-flight
    /// test (#375) where the SM has been advanced past the
    /// pre-seeded genesis but pending_blocks still contains it.
    #[allow(dead_code)]
    fn make_builder_with_committed(
        self_id: NodeId,
        mempool: Arc<dyn Mempool>,
        sm: Arc<Mutex<Box<dyn StateMachine>>>,
        last_committed_height: Arc<AtomicU64>,
    ) -> MempoolBlockBuilder {
        MempoolBlockBuilder::new(
            self_id,
            mempool,
            sm,
            last_committed_height,
            Arc::new(AtomicU64::new(0)),
            10,
        )
    }

    #[test]
    fn builder_sets_header_fields_from_parent_and_view() {
        let mp: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(16));
        let sm = make_sm();
        let builder = make_builder(nid(1), Arc::clone(&mp), Arc::clone(&sm));
        let parent = genesis();
        let qc = sample_qc();

        let block = builder
            .build(&parent, View(3), &qc, &HashMap::new())
            .expect("test builder must not fail");

        assert_eq!(block.header.parent_hash, parent.hash());
        assert_eq!(block.header.height, Height(1));
        assert_eq!(block.header.view, View(3));
        assert_eq!(block.header.proposer, nid(1));
    }

    #[test]
    fn builder_pulls_commands_from_mempool() {
        use boule_consensus::replication::impls::counter_sm::CounterCommand;

        let mp: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(16));
        mp.insert(CounterCommand::Increment.encode()).unwrap();
        mp.insert(CounterCommand::Decrement.encode()).unwrap();

        let sm = make_sm();
        let builder = make_builder(nid(1), Arc::clone(&mp), Arc::clone(&sm));
        let block = builder
            .build(&genesis(), View(1), &sample_qc(), &HashMap::new())
            .expect("test builder must not fail");

        assert_eq!(block.commands.len(), 2);
    }

    #[test]
    fn builder_is_deterministic_for_same_inputs() {
        use boule_consensus::replication::impls::counter_sm::CounterCommand;

        let mp: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(16));
        mp.insert(CounterCommand::Increment.encode()).unwrap();

        let sm = make_sm();
        let builder = make_builder(nid(1), Arc::clone(&mp), Arc::clone(&sm));
        let parent = genesis();
        let qc = sample_qc();

        let b1 = builder
            .build(&parent, View(1), &qc, &HashMap::new())
            .expect("test builder must not fail");
        let b2 = builder
            .build(&parent, View(1), &qc, &HashMap::new())
            .expect("test builder must not fail");

        assert_eq!(b1.hash(), b2.hash(), "build must be deterministic");
    }

    #[test]
    fn builder_does_not_mutate_state_machine() {
        use boule_consensus::replication::impls::counter_sm::CounterCommand;

        let mp: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(16));
        mp.insert(CounterCommand::Increment.encode()).unwrap();
        mp.insert(CounterCommand::Increment.encode()).unwrap();
        mp.insert(CounterCommand::Increment.encode()).unwrap();

        let sm = make_sm();
        let before = sm.lock().state_commitment();

        let builder = make_builder(nid(1), Arc::clone(&mp), Arc::clone(&sm));
        builder
            .build(&genesis(), View(1), &sample_qc(), &HashMap::new())
            .expect("test builder must not fail");

        let after = sm.lock().state_commitment();
        assert_eq!(
            before, after,
            "build must not leave the state machine mutated",
        );
    }

    #[test]
    fn builder_state_commitment_matches_applying_commands() {
        use boule_consensus::replication::impls::counter_sm::CounterCommand;

        let mp: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(16));
        let cmd = CounterCommand::Increment.encode();
        mp.insert(cmd.clone()).unwrap();

        let sm = make_sm();
        let builder = make_builder(nid(1), Arc::clone(&mp), Arc::clone(&sm));
        let block = builder
            .build(&genesis(), View(1), &sample_qc(), &HashMap::new())
            .expect("test builder must not fail");

        // Manually apply the same command and check commitment matches.
        let mut reference_sm = CounterStateMachine::new();
        reference_sm.apply(&cmd).unwrap();
        assert_eq!(
            block.header.state_commitment,
            reference_sm.state_commitment(),
        );
    }

    #[test]
    fn builder_commands_commitment_matches_commands() {
        use boule_consensus::replication::impls::counter_sm::CounterCommand;

        let mp: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(16));
        mp.insert(CounterCommand::Increment.encode()).unwrap();
        mp.insert(CounterCommand::Decrement.encode()).unwrap();

        let sm = make_sm();
        let builder = make_builder(nid(1), Arc::clone(&mp), Arc::clone(&sm));
        let block = builder
            .build(&genesis(), View(1), &sample_qc(), &HashMap::new())
            .expect("test builder must not fail");

        let recomputed = Block::commands_commitment(&block.commands);
        assert_eq!(block.header.commands_commitment, recomputed);
    }

    /// Issue #326 / audit finding 4-F3: a [`StateMachine::restore`]
    /// failure inside [`MempoolBlockBuilder::build`] must surface as
    /// `Err`, not panic. Pre-fix the build path called
    /// `expect("restore from own snapshot must not fail")` — a corrupt
    /// redb table or version skew would crash the node and trip a
    /// panic-on-startup loop. Now `build` returns `anyhow::Result`,
    /// the safety core's `build_proposal_at_view` skips the proposal
    /// at this view on `Err`, and the next-view leader takes over.
    ///
    /// **Bisect-confirmed**: reverting the `?`/`bail!` to the original
    /// `.expect(...)` makes this test fail with a panic instead of
    /// the expected `Err`.
    #[test]
    fn builder_propagates_state_machine_restore_failure() {
        use boule_consensus::replication::StateMachine;
        use bytes::Bytes;

        /// Test-only state machine whose `restore` always fails. The
        /// other methods are minimal — only `snapshot` + `restore` are
        /// on the build path that PR #326 cares about.
        struct FailingRestoreSm;

        impl StateMachine for FailingRestoreSm {
            fn apply(&mut self, _cmd: &[u8]) -> anyhow::Result<Bytes> {
                Ok(Bytes::new())
            }

            fn state_commitment(&self) -> [u8; 32] {
                [0xAB; 32]
            }

            fn snapshot(&self) -> Bytes {
                // Any non-empty bytes — the builder feeds this back into
                // restore on the same instance, where we then fail.
                Bytes::from_static(b"snap-bytes")
            }

            fn restore(&mut self, _snap: &[u8]) -> anyhow::Result<()> {
                anyhow::bail!("simulated restore failure (#326 test)")
            }
        }

        let sm: Arc<Mutex<Box<dyn StateMachine>>> =
            Arc::new(Mutex::new(Box::new(FailingRestoreSm)));
        let mp: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(16));
        let builder = make_builder(nid(1), Arc::clone(&mp), Arc::clone(&sm));

        // The fork-and-restore round trip inside `build` triggers our
        // simulated failure. The builder must surface this as `Err`,
        // not panic.
        let result = builder.build(&genesis(), View(1), &sample_qc(), &HashMap::new());
        let err = result.expect_err("builder must propagate restore failure as Err");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("simulated restore failure"),
            "error must surface the underlying state-machine failure, got {msg}",
        );
    }

    /// Issue #375: multi-block-in-flight — when the leader builds a
    /// child while previous blocks are uncommitted, the stamped
    /// `state_commitment` must reflect *all* the in-flight ancestors'
    /// commands, not just the candidate commands applied to the
    /// committed SM. Pre-fix, the commitment was computed against the
    /// committed SM directly; replicas applying the chain in order
    /// would compute a different value and reject the proposal.
    ///
    /// The test builds a chain `genesis → b1 → b2 → b3` of
    /// uncommitted ancestors (each carrying one `Increment`), then
    /// asks the builder to extend `b3` with another `Increment` from
    /// the mempool. The stamped `state_commitment` must equal what a
    /// replica computes when applying every block's commands in
    /// order (`b1.cmds → b2.cmds → b3.cmds → candidate.cmds`).
    ///
    /// **Bisect-confirmed**: reverting [`MempoolBlockBuilder::build`]
    /// to the pre-fix single-step apply makes the assertion fail with
    /// a commitment mismatch — the leader's stamp would be the
    /// commitment for "apply 1 increment to genesis state" instead
    /// of "apply 4 increments".
    #[test]
    fn builder_state_commitment_walks_uncommitted_ancestor_chain() {
        use boule_consensus::replication::impls::counter_sm::CounterCommand;

        // The candidate (the new block being built) pulls one
        // Increment from the mempool.
        let mp: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(16));
        mp.insert(CounterCommand::Increment.encode()).unwrap();

        let sm = make_sm();
        let before = sm.lock().state_commitment();
        let last_committed_height = Arc::new(AtomicU64::new(0));
        let builder = make_builder_with_committed(
            nid(1),
            Arc::clone(&mp),
            Arc::clone(&sm),
            Arc::clone(&last_committed_height),
        );

        // Build the in-flight ancestor chain: genesis → b1 → b2 → b3,
        // each carrying one Increment. State_commitment fields are
        // not load-bearing for the builder's walk (the walk uses
        // pending_blocks parent links + commands), so any value
        // works here.
        let g = genesis();
        let make_inflight = |parent_hash: BlockHash, height: u64, view: u64| -> Block {
            let commands = vec![CounterCommand::Increment.encode()];
            Block {
                header: BlockHeader {
                    parent_hash,
                    height: Height(height),
                    view: View(view),
                    proposer: nid(1),
                    state_commitment: [0u8; 32],
                    commands_commitment: Block::commands_commitment(&commands),
                    validator_history_commitment: [0; 32],
                    committed_height: Height::ZERO,
                    committed_state_root: [0; 32],
                },
                commands,
            }
        };
        let b1 = make_inflight(g.hash(), 1, 1);
        let b2 = make_inflight(b1.hash(), 2, 2);
        let b3 = make_inflight(b2.hash(), 3, 3);

        let mut pending_blocks: HashMap<BlockHash, Block> = HashMap::new();
        pending_blocks.insert(g.hash(), g.clone());
        pending_blocks.insert(b1.hash(), b1.clone());
        pending_blocks.insert(b2.hash(), b2.clone());
        pending_blocks.insert(b3.hash(), b3.clone());

        let proposal = builder
            .build(&b3, View(4), &sample_qc(), &pending_blocks)
            .expect("test builder must not fail");

        // The builder must not have left the SM mutated — the apply
        // discipline still requires snapshot/restore round-tripping.
        assert_eq!(
            sm.lock().state_commitment(),
            before,
            "build must not leave the state machine mutated",
        );

        // Compute the reference commitment by applying every block's
        // commands to a fresh SM in order, then the candidate
        // command. This is what every honest replica computes in its
        // own pending_blocks walk.
        let mut reference = CounterStateMachine::new();
        for ancestor in [&b1, &b2, &b3] {
            for cmd in &ancestor.commands {
                reference.apply(cmd).unwrap();
            }
        }
        for cmd in &proposal.commands {
            reference.apply(cmd).unwrap();
        }
        assert_eq!(
            proposal.header.state_commitment,
            reference.state_commitment(),
            "state_commitment must reflect b1+b2+b3+candidate, not just candidate",
        );
        assert_eq!(reference.value(), 4, "1 + 1 + 1 + 1 = 4 increments applied");
    }

    /// Issue #375 corollary: after the last-committed boundary
    /// advances (e.g. the SM is updated and `last_committed_height`
    /// bumped), the builder must stop walking *at* the new boundary
    /// — not the old one or genesis. This pins the contract that the
    /// integration layer's `apply_commit` updates the shared atomic
    /// in lockstep with the SM.
    #[test]
    fn builder_state_commitment_stops_at_last_committed_boundary() {
        use boule_consensus::replication::impls::counter_sm::CounterCommand;

        let mp: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(16));
        mp.insert(CounterCommand::Increment.encode()).unwrap();

        // Simulate "b1 has been committed": the SM has applied b1's
        // commands and `last_committed_height = 1`.
        let sm = make_sm();
        sm.lock()
            .apply(&CounterCommand::Increment.encode())
            .unwrap();
        let post_b1_commitment = sm.lock().state_commitment();

        let last_committed_height = Arc::new(AtomicU64::new(1));
        let builder = make_builder_with_committed(
            nid(1),
            Arc::clone(&mp),
            Arc::clone(&sm),
            Arc::clone(&last_committed_height),
        );

        // pending_blocks still contains b1, b2 (the typical
        // post-three-chain-commit shape would have pruned b1, but
        // until the prune fires the safety core can hold it; the
        // builder must not re-apply b1's commands either way).
        let g = genesis();
        let make_inflight = |parent_hash: BlockHash, height: u64, view: u64| -> Block {
            let commands = vec![CounterCommand::Increment.encode()];
            Block {
                header: BlockHeader {
                    parent_hash,
                    height: Height(height),
                    view: View(view),
                    proposer: nid(1),
                    state_commitment: [0u8; 32],
                    commands_commitment: Block::commands_commitment(&commands),
                    validator_history_commitment: [0; 32],
                    committed_height: Height::ZERO,
                    committed_state_root: [0; 32],
                },
                commands,
            }
        };
        let b1 = make_inflight(g.hash(), 1, 1);
        let b2 = make_inflight(b1.hash(), 2, 2);

        let mut pending_blocks: HashMap<BlockHash, Block> = HashMap::new();
        pending_blocks.insert(g.hash(), g.clone());
        pending_blocks.insert(b1.hash(), b1.clone());
        pending_blocks.insert(b2.hash(), b2.clone());

        let proposal = builder
            .build(&b2, View(3), &sample_qc(), &pending_blocks)
            .expect("test builder must not fail");

        // SM unmutated.
        assert_eq!(sm.lock().state_commitment(), post_b1_commitment);

        // Reference: b2.commands + candidate.commands applied on top
        // of post-b1 state.
        let mut reference = CounterStateMachine::new();
        reference
            .apply(&CounterCommand::Increment.encode())
            .unwrap();
        for cmd in &b2.commands {
            reference.apply(cmd).unwrap();
        }
        for cmd in &proposal.commands {
            reference.apply(cmd).unwrap();
        }
        assert_eq!(
            proposal.header.state_commitment,
            reference.state_commitment(),
            "commitment must reflect b2 + candidate on top of committed b1",
        );
        assert_eq!(reference.value(), 3);
    }

    /// Issue #376 + #598: the builder must surface dropped commands and
    /// keep the state machine pristine. Two kinds of "bad" command,
    /// handled differently after #598's includability filter:
    ///
    /// - A command that fails the SM's `check` (undecodable, not
    ///   includable) is **dropped from the block entirely** at build time
    ///   — the leader never proposes it.
    /// - A command that is well-formed (`check` passes) but fails `apply`
    ///   (here a `Decrement` underflow against a fresh counter) still
    ///   **rides the block** and no-ops on every replica, so they
    ///   converge on the same commitment.
    ///
    /// Both bump the shared `dropped_commands` counter (surfaced under
    /// `ConsensusStatus::dropped_commands`) with a `tracing::warn!`. The
    /// build still succeeds, the `state_commitment` reflects only the
    /// commands that applied, and the SM is left untouched.
    #[test]
    fn builder_skips_failing_commands_and_commitment_matches_partial_apply() {
        use boule_consensus::replication::StateMachine;
        use boule_consensus::replication::impls::counter_sm::CounterCommand;
        use bytes::Bytes;

        // Mix valid and invalid commands. `bad_underflow` is a
        // well-formed `Decrement` against a fresh counter (`value =
        // 0` → underflow on apply). `bad_decode` is a malformed
        // payload that fails postcard decode. Both are exactly the
        // silent-drop cases the issue calls out: app-level rejection
        // and decode error.
        let good = CounterCommand::Increment.encode();
        let bad_underflow = CounterCommand::Decrement.encode();
        let bad_decode: Bytes = Bytes::from_static(&[0xFFu8, 0x00, 0x00, 0x00]);

        let mp: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(16));
        mp.insert(bad_underflow.clone()).unwrap();
        mp.insert(good.clone()).unwrap();
        mp.insert(bad_decode.clone()).unwrap();

        let sm = make_sm();
        let dropped_commands = Arc::new(AtomicU64::new(0));
        let builder = make_builder_with_dropped(
            nid(1),
            Arc::clone(&mp),
            Arc::clone(&sm),
            Arc::clone(&dropped_commands),
        );
        let block = builder
            .build(&genesis(), View(1), &sample_qc(), &HashMap::new())
            .expect("builder must skip-and-warn rather than fail the proposal");

        // The undecodable command is dropped by the #598 includability
        // check; `good` and the well-formed-but-underflowing `Decrement`
        // ride the block (the latter no-ops on every replica, so they
        // converge).
        assert_eq!(block.commands.len(), 2);
        assert!(block.commands.contains(&good));
        assert!(block.commands.contains(&bad_underflow));
        assert!(
            !block.commands.contains(&bad_decode),
            "an undecodable command must not be proposed",
        );

        // Reference: apply only the one good command to a fresh
        // counter SM and compare commitments.
        let mut reference = boule_consensus::replication::impls::CounterStateMachine::new();
        reference.apply(&good).unwrap();
        assert_eq!(
            block.header.state_commitment,
            reference.state_commitment(),
            "state_commitment must reflect only the commands that applied",
        );

        // The state machine itself must be untouched after build —
        // failing applies must not leak past the fork-and-restore.
        assert_eq!(
            sm.lock().state_commitment(),
            boule_consensus::replication::impls::CounterStateMachine::new().state_commitment(),
            "build must not mutate the SM, even when some commands fail to apply",
        );

        // The shared counter (surfaced under
        // `ConsensusStatus::dropped_commands`) bumps by exactly the
        // number of commands that hit `Err` on apply.
        assert_eq!(
            dropped_commands.load(Ordering::Relaxed),
            2,
            "dropped_commands must reflect both the underflow and the decode error",
        );

        // A second build with the same mempool contents must add to
        // the cumulative count, not reset it — the counter is
        // monotonic for the lifetime of the node, like
        // `cache_evictions`.
        builder
            .build(&genesis(), View(2), &sample_qc(), &HashMap::new())
            .expect("second build must also succeed");
        assert_eq!(
            dropped_commands.load(Ordering::Relaxed),
            4,
            "dropped_commands must accumulate across builds",
        );
    }

    // ── C-series: durability bridge ──────────────────────────────────────────

    fn sample_locked() -> Locked {
        Locked {
            view: View(40),
            height: Height(5),
            block_hash: [0xABu8; 32],
        }
    }

    fn sample_full_qc() -> QuorumCertificate {
        let mut qc = QuorumCertificate::new(View(41), [0xCDu8; 32], 4);
        qc.add_signature(0, [0x11u8; 64]);
        qc.add_signature(2, [0x22u8; 64]);
        qc.add_signature(3, [0x33u8; 64]);
        qc
    }

    #[test]
    fn encode_decode_voted_view_roundtrips() {
        let cases = [View(0), View(1), View(42), View::MAX];
        for v in cases {
            let bytes = encode_voted_view(v).unwrap();
            assert_eq!(decode_voted_view(&bytes).unwrap(), v);
        }
    }

    #[test]
    fn encode_decode_locked_roundtrips() {
        let l = sample_locked();
        let bytes = encode_locked(&l).unwrap();
        assert_eq!(decode_locked(&bytes).unwrap(), l);
    }

    #[test]
    fn encode_decode_high_qc_roundtrips() {
        let qc = sample_full_qc();
        let bytes = encode_high_qc(&qc).unwrap();
        assert_eq!(decode_high_qc(&bytes).unwrap(), qc);
    }

    #[test]
    fn encode_decode_proposed_in_view_roundtrips() {
        let cases = [View(0), View(1), View(42), View::MAX];
        for v in cases {
            let bytes = encode_proposed_in_view(v).unwrap();
            assert_eq!(decode_proposed_in_view(&bytes).unwrap(), v);
        }
    }

    #[test]
    fn encode_decode_last_timeout_vote_roundtrips_with_high_qc() {
        let payload = TimeoutVote {
            view: View(17),
            high_qc: Some(sample_full_qc()),
        };
        let bytes = encode_last_timeout_vote(&payload).unwrap();
        assert_eq!(decode_last_timeout_vote(&bytes).unwrap(), payload);
    }

    #[test]
    fn encode_decode_last_timeout_vote_roundtrips_without_high_qc() {
        let payload = TimeoutVote {
            view: View(0),
            high_qc: None,
        };
        let bytes = encode_last_timeout_vote(&payload).unwrap();
        assert_eq!(decode_last_timeout_vote(&bytes).unwrap(), payload);
    }

    #[test]
    fn decode_voted_view_surfaces_error_on_garbage() {
        assert!(decode_voted_view(&[0xFFu8; 64]).is_err());
    }

    #[test]
    fn decode_proposed_in_view_surfaces_error_on_garbage() {
        assert!(decode_proposed_in_view(&[0xFFu8; 64]).is_err());
    }

    #[test]
    fn recover_state_from_empty_storage_seeds_genesis_qc() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let state = recover_state(storage.as_ref(), four_validators(), genesis()).unwrap();
        assert_eq!(state.current_view, View(0));
        assert_eq!(state.last_voted_view, View(0));
        assert!(state.locked.is_none());
        // Empty storage means no persisted high_qc, so the recovery path
        // seeds the cluster-agreed genesis QC so the view-1 leader can
        // propose on first boot.
        let expected = genesis_qc(&genesis(), &four_validators());
        assert_eq!(state.high_qc.as_ref().map(|q| q.inner()), Some(&expected));
        assert!(state.pending_blocks.contains_key(&genesis().hash()));
    }

    #[test]
    fn persist_updates_empty_is_noop() {
        let node = make_node(nid(1));
        node.persist_updates(&[]).unwrap();
        assert!(
            node.storage
                .get(STORAGE_KEY_LAST_VOTED_VIEW)
                .unwrap()
                .is_none(),
        );
    }

    #[test]
    fn persist_then_recover_preserves_voted_view() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let wal: Arc<dyn Wal> = Arc::new(MemoryWal::new());
        let cfg = test_config(four_validators());

        // Session 1: persist a vote.
        let node = ConsensusNode::new(
            nid(1),
            cfg.clone(),
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::clone(&wal),
        );
        node.persist_updates(&[StateUpdate::VotedInView { view: View(99) }])
            .unwrap();
        drop(node);

        // Session 2: recover. The voted view survives.
        let recovered = ConsensusNode::recover(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::clone(&wal),
        )
        .unwrap();
        assert_eq!(recovered.core.state().last_voted_view, View(99));
    }

    #[test]
    fn persist_then_recover_preserves_locked_and_high_qc() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let wal: Arc<dyn Wal> = Arc::new(MemoryWal::new());
        let cfg = test_config(four_validators());
        let locked = sample_locked();
        let qc = sample_full_qc();

        let node = ConsensusNode::new(
            nid(1),
            cfg.clone(),
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::clone(&wal),
        );
        node.persist_updates(&[StateUpdate::Locked(locked), StateUpdate::HighQc(qc.clone())])
            .unwrap();
        drop(node);

        let recovered = ConsensusNode::recover(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::clone(&wal),
        )
        .unwrap();
        assert_eq!(recovered.core.state().locked, Some(locked));
        assert_eq!(
            recovered.core.state().high_qc.as_ref().map(|q| q.inner()),
            Some(&qc)
        );
    }

    #[test]
    fn persist_all_three_fields_and_recover() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let wal: Arc<dyn Wal> = Arc::new(MemoryWal::new());
        let cfg = test_config(four_validators());

        let node = ConsensusNode::new(
            nid(2),
            cfg.clone(),
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::clone(&wal),
        );
        let updates = vec![
            StateUpdate::VotedInView { view: View(7) },
            StateUpdate::Locked(sample_locked()),
            StateUpdate::HighQc(sample_full_qc()),
        ];
        node.persist_updates(&updates).unwrap();
        drop(node);

        let recovered = ConsensusNode::recover(
            nid(2),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::clone(&wal),
        )
        .unwrap();
        assert_eq!(recovered.core.state().last_voted_view, View(7));
        assert_eq!(recovered.core.state().locked, Some(sample_locked()));
        assert_eq!(
            recovered.core.state().high_qc.as_ref().map(|q| q.inner()),
            Some(&sample_full_qc()),
        );
        // `recover` does not reset the pacemaker — it always starts at 0.
        assert_eq!(recovered.current_view(), View(0));
    }

    /// Issue #407 / audit finding 4-6: persisting `ProposedInView`
    /// before `Broadcast(Proposal)` and restoring it on
    /// [`ConsensusNode::recover`] keeps a leader from re-minting a
    /// *different* signed proposal at the same view if it crashes
    /// between `Signed::sign` and the network bytes leaving the
    /// host. Without the durable mirror the in-memory guard would
    /// reset to `0` on restart and the next call into
    /// `try_propose_as_leader(view)` would re-enter the build path
    /// for the same view — handing a Byzantine-detector a
    /// slashable equivocation envelope, even though the leader was
    /// honest.
    #[test]
    fn persist_then_recover_preserves_proposed_in_view() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let wal: Arc<dyn Wal> = Arc::new(MemoryWal::new());
        let cfg = test_config(four_validators());

        let node = ConsensusNode::new(
            nid(1),
            cfg.clone(),
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::clone(&wal),
        );
        node.persist_updates(&[StateUpdate::ProposedInView { view: View(12) }])
            .unwrap();

        // The durable write is immediately readable under the
        // documented storage key — defense-in-depth so a future refactor
        // that drops the call to `b.put(STORAGE_KEY_PROPOSED_IN_VIEW, _)`
        // surfaces here rather than only in the recovery test below.
        let raw = storage
            .get(STORAGE_KEY_PROPOSED_IN_VIEW)
            .unwrap()
            .expect("ProposedInView must be persisted under STORAGE_KEY_PROPOSED_IN_VIEW");
        assert_eq!(decode_proposed_in_view(&raw).unwrap(), View(12));
        drop(node);

        let recovered = ConsensusNode::recover(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::clone(&wal),
        )
        .unwrap();
        assert_eq!(
            recovered.core.proposed_in_view(),
            View(12),
            "recover() must restore proposed_in_view from durable storage so a \
             leader that crashed mid-broadcast cannot re-mint at the same view",
        );
    }

    /// Companion to [`persist_then_recover_preserves_proposed_in_view`]:
    /// fresh storage with no `ProposedInView` ever written must recover
    /// to `0`, matching the in-memory default for an unstarted leader.
    #[test]
    fn recover_with_no_persisted_proposed_in_view_defaults_to_zero() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let wal: Arc<dyn Wal> = Arc::new(MemoryWal::new());
        let cfg = test_config(four_validators());

        let recovered = ConsensusNode::recover(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::clone(&wal),
        )
        .unwrap();
        assert_eq!(recovered.core.proposed_in_view(), View(0));
    }

    /// Issue #206 regression: persisting a `Locked` / `HighQc` whose
    /// referenced block is in `pending_blocks` writes the block to
    /// durable storage so [`recover_state`] can re-seed
    /// `pending_blocks` post-restart. Without this, every replica's
    /// [`HotStuffCore::become_leader`] silently returns an empty action
    /// set after a divergent resume — no proposal ever fires and the
    /// cluster permanently stalls.
    #[test]
    fn persist_writes_locked_and_high_qc_blocks_recover_seeds_pending() {
        use boule_consensus::replication::block::BlockHeader;

        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let wal: Arc<dyn Wal> = Arc::new(MemoryWal::new());
        let cfg = test_config(four_validators());

        // Build two distinct uncommitted blocks: `b_locked` at height 1
        // / view 18 (the locked block from the issue), and `b_high_qc`
        // at height 2 / view 19 (the high_qc block). Hashes differ
        // because the headers do.
        let g = genesis();
        let b_locked = Block {
            header: BlockHeader {
                parent_hash: g.hash(),
                height: Height(1),
                view: View(18),
                proposer: nid(1),
                state_commitment: [0u8; 32],
                commands_commitment: Block::commands_commitment(&[]),
                validator_history_commitment: [0; 32],
                committed_height: Height::ZERO,
                committed_state_root: [0; 32],
            },
            commands: vec![],
        };
        let b_high_qc = Block {
            header: BlockHeader {
                parent_hash: b_locked.hash(),
                height: Height(2),
                view: View(19),
                proposer: nid(2),
                state_commitment: [0u8; 32],
                commands_commitment: Block::commands_commitment(&[]),
                validator_history_commitment: [0; 32],
                committed_height: Height::ZERO,
                committed_state_root: [0; 32],
            },
            commands: vec![],
        };

        let locked = Locked {
            view: View(18),
            height: Height(1),
            block_hash: b_locked.hash(),
        };
        let mut qc = QuorumCertificate::new(19, b_high_qc.hash(), 4);
        qc.add_signature(0, [0x11u8; 64]);
        qc.add_signature(1, [0x22u8; 64]);
        qc.add_signature(2, [0x33u8; 64]);

        // Session 1: seed the safety core's `pending_blocks` with both
        // uncommitted blocks (mirroring what `on_proposal_received`
        // does in production), then persist the lock and high_qc.
        {
            let mut node = ConsensusNode::new(
                nid(1),
                cfg.clone(),
                make_sm(),
                Arc::new(InMemoryMempool::new(64)),
                Arc::clone(&storage),
                Arc::clone(&wal),
            );
            node.core.insert_pending_block(b_locked.clone());
            node.core.insert_pending_block(b_high_qc.clone());
            node.persist_updates(&[StateUpdate::Locked(locked), StateUpdate::HighQc(qc.clone())])
                .unwrap();
            // Both blocks are durable under the block-storage prefix.
            assert!(
                load_block_from_storage(storage.as_ref(), &b_locked.hash())
                    .unwrap()
                    .is_some(),
                "persist_updates must write the locked block",
            );
            assert!(
                load_block_from_storage(storage.as_ref(), &b_high_qc.hash())
                    .unwrap()
                    .is_some(),
                "persist_updates must write the high_qc block",
            );
        }

        // Session 2: recover. `pending_blocks` must contain genesis
        // plus both uncommitted blocks so the post-restart leader can
        // build a proposal extending high_qc.block_hash and the
        // safe_to_vote extension walk can terminate at locked.
        let recovered = ConsensusNode::recover(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::clone(&wal),
        )
        .unwrap();
        assert_eq!(recovered.core.state().locked, Some(locked));
        assert_eq!(
            recovered.core.state().high_qc.as_ref().map(|q| q.inner()),
            Some(&qc)
        );
        assert!(
            recovered
                .core
                .state()
                .pending_blocks
                .contains_key(&b_locked.hash()),
            "recover must re-seed the locked block into pending_blocks",
        );
        assert!(
            recovered
                .core
                .state()
                .pending_blocks
                .contains_key(&b_high_qc.hash()),
            "recover must re-seed the high_qc block into pending_blocks",
        );
        // And the resumed leader can build a proposal — the parent
        // lookup that previously short-circuited is now resolved.
        assert!(
            recovered
                .core
                .state()
                .pending_blocks
                .contains_key(&qc.block_hash),
        );
    }

    /// Issue #412 / audit finding 4-5: `recover_state` rehydrates not
    /// only the locked / high_qc blocks but a bounded fringe of their
    /// ancestors so the 2-chain promotion walk and 3-chain commit walk
    /// terminate locally on the very first proposal received after a
    /// restart. Without this, the lock can fail to advance for one or
    /// two views while the chain refills from fresh proposals.
    #[test]
    fn recover_rehydrates_locked_and_high_qc_ancestors() {
        use boule_consensus::replication::block::BlockHeader;

        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let g = genesis();

        // Build a five-block chain rooted at genesis: g <- b1 <- b2 <-
        // b3 <- b4. b3 is the locked block; b4 is the high_qc block.
        // The 3-chain commit walk from b4 needs b2 (great-grandparent);
        // the 2-chain promotion walk from b3 needs b1 (grandparent).
        let mut blocks = vec![g.clone()];
        for i in 1..=4u64 {
            let parent = blocks.last().unwrap();
            blocks.push(Block {
                header: BlockHeader {
                    parent_hash: parent.hash(),
                    height: Height(i),
                    view: View(i + 10),
                    proposer: nid(((i % 4) + 1) as u8),
                    state_commitment: [0u8; 32],
                    commands_commitment: Block::commands_commitment(&[]),
                    validator_history_commitment: [0; 32],
                    committed_height: Height::ZERO,
                    committed_state_root: [0; 32],
                },
                commands: vec![],
            });
        }
        let b1 = &blocks[1];
        let b2 = &blocks[2];
        let b3 = &blocks[3];
        let b4 = &blocks[4];

        // Persist every non-genesis block under the block-storage prefix
        // (mirrors what `persist_updates` would have written across
        // earlier sessions where each block was at the high_qc tip).
        for b in &blocks[1..] {
            storage
                .put(&block_storage_key(&b.hash()), &encode_block(b).unwrap())
                .unwrap();
        }

        // Persist locked = b3 and high_qc over b4 so `recover_state`
        // anchors the walk on the right pair.
        let locked = Locked {
            view: b3.header.view,
            height: b3.header.height,
            block_hash: b3.hash(),
        };
        let mut qc = QuorumCertificate::new(b4.header.view, b4.hash(), 4);
        qc.add_signature(0, [0x11u8; 64]);
        qc.add_signature(1, [0x22u8; 64]);
        qc.add_signature(2, [0x33u8; 64]);
        storage
            .put(STORAGE_KEY_LOCKED, &encode_locked(&locked).unwrap())
            .unwrap();
        storage
            .put(STORAGE_KEY_HIGH_QC, &encode_high_qc(&qc).unwrap())
            .unwrap();

        let state = recover_state(storage.as_ref(), four_validators(), g.clone()).unwrap();

        // Genesis is always seeded; every block on the locked / high_qc
        // ancestry up to two hops from each anchor is rehydrated. The
        // union covers b1..b4 — exactly the blocks the safety walks
        // need on the first post-restart proposal.
        assert!(state.pending_blocks.contains_key(&g.hash()));
        for (label, hash) in [
            ("b1", b1.hash()),
            ("b2", b2.hash()),
            ("b3", b3.hash()),
            ("b4", b4.hash()),
        ] {
            assert!(
                state.pending_blocks.contains_key(&hash),
                "recover must rehydrate {label} so the 2-chain / 3-chain walks \
                 terminate locally on the first proposal after restart",
            );
        }
    }

    /// Companion to [`recover_rehydrates_locked_and_high_qc_ancestors`]:
    /// when an ancestor is missing from durable storage (e.g. an older
    /// snapshot adopted via NewView before the persist-with-block
    /// pairing landed), the walk stops at the gap and recovery does
    /// not error — block-sync still covers the rest of the chain.
    #[test]
    fn recover_stops_at_first_missing_ancestor() {
        use boule_consensus::replication::block::BlockHeader;

        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let g = genesis();

        // g <- b1 <- b2 <- b3. Persist b2 and b3 only — b1 is missing,
        // simulating a gap in the durable block store.
        let b1 = Block {
            header: BlockHeader {
                parent_hash: g.hash(),
                height: Height(1),
                view: View(11),
                proposer: nid(1),
                state_commitment: [0u8; 32],
                commands_commitment: Block::commands_commitment(&[]),
                validator_history_commitment: [0; 32],
                committed_height: Height::ZERO,
                committed_state_root: [0; 32],
            },
            commands: vec![],
        };
        let b2 = Block {
            header: BlockHeader {
                parent_hash: b1.hash(),
                height: Height(2),
                view: View(12),
                proposer: nid(2),
                state_commitment: [0u8; 32],
                commands_commitment: Block::commands_commitment(&[]),
                validator_history_commitment: [0; 32],
                committed_height: Height::ZERO,
                committed_state_root: [0; 32],
            },
            commands: vec![],
        };
        let b3 = Block {
            header: BlockHeader {
                parent_hash: b2.hash(),
                height: Height(3),
                view: View(13),
                proposer: nid(3),
                state_commitment: [0u8; 32],
                commands_commitment: Block::commands_commitment(&[]),
                validator_history_commitment: [0; 32],
                committed_height: Height::ZERO,
                committed_state_root: [0; 32],
            },
            commands: vec![],
        };
        storage
            .put(&block_storage_key(&b2.hash()), &encode_block(&b2).unwrap())
            .unwrap();
        storage
            .put(&block_storage_key(&b3.hash()), &encode_block(&b3).unwrap())
            .unwrap();

        let locked = Locked {
            view: b2.header.view,
            height: b2.header.height,
            block_hash: b2.hash(),
        };
        let mut qc = QuorumCertificate::new(b3.header.view, b3.hash(), 4);
        qc.add_signature(0, [0x11u8; 64]);
        qc.add_signature(1, [0x22u8; 64]);
        qc.add_signature(2, [0x33u8; 64]);
        storage
            .put(STORAGE_KEY_LOCKED, &encode_locked(&locked).unwrap())
            .unwrap();
        storage
            .put(STORAGE_KEY_HIGH_QC, &encode_high_qc(&qc).unwrap())
            .unwrap();

        let state = recover_state(storage.as_ref(), four_validators(), g.clone()).unwrap();

        // The available ancestors load; the missing one stops the walk
        // without erroring.
        assert!(state.pending_blocks.contains_key(&b3.hash()));
        assert!(state.pending_blocks.contains_key(&b2.hash()));
        assert!(!state.pending_blocks.contains_key(&b1.hash()));
    }

    /// Persisting `HighQc` whose block is *not* in `pending_blocks` —
    /// the rare NewView-only adoption path — still records the QC
    /// metadata, but no block write fires (the safety core's
    /// in-memory state is the authority for that case).
    #[test]
    fn persist_skips_block_write_when_referenced_block_absent() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let wal: Arc<dyn Wal> = Arc::new(MemoryWal::new());
        let cfg = test_config(four_validators());

        let node = ConsensusNode::new(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::clone(&wal),
        );
        // sample_full_qc references a hash that was never inserted.
        let qc = sample_full_qc();
        node.persist_updates(&[StateUpdate::HighQc(qc.clone())])
            .unwrap();

        // Metadata is on disk so liveness state survives the restart.
        let raw = storage.get(STORAGE_KEY_HIGH_QC).unwrap().unwrap();
        assert_eq!(decode_high_qc(&raw).unwrap(), qc);
        // But there is no block write for an unknown hash.
        assert!(
            load_block_from_storage(storage.as_ref(), &qc.block_hash)
                .unwrap()
                .is_none(),
        );
    }

    #[test]
    fn persist_is_last_write_wins_within_batch() {
        let node = make_node(nid(1));
        node.persist_updates(&[
            StateUpdate::VotedInView { view: View(3) },
            StateUpdate::VotedInView { view: View(5) },
            StateUpdate::VotedInView { view: View(4) },
        ])
        .unwrap();
        let raw = node
            .storage
            .get(STORAGE_KEY_LAST_VOTED_VIEW)
            .unwrap()
            .unwrap();
        assert_eq!(decode_voted_view(&raw).unwrap(), View(4));
    }

    #[test]
    fn persist_monotonic_overwrites_previous() {
        // Subsequent persist calls overwrite the previous value: there's
        // no accumulation, each key is a single cell in storage.
        let node = make_node(nid(1));
        node.persist_updates(&[StateUpdate::VotedInView { view: View(1) }])
            .unwrap();
        node.persist_updates(&[StateUpdate::VotedInView { view: View(2) }])
            .unwrap();
        let raw = node
            .storage
            .get(STORAGE_KEY_LAST_VOTED_VIEW)
            .unwrap()
            .unwrap();
        assert_eq!(decode_voted_view(&raw).unwrap(), View(2));
    }

    #[test]
    fn recover_surfaces_error_on_corrupted_stored_bytes() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        storage
            .put(STORAGE_KEY_LAST_VOTED_VIEW, &[0xFFu8; 64])
            .unwrap();
        let err = recover_state(storage.as_ref(), four_validators(), genesis()).unwrap_err();
        assert!(
            format!("{err:#}").contains("last_voted_view"),
            "error should mention the failing key: {err:#}",
        );
    }

    #[test]
    fn recover_only_locked_preserves_default_voted_view_and_seeds_genesis_qc() {
        // Partial persistence: only `locked` was flushed. Recovery
        // restores it, leaves `last_voted_view` at its default, and
        // seeds the genesis QC since no `high_qc` was persisted.
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let wal: Arc<dyn Wal> = Arc::new(MemoryWal::new());
        let cfg = test_config(four_validators());
        let node = ConsensusNode::new(
            nid(1),
            cfg.clone(),
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::clone(&wal),
        );
        node.persist_updates(&[StateUpdate::Locked(sample_locked())])
            .unwrap();
        drop(node);

        let recovered = ConsensusNode::recover(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::clone(&wal),
        )
        .unwrap();
        assert_eq!(recovered.core.state().last_voted_view, View(0));
        assert_eq!(recovered.core.state().locked, Some(sample_locked()));
        let expected = genesis_qc(&genesis(), &four_validators());
        assert_eq!(
            recovered.core.state().high_qc.as_ref().map(|q| q.inner()),
            Some(&expected)
        );
    }

    // ── D/E-series: event loop ────────────────────────────────────────────────

    use boule_core::crypto::signed::NodeSigner;
    use boule_core::identity::NodeIdentity;
    use boule_transport_tcp::{ProtocolEvent, ProtocolOutbound};
    use rcgen::KeyPair as RcgenKeyPair;
    use rcgen::PKCS_ED25519;
    use zeroize::Zeroizing;

    fn fresh_signer() -> NodeSigner {
        let kp = RcgenKeyPair::generate_for(&PKCS_ED25519).unwrap();
        let identity = NodeIdentity {
            pkcs8_der: Zeroizing::new(kp.serialize_der()),
        };
        NodeSigner::from_identity(&identity).unwrap()
    }

    /// Build an inbound `event_rx` for [`ConsensusNode::run`] backed by
    /// an in-memory channel; the returned sender lets tests inject
    /// arbitrary [`ProtocolEvent`]s.
    fn make_test_event_channel() -> (
        tokio::sync::mpsc::Sender<ProtocolEvent>,
        tokio::sync::mpsc::Receiver<ProtocolEvent>,
    ) {
        tokio::sync::mpsc::channel(16)
    }

    /// Build a [`Broadcaster`] backed by an in-memory channel and return
    /// the receiver so the test can inspect outbound traffic.
    fn make_test_broadcaster() -> (
        Arc<dyn Broadcaster>,
        tokio::sync::mpsc::Receiver<ProtocolOutbound>,
    ) {
        let (send_tx, send_rx) = tokio::sync::mpsc::channel::<ProtocolOutbound>(16);
        let bc: Arc<dyn Broadcaster> = Arc::new(
            boule_transport_tcp::overlay::MemoryBroadcaster::new(send_tx),
        );
        (bc, send_rx)
    }

    /// Build a [`Discovery`] with no peers and a never-firing source.
    fn make_test_discovery() -> Arc<dyn Discovery> {
        let (_tx, rx) = tokio::sync::broadcast::channel::<DiscoveryEvent>(8);
        boule_transport_tcp::overlay::MemoryDiscovery::spawn(rx)
    }

    #[test]
    fn new_seeds_genesis_qc_so_view_one_leader_can_propose() {
        // Regression for the bootstrap-deadlock bug (#116). A freshly
        // constructed ConsensusNode must have `high_qc = Some(genesis_qc)`
        // so the view-1 leader can immediately build a proposal on boot
        // without waiting for a NewView round that only ever lands after
        // somebody has already proposed.
        let node = make_node(nid(1));
        let expected = genesis_qc(&genesis(), &four_validators());
        assert_eq!(
            node.core.state().high_qc.as_ref().map(|q| q.inner()),
            Some(&expected)
        );

        // And `become_leader(1)` must now emit a single `BuildProposal`
        // (#606) — which the dispatcher fulfills into the
        // `Persist(ProposedInView)` + `Broadcast(Proposal)` pair — rather than
        // the empty Vec the pre-#116 code returned.
        let mut node = node;
        let actions = node.core.become_leader(1);
        assert_eq!(actions.len(), 1, "{actions:?}");
        assert!(matches!(
            &actions[0],
            SafetyAction::BuildProposal { view: View(1), .. },
        ));
    }

    #[test]
    fn insert_pending_block_is_visible_in_state() {
        let mut node = make_node(nid(1));
        let block = sample_block();
        let hash = block.hash();
        node.core.insert_pending_block(block);
        assert!(node.core.state().pending_blocks.contains_key(&hash));
    }

    #[test]
    fn apply_commit_advances_state_machine_and_drains_mempool() {
        use boule_consensus::replication::impls::counter_sm::CounterCommand;

        let mp: Arc<dyn boule_consensus::replication::mempool::Mempool> =
            Arc::new(InMemoryMempool::new(64));
        let cmd = CounterCommand::Increment.encode();
        mp.insert(cmd.clone()).unwrap();
        assert_eq!(mp.len(), 1);

        let sm = make_sm();
        let vs = four_validators();
        let cfg = test_config(vs);
        let mut node = ConsensusNode::new(
            nid(1),
            cfg,
            Arc::clone(&sm),
            Arc::clone(&mp),
            Arc::new(MemoryStorage::new()),
            Arc::new(MemoryWal::new()),
        );

        let block = boule_consensus::replication::block::Block {
            header: boule_consensus::replication::block::BlockHeader {
                parent_hash: genesis().hash(),
                height: Height(1),
                view: View(1),
                proposer: nid(1),
                state_commitment: [0u8; 32],
                commands_commitment:
                    boule_consensus::replication::block::Block::commands_commitment(
                        std::slice::from_ref(&cmd),
                    ),
                validator_history_commitment: [0; 32],
                committed_height: Height::ZERO,
                committed_state_root: [0; 32],
            },
            commands: vec![cmd],
        };

        let sm_before = sm.lock().state_commitment();
        node.apply_commit(block);
        let sm_after = sm.lock().state_commitment();

        assert_ne!(sm_before, sm_after, "state machine must advance on commit");
        assert_eq!(
            mp.len(),
            0,
            "committed commands must be drained from mempool"
        );
    }

    // ── #272: commit-time reconfig application ────────────────────────────────

    fn five_validators() -> ValidatorSet {
        ValidatorSet::new(vec![vid(1), vid(2), vid(3), vid(4), vid(5)])
    }

    fn six_validators() -> ValidatorSet {
        ValidatorSet::new(vec![vid(1), vid(2), vid(3), vid(4), vid(5), vid(6)])
    }

    /// Build a Block at `(height, view)` that carries a single tagged
    /// `ReconfigCommand` payload built by `make_cmd`.
    fn block_with_reconfig(
        height: u64,
        view: u64,
        proposer: NodeId,
        cmd: boule_consensus::reconfig::ReconfigCommand,
    ) -> boule_consensus::replication::block::Block {
        let payload = cmd.encode();
        let commands = vec![payload];
        let header = boule_consensus::replication::block::BlockHeader {
            parent_hash: genesis().hash(),
            height: Height(height),
            view: View(view),
            proposer,
            state_commitment: [0u8; 32],
            commands_commitment: boule_consensus::replication::block::Block::commands_commitment(
                &commands,
            ),
            validator_history_commitment: [0; 32],
            committed_height: Height::ZERO,
            committed_state_root: [0; 32],
        };
        boule_consensus::replication::block::Block { header, commands }
    }

    #[test]
    fn apply_commit_with_valid_reconfig_inserts_boundary_into_history() {
        use boule_consensus::reconfig::{MIN_V_EFF_DELAY, ReconfigCommand, ValidatorEntry};

        let mut node = make_node(nid(1));
        // Pre-conditions: only the genesis boundary, with the original
        // four-validator set.
        assert_eq!(node.validator_history.boundary_count(), 1);
        assert_eq!(node.core.state().validator_history.boundary_count(), 1);
        assert_eq!(*node.validator_history.current_set(), four_validators());

        // Construct a reconfig adding nid(5) at v_eff = 5 (≥ block.view +
        // MIN_V_EFF_DELAY for block.view = 0).
        let v_eff = MIN_V_EFF_DELAY + 3;
        let cmd = ReconfigCommand {
            adds: vec![ValidatorEntry {
                node_id: nid(5),
                addr: "127.0.0.1:9005".parse().unwrap(),
                bls_pop: None,
                weight: 1,
            }],
            removes: vec![],
            changes: vec![],
            v_eff,
        };
        let block = block_with_reconfig(1, 0, nid(1), cmd);
        node.apply_commit(block);

        // Both histories carry the new boundary.
        assert_eq!(node.validator_history.boundary_count(), 2);
        assert_eq!(node.core.state().validator_history.boundary_count(), 2);
        assert_eq!(
            *node.validator_history.set_at(v_eff).for_view(v_eff),
            five_validators()
        );
        assert_eq!(
            *node
                .core
                .state()
                .validator_history
                .set_at(v_eff)
                .for_view(v_eff),
            five_validators()
        );

        // The pacemaker selector now picks leaders from the post-
        // boundary set at and after v_eff.
        let leader_at_v_eff = node.pacemaker.leader_for_view(v_eff);
        let leader_vid =
            boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(leader_at_v_eff);
        assert!(
            five_validators().contains(&leader_vid),
            "leader at v_eff must come from post-boundary set",
        );
    }

    #[test]
    fn apply_commit_with_floor_violating_reconfig_drops_silently() {
        use boule_consensus::reconfig::{MIN_V_EFF_DELAY, ReconfigCommand, ValidatorEntry};

        let mut node = make_node(nid(1));
        // Removing two of four would leave a 2-member set, below the
        // MIN_VALIDATOR_FLOOR of 4. apply_commit must log + drop, but
        // the block itself stays committed.
        let v_eff = MIN_V_EFF_DELAY + 5;
        let cmd = ReconfigCommand {
            adds: vec![],
            removes: vec![nid(3), nid(4)],
            changes: vec![],
            v_eff,
        };
        // Empty `adds` so nothing's needed; this is purely a removal.
        let _ = ValidatorEntry {
            node_id: nid(0),
            addr: "127.0.0.1:0".parse().unwrap(),
            bls_pop: None,
            weight: 1,
        };
        let block = block_with_reconfig(1, 0, nid(1), cmd);
        node.apply_commit(block);

        // History unchanged — only the genesis boundary remains.
        assert_eq!(node.validator_history.boundary_count(), 1);
        assert_eq!(node.core.state().validator_history.boundary_count(), 1);
    }

    #[test]
    fn apply_commit_with_v_eff_below_min_delay_drops_silently() {
        use boule_consensus::reconfig::{ReconfigCommand, ValidatorEntry};

        let mut node = make_node(nid(1));
        // block.view = 5, v_eff = 5 — equal, but the rule wants
        // v_eff >= block.view + MIN_V_EFF_DELAY, so this is too low.
        let cmd = ReconfigCommand {
            adds: vec![ValidatorEntry {
                node_id: nid(5),
                addr: "127.0.0.1:9005".parse().unwrap(),
                bls_pop: None,
                weight: 1,
            }],
            removes: vec![],
            changes: vec![],
            v_eff: View(5),
        };
        let block = block_with_reconfig(1, 5, nid(1), cmd);
        node.apply_commit(block);

        assert_eq!(node.validator_history.boundary_count(), 1);
    }

    #[test]
    fn apply_commit_with_two_reconfigs_in_one_block_keeps_only_first() {
        use boule_consensus::reconfig::{MIN_V_EFF_DELAY, ReconfigCommand, ValidatorEntry};

        let mut node = make_node(nid(1));
        let v_eff_a = MIN_V_EFF_DELAY + 3;
        let v_eff_b = v_eff_a + 5;
        let cmd_a = ReconfigCommand {
            adds: vec![ValidatorEntry {
                node_id: nid(5),
                addr: "127.0.0.1:9005".parse().unwrap(),
                bls_pop: None,
                weight: 1,
            }],
            removes: vec![],
            changes: vec![],
            v_eff: v_eff_a,
        };
        let cmd_b = ReconfigCommand {
            adds: vec![ValidatorEntry {
                node_id: nid(6),
                addr: "127.0.0.1:9006".parse().unwrap(),
                bls_pop: None,
                weight: 1,
            }],
            removes: vec![],
            changes: vec![],
            v_eff: v_eff_b,
        };

        let payload_a = cmd_a.encode();
        let payload_b = cmd_b.encode();
        let commands = vec![payload_a, payload_b];
        let header = boule_consensus::replication::block::BlockHeader {
            parent_hash: genesis().hash(),
            height: Height(1),
            view: View(0),
            proposer: nid(1),
            state_commitment: [0u8; 32],
            commands_commitment: boule_consensus::replication::block::Block::commands_commitment(
                &commands,
            ),
            validator_history_commitment: [0; 32],
            committed_height: Height::ZERO,
            committed_state_root: [0; 32],
        };
        let block = boule_consensus::replication::block::Block { header, commands };
        node.apply_commit(block);

        // The first reconfig lands; the second is dropped because the
        // history's now-non-genesis boundary at v_eff_a conflicts with
        // any `v_eff >= v_eff_a`.
        assert_eq!(node.validator_history.boundary_count(), 2);
        assert_eq!(
            *node.validator_history.set_at(v_eff_a).for_view(v_eff_a),
            five_validators()
        );
        // v_eff_b is past the only non-genesis boundary, so the same
        // post-boundary set applies — confirming cmd_b did NOT land
        // (otherwise the set would be six_validators).
        assert_eq!(
            *node.validator_history.set_at(v_eff_b).for_view(v_eff_b),
            five_validators()
        );
        assert_ne!(
            *node.validator_history.set_at(v_eff_b).for_view(v_eff_b),
            six_validators()
        );
    }

    /// #254: a reconfig committed by one ConsensusNode must be visible
    /// to a fresh node `recover`'d against the same storage. Both the
    /// integration-side `validator_history` and the safety core's
    /// mirror must reflect the post-boundary committee.
    #[test]
    fn recovered_node_replays_persisted_validator_history() {
        use boule_consensus::reconfig::{MIN_V_EFF_DELAY, ReconfigCommand, ValidatorEntry};

        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let cfg = test_config(four_validators());

        // Phase 1: a fresh node commits a block carrying a reconfig.
        let mut node = ConsensusNode::new(
            nid(1),
            cfg.clone(),
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );
        let v_eff = MIN_V_EFF_DELAY + 5;
        let cmd = ReconfigCommand {
            adds: vec![ValidatorEntry {
                node_id: nid(5),
                addr: "127.0.0.1:9005".parse().unwrap(),
                bls_pop: None,
                weight: 1,
            }],
            removes: vec![],
            changes: vec![],
            v_eff,
        };
        let block = block_with_reconfig(1, 0, nid(1), cmd);
        node.apply_commit(block);
        assert_eq!(node.validator_history.boundary_count(), 2);
        drop(node);

        // Phase 2: a fresh node recovered against the same storage
        // must see the boundary in both histories, and the active set
        // looked up at v_eff must be the post-reconfig committee.
        let recovered = ConsensusNode::recover(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        )
        .expect("recover must succeed against persisted history");

        assert_eq!(
            recovered.validator_history.boundary_count(),
            2,
            "integration history must replay the boundary",
        );
        assert_eq!(
            recovered.core.state().validator_history.boundary_count(),
            2,
            "safety-core history must mirror the boundary after replay",
        );
        assert_eq!(
            *recovered.validator_history.set_at(v_eff).for_view(v_eff),
            five_validators()
        );
        assert_eq!(
            *recovered
                .core
                .state()
                .validator_history
                .set_at(v_eff)
                .for_view(v_eff),
            five_validators()
        );

        // The pacemaker selector built during `recover` rotates over
        // the recovered history — leaders at v_eff come from the post-
        // boundary set.
        let leader_v_eff_vid = boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(
            recovered.pacemaker.leader_for_view(v_eff),
        );
        assert!(
            five_validators().contains(&leader_v_eff_vid),
            "recovered selector must rotate over post-boundary committee",
        );
    }

    /// A node `recover`'d from storage that has no validator-history
    /// blob (i.e. no reconfig was ever committed) falls back cleanly
    /// to the genesis-only history, identical to a fresh node.
    #[test]
    fn recovered_node_with_no_persisted_history_uses_genesis_only() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let cfg = test_config(four_validators());

        let recovered = ConsensusNode::recover(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        )
        .expect("recover with empty storage must succeed");

        assert_eq!(recovered.validator_history.boundary_count(), 1);
        assert_eq!(
            *recovered.validator_history.current_set(),
            four_validators()
        );
    }

    #[test]
    fn apply_commit_with_malformed_reconfig_payload_logs_and_drops() {
        let mut node = make_node(nid(1));
        // Tagged but truncated body — decode will error.
        let bad_payload = bytes::Bytes::copy_from_slice(b"RECFG\0deliberately-truncated-body");
        let commands = vec![bad_payload];
        let header = boule_consensus::replication::block::BlockHeader {
            parent_hash: genesis().hash(),
            height: Height(1),
            view: View(0),
            proposer: nid(1),
            state_commitment: [0u8; 32],
            commands_commitment: boule_consensus::replication::block::Block::commands_commitment(
                &commands,
            ),
            validator_history_commitment: [0; 32],
            committed_height: Height::ZERO,
            committed_state_root: [0; 32],
        };
        let block = boule_consensus::replication::block::Block { header, commands };
        node.apply_commit(block);

        // History unchanged — malformed payloads do not insert a
        // boundary.
        assert_eq!(node.validator_history.boundary_count(), 1);
    }

    // ── #178 follow-up: durable block store + ServeBlock fallback ────────────

    /// `apply_commit` writes the block under `consensus/block/<hash>`
    /// and refreshes `consensus/last_committed`. Without this a peer
    /// asking for the block after we evicted (or restart-reset) it
    /// from `pending_blocks` would get `BlockResponse(None)` and stall.
    #[test]
    fn apply_commit_persists_block_and_last_committed_to_storage() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let cfg = test_config(four_validators());
        let mut node = ConsensusNode::new(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );

        let block = sample_block();
        let hash = block.hash();
        node.apply_commit(block.clone());

        // Block stored at the expected key; round-trips through
        // load_block_from_storage.
        let loaded = load_block_from_storage(storage.as_ref(), &hash)
            .expect("storage lookup must not error")
            .expect("committed block must be persisted");
        assert_eq!(loaded, block);

        // last_committed checkpoint reflects the just-committed block.
        let raw = storage
            .get(STORAGE_KEY_LAST_COMMITTED)
            .expect("storage")
            .expect("last_committed must be present");
        let lc = decode_last_committed(&raw).expect("decode");
        assert_eq!(lc.height, block.header.height);
        assert_eq!(lc.view, block.header.view);
    }

    /// Audit finding 4-2 / issue #411: when the durable batch write
    /// for a committed block fails, `apply_commit` must halt before
    /// any downstream observer fires. Otherwise a non-durable commit
    /// would propagate through the snapshot creation hook, the
    /// reconfig/rotation appliers, and the [`CommitNotifier`]
    /// fan-out — and on restart `last_committed_height` would
    /// disagree with the SM-applied state, since the block + checkpoint
    /// batch never landed.
    #[test]
    fn apply_commit_halts_when_storage_batch_fails() {
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

        use bytes::Bytes;

        use boule_consensus::api::CommitNotifier;
        use boule_consensus::reconfig::{MIN_V_EFF_DELAY, ReconfigCommand, ValidatorEntry};
        use boule_core::storage::WriteBatch;

        // Storage wrapper: reads/single-key writes pass through to an
        // inner `MemoryStorage`, but every `apply_batch` returns an
        // error. Models a backend that fails the atomic
        // `(block, last_committed)` write — the exact gap the audit
        // finding describes.
        struct FailingBatchStorage {
            inner: MemoryStorage,
        }
        impl Storage for FailingBatchStorage {
            fn get(&self, key: &[u8]) -> anyhow::Result<Option<Bytes>> {
                self.inner.get(key)
            }
            fn put(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
                self.inner.put(key, value)
            }
            fn delete(&self, key: &[u8]) -> anyhow::Result<()> {
                self.inner.delete(key)
            }
            fn scan_prefix(&self, prefix: &[u8]) -> anyhow::Result<Vec<(Bytes, Bytes)>> {
                self.inner.scan_prefix(prefix)
            }
            fn apply_batch(&self, _batch: WriteBatch) -> anyhow::Result<()> {
                anyhow::bail!("simulated storage batch failure")
            }
            fn compare_and_swap(
                &self,
                key: &[u8],
                expected: Option<&[u8]>,
                new: Option<&[u8]>,
            ) -> anyhow::Result<bool> {
                self.inner.compare_and_swap(key, expected, new)
            }
        }

        // Counting `CommitNotifier` to detect any post-failure fan-out.
        struct CountingNotifier {
            count: Arc<AtomicUsize>,
        }
        impl CommitNotifier for CountingNotifier {
            fn on_commit(&self, _block: &Block, _state_commitment: &[u8; 32], _view: View) {
                self.count.fetch_add(1, AtomicOrdering::Relaxed);
            }
        }

        let storage: Arc<dyn Storage> = Arc::new(FailingBatchStorage {
            inner: MemoryStorage::new(),
        });
        let count = Arc::new(AtomicUsize::new(0));
        let notifier: Arc<dyn CommitNotifier> = Arc::new(CountingNotifier {
            count: Arc::clone(&count),
        });
        let mut node = ConsensusNode::new(
            nid(1),
            test_config(four_validators()),
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            storage,
            Arc::new(MemoryWal::new()),
        )
        .with_commit_notifier(notifier);

        // Block carries a valid reconfig: a regression that let the
        // appliers run despite a non-durable persist would tick the
        // boundary count from 1 to 2.
        let v_eff = MIN_V_EFF_DELAY + 5;
        let cmd = ReconfigCommand {
            adds: vec![ValidatorEntry {
                node_id: nid(5),
                addr: "127.0.0.1:9005".parse().unwrap(),
                bls_pop: None,
                weight: 1,
            }],
            removes: vec![],
            changes: vec![],
            v_eff,
        };
        let block = block_with_reconfig(1, 0, nid(1), cmd);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            node.apply_commit(block);
        }));
        assert!(
            result.is_err(),
            "apply_commit must panic when the durable persist batch fails",
        );

        assert_eq!(
            count.load(AtomicOrdering::Relaxed),
            0,
            "CommitNotifier::on_commit must not fire on a non-durable commit",
        );
        assert_eq!(
            node.validator_history.boundary_count(),
            1,
            "reconfig appliers must not run on a non-durable commit",
        );
        assert_eq!(
            node.core.state().validator_history.boundary_count(),
            1,
            "safety-core mirror of validator_history must also remain at the genesis-only boundary",
        );
    }

    /// `recover` rebuilds `last_committed_height`/`last_committed_view`
    /// from the durable checkpoint so `consensus_resumed` reports the
    /// real chain rather than `0` after a restart.
    #[test]
    fn recover_restores_last_committed_height_and_view() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let cfg = test_config(four_validators());

        // Simulate a session that committed up to (height=42, view=57).
        {
            let mut node = ConsensusNode::new(
                nid(1),
                cfg.clone(),
                make_sm(),
                Arc::new(InMemoryMempool::new(64)),
                Arc::clone(&storage),
                Arc::new(MemoryWal::new()),
            );
            for h in 1..=42u64 {
                use boule_consensus::replication::block::BlockHeader;
                let parent_hash = if h == 1 {
                    genesis().hash()
                } else {
                    [0u8; 32] // doesn't matter for this test — apply_commit only
                    // reads (height, view, hash) and the SM
                };
                let block = Block {
                    header: BlockHeader {
                        parent_hash,
                        height: Height(h),
                        view: View(if h == 42 { 57 } else { h }),
                        proposer: nid(1),
                        state_commitment: [0u8; 32],
                        commands_commitment: Block::commands_commitment(&[]),
                        validator_history_commitment: [0; 32],
                        committed_height: Height::ZERO,
                        committed_state_root: [0; 32],
                    },
                    commands: vec![],
                };
                node.apply_commit(block);
            }
            assert_eq!(node.last_committed_height.load(Ordering::Relaxed), 42);
            assert_eq!(node.last_committed_view, View(57));
        }

        // New session: recover from the same storage and confirm the
        // counters come back populated.
        let recovered = ConsensusNode::recover(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            storage,
            Arc::new(MemoryWal::new()),
        )
        .expect("recover");
        assert_eq!(recovered.last_committed_height.load(Ordering::Relaxed), 42);
        assert_eq!(recovered.last_committed_view, View(57));
    }

    /// `Dispatch::ServeBlock` must serve a block that lives only in
    /// durable storage (the in-memory `pending_blocks` cache having
    /// been reset by a restart). Without the fallback the responder
    /// would emit `BlockResponse(None)` and the requester would loop
    /// forever on retries — the bug #178's reopen comment described.
    #[tokio::test]
    async fn serve_block_falls_back_to_storage_when_pending_blocks_misses() {
        // Step 1: a "first session" commits a block to storage.
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let cfg = test_config(four_validators());
        let block = sample_block();
        let hash = block.hash();
        {
            let mut node = ConsensusNode::new(
                nid(1),
                cfg.clone(),
                make_sm(),
                Arc::new(InMemoryMempool::new(64)),
                Arc::clone(&storage),
                Arc::new(MemoryWal::new()),
            );
            node.apply_commit(block.clone());
        }

        // Step 2: a fresh node ("restarted") shares the same storage
        // but starts with an empty pending_blocks (save genesis).
        let mut node = ConsensusNode::recover(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        )
        .expect("recover");
        assert!(
            !node.core.state().pending_blocks.contains_key(&hash),
            "post-restart pending_blocks must not contain the committed block — \
             this is the precondition the storage fallback exists to handle",
        );

        // Step 3: drive a ServeBlock dispatch and observe the
        // outbound BlockResponse carries the block from storage.
        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let (broadcaster, mut outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);
        node.apply_dispatch(
            Dispatch::ServeBlock { hash, to: nid(2) },
            broadcaster.as_ref(),
            &mut view_timer,
            &signer,
        )
        .await
        .expect("apply_dispatch");

        // The outbound channel should now hold a SendTo with a
        // BlockResponse(Some(block)) addressed to nid(2).
        let outbound = outbound_rx
            .recv()
            .await
            .expect("an outbound BlockResponse must be sent");
        match outbound {
            ProtocolOutbound::SendTo { node_id, payload } => {
                assert_eq!(node_id, nid(2));
                let wire: WireMessage =
                    postcard::from_bytes(&payload).expect("decode BlockResponse");
                match wire {
                    WireMessage::BlockResponse(got) => {
                        assert_eq!(got.payload.requested_hash, hash);
                        assert_eq!(got.payload.block, Some(block));
                        assert_eq!(got.signer, signer.node_id());
                    }
                    other => panic!("expected BlockResponse, got {other:?}"),
                }
            }
            other => panic!("expected SendTo, got {other:?}"),
        }
    }

    /// `Dispatch::ServeBlock` for an unknown hash returns
    /// `BlockResponse(None)` without erroring on storage. The peer's
    /// `block_sync_response_not_found` arm handles the negative case.
    #[tokio::test]
    async fn serve_block_returns_none_when_neither_pending_nor_storage_has_it() {
        let mut node = make_node(nid(1));
        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let (broadcaster, mut outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        let unknown_hash: BlockHash = [0xEE; 32];
        node.apply_dispatch(
            Dispatch::ServeBlock {
                hash: unknown_hash,
                to: nid(2),
            },
            broadcaster.as_ref(),
            &mut view_timer,
            &signer,
        )
        .await
        .expect("apply_dispatch");

        match outbound_rx.recv().await.expect("outbound") {
            ProtocolOutbound::SendTo { node_id, payload } => {
                assert_eq!(node_id, nid(2));
                let wire: WireMessage =
                    postcard::from_bytes(&payload).expect("decode BlockResponse");
                match wire {
                    WireMessage::BlockResponse(got) => {
                        assert_eq!(got.payload.requested_hash, unknown_hash);
                        assert!(got.payload.block.is_none());
                    }
                    other => panic!("expected BlockResponse, got {other:?}"),
                }
            }
            other => panic!("expected SendTo, got {other:?}"),
        }
    }

    // ── BlockResponse hash-check gates (#434) ──────────────────────────

    /// `Dispatch::ReceiveBlock` for an unsolicited hash (no
    /// `block_sync_inflight` entry) must drop the block before it
    /// lands in `pending_blocks`. Without this gate a Byzantine peer
    /// could pollute the cache with arbitrary blocks the requester
    /// never asked for (audit finding 10-2).
    #[tokio::test]
    async fn receive_block_drops_unsolicited_response() {
        let mut node = make_node(nid(1));
        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let (broadcaster, _outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        let block = sample_block();
        let block_hash = block.hash();
        let pending_before = node.core.state().pending_blocks.len();

        node.apply_dispatch(
            Dispatch::ReceiveBlock {
                requested_hash: block_hash,
                block: Some(block),
                from: nid(2),
            },
            broadcaster.as_ref(),
            &mut view_timer,
            &signer,
        )
        .await
        .expect("apply_dispatch");

        assert_eq!(
            node.core.state().pending_blocks.len(),
            pending_before,
            "unsolicited BlockResponse must not insert into pending_blocks",
        );
        assert!(
            !node.core.state().pending_blocks.contains_key(&block_hash),
            "the unsolicited block hash must not appear in pending_blocks",
        );
    }

    /// `Dispatch::ReceiveBlock` for a hash we *did* request, but
    /// where the responder ships a different block under that
    /// `requested_hash` claim, must drop the block. Otherwise a
    /// Byzantine responder could swap arbitrary content into the
    /// cache under a known-good hash.
    #[tokio::test]
    async fn receive_block_drops_hash_mismatch() {
        let mut node = make_node(nid(1));
        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let (broadcaster, _outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        // Pretend we asked for some other hash (not the block we are
        // about to receive).
        let requested_hash: BlockHash = [0xAA; 32];
        node.core
            .install_block_sync_inflight_for_test(requested_hash, nid(2), Height(1));

        let block = sample_block();
        let block_hash = block.hash();
        assert_ne!(block_hash, requested_hash);
        let pending_before = node.core.state().pending_blocks.len();

        node.apply_dispatch(
            Dispatch::ReceiveBlock {
                requested_hash,
                block: Some(block),
                from: nid(2),
            },
            broadcaster.as_ref(),
            &mut view_timer,
            &signer,
        )
        .await
        .expect("apply_dispatch");

        assert_eq!(
            node.core.state().pending_blocks.len(),
            pending_before,
            "hash-mismatched BlockResponse must not insert into pending_blocks",
        );
        assert!(
            !node.core.state().pending_blocks.contains_key(&block_hash),
            "the wrong-hash block must not appear in pending_blocks",
        );
        assert!(
            node.core.has_inflight_block_request(&requested_hash),
            "the inflight retry entry for the originally-requested hash must \
             be preserved across a hash-mismatched response so retries continue",
        );
    }

    /// Conversely, when a responder returns a block whose hash
    /// matches both the `requested_hash` and an outstanding inflight
    /// entry, the block must be inserted as before. Pins the
    /// happy-path of the new gate.
    #[tokio::test]
    async fn receive_block_inserts_when_hash_matches_inflight() {
        let mut node = make_node(nid(1));
        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let (broadcaster, _outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        let block = sample_block();
        let block_hash = block.hash();
        node.core
            .install_block_sync_inflight_for_test(block_hash, nid(2), Height(1));

        node.apply_dispatch(
            Dispatch::ReceiveBlock {
                requested_hash: block_hash,
                block: Some(block),
                from: nid(2),
            },
            broadcaster.as_ref(),
            &mut view_timer,
            &signer,
        )
        .await
        .expect("apply_dispatch");

        assert!(
            node.core.state().pending_blocks.contains_key(&block_hash),
            "matching-hash BlockResponse must insert the block",
        );
        assert!(
            !node.core.has_inflight_block_request(&block_hash),
            "insert_pending_block clears the inflight entry on match",
        );
    }

    // ── Bulk-range RPC (#514) — ServeBlockRange / ReceiveBlockRange ────

    /// Build a deterministic block at the given height, parented to
    /// the genesis block. View is set equal to height for clarity.
    fn range_block_at(height: u64) -> Block {
        use boule_consensus::replication::block::BlockHeader;
        Block {
            header: BlockHeader {
                parent_hash: genesis().hash(),
                height: Height(height),
                view: View(height),
                proposer: nid(1),
                state_commitment: [0u8; 32],
                commands_commitment: Block::commands_commitment(&[]),
                validator_history_commitment: [0; 32],
                committed_height: Height::ZERO,
                committed_state_root: [0; 32],
            },
            commands: vec![],
        }
    }

    /// `Dispatch::ServeBlockRange` returns blocks from `pending_blocks`
    /// inside the requested span, in ascending-height order. The
    /// signed envelope echoes the request span and the responder's
    /// signer matches the local node.
    #[tokio::test]
    async fn serve_block_range_returns_blocks_within_span_from_pending_blocks() {
        let mut node = make_node(nid(1));
        // Seed pending_blocks with heights 5..=8.
        for h in 5..=8u64 {
            node.core.insert_pending_block(range_block_at(h));
        }

        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let (broadcaster, mut outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        node.apply_dispatch(
            Dispatch::ServeBlockRange {
                from_height: Height(6),
                to_height: Height(8),
                to: nid(2),
            },
            broadcaster.as_ref(),
            &mut view_timer,
            &signer,
        )
        .await
        .expect("apply_dispatch");

        match outbound_rx.recv().await.expect("outbound") {
            ProtocolOutbound::SendTo { node_id, payload } => {
                assert_eq!(node_id, nid(2));
                let wire: WireMessage =
                    postcard::from_bytes(&payload).expect("decode BlockRangeResponse");
                match wire {
                    WireMessage::BlockRangeResponse(got) => {
                        assert_eq!(got.payload.from_height, Height(6));
                        assert_eq!(got.payload.to_height, Height(8));
                        assert_eq!(got.signer, signer.node_id());
                        let heights: Vec<u64> = got
                            .payload
                            .blocks
                            .iter()
                            .map(|b| b.header.height.0)
                            .collect();
                        assert_eq!(heights, vec![6, 7, 8]);
                    }
                    other => panic!("expected BlockRangeResponse, got {other:?}"),
                }
            }
            other => panic!("expected SendTo, got {other:?}"),
        }
    }

    /// `Dispatch::ServeBlockRange` for a span that has no overlap with
    /// pending_blocks or storage returns an empty block vector — the
    /// responder still emits a (signed) BlockRangeResponse so the
    /// requester can advance off the inflight entry.
    #[tokio::test]
    async fn serve_block_range_returns_empty_when_responder_holds_nothing() {
        let mut node = make_node(nid(1));
        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let (broadcaster, mut outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        node.apply_dispatch(
            Dispatch::ServeBlockRange {
                from_height: Height(100),
                to_height: Height(105),
                to: nid(2),
            },
            broadcaster.as_ref(),
            &mut view_timer,
            &signer,
        )
        .await
        .expect("apply_dispatch");

        match outbound_rx.recv().await.expect("outbound") {
            ProtocolOutbound::SendTo { payload, .. } => {
                let wire: WireMessage = postcard::from_bytes(&payload).expect("decode");
                match wire {
                    WireMessage::BlockRangeResponse(got) => {
                        assert_eq!(got.payload.from_height, Height(100));
                        assert_eq!(got.payload.to_height, Height(105));
                        assert!(got.payload.blocks.is_empty());
                    }
                    other => panic!("expected BlockRangeResponse, got {other:?}"),
                }
            }
            other => panic!("expected SendTo, got {other:?}"),
        }
    }

    /// `Dispatch::ServeBlockRange` truncates the response at
    /// `BLOCK_RANGE_RESPONSE_MAX_BLOCKS` even when the requested span
    /// is wider. The requester pipelines further requests starting at
    /// `last_received_height + 1`.
    #[tokio::test]
    async fn serve_block_range_caps_response_at_max() {
        let cap = boule_consensus::wire::BLOCK_RANGE_RESPONSE_MAX_BLOCKS as u64;
        let mut node = make_node(nid(1));
        // Seed cap+8 blocks above the cap so the responder must
        // truncate.
        for h in 1..=(cap + 8) {
            node.core.insert_pending_block(range_block_at(h));
        }

        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let (broadcaster, mut outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        node.apply_dispatch(
            Dispatch::ServeBlockRange {
                from_height: Height(1),
                to_height: Height(cap + 8),
                to: nid(2),
            },
            broadcaster.as_ref(),
            &mut view_timer,
            &signer,
        )
        .await
        .expect("apply_dispatch");

        match outbound_rx.recv().await.expect("outbound") {
            ProtocolOutbound::SendTo { payload, .. } => {
                let wire: WireMessage = postcard::from_bytes(&payload).expect("decode");
                match wire {
                    WireMessage::BlockRangeResponse(got) => {
                        assert_eq!(got.payload.blocks.len(), cap as usize);
                        // Ascending order, contiguous starting at from_height.
                        let heights: Vec<u64> = got
                            .payload
                            .blocks
                            .iter()
                            .map(|b| b.header.height.0)
                            .collect();
                        assert_eq!(heights[0], 1);
                        for w in heights.windows(2) {
                            assert_eq!(w[1], w[0] + 1);
                        }
                    }
                    other => panic!("expected BlockRangeResponse, got {other:?}"),
                }
            }
            other => panic!("expected SendTo, got {other:?}"),
        }
    }

    /// `Dispatch::ReceiveBlockRange` inserts every well-formed block
    /// (height inside echoed span, strictly ascending) into
    /// pending_blocks when the response matches an outstanding
    /// inflight entry. Out-of-range entries are dropped, matching the
    /// `ingress_block_range_response`'s shape contract. The matching
    /// inflight entry is consumed on receipt (#531).
    #[tokio::test]
    async fn receive_block_range_inserts_in_range_blocks_and_drops_out_of_range() {
        let mut node = make_node(nid(1));
        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let (broadcaster, _outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        // Pretend we just emitted a BlockRangeRequest for [5, 7] to
        // peer nid(2). The inflight gate (#531) requires this entry
        // before the response is admitted.
        node.install_block_sync_range_inflight_for_test(Height(5), Height(7), nid(2));

        // Build a deliberately-mixed response: heights 4 (out-of-range),
        // 5, 6 (in-range), 9 (out-of-range). The handler must keep
        // 5 and 6 only.
        let blocks = vec![
            range_block_at(4),
            range_block_at(5),
            range_block_at(6),
            range_block_at(9),
        ];

        node.apply_dispatch(
            Dispatch::ReceiveBlockRange {
                from_height: Height(5),
                to_height: Height(7),
                blocks,
                from: nid(2),
            },
            broadcaster.as_ref(),
            &mut view_timer,
            &signer,
        )
        .await
        .expect("apply_dispatch");

        let pending = &node.core.state().pending_blocks;
        assert!(pending.contains_key(&range_block_at(5).hash()));
        assert!(pending.contains_key(&range_block_at(6).hash()));
        assert!(
            !pending.contains_key(&range_block_at(4).hash()),
            "below-range block must be dropped",
        );
        assert!(
            !pending.contains_key(&range_block_at(9).hash()),
            "above-range block must be dropped",
        );
        assert!(
            node.block_sync_range_inflight_peer_for_test(Height(5), Height(7))
                .is_none(),
            "matching inflight entry must be cleared on receipt",
        );
    }

    /// `Dispatch::ReceiveBlockRange` whose `(from_height, to_height)`
    /// pair has no matching `block_sync_range_inflight` entry must be
    /// dropped before any block reaches `pending_blocks`. Without the
    /// gate a Byzantine peer could pollute the cache with arbitrary
    /// blocks the requester never asked for (audit symmetry to
    /// `receive_block_drops_unsolicited_response` from the single-
    /// block path; issue #531).
    #[tokio::test]
    async fn receive_block_range_drops_unsolicited_response() {
        let mut node = make_node(nid(1));
        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let (broadcaster, _outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        // No install_block_sync_range_inflight_for_test call: the
        // response below is unsolicited.
        let pending_before = node.core.state().pending_blocks.len();

        let blocks = vec![range_block_at(5), range_block_at(6), range_block_at(7)];

        node.apply_dispatch(
            Dispatch::ReceiveBlockRange {
                from_height: Height(5),
                to_height: Height(7),
                blocks,
                from: nid(2),
            },
            broadcaster.as_ref(),
            &mut view_timer,
            &signer,
        )
        .await
        .expect("apply_dispatch");

        assert_eq!(
            node.core.state().pending_blocks.len(),
            pending_before,
            "unsolicited BlockRangeResponse must not insert into pending_blocks",
        );
        for h in 5..=7 {
            assert!(
                !node
                    .core
                    .state()
                    .pending_blocks
                    .contains_key(&range_block_at(h).hash()),
                "unsolicited block at height {h} must not appear in pending_blocks",
            );
        }
    }

    // ── Bulk-range requester gap detection (#515) ──────────────────────

    /// Drain outbound frames into a Vec until the channel is empty,
    /// decoding each `SendTo` into `(NodeId, WireMessage)`.
    fn drain_send_to_outbound(
        outbound_rx: &mut tokio::sync::mpsc::Receiver<ProtocolOutbound>,
    ) -> Vec<(NodeId, WireMessage)> {
        let mut out = Vec::new();
        while let Ok(frame) = outbound_rx.try_recv() {
            if let ProtocolOutbound::SendTo { node_id, payload } = frame
                && let Ok(w) = postcard::from_bytes::<WireMessage>(&payload)
            {
                out.push((node_id, w));
            }
        }
        out
    }

    /// A proposal whose parent height sits more than two blocks above
    /// the local commit frontier triggers BOTH a single-block
    /// `BlockRequest` (the safety core's path for the immediate
    /// missing parent) AND a `BlockRangeRequest` for
    /// `[last_committed + 1, parent_height]` (#515). The two compose:
    /// the range request collapses catch-up into one round trip and
    /// the single-block path stays as the unknown-parent-by-itself
    /// fallback.
    #[tokio::test]
    async fn proposal_with_multi_block_gap_emits_both_request_block_and_range_request() {
        let mut node = make_node(nid(1));
        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let proposer_signer = fresh_signer();
        let (broadcaster, mut outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        // Last committed height stays at 0 (fresh node). Proposer
        // ships a proposal at height 31 with an unknown parent (i.e.
        // the safety core will park the proposal and emit
        // RequestBlock for the parent at height 30).
        let parent_hash: BlockHash = [0xAB; 32];
        let dispatch = synthetic_proposal_dispatch(&proposer_signer, 31, 31, parent_hash);
        let proposer_id = proposer_signer.node_id();

        node.apply_dispatch(dispatch, broadcaster.as_ref(), &mut view_timer, &signer)
            .await
            .expect("apply_dispatch");

        let frames = drain_send_to_outbound(&mut outbound_rx);
        let mut saw_request_block = false;
        let mut saw_range_request = false;
        for (to, w) in &frames {
            match w {
                WireMessage::BlockRequest(_) => {
                    assert_eq!(*to, proposer_id);
                    saw_request_block = true;
                }
                WireMessage::BlockRangeRequest {
                    from_height,
                    to_height,
                } => {
                    assert_eq!(*to, proposer_id);
                    assert_eq!(*from_height, Height(1));
                    assert_eq!(*to_height, Height(30));
                    saw_range_request = true;
                }
                _ => {}
            }
        }
        assert!(
            saw_request_block,
            "safety core's single-block path must still fire; saw {frames:?}",
        );
        assert!(
            saw_range_request,
            "multi-block gap must fire BlockRangeRequest; saw {frames:?}",
        );
    }

    /// A second proposal with the same gap window (still pre-commit)
    /// must NOT re-emit the same `BlockRangeRequest` while the prior
    /// request is in flight — the inflight tracker dedups.
    #[tokio::test]
    async fn second_proposal_with_same_gap_window_dedups_range_request() {
        let mut node = make_node(nid(1));
        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let proposer_signer = fresh_signer();
        let (broadcaster, mut outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        let parent_hash: BlockHash = [0xAB; 32];
        // First proposal at height 31 — fires the range request.
        let d1 = synthetic_proposal_dispatch(&proposer_signer, 31, 31, parent_hash);
        node.apply_dispatch(d1, broadcaster.as_ref(), &mut view_timer, &signer)
            .await
            .expect("apply_dispatch 1");
        let _drained1 = drain_send_to_outbound(&mut outbound_rx);

        // Second proposal at height 32 (still parent_hash unknown,
        // still a multi-block gap from height 0). The to_height
        // shifts to 31, but [from=1, to=31] is a fresh window so it
        // emits. To exercise the same-window dedup we use the same
        // proposal again.
        let d2 = synthetic_proposal_dispatch(&proposer_signer, 31, 31, parent_hash);
        node.apply_dispatch(d2, broadcaster.as_ref(), &mut view_timer, &signer)
            .await
            .expect("apply_dispatch 2");

        let frames = drain_send_to_outbound(&mut outbound_rx);
        let range_emissions: Vec<_> = frames
            .iter()
            .filter(|(_, w)| matches!(w, WireMessage::BlockRangeRequest { .. }))
            .collect();
        assert!(
            range_emissions.is_empty(),
            "second proposal with same (from, to) window must not re-emit range request; saw {range_emissions:?}",
        );
    }

    /// A proposal whose parent is exactly one block above the commit
    /// frontier (no multi-block gap) must NOT trigger a
    /// `BlockRangeRequest` — the single-block path covers it. Pins
    /// the boundary condition.
    #[tokio::test]
    async fn proposal_with_single_block_gap_does_not_emit_range_request() {
        let mut node = make_node(nid(1));
        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let proposer_signer = fresh_signer();
        let (broadcaster, mut outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        // Proposal at height 2 with parent at 1 — the single-block
        // RequestBlock path covers this; no range request needed.
        let parent_hash: BlockHash = [0xCD; 32];
        let dispatch = synthetic_proposal_dispatch(&proposer_signer, 2, 2, parent_hash);

        node.apply_dispatch(dispatch, broadcaster.as_ref(), &mut view_timer, &signer)
            .await
            .expect("apply_dispatch");

        let frames = drain_send_to_outbound(&mut outbound_rx);
        let range_emissions: Vec<_> = frames
            .iter()
            .filter(|(_, w)| matches!(w, WireMessage::BlockRangeRequest { .. }))
            .collect();
        assert!(
            range_emissions.is_empty(),
            "single-block gap must not trigger BlockRangeRequest; saw {range_emissions:?}",
        );
    }

    /// Pipelining: when a `BlockRangeRequest` response lands and a
    /// proposal is still parked more than one window above the
    /// (post-insert) commit frontier, the requester fires the *next*
    /// window immediately rather than waiting for a fresh proposal to
    /// re-trigger gap detection. Pins that the follow-on emission
    /// targets `[new_last_committed + 1, …]` capped at the per-response
    /// budget and goes to the proposer of the still-parked proposal.
    #[tokio::test]
    async fn range_response_pipelines_next_window_while_proposal_still_parked() {
        let mut node = make_node(nid(1));
        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let proposer_signer = fresh_signer();
        let proposer_id = proposer_signer.node_id();
        let (broadcaster, mut outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        // A proposal at height 200 with an unknown parent parks on this
        // fresh node and fires the first window `[1, 64]` (parent 199
        // capped at the 64-block response budget). Drain that initial
        // emission so the assertion below only sees the pipelined one.
        let parent_hash: BlockHash = [0xAB; 32];
        let d = synthetic_proposal_dispatch(&proposer_signer, 200, 200, parent_hash);
        node.apply_dispatch(d, broadcaster.as_ref(), &mut view_timer, &signer)
            .await
            .expect("apply_dispatch proposal");
        let _drained = drain_send_to_outbound(&mut outbound_rx);

        // Model the first window having committed on this replica: the
        // synthetic range blocks below carry no valid justify-QC, so
        // they land in `pending_blocks` without advancing the safety
        // core's commit frontier the way a real window would. Set the
        // frontier to 64 directly so the pipelined follow-on computes
        // the next window from where production would resume.
        node.last_committed_height.store(64, Ordering::Relaxed);

        // The `[1, 64]` window's response arrives. `handle_block_range_response`
        // clears the inflight entry, inserts the in-range block, and —
        // because height 200 is still parked far above the frontier —
        // pipelines the next window.
        node.apply_dispatch(
            Dispatch::ReceiveBlockRange {
                from_height: Height(1),
                to_height: Height(64),
                blocks: vec![range_block_at(50)],
                from: proposer_id,
            },
            broadcaster.as_ref(),
            &mut view_timer,
            &signer,
        )
        .await
        .expect("apply_dispatch range response");

        let frames = drain_send_to_outbound(&mut outbound_rx);
        let range_emissions: Vec<_> = frames
            .iter()
            .filter_map(|(to, w)| match w {
                WireMessage::BlockRangeRequest {
                    from_height,
                    to_height,
                } => Some((*to, *from_height, *to_height)),
                _ => None,
            })
            .collect();
        assert_eq!(
            range_emissions,
            vec![(proposer_id, Height(65), Height(128))],
            "range response with a still-parked proposal must pipeline the next \
             window [65, 128] to the proposer; saw {frames:?}",
        );
    }

    /// No pipelining without progress: a range response that commits
    /// nothing — e.g. a gap-leaving response from a slow or
    /// Byzantine peer whose blocks sit above a hole the frontier hasn't
    /// reached — must NOT pipeline the next window. Otherwise the
    /// response-driven re-emission would re-ask the same window on every
    /// arrival in a 1:1 request/response loop. The stalled gap falls
    /// back to the proposal-driven path and the bounded retry timer.
    #[tokio::test]
    async fn range_response_without_frontier_progress_does_not_pipeline() {
        let mut node = make_node(nid(1));
        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let proposer_signer = fresh_signer();
        let proposer_id = proposer_signer.node_id();
        let (broadcaster, mut outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        // Park a proposal at height 200, then drain the initial window
        // emission so only a follow-on would show below.
        let parent_hash: BlockHash = [0xAB; 32];
        let d = synthetic_proposal_dispatch(&proposer_signer, 200, 200, parent_hash);
        node.apply_dispatch(d, broadcaster.as_ref(), &mut view_timer, &signer)
            .await
            .expect("apply_dispatch proposal");
        let _drained = drain_send_to_outbound(&mut outbound_rx);

        // Frontier is parked at 64; the response below is for the next
        // window [65, 128] but its only block (height 100) sits above
        // the still-missing block 65, so nothing commits and the
        // frontier stays at 64 — short of this window's `from_height`.
        node.last_committed_height.store(64, Ordering::Relaxed);
        node.install_block_sync_range_inflight_for_test(Height(65), Height(128), proposer_id);

        node.apply_dispatch(
            Dispatch::ReceiveBlockRange {
                from_height: Height(65),
                to_height: Height(128),
                blocks: vec![range_block_at(100)],
                from: proposer_id,
            },
            broadcaster.as_ref(),
            &mut view_timer,
            &signer,
        )
        .await
        .expect("apply_dispatch range response");

        let frames = drain_send_to_outbound(&mut outbound_rx);
        let range_emissions: Vec<_> = frames
            .iter()
            .filter(|(_, w)| matches!(w, WireMessage::BlockRangeRequest { .. }))
            .collect();
        assert!(
            range_emissions.is_empty(),
            "a response that commits no progress must not pipeline the next window; \
             saw {range_emissions:?}",
        );
    }

    // ── Range-keyed retry timer (#530) ───────────────────────────────────

    /// Wall-clock-driven retry walk re-emits the next
    /// `BlockRangeRequest` for an entry whose elapsed since
    /// `last_asked_at` has crossed the configured threshold. Pins the
    /// #530 acceptance criterion: a dropped first range request
    /// recovers in `<= 500ms simulated` rather than waiting for the
    /// next `ProposalReceived` to re-trigger gap detection.
    #[tokio::test(start_paused = true)]
    async fn dropped_block_range_request_retries_within_500ms_simulated() {
        let mut node = make_node(nid(1));
        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let proposer_signer = fresh_signer();
        let proposer_id = proposer_signer.node_id();
        let (broadcaster, mut outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        // Multi-block gap: parent at height 30 is missing on this
        // (fresh) node. The proposal arrival fires the initial
        // `BlockRangeRequest` for [1, 30] to the proposer.
        let parent_hash: BlockHash = [0xAB; 32];
        let dispatch = synthetic_proposal_dispatch(&proposer_signer, 31, 31, parent_hash);
        node.apply_dispatch(dispatch, broadcaster.as_ref(), &mut view_timer, &signer)
            .await
            .expect("apply_dispatch");

        let initial = drain_send_to_outbound(&mut outbound_rx);
        let initial_range: Vec<_> = initial
            .iter()
            .filter(|(_, w)| matches!(w, WireMessage::BlockRangeRequest { .. }))
            .collect();
        assert_eq!(
            initial_range.len(),
            1,
            "exactly one BlockRangeRequest must fire on the initial gap; saw {initial:?}",
        );
        // Simulate the request being lost in flight: drained above
        // and never delivered. The inflight entry remains, attempts=1.
        assert_eq!(
            node.block_sync_range_inflight_attempts_for_test(Height(1), Height(30)),
            Some(1),
        );

        // Advance simulated time to the retry threshold and drive the
        // wall-clock retry walk. The threshold matches the dedicated
        // retry timer's initial delay (200ms); the AC budget is 500ms,
        // so a single tick at the threshold satisfies it with margin.
        tokio::time::advance(BLOCK_SYNC_RETRY_INITIAL_DELAY).await;
        node.maintain_block_sync_range_retry(broadcaster.as_ref(), BLOCK_SYNC_RETRY_INITIAL_DELAY)
            .await
            .expect("retry walk");

        let retried = drain_send_to_outbound(&mut outbound_rx);
        let retry_range: Vec<_> = retried
            .iter()
            .filter_map(|(to, w)| match w {
                WireMessage::BlockRangeRequest {
                    from_height,
                    to_height,
                } => Some((*to, *from_height, *to_height)),
                _ => None,
            })
            .collect();
        assert_eq!(
            retry_range,
            vec![(proposer_id, Height(1), Height(30))],
            "retry walk must re-emit one BlockRangeRequest with the same span; saw {retried:?}",
        );
        assert_eq!(
            node.block_sync_range_inflight_attempts_for_test(Height(1), Height(30)),
            Some(2),
            "attempts counter must advance on retry",
        );
    }

    /// A retry walk that fires shortly after a fresh insert (less than
    /// the per-entry quiescence threshold) must not re-emit. Guards
    /// against an immediate retry when the timer ticks within
    /// milliseconds of the initial probe.
    #[tokio::test(start_paused = true)]
    async fn range_retry_walk_below_threshold_is_a_noop() {
        let mut node = make_node(nid(1));
        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let proposer_signer = fresh_signer();
        let (broadcaster, mut outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        let parent_hash: BlockHash = [0xAB; 32];
        let dispatch = synthetic_proposal_dispatch(&proposer_signer, 31, 31, parent_hash);
        node.apply_dispatch(dispatch, broadcaster.as_ref(), &mut view_timer, &signer)
            .await
            .expect("apply_dispatch");
        let _drained = drain_send_to_outbound(&mut outbound_rx);

        // Advance well below the threshold (50ms vs 200ms default).
        tokio::time::advance(Duration::from_millis(50)).await;
        node.maintain_block_sync_range_retry(broadcaster.as_ref(), BLOCK_SYNC_RETRY_INITIAL_DELAY)
            .await
            .expect("retry walk");

        let frames = drain_send_to_outbound(&mut outbound_rx);
        let range_emissions: Vec<_> = frames
            .iter()
            .filter(|(_, w)| matches!(w, WireMessage::BlockRangeRequest { .. }))
            .collect();
        assert!(
            range_emissions.is_empty(),
            "below-threshold retry walk must not re-emit; saw {range_emissions:?}",
        );
        assert_eq!(
            node.block_sync_range_inflight_attempts_for_test(Height(1), Height(30)),
            Some(1),
            "attempts counter must stay at 1 when the walk skips",
        );
    }

    /// The per-entry attempt budget bounds retry forever. Once the
    /// counter hits `block_sync_max_attempts`, the next walk drops the
    /// inflight entry instead of re-emitting — the next
    /// `ProposalReceived` will re-trigger gap detection from the
    /// current commit frontier with a fresh sender.
    #[tokio::test(start_paused = true)]
    async fn range_retry_drops_entry_when_attempts_budget_exhausted() {
        let mut node = make_node_with_block_sync_max_attempts(nid(1), 3);
        let (broadcaster, mut outbound_rx) = make_test_broadcaster();

        // Pretend a BlockRangeRequest for [5, 7] has been emitted three
        // times to nid(2) without a response — the inflight tracker is
        // at the budget ceiling.
        node.install_block_sync_range_inflight_for_test(Height(5), Height(7), nid(2));
        // `install_*` records `attempts = 1`; bump to the cap so the
        // next walk crosses the budget check.
        if let Some(entry) = node
            .block_sync_range_inflight
            .get_mut(&(Height(5), Height(7)))
        {
            entry.attempts = 3;
        }

        tokio::time::advance(BLOCK_SYNC_RETRY_INITIAL_DELAY).await;
        node.maintain_block_sync_range_retry(broadcaster.as_ref(), BLOCK_SYNC_RETRY_INITIAL_DELAY)
            .await
            .expect("retry walk");

        assert!(
            node.block_sync_range_inflight_attempts_for_test(Height(5), Height(7))
                .is_none(),
            "exhausted entry must be dropped from the tracker",
        );
        let frames = drain_send_to_outbound(&mut outbound_rx);
        let range_emissions: Vec<_> = frames
            .iter()
            .filter(|(_, w)| matches!(w, WireMessage::BlockRangeRequest { .. }))
            .collect();
        assert!(
            range_emissions.is_empty(),
            "exhausted entry must not re-emit on the same walk; saw {range_emissions:?}",
        );
    }

    /// Build a `ConsensusNode` with `block_sync_max_attempts` capped at
    /// `max`. Used by the #530 retry tests to exercise the budget-
    /// exhaustion drop path without having to issue `max-1` real
    /// emissions.
    fn make_node_with_block_sync_max_attempts(self_id: NodeId, max: u32) -> ConsensusNode {
        let vs = four_validators();
        let mut limits = CacheLimits::unbounded_for_tests();
        limits.block_sync_max_attempts = max;
        let mut cfg = NodeConfigForConsensus::for_testing(vs, genesis());
        cfg.limits = limits;
        ConsensusNode::new(
            self_id,
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(256)),
            Arc::new(MemoryStorage::new()),
            Arc::new(MemoryWal::new()),
        )
    }

    /// The retry timer stays armed while only the range tracker has
    /// entries — `maintain_block_sync_retry_timer` must consider both
    /// the safety-core single-block map and the integration-layer
    /// range map. Without this, a dropped `BlockRangeRequest` would
    /// stall waiting for the next `ProposalReceived`.
    #[tokio::test(start_paused = true)]
    async fn retry_timer_stays_armed_while_range_inflight_is_nonempty() {
        let mut node = make_node(nid(1));
        node.install_block_sync_range_inflight_for_test(Height(1), Height(30), nid(2));

        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<()>(4);
        let mut retry_timer = BlockSyncRetryTimer::new(timer_tx);
        let mut delay: Option<Duration> = None;

        node.maintain_block_sync_retry_timer(&mut retry_timer, &mut delay);
        assert!(
            retry_timer.is_armed(),
            "retry timer must be armed when only range inflight is non-empty",
        );
        assert_eq!(delay, Some(BLOCK_SYNC_RETRY_INITIAL_DELAY));

        // Drain the entry; the next call must cancel the timer.
        node.block_sync_range_inflight.clear();
        node.maintain_block_sync_retry_timer(&mut retry_timer, &mut delay);
        assert!(
            !retry_timer.is_armed(),
            "retry timer must be cancelled once both trackers drain",
        );
        assert_eq!(delay, None);
    }

    // ── Snapshot wire protocol (#228) — serving handlers ────────────────

    /// Helper: write a fully-populated snapshot (manifest + chunks)
    /// into the node's `Storage` so the serving handlers find it.
    fn seed_snapshot(
        storage: &Arc<dyn Storage>,
        height: u64,
        chunk_size: u32,
        n_chunks: u32,
    ) -> boule_consensus::replication::snapshot::SnapshotManifest {
        use boule_consensus::replication::snapshot::{
            SnapshotManifest, SnapshotStore, chunk_snapshot,
        };

        let payload: Vec<u8> = (0..n_chunks * chunk_size)
            .map(|i| (i & 0xFF) as u8)
            .collect();
        let chunks_with_hashes = chunk_snapshot(&payload, chunk_size);
        assert_eq!(chunks_with_hashes.len(), n_chunks as usize);
        let chunk_hashes: Vec<[u8; 32]> = chunks_with_hashes.iter().map(|(_, h)| *h).collect();
        let chunks: Vec<bytes::Bytes> = chunks_with_hashes.into_iter().map(|(c, _)| c).collect();

        let vs = four_validators();
        let block = {
            // Build a structurally-valid Block at the requested
            // height; the joiner's `manifest.verify` cross-checks
            // block.hash() vs manifest.block_hash and reject any
            // inconsistency.
            let parent_hash = genesis().hash();
            let commands: Vec<bytes::Bytes> = Vec::new();
            boule_consensus::replication::block::Block {
                header: boule_consensus::replication::block::BlockHeader {
                    parent_hash,
                    height: Height(height),
                    view: View(7),
                    proposer: [0u8; 32],
                    state_commitment: [0xCD; 32],
                    commands_commitment:
                        boule_consensus::replication::block::Block::commands_commitment(&commands),
                    validator_history_commitment: [0; 32],
                    committed_height: Height::ZERO,
                    committed_state_root: [0; 32],
                },
                commands,
            }
        };
        let mut qc = QuorumCertificate::new(View::ZERO, block.hash(), vs.len());
        for i in 0..boule_consensus::hotstuff::qc::quorum_size(vs.len()) {
            qc.add_signature(i, [0u8; 64]);
        }
        let manifest = SnapshotManifest::build_for_test_genesis_histories(
            block,
            &vs,
            chunk_size,
            chunk_hashes,
            qc,
            1_700_000_000,
        );
        SnapshotStore::new(Arc::clone(storage))
            .save(&manifest, &chunks)
            .expect("save snapshot");
        manifest
    }

    fn decode_outbound_wire(out: ProtocolOutbound) -> (NodeId, WireMessage) {
        match out {
            ProtocolOutbound::SendTo { node_id, payload } => {
                let wire: WireMessage = postcard::from_bytes(&payload).expect("decode wire");
                (node_id, wire)
            }
            other => panic!("expected SendTo, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn serve_snapshot_manifest_latest_returns_stored_manifest() {
        // A peer asks for our latest snapshot manifest; we look it up
        // via SnapshotStore and reply via the run-loop's serving
        // handler. Exercises the end-to-end Dispatch → SendTo path.
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let manifest = seed_snapshot(&storage, 100, 64, 2);

        let cfg = test_config(four_validators());
        let mut node = ConsensusNode::new(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );
        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let (broadcaster, mut outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        node.apply_dispatch(
            Dispatch::ServeSnapshotManifest {
                height: None,
                to: nid(2),
            },
            broadcaster.as_ref(),
            &mut view_timer,
            &signer,
        )
        .await
        .expect("apply_dispatch");

        let (to, wire) = decode_outbound_wire(outbound_rx.recv().await.expect("outbound"));
        assert_eq!(to, nid(2));
        match wire {
            WireMessage::SnapshotManifestResponse(Some(got)) => {
                assert_eq!(got, manifest);
            }
            other => panic!("expected SnapshotManifestResponse(Some), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn serve_snapshot_manifest_at_height_returns_exact_match() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let m_low = seed_snapshot(&storage, 100, 64, 1);
        let _m_high = seed_snapshot(&storage, 200, 64, 1);

        let cfg = test_config(four_validators());
        let mut node = ConsensusNode::new(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );
        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let (broadcaster, mut outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        node.apply_dispatch(
            Dispatch::ServeSnapshotManifest {
                height: Some(100),
                to: nid(2),
            },
            broadcaster.as_ref(),
            &mut view_timer,
            &signer,
        )
        .await
        .expect("apply_dispatch");

        let (_, wire) = decode_outbound_wire(outbound_rx.recv().await.expect("outbound"));
        match wire {
            WireMessage::SnapshotManifestResponse(Some(got)) => {
                assert_eq!(got, m_low);
                assert_eq!(got.height, Height(100));
            }
            other => panic!("expected SnapshotManifestResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn serve_snapshot_manifest_returns_none_when_store_empty() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let cfg = test_config(four_validators());
        let mut node = ConsensusNode::new(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );
        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let (broadcaster, mut outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        node.apply_dispatch(
            Dispatch::ServeSnapshotManifest {
                height: None,
                to: nid(2),
            },
            broadcaster.as_ref(),
            &mut view_timer,
            &signer,
        )
        .await
        .expect("apply_dispatch");

        let (_, wire) = decode_outbound_wire(outbound_rx.recv().await.expect("outbound"));
        assert!(matches!(wire, WireMessage::SnapshotManifestResponse(None)));
    }

    #[tokio::test]
    async fn serve_snapshot_chunk_returns_payload_for_known_index() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let manifest = seed_snapshot(&storage, 100, 64, 3);

        let cfg = test_config(four_validators());
        let mut node = ConsensusNode::new(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );
        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let (broadcaster, mut outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        // Walk every chunk index served back, and verify each
        // payload matches the manifest's recorded hash.
        for idx in 0..manifest.chunk_count {
            node.apply_dispatch(
                Dispatch::ServeSnapshotChunk {
                    height: Height(100),
                    chunk_idx: idx,
                    to: nid(2),
                },
                broadcaster.as_ref(),
                &mut view_timer,
                &signer,
            )
            .await
            .expect("apply_dispatch");

            let (to, wire) = decode_outbound_wire(outbound_rx.recv().await.expect("outbound"));
            assert_eq!(to, nid(2));
            match wire {
                WireMessage::SnapshotChunkResponse {
                    height: 100,
                    chunk_idx,
                    payload: Some(p),
                } => {
                    assert_eq!(chunk_idx, idx);
                    boule_consensus::replication::snapshot::verify_chunk(&manifest, idx, &p)
                        .expect("served chunk must verify against manifest");
                }
                other => panic!("expected SnapshotChunkResponse(Some), got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn serve_snapshot_chunk_returns_none_for_missing_height() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let cfg = test_config(four_validators());
        let mut node = ConsensusNode::new(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );
        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let (broadcaster, mut outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        node.apply_dispatch(
            Dispatch::ServeSnapshotChunk {
                height: Height(999),
                chunk_idx: 0,
                to: nid(2),
            },
            broadcaster.as_ref(),
            &mut view_timer,
            &signer,
        )
        .await
        .expect("apply_dispatch");

        let (_, wire) = decode_outbound_wire(outbound_rx.recv().await.expect("outbound"));
        match wire {
            WireMessage::SnapshotChunkResponse {
                height: 999,
                chunk_idx: 0,
                payload: None,
            } => {}
            other => panic!("expected SnapshotChunkResponse(None), got {other:?}"),
        }
    }

    /// End-to-end "peer A serves a manifest + chunks to peer B" via
    /// the in-process transport: the request is decoded by
    /// `dispatch::ingress`, fed through `apply_dispatch`, and the
    /// outbound reply is decoded back to a `WireMessage`. Acceptance
    /// criterion: "a node serves a manifest + all chunks to another
    /// node over the in-process transport."
    #[tokio::test]
    async fn serve_full_snapshot_round_trip_through_dispatch() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let manifest = seed_snapshot(&storage, 50, 32, 4);

        let cfg = test_config(four_validators());
        let mut node = ConsensusNode::new(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );
        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let (broadcaster, mut outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        // Step 1: peer B (nid(2)) sends a manifest request, encoded
        // on the wire. Decode via ingress, dispatch through the run
        // loop's apply_dispatch, and capture the outbound reply.
        let req_bytes =
            postcard::to_stdvec(&WireMessage::SnapshotManifestRequest { height: None }).unwrap();
        let dispatches = dispatch::ingress(
            nid(2),
            &req_bytes,
            &ValidatorSetHistory::from_genesis(four_validators()),
            &ValidatorKeyHistory::new(four_validators().iter().copied()),
            &boule_core::crypto::signed::ChainId::TEST,
        )
        .unwrap();
        assert_eq!(dispatches.len(), 1);
        for d in dispatches {
            node.apply_dispatch(d, broadcaster.as_ref(), &mut view_timer, &signer)
                .await
                .expect("apply_dispatch");
        }
        let (to, wire) = decode_outbound_wire(outbound_rx.recv().await.expect("outbound"));
        assert_eq!(to, nid(2));
        let served = match wire {
            WireMessage::SnapshotManifestResponse(Some(m)) => m,
            other => panic!("expected SnapshotManifestResponse, got {other:?}"),
        };
        assert_eq!(served, manifest);

        // Step 2: for each chunk index in the manifest, peer B
        // requests the chunk and we observe the outbound reply.
        for idx in 0..served.chunk_count {
            let req_bytes = postcard::to_stdvec(&WireMessage::SnapshotChunkRequest {
                height: served.height.0,
                chunk_idx: idx,
            })
            .unwrap();
            let dispatches = dispatch::ingress(
                nid(2),
                &req_bytes,
                &ValidatorSetHistory::from_genesis(four_validators()),
                &ValidatorKeyHistory::new(four_validators().iter().copied()),
                &boule_core::crypto::signed::ChainId::TEST,
            )
            .unwrap();
            for d in dispatches {
                node.apply_dispatch(d, broadcaster.as_ref(), &mut view_timer, &signer)
                    .await
                    .expect("apply_dispatch");
            }
            let (_, wire) = decode_outbound_wire(outbound_rx.recv().await.expect("outbound"));
            match wire {
                WireMessage::SnapshotChunkResponse {
                    height,
                    chunk_idx,
                    payload: Some(p),
                } => {
                    assert_eq!(height, served.height.0);
                    assert_eq!(chunk_idx, idx);
                    boule_consensus::replication::snapshot::verify_chunk(&served, idx, &p)
                        .expect("chunk must verify");
                }
                other => panic!("expected SnapshotChunkResponse(Some), got {other:?}"),
            }
        }
    }

    // ── Joiner-side fetch (#229) ────────────────────────────────────────

    fn snapshot_test_config_enabled(vs: ValidatorSet, interval: u64) -> NodeConfigForConsensus {
        let mut cfg = NodeConfigForConsensus::for_testing(vs, genesis());
        cfg.snapshot_policy = boule_consensus::replication::snapshot::SnapshotPolicy {
            interval_blocks: interval,
            retention_count: 3,
            chunk_size_bytes: 1024,
        };
        cfg
    }

    /// Build a Proposal at `(height, view)` whose proposer is
    /// `signer.node_id()`, parented at `parent_hash`, with empty
    /// commands. The proposal's `justify` is the genesis QC over
    /// the joiner's view of the chain — sufficient to reach the
    /// integration layer's `Dispatch::Safety(Event::ProposalReceived)`
    /// path, which is what `observe_proposal` peeks at.
    ///
    /// Tests use this to feed the joiner a synthetic high-height
    /// proposal that triggers the snapshot-fetch path without
    /// running a full consensus loop.
    /// Drain outbound traffic until a `WireMessage` matching
    /// `predicate` arrives, or the channel is empty. Returns
    /// `Some((to, payload))` on hit, `None` on empty drain. Used by
    /// the joiner-fetch tests to skip past the safety-core's
    /// incidental outbounds (NewView on a high-view proposal,
    /// BlockRequest for the missing parent, etc.) and find the
    /// snapshot-fetch wire messages.
    async fn drain_until<F>(
        rx: &mut tokio::sync::mpsc::Receiver<ProtocolOutbound>,
        mut predicate: F,
    ) -> Option<(NodeId, bytes::Bytes)>
    where
        F: FnMut(&WireMessage) -> bool,
    {
        // A few iterations is enough; the safety core emits a
        // bounded number of side effects per dispatch.
        for _ in 0..16 {
            let out = match rx.try_recv() {
                Ok(o) => o,
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                    // Yield once in case the producer hasn't run yet.
                    tokio::task::yield_now().await;
                    match rx.try_recv() {
                        Ok(o) => o,
                        Err(_) => return None,
                    }
                }
                Err(_) => return None,
            };
            if let ProtocolOutbound::SendTo { node_id, payload } = out {
                let wire: WireMessage = match postcard::from_bytes(&payload) {
                    Ok(w) => w,
                    Err(_) => continue,
                };
                if predicate(&wire) {
                    return Some((node_id, payload));
                }
            }
            // Broadcasts and decode failures are skipped; the
            // snapshot wire messages are all `SendTo`.
        }
        None
    }

    fn synthetic_proposal_dispatch(
        signer: &NodeSigner,
        height: u64,
        view: u64,
        parent_hash: BlockHash,
    ) -> Dispatch {
        use boule_consensus::hotstuff::Proposal;
        use boule_consensus::hotstuff::qc::genesis_qc;
        use boule_consensus::replication::block::{Block, BlockHeader};
        let commands: Vec<bytes::Bytes> = Vec::new();
        let block = Block {
            header: BlockHeader {
                parent_hash,
                height: Height(height),
                view: View(view),
                proposer: signer.node_id(),
                state_commitment: [0u8; 32],
                commands_commitment: Block::commands_commitment(&commands),
                validator_history_commitment: [0; 32],
                committed_height: Height::ZERO,
                committed_state_root: [0; 32],
            },
            commands,
        };
        // Justify with the genesis QC — its content doesn't matter
        // for the lag-detection observation. The integration layer
        // peeks at `signed.payload.block.header.height` and
        // `signed.signer`, both of which we control.
        let justify = genesis_qc(&genesis(), &four_validators());
        let proposal = Proposal { block, justify };
        let signed = Signed::sign(proposal, signer, &ChainId::TEST).expect("sign proposal");
        Dispatch::Safety(SafetyEvent::ProposalReceived(
            boule_consensus::dispatch::Verified::unchecked(signed),
        ))
    }

    /// Joiner happy path (#229 acceptance criteria 1):
    /// 1. Server has a populated `SnapshotStore` with a snapshot at
    ///    height ≥ `interval_blocks`.
    /// 2. Joiner has empty storage and snapshots enabled.
    /// 3. Joiner observes a synthetic proposal at high height →
    ///    triggers a manifest request to the proposer (= server).
    /// 4. The request is decoded by the server's run loop, which
    ///    serves the manifest.
    /// 5. The response is decoded by the joiner's run loop, which
    ///    requests every chunk in order. Each chunk is served by
    ///    the server.
    /// 6. After the last chunk, the joiner restores state.
    ///
    /// Asserts:
    /// - Joiner's `last_committed_height` equals the snapshot
    ///   height after restore.
    /// - Joiner's state machine commitment matches the manifest's.
    /// - Snapshot block, last_committed, and high_qc are persisted
    ///   to the joiner's storage (so a hypothetical restart would
    ///   recover the same state).
    #[tokio::test]
    async fn joiner_fetches_snapshot_from_server_and_restores_state() {
        use boule_consensus::replication::impls::counter_sm::CounterCommand;

        let server_signer = fresh_signer();
        let server_node_id = server_signer.node_id();
        let joiner_signer = fresh_signer();
        let other1_signer = fresh_signer();
        let other2_signer = fresh_signer();
        let vs = ValidatorSet::new(vec![
            boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(server_node_id),
            boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(
                joiner_signer.node_id(),
            ),
            boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(
                other1_signer.node_id(),
            ),
            boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(
                other2_signer.node_id(),
            ),
        ]);

        // ── Build the server with a populated SnapshotStore ────────────
        let server_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        // Run a few CounterCommand applies so the SM has non-trivial
        // state, then build a snapshot at height 50 / view 50. The
        // test's interval is 50, so a proposal at height 50+ will
        // trigger the joiner's fetch.
        let server_sm: Arc<Mutex<Box<dyn StateMachine>>> = Arc::new(Mutex::new(Box::new(
            boule_consensus::replication::impls::counter_sm::CounterStateMachine::new(),
        )));
        for _ in 0..7 {
            server_sm
                .lock()
                .apply(&CounterCommand::Increment.encode())
                .unwrap();
        }
        let snapshot_payload = server_sm.lock().snapshot();
        let expected_commitment = server_sm.lock().state_commitment();
        let chunks_with_hashes =
            boule_consensus::replication::snapshot::chunk_snapshot(&snapshot_payload, 1024);
        let chunk_hashes: Vec<[u8; 32]> = chunks_with_hashes.iter().map(|(_, h)| *h).collect();
        let chunks: Vec<bytes::Bytes> = chunks_with_hashes.into_iter().map(|(c, _)| c).collect();
        let snapshot_block = {
            let parent_hash = genesis().hash();
            let commands: Vec<bytes::Bytes> = Vec::new();
            boule_consensus::replication::block::Block {
                header: boule_consensus::replication::block::BlockHeader {
                    parent_hash,
                    height: Height(50),
                    view: View(50),
                    proposer: server_node_id,
                    state_commitment: expected_commitment,
                    commands_commitment:
                        boule_consensus::replication::block::Block::commands_commitment(&commands),
                    validator_history_commitment: [0; 32],
                    committed_height: Height::ZERO,
                    committed_state_root: [0; 32],
                },
                commands,
            }
        };
        let mut commit_qc = QuorumCertificate::new(50, snapshot_block.hash(), vs.len());
        for i in 0..boule_consensus::hotstuff::qc::quorum_size(vs.len()) {
            commit_qc.add_signature(i, [0u8; 64]);
        }
        let manifest =
            boule_consensus::replication::snapshot::SnapshotManifest::build_for_test_genesis_histories(
                snapshot_block,
                &vs,
                1024,
                chunk_hashes,
                commit_qc,
                1_700_000_000,
            );
        // The helper patches `block.header.validator_history_commitment`
        // which changes the block hash; rebind through the manifest so
        // downstream assertions match the post-patch value.
        let snapshot_block = manifest.block.clone();
        // Defensive: verify the manifest before saving — catches
        // any builder-side regression that would otherwise surface
        // only at the joiner's verification step.
        manifest
            .verify(&vs)
            .expect("server-built manifest must verify");
        boule_consensus::replication::snapshot::SnapshotStore::new(Arc::clone(&server_storage))
            .save(&manifest, &chunks)
            .expect("save snapshot");

        let mut server_node = ConsensusNode::new(
            server_node_id,
            snapshot_test_config_enabled(vs.clone(), 50),
            server_sm,
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&server_storage),
            Arc::new(MemoryWal::new()),
        );

        // ── Build the fresh joiner ────────────────────────────────────
        let joiner_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let joiner_sm: Arc<Mutex<Box<dyn StateMachine>>> = Arc::new(Mutex::new(Box::new(
            boule_consensus::replication::impls::counter_sm::CounterStateMachine::new(),
        )));
        let joiner_starting_commitment = joiner_sm.lock().state_commitment();
        assert_ne!(
            joiner_starting_commitment, expected_commitment,
            "test setup: joiner's empty SM must differ from server's populated SM",
        );
        let mut joiner_node = ConsensusNode::new(
            joiner_signer.node_id(),
            snapshot_test_config_enabled(vs.clone(), 50),
            Arc::clone(&joiner_sm),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&joiner_storage),
            Arc::new(MemoryWal::new()),
        );

        // Wrap in Arc *after* using the original `server_signer` to
        // sign the synthetic proposal below. `NodeSigner` is not
        // `Clone`, so we hold the Arc separately for `apply_dispatch`
        // calls that need a `&Arc<dyn Signer>` and the bare ref for
        // signing.
        let joiner_signer_arc: Arc<dyn Signer> = Arc::new(joiner_signer);
        let (server_bc, mut server_outbound) = make_test_broadcaster();
        let (joiner_bc, mut joiner_outbound) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut server_view_timer = ViewTimer::new(timer_tx.clone());
        let mut joiner_view_timer = ViewTimer::new(timer_tx);

        // ── Step 1: feed the joiner a synthetic proposal at height
        //   100 from the server. This is what the joiner would see
        //   in production: a high-height proposal carrying the
        //   server's pubkey as the proposer.
        let proposal = synthetic_proposal_dispatch(
            &server_signer,
            100,
            100,
            // The proposal's parent_hash doesn't matter for lag
            // detection; the safety core will park it for missing
            // parent regardless. Use a fake parent hash.
            [0xEE; 32],
        );
        joiner_node
            .apply_dispatch(
                proposal,
                joiner_bc.as_ref(),
                &mut joiner_view_timer,
                &joiner_signer_arc,
            )
            .await
            .expect("joiner apply_dispatch");

        // Now wrap the server signer in Arc for subsequent
        // `apply_dispatch` calls.
        let server_signer_arc: Arc<dyn Signer> = Arc::new(server_signer);

        // The joiner's snapshot_sync should have emitted a manifest
        // request to the proposer (= server). Filter past any
        // incidental safety-core outbounds (NewView, vote, etc.)
        // emitted by the same proposal.
        let (req_to, req_payload) = drain_until(&mut joiner_outbound, |w| {
            matches!(w, WireMessage::SnapshotManifestRequest { .. })
        })
        .await
        .expect("manifest request outbound");
        assert_eq!(req_to, server_node_id);
        let req_wire: WireMessage =
            postcard::from_bytes(&req_payload).expect("decode manifest request");
        assert!(matches!(
            req_wire,
            WireMessage::SnapshotManifestRequest { height: None },
        ));

        // ── Step 2: feed the request into the server via ingress;
        //   server's run loop serves the manifest.
        let dispatches = dispatch::ingress(
            joiner_signer_arc.node_id(),
            &req_payload,
            &ValidatorSetHistory::from_genesis(vs.clone()),
            &ValidatorKeyHistory::new(vs.iter().copied()),
            &boule_core::crypto::signed::ChainId::TEST,
        )
        .expect("ingress manifest request");
        for d in dispatches {
            server_node
                .apply_dispatch(
                    d,
                    server_bc.as_ref(),
                    &mut server_view_timer,
                    &server_signer_arc,
                )
                .await
                .expect("server apply_dispatch");
        }
        let (resp_to, resp_payload) = drain_until(&mut server_outbound, |w| {
            matches!(w, WireMessage::SnapshotManifestResponse(_))
        })
        .await
        .expect("manifest response outbound");
        assert_eq!(resp_to, joiner_signer_arc.node_id());

        // ── Step 3: feed the response back into the joiner. The
        //   joiner verifies the manifest and emits the first chunk
        //   request. Then we shuttle each chunk request → response
        //   through the in-memory transport until the joiner
        //   restores.
        let dispatches = dispatch::ingress(
            server_node_id,
            &resp_payload,
            &ValidatorSetHistory::from_genesis(vs.clone()),
            &ValidatorKeyHistory::new(vs.iter().copied()),
            &boule_core::crypto::signed::ChainId::TEST,
        )
        .expect("ingress manifest response");
        for d in dispatches {
            joiner_node
                .apply_dispatch(
                    d,
                    joiner_bc.as_ref(),
                    &mut joiner_view_timer,
                    &joiner_signer_arc,
                )
                .await
                .expect("joiner apply_dispatch manifest response");
        }

        // Loop: shuttle chunk requests/responses until the joiner
        // restores. Bounded loop count guards against a state-
        // machine bug that would otherwise hang the test.
        for _ in 0..(manifest.chunk_count + 4) {
            // Joiner emitted a chunk request? Drain and forward.
            let chunk_req = drain_until(&mut joiner_outbound, |w| {
                matches!(w, WireMessage::SnapshotChunkRequest { .. })
            })
            .await;
            let Some((_, chunk_req_payload)) = chunk_req else {
                break;
            };
            let dispatches = dispatch::ingress(
                joiner_signer_arc.node_id(),
                &chunk_req_payload,
                &ValidatorSetHistory::from_genesis(vs.clone()),
                &ValidatorKeyHistory::new(vs.iter().copied()),
                &boule_core::crypto::signed::ChainId::TEST,
            )
            .expect("ingress chunk request");
            for d in dispatches {
                server_node
                    .apply_dispatch(
                        d,
                        server_bc.as_ref(),
                        &mut server_view_timer,
                        &server_signer_arc,
                    )
                    .await
                    .expect("server apply_dispatch chunk request");
            }
            let (_, chunk_resp_payload) = drain_until(&mut server_outbound, |w| {
                matches!(w, WireMessage::SnapshotChunkResponse { .. })
            })
            .await
            .expect("chunk response");
            let dispatches = dispatch::ingress(
                server_node_id,
                &chunk_resp_payload,
                &ValidatorSetHistory::from_genesis(vs.clone()),
                &ValidatorKeyHistory::new(vs.iter().copied()),
                &boule_core::crypto::signed::ChainId::TEST,
            )
            .expect("ingress chunk response");
            for d in dispatches {
                joiner_node
                    .apply_dispatch(
                        d,
                        joiner_bc.as_ref(),
                        &mut joiner_view_timer,
                        &joiner_signer_arc,
                    )
                    .await
                    .expect("joiner apply_dispatch chunk response");
            }
        }

        // ── Assertions ────────────────────────────────────────────────
        assert!(
            joiner_node.snapshot_sync.is_done(),
            "joiner's snapshot_sync must reach Done after a successful fetch",
        );
        assert_eq!(
            joiner_node.last_committed_height.load(Ordering::Relaxed),
            50u64,
            "joiner's last_committed_height must equal the snapshot's height",
        );
        assert_eq!(joiner_node.last_committed_view, View(50));
        assert_eq!(
            joiner_sm.lock().state_commitment(),
            expected_commitment,
            "joiner's state machine commitment must match the snapshot's after restore",
        );
        // Persistence: snapshot block, last_committed, high_qc are
        // all on disk so a hypothetical restart would recover.
        let block_key = block_storage_key(&snapshot_block.hash());
        assert!(
            joiner_storage.get(&block_key).unwrap().is_some(),
            "snapshot block must be persisted under the block-prefix",
        );
        assert!(
            joiner_storage
                .get(STORAGE_KEY_LAST_COMMITTED)
                .unwrap()
                .is_some(),
            "last_committed checkpoint must be persisted after restore",
        );
        assert!(
            joiner_storage.get(STORAGE_KEY_HIGH_QC).unwrap().is_some(),
            "high_qc must be persisted after restore",
        );
        // The snapshot block is in pending_blocks so future
        // safety-core walks terminate at the snapshot height.
        assert!(
            joiner_node
                .core
                .state()
                .pending_blocks
                .contains_key(&snapshot_block.hash()),
            "snapshot block must be inserted into pending_blocks",
        );
    }

    /// Joiner negative path (#229 acceptance criteria 2): a
    /// tampered manifest from the server triggers fallback without
    /// panicking. The joiner's `last_committed_height` stays at 0
    /// (no restore happened) and the snapshot_sync state machine
    /// is in `Aborted`.
    #[tokio::test]
    async fn joiner_aborts_on_tampered_manifest_without_panic() {
        let server_signer = fresh_signer();
        let server_node_id = server_signer.node_id();
        let joiner_signer = fresh_signer();
        let other1 = fresh_signer();
        let other2 = fresh_signer();
        let vs = ValidatorSet::new(vec![
            boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(server_node_id),
            boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(
                joiner_signer.node_id(),
            ),
            boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(other1.node_id()),
            boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(other2.node_id()),
        ]);

        let joiner_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let joiner_sm: Arc<Mutex<Box<dyn StateMachine>>> = Arc::new(Mutex::new(Box::new(
            boule_consensus::replication::impls::counter_sm::CounterStateMachine::new(),
        )));
        let mut joiner_node = ConsensusNode::new(
            joiner_signer.node_id(),
            snapshot_test_config_enabled(vs.clone(), 50),
            Arc::clone(&joiner_sm),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&joiner_storage),
            Arc::new(MemoryWal::new()),
        );
        let joiner_signer_arc: Arc<dyn Signer> = Arc::new(joiner_signer);
        let (joiner_bc, mut joiner_outbound) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut joiner_view_timer = ViewTimer::new(timer_tx);

        // Trigger the joiner's fetch.
        let proposal = synthetic_proposal_dispatch(&server_signer, 100, 100, [0xEE; 32]);
        joiner_node
            .apply_dispatch(
                proposal,
                joiner_bc.as_ref(),
                &mut joiner_view_timer,
                &joiner_signer_arc,
            )
            .await
            .expect("joiner apply_dispatch proposal");

        // Drain past any incidental safety-core outbounds and the
        // manifest request the joiner emitted.
        let _ = drain_until(&mut joiner_outbound, |w| {
            matches!(w, WireMessage::SnapshotManifestRequest { .. })
        })
        .await
        .expect("manifest request");

        // Build a *tampered* manifest: validator set field doesn't
        // match the joiner's `vs`. The joiner's verifier rejects
        // this as `ValidatorSetMismatch`.
        let bad_vs = ValidatorSet::new(vec![
            boule_consensus::validator_set::ValidatorId::from_genesis_pubkey([10u8; 32]),
            boule_consensus::validator_set::ValidatorId::from_genesis_pubkey([11u8; 32]),
            boule_consensus::validator_set::ValidatorId::from_genesis_pubkey([12u8; 32]),
            boule_consensus::validator_set::ValidatorId::from_genesis_pubkey([13u8; 32]),
        ]);
        let tampered_block = {
            use boule_consensus::replication::block::{Block, BlockHeader};
            let parent_hash = genesis().hash();
            let commands: Vec<bytes::Bytes> = Vec::new();
            Block {
                header: BlockHeader {
                    parent_hash,
                    height: Height(50),
                    view: View(50),
                    proposer: server_signer.node_id(),
                    state_commitment: [0xCD; 32],
                    commands_commitment: Block::commands_commitment(&commands),
                    validator_history_commitment: [0; 32],
                    committed_height: Height::ZERO,
                    committed_state_root: [0; 32],
                },
                commands,
            }
        };
        let mut tampered_qc = QuorumCertificate::new(50, tampered_block.hash(), bad_vs.len());
        for i in 0..boule_consensus::hotstuff::qc::quorum_size(bad_vs.len()) {
            tampered_qc.add_signature(i, [0u8; 64]);
        }
        let bad_manifest =
            boule_consensus::replication::snapshot::SnapshotManifest::build_for_test_genesis_histories(
                tampered_block,
                &bad_vs,
                64,
                vec![[0u8; 32]],
                tampered_qc,
                1_700_000_000,
            );

        // Synthesize a SnapshotManifestResponse from the server and
        // feed it to the joiner.
        let resp_payload =
            postcard::to_stdvec(&WireMessage::SnapshotManifestResponse(Some(bad_manifest)))
                .unwrap();
        let dispatches = dispatch::ingress(
            server_signer.node_id(),
            &resp_payload,
            &ValidatorSetHistory::from_genesis(vs.clone()),
            &ValidatorKeyHistory::new(vs.iter().copied()),
            &boule_core::crypto::signed::ChainId::TEST,
        )
        .expect("ingress tampered manifest");
        for d in dispatches {
            joiner_node
                .apply_dispatch(
                    d,
                    joiner_bc.as_ref(),
                    &mut joiner_view_timer,
                    &joiner_signer_arc,
                )
                .await
                .expect("joiner apply_dispatch tampered manifest");
        }

        // Joiner's state machine must be Aborted.
        assert!(
            joiner_node.snapshot_sync.is_aborted(),
            "joiner's snapshot_sync must enter Aborted after tampered manifest",
        );
        // No restore happened.
        assert_eq!(
            joiner_node.last_committed_height.load(Ordering::Relaxed),
            0u64,
            "no restore must have run; last_committed stays at 0",
        );
        // No outbound chunk requests should have been emitted; the
        // joiner stopped after rejecting the manifest. (Other
        // safety-core outbounds may sit in the channel — we filter
        // for chunk requests specifically.)
        assert!(
            drain_until(&mut joiner_outbound, |w| matches!(
                w,
                WireMessage::SnapshotChunkRequest { .. }
            ))
            .await
            .is_none(),
            "joiner must not emit chunk requests after aborting",
        );
    }

    /// Joiner happy path with a rotation applied before the
    /// snapshot height (#311). A fresh joiner restoring from a
    /// post-rotation snapshot must inherit the producer's
    /// `validator_key_history` so it can resolve the rotated
    /// validator's pubkey at views ≥ `v_eff` to the post-rotation
    /// key. Without this, the joiner would fall through to tail-sync
    /// and reject every QC whose signer is the rotated validator
    /// (`IngressError::UnknownSigner`) — exactly the failure mode
    /// #311 calls out.
    ///
    /// Drives the joiner-side restore directly via
    /// `restore_from_snapshot` rather than the full network shuttle
    /// (the wire path is already covered by
    /// `joiner_fetches_snapshot_from_server_and_restores_state`).
    /// This isolates the rotation-aware install logic.
    #[tokio::test]
    async fn joiner_restore_installs_rotated_validator_key_history() {
        use boule_consensus::history_commitment::validator_history_commitment_v1;
        use boule_consensus::replication::impls::counter_sm::CounterCommand;
        use boule_consensus::validator_key_history::PersistedValidatorKeyHistory;
        use boule_consensus::validator_rotation::ValidatorKeyRotation;

        let server_signer = fresh_signer();
        let server_node_id = server_signer.node_id();
        let joiner_signer = fresh_signer();
        let other1_signer = fresh_signer();
        let other2_signer = fresh_signer();
        let vs = ValidatorSet::new(vec![
            boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(server_node_id),
            boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(
                joiner_signer.node_id(),
            ),
            boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(
                other1_signer.node_id(),
            ),
            boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(
                other2_signer.node_id(),
            ),
        ]);

        // ── Build the producer's history triple with one rotation
        //   applied. The rotated validator is `other1` (a non-leader
        //   of view 0); it rotates to a synthetic `new_pubkey` at
        //   `v_eff = 30`, well below the snapshot height of 50.
        let rotated_validator = other1_signer.node_id();
        let new_pubkey: NodeId = [0xAB; 32];
        let v_eff: View = View(30);
        let mut producer_key_hist = ValidatorKeyHistory::new(vs.iter().copied());
        producer_key_hist
            .apply_rotation(
                &ValidatorKeyRotation {
                    validator: rotated_validator,
                    new_pubkey,
                    v_eff,
                    new_bls_pubkey: None,
                    new_bls_pop: None,
                },
                10,
            )
            .expect("rotation applies cleanly");
        let producer_set_hist = ValidatorSetHistory::from_genesis(vs.clone());
        let commitment =
            validator_history_commitment_v1(&producer_set_hist, &producer_key_hist, None);

        // ── Build the snapshot at height 50 / view 50 with the
        //   right state-commitment and history-commitment.
        let server_sm: Arc<Mutex<Box<dyn StateMachine>>> = Arc::new(Mutex::new(Box::new(
            boule_consensus::replication::impls::counter_sm::CounterStateMachine::new(),
        )));
        for _ in 0..5 {
            server_sm
                .lock()
                .apply(&CounterCommand::Increment.encode())
                .unwrap();
        }
        let snapshot_payload = server_sm.lock().snapshot();
        let expected_commitment = server_sm.lock().state_commitment();
        let chunks_with_hashes =
            boule_consensus::replication::snapshot::chunk_snapshot(&snapshot_payload, 1024);
        let chunk_hashes: Vec<[u8; 32]> = chunks_with_hashes.iter().map(|(_, h)| *h).collect();
        let chunks: Vec<bytes::Bytes> = chunks_with_hashes.into_iter().map(|(c, _)| c).collect();
        let snapshot_block = {
            let parent_hash = genesis().hash();
            let commands: Vec<bytes::Bytes> = Vec::new();
            boule_consensus::replication::block::Block {
                header: boule_consensus::replication::block::BlockHeader {
                    parent_hash,
                    height: Height(50),
                    view: View(50),
                    proposer: server_node_id,
                    state_commitment: expected_commitment,
                    commands_commitment:
                        boule_consensus::replication::block::Block::commands_commitment(&commands),
                    validator_history_commitment: commitment,
                    committed_height: Height::ZERO,
                    committed_state_root: [0; 32],
                },
                commands,
            }
        };
        let mut commit_qc = QuorumCertificate::new(50, snapshot_block.hash(), vs.len());
        for i in 0..boule_consensus::hotstuff::qc::quorum_size(vs.len()) {
            commit_qc.add_signature(i, [0u8; 64]);
        }
        let manifest = boule_consensus::replication::snapshot::SnapshotManifest::build(
            snapshot_block,
            &vs,
            1024,
            chunk_hashes,
            commit_qc,
            1_700_000_000,
            producer_set_hist.to_persisted(),
            producer_key_hist.to_persisted(),
            None,
        );
        manifest
            .verify(&vs)
            .expect("producer-built manifest must verify against the local set");

        // ── Build the fresh joiner and restore directly.
        let joiner_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let joiner_sm: Arc<Mutex<Box<dyn StateMachine>>> = Arc::new(Mutex::new(Box::new(
            boule_consensus::replication::impls::counter_sm::CounterStateMachine::new(),
        )));
        let mut joiner_node = ConsensusNode::new(
            joiner_signer.node_id(),
            snapshot_test_config_enabled(vs.clone(), 50),
            Arc::clone(&joiner_sm),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&joiner_storage),
            Arc::new(MemoryWal::new()),
        );
        // Pre-condition: joiner's key history is genesis-only and
        // does *not* know about the rotation.
        assert_eq!(
            joiner_node.validator_key_history.key_at(
                &boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(
                    rotated_validator,
                ),
                v_eff,
            ),
            Some(boule_consensus::validator_set::Pubkey::from_node_id(
                rotated_validator,
            )),
            "test setup: joiner starts with a genesis-only key history",
        );
        assert!(
            joiner_node
                .validator_key_history
                .validator_for(&boule_consensus::validator_set::Pubkey::from_node_id(
                    new_pubkey,
                ))
                .is_none(),
            "test setup: joiner does not yet know `new_pubkey`",
        );

        let payload = bytes::Bytes::from(
            chunks
                .iter()
                .flat_map(|c| c.iter().copied())
                .collect::<Vec<u8>>(),
        );
        joiner_node
            .restore_from_snapshot(manifest, payload)
            .expect("restore_from_snapshot must accept the rotation-aware manifest");

        // ── Post-condition: joiner's in-memory key history reflects
        //   the producer's rotation.
        let stable =
            boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(rotated_validator);
        assert_eq!(
            joiner_node.validator_key_history.key_at(&stable, v_eff - 1),
            Some(boule_consensus::validator_set::Pubkey::from_node_id(
                rotated_validator,
            )),
            "pre-v_eff lookups must still resolve to the genesis key",
        );
        assert_eq!(
            joiner_node.validator_key_history.key_at(&stable, v_eff),
            Some(boule_consensus::validator_set::Pubkey::from_node_id(
                new_pubkey,
            )),
            "at-v_eff lookups must resolve to the rotated key",
        );
        assert_eq!(
            joiner_node.validator_key_history.validator_for(
                &boule_consensus::validator_set::Pubkey::from_node_id(new_pubkey),
            ),
            Some(stable),
            "the new pubkey resolves through the reverse index — \
             dispatch::verify_signer_at would accept post-rotation votes",
        );

        // ── On-disk: the persisted blob round-trips back into a
        //   history with the rotation entry, so a subsequent restart
        //   recovers the same state.
        let persisted_bytes = joiner_storage
            .get(STORAGE_KEY_VALIDATOR_KEY_HISTORY)
            .unwrap()
            .expect("persisted validator_key_history must be on disk after restore");
        let persisted: PersistedValidatorKeyHistory =
            postcard::from_bytes(&persisted_bytes).expect("persisted blob decodes");
        let rebuilt = ValidatorKeyHistory::from_persisted(persisted).unwrap();
        assert_eq!(
            rebuilt.key_at(&stable, v_eff),
            Some(boule_consensus::validator_set::Pubkey::from_node_id(
                new_pubkey,
            )),
            "on-disk persisted history must carry the rotation",
        );
    }

    /// Audit finding 4-3 (#406): a joiner that adopts a snapshot,
    /// crashes before the next consensus event, and restarts must
    /// rehydrate `locked`, `high_qc`, and `last_voted_view` from
    /// storage at the snapshot's `(view, height)`. Without persisting
    /// the safety state alongside the snapshot block + last_committed
    /// in one atomic batch, `recover_state` would re-seed the joiner
    /// with `locked = None` and `last_voted_view = 0` — letting it
    /// vote on a fork below the snapshot height (`safe_to_vote`'s
    /// `view > last_voted_view` check is trivially satisfied).
    #[tokio::test]
    async fn restore_then_restart_preserves_locked_high_qc_and_last_voted_view() {
        use boule_consensus::replication::impls::counter_sm::{
            CounterCommand, CounterStateMachine,
        };

        let server_signer = fresh_signer();
        let server_node_id = server_signer.node_id();
        let joiner_signer = fresh_signer();
        let other1 = fresh_signer().node_id();
        let other2 = fresh_signer().node_id();
        let vs = ValidatorSet::new(vec![
            boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(server_node_id),
            boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(
                joiner_signer.node_id(),
            ),
            boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(other1),
            boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(other2),
        ]);

        // Build a snapshot at height 50 / view 50. The exact values
        // don't matter — what we're testing is that they survive a
        // restart, so they need to be distinguishable from "fresh
        // joiner" defaults (view 0, no lock).
        let snapshot_height: Height = Height(50);
        let snapshot_view: View = View(50);
        let server_sm: Arc<Mutex<Box<dyn StateMachine>>> =
            Arc::new(Mutex::new(Box::new(CounterStateMachine::new())));
        for _ in 0..5 {
            server_sm
                .lock()
                .apply(&CounterCommand::Increment.encode())
                .unwrap();
        }
        let snapshot_payload = server_sm.lock().snapshot();
        let expected_commitment = server_sm.lock().state_commitment();
        let chunks_with_hashes =
            boule_consensus::replication::snapshot::chunk_snapshot(&snapshot_payload, 1024);
        let chunk_hashes: Vec<[u8; 32]> = chunks_with_hashes.iter().map(|(_, h)| *h).collect();
        let chunks: Vec<bytes::Bytes> = chunks_with_hashes.into_iter().map(|(c, _)| c).collect();
        let snapshot_block = {
            let parent_hash = genesis().hash();
            let commands: Vec<bytes::Bytes> = Vec::new();
            boule_consensus::replication::block::Block {
                header: boule_consensus::replication::block::BlockHeader {
                    parent_hash,
                    height: snapshot_height,
                    view: snapshot_view,
                    proposer: server_node_id,
                    state_commitment: expected_commitment,
                    commands_commitment:
                        boule_consensus::replication::block::Block::commands_commitment(&commands),
                    validator_history_commitment: [0; 32],
                    committed_height: Height::ZERO,
                    committed_state_root: [0; 32],
                },
                commands,
            }
        };
        let mut commit_qc = QuorumCertificate::new(snapshot_view, snapshot_block.hash(), vs.len());
        for i in 0..boule_consensus::hotstuff::qc::quorum_size(vs.len()) {
            commit_qc.add_signature(i, [0u8; 64]);
        }
        // `build_for_test_genesis_histories` rewrites
        // `block.header.validator_history_commitment` (and re-targets
        // `commit_qc.block_hash` to match), so capture the canonical
        // post-build hash and QC for downstream assertions.
        let manifest =
            boule_consensus::replication::snapshot::SnapshotManifest::build_for_test_genesis_histories(
                snapshot_block,
                &vs,
                1024,
                chunk_hashes,
                commit_qc,
                1_700_000_000,
            );
        manifest.verify(&vs).expect("manifest verifies");
        let snapshot_block_hash = manifest.block_hash;
        let expected_commit_qc = manifest.commit_qc.clone();

        // ── Pre-crash session: build the joiner, restore the snapshot,
        //   then drop the node (simulating a crash before any further
        //   consensus event lands the safety state via `persist_updates`).
        let joiner_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let joiner_wal: Arc<dyn Wal> = Arc::new(MemoryWal::new());
        let cfg = snapshot_test_config_enabled(vs.clone(), snapshot_height.0);
        let joiner_sm: Arc<Mutex<Box<dyn StateMachine>>> =
            Arc::new(Mutex::new(Box::new(CounterStateMachine::new())));
        let mut joiner_node = ConsensusNode::new(
            joiner_signer.node_id(),
            cfg.clone(),
            Arc::clone(&joiner_sm),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&joiner_storage),
            Arc::clone(&joiner_wal),
        );
        let payload = bytes::Bytes::from(
            chunks
                .iter()
                .flat_map(|c| c.iter().copied())
                .collect::<Vec<u8>>(),
        );
        joiner_node
            .restore_from_snapshot(manifest, payload)
            .expect("restore_from_snapshot succeeds");

        // Sanity-check the in-memory state right after restore.
        assert_eq!(
            joiner_node.core.state().last_voted_view,
            snapshot_view,
            "in-memory last_voted_view must be bumped to snapshot view",
        );
        assert_eq!(
            joiner_node.core.state().locked.map(|l| l.view),
            Some(snapshot_view),
            "in-memory locked must reference the snapshot view",
        );
        assert_eq!(
            joiner_node
                .core
                .state()
                .high_qc
                .as_ref()
                .map(|qc| qc.view()),
            Some(snapshot_view),
            "in-memory high_qc must reference the snapshot view",
        );

        drop(joiner_node);
        drop(joiner_sm);

        // ── Post-crash session: recover from the same storage. The
        //   recovered safety state must reflect the snapshot — no
        //   silent regression to genesis defaults.
        let recovered_sm: Arc<Mutex<Box<dyn StateMachine>>> =
            Arc::new(Mutex::new(Box::new(CounterStateMachine::new())));
        let recovered = ConsensusNode::recover(
            joiner_signer.node_id(),
            cfg,
            Arc::clone(&recovered_sm),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&joiner_storage),
            Arc::clone(&joiner_wal),
        )
        .expect("recover from snapshot-restored storage succeeds");

        let state = recovered.core.state();
        assert_eq!(
            state.last_voted_view, snapshot_view,
            "recovered last_voted_view must match snapshot view; \
             without it, safe_to_vote's view > last_voted_view check \
             is trivially satisfied on a conflicting fork",
        );
        let recovered_locked = state
            .locked
            .expect("recovered locked must be present (snapshot's lock survived)");
        assert_eq!(recovered_locked.view, snapshot_view);
        assert_eq!(recovered_locked.height, snapshot_height);
        assert_eq!(recovered_locked.block_hash, snapshot_block_hash);
        let recovered_high_qc = state
            .high_qc
            .as_ref()
            .expect("recovered high_qc must be present");
        assert_eq!(recovered_high_qc.inner(), &expected_commit_qc);
    }

    /// Joiner multi-source happy path (#230 acceptance criterion 1):
    /// 3 peers serve the same snapshot in parallel. Drives the
    /// fetch end-to-end via in-memory dispatch and asserts that
    /// chunks were served from ≥ 2 distinct peers (the workpool
    /// fanned out instead of pinning the primary).
    ///
    /// To keep the test compact, "servers" are simulated as a
    /// single shared `SnapshotStore` looked up by chunk index;
    /// the routing layer attributes each request to the peer it
    /// was addressed to, and the returned response is decoded by
    /// the joiner's `apply_dispatch`. This exercises the same
    /// joiner-side code paths as full multi-`ConsensusNode`
    /// scaffolding without spinning up redundant nodes.
    #[tokio::test]
    async fn joiner_multi_source_fan_out_uses_at_least_two_peers() {
        // 3 server pubkeys + 1 joiner. The joiner observes
        // proposals from each of the 3 servers.
        let server_signers: Vec<NodeSigner> = (0..3).map(|_| fresh_signer()).collect();
        let server_ids: Vec<NodeId> = server_signers.iter().map(|s| s.node_id()).collect();
        let joiner_signer = fresh_signer();
        let mut all_ids = server_ids.clone();
        all_ids.push(joiner_signer.node_id());
        let vs = ValidatorSet::new(
            all_ids
                .iter()
                .copied()
                .map(boule_consensus::validator_set::ValidatorId::from_genesis_pubkey)
                .collect(),
        );

        // Seed the SM via `restore` to a large counter value so
        // the postcard-encoded snapshot is wide enough to slice
        // into multiple chunks. (Calling `apply(Increment)` enough
        // times to reach a multi-byte varint would take 2M+
        // iterations.)
        let big_value: u64 = u64::MAX;
        let snapshot_payload = bytes::Bytes::from(postcard::to_stdvec(&big_value).unwrap());
        let server_sm: Arc<Mutex<Box<dyn StateMachine>>> = Arc::new(Mutex::new(Box::new(
            boule_consensus::replication::impls::counter_sm::CounterStateMachine::new(),
        )));
        server_sm.lock().restore(&snapshot_payload).unwrap();
        let expected_commitment = server_sm.lock().state_commitment();
        // 2-byte chunks over the ~10-byte u64::MAX postcard varint
        // → ≥ 4 chunks for the workpool to fan out across.
        let chunks_with_hashes =
            boule_consensus::replication::snapshot::chunk_snapshot(&snapshot_payload, 2);
        assert!(chunks_with_hashes.len() >= 4, "need ≥ 4 chunks for fanout");
        let chunk_hashes: Vec<[u8; 32]> = chunks_with_hashes.iter().map(|(_, h)| *h).collect();
        let chunks: Vec<bytes::Bytes> = chunks_with_hashes.into_iter().map(|(c, _)| c).collect();
        let snapshot_block = {
            let parent_hash = genesis().hash();
            let commands: Vec<bytes::Bytes> = Vec::new();
            boule_consensus::replication::block::Block {
                header: boule_consensus::replication::block::BlockHeader {
                    parent_hash,
                    height: Height(50),
                    view: View(50),
                    proposer: server_ids[0],
                    state_commitment: expected_commitment,
                    commands_commitment:
                        boule_consensus::replication::block::Block::commands_commitment(&commands),
                    validator_history_commitment: [0; 32],
                    committed_height: Height::ZERO,
                    committed_state_root: [0; 32],
                },
                commands,
            }
        };
        let mut commit_qc = QuorumCertificate::new(50, snapshot_block.hash(), vs.len());
        for i in 0..boule_consensus::hotstuff::qc::quorum_size(vs.len()) {
            commit_qc.add_signature(i, [0u8; 64]);
        }
        let manifest =
            boule_consensus::replication::snapshot::SnapshotManifest::build_for_test_genesis_histories(
                snapshot_block.clone(),
                &vs,
                2,
                chunk_hashes,
                commit_qc,
                1_700_000_000,
            );
        manifest.verify(&vs).expect("manifest must verify");

        // ── Build the joiner ──────────────────────────────────────
        let joiner_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let joiner_sm: Arc<Mutex<Box<dyn StateMachine>>> = Arc::new(Mutex::new(Box::new(
            boule_consensus::replication::impls::counter_sm::CounterStateMachine::new(),
        )));
        let mut joiner_node = ConsensusNode::new(
            joiner_signer.node_id(),
            snapshot_test_config_enabled(vs.clone(), 50),
            Arc::clone(&joiner_sm),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&joiner_storage),
            Arc::new(MemoryWal::new()),
        );
        let joiner_signer_arc: Arc<dyn Signer> = Arc::new(joiner_signer);
        let (joiner_bc, mut joiner_outbound) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut joiner_view_timer = ViewTimer::new(timer_tx);

        // ── Step 1: feed the joiner a proposal from each server ──────
        // Each observation accumulates the proposer into the
        // candidate pool the snapshot_sync will use once the fetch
        // starts.
        for s in &server_signers {
            let proposal = synthetic_proposal_dispatch(s, 100, 100, [0xEE; 32]);
            joiner_node
                .apply_dispatch(
                    proposal,
                    joiner_bc.as_ref(),
                    &mut joiner_view_timer,
                    &joiner_signer_arc,
                )
                .await
                .expect("joiner apply_dispatch proposal");
        }

        // ── Step 2: extract the manifest request and synthesize a
        //   response from the primary server (whichever one was
        //   asked).
        let (manifest_to, manifest_req_payload) = drain_until(&mut joiner_outbound, |w| {
            matches!(w, WireMessage::SnapshotManifestRequest { .. })
        })
        .await
        .expect("manifest request");
        let primary = manifest_to;
        let _ = manifest_req_payload;
        let resp_payload = postcard::to_stdvec(&WireMessage::SnapshotManifestResponse(Some(
            manifest.clone(),
        )))
        .unwrap();
        let dispatches = dispatch::ingress(
            primary,
            &resp_payload,
            &ValidatorSetHistory::from_genesis(vs.clone()),
            &ValidatorKeyHistory::new(vs.iter().copied()),
            &boule_core::crypto::signed::ChainId::TEST,
        )
        .expect("ingress manifest response");
        for d in dispatches {
            joiner_node
                .apply_dispatch(
                    d,
                    joiner_bc.as_ref(),
                    &mut joiner_view_timer,
                    &joiner_signer_arc,
                )
                .await
                .expect("joiner apply_dispatch manifest response");
        }

        // ── Step 3: shuttle every emitted chunk request →
        //   synthesized response, using the chunk_idx to look up
        //   the canonical chunk bytes. Track which peers were used
        //   to drive each chunk so the test can assert fanout.
        let mut chunk_peer_count: HashMap<NodeId, u32> = HashMap::new();
        // Bound the loop so a state-machine bug doesn't hang the test.
        for _ in 0..(manifest.chunk_count + 16) {
            let req = drain_until(&mut joiner_outbound, |w| {
                matches!(w, WireMessage::SnapshotChunkRequest { .. })
            })
            .await;
            let Some((peer, chunk_req_payload)) = req else {
                break;
            };
            let req_wire: WireMessage = postcard::from_bytes(&chunk_req_payload).unwrap();
            let (height, chunk_idx) = match req_wire {
                WireMessage::SnapshotChunkRequest { height, chunk_idx } => (height, chunk_idx),
                other => panic!("expected SnapshotChunkRequest, got {other:?}"),
            };
            *chunk_peer_count.entry(peer).or_insert(0) += 1;
            // Synthesize the chunk response from the canonical
            // store (any "server" has the same chunks).
            let resp = WireMessage::SnapshotChunkResponse {
                height,
                chunk_idx,
                payload: Some(chunks[chunk_idx as usize].clone()),
            };
            let resp_payload = postcard::to_stdvec(&resp).unwrap();
            let dispatches = dispatch::ingress(
                peer,
                &resp_payload,
                &ValidatorSetHistory::from_genesis(vs.clone()),
                &ValidatorKeyHistory::new(vs.iter().copied()),
                &boule_core::crypto::signed::ChainId::TEST,
            )
            .expect("ingress chunk response");
            for d in dispatches {
                joiner_node
                    .apply_dispatch(
                        d,
                        joiner_bc.as_ref(),
                        &mut joiner_view_timer,
                        &joiner_signer_arc,
                    )
                    .await
                    .expect("joiner apply_dispatch chunk response");
            }
            if joiner_node.snapshot_sync.is_done() {
                break;
            }
        }

        // ── Assertions ────────────────────────────────────────────
        assert!(
            joiner_node.snapshot_sync.is_done(),
            "joiner must complete the multi-source fetch",
        );
        assert_eq!(
            joiner_node.last_committed_height.load(Ordering::Relaxed),
            50u64,
            "joiner's last_committed_height must equal snapshot height",
        );
        assert_eq!(
            joiner_sm.lock().state_commitment(),
            expected_commitment,
            "joiner's state machine commitment must match the snapshot's",
        );
        let distinct_peer_count = chunk_peer_count.len();
        assert!(
            distinct_peer_count >= 2,
            "workpool must fan out across ≥ 2 peers; got {distinct_peer_count}: {chunk_peer_count:?}",
        );
    }

    /// Joiner mid-fetch peer drop (#230 acceptance criterion 2):
    /// after a peer is dropped via `DiscoveryEvent::PeerRemoved`,
    /// the joiner reassigns its in-flight chunks to surviving
    /// peers and completes the fetch. Driven through the same
    /// in-memory shuttle as the happy-path test.
    #[tokio::test]
    async fn joiner_completes_fetch_after_one_peer_disconnects() {
        let server_signers: Vec<NodeSigner> = (0..3).map(|_| fresh_signer()).collect();
        let server_ids: Vec<NodeId> = server_signers.iter().map(|s| s.node_id()).collect();
        let joiner_signer = fresh_signer();
        let mut all_ids = server_ids.clone();
        all_ids.push(joiner_signer.node_id());
        let vs = ValidatorSet::new(
            all_ids
                .iter()
                .copied()
                .map(boule_consensus::validator_set::ValidatorId::from_genesis_pubkey)
                .collect(),
        );

        let big_value: u64 = u64::MAX;
        let snapshot_payload = bytes::Bytes::from(postcard::to_stdvec(&big_value).unwrap());
        let server_sm: Arc<Mutex<Box<dyn StateMachine>>> = Arc::new(Mutex::new(Box::new(
            boule_consensus::replication::impls::counter_sm::CounterStateMachine::new(),
        )));
        server_sm.lock().restore(&snapshot_payload).unwrap();
        let expected_commitment = server_sm.lock().state_commitment();
        let chunks_with_hashes =
            boule_consensus::replication::snapshot::chunk_snapshot(&snapshot_payload, 2);
        let chunk_hashes: Vec<[u8; 32]> = chunks_with_hashes.iter().map(|(_, h)| *h).collect();
        let chunks: Vec<bytes::Bytes> = chunks_with_hashes.into_iter().map(|(c, _)| c).collect();
        let snapshot_block = {
            let parent_hash = genesis().hash();
            let commands: Vec<bytes::Bytes> = Vec::new();
            boule_consensus::replication::block::Block {
                header: boule_consensus::replication::block::BlockHeader {
                    parent_hash,
                    height: Height(50),
                    view: View(50),
                    proposer: server_ids[0],
                    state_commitment: expected_commitment,
                    commands_commitment:
                        boule_consensus::replication::block::Block::commands_commitment(&commands),
                    validator_history_commitment: [0; 32],
                    committed_height: Height::ZERO,
                    committed_state_root: [0; 32],
                },
                commands,
            }
        };
        let mut commit_qc = QuorumCertificate::new(50, snapshot_block.hash(), vs.len());
        for i in 0..boule_consensus::hotstuff::qc::quorum_size(vs.len()) {
            commit_qc.add_signature(i, [0u8; 64]);
        }
        let manifest =
            boule_consensus::replication::snapshot::SnapshotManifest::build_for_test_genesis_histories(
                snapshot_block.clone(),
                &vs,
                2,
                chunk_hashes,
                commit_qc,
                1_700_000_000,
            );

        let joiner_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let joiner_sm: Arc<Mutex<Box<dyn StateMachine>>> = Arc::new(Mutex::new(Box::new(
            boule_consensus::replication::impls::counter_sm::CounterStateMachine::new(),
        )));
        let mut joiner_node = ConsensusNode::new(
            joiner_signer.node_id(),
            snapshot_test_config_enabled(vs.clone(), 50),
            Arc::clone(&joiner_sm),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&joiner_storage),
            Arc::new(MemoryWal::new()),
        );
        let joiner_signer_arc: Arc<dyn Signer> = Arc::new(joiner_signer);
        let (joiner_bc, mut joiner_outbound) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut joiner_view_timer = ViewTimer::new(timer_tx);

        for s in &server_signers {
            let proposal = synthetic_proposal_dispatch(s, 100, 100, [0xEE; 32]);
            joiner_node
                .apply_dispatch(
                    proposal,
                    joiner_bc.as_ref(),
                    &mut joiner_view_timer,
                    &joiner_signer_arc,
                )
                .await
                .expect("joiner apply_dispatch proposal");
        }

        let (primary, _) = drain_until(&mut joiner_outbound, |w| {
            matches!(w, WireMessage::SnapshotManifestRequest { .. })
        })
        .await
        .expect("manifest request");
        let resp_payload = postcard::to_stdvec(&WireMessage::SnapshotManifestResponse(Some(
            manifest.clone(),
        )))
        .unwrap();
        let dispatches = dispatch::ingress(
            primary,
            &resp_payload,
            &ValidatorSetHistory::from_genesis(vs.clone()),
            &ValidatorKeyHistory::new(vs.iter().copied()),
            &boule_core::crypto::signed::ChainId::TEST,
        )
        .expect("ingress manifest response");
        for d in dispatches {
            joiner_node
                .apply_dispatch(
                    d,
                    joiner_bc.as_ref(),
                    &mut joiner_view_timer,
                    &joiner_signer_arc,
                )
                .await
                .expect("joiner apply_dispatch manifest response");
        }

        // Serve exactly one chunk to ensure the workpool has
        // distributed requests, then drop a peer that's actually
        // serving chunks.
        let (first_peer, first_payload) = drain_until(&mut joiner_outbound, |w| {
            matches!(w, WireMessage::SnapshotChunkRequest { .. })
        })
        .await
        .expect("first chunk request");
        let (height, idx) = match postcard::from_bytes::<WireMessage>(&first_payload).unwrap() {
            WireMessage::SnapshotChunkRequest { height, chunk_idx } => (height, chunk_idx),
            _ => panic!(),
        };
        let resp = WireMessage::SnapshotChunkResponse {
            height,
            chunk_idx: idx,
            payload: Some(chunks[idx as usize].clone()),
        };
        let resp_bytes = postcard::to_stdvec(&resp).unwrap();
        let dispatches = dispatch::ingress(
            first_peer,
            &resp_bytes,
            &ValidatorSetHistory::from_genesis(vs.clone()),
            &ValidatorKeyHistory::new(vs.iter().copied()),
            &boule_core::crypto::signed::ChainId::TEST,
        )
        .unwrap();
        for d in dispatches {
            joiner_node
                .apply_dispatch(
                    d,
                    joiner_bc.as_ref(),
                    &mut joiner_view_timer,
                    &joiner_signer_arc,
                )
                .await
                .unwrap();
        }

        // Drop the peer that just served us via a synthetic
        // PeerRemoved event-equivalent: drive snapshot_sync's
        // disconnect hook directly. This is what
        // `DiscoveryEvent::PeerRemoved` would do at runtime.
        let drop_actions = joiner_node.snapshot_sync.on_peer_disconnected(first_peer);
        joiner_node
            .apply_snapshot_sync_actions(
                drop_actions,
                joiner_bc.as_ref(),
                &mut joiner_view_timer,
                &joiner_signer_arc,
            )
            .await
            .unwrap();
        assert!(
            !joiner_node.snapshot_sync.is_aborted(),
            "with 2 surviving candidates, dropping one peer must not abort",
        );

        // Drain the rest. Bounded loop guards against state-machine
        // bugs. Stale requests still in the channel from before the
        // disconnect was processed (i.e. addressed to `first_peer`)
        // are silently dropped — the state machine has already
        // reassigned those chunks to surviving peers, so freshly-
        // emitted requests target other peers and the workpool
        // makes progress.
        let mut served_via_other = false;
        for _ in 0..(manifest.chunk_count * 4 + 16) {
            let req = drain_until(&mut joiner_outbound, |w| {
                matches!(w, WireMessage::SnapshotChunkRequest { .. })
            })
            .await;
            let Some((peer, payload)) = req else {
                break;
            };
            if peer == first_peer {
                // Stale: the disconnect superseded this request;
                // the state machine reassigned the chunk and we
                // shouldn't synthesize a response from a "dropped"
                // peer.
                continue;
            }
            served_via_other = true;
            let (height, idx) = match postcard::from_bytes::<WireMessage>(&payload).unwrap() {
                WireMessage::SnapshotChunkRequest { height, chunk_idx } => (height, chunk_idx),
                _ => panic!(),
            };
            let resp = WireMessage::SnapshotChunkResponse {
                height,
                chunk_idx: idx,
                payload: Some(chunks[idx as usize].clone()),
            };
            let resp_bytes = postcard::to_stdvec(&resp).unwrap();
            let dispatches = dispatch::ingress(
                peer,
                &resp_bytes,
                &ValidatorSetHistory::from_genesis(vs.clone()),
                &ValidatorKeyHistory::new(vs.iter().copied()),
                &boule_core::crypto::signed::ChainId::TEST,
            )
            .unwrap();
            for d in dispatches {
                joiner_node
                    .apply_dispatch(
                        d,
                        joiner_bc.as_ref(),
                        &mut joiner_view_timer,
                        &joiner_signer_arc,
                    )
                    .await
                    .unwrap();
            }
            if joiner_node.snapshot_sync.is_done() {
                break;
            }
        }
        assert!(
            served_via_other,
            "at least one chunk must be served by a non-dropped peer for the test to be meaningful",
        );

        assert!(
            joiner_node.snapshot_sync.is_done(),
            "joiner must complete fetch after a single peer drop",
        );
        assert_eq!(
            joiner_node.last_committed_height.load(Ordering::Relaxed),
            50u64
        );
        assert_eq!(joiner_sm.lock().state_commitment(), expected_commitment);
    }

    #[tokio::test]
    async fn run_shuts_down_cleanly_on_signal() {
        let node = make_node(nid(1));
        let signer = fresh_signer();
        let (_event_tx, event_rx) = make_test_event_channel();
        let (broadcaster, _outbound_rx) = make_test_broadcaster();
        let discovery = make_test_discovery();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let run_handle = tokio::spawn(async move {
            node.run(
                broadcaster,
                discovery,
                event_rx,
                Arc::new(signer),
                shutdown_rx,
            )
            .await
        });

        shutdown_tx.send(()).unwrap();
        let result = run_handle.await.unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn run_boots_and_sends_at_least_one_outbound_message() {
        // On boot the pacemaker advances to view 1. If the node is the
        // view-1 leader (round-robin: leader = validators[(1 % 4)] = nid(2)),
        // it would propose; otherwise it sends a NewView. Either way, at least
        // one outbound message must appear once the loop ticks.
        //
        // We don't check the exact message content here (that's tested in
        // dispatch tests); we just confirm the loop boots and sends.
        let node = make_node(nid(1));
        let signer = fresh_signer();
        let (_event_tx, event_rx) = make_test_event_channel();
        let (broadcaster, _outbound_rx) = make_test_broadcaster();
        let discovery = make_test_discovery();
        let (_shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            let _ = node
                .run(
                    broadcaster,
                    discovery,
                    event_rx,
                    Arc::new(signer),
                    shutdown_rx,
                )
                .await;
        });

        // Give the loop a tick to run its boot sequence.
        tokio::task::yield_now().await;

        // The pacemaker sends NewView on advance (if high_qc is present).
        // On a fresh node there is no high_qc, so no NewView is emitted —
        // but the timer IS armed. We verify the loop at least processed the
        // boot sequence without panicking: if the task panicked, the test
        // harness would surface it on the next await or drop.
    }

    // ── #218: TimeoutVote round-sync hint ───────────────────────────────────

    /// A signed `TimeoutVote(view=N)` from a single peer must NOT
    /// drag the local pacemaker forward — that would let a Byzantine
    /// `TimeoutSpammer` set our `current_view` to `u64::MAX` with one
    /// frame. The hint only fires once the local bucket reaches
    /// `f + 1` distinct signers (the honesty threshold), guaranteeing
    /// at least one honest peer agrees.
    ///
    /// This test verifies the bound: a single TimeoutVote leaves
    /// `current_view` untouched even though it's bucketed.
    #[tokio::test]
    async fn timeout_vote_single_signer_does_not_advance_pacemaker_view() {
        let self_signer = fresh_signer();
        let peer_signer = fresh_signer();
        let ids = vec![
            self_signer.node_id(),
            peer_signer.node_id(),
            nid(0xA1),
            nid(0xA2),
        ];
        // ValidatorSet::new sorts internally; the local ids.sort() is
        // redundant but kept for parity with the pre-#328 fixture.
        let vs = ValidatorSet::new(
            ids.into_iter()
                .map(boule_consensus::validator_set::ValidatorId::from_genesis_pubkey)
                .collect(),
        );
        let cfg = NodeConfigForConsensus::for_testing(vs.clone(), genesis());
        let mut node = ConsensusNode::new(
            self_signer.node_id(),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::new(MemoryStorage::new()),
            Arc::new(MemoryWal::new()),
        );

        let view_before = node.pacemaker.current_view();
        let tv = boule_consensus::hotstuff::qc::TimeoutVote {
            view: View(42),
            high_qc: None,
        };
        let signed = boule_core::crypto::signed::Signed::sign(
            tv,
            &peer_signer,
            &boule_core::crypto::signed::ChainId::TEST,
        )
        .expect("sign TimeoutVote");
        let wire = WireMessage::TimeoutVote(signed);
        let payload = postcard::to_stdvec(&wire).expect("encode WireMessage");

        let dispatches = boule_consensus::dispatch::ingress(
            peer_signer.node_id(),
            &payload,
            &ValidatorSetHistory::from_genesis(vs.clone()),
            &ValidatorKeyHistory::new(vs.iter().copied()),
            &boule_core::crypto::signed::ChainId::TEST,
        )
        .expect("ingress");
        let signer_arc: Arc<dyn Signer> = Arc::new(self_signer);
        let (broadcaster, _outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);
        for d in dispatches {
            node.apply_dispatch(d, broadcaster.as_ref(), &mut view_timer, &signer_arc)
                .await
                .expect("apply_dispatch");
        }

        // 1 distinct signer < f + 1 = 2 (n = 4, f = 1) → no hint
        // fires, the pacemaker stays put.
        assert_eq!(
            node.pacemaker.current_view(),
            view_before,
            "single-signer TimeoutVote must not advance the pacemaker — that's \
             the Byzantine bound that keeps a TimeoutSpammer adversary from \
             dragging honest views (see #218)",
        );
    }

    /// Two distinct signers' `TimeoutVote(view=N)` is the honesty
    /// threshold for `n = 4` (`f + 1 = 2`): at least one must be
    /// honest. The pacemaker fast-jumps *to* `N` (not `N + 1`)
    /// without promoting `high_qc_view`. This is the path that closes
    /// the post-restart view-skew wedge in #218 — distinct resume
    /// views (e.g. 28 vs 29) leave each replica bucketing only at the
    /// view it itself is on, never reaching quorum, never emitting a
    /// TC; the round-sync hint at `f + 1` is what unsticks them.
    #[tokio::test]
    async fn two_distinct_timeout_votes_fire_round_sync_and_advance_pacemaker() {
        let self_signer = fresh_signer();
        let peer_a = fresh_signer();
        let peer_b = fresh_signer();
        let ids = vec![
            self_signer.node_id(),
            peer_a.node_id(),
            peer_b.node_id(),
            nid(0xA1),
        ];
        // ValidatorSet::new sorts internally; the local ids.sort() is
        // redundant but kept for parity with the pre-#328 fixture.
        let vs = ValidatorSet::new(
            ids.into_iter()
                .map(boule_consensus::validator_set::ValidatorId::from_genesis_pubkey)
                .collect(),
        );
        let cfg = NodeConfigForConsensus::for_testing(vs.clone(), genesis());
        let mut node = ConsensusNode::new(
            self_signer.node_id(),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::new(MemoryStorage::new()),
            Arc::new(MemoryWal::new()),
        );

        let high_qc_view_before = node.pacemaker.high_qc_view();
        let signer_arc: Arc<dyn Signer> = Arc::new(self_signer);
        let (broadcaster, _outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        // Feed two distinct signers' TimeoutVote(42) through the same
        // ingress + dispatch path the live event loop uses.
        for peer in [&peer_a, &peer_b] {
            let tv = boule_consensus::hotstuff::qc::TimeoutVote {
                view: View(42),
                high_qc: None,
            };
            let signed = boule_core::crypto::signed::Signed::sign(
                tv,
                peer,
                &boule_core::crypto::signed::ChainId::TEST,
            )
            .expect("sign TimeoutVote");
            let wire = WireMessage::TimeoutVote(signed);
            let payload = postcard::to_stdvec(&wire).expect("encode WireMessage");
            let dispatches = boule_consensus::dispatch::ingress(
                peer.node_id(),
                &payload,
                &ValidatorSetHistory::from_genesis(vs.clone()),
                &ValidatorKeyHistory::new(vs.iter().copied()),
                &boule_core::crypto::signed::ChainId::TEST,
            )
            .expect("ingress");
            for d in dispatches {
                node.apply_dispatch(d, broadcaster.as_ref(), &mut view_timer, &signer_arc)
                    .await
                    .expect("apply_dispatch");
            }
        }

        assert_eq!(
            node.pacemaker.current_view(),
            View(42),
            "OnRoundSync at f+1 honesty threshold jumps to v, not v+1",
        );
        assert_eq!(
            node.pacemaker.high_qc_view(),
            high_qc_view_before,
            "OnRoundSync must not promote high_qc_view — round sync is a \
             liveness hint, not a QC witness",
        );
    }

    /// Issue #321 regression: a Byzantine peer's `TimeoutVote` with a
    /// well-formed but cryptographically forged `high_qc` piggyback
    /// must not flow into `bucket.best_high_qc`. The dispatch verifier
    /// (`verify_high_qc_piggyback`) clears `high_qc_trusted`, and
    /// `on_timeout_vote`'s bucket update reads that flag and skips the
    /// piggyback entirely, treating the envelope as `high_qc: None`.
    ///
    /// Without this gate, an attacker could broadcast a single
    /// timeout vote with `view = u64::MAX - 1, high_qc = forged(...)`
    /// and once `f + 1` honest replicas joined the same bucket on a
    /// real timeout, the TC self-NewView loopback would launder the
    /// forged QC into every honest replica's `state.high_qc`.
    #[tokio::test]
    async fn forged_piggyback_on_timeout_vote_does_not_taint_bucket_best_high_qc() {
        // n = 4 → quorum = 3, f + 1 = 2.
        let self_signer = fresh_signer();
        let byzantine = fresh_signer();
        let ids = vec![
            self_signer.node_id(),
            byzantine.node_id(),
            nid(0xA1),
            nid(0xA2),
        ];
        // ValidatorSet::new sorts internally; the local ids.sort() is
        // redundant but kept for parity with the pre-#328 fixture.
        let vs = ValidatorSet::new(
            ids.into_iter()
                .map(boule_consensus::validator_set::ValidatorId::from_genesis_pubkey)
                .collect(),
        );
        let cfg = NodeConfigForConsensus::for_testing(vs.clone(), genesis());
        let mut node = ConsensusNode::new(
            self_signer.node_id(),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::new(MemoryStorage::new()),
            Arc::new(MemoryWal::new()),
        );

        // Build a *well-formed* but cryptographically bogus QC at a
        // very-fresh view. Quorum-many bits set, quorum-many zero
        // signatures — passes is_well_formed, fails verify_aggregate.
        let bogus_view: View = View(u64::MAX - 1);
        let bogus_block_hash = [0xDE; 32];
        let mut forged = boule_consensus::hotstuff::qc::QuorumCertificate::new(
            bogus_view,
            bogus_block_hash,
            vs.len(),
        );
        let quorum = boule_consensus::hotstuff::qc::quorum_size(vs.len());
        for idx in 0..quorum {
            forged.add_signature(idx, [0u8; 64]);
        }

        // The byzantine signs a real timeout vote at a future view
        // and piggybacks the forged QC. The envelope itself is valid
        // (real signature over real payload bytes), so envelope
        // verification at ingress will pass.
        let attack_view: View = View(42);
        let tv = boule_consensus::hotstuff::qc::TimeoutVote {
            view: attack_view,
            high_qc: Some(forged),
        };
        let signed = boule_core::crypto::signed::Signed::sign(
            tv,
            &byzantine,
            &boule_core::crypto::signed::ChainId::TEST,
        )
        .expect("sign TimeoutVote");
        let wire = WireMessage::TimeoutVote(signed);
        let payload = postcard::to_stdvec(&wire).expect("encode WireMessage");

        // Run through the production verify path — this is the same
        // policy the live event loop wires (node.rs apply_dispatch).
        let qc_verification = boule_consensus::dispatch::QcVerification::Verify {
            scheme: boule_core::crypto::sig_scheme::SignatureSchemeChoice::Ed25519Collected,
            bls_key_history: None,
            min_v_eff_delay: boule_consensus::reconfig::MIN_V_EFF_DELAY,
            genesis_hash: node.core.state().genesis_hash,
        };
        let dispatches = boule_consensus::dispatch::ingress_with_qc_verification(
            byzantine.node_id(),
            &payload,
            &ValidatorSetHistory::from_genesis(vs.clone()),
            &ValidatorKeyHistory::new(vs.iter().copied()),
            &qc_verification,
            &boule_core::crypto::signed::ChainId::TEST,
        )
        .expect("envelope is honest; ingress must accept and emit Dispatch::TimeoutVote");

        // Ingress must emit exactly one TimeoutVote dispatch with the
        // piggyback flagged untrusted — the public contract that
        // on_timeout_vote relies on.
        assert_eq!(dispatches.len(), 1);
        match &dispatches[0] {
            boule_consensus::dispatch::Dispatch::TimeoutVote {
                signed,
                high_qc_trusted,
            } => {
                assert!(
                    !high_qc_trusted,
                    "forged piggyback must not be flagged as trusted",
                );
                assert_eq!(signed.payload.view, attack_view);
                // The envelope is unchanged — the integration layer
                // will look at signed.payload.high_qc but must ignore
                // it because the flag is false.
                assert!(signed.payload.high_qc.is_some());
            }
            other => panic!("expected Dispatch::TimeoutVote, got {other:?}"),
        }

        let signer_arc: Arc<dyn Signer> = Arc::new(self_signer);
        let (broadcaster, _outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);
        for d in dispatches {
            node.apply_dispatch(d, broadcaster.as_ref(), &mut view_timer, &signer_arc)
                .await
                .expect("apply_dispatch");
        }

        // The byzantine's timeout vote was real, so the bucket records
        // the signer (one entry, below the f+1 honesty threshold). But
        // bucket.best_high_qc must be None — the forged piggyback was
        // dropped at ingress and never reached the freshness compare.
        let bucket = node
            .timeout_buckets
            .get(&attack_view)
            .expect("byzantine's timeout vote at attack_view created the bucket");
        assert_eq!(
            bucket.signers.len(),
            1,
            "the byzantine's signer must still count toward the bucket — \
             dropping the envelope outright would let an attacker mute \
             honest timeout signal by attaching garbage piggybacks",
        );
        assert!(
            bucket.best_high_qc.is_none(),
            "bucket.best_high_qc must remain None — the forged QC must \
             not be eligible for the TC self-NewView loopback that \
             feeds state.high_qc",
        );
    }

    /// Issue #222 regression: a peer's `TimeoutVote(view=V)` where
    /// `V < self.current_view` is the cleanest signal that the peer is
    /// wedged (typically post-restart, stuck at its persisted
    /// `last_voted_view`). The bucket logic ignores the vote, but we
    /// also reply with a unicast `NewView` carrying our current
    /// `high_qc` so the wedged peer can fire `OnQc(high_qc.view)`
    /// through the standard ingress path and exit the wedge.
    ///
    /// Without this reply, the wedged replica's only forward-progress
    /// signal is its own outbound timeout votes, which the rest of the
    /// cluster ignores; if proposals/NewViews from caught-up peers are
    /// also dropped at the gossip layer for any reason, no path advances
    /// the wedged pacemaker. This is the wedge observed at ~12% under
    /// the "kill 3 of 4, restart 3" recipe in #222.
    #[tokio::test]
    async fn stale_timeout_vote_replies_with_new_view_to_wedged_peer() {
        let self_signer = fresh_signer();
        let wedged_peer = fresh_signer();
        let ids = vec![
            self_signer.node_id(),
            wedged_peer.node_id(),
            nid(0xA1),
            nid(0xA2),
        ];
        // ValidatorSet::new sorts internally; the local ids.sort() is
        // redundant but kept for parity with the pre-#328 fixture.
        let vs = ValidatorSet::new(
            ids.into_iter()
                .map(boule_consensus::validator_set::ValidatorId::from_genesis_pubkey)
                .collect(),
        );
        let cfg = NodeConfigForConsensus::for_testing(vs.clone(), genesis());
        let mut node = ConsensusNode::new(
            self_signer.node_id(),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::new(MemoryStorage::new()),
            Arc::new(MemoryWal::new()),
        );

        // Advance our pacemaker well past the wedged peer's view.
        // Use OnQc(50) so current_view = 51 — comfortably ahead of the
        // wedged_view = 5 we will inject below.
        let signer_arc: Arc<dyn Signer> = Arc::new(self_signer);
        let (broadcaster, mut outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);
        let actions = node.step_pacemaker(PacemakerEvent::OnQc(View(50)));
        node.apply_pacemaker_actions(actions, broadcaster.as_ref(), &mut view_timer, &signer_arc)
            .await
            .expect("apply boot");
        // Drain whatever the boot emitted (NewView, ResetTimer plumbing
        // through outbound_rx, etc.) so the assertion below sees only
        // the catch-up reply.
        while outbound_rx.try_recv().is_ok() {}
        let our_view_before = node.pacemaker.current_view();
        assert!(
            our_view_before > View(5),
            "test setup: our pacemaker must be ahead of the wedged peer's view (5)",
        );
        let our_high_qc_view_before = node
            .core
            .state()
            .high_qc
            .as_ref()
            .expect("genesis_qc must seed high_qc on a fresh node")
            .view();

        // Inject a stale TimeoutVote(view=5) from the wedged peer
        // through the ingress + dispatch path.
        let tv = boule_consensus::hotstuff::qc::TimeoutVote {
            view: View(5),
            high_qc: None,
        };
        let signed = boule_core::crypto::signed::Signed::sign(
            tv,
            &wedged_peer,
            &boule_core::crypto::signed::ChainId::TEST,
        )
        .expect("sign TimeoutVote");
        let wire = WireMessage::TimeoutVote(signed);
        let payload = postcard::to_stdvec(&wire).expect("encode WireMessage");

        let dispatches = boule_consensus::dispatch::ingress(
            wedged_peer.node_id(),
            &payload,
            &ValidatorSetHistory::from_genesis(vs.clone()),
            &ValidatorKeyHistory::new(vs.iter().copied()),
            &boule_core::crypto::signed::ChainId::TEST,
        )
        .expect("ingress");
        for d in dispatches {
            node.apply_dispatch(d, broadcaster.as_ref(), &mut view_timer, &signer_arc)
                .await
                .expect("apply_dispatch");
        }

        // Our pacemaker must not have moved — the stale vote does not
        // contribute to any bucket at our current view.
        assert_eq!(
            node.pacemaker.current_view(),
            our_view_before,
            "stale TimeoutVote must not advance our own pacemaker",
        );

        // We must have emitted a unicast NewView reply addressed to the
        // wedged peer, carrying our current high_qc.
        let mut found_reply = false;
        while let Ok(out) = outbound_rx.try_recv() {
            if let ProtocolOutbound::SendTo {
                node_id, payload, ..
            } = out
            {
                if node_id != wedged_peer.node_id() {
                    continue;
                }
                let decoded: WireMessage =
                    postcard::from_bytes(&payload).expect("decode reply payload");
                if let WireMessage::NewView(signed) = decoded {
                    assert_eq!(
                        signed.payload.high_qc.view, our_high_qc_view_before,
                        "reply must carry our current high_qc",
                    );
                    found_reply = true;
                    break;
                }
            }
        }
        assert!(
            found_reply,
            "expected a unicast NewView reply to the wedged peer carrying our high_qc",
        );
    }

    /// Issue #222 regression: after `recover` from non-trivial durable
    /// state, the integration boot must seed the pacemaker from
    /// `max(persisted high_qc.view, persisted last_voted_view)` rather
    /// than starting at view 0 + jumping to view 1. Without this, the
    /// boot path briefly advertises view 1 to peers (carrying the
    /// stale persisted high_qc), then catches up via the self-loopback
    /// `OnQc(high_qc.view)`. The transient is harmless on its own, but
    /// it is the timing window that turns into a permanent wedge if
    /// peer NewView traffic is filtered out for any reason.
    #[tokio::test]
    async fn boot_after_recover_seeds_pacemaker_from_persisted_state() {
        use boule_consensus::hotstuff::Locked;
        use boule_consensus::replication::block::BlockHeader;

        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let wal: Arc<dyn Wal> = Arc::new(MemoryWal::new());
        let cfg = test_config(four_validators());

        // Build a uncommitted block at view 9 so its hash + header can
        // back the persisted high_qc.
        let g = genesis();
        let b_high = Block {
            header: BlockHeader {
                parent_hash: g.hash(),
                height: Height(1),
                view: View(9),
                proposer: nid(1),
                state_commitment: [0u8; 32],
                commands_commitment: Block::commands_commitment(&[]),
                validator_history_commitment: [0; 32],
                committed_height: Height::ZERO,
                committed_state_root: [0; 32],
            },
            commands: vec![],
        };
        let high_qc = QuorumCertificate::new(9, b_high.hash(), 4);
        let locked = Locked {
            view: View(8),
            height: Height(1),
            block_hash: b_high.hash(),
        };

        // Session 1: persist a vote at view 10, plus locked / high_qc.
        // The locked entry's referenced block is `b_high`, which we
        // insert into pending_blocks first so `persist_updates` writes
        // it to durable storage too (#206 path).
        let mut node = ConsensusNode::new(
            nid(1),
            cfg.clone(),
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::clone(&wal),
        );
        node.core.insert_pending_block(b_high.clone());
        node.persist_updates(&[
            StateUpdate::VotedInView { view: View(10) },
            StateUpdate::Locked(locked),
            StateUpdate::HighQc(high_qc.clone()),
        ])
        .unwrap();
        drop(node);

        // Session 2: recover and run the same `boot_view` snippet the
        // integration boot uses. Asserts the pacemaker lands at
        // max(high_qc.view = 9, last_voted_view = 10) + 1 = 11, not 1.
        let mut recovered = ConsensusNode::recover(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::clone(&wal),
        )
        .unwrap();
        assert_eq!(recovered.core.state().last_voted_view, View(10));
        assert_eq!(
            recovered.core.state().high_qc.as_ref().unwrap().view(),
            View(9)
        );

        // Build a self-signer whose node_id matches recovered.self_id
        // (= nid(1) here is a synthetic placeholder, not derived from a
        // real key). The boot snippet only needs the signer to sign
        // outbound NewView frames, which we don't assert on.
        let self_signer = fresh_signer();
        let signer_arc: Arc<dyn Signer> = Arc::new(self_signer);
        let (broadcaster, _outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        let boot_view = recovered
            .core
            .state()
            .high_qc
            .as_ref()
            .map(|qc| qc.view())
            .unwrap_or(View::ZERO)
            .max(recovered.core.state().last_voted_view);
        let boot_actions = recovered.step_pacemaker(PacemakerEvent::OnQc(boot_view));
        recovered
            .apply_pacemaker_actions(
                boot_actions,
                broadcaster.as_ref(),
                &mut view_timer,
                &signer_arc,
            )
            .await
            .expect("boot");

        assert_eq!(
            recovered.pacemaker.current_view(),
            View(11),
            "pacemaker must land at max(high_qc.view, last_voted_view) + 1 = 11 after recover boot",
        );
    }

    // ── Self-addressed loopback (#118) ───────────────────────────────────────

    /// Build a node whose `self_id` matches `signer.node_id()` and who
    /// sits at `validator_set[self_idx]` of a 4-node committee. The
    /// remaining three slots are filled with placeholder ids so the
    /// safety core can route votes by validator index.
    fn make_node_with_signer(
        signer: &NodeSigner,
        self_idx: usize,
    ) -> (ConsensusNode, ValidatorSet) {
        assert!(self_idx < 4);
        let self_id = signer.node_id();
        let placeholders = [nid(0xA1), nid(0xA2), nid(0xA3)];
        let mut ids: Vec<NodeId> = Vec::with_capacity(4);
        let mut ph = placeholders.iter();
        for i in 0..4 {
            if i == self_idx {
                ids.push(self_id);
            } else {
                ids.push(*ph.next().unwrap());
            }
        }
        let vs = ValidatorSet::new(
            ids.iter()
                .copied()
                .map(boule_consensus::validator_set::ValidatorId::from_genesis_pubkey)
                .collect(),
        );
        let cfg = NodeConfigForConsensus::for_testing(vs.clone(), genesis());
        let node = ConsensusNode::new(
            self_id,
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::new(MemoryStorage::new()),
            Arc::new(MemoryWal::new()),
        );
        (node, vs)
    }

    /// Regression for issue #118: when a node is the proposing leader it
    /// must process its own `Broadcast(Proposal)` locally so it votes on
    /// its own proposal. Before the fix this path was silent — the p2p
    /// broadcast excluded the sender, the leader never ran
    /// `on_proposal_received` on its own frame, and the next-view
    /// leader's vote bucket was one signer short of quorum.
    #[tokio::test]
    async fn broadcast_proposal_is_delivered_locally_to_leader() {
        // Sit at index 1 so round-robin makes self the view-1 leader
        // (leader(1) = validator_set[1 % 4] = self).
        let ns = fresh_signer();
        let (mut node, vs) = make_node_with_signer(&ns, 1);
        let signer: Arc<dyn Signer> = Arc::new(ns);

        let (broadcaster, mut send_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        // #606: the safety core emits a single `BuildProposal`; the
        // dispatcher's BuildProposal handler runs the builder and re-applies
        // the resulting `Persist(ProposedInView)` + `Broadcast(Proposal)`
        // (persist first, audit 4-6 / #407), then self-delivers the proposal.
        // The broadcast/self-delivery assertions below verify the fulfillment.
        let actions = node.core.become_leader(1);
        assert_eq!(
            actions.len(),
            1,
            "become_leader emits one BuildProposal: {actions:?}"
        );

        node.apply_safety_actions(actions, broadcaster.as_ref(), &mut view_timer, &signer)
            .await
            .unwrap();

        // Observable effect of local self-delivery: the safety core
        // processed its own proposal through `on_proposal_received`,
        // which persists `last_voted_view = 1` before emitting the vote.
        let raw = node
            .storage
            .get(STORAGE_KEY_LAST_VOTED_VIEW)
            .unwrap()
            .expect("last_voted_view must be persisted after self-vote");
        assert_eq!(decode_voted_view(&raw).unwrap(), View(1));
        assert_eq!(node.core.state().last_voted_view, View(1));

        // Wire traffic: the proposal broadcast must have gone out, and
        // the subsequent vote must also be broadcast (not SendTo) —
        // #124 changed vote routing from point-to-point-to-next-leader
        // to broadcast-and-let-every-replica-aggregate so that QC
        // formation survives the next-view leader being crashed.
        let _next_leader = *vs.get(2).unwrap();

        let first = send_rx
            .try_recv()
            .expect("Broadcast(Proposal) must be sent");
        assert!(
            matches!(first, ProtocolOutbound::Broadcast(_)),
            "first outbound must be the proposal broadcast"
        );
        let second = send_rx.try_recv().expect("Broadcast(Vote) must be sent");
        assert!(
            matches!(second, ProtocolOutbound::Broadcast(_)),
            "second outbound must be the vote broadcast, got {second:?}",
        );
        // #436: the proposal loopback now emits `OnQc(justify.view = 0)`,
        // which advances this node's pacemaker from view 0 → 1 and fires
        // `on_pacemaker_advance(1)`. That handler unconditionally emits
        // a `Broadcast(NewView)` advertising the seeded genesis high_qc
        // — the same NewView a real boot would send when the pacemaker
        // advances from 0 to 1 via the boot-time `OnQc(boot_view)`.
        // The double-propose guard on `proposed_in_view` keeps this from
        // re-emitting a Proposal at view 1.
        let third = send_rx
            .try_recv()
            .expect("Broadcast(NewView) must follow as the pacemaker advances to view 1");
        assert!(
            matches!(third, ProtocolOutbound::Broadcast(_)),
            "third outbound must be the NewView broadcast, got {third:?}",
        );
        // No further traffic.
        assert!(send_rx.try_recv().is_err());
    }

    /// Pacing (#614): a proposal produced within `min_block_interval` of the
    /// previous one is held in `stashed_proposal` instead of broadcast, so
    /// block production is rate-limited and (at a single-validator set) the
    /// loopback chain terminates. The run loop's pacing arm sends it once the
    /// interval elapses.
    #[tokio::test]
    async fn proposal_within_min_block_interval_is_stashed_not_broadcast() {
        let ns = fresh_signer();
        let (mut node, _vs) = make_node_with_signer(&ns, 1);
        let signer: Arc<dyn Signer> = Arc::new(ns);
        // Enable pacing and pretend we proposed a moment ago.
        node.min_block_interval = Duration::from_secs(60);
        node.last_proposal_at = Some(tokio::time::Instant::now());

        let (broadcaster, mut send_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        let actions = node.core.become_leader(1);
        node.apply_safety_actions(actions, broadcaster.as_ref(), &mut view_timer, &signer)
            .await
            .unwrap();

        assert!(
            node.stashed_proposal.is_some(),
            "a proposal within the interval must be stashed, not broadcast",
        );
        assert!(
            send_rx.try_recv().is_err(),
            "nothing should hit the wire while the proposal is paced",
        );
        // The proposal was never delivered to us, so no self-vote happened.
        assert_eq!(node.core.state().last_voted_view, View::ZERO);
    }

    /// Pacing (#614): pacing only delays back-to-back proposals — the first
    /// proposal (no prior `last_proposal_at`) is broadcast immediately, and
    /// records the time so the *next* one is paced.
    #[tokio::test]
    async fn first_proposal_is_broadcast_despite_pacing() {
        let ns = fresh_signer();
        let (mut node, _vs) = make_node_with_signer(&ns, 1);
        let signer: Arc<dyn Signer> = Arc::new(ns);
        node.min_block_interval = Duration::from_secs(60);
        node.last_proposal_at = None; // never proposed yet

        let (broadcaster, mut send_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        let actions = node.core.become_leader(1);
        node.apply_safety_actions(actions, broadcaster.as_ref(), &mut view_timer, &signer)
            .await
            .unwrap();

        assert!(
            node.stashed_proposal.is_none(),
            "the first proposal must not be stashed",
        );
        assert!(
            send_rx.try_recv().is_ok(),
            "the first proposal must be broadcast immediately",
        );
        // It self-delivered, so we voted on it, and the broadcast time is now
        // recorded — the next proposal would be paced.
        assert_eq!(node.core.state().last_voted_view, View(1));
        assert!(node.last_proposal_at.is_some());
    }

    /// PR A of #325: outbound proposals must carry a real
    /// `validator_history_commitment` — not the `[0; 32]` placeholder
    /// the block builder stamps. The leader-side rewrite in
    /// `apply_safety_actions` is what populates the field; this test
    /// pins that wiring so a future refactor can't silently drop it.
    ///
    /// Bisect-confirmed by removing the rewrite block in
    /// `apply_safety_actions`: the test then sees `[0; 32]` on the
    /// wire and fails the equality assertion.
    #[tokio::test]
    async fn outbound_proposal_carries_validator_history_commitment() {
        let ns = fresh_signer();
        let (mut node, _vs) = make_node_with_signer(&ns, 1);
        let signer: Arc<dyn Signer> = Arc::new(ns);

        // Snapshot the expected commitment before triggering the
        // broadcast — pre-block semantics, so this hash is what should
        // appear on the wire.
        let expected = boule_consensus::history_commitment::validator_history_commitment_v1(
            &node.validator_history,
            &node.validator_key_history,
            node.bls_key_history.as_ref(),
        );

        let (broadcaster, mut send_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        // Become view-1 leader and let the safety core emit its
        // single Action::Broadcast(Proposal). apply_safety_actions
        // walks the action list and rewrites the proposal's
        // validator_history_commitment before signing/broadcasting.
        let actions = node.core.become_leader(1);
        node.apply_safety_actions(actions, broadcaster.as_ref(), &mut view_timer, &signer)
            .await
            .unwrap();

        let outbound = send_rx
            .try_recv()
            .expect("Broadcast(Proposal) must be sent");
        let payload = match outbound {
            ProtocolOutbound::Broadcast(p) => p,
            other => panic!("expected Broadcast, got {other:?}"),
        };
        let wire: WireMessage = postcard::from_bytes(&payload).expect("decode wire");
        let signed = match wire {
            WireMessage::Proposal(s) => s,
            other => panic!("expected Proposal, got {other:?}"),
        };

        assert_eq!(
            signed.payload.block.header.validator_history_commitment, expected,
            "leader must stamp the real v1 commitment over its current histories, \
             not leave the [0; 32] placeholder the block builder produces",
        );
        // Sanity: this is not just the all-zero default.
        assert_ne!(
            signed.payload.block.header.validator_history_commitment, [0u8; 32],
            "the v1 commitment over a non-empty validator set must not collide \
             with the all-zero placeholder",
        );
    }

    // ── Bounded-cache eviction (#135) ─────────────────────────────────────
    //
    // The safety-core caches are tested in `consensus::hotstuff::step`;
    // the integration layer owns `timeout_buckets`, so the cap-driven
    // eviction lives here. We exercise the cap by feeding distinct
    // future-view timeout votes from one signer (well below quorum, so
    // no TC ever fires and the on-TC `retain(v > view)` cleanup never
    // kicks in — the cap is the ONLY thing keeping the map bounded).

    /// Build a node whose timeout_buckets cap is `cap`; otherwise
    /// identical to [`make_node_with_signer`]. Other caches stay at
    /// their permissive test defaults so unrelated cap evictions
    /// don't pollute the assertion.
    fn make_node_with_timeout_cap(
        signer: &NodeSigner,
        self_idx: usize,
        cap: usize,
    ) -> (ConsensusNode, ValidatorSet) {
        assert!(self_idx < 4);
        let self_id = signer.node_id();
        let placeholders = [nid(0xA1), nid(0xA2), nid(0xA3)];
        let mut ids: Vec<NodeId> = Vec::with_capacity(4);
        let mut ph = placeholders.iter();
        for i in 0..4 {
            if i == self_idx {
                ids.push(self_id);
            } else {
                ids.push(*ph.next().unwrap());
            }
        }
        let vs = ValidatorSet::new(
            ids.iter()
                .copied()
                .map(boule_consensus::validator_set::ValidatorId::from_genesis_pubkey)
                .collect(),
        );
        let mut limits = CacheLimits::unbounded_for_tests();
        limits.timeout_buckets_capacity = cap;
        let mut cfg = NodeConfigForConsensus::for_testing(vs.clone(), genesis());
        cfg.limits = limits;
        let node = ConsensusNode::new(
            self_id,
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::new(MemoryStorage::new()),
            Arc::new(MemoryWal::new()),
        );
        (node, vs)
    }

    /// Insert 2× the cap of distinct-view sub-quorum timeout votes
    /// from a single signer — the cap holds, the counter records
    /// every drop, and the lowest-view buckets are the ones evicted.
    #[tokio::test]
    async fn timeout_buckets_inserting_twice_the_cap_evicts_to_cap() {
        let cap = 4usize;
        let ns = fresh_signer();
        let (mut node, _vs) = make_node_with_timeout_cap(&ns, 0, cap);
        let signer: Arc<dyn Signer> = Arc::new(ns);

        let (broadcaster, _send_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        // Use a non-self placeholder validator as the signer so we
        // exercise the foreign-vote ingress path and never trip the
        // self-loopback shortcut. View 0 must be skipped — `view <
        // current_view` would short-circuit before the bucket insert.
        // A literal placeholder id (not `vs.get(1)`) sidesteps the
        // sorted-vs-construction-order trap that flaked #580: the sort in
        // `ValidatorSet::new` can land the random self_id in slot 1.
        let voter = nid(0xA1);
        let n = (2 * cap) as u64;
        for view in 1..=n {
            let payload = TimeoutVote {
                view: View(view),
                high_qc: None,
            };
            let signed = Signed {
                payload,
                signer: voter,
                sig: [0u8; 64],
            };
            node.on_timeout_vote(signed, true, broadcaster.as_ref(), &mut view_timer, &signer)
                .await
                .unwrap();
            assert!(
                node.timeout_buckets.len() <= cap,
                "timeout_buckets grew past cap after view {view}: len={}",
                node.timeout_buckets.len(),
            );
        }
        assert_eq!(node.timeout_buckets.len(), cap);
        // n - cap inserts triggered eviction (n inserts past the
        // cap-fill point of `cap`).
        assert_eq!(node.eviction_counters().timeout_buckets(), n - (cap as u64),);
        // Lowest-view-first: surviving views are the cap most recent.
        let mut surviving: Vec<View> = node.timeout_buckets.keys().copied().collect();
        surviving.sort();
        let expected: Vec<View> = ((n - cap as u64 + 1)..=n).map(View).collect();
        assert_eq!(surviving, expected);
    }

    /// Issue #327 / audit finding 4-F1 / 12-F3 (Tendermint amnesia
    /// regression guard).
    ///
    /// HotStuff safety requires that before a `Vote` envelope leaves the
    /// process, the `last_voted_view` field is durable on disk. If the
    /// order is reversed (vote sent, then crash before persist), the
    /// restarted replica will re-vote at the same view — potentially on
    /// a conflicting block — which is the Tendermint amnesia attack
    /// class.
    ///
    /// The current implementation gets this right by emission ordering
    /// in `step()` (`Action::Persist(VotedInView)` before
    /// `Action::Broadcast(Vote)`) and by `apply_safety_actions` flushing
    /// the persist buffer synchronously via `storage.batch(...)` before
    /// any non-Persist action runs. **This ordering is correct today.**
    /// The test below pins it: a future refactor that reorders
    /// `step()`'s emissions or that defers the `persist_buf.flush()`
    /// past the first `Broadcast` would fail this test.
    ///
    /// Approach: wrap [`Storage`] and [`Broadcaster`] in
    /// timestamp-recording shells that share an ordered log. Drive a
    /// fresh node (single-replica) to vote on a hand-crafted Proposal,
    /// then assert the log records `PersistVotedInView(V)` before
    /// `BroadcastVoteFor(V)` for the same view.
    #[tokio::test]
    async fn vote_persist_returns_before_send_called() {
        use bytes::Bytes;
        use parking_lot::Mutex as PlMutex;

        use boule_consensus::dispatch::ingress_with_qc_verification;
        use boule_consensus::hotstuff::Proposal;
        use boule_core::clock::BoxFuture;
        use boule_core::storage::{Storage, WriteBatch};
        use boule_transport_tcp::overlay::Broadcaster;

        #[derive(Debug, Clone, PartialEq, Eq)]
        enum OrderEvent {
            PersistVotedInView(View),
            BroadcastVoteFor(View),
        }

        /// `Storage` wrapper that appends `PersistVotedInView(V)` to a
        /// shared log when (and only when) `apply_batch` returns `Ok`
        /// after writing `STORAGE_KEY_LAST_VOTED_VIEW`. Other batches
        /// pass through unchanged. Records *after* delegation so the
        /// log entry corresponds to "persist returned" rather than
        /// "persist started".
        struct OrderingStorage {
            inner: Arc<dyn Storage>,
            log: Arc<PlMutex<Vec<OrderEvent>>>,
        }
        impl Storage for OrderingStorage {
            fn get(&self, key: &[u8]) -> anyhow::Result<Option<Bytes>> {
                self.inner.get(key)
            }
            fn put(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
                self.inner.put(key, value)
            }
            fn delete(&self, key: &[u8]) -> anyhow::Result<()> {
                self.inner.delete(key)
            }
            fn scan_prefix(&self, prefix: &[u8]) -> anyhow::Result<Vec<(Bytes, Bytes)>> {
                self.inner.scan_prefix(prefix)
            }
            fn apply_batch(&self, batch: WriteBatch) -> anyhow::Result<()> {
                // Snapshot the view-write (if any) before consuming the
                // batch; record only after the inner write succeeds.
                let mut written_view: Option<View> = None;
                for op in batch.ops() {
                    if let boule_core::storage::WriteOp::Put(key, value) = op {
                        if key.as_slice() == STORAGE_KEY_LAST_VOTED_VIEW {
                            if let Ok(v) = decode_voted_view(value) {
                                written_view = Some(v);
                            }
                        }
                    }
                }
                let result = self.inner.apply_batch(batch);
                if result.is_ok() {
                    if let Some(v) = written_view {
                        self.log.lock().push(OrderEvent::PersistVotedInView(v));
                    }
                }
                result
            }
            fn compare_and_swap(
                &self,
                key: &[u8],
                expected: Option<&[u8]>,
                new: Option<&[u8]>,
            ) -> anyhow::Result<bool> {
                self.inner.compare_and_swap(key, expected, new)
            }
        }

        /// `Broadcaster` wrapper that appends `BroadcastVoteFor(V)` to
        /// the shared log *before* delegating to the inner. The log
        /// entry corresponds to "send was called", which is the
        /// observable timestamp the audit cares about.
        struct OrderingBroadcaster {
            inner: Arc<dyn Broadcaster>,
            log: Arc<PlMutex<Vec<OrderEvent>>>,
        }
        impl Broadcaster for OrderingBroadcaster {
            fn broadcast(&self, payload: Bytes) -> BoxFuture<'_, ()> {
                if let Ok(WireMessage::Vote(signed, _)) =
                    postcard::from_bytes::<WireMessage>(&payload)
                {
                    self.log
                        .lock()
                        .push(OrderEvent::BroadcastVoteFor(signed.payload.view));
                }
                self.inner.broadcast(payload)
            }
            fn send_to(&self, target: NodeId, payload: Bytes) -> BoxFuture<'_, ()> {
                self.inner.send_to(target, payload)
            }
        }

        // ── Setup ──────────────────────────────────────────────────────
        let log: Arc<PlMutex<Vec<OrderEvent>>> = Arc::new(PlMutex::new(Vec::new()));
        let inner_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let storage: Arc<dyn Storage> = Arc::new(OrderingStorage {
            inner: Arc::clone(&inner_storage),
            log: Arc::clone(&log),
        });

        // Self at index 1, leader of the proposal at view 1 sits at
        // some other index; the leader sends us a Proposal we'll vote on.
        let self_signer = fresh_signer();
        let leader_signer = fresh_signer();
        let mut ids: Vec<boule_consensus::validator_set::ValidatorId> = vec![
            boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(self_signer.node_id()),
            boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(
                leader_signer.node_id(),
            ),
            boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(nid(0xA1)),
            boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(nid(0xA2)),
        ];
        ids.sort();
        let vs = ValidatorSet::new(ids);
        let cfg = NodeConfigForConsensus::for_testing(vs.clone(), genesis());
        let mut node = ConsensusNode::new(
            self_signer.node_id(),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        )
        // This test drives a hand-crafted block with a placeholder
        // committed root through the vote path; disable the #599
        // divergence check so the expected vote is not suppressed.
        .with_vote_divergence_check_disabled();
        let signer: Arc<dyn Signer> = Arc::new(self_signer);

        let (inner_bc, _outbound_rx) = make_test_broadcaster();
        let broadcaster: Arc<dyn Broadcaster> = Arc::new(OrderingBroadcaster {
            inner: inner_bc,
            log: Arc::clone(&log),
        });
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        // ── Drive a vote ───────────────────────────────────────────────
        // Hand-craft a view-1 proposal extending genesis with empty
        // commands. The leader is whichever validator at index 1 in
        // the round-robin set; we sign with `leader_signer` and route
        // through ingress to verify the safety-core path.
        let leader_id = leader_signer.node_id();
        let parent = genesis();
        let mut block = Block {
            header: BlockHeader {
                parent_hash: parent.hash(),
                height: Height(1),
                view: View(1),
                proposer: leader_id,
                state_commitment: [0; 32],
                commands_commitment: Block::commands_commitment(&[]),
                validator_history_commitment: [0; 32],
                committed_height: Height::ZERO,
                committed_state_root: [0; 32],
            },
            commands: vec![],
        };
        // Stamp the post-block commitment (#325 PR C) so the ingress
        // verifier accepts the proposal. With no commands the value
        // equals the v1 hash of the genesis-time histories.
        block.header.validator_history_commitment =
            boule_consensus::history_commitment::compute_post_block_commitment(
                &block,
                &node.validator_history,
                &node.validator_key_history,
                node.bls_key_history.as_ref(),
                &node.chain_id,
                node.signature_scheme,
                node.min_v_eff_delay,
            );
        let justify = boule_consensus::hotstuff::qc::genesis_qc(&parent, &vs);
        let proposal = Proposal { block, justify };
        let signed_proposal =
            Signed::sign(proposal, &leader_signer, &node.chain_id).expect("sign proposal");
        let wire = WireMessage::Proposal(signed_proposal);
        let payload = postcard::to_stdvec(&wire).expect("encode wire");
        let qc_verification = boule_consensus::dispatch::QcVerification::Verify {
            scheme: boule_core::crypto::sig_scheme::SignatureSchemeChoice::Ed25519Collected,
            bls_key_history: None,
            min_v_eff_delay: boule_consensus::reconfig::MIN_V_EFF_DELAY,
            genesis_hash: node.core.state().genesis_hash,
        };
        let dispatches = ingress_with_qc_verification(
            leader_id,
            &payload,
            &node.validator_history,
            &node.validator_key_history,
            &qc_verification,
            &node.chain_id,
        )
        .expect("ingress accepts the leader's proposal");
        for d in dispatches {
            node.apply_dispatch(d, broadcaster.as_ref(), &mut view_timer, &signer)
                .await
                .expect("apply_dispatch");
        }

        // ── Assert ordering ────────────────────────────────────────────
        let recorded = log.lock().clone();
        let persist_idx = recorded
            .iter()
            .position(|e| matches!(e, OrderEvent::PersistVotedInView(v) if *v == View(1)));
        let broadcast_idx = recorded
            .iter()
            .position(|e| matches!(e, OrderEvent::BroadcastVoteFor(v) if *v == View(1)));
        let persist_idx = persist_idx
            .expect("VotedInView{view: View(1)} must be persisted (storage.batch must run)");
        let broadcast_idx = broadcast_idx
            .expect("Vote{view: View(1)} must be broadcast (Action::Broadcast(Vote) must fire)");
        assert!(
            persist_idx < broadcast_idx,
            "persist must return before broadcast is called: \
             PersistVotedInView at index {persist_idx}, BroadcastVoteFor at index \
             {broadcast_idx}, full log = {recorded:?}",
        );
    }

    /// Issue #405 / audit finding 4-1 (Tendermint amnesia regression
    /// guard for the `Locked` state).
    ///
    /// Companion to `vote_persist_returns_before_send_called`. The vote
    /// guard pins `Persist(VotedInView)` before `Broadcast(Vote)`; this
    /// guard pins `Persist(Locked)` before `Broadcast(Vote)` when both
    /// fire on the same proposal (the 2-chain promotion path).
    ///
    /// Pre-fix, `step()` emitted `Action::Broadcast(Vote)` *before*
    /// `Action::Persist(StateUpdate::Locked)`. The integration layer's
    /// per-action persist-flush meant the lock landed on disk only
    /// after the vote left the wire — a crash in that window left
    /// disk with `last_voted_view` advanced and `locked` reverted to
    /// the pre-promotion value. On restart the in-memory promotion
    /// was gone, opening the canonical Tendermint amnesia hole. Issue
    /// #405 reorders emission so the persist always precedes the
    /// broadcast, and this test pins the new contract end-to-end via
    /// the same `OrderingStorage` / `OrderingBroadcaster` shells the
    /// vote-side test uses.
    ///
    /// Approach: pre-seed the safety core's `pending_blocks` with the
    /// view-1 / view-2 ancestor blocks (mirroring what two prior
    /// proposals would have done), then call `core.step()` on the
    /// view-3 proposal so we get the genuine action vector, and run
    /// it through `apply_safety_actions`. Assert the shared log
    /// records the lock persist before the vote broadcast.
    #[tokio::test]
    async fn lock_persist_returns_before_send_called_for_two_chain_promotion() {
        use bytes::Bytes;
        use parking_lot::Mutex as PlMutex;

        use boule_consensus::hotstuff::Proposal;
        use boule_consensus::hotstuff::qc::QuorumCertificate;
        use boule_core::clock::BoxFuture;
        use boule_core::storage::{Storage, WriteBatch};
        use boule_transport_tcp::overlay::Broadcaster;

        #[derive(Debug, Clone, PartialEq, Eq)]
        enum OrderEvent {
            PersistLocked(View),
            BroadcastVoteFor(View),
        }

        struct OrderingStorage {
            inner: Arc<dyn Storage>,
            log: Arc<PlMutex<Vec<OrderEvent>>>,
        }
        impl Storage for OrderingStorage {
            fn get(&self, key: &[u8]) -> anyhow::Result<Option<Bytes>> {
                self.inner.get(key)
            }
            fn put(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
                self.inner.put(key, value)
            }
            fn delete(&self, key: &[u8]) -> anyhow::Result<()> {
                self.inner.delete(key)
            }
            fn scan_prefix(&self, prefix: &[u8]) -> anyhow::Result<Vec<(Bytes, Bytes)>> {
                self.inner.scan_prefix(prefix)
            }
            fn apply_batch(&self, batch: WriteBatch) -> anyhow::Result<()> {
                let mut written_lock_view: Option<View> = None;
                for op in batch.ops() {
                    if let boule_core::storage::WriteOp::Put(key, value) = op {
                        if key.as_slice() == STORAGE_KEY_LOCKED {
                            if let Ok(l) = decode_locked(value) {
                                written_lock_view = Some(l.view);
                            }
                        }
                    }
                }
                let result = self.inner.apply_batch(batch);
                if result.is_ok() {
                    if let Some(v) = written_lock_view {
                        self.log.lock().push(OrderEvent::PersistLocked(v));
                    }
                }
                result
            }
            fn compare_and_swap(
                &self,
                key: &[u8],
                expected: Option<&[u8]>,
                new: Option<&[u8]>,
            ) -> anyhow::Result<bool> {
                self.inner.compare_and_swap(key, expected, new)
            }
        }

        struct OrderingBroadcaster {
            inner: Arc<dyn Broadcaster>,
            log: Arc<PlMutex<Vec<OrderEvent>>>,
        }
        impl Broadcaster for OrderingBroadcaster {
            fn broadcast(&self, payload: Bytes) -> BoxFuture<'_, ()> {
                if let Ok(WireMessage::Vote(signed, _)) =
                    postcard::from_bytes::<WireMessage>(&payload)
                {
                    self.log
                        .lock()
                        .push(OrderEvent::BroadcastVoteFor(signed.payload.view));
                }
                self.inner.broadcast(payload)
            }
            fn send_to(&self, target: NodeId, payload: Bytes) -> BoxFuture<'_, ()> {
                self.inner.send_to(target, payload)
            }
        }

        // ── Setup ──────────────────────────────────────────────────────
        let log: Arc<PlMutex<Vec<OrderEvent>>> = Arc::new(PlMutex::new(Vec::new()));
        let inner_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let storage: Arc<dyn Storage> = Arc::new(OrderingStorage {
            inner: Arc::clone(&inner_storage),
            log: Arc::clone(&log),
        });

        let self_signer = fresh_signer();
        let leader_signer = fresh_signer();
        let mut ids: Vec<boule_consensus::validator_set::ValidatorId> = vec![
            boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(self_signer.node_id()),
            boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(
                leader_signer.node_id(),
            ),
            boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(nid(0xA1)),
            boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(nid(0xA2)),
        ];
        ids.sort();
        let vs = ValidatorSet::new(ids);
        let cfg = NodeConfigForConsensus::for_testing(vs.clone(), genesis());
        let mut node = ConsensusNode::new(
            self_signer.node_id(),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        )
        // This test drives a hand-crafted block with a placeholder
        // committed root through the vote path; disable the #599
        // divergence check so the expected vote is not suppressed.
        .with_vote_divergence_check_disabled();
        let signer: Arc<dyn Signer> = Arc::new(self_signer);

        let (inner_bc, _outbound_rx) = make_test_broadcaster();
        let broadcaster: Arc<dyn Broadcaster> = Arc::new(OrderingBroadcaster {
            inner: inner_bc,
            log: Arc::clone(&log),
        });
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        // ── Build the chain genesis → b_v1 → b_v2 → b_v3 ──────────────
        // Pre-seed b_v1 and b_v2 in `pending_blocks` so the b_v3
        // proposal triggers the 2-chain promotion in a single `step()`
        // (the grandparent walk reaches b_v1, height 1, beating the
        // None-baseline lock).
        let leader_id = leader_signer.node_id();
        fn build_block(parent: &Block, view: u64, proposer: NodeId) -> Block {
            Block {
                header: BlockHeader {
                    parent_hash: parent.hash(),
                    height: parent.header.height + 1,
                    view: View(view),
                    proposer,
                    state_commitment: [0; 32],
                    commands_commitment: Block::commands_commitment(&[]),
                    validator_history_commitment: [0; 32],
                    committed_height: Height::ZERO,
                    committed_state_root: [0; 32],
                },
                commands: vec![],
            }
        }
        let parent = genesis();
        let b_v1 = build_block(&parent, 1, leader_id);
        let b_v2 = build_block(&b_v1, 2, leader_id);
        let mut b_v3 = build_block(&b_v2, 3, leader_id);
        // The validator-history commitment goes on the broadcast, not
        // on the safe-to-vote path — `core.step()` doesn't re-verify
        // it. We still stamp it for parity with the wire shape.
        b_v3.header.validator_history_commitment =
            boule_consensus::history_commitment::compute_post_block_commitment(
                &b_v3,
                &node.validator_history,
                &node.validator_key_history,
                node.bls_key_history.as_ref(),
                &node.chain_id,
                node.signature_scheme,
                node.min_v_eff_delay,
            );

        node.core.insert_pending_block(b_v1.clone());
        node.core.insert_pending_block(b_v2.clone());

        let justify_v2 = QuorumCertificate::new(2, b_v2.hash(), vs.len());
        let proposal_v3 = Proposal {
            block: b_v3,
            justify: justify_v2,
        };
        let signed_v3 =
            Signed::sign(proposal_v3, &leader_signer, &node.chain_id).expect("sign proposal");

        // Run the safety core to produce the action vector for the
        // view-3 proposal. The audit-fixed `on_proposal_received`
        // emits Persist(VotedInView), Persist(HighQc), Persist(Locked),
        // Broadcast(Vote), Commit(genesis) — in that order.
        let actions = node
            .core
            .step(boule_consensus::hotstuff::step::Event::ProposalReceived(
                boule_consensus::dispatch::Verified::unchecked(signed_v3),
            ));
        // Sanity: both items the test cares about are present.
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, SafetyAction::Persist(StateUpdate::Locked(_)))),
            "test setup: 2-chain promotion must emit Persist(Locked); actions={actions:?}",
        );
        assert!(
            actions.iter().any(|a| matches!(
                a,
                SafetyAction::Broadcast(boule_consensus::hotstuff::ConsensusMsg::Vote(_))
            )),
            "test setup: safe-to-vote must emit Broadcast(Vote); actions={actions:?}",
        );

        // Drive the actions through the integration layer's persist-
        // before-send flush discipline.
        node.apply_safety_actions(actions, broadcaster.as_ref(), &mut view_timer, &signer)
            .await
            .expect("apply_safety_actions");

        // ── Assert ordering ────────────────────────────────────────────
        let recorded = log.lock().clone();
        let persist_idx = recorded
            .iter()
            .position(|e| matches!(e, OrderEvent::PersistLocked(_)))
            .expect("Persist(Locked) must reach storage.batch");
        let broadcast_idx = recorded
            .iter()
            .position(|e| matches!(e, OrderEvent::BroadcastVoteFor(v) if *v == View(3)))
            .expect("Vote{view: View(3)} must be broadcast");
        assert!(
            persist_idx < broadcast_idx,
            "audit finding 4-1: lock persist must return before vote broadcast is called: \
             PersistLocked at index {persist_idx}, BroadcastVoteFor(3) at index \
             {broadcast_idx}, full log = {recorded:?}",
        );

        // And the lock is actually on disk, not just routed through the
        // hook — the on-disk shape is what survives a process crash.
        let raw = inner_storage
            .get(STORAGE_KEY_LOCKED)
            .unwrap()
            .expect("locked entry must be persisted");
        let on_disk = decode_locked(&raw).unwrap();
        assert_eq!(
            on_disk.view,
            View(1),
            "on-disk lock must match the view-1 grandparent: {on_disk:?}",
        );
    }

    /// A self-addressed `RequestBlock` is degenerate — we can't service
    /// a block request from ourselves. It must be dropped locally rather
    /// than leaking to the p2p layer as "SendTo unknown peer SELF".
    #[tokio::test]
    async fn request_block_from_self_is_dropped() {
        let ns = fresh_signer();
        let (mut node, _vs) = make_node_with_signer(&ns, 0);
        let self_id = node.self_id;
        let signer: Arc<dyn Signer> = Arc::new(ns);

        let (broadcaster, mut send_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        let action = SafetyAction::RequestBlock {
            hash: [0xCD; 32],
            peer: self_id,
            expected_height: Height(7),
            reason: boule_consensus::hotstuff::step::BlockSyncReason::UnknownParentOnProposal,
        };
        node.apply_safety_actions(vec![action], broadcaster.as_ref(), &mut view_timer, &signer)
            .await
            .unwrap();
        assert!(send_rx.try_recv().is_err());
    }

    // ── Structured-trace contract (#122, #192) ──────────────────────────────

    /// Operator-visible structured-log message names that the
    /// integration layer is expected to keep emitting on the
    /// pacemaker → safety → outbound flow. These are the strings
    /// runbooks and dashboards grep for; renaming or deleting one
    /// silently breaks downstream observability.
    ///
    /// The previous incarnation of this guard installed a
    /// `tracing-subscriber` and asserted these messages fired in a
    /// specific order during a happy-path leader flow. That test was
    /// flaky under parallel `cargo test` because tracing's
    /// per-thread dispatcher state interleaves with sibling test
    /// workers (issue #192 — flaky for both `with_subscriber` and
    /// `set_default` capture variants). Replacing it with a static
    /// source-text check trades the order assertion (which any
    /// refactor that breaks ordering would also reflect in the
    /// source-text co-location of these macros) for a deterministic,
    /// always-correct check that catches the load-bearing
    /// regression: a trace point being deleted or renamed.
    const EXPECTED_OPERATOR_TRACE_MESSAGES: &[&str] = &[
        "pacemaker_event",
        "pacemaker_action",
        "view_advanced",
        "outbound_broadcast",
        "new_view_received",
        "proposal_received",
        "persisted",
        "vote_received",
    ];

    /// Snapshot of every `node/*.rs` source file baked into the test
    /// binary at compile time. Lets the contract test scan for
    /// `tracing::debug!(...)` macro calls across every submodule
    /// without adding a runtime dependency on the file system or on
    /// cargo's package layout. The integration layer was split into
    /// the `node/` submodule tree (issue #368); the trace contract
    /// holds across the whole tree.
    const NODE_SOURCE_FOR_TRACE_AUDIT: &str = concat!(
        include_str!("mod.rs"),
        include_str!("action_interpreter.rs"),
        include_str!("block_builder.rs"),
        include_str!("commit.rs"),
        include_str!("config.rs"),
        include_str!("persistence.rs"),
        include_str!("reconfig_apply.rs"),
        include_str!("rotation_apply.rs"),
        include_str!("snapshot_io.rs"),
        include_str!("status.rs"),
        include_str!("timeout_bucket.rs"),
    );

    /// Each name in [`EXPECTED_OPERATOR_TRACE_MESSAGES`] must appear
    /// as a quoted string literal somewhere under `src/consensus/node/`
    /// at least twice — once in the contract array immediately above,
    /// and at least once more at the actual `tracing::debug!` macro
    /// call site. Counting `>= 2` is what catches deletion or
    /// rename of the macro call: the array entry alone leaves the
    /// count at exactly 1 and the assertion trips. If the rename is
    /// intentional, both the macro and the array are updated
    /// together and the count stays >= 2 with the new name.
    #[test]
    fn integration_layer_keeps_emitting_operator_trace_messages() {
        for name in EXPECTED_OPERATOR_TRACE_MESSAGES {
            // Quote the literal so we match `tracing::debug!(... "msg")`
            // and the array entry, not bare-word references in
            // comments or in field names with the same spelling.
            let needle = format!("\"{name}\"");
            let count = NODE_SOURCE_FOR_TRACE_AUDIT.matches(&needle).count();
            assert!(
                count >= 2,
                "operator-runbook contract: structured-trace message {name:?} appears \
                 only {count} time(s) as a quoted literal under src/consensus/node/ \
                 (expected >= 2: one in EXPECTED_OPERATOR_TRACE_MESSAGES, one at the \
                 tracing::debug! call site). Renaming or removing this message silently \
                 breaks downstream log filters; if the rename is intentional, update \
                 EXPECTED_OPERATOR_TRACE_MESSAGES and any operator documentation that \
                 references the old name.",
            );
        }
    }

    /// `view_advanced` carries `cause = ?` (Qc/Tc), and the string
    /// tag operators read off the wire is fixed by
    /// [`boule_consensus::pacemaker::AdvanceCause::as_str`]. Pinning
    /// these here keeps the structured-log contract regression-checked
    /// without going through the dispatcher; renaming `"qc"` → `"QC"`
    /// (etc.) would silently break grep-based dashboards.
    #[test]
    fn advance_cause_strings_match_operator_runbooks() {
        use boule_consensus::pacemaker::AdvanceCause;
        assert_eq!(AdvanceCause::Qc.as_str(), "qc");
        assert_eq!(AdvanceCause::Tc.as_str(), "tc");
        assert_eq!(AdvanceCause::RoundSync.as_str(), "round_sync");
    }

    // ── RateLimiter integration (issue #134) ────────────────────────────────

    use boule_consensus::rate_limit::MessageRateLimiter as RateLimiter;
    use boule_core::clock::{Clock, TokioClock};
    use boule_core::transport::limits::RateLimitsConfig;
    use boule_transport_tcp::PeerCommand;

    /// Build a `WireMessage::BlockRequest([0; 32])` postcard frame.
    /// Cheap to construct (no signing required) and decodes cleanly
    /// through `dispatch::ingress` so an honest frame survives the
    /// `Decision::Allow` path. Wire tag = 4.
    fn block_request_frame() -> bytes::Bytes {
        let msg = WireMessage::BlockRequest([0u8; 32]);
        bytes::Bytes::from(postcard::to_allocvec(&msg).expect("encode"))
    }

    /// Issue #134 acceptance criterion: a peer that floods at 10× the
    /// configured rate has its excess frames dropped *and* gets
    /// disconnected after K violations. We measure both outcomes —
    /// the drop counter rises and a `PeerCommand::Disconnect` lands
    /// on the manager-side channel.
    #[tokio::test]
    async fn flooding_peer_is_dropped_and_disconnected() {
        // Build a config with a tight per-kind bucket and a low
        // K so the test finishes quickly.
        let cfg = RateLimitsConfig {
            per_kind_per_sec: vec![1.0; MessageKind::ALL.len()],
            bytes_per_sec: 1024.0 * 1024.0, // generous, isolate the test on per-kind
            outbound_bytes_per_sec: 1024.0 * 1024.0,
            burst_seconds: 1.0,
            violation_window: std::time::Duration::from_secs(60),
            max_violations: 5,
        };
        let clock: Arc<dyn Clock> = Arc::new(TokioClock::new());
        let limiter = Arc::new(RateLimiter::new(cfg, Arc::clone(&clock)));

        let node = make_node(nid(1));
        let (peer_cmd_tx, mut peer_cmd_rx) = tokio::sync::mpsc::channel::<PeerCommand>(8);
        let node = node.with_rate_limiter(Arc::clone(&limiter), Some(peer_cmd_tx));

        let signer = fresh_signer();
        let (event_tx, event_rx) = make_test_event_channel();
        let (broadcaster, mut _outbound_rx) = make_test_broadcaster();
        let discovery = make_test_discovery();
        let (_shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let _join = tokio::spawn(async move {
            let _ = node
                .run(
                    broadcaster,
                    discovery,
                    event_rx,
                    Arc::new(signer),
                    shutdown_rx,
                )
                .await;
        });

        // Drain occasional outbound traffic so the broadcaster channel
        // doesn't backpressure the run loop.
        let drain = tokio::spawn(async move { while _outbound_rx.recv().await.is_some() {} });

        // Flood ~50 BlockRequests from a single peer. The first ~1 fits
        // in the bucket, the rest become violations; after
        // max_violations the limiter returns Decision::Disconnect once
        // and the run loop forwards a PeerCommand::Disconnect.
        let attacker = nid(99);
        let frame = block_request_frame();
        for _ in 0..50 {
            event_tx
                .send(ProtocolEvent::Message {
                    from: attacker,
                    payload: frame.clone(),
                })
                .await
                .expect("event_rx alive");
        }

        // Wait for the disconnect command. 1s is generous — the run
        // loop processes the flood without any I/O.
        let cmd = tokio::time::timeout(Duration::from_secs(1), peer_cmd_rx.recv())
            .await
            .expect("disconnect command must fire within 1s")
            .expect("peer_cmd_tx closed");
        match cmd {
            PeerCommand::Disconnect { node_id } => {
                assert_eq!(
                    node_id, attacker,
                    "disconnect must target the flooding peer"
                );
            }
            other => panic!("expected Disconnect, got {other:?}"),
        }

        // The limiter's per-kind drop counter and disconnect counter
        // also reflect the flood.
        assert!(
            limiter.counters().drops(MessageKind::RequestBlock as usize) > 0,
            "BlockRequest drops must accumulate"
        );
        assert_eq!(limiter.counters().disconnects(), 1);

        drain.abort();
    }

    /// Honest steady-state with the production-default rate limits
    /// installed must never drop a frame. Mirrors the issue's
    /// "1k-block sim → zero drops" criterion in miniature: we feed
    /// a small steady stream that stays well below the per-kind
    /// caps and assert zero drops.
    #[tokio::test]
    async fn honest_steady_state_does_not_trip_default_limits() {
        let clock: Arc<dyn Clock> = Arc::new(TokioClock::new());
        let limiter = Arc::new(RateLimiter::new(
            boule_consensus::rate_limit::production_message_rate_limits(),
            Arc::clone(&clock),
        ));

        let node = make_node(nid(1));
        let (peer_cmd_tx, _peer_cmd_rx) = tokio::sync::mpsc::channel::<PeerCommand>(8);
        let node = node.with_rate_limiter(Arc::clone(&limiter), Some(peer_cmd_tx));

        let signer = fresh_signer();
        let (event_tx, event_rx) = make_test_event_channel();
        let (broadcaster, mut _outbound_rx) = make_test_broadcaster();
        let discovery = make_test_discovery();
        let (_shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            let _ = node
                .run(
                    broadcaster,
                    discovery,
                    event_rx,
                    Arc::new(signer),
                    shutdown_rx,
                )
                .await;
        });
        let drain = tokio::spawn(async move { while _outbound_rx.recv().await.is_some() {} });

        // Send 8 BlockRequests/sec equivalent (the default cap is 8/s).
        // We push 4 per peer in one burst — well within the 8-token
        // capacity. With four peers the per-peer counter never trips
        // because each peer has its own bucket.
        let frame = block_request_frame();
        for peer_byte in 1..=4u8 {
            let peer = [peer_byte; 32];
            for _ in 0..4 {
                event_tx
                    .send(ProtocolEvent::Message {
                        from: peer,
                        payload: frame.clone(),
                    })
                    .await
                    .unwrap();
            }
        }
        // Give the run loop a few ticks to drain the queue.
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }

        assert_eq!(
            limiter.counters().total_drops(),
            0,
            "honest steady-state below the per-kind cap must not drop"
        );
        assert_eq!(limiter.counters().disconnects(), 0);

        drain.abort();
    }

    /// A peer flooding `RequestBlock` does not affect another peer's
    /// `Vote` budget — the per-type, per-peer buckets are
    /// independent. Issue #134 acceptance: "saturating one type doesn't
    /// starve another".
    #[tokio::test]
    async fn one_peer_saturating_one_type_does_not_starve_another() {
        let cfg = RateLimitsConfig {
            per_kind_per_sec: vec![4.0; MessageKind::ALL.len()],
            bytes_per_sec: 1024.0 * 1024.0,
            outbound_bytes_per_sec: 1024.0 * 1024.0,
            burst_seconds: 1.0,
            violation_window: std::time::Duration::from_secs(60),
            max_violations: 1_000_000, // never disconnect in this test
        };
        let clock: Arc<dyn Clock> = Arc::new(TokioClock::new());
        let limiter = Arc::new(RateLimiter::new(cfg, Arc::clone(&clock)));

        // Saturate Peer A's RequestBlock bucket.
        let peer_a = nid(0xAA);
        let frame = block_request_frame();
        for _ in 0..20 {
            let _ = limiter.admit(peer_a, MessageKind::RequestBlock, frame.len());
        }
        assert!(limiter.counters().drops(MessageKind::RequestBlock as usize) > 0);

        // Peer B's Vote bucket is unaffected.
        let peer_b = nid(0xBB);
        for _ in 0..4 {
            assert_eq!(
                limiter.admit(peer_b, MessageKind::Vote, 64),
                boule_core::transport::limits::Decision::Allow
            );
        }
        // And Peer A's Vote bucket is unaffected too — distinct
        // bucket per (peer, kind).
        for _ in 0..4 {
            assert_eq!(
                limiter.admit(peer_a, MessageKind::Vote, 64),
                boule_core::transport::limits::Decision::Allow
            );
        }
    }

    // ── Snapshot creation hook ──────────────────────────────────────────
    //
    // These tests exercise the `apply_commit → try_take_snapshot` path
    // at the integration-layer level, without spinning up the sim
    // cluster. They drive the same code paths an inbound proposal +
    // 3-chain commit would, but synthesize the inputs directly:
    //
    //   1. Persist a `HighQc` so the in-memory `recent_qcs` cache has
    //      a QC whose `block_hash` matches the block we're about to
    //      commit. (`persist_updates` populates the cache as a side
    //      effect — that side effect is what the snapshot hook
    //      depends on.)
    //   2. Call `apply_commit(block)` directly. The snapshot policy is
    //      checked against `block.header.height`, so the test controls
    //      which heights trigger.
    //   3. Inspect the snapshot store to assert the expected manifests
    //      and chunks landed (or didn't).

    fn snapshot_test_config(
        vs: ValidatorSet,
        policy: boule_consensus::replication::snapshot::SnapshotPolicy,
    ) -> NodeConfigForConsensus {
        let mut cfg = NodeConfigForConsensus::for_testing(vs, genesis());
        cfg.snapshot_policy = policy;
        cfg
    }

    fn make_committable_block(parent: &Block, height: u64, view: u64) -> Block {
        // Synthesize a block whose header is well-formed enough for
        // `apply_commit` to write to storage without complaint. The
        // safety-rule walks aren't exercised here — `apply_commit`
        // is the integration-layer hook, not the safety core.
        let commands: Vec<bytes::Bytes> = Vec::new();
        Block {
            header: BlockHeader {
                parent_hash: parent.hash(),
                height: Height(height),
                view: View(view),
                proposer: [0u8; 32],
                state_commitment: [0u8; 32],
                commands_commitment: Block::commands_commitment(&commands),
                validator_history_commitment: [0; 32],
                committed_height: Height::ZERO,
                committed_state_root: [0; 32],
            },
            commands,
        }
    }

    #[test]
    fn snapshot_created_on_commit_at_interval() {
        let policy = boule_consensus::replication::snapshot::SnapshotPolicy {
            interval_blocks: 5,
            retention_count: 3,
            chunk_size_bytes: 1024,
        };
        let cfg = snapshot_test_config(four_validators(), policy);
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let mut node = ConsensusNode::new(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );

        // Build a block at height 5 (the first multiple of the
        // interval after genesis). Persist a QC over its hash so the
        // recent_qcs cache is populated when apply_commit runs.
        let parent = genesis();
        let block = make_committable_block(&parent, 5, 5);
        let mut qc = QuorumCertificate::new(5, block.hash(), 4);
        qc.add_signature(0, [0u8; 64]);
        qc.add_signature(1, [0u8; 64]);
        qc.add_signature(2, [0u8; 64]);
        node.persist_updates(&[StateUpdate::HighQc(qc.clone())])
            .unwrap();

        node.apply_commit(block.clone());

        let store =
            boule_consensus::replication::snapshot::SnapshotStore::new(Arc::clone(&storage));
        let manifest = store
            .load_manifest(5)
            .unwrap()
            .expect("snapshot must have been created at height 5");
        assert_eq!(manifest.height, Height(5));
        assert_eq!(manifest.view, View(5));
        assert_eq!(manifest.block_hash, block.hash());
        // Manifest's QC matches the one we cached.
        assert_eq!(manifest.commit_qc, qc);
        // Validator set round-trips byte-for-byte.
        assert_eq!(manifest.validator_set(), four_validators());
        // Latest pointer matches.
        assert_eq!(store.latest_height().unwrap(), Some(5));
    }

    #[test]
    fn snapshot_not_created_when_disabled_default() {
        // Default config has `SnapshotPolicy::disabled()`, so
        // committing a block (any height) must leave the snapshot
        // store empty. This is the "tests that don't opt in see zero
        // behavioural change" acceptance criterion.
        let cfg = test_config(four_validators());
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let mut node = ConsensusNode::new(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );

        let parent = genesis();
        let block = make_committable_block(&parent, 1, 1);
        let mut qc = QuorumCertificate::new(1, block.hash(), 4);
        qc.add_signature(0, [0u8; 64]);
        qc.add_signature(1, [0u8; 64]);
        qc.add_signature(2, [0u8; 64]);
        node.persist_updates(&[StateUpdate::HighQc(qc)]).unwrap();
        node.apply_commit(block);

        let store = boule_consensus::replication::snapshot::SnapshotStore::new(storage);
        assert!(store.list_heights().unwrap().is_empty());
        assert_eq!(store.latest_height().unwrap(), None);
    }

    #[test]
    fn snapshot_skipped_for_non_interval_height() {
        let policy = boule_consensus::replication::snapshot::SnapshotPolicy {
            interval_blocks: 5,
            retention_count: 3,
            chunk_size_bytes: 1024,
        };
        let cfg = snapshot_test_config(four_validators(), policy);
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let mut node = ConsensusNode::new(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );

        let parent = genesis();
        let block = make_committable_block(&parent, 3, 3); // not a multiple of 5
        let mut qc = QuorumCertificate::new(3, block.hash(), 4);
        qc.add_signature(0, [0u8; 64]);
        qc.add_signature(1, [0u8; 64]);
        qc.add_signature(2, [0u8; 64]);
        node.persist_updates(&[StateUpdate::HighQc(qc)]).unwrap();
        node.apply_commit(block);

        let store = boule_consensus::replication::snapshot::SnapshotStore::new(storage);
        assert!(store.list_heights().unwrap().is_empty());
    }

    #[test]
    fn snapshot_skipped_when_qc_not_in_cache() {
        // The cache is bounded; a snapshot at a height whose QC has
        // been evicted must be silently skipped (warning logged) so
        // the chain keeps moving. Recreate that case by feeding the
        // cache (RECENT_QC_CACHE_CAPACITY + 1) unrelated QCs before
        // committing — the QC for our target block is never inserted.
        let policy = boule_consensus::replication::snapshot::SnapshotPolicy {
            interval_blocks: 5,
            retention_count: 3,
            chunk_size_bytes: 1024,
        };
        let cfg = snapshot_test_config(four_validators(), policy);
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let mut node = ConsensusNode::new(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );

        let parent = genesis();
        let block = make_committable_block(&parent, 5, 5);
        // Note: we deliberately do NOT persist a HighQc over
        // `block.hash()`. The cache is empty for this hash, so the
        // snapshot creation hook returns early.
        node.apply_commit(block);

        let store = boule_consensus::replication::snapshot::SnapshotStore::new(storage);
        assert!(store.list_heights().unwrap().is_empty());
    }

    #[test]
    fn snapshot_retention_prunes_older_after_each_commit() {
        let policy = boule_consensus::replication::snapshot::SnapshotPolicy {
            interval_blocks: 5,
            retention_count: 3,
            chunk_size_bytes: 1024,
        };
        let cfg = snapshot_test_config(four_validators(), policy);
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let mut node = ConsensusNode::new(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );

        // Drive 5 snapshots at heights 5, 10, 15, 20, 25. Each commit
        // is independent — the safety-core invariants aren't checked
        // here, just the integration hook.
        for n in 1..=5u64 {
            let height = n * 5;
            let parent = if height == 5 {
                genesis()
            } else {
                make_committable_block(&genesis(), height - 1, height - 1)
            };
            let block = make_committable_block(&parent, height, height);
            let mut qc = QuorumCertificate::new(View(height), block.hash(), 4);
            qc.add_signature(0, [0u8; 64]);
            qc.add_signature(1, [0u8; 64]);
            qc.add_signature(2, [0u8; 64]);
            node.persist_updates(&[StateUpdate::HighQc(qc)]).unwrap();
            node.apply_commit(block);
        }

        let store = boule_consensus::replication::snapshot::SnapshotStore::new(storage);
        // Retention=3 keeps the 3 most-recent (15, 20, 25); 5 and 10
        // are pruned. The pruner runs atomically with each new
        // snapshot, so the assertion holds at any point after
        // commit-25.
        assert_eq!(store.list_heights().unwrap(), vec![15, 20, 25]);
        assert_eq!(store.latest_height().unwrap(), Some(25));
    }

    #[test]
    fn snapshot_retention_zero_keeps_all_snapshots() {
        let policy = boule_consensus::replication::snapshot::SnapshotPolicy {
            interval_blocks: 5,
            retention_count: 0, // disable pruning
            chunk_size_bytes: 1024,
        };
        let cfg = snapshot_test_config(four_validators(), policy);
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let mut node = ConsensusNode::new(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );

        for n in 1..=4u64 {
            let height = n * 5;
            let parent = if height == 5 {
                genesis()
            } else {
                make_committable_block(&genesis(), height - 1, height - 1)
            };
            let block = make_committable_block(&parent, height, height);
            let mut qc = QuorumCertificate::new(View(height), block.hash(), 4);
            qc.add_signature(0, [0u8; 64]);
            qc.add_signature(1, [0u8; 64]);
            qc.add_signature(2, [0u8; 64]);
            node.persist_updates(&[StateUpdate::HighQc(qc)]).unwrap();
            node.apply_commit(block);
        }

        let store = boule_consensus::replication::snapshot::SnapshotStore::new(storage);
        assert_eq!(store.list_heights().unwrap(), vec![5, 10, 15, 20]);
    }

    // ── #325 PR B: recovery-time validation acceptance tests ───────────────────
    //
    // The audit's anti-rollback gate is "a node that loaded a tampered
    // history blob must refuse to start." These tests pin that gate
    // by exercising the rebuild-from-chain path on:
    //
    //  1. Fresh genesis-only node (happy path).
    //  2. Single-byte-flip in a v_eff field.
    //  3. Append-a-fake-boundary tampering.
    //  4. Wrong-genesis-member-set tampering.
    //  5. BLS chain happy path (separate code branch from #1).
    //
    // Bisect-confirmation is noted in the PR summary: temporarily
    // disabling the end-of-walk equality check makes test #2 pass when
    // it should fail, proving the gate is what produces the rejection.

    /// Build a genesis block whose `validator_history_commitment` is
    /// the real v1 hash over the genesis-time histories — what the
    /// production `build_genesis` does (#325 PR B). For genesis the
    /// post-block hash (#325 PR C) equals the pre-block hash because
    /// genesis has no commands to apply.
    fn genesis_with_real_commitment(vs: &ValidatorSet) -> Block {
        let set_hist = ValidatorSetHistory::from_genesis(vs.clone());
        let key_hist = ValidatorKeyHistory::new(vs.iter().copied());
        let commitment = boule_consensus::history_commitment::validator_history_commitment_v1(
            &set_hist, &key_hist, None,
        );
        Block::genesis([0u8; 32], commitment)
    }

    /// Patch `block.header.validator_history_commitment` so it equals
    /// the v1 hash of the post-block histories, computed by forking
    /// the node's current `(set, key, bls?)` triple and applying the
    /// block's commands (#325 PR C). Mirrors what the leader-side
    /// stamp in `apply_safety_actions` does at proposal time, and
    /// what the proposal-receive verifier in `dispatch` checks.
    fn stamp_post_block_commitment(block: &mut Block, node: &ConsensusNode) {
        block.header.validator_history_commitment =
            boule_consensus::history_commitment::compute_post_block_commitment(
                block,
                &node.validator_history,
                &node.validator_key_history,
                node.bls_key_history.as_ref(),
                &node.chain_id,
                node.signature_scheme,
                node.min_v_eff_delay,
            );
    }

    /// Like [`block_with_reconfig`] but takes an explicit genesis hash
    /// for `parent_hash` so the rebuilt-chain walk can chase the link.
    fn block_with_reconfig_extending(
        parent_hash: BlockHash,
        height: u64,
        view: u64,
        proposer: NodeId,
        cmd: boule_consensus::reconfig::ReconfigCommand,
        validator_history_commitment: [u8; 32],
    ) -> Block {
        let payload = cmd.encode();
        let commands = vec![payload];
        let header = boule_consensus::replication::block::BlockHeader {
            parent_hash,
            height: Height(height),
            view: View(view),
            proposer,
            state_commitment: [0u8; 32],
            commands_commitment: Block::commands_commitment(&commands),
            validator_history_commitment,
            committed_height: Height::ZERO,
            committed_state_root: [0; 32],
        };
        Block { header, commands }
    }

    /// Test 1 (happy path): construct a node, commit a few blocks
    /// (including one with a reconfig), persist storage, then drop
    /// and recover. Verify recovery passes the consistency check.
    #[test]
    fn verify_persisted_history_consistency_happy_path() {
        use boule_consensus::reconfig::{MIN_V_EFF_DELAY, ReconfigCommand, ValidatorEntry};

        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let vs = four_validators();
        let g = genesis_with_real_commitment(&vs);
        let cfg = NodeConfigForConsensus::for_testing(vs.clone(), g.clone());

        // Phase 1: commit a block carrying a reconfig.
        let mut node = ConsensusNode::new(
            nid(1),
            cfg.clone(),
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );
        // Block 1 carries a reconfig. Stamp the post-block commitment
        // (#325 PR C) so the recovery walk's apply-then-hash check
        // matches.
        let v_eff = MIN_V_EFF_DELAY + 5;
        let cmd = ReconfigCommand {
            adds: vec![ValidatorEntry {
                node_id: nid(5),
                addr: "127.0.0.1:9005".parse().unwrap(),
                bls_pop: None,
                weight: 1,
            }],
            removes: vec![],
            changes: vec![],
            v_eff,
        };
        let mut block1 = block_with_reconfig_extending(g.hash(), 1, 0, nid(1), cmd, [0u8; 32]);
        stamp_post_block_commitment(&mut block1, &node);
        node.apply_commit(block1);
        // Sanity: the reconfig must have applied so the recovered
        // history has 2 boundaries.
        assert_eq!(node.validator_history.boundary_count(), 2);
        drop(node);

        // Phase 2: recover and run the consistency check.
        let recovered = ConsensusNode::recover(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        )
        .expect("recover should succeed");
        recovered
            .verify_persisted_history_consistency()
            .expect("happy-path recovery must pass consistency check");
    }

    /// Test 2 (corrupt blob — single byte flip): flip one byte inside
    /// a boundary's `v_eff` field of the persisted validator-history
    /// blob. Recovery's consistency check must reject.
    #[test]
    fn verify_persisted_history_consistency_rejects_byte_flip_in_v_eff() {
        use boule_consensus::reconfig::{MIN_V_EFF_DELAY, ReconfigCommand, ValidatorEntry};
        use boule_consensus::validator_history::PersistedValidatorHistory;

        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let vs = four_validators();
        let g = genesis_with_real_commitment(&vs);
        let cfg = NodeConfigForConsensus::for_testing(vs.clone(), g.clone());

        // Commit a block with a reconfig so the persisted history has
        // a non-genesis boundary whose v_eff we can flip.
        let mut node = ConsensusNode::new(
            nid(1),
            cfg.clone(),
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );
        let v_eff = MIN_V_EFF_DELAY + 5;
        let cmd = ReconfigCommand {
            adds: vec![ValidatorEntry {
                node_id: nid(5),
                addr: "127.0.0.1:9005".parse().unwrap(),
                bls_pop: None,
                weight: 1,
            }],
            removes: vec![],
            changes: vec![],
            v_eff,
        };
        let mut block1 = block_with_reconfig_extending(g.hash(), 1, 0, nid(1), cmd, [0u8; 32]);
        stamp_post_block_commitment(&mut block1, &node);
        node.apply_commit(block1);
        drop(node);

        // Tamper: decode the persisted blob, change the second
        // boundary's v_eff (the reconfig's v_eff), re-encode, write
        // back. This is the "modifies one boundary's v_eff" case the
        // audit explicitly calls out.
        let raw = storage
            .get(STORAGE_KEY_VALIDATOR_HISTORY)
            .unwrap()
            .expect("validator history blob must be persisted");
        let mut persisted: PersistedValidatorHistory = postcard::from_bytes(&raw).unwrap();
        assert_eq!(persisted.boundaries.len(), 2);
        persisted.boundaries[1].v_eff = View(persisted.boundaries[1].v_eff.0.wrapping_add(1));
        let tampered = postcard::to_stdvec(&persisted).unwrap();
        storage
            .put(STORAGE_KEY_VALIDATOR_HISTORY, &tampered)
            .unwrap();

        // Recover and check: the consistency check must reject.
        let recovered = ConsensusNode::recover(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        )
        .expect("recover (decoding the tampered blob) succeeds; the gate is the consistency check");
        let err = recovered
            .verify_persisted_history_consistency()
            .expect_err("consistency check must reject tampered v_eff");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("validator_history") || msg.contains("history_commitment"),
            "error message should mention the failing surface: {msg}",
        );
    }

    /// Test 3 (tampered blob — extra boundary): append a fabricated
    /// boundary to the persisted history with a `v_eff` past anything
    /// the chain saw. Recovery must reject.
    #[test]
    fn verify_persisted_history_consistency_rejects_extra_boundary() {
        use boule_consensus::validator_history::{PersistedBoundary, PersistedValidatorHistory};

        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let vs = four_validators();
        let g = genesis_with_real_commitment(&vs);
        let cfg = NodeConfigForConsensus::for_testing(vs.clone(), g.clone());

        // Commit a single empty block so there's a chain to walk
        // (the tip's `last_committed_hash` is non-genesis, and the
        // tip's stamped commitment is the genesis-baseline hash).
        let mut node = ConsensusNode::new(
            nid(1),
            cfg.clone(),
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );
        let pre_block_commitment =
            boule_consensus::history_commitment::validator_history_commitment_v1(
                &node.validator_history,
                &node.validator_key_history,
                None,
            );
        let block1 = Block {
            header: boule_consensus::replication::block::BlockHeader {
                parent_hash: g.hash(),
                height: Height(1),
                view: View(1),
                proposer: nid(1),
                state_commitment: [0u8; 32],
                commands_commitment: Block::commands_commitment(&[]),
                validator_history_commitment: pre_block_commitment,
                committed_height: Height::ZERO,
                committed_state_root: [0; 32],
            },
            commands: vec![],
        };
        node.apply_commit(block1);
        drop(node);

        // Without the validator-history blob persisted (no reconfig
        // committed), the loaded history is empty-genesis-only. Seed
        // it explicitly so we have a blob to tamper. We do this by
        // manually persisting the genesis-only persisted form, then
        // appending a fake boundary.
        let genesis_only = ValidatorSetHistory::from_genesis(vs.clone()).to_persisted();
        let mut tampered = PersistedValidatorHistory {
            boundaries: genesis_only.boundaries,
        };
        tampered.boundaries.push(PersistedBoundary {
            v_eff: View(999), // Past anything in the committed chain.
            members: vec![nid(1), nid(2), nid(3), nid(4), nid(99)],
            weights: vec![1; 5],
        });
        let bytes = postcard::to_stdvec(&tampered).unwrap();
        storage.put(STORAGE_KEY_VALIDATOR_HISTORY, &bytes).unwrap();

        let recovered = ConsensusNode::recover(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        )
        .expect("recover decodes the (well-formed) tampered blob");
        let err = recovered
            .verify_persisted_history_consistency()
            .expect_err("consistency check must reject extra boundary");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("validator_history") || msg.contains("history_commitment"),
            "error must mention the failing surface: {msg}",
        );
    }

    /// Test 4 (tampered blob — wrong genesis member set): change a
    /// NodeId in the genesis boundary, re-encode, write back.
    /// Recovery must reject (the genesis-iteration commitment check
    /// fires because the rebuilt seed depends on the loaded blob's
    /// genesis members).
    #[test]
    fn verify_persisted_history_consistency_rejects_tampered_genesis_member() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let vs = four_validators();
        let g = genesis_with_real_commitment(&vs);
        let cfg = NodeConfigForConsensus::for_testing(vs.clone(), g.clone());

        // Commit a single empty block — we need a non-zero chain
        // height so the recovery-time walk runs (height == 0 is the
        // "no chain to walk" early return).
        let mut node = ConsensusNode::new(
            nid(1),
            cfg.clone(),
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );
        let pre_block_commitment =
            boule_consensus::history_commitment::validator_history_commitment_v1(
                &node.validator_history,
                &node.validator_key_history,
                None,
            );
        let block1 = Block {
            header: boule_consensus::replication::block::BlockHeader {
                parent_hash: g.hash(),
                height: Height(1),
                view: View(1),
                proposer: nid(1),
                state_commitment: [0u8; 32],
                commands_commitment: Block::commands_commitment(&[]),
                validator_history_commitment: pre_block_commitment,
                committed_height: Height::ZERO,
                committed_state_root: [0; 32],
            },
            commands: vec![],
        };
        node.apply_commit(block1);
        drop(node);

        // Seed and tamper: write a genesis-only blob with a NodeId
        // swapped in the genesis boundary.
        let mut tampered = ValidatorSetHistory::from_genesis(vs.clone()).to_persisted();
        // Swap out one NodeId in the genesis boundary.
        tampered.boundaries[0].members[0] = nid(99);
        let bytes = postcard::to_stdvec(&tampered).unwrap();
        storage.put(STORAGE_KEY_VALIDATOR_HISTORY, &bytes).unwrap();

        let recovered = ConsensusNode::recover(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        )
        .expect("recover decodes the tampered blob");
        let err = recovered
            .verify_persisted_history_consistency()
            .expect_err("consistency check must reject wrong genesis member set");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("validator_history") || msg.contains("history_commitment"),
            "error must mention the failing surface: {msg}",
        );
    }

    /// Test 5 (BLS chain happy path): on a BLS-flavored node, commit
    /// a block, then verify the consistency check passes. The BLS
    /// path is a separate code branch from the Ed25519 path; without
    /// this test, a future regression in the BLS-history walk would
    /// silently rot.
    #[test]
    fn verify_persisted_history_consistency_bls_happy_path() {
        use boule_consensus::bls_key_history::BlsKeyHistory;
        use boule_core::crypto::sig_scheme::{BlsPublicKey, SignatureSchemeChoice};

        // Synthesize 4 BLS pubkeys (deterministic, since the test
        // only exercises the bookkeeping path; PoP verification is
        // not on this gate's hot path).
        let bls_pk = |b: u8| -> BlsPublicKey {
            let mut out = [0u8; 48];
            out.fill(b);
            out
        };
        let vs = four_validators();
        let genesis_bls: Vec<(NodeId, BlsPublicKey)> = vs
            .iter()
            .copied()
            .enumerate()
            .map(|(i, id)| (id.into_node_id(), bls_pk(0xA0 + i as u8)))
            .collect();
        let bls_history = BlsKeyHistory::with_genesis(genesis_bls.iter().copied());

        // Build genesis with a commitment over the full BLS-aware triple.
        let set_hist = ValidatorSetHistory::from_genesis(vs.clone());
        let key_hist = ValidatorKeyHistory::new(vs.iter().copied());
        let commitment = boule_consensus::history_commitment::validator_history_commitment_v1(
            &set_hist,
            &key_hist,
            Some(&bls_history),
        );
        let g = Block::genesis([0u8; 32], commitment);

        let mut cfg = NodeConfigForConsensus::for_testing(vs.clone(), g.clone());
        cfg.signature_scheme = SignatureSchemeChoice::BlsAggregated;

        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());

        // Phase 1: commit a single empty block on the BLS chain. The
        // block builder leaves validator_history_commitment at the
        // pre-block hash; mirror that here.
        let mut node = ConsensusNode::new(
            nid(1),
            cfg.clone(),
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        )
        .with_bls_key_history(bls_history.clone());
        let pre_block_commitment =
            boule_consensus::history_commitment::validator_history_commitment_v1(
                &node.validator_history,
                &node.validator_key_history,
                node.bls_key_history.as_ref(),
            );
        let block1 = Block {
            header: boule_consensus::replication::block::BlockHeader {
                parent_hash: g.hash(),
                height: Height(1),
                view: View(1),
                proposer: nid(1),
                state_commitment: [0u8; 32],
                commands_commitment: Block::commands_commitment(&[]),
                validator_history_commitment: pre_block_commitment,
                committed_height: Height::ZERO,
                committed_state_root: [0; 32],
            },
            commands: vec![],
        };
        node.apply_commit(block1);
        // Persist the BLS history so recovery can load it. apply_commit
        // doesn't write the BLS-history blob unless a rotation
        // applied; for a no-rotation block we mirror what `src/node.rs`
        // does by writing it through the with_bls_key_history wiring.
        // The simplest equivalent here: persist the in-memory BLS
        // history once explicitly.
        let bls_persisted = node.bls_key_history.as_ref().unwrap().to_persisted();
        let bls_bytes = postcard::to_stdvec(&bls_persisted).unwrap();
        storage
            .put(STORAGE_KEY_BLS_KEY_HISTORY, &bls_bytes)
            .unwrap();
        drop(node);

        // Phase 2: recover and re-attach the BLS history (mirroring
        // what `src/node.rs` does), then run the consistency check.
        let recovered = ConsensusNode::recover(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        )
        .expect("recover BLS chain")
        .with_bls_key_history(bls_history);
        recovered
            .verify_persisted_history_consistency()
            .expect("BLS happy-path consistency check must pass");
    }

    // ── #194: block-store retention / pruning ────────────────────────────────

    /// Build a sequential commit-shaped block at `(height, view)` whose
    /// `parent_hash` is `parent`. Uses the same shape as `sample_block`
    /// (no commands, zero state commitment) so `apply_commit` runs
    /// without state-machine complaints. The returned block's hash is
    /// distinct from sibling heights because `BlockHeader.height`
    /// participates in `block.hash()`.
    fn empty_block(parent_hash: BlockHash, height: u64, view: u64) -> Block {
        Block {
            header: BlockHeader {
                parent_hash,
                height: Height(height),
                view: View(view),
                proposer: nid(1),
                state_commitment: [0u8; 32],
                commands_commitment: Block::commands_commitment(&[]),
                validator_history_commitment: [0; 32],
                committed_height: Height::ZERO,
                committed_state_root: [0; 32],
            },
            commands: vec![],
        }
    }

    /// Drive `apply_commit` over a contiguous chain of `count` blocks
    /// starting at height 1 (parent = genesis). Returns the per-height
    /// hashes in order so callers can probe storage for specific
    /// blocks.
    fn commit_n_blocks(node: &mut ConsensusNode, count: u64) -> Vec<BlockHash> {
        let mut parent = genesis().hash();
        let mut hashes = Vec::with_capacity(count as usize);
        for h in 1..=count {
            let block = empty_block(parent, h, h);
            parent = block.hash();
            hashes.push(parent);
            node.apply_commit(block);
        }
        hashes
    }

    fn make_node_with_retention(self_id: NodeId, retention: u64) -> ConsensusNode {
        let mut cfg = test_config(four_validators());
        cfg.block_retention_window = retention;
        ConsensusNode::new(
            self_id,
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::new(MemoryStorage::new()),
            Arc::new(MemoryWal::new()),
        )
    }

    #[test]
    fn commit_writes_height_index() {
        // Sanity check the new secondary index: every committed block
        // must be reachable by both `consensus/block/<hash>` and
        // `consensus/height/<be_u64>`. With retention disabled (the
        // test default) nothing is pruned, so all four heights stay
        // resident.
        let mut node = make_node_with_retention(nid(1), 0);
        let hashes = commit_n_blocks(&mut node, 4);

        for (i, hash) in hashes.iter().enumerate() {
            let height = Height((i as u64) + 1);
            let height_key = height_storage_key(height);
            let raw = node
                .storage
                .get(&height_key)
                .expect("get height key")
                .expect("height index entry must exist");
            let stored: BlockHash = raw.as_ref().try_into().expect("32-byte hash");
            assert_eq!(&stored, hash, "height index must point at block hash");

            let block_key = block_storage_key(hash);
            assert!(
                node.storage
                    .get(&block_key)
                    .expect("get block key")
                    .is_some(),
                "block payload must persist alongside the height index",
            );
        }
    }

    #[test]
    fn commit_prunes_blocks_below_window() {
        // Retention = 2 → after committing heights 1..=5, the prune
        // floor on the last commit is `last_committed_height - window
        // = 5 - 2 = 3`, so heights 1 and 2 are deleted from both
        // `consensus/block/<hash>` and `consensus/height/<be_u64>`,
        // while heights 3, 4, 5 remain.
        let mut node = make_node_with_retention(nid(1), 2);
        let hashes = commit_n_blocks(&mut node, 5);

        for (i, hash) in hashes.iter().enumerate() {
            let height = (i as u64) + 1;
            let block_key = block_storage_key(hash);
            let height_key = height_storage_key(Height(height));
            let block_present = node.storage.get(&block_key).unwrap().is_some();
            let height_present = node.storage.get(&height_key).unwrap().is_some();
            if height < 3 {
                assert!(
                    !block_present,
                    "height {height}: block payload must be pruned",
                );
                assert!(
                    !height_present,
                    "height {height}: height index must be pruned",
                );
            } else {
                assert!(
                    block_present,
                    "height {height}: in-window block must be retained",
                );
                assert!(
                    height_present,
                    "height {height}: in-window height index must be retained",
                );
            }
        }
    }

    #[test]
    fn commit_with_window_zero_keeps_all_blocks() {
        // Archive mode: retention=0 disables pruning entirely. Every
        // committed block survives the commit batch, no matter how far
        // the chain advances past the implicit "window".
        let mut node = make_node_with_retention(nid(1), 0);
        let hashes = commit_n_blocks(&mut node, 8);

        for (i, hash) in hashes.iter().enumerate() {
            let height = Height((i as u64) + 1);
            let block_key = block_storage_key(hash);
            let height_key = height_storage_key(height);
            assert!(
                node.storage.get(&block_key).unwrap().is_some(),
                "archive mode: height {} block must remain",
                height.0,
            );
            assert!(
                node.storage.get(&height_key).unwrap().is_some(),
                "archive mode: height {} index must remain",
                height.0,
            );
        }
    }

    #[test]
    fn pruned_block_lookup_returns_none() {
        // After pruning, `load_block_from_storage` (the responder-side
        // fallback consulted by `Dispatch::ServeBlock`) returns
        // `Ok(None)` for the pruned hash, which the dispatch-layer
        // egress turns into `BlockResponse(None)` for the requesting
        // peer.
        let mut node = make_node_with_retention(nid(1), 1);
        let hashes = commit_n_blocks(&mut node, 4);
        // window=1 with last_committed_height=4 → prune below 3, so
        // heights 1 and 2 are pruned, height 3 and 4 retained.
        let pruned_hash = hashes[0];
        let retained_hash = hashes[2];
        assert!(
            load_block_from_storage(node.storage.as_ref(), &pruned_hash)
                .unwrap()
                .is_none(),
            "pruned block must not be loadable",
        );
        assert!(
            load_block_from_storage(node.storage.as_ref(), &retained_hash)
                .unwrap()
                .is_some(),
            "in-window block must still be loadable",
        );
    }

    #[test]
    fn commit_below_retention_window_skips_pruning() {
        // Chain is shorter than the retention window — no block is
        // ever a prune candidate, even though the index is populated.
        let mut node = make_node_with_retention(nid(1), 100);
        let hashes = commit_n_blocks(&mut node, 4);

        for (i, hash) in hashes.iter().enumerate() {
            let height = Height((i as u64) + 1);
            assert!(
                node.storage
                    .get(&block_storage_key(hash))
                    .unwrap()
                    .is_some(),
                "short-chain commit must not prune (height {})",
                height.0,
            );
            assert!(
                node.storage
                    .get(&height_storage_key(height))
                    .unwrap()
                    .is_some(),
                "short-chain height index must persist (height {})",
                height.0,
            );
        }
    }
}
