//! HotStuff safety-core state machine.
//!
//! [`HotStuffCore`] composes the wire types in [`super::qc`] and the pure
//! predicates over [`super::state::HotStuffState`] into an
//! `Event -> Vec<Action>` dispatcher — the entire public API of the
//! safety core. Submodules cover the dispatch handlers (`handlers`),
//! leader proposal building (`proposal`), block-sync retry
//! (`block_sync`), cache eviction (`eviction`), and the public I/O types
//! (`types`).
//!
//! # Purity
//!
//! No `tokio`, no [`boule_core::clock::Clock`], no storage, no network:
//! inputs are [`Event`]s, outputs are [`Action`]s. Inbound [`Signed`]
//! payloads are assumed signature-verified by the integration layer
//! before `step` runs, so the core is deterministic and replayable.
//!
//! [`Signed`]: boule_core::crypto::signed::Signed

use std::collections::HashMap;

use crate::limits::{CacheEvictionCounters, CacheLimits};
use crate::replication::block::{Block, BlockHash};
use crate::{Height, View};
use boule_core::crypto::signed::Signed;
use boule_core::identity::NodeId;

use super::qc::{ConsensusMsg, NewView, Proposal, QuorumCertificate, VerifiedQc, Vote};
use super::safety_rules::{safe_to_vote, should_update_high_qc, three_chain_commit};
use super::state::{HotStuffState, Locked};
use crate::validator_set::{ValidatorId, ValidatorSet};
use boule_core::crypto::sig_scheme::BlsPartialSig;

/// Tracing target shared with the integration layer so safety-core
/// eviction logs flow through the same `RUST_LOG` filter.
const TRACE_TARGET: &str = "boule_core::consensus";

mod block_sync;
mod eviction;
mod handlers;
mod proposal;
mod types;
pub use types::*;

/// HotStuff safety core: the `Event → Vec<Action>` state machine.
///
/// Construct with the local [`NodeId`], an initial [`HotStuffState`],
/// and a [`BlockBuilder`] the integration layer plugs in. Drive it by
/// calling [`step`] for each event; the returned actions are the
/// integration layer's to carry out.
///
/// # Purity
///
/// No `tokio`, no clock, no storage, no network. The machine is
/// deterministic: identical `(state, event-sequence)` inputs produce
/// identical `Vec<Vec<Action>>` outputs — which is exactly what
/// [`replay`] exploits to turn a failing property-test seed into a
/// reproducible regression.
///
/// [`step`]: HotStuffCore::step
/// [`replay`]: HotStuffCore::replay
pub struct HotStuffCore {
    self_id: NodeId,
    state: HotStuffState,
    /// Partial QCs the leader is accumulating, keyed by
    /// `(vote.view, vote.block_hash)`. A bucket becomes a full QC once
    /// `signer_count >= quorum_size(validator_set.len())`.
    vote_bucket: HashMap<(View, BlockHash), QuorumCertificate>,
    /// Per-`(view, validator)` block-hash dedup. The first vote a signer
    /// contributes at a view records its `block_hash`; a later vote at the
    /// same view from the same signer for a *different* `block_hash` is
    /// equivocation: the conflicting vote is dropped (the voter reaches at
    /// most one bucket per view locally) and an
    /// [`Action::EquivocationEvidence`] is emitted. Garbage-collected
    /// alongside [`Self::vote_bucket`] in
    /// [`Self::evict_vote_buckets_below`] so a flood of low-view
    /// distinct-hash votes can't pin memory.
    vote_dedupe: HashMap<(View, ValidatorId), BlockHash>,
    /// Per-`(view, leader)` proposal-hash dedup, the proposer-side
    /// analogue of [`Self::vote_dedupe`]. The first proposal a leader
    /// contributes at a view records its `block_hash`; a later proposal at
    /// the same view from the same leader for a *different* `block_hash`
    /// emits [`Action::ProposalEquivocationEvidence`]. Both forks are
    /// still admitted into `pending_blocks` — `last_voted_view`
    /// monotonicity stops a replica voting for both, so admitting both is
    /// harmless and preserves block-sync utility (a parked child of either
    /// fork can unpark once its parent arrives). Garbage-collected
    /// alongside [`Self::vote_bucket`] in
    /// [`Self::evict_vote_buckets_below`].
    proposal_dedupe: HashMap<(View, ValidatorId), BlockHash>,
    /// Proposals we received before their parent landed. Keyed by the
    /// proposal's own block hash so a later `PacemakerAdvance` can
    /// re-evaluate every parked child whose parent has since arrived.
    parked_proposals: HashMap<BlockHash, Signed<Proposal>>,
    /// In-flight `RequestBlock` retry state, keyed by the missing parent
    /// hash so cross-round re-emissions deduplicate. Tracking
    /// `(attempts, last_asked_view)` throttles re-emissions, rotates to
    /// other validators once the per-peer budget is exhausted, and drops
    /// the parked proposal once the total attempt budget is spent.
    block_sync_inflight: HashMap<BlockHash, BlockSyncInflight>,
    /// Highest view at which this replica has broadcast a proposal as
    /// leader. Guards against double-proposing across the three entry
    /// points that can fire `try_propose_as_leader` for the same view:
    /// `become_leader` (once, on pacemaker advance), `on_pacemaker_advance`
    /// (every `PacemakerAdvance`, including after a block-sync response
    /// supplies a previously-missing high_qc parent), and the QC-formed
    /// branch of `on_vote_received` (when the next-view leader collects
    /// quorum). Without it, a leader whose first attempt failed on a
    /// missing high_qc parent could emit two proposals at one view if
    /// block-sync arrived between the QC-formed branch and the
    /// `AdvanceToView` action — indistinguishable from equivocation.
    /// Mirrored durably via [`StateUpdate::ProposedInView`]: the
    /// integration layer flushes the persist before the matching
    /// `Broadcast(Proposal)` leaves, and [`Self::with_proposed_in_view`]
    /// restores it on recovery, so a crash between `Signed::sign` and the
    /// bytes leaving the host can't re-mint a different proposal at the
    /// same view.
    proposed_in_view: View,
    /// Per-cache caps. A forced eviction fires when an `insert` would grow
    /// a cache past its cap; see [`CacheLimits`]. Tests pass
    /// [`CacheLimits::unbounded_for_tests`] to disable eviction.
    limits: CacheLimits,
    /// Cumulative eviction counts surfaced via the consensus status
    /// snapshot. Cloned into the integration layer so the timeout-bucket
    /// handler shares a single counter handle.
    eviction_counters: CacheEvictionCounters,
}

/// Per-parent-hash retry accounting for `RequestBlock`. See
/// [`HotStuffCore::block_sync_inflight`].
#[derive(Debug, Clone, Copy)]
struct BlockSyncInflight {
    /// Signer of the proposal that originally triggered the request.
    /// Round 0 of the rotation re-asks this peer; round 1 onward steps
    /// through the validator ring (skipping `self_id`).
    original_sender: NodeId,
    /// `RequestBlock` actions emitted for this parent so far, including
    /// the initial probe. Compared against
    /// [`CacheLimits::block_sync_max_attempts`] to decide whether parked
    /// proposals depending on this parent should be dropped.
    attempts: u32,
    /// View at which the most recent retry was emitted. The next retry is
    /// gated on `current_view - last_asked_view >= backoff(attempts)`.
    last_asked_view: View,
    /// Parent height (= child header height − 1), carried verbatim into
    /// every retry's `expected_height`. Cached so the retry loop need not
    /// re-walk `parked_proposals`.
    expected_height: Height,
}

impl HotStuffCore {
    /// Build a fresh core around `state` with unbounded caches. Block
    /// construction lives in the integration layer: the core emits
    /// [`Action::BuildProposal`]. Production uses
    /// [`HotStuffCore::with_limits`] to plumb operator-configured caps.
    pub fn new(self_id: NodeId, state: HotStuffState) -> Self {
        Self::with_limits(
            self_id,
            state,
            CacheLimits::unbounded_for_tests(),
            CacheEvictionCounters::default(),
        )
    }

    /// Build a fresh core with explicit per-cache caps and a counter
    /// handle. The production constructor; [`Self::new`] is the
    /// unbounded shorthand for tests.
    pub fn with_limits(
        self_id: NodeId,
        mut state: HotStuffState,
        limits: CacheLimits,
        eviction_counters: CacheEvictionCounters,
    ) -> Self {
        // Bind the cap and counter handle into the safety state so its
        // `insert_pending` path evicts under flood without the dispatcher
        // threading caps in on every call.
        state.set_pending_blocks_limit(limits.pending_blocks_capacity, eviction_counters.clone());
        Self {
            self_id,
            state,
            vote_bucket: HashMap::new(),
            vote_dedupe: HashMap::new(),
            proposal_dedupe: HashMap::new(),
            parked_proposals: HashMap::new(),
            block_sync_inflight: HashMap::new(),
            proposed_in_view: View::ZERO,
            limits,
            eviction_counters,
        }
    }

    /// Restore the durably-persisted `proposed_in_view` value. The
    /// recovery path calls this once at boot from the persisted
    /// [`StateUpdate::ProposedInView`] write, so a leader that crashed
    /// between `Signed::sign` and the bytes leaving the host cannot
    /// re-mint a different proposal at the same view on restart. Defaults
    /// to `0` for fresh-storage boots and tests.
    pub fn with_proposed_in_view(mut self, view: View) -> Self {
        self.proposed_in_view = view;
        self
    }

    /// Highest view at which this replica has minted a proposal as leader.
    /// Exposed for tests and recovery assertions; durability goes through
    /// [`StateUpdate::ProposedInView`] and restore through
    /// [`Self::with_proposed_in_view`].
    pub fn proposed_in_view(&self) -> View {
        self.proposed_in_view
    }

    /// Borrow the eviction counters this core increments. The same handle
    /// is shared with the timeout-vote path so all caches' counters live
    /// behind one `Arc`.
    pub fn eviction_counters(&self) -> &CacheEvictionCounters {
        &self.eviction_counters
    }

    /// The local node's identity, as supplied at construction.
    pub fn self_id(&self) -> NodeId {
        self.self_id
    }

    /// Borrow the current safety-core state. Read-only by design — the
    /// only way to mutate is through [`step`].
    ///
    /// [`step`]: HotStuffCore::step
    pub fn state(&self) -> &HotStuffState {
        &self.state
    }

    /// Insert a committed validator-set boundary into the safety core's
    /// history. The *only* sanctioned mutation of `state.validator_history`
    /// from outside `step`, driven by the integration layer's commit-time
    /// reconfig hook.
    ///
    /// `set` is the resulting set after the reconfig applies. The caller
    /// must have already validated the `ReconfigCommand` (floor, overlap,
    /// v_eff delay); this method only enforces per-history monotonicity.
    pub fn insert_validator_boundary(
        &mut self,
        v_eff: View,
        set: ValidatorSet,
    ) -> anyhow::Result<()> {
        // Mirror the boundary into `state.validator_set` if `v_eff` is
        // already reached. The commit hook only inserts strictly future
        // boundaries (`v_eff > current_view`), so this branch is
        // defensive but cheap and keeps `validator_set` honest if the
        // rule ever loosens.
        let new_set = set.clone();
        self.state.validator_history.insert_boundary(v_eff, set)?;
        if v_eff <= self.state.current_view {
            self.state.validator_set = new_set;
        }
        Ok(())
    }

    /// Iterate over the currently-accumulating vote buckets. Consumed by
    /// [`crate::status`] to surface partial-QC progress; read-only.
    pub fn vote_buckets(&self) -> impl Iterator<Item = (&(View, BlockHash), &QuorumCertificate)> {
        self.vote_bucket.iter()
    }

    /// Iterate over the currently-parked proposals (proposals whose
    /// parent block has not yet arrived). Consumed by
    /// [`crate::status`].
    pub fn parked_proposals(&self) -> impl Iterator<Item = &Signed<Proposal>> {
        self.parked_proposals.values()
    }

    /// Insert a block into `pending_blocks` directly.
    ///
    /// Used when a `BlockResponse` arrives for a requested block: insert
    /// it, then re-drive via `step(Event::PacemakerAdvance(current_view))`
    /// to un-park proposals waiting on this parent.
    ///
    /// Clears any in-flight `RequestBlock` retry tracking for the inserted
    /// hash — the parent has arrived, so the next advance must not waste a
    /// rotation slot on a parent we already have.
    pub fn insert_pending_block(&mut self, block: Block) {
        let hash = block.hash();
        self.state.insert_pending(block);
        self.block_sync_inflight.remove(&hash);
    }

    /// Directly set `high_qc` on the safety-core state.
    ///
    /// Used at boot to seed a well-known genesis QC (see
    /// [`super::qc::genesis_qc`]) so the view-1 leader can call
    /// `become_leader` immediately without a NewView round. The core does
    /// not re-verify embedded QC signatures — envelopes are authenticated
    /// by the integration layer — so a genesis QC with placeholder
    /// signatures is safe here.
    ///
    /// Takes a [`VerifiedQc`] so an unverified QC can't be landed into the
    /// core except through the grep-able `VerifiedQc::unchecked` wrap site.
    ///
    /// After bootstrap, `high_qc` is adopted through ordinary proposal /
    /// vote / NewView / TimeoutVote paths; prefer those.
    pub fn set_high_qc(&mut self, qc: VerifiedQc) {
        self.state.high_qc = Some(qc);
    }

    /// Adopt a verified snapshot as a new starting point for the safety
    /// core.
    ///
    /// Sets the safety state as if the joiner had committed up to the
    /// snapshot's `(height, view)`:
    ///
    /// - Inserts `snapshot_block` into `pending_blocks` so parent-walks
    ///   terminate at the snapshot rather than recursing to genesis (the
    ///   joiner lacks the intermediate blocks).
    /// - Sets `locked` to the snapshot's `(view, height, block_hash)`. Lock
    ///   monotonicity holds: the joiner's prior `locked` is at most genesis
    ///   (height 0), strictly below the snapshot's height.
    /// - Adopts `commit_qc` as `high_qc`; same view-monotonicity argument
    ///   (prior `high_qc` is at most the genesis QC at view 0).
    /// - Bumps `last_voted_view` to `snapshot_view` so the joiner cannot
    ///   vote at a lower view post-adoption. Without it, a crash before the
    ///   first post-snapshot durable write would let `recover_state`
    ///   rehydrate `last_voted_view = 0`, trivially satisfying
    ///   `safe_to_vote`'s `view > last_voted_view` check on a conflicting
    ///   fork.
    ///
    /// Returns the [`Action::Persist`] sequence the caller must flush
    /// durably *before* any further consensus action. `restore_from_snapshot`
    /// folds these into the same atomic batch as its `block` /
    /// `last_committed` writes, so a crash in the restore window leaves
    /// zero or all of the snapshot state on disk — never the middle where
    /// `high_qc` is fresh but `locked` and `last_voted_view` are stale.
    ///
    /// Caller must verify `commit_qc` is well-formed under the validator
    /// set and has quorum
    /// ([`crate::replication::snapshot::SnapshotManifest::verify`]) before
    /// calling. The [`VerifiedQc`] parameter pushes that obligation to the
    /// type level.
    #[must_use = "callers must flush the returned Persist actions atomically; see audit finding 4-3"]
    pub fn adopt_snapshot(
        &mut self,
        snapshot_block: Block,
        commit_qc: VerifiedQc,
        snapshot_view: View,
    ) -> Vec<Action> {
        let block_hash = snapshot_block.hash();
        let height = snapshot_block.header.height;
        self.state.insert_pending(snapshot_block);
        let locked = super::Locked {
            view: snapshot_view,
            height,
            block_hash,
        };
        self.state.locked = Some(locked);
        self.state.high_qc = Some(commit_qc.clone());
        if snapshot_view > self.state.last_voted_view {
            self.state.last_voted_view = snapshot_view;
        }
        vec![
            Action::Persist(StateUpdate::VotedInView {
                view: snapshot_view,
            }),
            Action::Persist(StateUpdate::Locked(locked)),
            Action::Persist(StateUpdate::HighQc(commit_qc.into_inner())),
        ]
    }

    /// React to `event` and return the [`Action`]s the integration layer
    /// must carry out, in emission order.
    pub fn step(&mut self, event: Event) -> Vec<Action> {
        let actions = match event {
            Event::ProposalReceived(verified) => {
                // Resolve the leader's stable `ValidatorId` from the
                // ingress-stamped envelope so the dedupe map keys on
                // identity that survives a key rotation. Re-dispatch from
                // the parked-proposals path in `on_proposal_received`
                // reuses the same `block_hash` keyed on first arrival, so
                // running dedupe once here covers both the happy and
                // parked re-delivery paths idempotently.
                let (signed, leader_id) = verified.into_parts();
                let view = signed.payload.block.header.view;
                let block_hash = signed.payload.block.hash();
                let mut actions = Vec::new();
                if let Some(ev) = self.check_proposal_dedupe(view, leader_id, block_hash) {
                    actions.push(ev);
                }
                actions.extend(self.on_proposal_received(signed));
                actions
            }
            Event::VoteReceived(variant) => self.on_vote_received(variant),
            Event::NewViewReceived(verified) => self.on_new_view_received(verified.into_inner()),
            Event::PacemakerAdvance(v) => self.on_pacemaker_advance(v),
        };

        // Lock-durable-before-vote invariant: within one `step` output,
        // `Persist(StateUpdate::Locked)` must precede every
        // `Broadcast(ConsensusMsg::Vote)`. The integration layer's
        // persist-before-send discipline flushes every preceding
        // `Persist(...)` before each non-`Persist` action; a `Vote`
        // broadcast before the lock's persist would, on a crash in that
        // window, leave disk with a stale lock and an advanced
        // `last_voted_view` — the Tendermint amnesia hole.
        #[cfg(debug_assertions)]
        debug_assert_lock_durable_before_vote(&actions);

        actions
    }

    /// Feed a trace of events through `step` in order, returning one
    /// `Vec<Action>` per event. Consumes `self`.
    pub fn replay(mut self, events: impl IntoIterator<Item = Event>) -> Vec<Vec<Action>> {
        events.into_iter().map(|e| self.step(e)).collect()
    }
}

/// Assert that within a single `step()` output
/// `Persist(StateUpdate::Locked)` precedes every
/// `Broadcast(ConsensusMsg::Vote)` — the safety-core half of the
/// persist-before-send contract for lock state. A violation re-opens the
/// Tendermint amnesia hole: a crash between vote-broadcast and lock-persist
/// would leave disk with a stale lock and an advanced `last_voted_view`.
///
/// Debug-only; release builds skip the walk to keep `step()`
/// allocation-free.
#[cfg(debug_assertions)]
fn debug_assert_lock_durable_before_vote(actions: &[Action]) {
    let mut seen_vote_at: Option<usize> = None;
    for (i, action) in actions.iter().enumerate() {
        match action {
            Action::Broadcast(ConsensusMsg::Vote(_)) => {
                seen_vote_at.get_or_insert(i);
            }
            Action::Persist(StateUpdate::Locked(_)) => {
                debug_assert!(
                    seen_vote_at.is_none(),
                    "audit invariant I4 violated: Persist(StateUpdate::Locked) at index {i} \
                     emitted after Broadcast(Vote) at index {} in the same step output \
                     ({} actions). The lock would persist after the vote leaves the wire, \
                     re-opening the amnesia window of audit finding 4-1 (#405): {actions:?}",
                    seen_vote_at.unwrap(),
                    actions.len(),
                );
            }
            _ => {}
        }
    }
}

/// Round-robin leader for `view` over `vs`. Mirrors
/// [`crate::pacemaker::leader::RoundRobinSelector`]; the safety core
/// doesn't own a selector instance, so swappable selectors are the
/// integration layer's job.
fn round_robin_leader(vs: &ValidatorSet, view: View) -> NodeId {
    let len = vs.len();
    debug_assert!(len > 0, "validator set must be non-empty");
    // Pick a stable id from the set; callers work in `NodeId` space.
    vs.get((view.0 as usize) % len)
        .expect("validator set is non-empty")
        .into_node_id()
}

/// Compute the view-gap to wait before the next `RequestBlock` retry
/// on a parent hash that has already been asked `attempts` times.
///
/// The schedule is `min(initial << (attempts - 1), max)` — exponential
/// doubling capped at `max`. `attempts == 0` returns `0` (no probe has
/// fired yet); `initial == 0` short-circuits to `0`, giving "retry every
/// advance" under [`CacheLimits::unbounded_for_tests`].
fn block_sync_backoff_views(attempts: u32, initial: u64, max: u64) -> u64 {
    if attempts == 0 || initial == 0 {
        return 0;
    }
    let shift = (attempts - 1).min(63);
    let raw = initial.checked_shl(shift).unwrap_or(u64::MAX);
    raw.min(max)
}

/// Pick the validator that should receive the `attempts`-th
/// `RequestBlock` retry for a parent hash. Round 0 (the initial probe
/// and any retries within the per-peer budget) re-asks
/// `original_sender`; subsequent rounds step through the validator
/// set in sorted order, skipping `self_id`.
///
/// `per_peer_attempts == 0` is treated as `1` — at minimum we ask
/// the sender once before rotating.
fn pick_block_sync_peer(
    original_sender: NodeId,
    attempts: u32,
    per_peer_attempts: u32,
    validator_set: &ValidatorSet,
    self_id: NodeId,
) -> NodeId {
    let per_peer = per_peer_attempts.max(1);
    // `attempts` counts probes already emitted. The probe we're about
    // to send is attempt #(attempts + 1). Map (attempts + 1) onto a
    // 1-indexed slot, then bucket into rounds of `per_peer`.
    let next_attempt = attempts.saturating_add(1);
    let round = ((next_attempt - 1) / per_peer) as usize;
    if round == 0 {
        return original_sender;
    }
    let len = validator_set.len();
    if len == 0 {
        return original_sender;
    }
    // Same byte-equality convention as `round_robin_leader`: the wire
    // `original_sender` and the validator set's stable id share bytes.
    let sender_vid = crate::validator_set::ValidatorId::from_genesis_pubkey(original_sender);
    let sender_idx = validator_set.index_of(&sender_vid).unwrap_or(0);
    // Build the rotation ring: every validator after `sender_idx`
    // (wrapping), skipping `self_id`.
    let mut ring: Vec<NodeId> = Vec::with_capacity(len);
    for offset in 1..=len {
        let candidate = validator_set
            .get((sender_idx + offset) % len)
            .expect("validator_set indexing in bounds")
            .into_node_id();
        if candidate != self_id {
            ring.push(candidate);
        }
    }
    if ring.is_empty() {
        // Self is the only validator — there is no peer to rotate to.
        // Fall back to the original sender so the action is well-
        // formed; the integration layer will short-circuit a
        // self-addressed RequestBlock at apply time.
        return original_sender;
    }
    ring[(round - 1) % ring.len()]
}

#[cfg(test)]
mod tests;
