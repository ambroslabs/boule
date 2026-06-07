//! Public step I/O types and the [`BlockBuilder`] trait.
use super::*;

/// Inputs the safety core reacts to.
///
/// Every state change goes through one of these variants — `step()` is a
/// total function `(HotStuffCore, Event) -> Vec<Action>`.
///
/// The wire-driven variants ([`ProposalReceived`](Self::ProposalReceived),
/// [`VoteReceived`](Self::VoteReceived),
/// [`NewViewReceived`](Self::NewViewReceived)) carry their payload as
/// [`crate::dispatch::Verified`], constructible only by the dispatch
/// verifiers (after every signer/signature/QC/history-commitment gate
/// returns `Ok`) or via
/// [`Verified::unchecked`](crate::dispatch::Verified::unchecked) in tests.
/// An ingress path that skips a check cannot construct these variants and
/// fails to compile. `Verified<T>` also stamps the stable
/// [`ValidatorId`](crate::validator_set::ValidatorId) the signer pubkey
/// resolved to during ingress (via
/// [`ValidatorKeyHistory::validator_for`](crate::validator_key_history::ValidatorKeyHistory::validator_for)),
/// so the core uses it directly for bitmap-index lookups rather than
/// re-deriving it from wire bytes — which would drop a vote signed under
/// a post-rotation active key.
///
/// [`PacemakerAdvance`](Self::PacemakerAdvance) is the one variant never
/// produced by the core: the integration layer injects it when the
/// pacemaker fires `AdvanceToView`.
#[derive(Debug, Clone, PartialEq, Eq)]
// `ProposalReceived` carries a full block and dwarfs the other variants;
// boxing it would churn every emission/match site for no real win at
// consensus-event volumes.
#[allow(clippy::large_enum_variant)]
pub enum Event {
    /// A signed proposal arrived on the wire.
    ProposalReceived(crate::dispatch::Verified<Signed<Proposal>>),
    /// A signed vote arrived on the wire. Only meaningful to the leader
    /// of `vote.view + 1`; other replicas drop it in [`HotStuffCore::step`].
    /// See [`VoteVariant`] for the per-scheme typing.
    VoteReceived(VoteVariant),
    /// A signed `NewView` arrived on the wire.
    NewViewReceived(crate::dispatch::Verified<Signed<NewView>>),
    /// The pacemaker advanced the local view. Never emitted by the core;
    /// injected by the integration layer after a pacemaker `AdvanceToView`.
    PacemakerAdvance(View),
}

/// Verified vote payload, typed by the chain's signature scheme.
///
/// Ed25519 chains carry no BLS partial; `bls_aggregated` chains carry a
/// partial already validated by the ingress verifier
/// (`crate::dispatch::verify_bls_partial_if_required`) against the
/// signer's per-historical-view BLS pubkey. The core matches on the
/// variant and folds the bytes without re-checking; "BLS chain + missing
/// partial" is unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoteVariant {
    /// Ed25519 chain vote: signed envelope only, no BLS partial.
    Ed25519(crate::dispatch::Verified<Signed<Vote>>),
    /// BLS-aggregated chain vote: signed envelope plus the BLS partial,
    /// folded into the QC bucket via
    /// [`QuorumCertificate::add_bls_partial`].
    Bls {
        signed: crate::dispatch::Verified<Signed<Vote>>,
        partial: BlsPartialSig,
    },
}

impl VoteVariant {
    /// Borrow the inner [`crate::dispatch::Verified`] envelope shared by both variants.
    pub fn verified(&self) -> &crate::dispatch::Verified<Signed<Vote>> {
        match self {
            VoteVariant::Ed25519(verified) => verified,
            VoteVariant::Bls { signed, .. } => signed,
        }
    }

    /// Constructor from an already-computed optional partial: `Some` →
    /// [`VoteVariant::Bls`], `None` → [`VoteVariant::Ed25519`].
    pub fn from_optional_partial(
        signed: crate::dispatch::Verified<Signed<Vote>>,
        bls_partial: Option<BlsPartialSig>,
    ) -> Self {
        match bls_partial {
            Some(partial) => VoteVariant::Bls { signed, partial },
            None => VoteVariant::Ed25519(signed),
        }
    }
}

/// A durable state change the integration layer must persist (WAL /
/// on-disk) so it survives a restart.
///
/// Produced, never consumed, by the core: the core updates its in-memory
/// [`super::state::HotStuffState`] immediately and emits the matching
/// `StateUpdate` so the driver can mirror it durably before any dependent
/// outbound [`Action`] leaves the machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateUpdate {
    /// Replica voted in `view`. Persisted so it never double-votes across
    /// restarts — HotStuff safety depends on this.
    VotedInView { view: View },
    /// Replica promoted its lock via the two-chain rule. Only the
    /// `(view, block_hash)` pair is durable: the core never reads signer
    /// data off the lock, and nothing ships it on the wire (`NewView`
    /// carries `high_qc`, not the lock).
    Locked(Locked),
    /// Replica adopted a fresher `high_qc` (via a proposal's justify, a
    /// freshly-formed QC, or a `NewView`).
    HighQc(QuorumCertificate),
    /// Leader minted a `Proposal` at `view`. Persisted before the
    /// corresponding `Broadcast(Proposal)` flushes: a crash between
    /// `Signed::sign` and the bytes leaving the host could otherwise let
    /// a restarted leader re-mint a *different* proposal at the same view
    /// (different parent walk / `high_qc` snapshot / mempool ordering),
    /// and two distinct signed `Proposal(v)` from one leader are slashable
    /// equivocation evidence.
    ProposedInView { view: View },
}

/// Effects the safety core asks the integration layer to perform.
///
/// The core never performs these itself; it returns them from `step` and
/// the integration layer translates each into real side effects
/// (broadcasting bytes, syncing the WAL, committing to the state machine).
/// Emission order within a single `step` call is deterministic and part
/// of the tested surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send `msg` to every validator in the set. Votes and new-views go
    /// out this way; there is no point-to-point variant (votes are
    /// deliberately broadcast).
    Broadcast(ConsensusMsg),
    /// Persist `update` durably before any outbound network effect that
    /// semantically depends on it is flushed.
    Persist(StateUpdate),
    /// Commit `block` to the state machine. Emitted when the three-chain
    /// rule fires on a freshly-adopted QC.
    Commit(Block),
    /// Parent of a received proposal is not in `pending_blocks`; ask
    /// `peer` (typically the proposal's sender) for the block at `hash`.
    ///
    /// `expected_height` is where the requested block should land
    /// (`child.header.height - 1`). `reason` distinguishes first probe
    /// from retry for the integration layer's structured logs.
    RequestBlock {
        hash: BlockHash,
        peer: NodeId,
        expected_height: Height,
        reason: BlockSyncReason,
    },
    /// A validator signed votes at `view` for two different blocks
    /// (`block_a` then `block_b`). An honest replica signs at most one
    /// vote per view (HotStuff safety / `safe_to_vote`), so this is
    /// non-repudiable evidence of a Byzantine signer.
    ///
    /// Emitted *before* the conflicting partial would be folded: the
    /// second vote is dropped, so a Byzantine voter contributing to two
    /// buckets at the same view sees only the first land. The integration
    /// layer logs at WARN and ticks
    /// [`crate::status::ConsensusStatus::equivocations_detected`];
    /// otherwise informational (slashing pipeline is future work).
    EquivocationEvidence {
        voter: ValidatorId,
        view: View,
        block_a: BlockHash,
        block_b: BlockHash,
    },
    /// A leader signed proposals at `view` for two different blocks
    /// (`block_a` then `block_b`). An honest leader proposes at most one
    /// block per view, so this is non-repudiable evidence of a Byzantine
    /// proposer.
    ///
    /// Leader-side sibling of [`Self::EquivocationEvidence`], kept a
    /// distinct variant so exhaustive `match` enforces per-kind handling.
    /// Detected in [`HotStuffCore::step`]'s [`Event::ProposalReceived`]
    /// dispatch via the `(view, leader_id) → block_hash` `proposal_dedupe`
    /// map: vacant records the first sighting, same-hash re-delivery is
    /// idempotent, a different-hash arrival emits this. Unlike vote
    /// equivocation both forks are admitted into `pending_blocks` (a
    /// replica's monotonic `last_voted_view` stops it voting for both).
    /// The integration layer logs at WARN and ticks
    /// [`crate::status::ConsensusStatus::proposal_equivocations_detected`];
    /// otherwise informational.
    ProposalEquivocationEvidence {
        leader: ValidatorId,
        view: View,
        block_a: BlockHash,
        block_b: BlockHash,
    },

    /// This replica leads `view` and should build a proposal extending
    /// `parent` with `high_qc` as its justify. Emitted instead of building
    /// inline so construction runs in the async-capable integration layer,
    /// not the synchronous core. The integration layer runs its
    /// `BlockBuilder`, then calls [`HotStuffCore::proposal_built`] to get
    /// the `Persist(ProposedInView)` + `Broadcast(Proposal)` actions and
    /// set the per-view double-propose guard. A build failure is dropped
    /// without calling `proposal_built`, so `proposed_in_view` stays unset
    /// and the view remains retriable.
    BuildProposal {
        view: View,
        high_qc: QuorumCertificate,
        parent: Block,
    },
}

/// Why the safety core emitted [`Action::RequestBlock`]. Surfaced via the
/// integration layer's `block_sync_request_emitted` event so an operator
/// can tell a first-probe burst (one per fresh proposal) from a retry loop
/// re-emitting the same hashes (responder has nothing, or the requester is
/// behind in an unexpected way).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockSyncReason {
    /// First emission: a proposal arrived whose parent is not in
    /// `pending_blocks`. See [`HotStuffCore::on_proposal_received`].
    UnknownParentOnProposal,
    /// Retry: a `PacemakerAdvance` fired with at least one proposal still
    /// parked on a missing parent. See
    /// [`HotStuffCore::on_pacemaker_advance`].
    StillParkedOnPacemakerAdvance,
    /// First emission: a `NewView` adopted a fresher `high_qc` whose block
    /// is not in `pending_blocks`. Needed before the replica can extend
    /// the chain, run the two-chain lock rule, or fire three-chain commit;
    /// without it a lagger lifts `current_view` from NewView traffic while
    /// `last_committed_height` stays parked. See
    /// [`HotStuffCore::on_new_view_received`].
    UnknownHighQcOnNewView,
    /// Retry: the integration layer's block-sync retry timer fired while a
    /// [`BlockSyncInflight`] entry was still pending. Decoupled from view
    /// cadence — fires on a wall-clock schedule (default 200 ms initial,
    /// exponential to a cap), so a lost `RequestBlock` recovers in
    /// `O(100ms)` rather than `O(view_timeout)`. See
    /// [`HotStuffCore::step_block_sync_retry_tick`].
    RetryTimerTick,
}

impl BlockSyncReason {
    /// Stable, human-readable tag suitable as a structured-log field.
    pub fn as_str(self) -> &'static str {
        match self {
            BlockSyncReason::UnknownParentOnProposal => "unknown_parent_on_proposal",
            BlockSyncReason::StillParkedOnPacemakerAdvance => "still_parked_on_pacemaker_advance",
            BlockSyncReason::UnknownHighQcOnNewView => "unknown_high_qc_on_new_view",
            BlockSyncReason::RetryTimerTick => "retry_timer_tick",
        }
    }
}

/// Integration-layer hook that turns "I lead this view and hold a fresh
/// justify-QC" into a concrete [`Block`].
///
/// The core never invents block contents — that's the mempool's and state
/// machine's job. A trait (rather than a hard dependency on either) keeps
/// components swappable and `HotStuffCore` unit-testable in isolation.
///
/// # Determinism
///
/// Implementations used under [`HotStuffCore::replay`] or the property
/// test **must** be deterministic for a given `(parent, view, high_qc)`,
/// else the shrinker produces irreproducible failing seeds.
///
/// [`HotStuffCore::replay`]: HotStuffCore::replay
pub trait BlockBuilder: Send + Sync {
    /// Produce a child block extending `parent` at `view` with `high_qc`
    /// as the proposal's justify. Implementations fill `header.proposer`
    /// from integration-layer context; the core does not thread its
    /// `NodeId` in here.
    ///
    /// `pending_blocks` is the core's [`HotStuffState::pending_blocks`] at
    /// build time, passed by reference so `MempoolBlockBuilder` can walk
    /// the uncommitted ancestor chain from `parent` to the last committed
    /// boundary and fold those commands into its `state_commitment`.
    /// Builders that compute no commitment (e.g. `TestBlockBuilder`) ignore
    /// it.
    ///
    /// Returns `Err` when a block cannot be built — e.g.
    /// `MempoolBlockBuilder` on a failed state-machine fork-and-restore
    /// round trip (corrupt redb table, on-disk bit-flip, version skew).
    /// The core treats `Err` as recoverable: it emits no proposal for the
    /// view, letting the next-view leader take over rather than crashing.
    ///
    /// `timestamp` is the proposal time in Unix epoch millis from the
    /// integration layer's wall clock, stamped into the header clamped to
    /// the parent so block time is non-decreasing (see
    /// [`BlockHeader::timestamp`](crate::replication::block::BlockHeader::timestamp)).
    ///
    /// [`HotStuffState::pending_blocks`]: super::state::HotStuffState::pending_blocks
    fn build(
        &self,
        parent: &Block,
        view: View,
        high_qc: &QuorumCertificate,
        pending_blocks: &HashMap<BlockHash, Block>,
        timestamp: u64,
    ) -> anyhow::Result<Block>;
}
