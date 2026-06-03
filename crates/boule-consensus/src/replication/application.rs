//! The production **application seam** the consensus integration layer
//! drives (#225 M1).
//!
//! Where [`BlockBuilder`](crate::hotstuff::step::BlockBuilder) is the
//! *synchronous* block-construction hook the safety-core test harnesses
//! fabricate proposals through, [`Application`] is the *asynchronous*
//! seam the real node runs on. An async seam is what lets a production
//! application do genuine I/O on the build path — most importantly an
//! Ethereum execution layer that builds payloads over the Engine API
//! (`forkchoiceUpdatedV3` + `getPayloadV3`) rather than computing a block
//! synchronously in-process.
//!
//! The counter application (the in-process `MempoolBlockBuilder` in
//! `boule-node`) implements this trait as a trivial wrapper over its
//! synchronous build — it does no real I/O, so its future is already
//! resolved. The point of the async seam is not the counter; it is that
//! an out-of-process execution layer can `await` here without blocking
//! the consensus loop on a blocking call.
//!
//! This trait grows over the M1 milestone: it starts owning only the
//! build path here, and later takes over commit-time execution and the
//! state-commitment queries that today still flow through
//! [`StateMachine`](crate::replication::state_machine::StateMachine).

use std::collections::HashMap;

use boule_core::clock::BoxFuture;
use boule_core::identity::NodeId;

use bytes::Bytes;

use crate::hotstuff::qc::QuorumCertificate;
use crate::replication::block::{Block, BlockHash};
use crate::{Height, View};

/// One application-driven change to the validator set, mirroring ABCI's
/// `ValidatorUpdate { pub_key, power }`: the application names a validator
/// by its identity key and the voting weight it should have.
///
/// `weight == 0` removes the validator; `weight >= 1` adds it (if not
/// currently seated) or changes its weight (if it is). The integration
/// layer translates a batch of these into the existing reconfig path and
/// applies them at a view boundary — that *consumer* is a follow-up; today
/// the integration layer only **receives** them, so this type is the seam,
/// not yet a live control path.
///
/// Resolving a network endpoint for a newly *added* validator is out of
/// scope here (it is the validator endpoint-advertisement concern); a
/// `weight`-only update is what the stake-source backends this seam exists
/// for need — a CL-native staking ledger, an EVM staking interface, or a
/// Cosmos x/staking module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorUpdate {
    /// The validator's identity key (its [`NodeId`]). ABCI's `pub_key`.
    pub node_id: NodeId,
    /// The voting weight the validator should have at the next view
    /// boundary; `0` removes it. ABCI's `power`.
    pub weight: u64,
}

/// What an [`Application`] returns from [`Application::commit`] — the channel
/// by which a committed block's execution feeds information back to consensus.
///
/// This is the application seam's commit-time return value, mirroring ABCI's
/// `ResponseFinalizeBlock`. It exists so an application that owns membership
/// (a staking module) can drive the validator set. [`Default`] is "nothing to
/// report": an application that does not drive membership — the reth EL, where
/// Ethereum keeps the validator set in the *consensus* layer, not the
/// execution layer — returns `CommitResult::default()` and behaves exactly as
/// the previous `Result<()>` return did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommitResult {
    /// Validator-set changes the application requests as a result of this
    /// commit. Empty for an application that does not drive membership. The
    /// integration layer does not consume these yet — applying them at a view
    /// boundary via the reconfig path is the next step on this seam.
    pub validator_updates: Vec<ValidatorUpdate>,
    /// Opaque application output for this commit (an ABCI `app_data`-style
    /// escape hatch). Carried for backends that need to surface per-commit
    /// data to consensus; the *commitment* story for it — a new header field
    /// vs. folding into the commands commitment — is deliberately left
    /// unsettled, so the integration layer currently ignores it.
    pub app_data: Option<Bytes>,
}

/// One validator's participation in the justifying QC, surfaced to the
/// application via [`AppContext::last_commit`]. Mirrors a single entry of
/// ABCI's `CommitInfo.votes`: the validator's identity and the voting
/// weight it carried in the set active at the QC's view.
///
/// Only validators that *signed* the QC are listed (a present-and-signed
/// entry); a non-signer simply does not appear. That is enough for the
/// reward and proposer-incentive use this exists for — apportioning a
/// reward across the validators whose votes actually formed the quorum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteInfo {
    /// The signing validator's identity key ([`NodeId`]).
    pub validator: NodeId,
    /// The validator's voting weight in the set active at the QC's view.
    pub weight: u64,
}

/// One piece of committed misbehaviour evidence, surfaced to the
/// application via [`AppContext::evidence`] with the offender already
/// resolved to a stable validator id. Mirrors ABCI's `Misbehavior`.
///
/// Consensus has already verified the underlying proof (resolving the
/// offender through the key history at the equivocation view) before
/// placing it here — the application reads the resolved offender and need
/// not re-verify the cryptographic proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    /// The misbehaving validator's stable identity key ([`NodeId`]).
    pub offender: NodeId,
    /// The view at which the equivocation occurred.
    pub view: View,
}

/// Per-block contextual information consensus surfaces to the
/// [`Application`] at proposal-build and commit time (#653) — an opaque
/// escape-hatch the application *reads*. Consensus does not interpret what
/// the application does with it; it is **not** consensus-interpreted state.
///
/// It exists to feed the application data that is not otherwise on the
/// [`Block`] it receives: who proposed, which validators' votes justify
/// the block (with weights), and any misbehaviour evidence committed in
/// it. The reth EL ignores it (Ethereum keeps proposer/vote accounting in
/// its own consensus layer); a Cosmos adapter maps it onto
/// `RequestPrepareProposal` / `RequestFinalizeBlock`; a staking
/// application reads `last_commit` to apportion rewards and `evidence` to
/// drive slashing.
///
/// # Which fields are populated when
///
/// - At [`Application::build_proposal`]: `proposer` is the local building
///   node, and `last_commit` is resolved from the `high_qc` the proposal
///   extends. `evidence` is empty (the leader's evidence-embedding
///   decision is made separately and lands in the block's commands).
/// - At [`Application::commit`]: `proposer` is the committed block's
///   proposer, and `evidence` is the resolved offenders from the block's
///   evidence commands. `last_commit` is currently empty here: the QC that
///   justified a committed block is not threaded into the commit path
///   today, and no consumer needs it yet (reth ignores it). Filling it is
///   a mechanical follow-up when a commit-time consumer (the Cosmos
///   adapter) appears.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppContext {
    /// The block's proposer: the local node at build time, the committed
    /// block's `header.proposer` at commit time.
    pub proposer: NodeId,
    /// Validators whose votes justify this block, with their weight in the
    /// set active at the justifying QC's view. See the type-level note on
    /// when this is populated.
    pub last_commit: Vec<VoteInfo>,
    /// Misbehaviour evidence committed in this block, offenders resolved.
    /// Populated at commit; empty at build.
    pub evidence: Vec<Evidence>,
}

/// The asynchronous production application seam.
///
/// Object-safe (`Arc<dyn Application>`) and async via the codebase's
/// [`BoxFuture`] convention rather than `async fn` in trait, so a `dyn`
/// implementation can be stored on the integration layer.
pub trait Application: Send + Sync {
    /// Build a child block extending `parent` at `view`, justified by
    /// `high_qc`. This is the async analogue of
    /// [`BlockBuilder::build`](crate::hotstuff::step::BlockBuilder::build);
    /// the contract on the arguments and the `Err` semantics are the same:
    ///
    /// - `pending_blocks` is the safety core's
    ///   [`HotStuffState::pending_blocks`] at the moment of build, so an
    ///   implementation can fold the uncommitted-ancestor chain into its
    ///   state commitment (issue #375).
    /// - `Err` is the recoverable "no proposal for this view" signal
    ///   (issue #326): the integration layer logs and skips, leaving the
    ///   core's `proposed_in_view` unset so a later leader retries.
    ///
    /// `timestamp` is the proposal time in Unix epoch milliseconds (the
    /// integration layer's wall clock), stamped into the header clamped to
    /// the parent so block time is non-decreasing. An execution layer also
    /// uses it as the block's execution time — see
    /// [`BlockHeader::timestamp`](crate::replication::block::BlockHeader::timestamp).
    ///
    /// All borrowed arguments share the future's lifetime, so the
    /// integration layer holds them across the `await`.
    ///
    /// `ctx` ([`AppContext`]) carries proposer/last-commit information the
    /// application may fold into the proposal (e.g. a staking app crediting
    /// the previous quorum); it is read-only and consensus-uninterpreted.
    ///
    /// [`HotStuffState::pending_blocks`]: crate::hotstuff::HotStuffState::pending_blocks
    fn build_proposal<'a>(
        &'a self,
        ctx: &'a AppContext,
        parent: &'a Block,
        view: View,
        high_qc: &'a QuorumCertificate,
        pending_blocks: &'a HashMap<BlockHash, Block>,
        timestamp: u64,
    ) -> BoxFuture<'a, anyhow::Result<Block>>;

    /// Execute a committed `block` — the deferred-execution step. This is
    /// the only point at which the application mutates its own state in
    /// response to consensus, and it is where an out-of-process execution
    /// layer does real async I/O: a reth EL runs `newPayloadV3` to execute
    /// the payload and `forkchoiceUpdatedV3` to finalize it. The counter
    /// application applies the block's commands to its in-process state
    /// machine.
    ///
    /// Called once per commit, in height order, by the integration layer
    /// *before* it does its own consensus-layer bookkeeping (durable block
    /// write, prune, snapshot, commit-notifier fan-out).
    ///
    /// `Err` is informational, not fatal: consensus commits a block
    /// regardless of execution outcome — the safety core is independent of
    /// payload validity (the deferred-execution model, where a leader's
    /// claimed post-state is validated one block later, not at vote time).
    /// The integration layer logs an `Err` and proceeds with the commit.
    /// Individual command-level failures the application treats as no-ops
    /// (per the [`StateMachine::apply`] contract) are its own concern and
    /// need not surface here.
    ///
    /// On success the application returns a [`CommitResult`] — the channel
    /// by which an application that owns membership feeds validator-set
    /// changes back to consensus. An application that does not drive
    /// membership (the reth EL) returns [`CommitResult::default`], which is
    /// behaviourally identical to the previous `Result<()>`.
    ///
    /// `ctx` ([`AppContext`]) carries the committed block's proposer and
    /// any resolved misbehaviour evidence — the channel by which a staking
    /// application reads evidence to drive slashing and the proposer to
    /// credit rewards. Read-only and consensus-uninterpreted.
    ///
    /// [`StateMachine::apply`]: crate::replication::state_machine::StateMachine::apply
    fn commit<'a>(
        &'a self,
        ctx: &'a AppContext,
        block: &'a Block,
    ) -> BoxFuture<'a, anyhow::Result<CommitResult>>;

    /// The height this application has actually **executed** — for an
    /// out-of-process execution layer (a reth EL) this can lag the consensus
    /// committed height, because [`Self::commit`] only advances the executed
    /// frontier when the EL reports the payload `VALID`; while the EL is
    /// `SYNCING` (missing the block's parent state) the frontier is held.
    ///
    /// `None` (the default) means "never lags": an in-process application that
    /// executes synchronously at commit is always at the committed height, so
    /// the integration layer's startup EL-catch-up (#635) skips it entirely.
    /// `Some(h)` lets the integration layer detect a behind EL and replay the
    /// committed payloads `(h, committed]` it still holds in storage.
    fn executed_height(&self) -> Option<Height> {
        None
    }

    /// Slash the validator `node_id` — the economic half of the
    /// equivocation penalty (#658b), called by the integration layer when
    /// committed evidence first records that validator. An application that
    /// owns a stake ledger zeroes the validator's bonded stake (a capital
    /// burn that also keeps the ledger consistent with the consensus-layer
    /// jail #658a applies via the reconfig path); the resulting `weight 0`
    /// delta rides the next [`Self::commit`]'s [`CommitResult`].
    ///
    /// The default is a no-op: a tokenless application has no stake, and the
    /// *membership* consequence is the consensus-layer jail (#658a / #457),
    /// which runs regardless of this hook.
    fn slash(&self, _node_id: NodeId) {}

    // ── Synchronous state queries ──────────────────────────────────────
    //
    // These mirror the same-named [`StateMachine`] methods and are the
    // integration layer's read/serialize/restore window onto application
    // state. They are synchronous by contract: each is cheap and on a hot
    // or latency-sensitive path (the per-command vote check, the
    // divergence check on every vote, snapshot create/restore), and an
    // execution layer must answer them from already-resolved local state
    // (a tracked committed state root, an on-disk snapshot) rather than a
    // fresh round trip. The reth EL satisfies this: `state_commitment` is
    // its tracked committed state root and `check` is form-only.

    /// Tier-1 includability check for one command — the
    /// [`StateMachine::check`] contract. Stateless and deterministic, run
    /// on both the build and the vote paths.
    ///
    /// [`StateMachine::check`]: crate::replication::state_machine::StateMachine::check
    fn check(&self, cmd: &[u8]) -> anyhow::Result<()>;

    /// A deterministic 32-byte commitment over the application's current
    /// committed state — the [`StateMachine::state_commitment`] contract.
    /// Used to detect divergence (compared against a block's stamped
    /// `committed_state_root`) and to cross-check a restored snapshot.
    ///
    /// [`StateMachine::state_commitment`]: crate::replication::state_machine::StateMachine::state_commitment
    fn state_commitment(&self) -> [u8; 32];

    /// Serialize the application's current state to opaque bytes for a
    /// consensus snapshot — the [`StateMachine::snapshot`] contract.
    ///
    /// [`StateMachine::snapshot`]: crate::replication::state_machine::StateMachine::snapshot
    fn snapshot(&self) -> Bytes;

    /// Overwrite the application's state from a snapshot blob previously
    /// produced by [`Self::snapshot`] — the [`StateMachine::restore`]
    /// contract. `Err` is recoverable: the joiner abandons this restore
    /// attempt rather than the node panicking.
    ///
    /// [`StateMachine::restore`]: crate::replication::state_machine::StateMachine::restore
    fn restore(&self, snap: &[u8]) -> anyhow::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_result_default_reports_nothing() {
        // The contract a non-membership-driving application (the reth EL)
        // relies on: the default is empty, i.e. behaviourally identical to
        // the old `Result<()>` return.
        let r = CommitResult::default();
        assert!(r.validator_updates.is_empty());
        assert!(r.app_data.is_none());
    }

    #[test]
    fn commit_result_carries_validator_updates() {
        // Locks the public shape the membership consumer will read: a
        // weight-keyed update where 0 removes. ABCI's `{pub_key, power}`.
        let r = CommitResult {
            validator_updates: vec![
                ValidatorUpdate {
                    node_id: [1u8; 32],
                    weight: 5,
                },
                ValidatorUpdate {
                    node_id: [2u8; 32],
                    weight: 0,
                },
            ],
            app_data: Some(Bytes::from_static(b"opaque")),
        };
        assert_eq!(r.validator_updates.len(), 2);
        assert_eq!(r.validator_updates[0].weight, 5);
        assert_eq!(r.validator_updates[1].weight, 0);
        assert_eq!(r.app_data.as_deref(), Some(b"opaque".as_ref()));
    }
}
