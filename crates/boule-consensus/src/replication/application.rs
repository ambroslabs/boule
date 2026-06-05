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

/// A read-only resolver, handed to [`Application::validate_proposal`], for any
/// **recent block the voter already holds** — by its header hash.
///
/// This spans two stores the integration layer owns: the proposed block's
/// uncommitted ancestors (the safety core's `pending_blocks`) and the
/// recently-committed frontier (the durable block store). It exists so a
/// vote-time check can anchor to a block a few links back without re-fetching it
/// over the network.
///
/// The reth backend's #797 weight-proof check is the sole user: a seated-weight
/// delta in a block's `extra_data` is derived from the staking/slashing logs of
/// a *source* block whose execution emitted them. The lag from that source block
/// to the block that carries the delta is bounded by the **commit depth** — the
/// delta is staged at the source block's commit (a three-chain deep) and the
/// very next built block carries the whole pending set, so an honest source is
/// at most a handful of blocks back and is always still resolvable here. That
/// bound is what lets the backend **reject** (rather than defer) a leader whose
/// weight names a source it cannot anchor: an honest leader never does.
///
/// `get` returns `None` for a hash outside the held window (a block evicted
/// below the retention horizon, or one the voter never saw) — far below any
/// honest weight-proof anchor, so the backend treats an unresolvable anchor as a
/// forgery, not an honest gap.
pub trait RecentBlocks: Send + Sync {
    /// The recent block with this header hash, if the voter holds it (in
    /// `pending_blocks` or the recently-committed block store), else `None`.
    fn get(&self, hash: &BlockHash) -> Option<Block>;
}

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

/// One richer validator-relevant effect an [`Application`] drives back into
/// consensus through [`CommitResult::effects`] — the part of the seam beyond a
/// plain voting-weight delta ([`CommitResult::validator_updates`]).
///
/// This is the **execution-layer transaction channel** (milestone #4, the
/// "route all transactions through the execution layer" direction): an EL that
/// has already *authorized* a validator-relevant transaction — an EVM
/// precompile that verified a dual-signed key rotation, a governance predeploy
/// that approved a reconfig — returns the resulting effect here, and consensus
/// re-materializes it as a real block command so it flows through the same
/// validated / header-committed / recoverable path a natively-submitted system
/// command would. Consensus applies a *typed* effect; it never reads "EVM logs"
/// directly. See issue #727.
///
/// Each variant carries the already-encoded consensus **system command** the
/// effect materializes into (e.g. a [`DualSignedRotation`] for a key rotation),
/// not raw EL state. Carrying the encoded command — rather than mutating
/// consensus state at commit — is what keeps recovery sound: the startup
/// integrity check re-derives validator history from committed block
/// *commands*, so any boundary an effect introduces must first become a real
/// command in a block (see `app_reconfig` for the same argument applied to
/// [`CommitResult::validator_updates`]).
///
/// Every category is **optional**: a backend emits only the variants its
/// authority model uses. A PoA / genesis-fixed-set backend emits none; the reth
/// EL's default emits none. The enum is `#[non_exhaustive]`: new categories are
/// added by their own milestone-#4 sub-issues without a breaking change.
///
/// [`DualSignedRotation`]: crate::validator_rotation::DualSignedRotation
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidatorEffect {
    /// A signing- or operator-key rotation the execution layer has already
    /// authorized (e.g. an EVM precompile verified the dual signature — #730),
    /// carried as the encoded consensus rotation command
    /// ([`DualSignedRotation`] / `OperatorSignedRotation` /
    /// `DualSignedOperatorRotation` / their cancels). Consensus re-materializes
    /// it as a block command so it flows through the existing rotation
    /// validate/apply path; the embedded signatures are re-verified there, so
    /// the proposer minting it need not be the rotating validator.
    ///
    /// [`DualSignedRotation`]: crate::validator_rotation::DualSignedRotation
    KeyRotation(Bytes),
    /// A validator endpoint-list update (#731 / #546): the EL records a
    /// validator's advertised network endpoints and surfaces the resulting
    /// signed endpoint command ([`SignedEndpointCommand`]) here. Consensus
    /// re-materializes it as a block command, applied via the endpoint registry
    /// (the signature + monotone `seq` are verified there).
    ///
    /// [`SignedEndpointCommand`]: crate::endpoint_registry::SignedEndpointCommand
    EndpointUpdate(Bytes),
    /// A live consensus-parameter update (#542): the EL drives a change to a
    /// tunable consensus parameter, carried as the encoded
    /// [`ConsensusParamUpdate`] command. Consensus re-materializes it as a block
    /// command, validated against the `v_eff` delay floor and scheduled at its
    /// view boundary.
    ///
    /// [`ConsensusParamUpdate`]: crate::consensus_params::ConsensusParamUpdate
    ParamUpdate(Bytes),
    /// A governance-approved membership reconfiguration (#729): the EL's
    /// governance mechanism tallied approval for a validator-set change and
    /// surfaces the resulting encoded [`ReconfigCommand`] here — adds (with
    /// endpoint + inbound `consent_sig`, #548), removes, and weight changes.
    ///
    /// Consensus re-materializes it as a block command, applied via the existing
    /// reconfig path (membership validation + the `v_eff` boundary). Unlike a
    /// staking-driven weight delta ([`CommitResult::validator_updates`]), this
    /// carries the *whole* command and is minted **verbatim**: an add's
    /// `consent_sig` pre-image is bound to the command's `v_eff`, so consensus
    /// must not recompute it. It is minted under the same one-reconfig-boundary-
    /// at-a-time discipline as the staking path, so the two never conflict.
    ///
    /// [`ReconfigCommand`]: crate::reconfig::ReconfigCommand
    Reconfig(Bytes),
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
///
/// It carries two effect channels: [`Self::validator_updates`], the
/// ABCI-shaped voting-weight deltas (the common PoS/staking case), and
/// [`Self::effects`], the richer [`ValidatorEffect`] categories that route
/// every other validator-relevant transaction through the execution layer
/// (milestone #4 / #727). Both default empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommitResult {
    /// Voting-weight / membership deltas the application requests as a result
    /// of this commit — the ABCI `ValidatorUpdate`-shaped channel. The
    /// integration layer stages these and mints them into a `ReconfigCommand`
    /// at the next proposal it builds as leader (deferred materialisation; see
    /// `app_reconfig`). Empty for an application that does not drive membership.
    pub validator_updates: Vec<ValidatorUpdate>,
    /// Richer validator-relevant effects beyond a plain weight delta — key
    /// rotations, endpoint updates, parameter updates (the execution-layer
    /// transaction channel, milestone #4 / #727). Each is materialized into a
    /// consensus system command at the next proposal. Empty for a backend that
    /// drives none of these (PoA, the reth default).
    pub effects: Vec<ValidatorEffect>,
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

/// One validator-relevant behaviour an [`Application`] backend can drive
/// through the execution-layer transaction seam — the in-code catalog of the
/// milestone-#4 integration surface. A backend *declares* the subset it
/// implements via [`Application::capabilities`]; the integration layer logs the
/// declared set when the application is wired, so a missing hook is a visible
/// gap rather than a silent one.
///
/// This is the full bidirectional surface, broader than [`ValidatorEffect`]
/// (which is only the EL→consensus *emit* side): it also names the behaviours
/// that *consume* an [`AppContext`] signal ([`Self::Slashing`] reads
/// `evidence`, [`Self::Rewards`] reads `last_commit`) and emit nothing typed.
///
/// Every capability is **optional** and chosen by the validator-authority
/// model: a PoA / genesis-fixed-set backend declares none (consensus runs with
/// a static set); a PoS backend declares [`Self::Membership`] and usually
/// [`Self::Slashing`]; only a PoS-with-rewards backend declares
/// [`Self::Rewards`] — rewards are never forced. See
/// `docs/transaction-integration-surface.md` for the full capability catalog
/// (signal consumed, effect emitted, consensus-native residue, and the
/// required-vs-optional matrix per authority model).
///
/// `#[non_exhaustive]`: new capabilities are added by their own milestone-#4
/// sub-issues without a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IntegrationCapability {
    /// Drives the validator set's membership and voting weights via
    /// [`CommitResult::validator_updates`]. Required for any
    /// stake-derived-weight model.
    Membership,
    /// Drives validator signing- / operator-key rotations via
    /// [`ValidatorEffect::KeyRotation`] (#730).
    KeyRotation,
    /// Drives validator network-endpoint advertisement via
    /// [`ValidatorEffect::EndpointUpdate`] (#731 / #546).
    EndpointAdvertisement,
    /// Drives live consensus-parameter updates via
    /// [`ValidatorEffect::ParamUpdate`] (#542).
    ParameterUpdates,
    /// Penalises committed misbehaviour: reads [`AppContext::evidence`] and
    /// emits a jail (`weight 0` in [`CommitResult::validator_updates`]) and/or
    /// an economic [`Application::slash`] (#732 / #658).
    Slashing,
    /// Apportions rewards to the validators whose votes formed a quorum: reads
    /// [`AppContext::last_commit`] at `build_proposal`. PoS-with-rewards only;
    /// never forced.
    Rewards,
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

    /// Vote-time proposal validation — the integrity gate that lets an
    /// application **refuse to vote** for a proposed `block` whose contents it
    /// cannot independently re-derive from its own consensus state (#797).
    ///
    /// Called on the **non-leader receive path**, *before* the safety core is
    /// allowed to emit a `Vote` for `block` (the integration layer runs this on
    /// `ProposalReceived` and, on `Err`, never feeds the proposal to the safety
    /// core, so no vote is cast). It must therefore be:
    ///
    /// - **Synchronous in spirit / cheap** — like the other read hooks it should
    ///   answer from already-resolved local state, not a fresh round trip. It is
    ///   async only to share the seam's [`BoxFuture`] convention; an
    ///   implementation that needs no I/O resolves immediately.
    /// - **Deterministic across honest replicas** — every honest validator must
    ///   reach the same accept/reject decision, or a forged proposal could be
    ///   accepted by some and rejected by others.
    ///
    /// The motivating attack (#797): under the reth EL, the leader stamps an
    /// authoritative registry write set `(keys, settledView, weights)` into the
    /// block's `extra_data`, which every replica's EL applies **unverified**. A
    /// Byzantine leader can forge an honest validator's key (then self-sign an
    /// equivocation and get it slashed) or forge weights to swing a quorum. This
    /// hook lets a validator re-derive the expected write set from its own state
    /// and reject a mismatch so a forged payload never reaches the BFT quorum.
    ///
    /// `Err` is the "do not vote for this proposal" signal: the integration layer
    /// logs it and drops the proposal rather than stepping it into the safety
    /// core, so the validator simply does not vote (and a later honest leader
    /// re-proposes). It is **not** a fault for the local node — the offending
    /// block is the proposer's.
    ///
    /// `recent` resolves any **recent block the voter already holds** by its
    /// header hash — the proposed block's uncommitted ancestors (the safety
    /// core's `pending_blocks`) *and* the recently-committed frontier (the
    /// durable block store). The reth backend uses it for the #797 weight
    /// **receipt-inclusion proof**: a weight delta riding this block's
    /// `extra_data` was derived from a *recent* block's EVM execution (its
    /// staking/slashing logs), so that source block's execution payload carries
    /// the `receiptsRoot` the carried proof is verified against — without
    /// re-executing anything. Because the lag from a delta's source block to the
    /// block carrying it is bounded by the commit depth (the source is at most a
    /// few blocks back — see [`RecentBlocks`]), the voter always holds the source
    /// block and can anchor the proof to it, so a leader claiming its weight's
    /// source is "too far back to verify" is rejected rather than deferred. An
    /// application with nothing proposer-authored to verify ignores `recent`.
    ///
    /// The default is `Ok(())`: an application with nothing proposer-authored to
    /// re-derive (the counter app, a PoA backend) accepts every safety-valid
    /// proposal, exactly as before this hook existed.
    fn validate_proposal<'a>(
        &'a self,
        _block: &'a Block,
        _recent: &'a dyn RecentBlocks,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async { Ok(()) })
    }

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
    /// by which an application feeds validator-relevant effects back to
    /// consensus: voting-weight deltas
    /// ([`CommitResult::validator_updates`]) and the richer
    /// [`ValidatorEffect`] categories ([`CommitResult::effects`]) that route
    /// every other validator transaction through the execution layer
    /// (milestone #4). An application that drives none of this (the reth EL)
    /// returns [`CommitResult::default`], which is behaviourally identical to
    /// the previous `Result<()>`.
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

    /// The execution layer's **actual head** — the highest block number the EL
    /// itself reports (a reth `eth_blockNumber`), as opposed to
    /// [`Self::executed_height`], which is boule's *tracked* committed frontier
    /// for the EL.
    ///
    /// These normally agree, but an **unclean crash** (SIGKILL mid-commit) can
    /// leave reth's real head *below* the frontier boule recorded: boule
    /// persisted the advanced frontier but reth never durably committed the
    /// block. The EL-catch-up replay (#826) must then start from reth's real
    /// head, not boule's frontier — replaying from `frontier+1` would skip the
    /// blocks reth is actually missing and re-wedge the EL.
    ///
    /// `None` (the default) means "no out-of-process head to query" — an
    /// in-process application, or a transport that cannot answer. The catch-up
    /// then falls back to [`Self::executed_height`] alone. An implementation
    /// returns `Some(h)` only when it has authoritatively read the EL's head;
    /// a transient query failure also yields `None` (best-effort), so the
    /// catch-up degrades to the frontier-based start rather than stalling.
    ///
    /// Async (unlike the other read hooks) because reading the EL head is a
    /// real round trip to the out-of-process EL; it is only ever called off the
    /// background EL-catch-up timer, never on a latency-sensitive path.
    fn el_head<'a>(&'a self) -> BoxFuture<'a, Option<Height>> {
        Box::pin(async { None })
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

    /// The validator-relevant behaviours this backend drives through the
    /// execution-layer transaction seam — the subset of
    /// [`IntegrationCapability`] its authority model implements. Purely
    /// declarative: the integration layer logs it when the application is wired
    /// so the integration surface a backend covers (and, by omission, the
    /// hooks it leaves to consensus) is visible rather than silent. See
    /// `docs/transaction-integration-surface.md`.
    ///
    /// The default is empty — a PoA / genesis-fixed-set backend, and the reth
    /// EL default, drive nothing and let consensus run with a static set.
    fn capabilities(&self) -> Vec<IntegrationCapability> {
        Vec::new()
    }

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
        assert!(r.effects.is_empty());
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
            ..Default::default()
        };
        assert_eq!(r.validator_updates.len(), 2);
        assert_eq!(r.validator_updates[0].weight, 5);
        assert_eq!(r.validator_updates[1].weight, 0);
        assert_eq!(r.app_data.as_deref(), Some(b"opaque".as_ref()));
    }

    #[test]
    fn commit_result_carries_typed_effects() {
        // The execution-layer transaction channel (#727): the richer effect
        // categories ride alongside weight deltas, each carrying the encoded
        // consensus command it materializes into.
        let r = CommitResult {
            effects: vec![
                ValidatorEffect::KeyRotation(Bytes::from_static(b"rot")),
                ValidatorEffect::EndpointUpdate(Bytes::from_static(b"ep")),
                ValidatorEffect::ParamUpdate(Bytes::from_static(b"param")),
                ValidatorEffect::Reconfig(Bytes::from_static(b"reconfig")),
            ],
            ..Default::default()
        };
        assert!(r.validator_updates.is_empty());
        assert_eq!(r.effects.len(), 4);
        assert_eq!(
            r.effects[0],
            ValidatorEffect::KeyRotation(Bytes::from_static(b"rot"))
        );
    }
}
