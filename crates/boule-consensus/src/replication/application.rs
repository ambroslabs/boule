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

use crate::View;
use crate::hotstuff::qc::QuorumCertificate;
use crate::replication::block::{Block, BlockHash};

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
    /// All borrowed arguments share the future's lifetime, so the
    /// integration layer holds them across the `await`.
    ///
    /// [`HotStuffState::pending_blocks`]: crate::hotstuff::HotStuffState::pending_blocks
    fn build_proposal<'a>(
        &'a self,
        parent: &'a Block,
        view: View,
        high_qc: &'a QuorumCertificate,
        pending_blocks: &'a HashMap<BlockHash, Block>,
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
    /// [`StateMachine::apply`]: crate::replication::state_machine::StateMachine::apply
    fn commit<'a>(&'a self, block: &'a Block) -> BoxFuture<'a, anyhow::Result<()>>;
}
