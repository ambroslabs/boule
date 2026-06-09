//! The production placeholder [`Application`] (#894).
//!
//! [`ConsensusNode::new`](super::ConsensusNode::new) /
//! [`recover`](super::ConsensusNode::recover) must seed the `app` field with
//! *something*, but the only supported production execution backend is reth
//! (`RethApplication`, #883), which every production startup path installs via
//! [`ConsensusNode::with_application`](super::ConsensusNode::with_application)
//! immediately after construction. In test/sim builds the constructors instead
//! seed the in-process counter `MempoolBlockBuilder` (feature-gated, #894).
//!
//! This leaves the non-`testing` build with no default in-process application
//! to wire — the counter is gated out. `UninitializedApplication` fills that
//! gap: it is a never-driven placeholder whose methods panic, encoding the
//! invariant that production MUST call `with_application` before running the
//! consensus loop. Because the loop only ever touches `app` after startup
//! wiring, the panics are unreachable in a correctly-wired node and serve as a
//! loud guard against a future caller that forgets the install step.

use std::collections::HashMap;

use boule_consensus::replication::application::{AppContext, Application, CommitResult};
use boule_consensus::replication::block::{Block, BlockHash};
use boule_consensus::{View, hotstuff::qc::QuorumCertificate};
use boule_core::clock::BoxFuture;
use bytes::Bytes;

/// Panicking placeholder wired by the constructors in non-`testing` builds.
/// Production replaces it via
/// [`ConsensusNode::with_application`](super::ConsensusNode::with_application)
/// before the consensus loop runs, so none of its methods are ever called.
#[derive(Debug, Default)]
pub(super) struct UninitializedApplication;

const MSG: &str = "BUG: ConsensusNode ran with the placeholder application; \
     production must install an execution backend via with_application() before run()";

impl Application for UninitializedApplication {
    fn build_proposal<'a>(
        &'a self,
        _ctx: &'a AppContext,
        _parent: &'a Block,
        _view: View,
        _high_qc: &'a QuorumCertificate,
        _pending_blocks: &'a HashMap<BlockHash, Block>,
        _timestamp: u64,
    ) -> BoxFuture<'a, anyhow::Result<Block>> {
        Box::pin(async { panic!("{MSG}") })
    }

    fn commit<'a>(
        &'a self,
        _ctx: &'a AppContext,
        _block: &'a Block,
    ) -> BoxFuture<'a, anyhow::Result<CommitResult>> {
        Box::pin(async { panic!("{MSG}") })
    }

    fn check(&self, _cmd: &[u8]) -> anyhow::Result<()> {
        panic!("{MSG}")
    }

    fn state_commitment(&self) -> [u8; 32] {
        panic!("{MSG}")
    }

    fn snapshot(&self) -> Bytes {
        panic!("{MSG}")
    }

    fn restore(&self, _snap: &[u8]) -> anyhow::Result<()> {
        panic!("{MSG}")
    }
}
