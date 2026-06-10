use std::collections::HashMap;

use boule_consensus::replication::application::{AppContext, Application, CommitResult};
use boule_consensus::replication::block::{Block, BlockHash};
use boule_consensus::{View, hotstuff::qc::QuorumCertificate};
use boule_core::clock::BoxFuture;
use bytes::Bytes;

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
