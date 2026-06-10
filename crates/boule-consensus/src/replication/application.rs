use std::collections::HashMap;

use boule_core::clock::BoxFuture;
use boule_core::identity::NodeId;

use bytes::Bytes;

use crate::hotstuff::qc::QuorumCertificate;
use crate::replication::block::{Block, BlockHash};
use crate::{Height, View};

pub trait RecentBlocks: Send + Sync {
    fn get(&self, hash: &BlockHash) -> Option<Block>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorUpdate {
    pub node_id: NodeId,

    pub weight: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidatorEffect {
    KeyRotation(Bytes),

    EndpointUpdate(Bytes),

    ParamUpdate(Bytes),

    Reconfig(Bytes),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommitResult {
    pub validator_updates: Vec<ValidatorUpdate>,

    pub effects: Vec<ValidatorEffect>,

    pub app_data: Option<Bytes>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteInfo {
    pub validator: NodeId,

    pub weight: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub offender: NodeId,

    pub view: View,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppContext {
    pub proposer: NodeId,

    pub last_commit: Vec<VoteInfo>,

    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IntegrationCapability {
    Membership,

    KeyRotation,

    EndpointAdvertisement,

    ParameterUpdates,

    Slashing,

    Rewards,
}

pub trait Application: Send + Sync {
    fn build_proposal<'a>(
        &'a self,
        ctx: &'a AppContext,
        parent: &'a Block,
        view: View,
        high_qc: &'a QuorumCertificate,
        pending_blocks: &'a HashMap<BlockHash, Block>,
        timestamp: u64,
    ) -> BoxFuture<'a, anyhow::Result<Block>>;

    fn validate_proposal<'a>(
        &'a self,
        _block: &'a Block,
        _recent: &'a dyn RecentBlocks,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn commit<'a>(
        &'a self,
        ctx: &'a AppContext,
        block: &'a Block,
    ) -> BoxFuture<'a, anyhow::Result<CommitResult>>;

    fn executed_height(&self) -> Option<Height> {
        None
    }

    fn el_head<'a>(&'a self) -> BoxFuture<'a, Option<Height>> {
        Box::pin(async { None })
    }

    fn el_devp2p_handoff<'a>(&'a self, _tip: &'a Block) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn slash(&self, _node_id: NodeId) {}

    fn capabilities(&self) -> Vec<IntegrationCapability> {
        Vec::new()
    }

    fn check(&self, cmd: &[u8]) -> anyhow::Result<()>;

    fn state_commitment(&self) -> [u8; 32];

    fn snapshot(&self) -> Bytes;

    fn restore(&self, snap: &[u8]) -> anyhow::Result<()>;
}
