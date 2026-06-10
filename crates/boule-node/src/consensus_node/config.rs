use std::time::Duration;

use boule_consensus::limits::CacheLimits;
use boule_consensus::replication::block::{Block, BlockHash};
use boule_consensus::validator_set::ValidatorSet;
use boule_consensus::{Height, View};
use boule_core::identity::NodeId;

#[derive(Debug, Clone)]
pub struct NodeConfigForConsensus {
    pub validator_set: ValidatorSet,

    pub genesis: Block,

    pub propose_limit: usize,

    pub timeout_base: Duration,

    pub timeout_max: Duration,

    pub limits: CacheLimits,

    pub snapshot_policy: boule_consensus::replication::snapshot::SnapshotPolicy,

    pub min_v_eff_delay: View,

    pub block_retention_window: u64,

    pub min_block_interval: Duration,

    pub weak_subjectivity_checkpoint: Option<(Height, BlockHash)>,

    pub operator_keys: Vec<(NodeId, NodeId)>,

    pub max_endpoint_list_length: usize,
}

impl NodeConfigForConsensus {
    pub fn for_testing(validator_set: ValidatorSet, genesis: Block) -> Self {
        Self {
            validator_set,
            genesis,
            propose_limit: 64,
            timeout_base: Duration::from_millis(200),
            timeout_max: Duration::from_secs(10),

            limits: CacheLimits::unbounded_for_tests(),

            snapshot_policy: boule_consensus::replication::snapshot::SnapshotPolicy::disabled(),
            min_v_eff_delay: boule_consensus::reconfig::MIN_V_EFF_DELAY,

            block_retention_window: 0,

            min_block_interval: Duration::ZERO,
            weak_subjectivity_checkpoint: None,

            operator_keys: Vec::new(),

            max_endpoint_list_length: 8,
        }
    }
}
