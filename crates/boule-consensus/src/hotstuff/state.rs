use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::limits::CacheEvictionCounters;
use crate::replication::block::{Block, BlockHash};
use crate::validator_history::ValidatorSetHistory;
use crate::validator_set::ValidatorSet;
use crate::{Height, View};

use super::qc::VerifiedQc;

const TRACE_TARGET: &str = "boule_core::consensus";

const PROTECTED_HIGH_QC_DEPTH: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Locked {
    pub view: View,
    pub height: Height,
    pub block_hash: BlockHash,
}

#[derive(Debug, Clone)]
pub struct HotStuffState {
    pub current_view: View,

    pub locked: Option<Locked>,

    pub high_qc: Option<VerifiedQc>,

    pub last_voted_view: View,

    pub validator_set: ValidatorSet,

    pub validator_history: ValidatorSetHistory,

    pub pending_blocks: HashMap<BlockHash, Block>,

    pub genesis_hash: BlockHash,

    pending_blocks_capacity: usize,

    eviction_counters: CacheEvictionCounters,
}

impl HotStuffState {
    pub fn new(validator_set: ValidatorSet, genesis: Block) -> Self {
        let genesis_hash = genesis.hash();
        let mut pending = HashMap::new();
        pending.insert(genesis_hash, genesis);
        let validator_history = ValidatorSetHistory::from_genesis(validator_set.clone());
        Self {
            current_view: View::ZERO,
            locked: None,
            high_qc: None,
            last_voted_view: View::ZERO,
            validator_set,
            validator_history,
            pending_blocks: pending,
            genesis_hash,

            pending_blocks_capacity: usize::MAX,
            eviction_counters: CacheEvictionCounters::default(),
        }
    }

    pub(crate) fn set_pending_blocks_limit(
        &mut self,
        capacity: usize,
        counters: CacheEvictionCounters,
    ) {
        self.pending_blocks_capacity = capacity;
        self.eviction_counters = counters;
    }

    pub fn insert_pending(&mut self, block: Block) {
        let hash = block.hash();
        if !self.pending_blocks.contains_key(&hash) {
            self.evict_pending_to_fit_one();
        }
        self.pending_blocks.insert(hash, block);
    }

    pub fn get_pending(&self, hash: &BlockHash) -> Option<&Block> {
        self.pending_blocks.get(hash)
    }

    fn evict_pending_to_fit_one(&mut self) {
        if self.pending_blocks.len() < self.pending_blocks_capacity {
            return;
        }
        let protected = self.protected_block_hashes();

        let Some((victim_hash, victim_height)) = self
            .pending_blocks
            .iter()
            .filter(|(hash, _)| !protected.contains(*hash))
            .map(|(hash, block)| (*hash, block.header.height))
            .min_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)))
        else {
            tracing::info!(
                target: TRACE_TARGET,
                cache = "pending_blocks",
                policy = "cap_skipped_all_protected",
                cap = self.pending_blocks_capacity,
                size = self.pending_blocks.len(),
                "consensus_cache_evicted",
            );
            return;
        };
        if self.pending_blocks.remove(&victim_hash).is_some() {
            self.eviction_counters.inc_pending_blocks(1);
            tracing::info!(
                target: TRACE_TARGET,
                cache = "pending_blocks",
                policy = "cap",
                evicted_height = %victim_height,
                cap = self.pending_blocks_capacity,
                size_after = self.pending_blocks.len(),
                "consensus_cache_evicted",
            );
        }
    }

    fn protected_block_hashes(&self) -> std::collections::HashSet<BlockHash> {
        let mut out = std::collections::HashSet::new();
        out.insert(self.genesis_hash);
        if let Some(qc) = &self.high_qc {
            let mut cursor = qc.block_hash();
            for _ in 0..PROTECTED_HIGH_QC_DEPTH {
                if !out.insert(cursor) {
                    break;
                }
                let Some(b) = self.pending_blocks.get(&cursor) else {
                    break;
                };
                cursor = b.header.parent_hash;
            }
        }
        out
    }
}
