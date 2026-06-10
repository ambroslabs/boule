use std::collections::BTreeMap;

use boule_core::identity::NodeId;

pub const INDEX_SCALE: u128 = 1_000_000_000_000_000_000;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RewardConfig {
    pub issuance_per_block: u64,

    pub proposer_bonus: u64,
}

impl RewardConfig {
    pub fn is_enabled(&self) -> bool {
        self.issuance_per_block > 0 || self.proposer_bonus > 0
    }
}

#[derive(Debug, Default, Clone)]
pub struct RewardLedger {
    index: u128,
    last_index: BTreeMap<NodeId, u128>,
    balance: BTreeMap<NodeId, u64>,
}

impl RewardLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn accrue_block(&mut self, proposer: NodeId, issuance: u64, bonus: u64, total_stake: u64) {
        if total_stake > 0 && issuance > 0 {
            self.index += (u128::from(issuance) * INDEX_SCALE) / u128::from(total_stake);
        }
        if bonus > 0 {
            let b = self.balance.entry(proposer).or_default();
            *b = b.saturating_add(bonus);
        }
    }

    pub fn settle(&mut self, node_id: NodeId, stake: u64) {
        let last = self.last_index.get(&node_id).copied().unwrap_or(0);
        if self.index > last && stake > 0 {
            let earned = (u128::from(stake) * (self.index - last)) / INDEX_SCALE;
            if earned > 0 {
                let bal = self.balance.entry(node_id).or_default();
                *bal = bal.saturating_add(earned as u64);
            }
        }
        self.last_index.insert(node_id, self.index);
    }

    pub fn balance_of(&self, node_id: &NodeId) -> u64 {
        self.balance.get(node_id).copied().unwrap_or(0)
    }

    pub fn claimable(&self, node_id: &NodeId, stake: u64) -> u64 {
        let last = self.last_index.get(node_id).copied().unwrap_or(0);
        let unsettled = if self.index > last && stake > 0 {
            ((u128::from(stake) * (self.index - last)) / INDEX_SCALE) as u64
        } else {
            0
        };
        self.balance_of(node_id).saturating_add(unsettled)
    }

    pub fn index(&self) -> u128 {
        self.index
    }
}
