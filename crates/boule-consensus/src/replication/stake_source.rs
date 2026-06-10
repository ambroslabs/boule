use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use boule_core::identity::NodeId;

use crate::Height;
use crate::replication::application::ValidatorUpdate;

pub const UNBONDING_DELAY: Height = Height(512);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StakeOp {
    Bond { amount: u64 },

    Unbond { amount: u64 },
}

pub trait StakeSource: Send + Sync {
    fn apply(&mut self, node_id: NodeId, op: StakeOp);

    fn take_updates(&mut self) -> Vec<ValidatorUpdate>;

    fn advance_to_height(&mut self, _height: Height) {}

    fn stake_of(&self, _node_id: &NodeId) -> u64 {
        0
    }

    fn total_stake(&self) -> u64 {
        0
    }

    fn slash(&mut self, node_id: NodeId) {
        self.apply(node_id, StakeOp::Unbond { amount: u64::MAX });
    }
}

#[derive(Debug, Clone, Copy)]
struct Unbonding {
    amount: u64,
    mature_at: Height,
}

pub struct BondedStakeLedger {
    stake: BTreeMap<NodeId, u64>,

    unbonding: BTreeMap<NodeId, Vec<Unbonding>>,

    current_height: Height,

    pending: Vec<ValidatorUpdate>,
}

impl BondedStakeLedger {
    pub fn empty() -> Self {
        Self {
            stake: BTreeMap::new(),
            unbonding: BTreeMap::new(),
            current_height: Height::ZERO,
            pending: Vec::new(),
        }
    }

    pub fn seeded_from(genesis: impl IntoIterator<Item = (NodeId, u64)>) -> Self {
        Self {
            stake: genesis.into_iter().filter(|(_, w)| *w > 0).collect(),
            unbonding: BTreeMap::new(),
            current_height: Height::ZERO,
            pending: Vec::new(),
        }
    }

    pub fn stake_of(&self, node_id: &NodeId) -> u64 {
        self.stake.get(node_id).copied().unwrap_or(0)
    }

    pub fn unbonding_of(&self, node_id: &NodeId) -> u64 {
        self.unbonding
            .get(node_id)
            .map(|q| q.iter().map(|u| u.amount).sum())
            .unwrap_or(0)
    }
}

impl StakeSource for BondedStakeLedger {
    fn apply(&mut self, node_id: NodeId, op: StakeOp) {
        let cur = self.stake_of(&node_id);
        match op {
            StakeOp::Bond { amount } => {
                let next = cur.saturating_add(amount);
                if next == cur {
                    return;
                }
                self.stake.insert(node_id, next);
                self.pending.push(ValidatorUpdate {
                    node_id,
                    weight: next,
                });
            }
            StakeOp::Unbond { amount } => {
                let moved = amount.min(cur);
                if moved == 0 {
                    return;
                }
                let next = cur - moved;
                if next == 0 {
                    self.stake.remove(&node_id);
                } else {
                    self.stake.insert(node_id, next);
                }
                self.unbonding.entry(node_id).or_default().push(Unbonding {
                    amount: moved,
                    mature_at: self.current_height.saturating_add(UNBONDING_DELAY),
                });
                self.pending.push(ValidatorUpdate {
                    node_id,
                    weight: next,
                });
            }
        }
    }

    fn take_updates(&mut self) -> Vec<ValidatorUpdate> {
        std::mem::take(&mut self.pending)
    }

    fn advance_to_height(&mut self, height: Height) {
        self.current_height = height;

        self.unbonding.retain(|_, queue| {
            queue.retain(|u| u.mature_at > height);
            !queue.is_empty()
        });
    }

    fn stake_of(&self, node_id: &NodeId) -> u64 {
        self.stake.get(node_id).copied().unwrap_or(0)
    }

    fn total_stake(&self) -> u64 {
        self.stake.values().copied().sum()
    }

    fn slash(&mut self, node_id: NodeId) {
        let had_active = self.stake.remove(&node_id).unwrap_or(0);
        self.unbonding.remove(&node_id);
        if had_active > 0 {
            self.pending.push(ValidatorUpdate { node_id, weight: 0 });
        }
    }
}
