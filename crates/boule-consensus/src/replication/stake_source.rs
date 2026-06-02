//! Pluggable source of the weighted validator set (#654).
//!
//! The authoritative stake-of-truth lives behind [`StakeSource`]. An
//! application that drives membership records [`StakeOp`]s against its
//! source and drains the resulting [`ValidatorUpdate`]s to return from
//! [`Application::commit`](crate::replication::application::Application::commit)
//! as `validator_updates` — which the integration layer then materialises
//! into a reconfig (#652).
//!
//! The default implementation here, [`BondedStakeLedger`], is **CL-native**:
//! stake lives in consensus-layer state. The same contract is meant to be
//! satisfied by an EVM deposit-contract reader (#655) or a Cosmos x/staking
//! adapter — so the stake source-of-truth is pluggable without a consensus
//! rewrite, while weighted quorum (#461) keeps reading the resulting
//! [`ValidatorSet`](crate::validator_set::ValidatorSet) exactly as before.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use boule_core::identity::NodeId;

use crate::replication::application::ValidatorUpdate;

/// A stake operation against a validator's bonded balance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StakeOp {
    /// Add `amount` to the validator's bonded stake.
    Bond { amount: u64 },
    /// Remove up to `amount` from the validator's bonded stake, saturating
    /// at zero (a full unbond removes the validator).
    Unbond { amount: u64 },
}

/// Pluggable source of the weighted validator set.
///
/// Records stake operations and yields the validator-set deltas they imply.
/// Implementations: the CL-native [`BondedStakeLedger`] below; an EVM
/// deposit-contract reader (#655); a Cosmos x/staking adapter.
pub trait StakeSource: Send + Sync {
    /// Apply a stake operation to `node_id`'s bonded balance.
    fn apply(&mut self, node_id: NodeId, op: StakeOp);

    /// Drain the validator-set changes accrued since the last call — the
    /// deltas (a new voting weight, or `weight 0` to remove) the
    /// application returns as `CommitResult::validator_updates`.
    fn take_updates(&mut self) -> Vec<ValidatorUpdate>;
}

/// CL-native [`StakeSource`]: an in-process ledger mapping each validator
/// to its bonded stake, with voting weight equal to that stake (a 1:1 toy
/// model — a richer source would map a balance to a weight curve).
///
/// Seeded from the genesis weighted set so unbonding a genesis validator
/// produces the correct delta. A change emits a [`ValidatorUpdate`] only
/// when the resulting weight actually differs, so a no-op operation (bond
/// 0, or unbond from an already-zero balance) accrues nothing.
pub struct BondedStakeLedger {
    /// Current bonded stake (== voting weight) per validator; a validator
    /// with zero stake is absent.
    stake: BTreeMap<NodeId, u64>,
    /// Updates accrued since the last [`StakeSource::take_updates`].
    pending: Vec<ValidatorUpdate>,
}

impl BondedStakeLedger {
    /// An empty ledger (no seated validators).
    pub fn empty() -> Self {
        Self {
            stake: BTreeMap::new(),
            pending: Vec::new(),
        }
    }

    /// Seed from a genesis weighted set: each `(node_id, weight)` becomes
    /// the validator's initial bonded stake. Zero-weight entries are
    /// ignored (the [`ValidatorSet`](crate::validator_set::ValidatorSet)
    /// invariant forbids them anyway).
    pub fn seeded_from(genesis: impl IntoIterator<Item = (NodeId, u64)>) -> Self {
        Self {
            stake: genesis.into_iter().filter(|(_, w)| *w > 0).collect(),
            pending: Vec::new(),
        }
    }

    /// Current bonded stake (== weight) of `node_id`, or 0 if unseated.
    pub fn stake_of(&self, node_id: &NodeId) -> u64 {
        self.stake.get(node_id).copied().unwrap_or(0)
    }
}

impl StakeSource for BondedStakeLedger {
    fn apply(&mut self, node_id: NodeId, op: StakeOp) {
        let cur = self.stake_of(&node_id);
        let next = match op {
            StakeOp::Bond { amount } => cur.saturating_add(amount),
            StakeOp::Unbond { amount } => cur.saturating_sub(amount),
        };
        if next == cur {
            return; // no-op: nothing changes, nothing to report.
        }
        if next == 0 {
            self.stake.remove(&node_id);
        } else {
            self.stake.insert(node_id, next);
        }
        self.pending.push(ValidatorUpdate {
            node_id,
            weight: next,
        });
    }

    fn take_updates(&mut self) -> Vec<ValidatorUpdate> {
        std::mem::take(&mut self.pending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bond_increases_weight_and_emits_update() {
        let mut l = BondedStakeLedger::seeded_from([([1u8; 32], 1)]);
        l.apply([1u8; 32], StakeOp::Bond { amount: 4 });
        assert_eq!(l.stake_of(&[1u8; 32]), 5);
        let u = l.take_updates();
        assert_eq!(u.len(), 1);
        assert_eq!(u[0].weight, 5);
        assert!(l.take_updates().is_empty(), "draining is one-shot");
    }

    #[test]
    fn full_unbond_removes_the_validator() {
        let mut l = BondedStakeLedger::seeded_from([([2u8; 32], 3)]);
        l.apply([2u8; 32], StakeOp::Unbond { amount: 3 });
        assert_eq!(l.stake_of(&[2u8; 32]), 0);
        let u = l.take_updates();
        assert_eq!(u.len(), 1);
        assert_eq!(u[0].node_id, [2u8; 32]);
        assert_eq!(u[0].weight, 0, "weight 0 is the removal signal");
    }

    #[test]
    fn partial_unbond_lowers_weight() {
        let mut l = BondedStakeLedger::seeded_from([([3u8; 32], 10)]);
        l.apply([3u8; 32], StakeOp::Unbond { amount: 4 });
        assert_eq!(l.take_updates()[0].weight, 6);
    }

    #[test]
    fn no_op_operations_emit_nothing() {
        let mut l = BondedStakeLedger::seeded_from([([4u8; 32], 2)]);
        l.apply([4u8; 32], StakeOp::Bond { amount: 0 }); // no change
        l.apply([9u8; 32], StakeOp::Unbond { amount: 5 }); // unseated -> stays 0
        assert!(l.take_updates().is_empty());
    }

    #[test]
    fn unbond_saturates_at_zero() {
        let mut l = BondedStakeLedger::seeded_from([([5u8; 32], 2)]);
        l.apply([5u8; 32], StakeOp::Unbond { amount: 100 });
        assert_eq!(l.take_updates()[0].weight, 0);
        assert_eq!(l.stake_of(&[5u8; 32]), 0);
    }
}
