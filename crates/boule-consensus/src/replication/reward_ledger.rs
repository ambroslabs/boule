//! Lazy validator-reward accrual (#659a).
//!
//! Distributing rewards to every validator on every block is O(N) state writes
//! per block — a throughput killer. This is the **F1 / reward-index** model
//! (Cosmos `distribution`, Synthetix/Curve reward-per-token) instead: a single
//! global index accumulates reward *per unit of stake*, and a validator's
//! accrued reward is **settled lazily** — only when it next touches a staking
//! event (deposit / withdraw / unbond / slash) or is read out. Per block costs
//! O(1) (bump the index, credit the proposer bonus); per staking event costs
//! O(1) (settle the one validator).
//!
//! Rewards are an **optional, application-level** concern — consensus never
//! computes a reward. An [`Application`](crate::replication::application::Application)
//! that wants rewards owns a `RewardLedger` and drives it; a tokenless / PoA
//! chain simply does not (and can reward via governance instead).
//!
//! # Determinism
//!
//! All math is fixed-point integer (no floats), so every replica accrues the
//! identical balance from the identical committed state. `index` is scaled by
//! [`INDEX_SCALE`]; the floor division at accrual leaves sub-unit "dust"
//! undistributed rather than rounding non-deterministically.

use std::collections::BTreeMap;

use boule_core::identity::NodeId;

/// Fixed-point scale for the reward-per-stake index. Large enough that a small
/// per-block issuance over a large total stake does not floor to zero each
/// block, small enough that `stake * index` stays well inside `u128`.
pub const INDEX_SCALE: u128 = 1_000_000_000_000_000_000; // 1e18

/// Reward policy for an application that opts into implicit protocol rewards
/// (#659a). All-zero (the default) disables rewards — a tokenless / PoA chain
/// rewards nothing implicitly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RewardConfig {
    /// Protocol issuance minted per committed block, distributed
    /// stake-proportionally across the active set. `0` disables issuance.
    pub issuance_per_block: u64,
    /// Flat bonus credited to each block's proposer. `0` disables the bonus.
    pub proposer_bonus: u64,
}

impl RewardConfig {
    /// True if any reward source is enabled.
    pub fn is_enabled(&self) -> bool {
        self.issuance_per_block > 0 || self.proposer_bonus > 0
    }
}

/// Per-validator reward state for the F1 lazy-accrual scheme (#659a).
///
/// `index` is the global cumulative reward per unit of stake (scaled by
/// [`INDEX_SCALE`]). `last_index[v]` is the index value as of `v`'s last
/// settlement; its unsettled reward is `stake_v * (index - last_index[v])`.
/// `balance[v]` is reward already settled to `v`'s recipient.
#[derive(Debug, Default, Clone)]
pub struct RewardLedger {
    index: u128,
    last_index: BTreeMap<NodeId, u128>,
    balance: BTreeMap<NodeId, u64>,
}

impl RewardLedger {
    /// A fresh ledger with a zero index and no balances.
    pub fn new() -> Self {
        Self::default()
    }

    /// Accrue one block's stake-proportional `issuance` across the active set
    /// (whose total voting weight is `total_stake`) and credit `bonus` to the
    /// block `proposer`. O(1): bumps the global index and one balance.
    ///
    /// `issuance` is distributed by stake via the index — a validator's share
    /// materialises lazily at its next [`Self::settle`]. The proposer bonus is
    /// credited immediately (the proposer is a single identity, so it is cheap
    /// and need not wait for a staking event). Dust from the floor division is
    /// left undistributed (deterministic).
    pub fn accrue_block(&mut self, proposer: NodeId, issuance: u64, bonus: u64, total_stake: u64) {
        if total_stake > 0 && issuance > 0 {
            self.index += (u128::from(issuance) * INDEX_SCALE) / u128::from(total_stake);
        }
        if bonus > 0 {
            let b = self.balance.entry(proposer).or_default();
            *b = b.saturating_add(bonus);
        }
    }

    /// Settle `node_id`'s accrued stake-proportional reward into its balance,
    /// given its `stake` at this point, and snap its index. Call this **before**
    /// changing a validator's stake (so the accrual since its last settlement is
    /// computed against the stake it actually held), and to read out a balance.
    /// O(1) and idempotent if the index has not moved.
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

    /// Settled reward balance of `node_id` (does not include unsettled accrual
    /// — call [`Self::settle`] first to materialise that). 0 if none.
    pub fn balance_of(&self, node_id: &NodeId) -> u64 {
        self.balance.get(node_id).copied().unwrap_or(0)
    }

    /// Total claimable reward of `node_id` at `stake` — settled balance plus the
    /// not-yet-settled accrual — without mutating the ledger. For reads / tests.
    pub fn claimable(&self, node_id: &NodeId, stake: u64) -> u64 {
        let last = self.last_index.get(node_id).copied().unwrap_or(0);
        let unsettled = if self.index > last && stake > 0 {
            ((u128::from(stake) * (self.index - last)) / INDEX_SCALE) as u64
        } else {
            0
        };
        self.balance_of(node_id).saturating_add(unsettled)
    }

    /// The current global reward index (scaled by [`INDEX_SCALE`]). Exposed for
    /// diagnostics / tests.
    pub fn index(&self) -> u128 {
        self.index
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    #[test]
    fn stake_proportional_accrual_settles_by_share() {
        // Two validators, stakes 3 and 1 (total 4). Issue 8/block for 1 block.
        let mut r = RewardLedger::new();
        r.accrue_block(nid(9), 8, 0, 4);
        // Settle each against its stake: shares are 6 and 2.
        r.settle(nid(1), 3);
        r.settle(nid(2), 1);
        assert_eq!(r.balance_of(&nid(1)), 6);
        assert_eq!(r.balance_of(&nid(2)), 2);
    }

    #[test]
    fn proposer_bonus_is_credited_immediately() {
        let mut r = RewardLedger::new();
        r.accrue_block(nid(1), 0, 5, 10); // bonus only
        assert_eq!(r.balance_of(&nid(1)), 5, "bonus needs no settle");
    }

    #[test]
    fn accrual_is_lazy_settling_late_yields_the_same_total() {
        // Accrue many blocks, then settle once — same as settling each block.
        let mut lazy = RewardLedger::new();
        let mut eager = RewardLedger::new();
        for _ in 0..100 {
            lazy.accrue_block(nid(9), 4, 0, 2);
            eager.accrue_block(nid(9), 4, 0, 2);
            eager.settle(nid(1), 2);
        }
        lazy.settle(nid(1), 2);
        assert_eq!(lazy.balance_of(&nid(1)), eager.balance_of(&nid(1)));
        assert_eq!(lazy.balance_of(&nid(1)), 100 * 4); // sole staker gets all
    }

    #[test]
    fn settle_before_a_stake_change_uses_the_old_stake() {
        // F1 correctness: a validator that unbonds mid-stream earns on the
        // stake it actually held for each accrual window.
        let mut r = RewardLedger::new();
        r.accrue_block(nid(9), 10, 0, 10); // v1 holds 10 of 10
        r.settle(nid(1), 10); // settle the first window at the old stake
        assert_eq!(r.balance_of(&nid(1)), 10);
        // v1's stake drops to 2 (of a new total 2); next block it earns on 2.
        r.accrue_block(nid(9), 10, 0, 2);
        r.settle(nid(1), 2);
        assert_eq!(r.balance_of(&nid(1)), 20);
    }

    #[test]
    fn zero_total_stake_accrues_nothing() {
        let mut r = RewardLedger::new();
        r.accrue_block(nid(9), 100, 0, 0); // empty set
        r.settle(nid(1), 5);
        assert_eq!(r.balance_of(&nid(1)), 0);
        assert_eq!(r.index(), 0);
    }
}
