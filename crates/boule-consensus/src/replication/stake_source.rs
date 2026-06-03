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

use crate::Height;
use crate::replication::application::ValidatorUpdate;

/// Heights a withdrawn (unbonding) stake stays locked and slashable before it
/// is released (#660).
///
/// An equivocation at height `H` is only provable while some honest node still
/// retains the conflicting envelopes (256 views — see the node's
/// `EVIDENCE_RETENTION_VIEWS`), plus the gossip + three-chain commit latency
/// for the resulting evidence to land. A validator must therefore stay
/// slashable for at least that window after it stops participating, or it could
/// equivocate and immediately withdraw to dodge the penalty (the anti-post-slash
/// -exit property). This delay is comfortably above that window; views ≥ heights,
/// so a height-denominated bound is conservative.
pub const UNBONDING_DELAY: Height = Height(512);

/// A stake operation against a validator's bonded balance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StakeOp {
    /// Add `amount` to the validator's bonded stake.
    Bond { amount: u64 },
    /// Begin unbonding up to `amount` of the validator's bonded stake,
    /// saturating at the bonded balance. The amount stops counting toward
    /// voting weight immediately (a full unbond removes the validator), but
    /// stays locked and **slashable** for [`UNBONDING_DELAY`] before it is
    /// released — so a validator cannot withdraw to escape a pending slash
    /// (#660).
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

    /// Advance the source's notion of the committed height to `height`,
    /// releasing any unbonding stake that has matured (#660). Called once per
    /// commit, before [`Self::apply`], so an [`StakeOp::Unbond`] this block
    /// schedules its release relative to the current height, and matured
    /// withdrawals are freed (and no longer slashable). Releasing emits no
    /// [`ValidatorUpdate`] — voting weight already dropped when unbonding began.
    /// The default is a no-op for a source without an unbonding period.
    fn advance_to_height(&mut self, _height: Height) {}

    /// Active (weight-bearing) bonded stake of `node_id`, or 0. Reward accrual
    /// (#659a) reads this to settle a validator at its current stake before a
    /// stake change. Default 0 for a source that does not expose balances.
    fn stake_of(&self, _node_id: &NodeId) -> u64 {
        0
    }

    /// Total active bonded stake across the set — the denominator for
    /// stake-proportional reward accrual (#659a). Default 0.
    fn total_stake(&self) -> u64 {
        0
    }

    /// Slash `node_id`'s entire bonded stake — the punitive zeroing applied on
    /// committed equivocation evidence (#658b), distinct in intent from a
    /// voluntary [`StakeOp::Unbond`]. Emits a `weight 0` [`ValidatorUpdate`]
    /// (drained by the next [`Self::take_updates`]), keeping the stake ledger
    /// consistent with the membership jail (#658a) and burning the equivocator's
    /// bonded capital. The default zeroes the balance via an unbond of the full
    /// amount; a source with real custody would forfeit rather than return it.
    fn slash(&mut self, node_id: NodeId) {
        self.apply(node_id, StakeOp::Unbond { amount: u64::MAX });
    }
}

/// One in-flight unbonding: `amount` stake locked until `mature_at`, still
/// slashable in the meantime (#660).
#[derive(Debug, Clone, Copy)]
struct Unbonding {
    amount: u64,
    mature_at: Height,
}

/// CL-native [`StakeSource`]: an in-process ledger mapping each validator
/// to its bonded stake, with voting weight equal to that stake (a 1:1 toy
/// model — a richer source would map a balance to a weight curve).
///
/// Seeded from the genesis weighted set so unbonding a genesis validator
/// produces the correct delta. A change emits a [`ValidatorUpdate`] only
/// when the resulting weight actually differs, so a no-op operation (bond
/// 0, or unbond from an already-zero balance) accrues nothing.
///
/// Unbonding (#660): an [`StakeOp::Unbond`] moves stake out of the active
/// (weight-bearing) balance immediately but into a per-validator unbonding
/// queue, where it stays **slashable** until [`UNBONDING_DELAY`] elapses
/// (tracked against the committed height fed by [`StakeSource::advance_to_height`]).
pub struct BondedStakeLedger {
    /// Active bonded stake (== voting weight) per validator; a validator
    /// with zero active stake is absent.
    stake: BTreeMap<NodeId, u64>,
    /// In-flight unbonding amounts per validator: no longer weight-bearing,
    /// not yet released, still slashable until `mature_at`.
    unbonding: BTreeMap<NodeId, Vec<Unbonding>>,
    /// Latest committed height seen via [`StakeSource::advance_to_height`];
    /// `Unbond` schedules release at `current_height + UNBONDING_DELAY`.
    current_height: Height,
    /// Updates accrued since the last [`StakeSource::take_updates`].
    pending: Vec<ValidatorUpdate>,
}

impl BondedStakeLedger {
    /// An empty ledger (no seated validators).
    pub fn empty() -> Self {
        Self {
            stake: BTreeMap::new(),
            unbonding: BTreeMap::new(),
            current_height: Height::ZERO,
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
            unbonding: BTreeMap::new(),
            current_height: Height::ZERO,
            pending: Vec::new(),
        }
    }

    /// Current active bonded stake (== weight) of `node_id`, or 0 if unseated.
    pub fn stake_of(&self, node_id: &NodeId) -> u64 {
        self.stake.get(node_id).copied().unwrap_or(0)
    }

    /// Total stake still locked in unbonding for `node_id` (slashable, not
    /// weight-bearing). 0 if none.
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
                    return; // bond 0: nothing changes.
                }
                self.stake.insert(node_id, next);
                self.pending.push(ValidatorUpdate {
                    node_id,
                    weight: next,
                });
            }
            StakeOp::Unbond { amount } => {
                // Move up to `amount` out of the active (weight-bearing)
                // balance and into the unbonding queue, where it stays
                // slashable until it matures.
                let moved = amount.min(cur);
                if moved == 0 {
                    return; // nothing bonded to unbond.
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
        // Release matured unbondings — they leave the slashable set with no
        // weight effect (weight already dropped when unbonding began).
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
        // Burn everything: the active (weight-bearing) balance *and* any
        // in-flight unbonding — so a validator cannot escape the penalty by
        // withdrawing just before its evidence commits (#660). Distinct from
        // an `Unbond`, which only *moves* active stake into the (still
        // slashable) unbonding queue, so the trait default is wrong here.
        let had_active = self.stake.remove(&node_id).unwrap_or(0);
        self.unbonding.remove(&node_id);
        if had_active > 0 {
            // Weight already 0 if the validator had fully unbonded; only emit
            // the removal delta when active weight actually changes.
            self.pending.push(ValidatorUpdate { node_id, weight: 0 });
        }
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

    #[test]
    fn slash_zeroes_the_stake_and_emits_a_removal() {
        // #658b: slashing burns the entire bonded balance regardless of size,
        // emitting the weight-0 removal signal.
        let mut l = BondedStakeLedger::seeded_from([([6u8; 32], 1_000)]);
        l.slash([6u8; 32]);
        assert_eq!(l.stake_of(&[6u8; 32]), 0);
        let u = l.take_updates();
        assert_eq!(u.len(), 1);
        assert_eq!(u[0].node_id, [6u8; 32]);
        assert_eq!(u[0].weight, 0);
    }

    #[test]
    fn slash_of_an_unstaked_validator_is_a_no_op() {
        let mut l = BondedStakeLedger::seeded_from([([7u8; 32], 5)]);
        l.slash([8u8; 32]); // never staked
        assert!(l.take_updates().is_empty());
    }

    #[test]
    fn unbond_drops_weight_now_but_locks_stake_until_it_matures() {
        // #660: unbonding moves stake out of weight immediately but keeps it
        // locked (slashable) until UNBONDING_DELAY elapses.
        let mut l = BondedStakeLedger::seeded_from([([1u8; 32], 10)]);
        l.advance_to_height(Height(5));
        l.apply([1u8; 32], StakeOp::Unbond { amount: 4 });

        assert_eq!(l.stake_of(&[1u8; 32]), 6, "active weight drops immediately");
        assert_eq!(
            l.unbonding_of(&[1u8; 32]),
            4,
            "the rest is locked unbonding"
        );
        assert_eq!(
            l.take_updates(),
            vec![ValidatorUpdate {
                node_id: [1u8; 32],
                weight: 6
            }]
        );

        // mature_at = 5 + UNBONDING_DELAY; not released a height early.
        l.advance_to_height(
            Height(5)
                .saturating_add(UNBONDING_DELAY)
                .saturating_sub(Height(1)),
        );
        assert_eq!(
            l.unbonding_of(&[1u8; 32]),
            4,
            "still locked before maturity"
        );

        // Released at maturity — and releasing emits no weight delta.
        l.advance_to_height(Height(5).saturating_add(UNBONDING_DELAY));
        assert_eq!(l.unbonding_of(&[1u8; 32]), 0, "released after the delay");
        assert!(
            l.take_updates().is_empty(),
            "release is not a weight change"
        );
    }

    #[test]
    fn slash_during_unbonding_burns_the_locked_stake() {
        // #660 anti-dodge: a validator that fully unstakes is still slashable
        // until its unbonding matures, so evidence that commits in the window
        // burns the locked capital.
        let mut l = BondedStakeLedger::seeded_from([([2u8; 32], 10)]);
        l.advance_to_height(Height(1));
        l.apply([2u8; 32], StakeOp::Unbond { amount: 10 }); // full unstake
        let _ = l.take_updates();
        assert_eq!(l.stake_of(&[2u8; 32]), 0, "weight already 0");
        assert_eq!(
            l.unbonding_of(&[2u8; 32]),
            10,
            "but still locked + slashable"
        );

        l.slash([2u8; 32]);
        assert_eq!(
            l.unbonding_of(&[2u8; 32]),
            0,
            "slash burns the in-flight unbonding"
        );
        assert!(
            l.take_updates().is_empty(),
            "no weight delta — the validator's weight was already 0",
        );
    }

    #[test]
    fn matured_unbonding_is_no_longer_slashable() {
        // Once released, the stake has left the slashable set — a later slash
        // finds nothing (the window is bounded by UNBONDING_DELAY).
        let mut l = BondedStakeLedger::seeded_from([([3u8; 32], 10)]);
        l.advance_to_height(Height::ZERO);
        l.apply([3u8; 32], StakeOp::Unbond { amount: 10 });
        let _ = l.take_updates();
        l.advance_to_height(UNBONDING_DELAY); // mature
        assert_eq!(l.unbonding_of(&[3u8; 32]), 0);

        l.slash([3u8; 32]);
        assert!(
            l.take_updates().is_empty(),
            "nothing left to slash after release"
        );
    }
}
