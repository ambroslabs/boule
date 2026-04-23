//! Pluggable leader selection for the HotStuff pacemaker.
//!
//! A [`LeaderSelector`] maps a [`View`] to the [`NodeId`] that is
//! responsible for proposing in that view. The default
//! [`RoundRobinSelector`] rotates through the [`ValidatorSet`] in sort
//! order — sufficient for baseline HotStuff and for all of #22's
//! verification criteria. Stake-weighted or reputation-based selectors
//! land as additional implementations behind the same trait.

use std::sync::Arc;

use crate::consensus::View;
use crate::consensus::validator_set::ValidatorSet;
use crate::p2p::NodeId;

/// Maps a [`View`] to the proposer for that view.
///
/// Implementations hold their own reference to the [`ValidatorSet`]; the
/// trait intentionally does not take it as a parameter, so callers
/// (notably the `Pacemaker` state machine) don't have to thread it
/// through every event. Dynamic validator-set churn is out of scope for
/// #22.
///
/// # Contract
///
/// - Determinism: `leader_for_view(v)` returns the same [`NodeId`] on
///   every call and every replica. Anything else breaks HotStuff.
/// - Totality: every view yields a leader. A selector that can't decide
///   for some view must either define a fallback or panic at construction.
pub trait LeaderSelector: Send + Sync {
    fn leader_for_view(&self, view: View) -> NodeId;
}

/// Rotates through the [`ValidatorSet`] in sort order:
/// `validators[view % validators.len()]`.
#[derive(Debug, Clone)]
pub struct RoundRobinSelector {
    validators: Arc<ValidatorSet>,
}

impl RoundRobinSelector {
    /// Panics if `validators` is empty — a pacemaker with no validators
    /// cannot make progress, and silently returning a zero [`NodeId`]
    /// would be a subtle footgun.
    pub fn new(validators: Arc<ValidatorSet>) -> Self {
        assert!(
            !validators.is_empty(),
            "RoundRobinSelector requires at least one validator"
        );
        Self { validators }
    }
}

impl LeaderSelector for RoundRobinSelector {
    fn leader_for_view(&self, view: View) -> NodeId {
        // `view % len as u64` before narrowing to usize so the rotation
        // is identical on 32- and 64-bit platforms.
        let idx = (view % self.validators.len() as u64) as usize;
        *self
            .validators
            .get(idx)
            .expect("modulo of non-zero length is always in bounds")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn sel(ids: Vec<NodeId>) -> RoundRobinSelector {
        RoundRobinSelector::new(Arc::new(ValidatorSet::new(ids)))
    }

    #[test]
    fn rotation_covers_every_validator_in_sort_order() {
        let s = sel(vec![nid(4), nid(1), nid(3), nid(2)]);
        let leaders: Vec<_> = (0..4).map(|v| s.leader_for_view(v)).collect();
        assert_eq!(leaders, vec![nid(1), nid(2), nid(3), nid(4)]);
    }

    #[test]
    fn deterministic() {
        let s = sel(vec![nid(1), nid(2), nid(3)]);
        assert_eq!(s.leader_for_view(42), s.leader_for_view(42));
        assert_eq!(s.leader_for_view(1_000_000), s.leader_for_view(1_000_000));
    }

    #[test]
    fn wraps_around() {
        let s = sel(vec![nid(1), nid(2), nid(3)]);
        for v in 0..9 {
            assert_eq!(s.leader_for_view(v), s.leader_for_view(v + 3));
        }
    }

    #[test]
    fn large_view_matches_modular_arithmetic() {
        // Past `u32::MAX`, make sure the result still tracks `v % len`.
        // `u32::MAX = 4_294_967_295` is divisible by 3, so
        // `(u32::MAX + 7) % 3 == 1` — the selector should return index 1.
        let s = sel(vec![nid(1), nid(2), nid(3)]);
        let v = (u32::MAX as u64) + 7;
        assert_eq!(s.leader_for_view(v), nid(2));
    }

    #[test]
    #[should_panic(expected = "at least one validator")]
    fn empty_validator_set_panics() {
        let _ = RoundRobinSelector::new(Arc::new(ValidatorSet::new(vec![])));
    }
}
