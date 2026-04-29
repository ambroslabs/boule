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
use crate::consensus::validator_history::ValidatorSetHistory;
use crate::consensus::validator_set::ValidatorSet;
use crate::p2p::NodeId;

/// Maps a [`View`] to the proposer for that view.
///
/// Implementations hold their own reference to the validator history; the
/// trait intentionally does not take it as a parameter, so callers
/// (notably the `Pacemaker` state machine) don't have to thread it
/// through every event.
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

/// Rotates through the [`ValidatorSet`] authoritative at `view`,
/// looked up via [`ValidatorSetHistory::set_at`]:
/// `set_at(view)[view % set_at(view).len()]`.
///
/// On either side of a reconfiguration boundary the rotation runs over
/// the corresponding committee — leaders before `v_eff` come from the
/// pre-boundary set, leaders at or after `v_eff` come from the post-
/// boundary set. Until #272 lands the commit-time application path the
/// history holds only the genesis boundary, so this matches the prior
/// single-set rotation exactly.
#[derive(Debug, Clone)]
pub struct RoundRobinSelector {
    history: Arc<ValidatorSetHistory>,
}

impl RoundRobinSelector {
    /// Build a selector backed by `history`. Panics if any boundary's
    /// set is empty — a pacemaker with no validators cannot make
    /// progress, and silently returning a zero [`NodeId`] would be a
    /// subtle footgun.
    pub fn new(history: Arc<ValidatorSetHistory>) -> Self {
        for (v_eff, set) in history.iter() {
            assert!(
                !set.is_empty(),
                "RoundRobinSelector: boundary at view {v_eff} has no validators"
            );
        }
        Self { history }
    }

    /// Convenience constructor for callers that still hold a single
    /// `Arc<ValidatorSet>` (no reconfiguration history). Equivalent to
    /// `Self::new(Arc::new(ValidatorSetHistory::from_genesis((*set).clone())))`.
    pub fn from_genesis_set(set: Arc<ValidatorSet>) -> Self {
        let history = Arc::new(ValidatorSetHistory::from_genesis((*set).clone()));
        Self::new(history)
    }
}

impl LeaderSelector for RoundRobinSelector {
    fn leader_for_view(&self, view: View) -> NodeId {
        let vs = self.history.set_at(view);
        // `view % len as u64` before narrowing to usize so the rotation
        // is identical on 32- and 64-bit platforms.
        let idx = (view % vs.len() as u64) as usize;
        // Round-robin returns the wire-form `NodeId` for the leader;
        // the bytes are the validator's stable id (#328 keeps the
        // bytes reusable across the typestate boundary).
        vs.get(idx)
            .expect("modulo of non-zero length is always in bounds")
            .into_node_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn vid(b: u8) -> crate::consensus::validator_set::ValidatorId {
        crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(nid(b))
    }

    fn sel(ids: Vec<NodeId>) -> RoundRobinSelector {
        let vids: Vec<_> = ids
            .into_iter()
            .map(crate::consensus::validator_set::ValidatorId::from_genesis_pubkey)
            .collect();
        RoundRobinSelector::from_genesis_set(Arc::new(ValidatorSet::new(vids)))
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
    #[should_panic(expected = "no validators")]
    fn empty_validator_set_panics() {
        let _ = RoundRobinSelector::from_genesis_set(Arc::new(ValidatorSet::new(vec![])));
    }

    // ── #271: leader rotation across a reconfiguration boundary ──────

    /// With a synthetic boundary at view `v_eff`, the round-robin index
    /// is computed against the set authoritative at each view: leaders
    /// before `v_eff` come from the old set, leaders at or after `v_eff`
    /// come from the new set.
    #[test]
    fn rotation_picks_pre_boundary_set_before_v_eff_and_post_at_or_after() {
        let old_set = ValidatorSet::new(vec![vid(1), vid(2), vid(3), vid(4)]);
        let new_set = ValidatorSet::new(vec![vid(10), vid(20), vid(30)]);
        let v_eff: View = 7;

        let mut history = ValidatorSetHistory::from_genesis(old_set.clone());
        history.insert_boundary(v_eff, new_set.clone()).unwrap();
        let s = RoundRobinSelector::new(Arc::new(history));

        // Pre-boundary leaders are the old set: idx = view % 4.
        for v in [0u64, 1, 2, 3, 4, 5, 6] {
            let expected = old_set.get((v % 4) as usize).unwrap().into_node_id();
            assert_eq!(s.leader_for_view(v), expected, "pre-boundary leader at {v}");
        }
        // At and beyond v_eff the new set rotates: idx = view % 3.
        for v in [7u64, 8, 9, 10, 11] {
            let expected = new_set.get((v % 3) as usize).unwrap().into_node_id();
            assert_eq!(
                s.leader_for_view(v),
                expected,
                "post-boundary leader at {v}",
            );
        }
    }

    /// A boundary that arrives at view 0 (i.e. the genesis "boundary")
    /// continues to drive the rotation even as later boundaries are
    /// stacked on top. Two consecutive boundaries: leaders advance
    /// through three regimes in order.
    #[test]
    fn multiple_boundaries_drive_rotation_through_each_regime() {
        let g = ValidatorSet::new(vec![vid(1), vid(2)]);
        let mid = ValidatorSet::new(vec![vid(3), vid(4), vid(5)]);
        let post = ValidatorSet::new(vec![vid(6), vid(7), vid(8), vid(9)]);

        let mut history = ValidatorSetHistory::from_genesis(g.clone());
        history.insert_boundary(5, mid.clone()).unwrap();
        history.insert_boundary(11, post.clone()).unwrap();
        let s = RoundRobinSelector::new(Arc::new(history));

        // Regime 1: views 0..=4 over the genesis set (size 2).
        assert_eq!(s.leader_for_view(0), g.get(0).unwrap().into_node_id());
        assert_eq!(s.leader_for_view(1), g.get(1).unwrap().into_node_id());
        assert_eq!(s.leader_for_view(4), g.get(0).unwrap().into_node_id());

        // Regime 2: views 5..=10 over the mid set (size 3).
        assert_eq!(s.leader_for_view(5), mid.get(2).unwrap().into_node_id()); // 5 % 3 = 2
        assert_eq!(s.leader_for_view(6), mid.get(0).unwrap().into_node_id()); // 6 % 3 = 0
        assert_eq!(s.leader_for_view(10), mid.get(1).unwrap().into_node_id()); // 10 % 3 = 1

        // Regime 3: views 11.. over the post set (size 4).
        assert_eq!(s.leader_for_view(11), post.get(3).unwrap().into_node_id()); // 11 % 4 = 3
        assert_eq!(s.leader_for_view(12), post.get(0).unwrap().into_node_id()); // 12 % 4 = 0
    }
}
