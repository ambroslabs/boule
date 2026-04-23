//! The ordered, deduplicated committee that participates in consensus.
//!
//! A [`ValidatorSet`] is the identity of a consensus committee: two sets
//! over the same underlying [`NodeId`]s have byte-identical representation
//! because [`ValidatorSet::new`] sorts and deduplicates on construction.
//! This invariant lets selectors like
//! [`super::pacemaker::leader::RoundRobinSelector`] rely on stable indexing
//! (`validators[view % len]`) — every honest replica picks the same
//! leader for a given view.
//!
//! # Scope
//!
//! This type is deliberately minimal. Milestone 7 (#23) will extend it
//! with `quorum_size()` / `f()` helpers once the safety core needs them;
//! dynamic validator-set churn is out of scope for both #22 and #23 per
//! their non-goals sections.

use std::sync::Arc;

use crate::p2p::NodeId;

/// An ordered, deduplicated set of [`NodeId`]s.
///
/// Members are sorted ascending (byte-lexicographic over `NodeId`) and
/// contain no duplicates. Clone is zero-cost — the set is `Arc`-backed —
/// so callers can hold `Arc<ValidatorSet>` on hot paths without copying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorSet {
    members: Arc<[NodeId]>,
}

impl ValidatorSet {
    /// Construct a validator set from `members`, sorting ascending and
    /// removing duplicates. Two calls with the same underlying nodes in
    /// different input orders produce equal sets.
    pub fn new(mut members: Vec<NodeId>) -> Self {
        members.sort_unstable();
        members.dedup();
        Self {
            members: members.into(),
        }
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    pub fn get(&self, idx: usize) -> Option<&NodeId> {
        self.members.get(idx)
    }

    pub fn contains(&self, id: &NodeId) -> bool {
        self.members.binary_search(id).is_ok()
    }

    pub fn index_of(&self, id: &NodeId) -> Option<usize> {
        self.members.binary_search(id).ok()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, NodeId> {
        self.members.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    #[test]
    fn new_sorts_and_dedups() {
        let v = ValidatorSet::new(vec![nid(3), nid(1), nid(2), nid(1)]);
        assert_eq!(v.len(), 3);
        assert_eq!(v.get(0), Some(&nid(1)));
        assert_eq!(v.get(1), Some(&nid(2)));
        assert_eq!(v.get(2), Some(&nid(3)));
    }

    #[test]
    fn equal_sets_from_different_input_orders() {
        let a = ValidatorSet::new(vec![nid(3), nid(1), nid(2)]);
        let b = ValidatorSet::new(vec![nid(1), nid(2), nid(3)]);
        assert_eq!(a, b);
    }

    #[test]
    fn empty_set() {
        let v = ValidatorSet::new(vec![]);
        assert!(v.is_empty());
        assert_eq!(v.len(), 0);
        assert_eq!(v.get(0), None);
        assert!(!v.contains(&nid(0)));
        assert_eq!(v.index_of(&nid(0)), None);
    }

    #[test]
    fn contains_and_index_of_are_consistent() {
        let v = ValidatorSet::new(vec![nid(10), nid(20), nid(30)]);
        for i in 0..v.len() {
            let m = v.get(i).unwrap();
            assert!(v.contains(m));
            assert_eq!(v.index_of(m), Some(i));
        }
        assert!(!v.contains(&nid(99)));
        assert_eq!(v.index_of(&nid(99)), None);
    }

    #[test]
    fn iter_yields_sorted_order() {
        let v = ValidatorSet::new(vec![nid(5), nid(2), nid(8)]);
        let collected: Vec<_> = v.iter().copied().collect();
        assert_eq!(collected, vec![nid(2), nid(5), nid(8)]);
    }
}
