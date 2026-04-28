//! Historical validator-set membership across reconfiguration boundaries
//! (#248).
//!
//! After validator-set reconfiguration (#140) lands, a single static
//! [`ValidatorSet`] is no longer enough: a QC at view `V` was signed by
//! whichever set was authoritative at view `V`, which may differ from the
//! set authoritative now. [`ValidatorSetHistory`] is the lookup table
//! that turns a view into the right set.
//!
//! This subtask is data-structure-only. The QC verification path (#249),
//! NewView verification (#250), and commit-time application (#253) are
//! the consumers; persistence across restarts is #254.
//!
//! # Invariants
//!
//! - The history always contains at least one boundary (the genesis set
//!   at `v_eff = 0`).
//! - Boundaries are stored in strictly increasing `v_eff` order.
//! - [`Self::set_at`] returns the rightmost boundary whose `v_eff <=
//!   view` — the set authoritative at that view.
//!
//! # Memory
//!
//! Each boundary holds an `Arc<ValidatorSet>`, so a `set_at` lookup is a
//! single `Arc::clone`. Validator sets are tiny (tens of [`NodeId`]s),
//! so storing one full set per boundary is cheaper than diff-decoding on
//! every lookup; the diff form will be derived on demand by the
//! persistence layer (#254).

use std::sync::Arc;

use crate::consensus::View;
use crate::consensus::validator_set::ValidatorSet;

/// One boundary in the history: the view at which `set` becomes
/// authoritative, and the set itself.
#[derive(Debug, Clone)]
struct Boundary {
    v_eff: View,
    set: Arc<ValidatorSet>,
}

/// Validator-set membership keyed by view.
///
/// Construct with [`Self::from_genesis`]; insert a boundary for every
/// committed reconfiguration with [`Self::insert_boundary`]; look up the
/// authoritative set for any view with [`Self::set_at`].
#[derive(Debug, Clone)]
pub struct ValidatorSetHistory {
    /// Sorted by `v_eff` ascending. Index 0 is always the genesis entry
    /// (`v_eff = 0`); the vector is never empty.
    boundaries: Vec<Boundary>,
}

impl ValidatorSetHistory {
    /// Build a history seeded with the genesis validator set. The genesis
    /// boundary is anchored at `v_eff = 0`, matching
    /// [`crate::replication::Block::genesis`].
    pub fn from_genesis(genesis: ValidatorSet) -> Self {
        Self {
            boundaries: vec![Boundary {
                v_eff: 0,
                set: Arc::new(genesis),
            }],
        }
    }

    /// Return the validator set authoritative at `view`.
    ///
    /// For any `view < boundaries[i].v_eff`, the answer is the boundary
    /// at index `i - 1`. The genesis boundary is at view 0, so this
    /// always finds a valid set.
    pub fn set_at(&self, view: View) -> Arc<ValidatorSet> {
        let idx = match self.boundaries.binary_search_by_key(&view, |b| b.v_eff) {
            Ok(i) => i,
            // `Err(i)` is the insertion index; the boundary in effect at
            // `view` is the one immediately before it. `i` is at least 1
            // here because the genesis boundary at `v_eff = 0` would have
            // matched any view-0 lookup as Ok(0).
            Err(i) => i.saturating_sub(1),
        };
        self.boundaries[idx].set.clone()
    }

    /// Append a new boundary at `v_eff`. Returns an error if `v_eff` is
    /// not strictly greater than the latest boundary's `v_eff`.
    ///
    /// Validation of the underlying [`crate::consensus::reconfig::ReconfigCommand`]
    /// (floor, overlap, current-membership rules) is the caller's
    /// responsibility — this method only enforces the per-history
    /// monotonicity invariant.
    pub fn insert_boundary(&mut self, v_eff: View, set: ValidatorSet) -> anyhow::Result<()> {
        let last = self
            .boundaries
            .last()
            .expect("history is non-empty by invariant");
        if v_eff <= last.v_eff {
            anyhow::bail!(
                "boundary v_eff {} must be strictly greater than latest v_eff {}",
                v_eff,
                last.v_eff
            );
        }
        self.boundaries.push(Boundary {
            v_eff,
            set: Arc::new(set),
        });
        Ok(())
    }

    /// The most recently inserted set — equivalent to `set_at(View::MAX)`
    /// but avoids the binary search.
    pub fn current_set(&self) -> Arc<ValidatorSet> {
        self.boundaries
            .last()
            .expect("history is non-empty by invariant")
            .set
            .clone()
    }

    /// Number of boundaries, including genesis.
    pub fn boundary_count(&self) -> usize {
        self.boundaries.len()
    }

    /// Iterate boundaries in chronological order: `(v_eff, &set)`.
    /// Intended for persistence (#254) and operator-facing introspection.
    pub fn iter(&self) -> impl Iterator<Item = (View, &Arc<ValidatorSet>)> {
        self.boundaries.iter().map(|b| (b.v_eff, &b.set))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::NodeId;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn genesis() -> ValidatorSet {
        ValidatorSet::new(vec![nid(1), nid(2), nid(3), nid(4)])
    }

    fn five() -> ValidatorSet {
        ValidatorSet::new(vec![nid(1), nid(2), nid(3), nid(4), nid(5)])
    }

    fn six() -> ValidatorSet {
        ValidatorSet::new(vec![nid(1), nid(2), nid(3), nid(4), nid(5), nid(6)])
    }

    #[test]
    fn genesis_only_returns_genesis_for_any_view() {
        let h = ValidatorSetHistory::from_genesis(genesis());
        assert_eq!(*h.set_at(0), genesis());
        assert_eq!(*h.set_at(1), genesis());
        assert_eq!(*h.set_at(1_000_000), genesis());
        assert_eq!(*h.set_at(View::MAX), genesis());
        assert_eq!(h.boundary_count(), 1);
    }

    #[test]
    fn boundary_lookup_partitions_views_correctly() {
        let mut h = ValidatorSetHistory::from_genesis(genesis());
        h.insert_boundary(10, five()).unwrap();

        // Genesis governs `view < 10`.
        assert_eq!(*h.set_at(0), genesis());
        assert_eq!(*h.set_at(9), genesis());
        // The new boundary takes effect at exactly `v_eff`.
        assert_eq!(*h.set_at(10), five());
        // ...and persists for all later views until another boundary.
        assert_eq!(*h.set_at(11), five());
        assert_eq!(*h.set_at(View::MAX), five());

        assert_eq!(*h.current_set(), five());
        assert_eq!(h.boundary_count(), 2);
    }

    #[test]
    fn multiple_boundaries_stack() {
        let mut h = ValidatorSetHistory::from_genesis(genesis());
        h.insert_boundary(10, five()).unwrap();
        h.insert_boundary(20, six()).unwrap();

        // Each window picks the right set.
        assert_eq!(*h.set_at(0), genesis());
        assert_eq!(*h.set_at(9), genesis());
        assert_eq!(*h.set_at(10), five());
        assert_eq!(*h.set_at(19), five());
        assert_eq!(*h.set_at(20), six());
        assert_eq!(*h.set_at(99), six());

        assert_eq!(h.boundary_count(), 3);
        assert_eq!(*h.current_set(), six());
    }

    #[test]
    fn insert_boundary_rejects_non_increasing_v_eff() {
        let mut h = ValidatorSetHistory::from_genesis(genesis());
        h.insert_boundary(10, five()).unwrap();

        // Equal to latest is rejected.
        let err = h.insert_boundary(10, six()).unwrap_err();
        assert!(err.to_string().contains("strictly greater"));
        // Below latest is rejected.
        let err = h.insert_boundary(5, six()).unwrap_err();
        assert!(err.to_string().contains("strictly greater"));
        // Below genesis is rejected.
        let mut h2 = ValidatorSetHistory::from_genesis(genesis());
        let err = h2.insert_boundary(0, five()).unwrap_err();
        assert!(err.to_string().contains("strictly greater"));

        // History unchanged after each rejection.
        assert_eq!(h.boundary_count(), 2);
        assert_eq!(*h.current_set(), five());
    }

    #[test]
    fn set_at_returns_arc_to_internal_storage() {
        // The Arc returned by set_at and the Arc held in the history
        // should reference the same allocation, so callers don't pay a
        // deep copy on hot paths.
        let mut h = ValidatorSetHistory::from_genesis(genesis());
        h.insert_boundary(10, five()).unwrap();
        let a = h.set_at(15);
        let b = h.set_at(15);
        assert!(Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn iter_yields_boundaries_in_order() {
        let mut h = ValidatorSetHistory::from_genesis(genesis());
        h.insert_boundary(10, five()).unwrap();
        h.insert_boundary(20, six()).unwrap();

        let collected: Vec<(View, ValidatorSet)> =
            h.iter().map(|(v, s)| (v, (**s).clone())).collect();
        assert_eq!(collected, vec![(0, genesis()), (10, five()), (20, six())]);
    }
}
