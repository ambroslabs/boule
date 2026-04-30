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
//! # View tagging at the API boundary
//!
//! [`Self::set_at`] returns a [`ValidatorSetAt`], not a bare
//! `Arc<ValidatorSet>` — the wrapper carries the [`View`] the lookup
//! was scoped to and only releases the underlying set through
//! [`ValidatorSetAt::for_view`], which debug-asserts the consumer
//! passes the same view. A refactor that caches the result and reuses
//! it past a reconfiguration boundary in the same handler trips the
//! assertion in tests instead of silently using the wrong set
//! (audit finding 5-2, #414).
//!
//! # Memory
//!
//! Each boundary holds an `Arc<ValidatorSet>`, so a `set_at` lookup is a
//! single `Arc::clone`. Validator sets are tiny (tens of [`NodeId`]s),
//! so storing one full set per boundary is cheaper than diff-decoding on
//! every lookup; the diff form will be derived on demand by the
//! persistence layer (#254).

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::consensus::View;
use crate::consensus::validator_set::{ValidatorId, ValidatorSet};
use crate::p2p::NodeId;

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

    /// Return the validator set authoritative at `view`, view-tagged
    /// so consumers re-assert scope at use site (#414).
    ///
    /// For any `view < boundaries[i].v_eff`, the answer is the boundary
    /// at index `i - 1`. The genesis boundary is at view 0, so this
    /// always finds a valid set.
    pub fn set_at(&self, view: View) -> ValidatorSetAt {
        let idx = match self.boundaries.binary_search_by_key(&view, |b| b.v_eff) {
            Ok(i) => i,
            // `Err(i)` is the insertion index; the boundary in effect at
            // `view` is the one immediately before it. `i` is at least 1
            // here because the genesis boundary at `v_eff = 0` would have
            // matched any view-0 lookup as Ok(0).
            Err(i) => i.saturating_sub(1),
        };
        ValidatorSetAt {
            view,
            set: self.boundaries[idx].set.clone(),
        }
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

    /// Snapshot the history into a serializable wire form (#254). The
    /// genesis boundary at `v_eff = 0` is included so a fresh node can
    /// restore the full chain of committee changes from a single blob.
    pub fn to_persisted(&self) -> PersistedValidatorHistory {
        let boundaries: Vec<PersistedBoundary> = self
            .iter()
            .map(|(v_eff, set)| PersistedBoundary {
                v_eff,
                members: set.iter().map(|v| v.into_node_id()).collect(),
            })
            .collect();
        PersistedValidatorHistory { boundaries }
    }

    /// Rebuild a history from its persisted form (#254). The first
    /// boundary must be the genesis boundary at `v_eff = 0`; subsequent
    /// entries must be in strictly increasing `v_eff` order.
    ///
    /// Each persisted `NodeId` is promoted back to a [`ValidatorId`]
    /// via [`ValidatorId::from_genesis_pubkey`]. This is allowed at
    /// recovery time for the same reason it is allowed at genesis-load
    /// time: we are reconstructing state authored by an honest replica
    /// that already went through the legitimate seeding/reconfig paths.
    pub fn from_persisted(persisted: PersistedValidatorHistory) -> anyhow::Result<Self> {
        let mut iter = persisted.boundaries.into_iter();
        let genesis = iter
            .next()
            .ok_or_else(|| anyhow::anyhow!("persisted history is empty"))?;
        if genesis.v_eff != 0 {
            anyhow::bail!(
                "persisted history's first boundary must be at v_eff = 0, got {}",
                genesis.v_eff
            );
        }
        let genesis_members: Vec<ValidatorId> = genesis
            .members
            .into_iter()
            .map(ValidatorId::from_genesis_pubkey)
            .collect();
        let mut history = Self::from_genesis(ValidatorSet::new(genesis_members));
        for boundary in iter {
            let members: Vec<ValidatorId> = boundary
                .members
                .into_iter()
                .map(ValidatorId::from_genesis_pubkey)
                .collect();
            history.insert_boundary(boundary.v_eff, ValidatorSet::new(members))?;
        }
        Ok(history)
    }
}

/// View-tagged result of [`ValidatorSetHistory::set_at`].
///
/// The wrapper carries the [`View`] the lookup was scoped to and only
/// releases the underlying [`ValidatorSet`] through
/// [`Self::for_view`], which debug-asserts the caller passes the same
/// view. This makes a refactor that caches the result and reuses it
/// past a reconfiguration boundary in the same handler — say, a fast
/// path that reads `set_at(view)` once and uses it for subsequent
/// operations on a higher view — trip an assertion in tests instead
/// of silently using the wrong set (audit finding 5-2, #414).
///
/// Release builds drop the assertion and use the cached set, which
/// preserves current behavior under the (correct-today) assumption
/// that no caller misuses it.
#[derive(Debug, Clone)]
pub struct ValidatorSetAt {
    view: View,
    set: Arc<ValidatorSet>,
}

impl ValidatorSetAt {
    /// Borrow the validator set, asserting the consumer's `view`
    /// matches the view the wrapper was looked up for.
    ///
    /// In debug builds, a mismatch is a hard panic — the lookup view
    /// and the use-site view disagree, so the cached set is for the
    /// wrong reconfiguration window. Release builds skip the check
    /// and return the cached set as-is.
    pub fn for_view(&self, view: View) -> &ValidatorSet {
        debug_assert_eq!(
            self.view, view,
            "validator-set scope mismatch: looked up at view {}, used at view {}",
            self.view, view,
        );
        &self.set
    }

    /// The view the wrapper was looked up for.
    pub fn view(&self) -> View {
        self.view
    }
}

/// One boundary in the persisted (wire) form of a [`ValidatorSetHistory`].
///
/// `members` is the *full* member list at and after `v_eff`; the diff
/// against the previous boundary can be derived but isn't part of the
/// wire shape — the format trades a few extra bytes per boundary for
/// validation simplicity at recovery time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedBoundary {
    pub v_eff: View,
    pub members: Vec<NodeId>,
}

/// Serializable snapshot of a [`ValidatorSetHistory`] (#254). Encoded
/// via postcard at storage write time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedValidatorHistory {
    pub boundaries: Vec<PersistedBoundary>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::NodeId;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn vid(b: u8) -> ValidatorId {
        ValidatorId::from_genesis_pubkey(nid(b))
    }

    fn genesis() -> ValidatorSet {
        ValidatorSet::new(vec![vid(1), vid(2), vid(3), vid(4)])
    }

    fn five() -> ValidatorSet {
        ValidatorSet::new(vec![vid(1), vid(2), vid(3), vid(4), vid(5)])
    }

    fn six() -> ValidatorSet {
        ValidatorSet::new(vec![vid(1), vid(2), vid(3), vid(4), vid(5), vid(6)])
    }

    #[test]
    fn genesis_only_returns_genesis_for_any_view() {
        let h = ValidatorSetHistory::from_genesis(genesis());
        assert_eq!(*h.set_at(0).for_view(0), genesis());
        assert_eq!(*h.set_at(1).for_view(1), genesis());
        assert_eq!(*h.set_at(1_000_000).for_view(1_000_000), genesis());
        assert_eq!(*h.set_at(View::MAX).for_view(View::MAX), genesis());
        assert_eq!(h.boundary_count(), 1);
    }

    #[test]
    fn boundary_lookup_partitions_views_correctly() {
        let mut h = ValidatorSetHistory::from_genesis(genesis());
        h.insert_boundary(10, five()).unwrap();

        // Genesis governs `view < 10`.
        assert_eq!(*h.set_at(0).for_view(0), genesis());
        assert_eq!(*h.set_at(9).for_view(9), genesis());
        // The new boundary takes effect at exactly `v_eff`.
        assert_eq!(*h.set_at(10).for_view(10), five());
        // ...and persists for all later views until another boundary.
        assert_eq!(*h.set_at(11).for_view(11), five());
        assert_eq!(*h.set_at(View::MAX).for_view(View::MAX), five());

        assert_eq!(*h.current_set(), five());
        assert_eq!(h.boundary_count(), 2);
    }

    #[test]
    fn multiple_boundaries_stack() {
        let mut h = ValidatorSetHistory::from_genesis(genesis());
        h.insert_boundary(10, five()).unwrap();
        h.insert_boundary(20, six()).unwrap();

        // Each window picks the right set.
        assert_eq!(*h.set_at(0).for_view(0), genesis());
        assert_eq!(*h.set_at(9).for_view(9), genesis());
        assert_eq!(*h.set_at(10).for_view(10), five());
        assert_eq!(*h.set_at(19).for_view(19), five());
        assert_eq!(*h.set_at(20).for_view(20), six());
        assert_eq!(*h.set_at(99).for_view(99), six());

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
        // The Arc held inside the wrapper and the Arc held in the
        // history should reference the same allocation, so callers
        // don't pay a deep copy on hot paths.
        let mut h = ValidatorSetHistory::from_genesis(genesis());
        h.insert_boundary(10, five()).unwrap();
        let a = h.set_at(15);
        let b = h.set_at(15);
        assert!(Arc::ptr_eq(&a.set, &b.set));
    }

    #[test]
    fn set_at_carries_lookup_view() {
        let h = ValidatorSetHistory::from_genesis(genesis());
        let at = h.set_at(42);
        assert_eq!(at.view(), 42);
        // for_view at the same view returns the set unconditionally.
        assert_eq!(*at.for_view(42), genesis());
    }

    #[test]
    #[should_panic(expected = "validator-set scope mismatch")]
    fn for_view_panics_in_debug_when_consumer_view_differs() {
        let h = ValidatorSetHistory::from_genesis(genesis());
        let at = h.set_at(42);
        // Reusing a view-42 lookup at view 43 is the exact bug shape
        // #414 catches: a cached set used past a reconfig boundary.
        let _ = at.for_view(43);
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

    // ── #254: persistence round-trip ────────────────────────────────────

    #[test]
    fn round_trips_through_persisted_form() {
        let mut h = ValidatorSetHistory::from_genesis(genesis());
        h.insert_boundary(7, five()).unwrap();
        h.insert_boundary(15, six()).unwrap();

        let persisted = h.to_persisted();
        let bytes = postcard::to_stdvec(&persisted).unwrap();
        let decoded: PersistedValidatorHistory = postcard::from_bytes(&bytes).unwrap();
        let restored = ValidatorSetHistory::from_persisted(decoded).unwrap();

        assert_eq!(restored.boundary_count(), 3);
        assert_eq!(*restored.set_at(0).for_view(0), genesis());
        assert_eq!(*restored.set_at(7).for_view(7), five());
        assert_eq!(*restored.set_at(15).for_view(15), six());
        assert_eq!(*restored.current_set(), six());
    }

    #[test]
    fn from_persisted_rejects_empty_blob() {
        let empty = PersistedValidatorHistory { boundaries: vec![] };
        let err = ValidatorSetHistory::from_persisted(empty).unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn from_persisted_rejects_non_genesis_first_boundary() {
        let bad = PersistedValidatorHistory {
            boundaries: vec![PersistedBoundary {
                v_eff: 5,
                members: vec![nid(1), nid(2), nid(3), nid(4)],
            }],
        };
        let err = ValidatorSetHistory::from_persisted(bad).unwrap_err();
        assert!(err.to_string().contains("v_eff = 0"));
    }

    /// Wire format must be byte-identical to the pre-#328 shape: the
    /// `members` field of `PersistedBoundary` is a `Vec<NodeId>` of
    /// 32-byte arrays, and the `ValidatorId`-typed `ValidatorSet`
    /// flattens to the same bytes via `into_node_id()` on persist.
    #[test]
    fn persisted_boundary_wire_format_unchanged() {
        let h = ValidatorSetHistory::from_genesis(genesis());
        let persisted = h.to_persisted();
        let expected_members: Vec<NodeId> = vec![nid(1), nid(2), nid(3), nid(4)];
        assert_eq!(persisted.boundaries[0].members, expected_members);
    }

    #[test]
    fn from_persisted_rejects_non_monotone_v_eff() {
        let bad = PersistedValidatorHistory {
            boundaries: vec![
                PersistedBoundary {
                    v_eff: 0,
                    members: vec![nid(1), nid(2), nid(3), nid(4)],
                },
                PersistedBoundary {
                    v_eff: 10,
                    members: vec![nid(1), nid(2), nid(3), nid(4), nid(5)],
                },
                // Out-of-order: v_eff 5 < previous 10.
                PersistedBoundary {
                    v_eff: 5,
                    members: vec![nid(1), nid(2), nid(3), nid(4)],
                },
            ],
        };
        let err = ValidatorSetHistory::from_persisted(bad).unwrap_err();
        assert!(err.to_string().contains("strictly greater"));
    }
}
