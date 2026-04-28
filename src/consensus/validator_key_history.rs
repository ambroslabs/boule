//! Per-validator consensus-key history (#259, part 1).
//!
//! [`ValidatorKeyHistory`] records, for each validator, every consensus
//! signing key it has used over time and the view at which each key
//! became effective. It is the building block the eventual
//! verification-path threading sits on:
//!
//! - A vote/QC at view `V` signed by pubkey `K` is valid only if
//!   `K == key_at(V)` for some validator. The lookup goes through this
//!   type.
//! - Spanning votes (late votes for older views) verify against the key
//!   that was active *at that older view*, not the validator's current
//!   key — so old QCs remain verifiable forever even after rotations.
//!
//! # Scope of this module
//!
//! Pure data structure plus the [`ValidatorKeyHistory::apply_rotation`]
//! mutator. Threading the lookup through the existing vote, proposal,
//! and QC verification paths in `consensus::dispatch` and
//! `consensus::hotstuff` is the second half of #259 — it waits for #140
//! to land per-view validator-set history, since the verification call
//! sites need both pieces of information together (which validators are
//! in the set at view V *and* what key each one is using). Persisting
//! the history across restarts is also out of scope here.
//!
//! # Identifying a validator across rotations
//!
//! In the absence of a dedicated stable-address layer (gated on #140),
//! this module uses the validator's *genesis pubkey* — the key it was
//! initialized with when [`ValidatorKeyHistory::new`] was called — as
//! its stable identifier. Every later pubkey the validator rotates
//! through is recorded in the per-validator history list and indexed in
//! a reverse map so a lookup by *any* pubkey the validator has ever
//! used resolves to the same stable identifier. When #140 introduces a
//! richer address type, this module can keep its current shape; only
//! the type of the stable identifier changes.

use std::collections::BTreeMap;

use crate::consensus::View;
use crate::consensus::validator_rotation::{RotationStructuralError, ValidatorKeyRotation};
use crate::p2p::NodeId;

/// One entry in a validator's key history: at view `v_eff` the validator
/// began signing with `pubkey`. The list of entries for a single
/// validator is stored sorted by `v_eff` (monotonic increasing), with
/// the genesis entry always at index 0 with `v_eff = 0`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct KeyEntry {
    v_eff: View,
    pubkey: NodeId,
}

/// Per-validator history of consensus signing keys over time.
///
/// The internal stable identifier for each validator is its genesis
/// pubkey. See the module docstring for why.
#[derive(Debug, Clone, Default)]
pub struct ValidatorKeyHistory {
    by_stable_id: BTreeMap<NodeId, Vec<KeyEntry>>,
    pubkey_to_stable_id: BTreeMap<NodeId, NodeId>,
}

/// Reasons [`ValidatorKeyHistory::apply_rotation`] can reject a
/// committed rotation. These are post-commit validation failures —
/// the rotation already passed signature verification (#258) and made
/// it into a committed block, but the history rejects it because some
/// invariant of the per-validator key timeline would be violated.
#[derive(Debug, PartialEq, Eq)]
pub enum HistoryError {
    /// `rotation.validate_structural(commit_view)` failed; the rotation
    /// is malformed relative to the view it committed at.
    Structural(RotationStructuralError),
    /// `rotation.validator` is not a pubkey this history has ever seen,
    /// so the rotation refers to a validator that doesn't exist (or
    /// existed under a stable id that was never registered at genesis).
    UnknownValidator { validator: NodeId },
    /// `rotation.v_eff` is not strictly greater than the most recent
    /// entry for this validator. Two rotations with overlapping or
    /// equal `v_eff` would create an ambiguous key timeline at that
    /// view; rejecting non-monotonic `v_eff` keeps `key_at` total.
    VeffNotStrictlyIncreasing { last_v_eff: View, v_eff: View },
    /// `rotation.new_pubkey` is already in use by a *different*
    /// validator. Allowing key collisions would break the reverse
    /// index — a single pubkey would resolve to two stable ids — and
    /// in practice represents either an operator mistake or an attack.
    /// Rotating back to a key the same validator used previously is
    /// allowed (it's idempotent for the reverse index).
    NewKeyCollidesWithOtherValidator { new_pubkey: NodeId, owner: NodeId },
}

impl std::fmt::Display for HistoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Structural(e) => write!(f, "rotation structural validation failed: {e}"),
            Self::UnknownValidator { validator } => write!(
                f,
                "rotation references unknown validator pubkey {}",
                hex::encode(validator)
            ),
            Self::VeffNotStrictlyIncreasing { last_v_eff, v_eff } => write!(
                f,
                "rotation v_eff={v_eff} is not strictly greater than the validator's previous \
                 v_eff={last_v_eff}",
            ),
            Self::NewKeyCollidesWithOtherValidator { new_pubkey, owner } => write!(
                f,
                "rotation new_pubkey {} is already in use by validator {}",
                hex::encode(new_pubkey),
                hex::encode(owner),
            ),
        }
    }
}

impl std::error::Error for HistoryError {}

impl From<RotationStructuralError> for HistoryError {
    fn from(e: RotationStructuralError) -> Self {
        Self::Structural(e)
    }
}

impl ValidatorKeyHistory {
    /// Build a history seeded with each genesis validator's pubkey
    /// active from view 0. The supplied iterator may yield duplicates;
    /// they are deduplicated, matching `ValidatorSet`'s convention.
    pub fn new(genesis_validators: impl IntoIterator<Item = NodeId>) -> Self {
        let mut h = Self::default();
        for v in genesis_validators {
            // `or_insert_with` skips duplicates: a validator can't be
            // re-registered at genesis with a different history.
            h.by_stable_id.entry(v).or_insert_with(|| {
                vec![KeyEntry {
                    v_eff: 0,
                    pubkey: v,
                }]
            });
            h.pubkey_to_stable_id.insert(v, v);
        }
        h
    }

    /// The active signing key for the validator identified by
    /// `pubkey_anywhere_in_history`, evaluated as of view `view`.
    ///
    /// `pubkey_anywhere_in_history` may be the validator's *current*
    /// pubkey, its *genesis* pubkey, or any pubkey it has rotated
    /// through in the past — the reverse index resolves all of them to
    /// the same stable id, so the same answer comes back regardless of
    /// which one the caller has in hand.
    ///
    /// Returns `None` if the pubkey is not associated with any
    /// validator in this history.
    pub fn key_at(&self, pubkey_anywhere_in_history: &NodeId, view: View) -> Option<NodeId> {
        let stable_id = self.pubkey_to_stable_id.get(pubkey_anywhere_in_history)?;
        let entries = self.by_stable_id.get(stable_id)?;
        // Entries are sorted by v_eff ascending; the active key at
        // `view` is the one from the entry with the largest v_eff that
        // is still <= view. Binary search for the partition point.
        let idx = entries.partition_point(|e| e.v_eff <= view);
        if idx == 0 {
            // No entry with v_eff <= view — should be unreachable
            // because the genesis entry has v_eff = 0, but defensively
            // returning None keeps lookup total and panic-free.
            return None;
        }
        Some(entries[idx - 1].pubkey)
    }

    /// The validator's current (most recently effective) signing key
    /// regardless of view. Convenience wrapper over the latest entry —
    /// useful for code paths that don't have a view in hand, like an
    /// admission-time check that the rotation tx is signed by *the*
    /// current key.
    pub fn current_key(&self, pubkey_anywhere_in_history: &NodeId) -> Option<NodeId> {
        let stable_id = self.pubkey_to_stable_id.get(pubkey_anywhere_in_history)?;
        let entries = self.by_stable_id.get(stable_id)?;
        entries.last().map(|e| e.pubkey)
    }

    /// Iterate over the stable identifiers (genesis pubkeys) of every
    /// validator in this history, in stable byte-lexicographic order.
    pub fn validators(&self) -> impl Iterator<Item = &NodeId> {
        self.by_stable_id.keys()
    }

    /// Apply a rotation that has just been committed at `commit_view`.
    ///
    /// The rotation's signatures are *not* re-checked here — that's
    /// the caller's job (#258 covers the cryptographic verification);
    /// this method enforces the timeline invariants that make
    /// `key_at` total and unambiguous. Specifically:
    ///
    /// - The rotation must pass [`ValidatorKeyRotation::validate_structural`]
    ///   against `commit_view`.
    /// - `rotation.validator` must resolve to a known validator via the
    ///   reverse index. Since today the validator field carries the
    ///   active pubkey at sign time, this works for both
    ///   never-rotated validators (genesis pubkey) and previously
    ///   rotated validators (any prior key).
    /// - `rotation.v_eff` must be strictly greater than the validator's
    ///   most recently recorded `v_eff`.
    /// - `rotation.new_pubkey` must not already belong to a *different*
    ///   validator. Rotating back to a key the same validator used
    ///   before is allowed.
    pub fn apply_rotation(
        &mut self,
        rotation: &ValidatorKeyRotation,
        commit_view: View,
    ) -> Result<(), HistoryError> {
        rotation.validate_structural(commit_view)?;

        let stable_id = *self.pubkey_to_stable_id.get(&rotation.validator).ok_or(
            HistoryError::UnknownValidator {
                validator: rotation.validator,
            },
        )?;

        if let Some(owner) = self.pubkey_to_stable_id.get(&rotation.new_pubkey) {
            if *owner != stable_id {
                return Err(HistoryError::NewKeyCollidesWithOtherValidator {
                    new_pubkey: rotation.new_pubkey,
                    owner: *owner,
                });
            }
        }

        let entries = self
            .by_stable_id
            .get_mut(&stable_id)
            .expect("reverse index points to a stable_id with no history");
        let last_v_eff = entries.last().expect("history list is non-empty").v_eff;
        if rotation.v_eff <= last_v_eff {
            return Err(HistoryError::VeffNotStrictlyIncreasing {
                last_v_eff,
                v_eff: rotation.v_eff,
            });
        }

        entries.push(KeyEntry {
            v_eff: rotation.v_eff,
            pubkey: rotation.new_pubkey,
        });
        self.pubkey_to_stable_id
            .insert(rotation.new_pubkey, stable_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::validator_rotation::V_EFF_MIN_DELAY;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn rot(validator: NodeId, new_pubkey: NodeId, v_eff: View) -> ValidatorKeyRotation {
        ValidatorKeyRotation {
            validator,
            new_pubkey,
            v_eff,
        }
    }

    // ── construction ──────────────────────────────────────────────────────

    #[test]
    fn new_seeds_each_genesis_validator_at_view_0() {
        let h = ValidatorKeyHistory::new([nid(1), nid(2), nid(3)]);
        for v in [nid(1), nid(2), nid(3)] {
            assert_eq!(h.key_at(&v, 0), Some(v));
            assert_eq!(h.key_at(&v, 1_000), Some(v));
            assert_eq!(h.current_key(&v), Some(v));
        }
    }

    #[test]
    fn new_deduplicates_identical_genesis_entries() {
        let h = ValidatorKeyHistory::new([nid(1), nid(1), nid(2)]);
        assert_eq!(h.validators().count(), 2);
    }

    #[test]
    fn validators_iterates_in_byte_lexicographic_order() {
        let h = ValidatorKeyHistory::new([nid(3), nid(1), nid(2)]);
        let collected: Vec<_> = h.validators().copied().collect();
        assert_eq!(collected, vec![nid(1), nid(2), nid(3)]);
    }

    #[test]
    fn key_at_returns_none_for_unknown_pubkey() {
        let h = ValidatorKeyHistory::new([nid(1)]);
        assert_eq!(h.key_at(&nid(99), 0), None);
        assert_eq!(h.key_at(&nid(99), 1_000), None);
        assert_eq!(h.current_key(&nid(99)), None);
    }

    // ── single rotation ───────────────────────────────────────────────────

    #[test]
    fn apply_rotation_records_new_key_at_v_eff() {
        let mut h = ValidatorKeyHistory::new([nid(1)]);
        let r = rot(nid(1), nid(10), 100);
        h.apply_rotation(&r, 50).unwrap();

        // Strictly before v_eff, the old key is still active.
        assert_eq!(h.key_at(&nid(1), 99), Some(nid(1)));
        // At v_eff and after, the new key is active.
        assert_eq!(h.key_at(&nid(1), 100), Some(nid(10)));
        assert_eq!(h.key_at(&nid(1), 1_000), Some(nid(10)));
    }

    #[test]
    fn lookup_resolves_through_either_old_or_new_pubkey_after_rotation() {
        let mut h = ValidatorKeyHistory::new([nid(1)]);
        h.apply_rotation(&rot(nid(1), nid(10), 100), 50).unwrap();

        // Spanning-vote scenario: a vote for view 50 was signed by
        // nid(1); the verifier calls key_at(nid(1), 50) and gets back
        // nid(1). It also calls key_at(nid(10), 50) — same stable id,
        // same answer.
        assert_eq!(h.key_at(&nid(1), 50), Some(nid(1)));
        assert_eq!(h.key_at(&nid(10), 50), Some(nid(1)));

        // Current-view lookup via either pubkey returns the new key.
        assert_eq!(h.key_at(&nid(1), 200), Some(nid(10)));
        assert_eq!(h.key_at(&nid(10), 200), Some(nid(10)));

        // Convenience accessor agrees.
        assert_eq!(h.current_key(&nid(1)), Some(nid(10)));
        assert_eq!(h.current_key(&nid(10)), Some(nid(10)));
    }

    // ── rejection paths ───────────────────────────────────────────────────

    #[test]
    fn apply_rotation_rejects_structurally_invalid() {
        let mut h = ValidatorKeyHistory::new([nid(1)]);
        // v_eff too soon (< commit_view + V_EFF_MIN_DELAY)
        let r = rot(nid(1), nid(10), 50);
        let err = h.apply_rotation(&r, 50).unwrap_err();
        assert!(matches!(err, HistoryError::Structural(_)));
    }

    #[test]
    fn apply_rotation_rejects_unknown_validator() {
        let mut h = ValidatorKeyHistory::new([nid(1)]);
        let r = rot(nid(99), nid(10), 100);
        assert_eq!(
            h.apply_rotation(&r, 50),
            Err(HistoryError::UnknownValidator { validator: nid(99) })
        );
    }

    #[test]
    fn apply_rotation_rejects_v_eff_equal_to_previous() {
        let mut h = ValidatorKeyHistory::new([nid(1)]);
        h.apply_rotation(&rot(nid(1), nid(10), 100), 50).unwrap();
        // Second rotation must address the validator by its current
        // active key (nid(10)) and have a strictly-greater v_eff.
        assert_eq!(
            h.apply_rotation(&rot(nid(10), nid(20), 100), 50),
            Err(HistoryError::VeffNotStrictlyIncreasing {
                last_v_eff: 100,
                v_eff: 100,
            })
        );
    }

    #[test]
    fn apply_rotation_rejects_v_eff_less_than_previous() {
        let mut h = ValidatorKeyHistory::new([nid(1)]);
        h.apply_rotation(&rot(nid(1), nid(10), 200), 50).unwrap();
        assert_eq!(
            h.apply_rotation(&rot(nid(10), nid(20), 150), 50),
            Err(HistoryError::VeffNotStrictlyIncreasing {
                last_v_eff: 200,
                v_eff: 150,
            })
        );
    }

    #[test]
    fn apply_rotation_rejects_new_key_owned_by_other_validator() {
        let mut h = ValidatorKeyHistory::new([nid(1), nid(2)]);
        // nid(2)'s genesis pubkey is nid(2); nid(1) must not be able
        // to rotate into it.
        let r = rot(nid(1), nid(2), 100);
        assert_eq!(
            h.apply_rotation(&r, 50),
            Err(HistoryError::NewKeyCollidesWithOtherValidator {
                new_pubkey: nid(2),
                owner: nid(2),
            })
        );
    }

    #[test]
    fn apply_rotation_rejects_collision_with_other_validators_rotated_key() {
        let mut h = ValidatorKeyHistory::new([nid(1), nid(2)]);
        // nid(2) rotates to nid(20). Now nid(1) attempts to rotate to
        // nid(20) — must be rejected.
        h.apply_rotation(&rot(nid(2), nid(20), 100), 50).unwrap();
        let err = h
            .apply_rotation(&rot(nid(1), nid(20), 200), 100)
            .unwrap_err();
        assert!(matches!(
            err,
            HistoryError::NewKeyCollidesWithOtherValidator { .. }
        ));
    }

    #[test]
    fn apply_rotation_allows_rotating_back_to_a_previous_key() {
        // K0 → K1 → K0 should be permitted: the reverse index already
        // points K0 at the right validator, so reinserting it is
        // idempotent rather than a cross-validator collision.
        let mut h = ValidatorKeyHistory::new([nid(1)]);
        h.apply_rotation(&rot(nid(1), nid(10), 100), 50).unwrap();
        h.apply_rotation(&rot(nid(10), nid(1), 200), 150).unwrap();
        assert_eq!(h.key_at(&nid(1), 50), Some(nid(1)));
        assert_eq!(h.key_at(&nid(1), 150), Some(nid(10)));
        assert_eq!(h.key_at(&nid(1), 250), Some(nid(1)));
        assert_eq!(h.current_key(&nid(1)), Some(nid(1)));
        assert_eq!(h.current_key(&nid(10)), Some(nid(1)));
    }

    // ── multi-rotation timeline ───────────────────────────────────────────

    #[test]
    fn three_consecutive_rotations_keep_full_timeline_visible() {
        let mut h = ValidatorKeyHistory::new([nid(1)]);
        h.apply_rotation(&rot(nid(1), nid(10), 100), 50).unwrap();
        h.apply_rotation(&rot(nid(10), nid(20), 200), 150).unwrap();
        h.apply_rotation(&rot(nid(20), nid(30), 300), 250).unwrap();

        // Spanning-vote lookups for each historical era return the
        // right key, regardless of which pubkey the caller queries by.
        for query in [nid(1), nid(10), nid(20), nid(30)] {
            assert_eq!(h.key_at(&query, 0), Some(nid(1)));
            assert_eq!(h.key_at(&query, 99), Some(nid(1)));
            assert_eq!(h.key_at(&query, 100), Some(nid(10)));
            assert_eq!(h.key_at(&query, 199), Some(nid(10)));
            assert_eq!(h.key_at(&query, 200), Some(nid(20)));
            assert_eq!(h.key_at(&query, 299), Some(nid(20)));
            assert_eq!(h.key_at(&query, 300), Some(nid(30)));
            assert_eq!(h.key_at(&query, 1_000), Some(nid(30)));
            assert_eq!(h.current_key(&query), Some(nid(30)));
        }
    }

    #[test]
    fn unknown_pubkey_after_rotations_still_returns_none() {
        let mut h = ValidatorKeyHistory::new([nid(1)]);
        h.apply_rotation(&rot(nid(1), nid(10), 100), 50).unwrap();
        h.apply_rotation(&rot(nid(10), nid(20), 200), 150).unwrap();
        // A pubkey nobody has used must not accidentally resolve to a
        // validator just because rotations happened in the meantime.
        assert_eq!(h.key_at(&nid(99), 250), None);
        assert_eq!(h.current_key(&nid(99)), None);
    }

    // ── edge cases on the timeline ────────────────────────────────────────

    #[test]
    fn key_at_view_zero_returns_genesis_key() {
        let mut h = ValidatorKeyHistory::new([nid(7)]);
        h.apply_rotation(&rot(nid(7), nid(70), 100), 50).unwrap();
        // No matter how many rotations happen later, view 0 always
        // resolves to the genesis key — important for verifying the
        // very first QC ever produced.
        assert_eq!(h.key_at(&nid(7), 0), Some(nid(7)));
        assert_eq!(h.key_at(&nid(70), 0), Some(nid(7)));
    }

    #[test]
    fn key_at_returns_old_key_at_v_eff_minus_one_and_new_at_v_eff() {
        // Boundary check: the contract is "active starting at v_eff",
        // i.e. inclusive at v_eff and exclusive below.
        let mut h = ValidatorKeyHistory::new([nid(1)]);
        let r = rot(nid(1), nid(10), 100);
        h.apply_rotation(&r, 50).unwrap();
        assert_eq!(h.key_at(&nid(1), 99), Some(nid(1)));
        assert_eq!(h.key_at(&nid(1), 100), Some(nid(10)));
    }

    #[test]
    fn apply_rotation_at_minimum_legal_v_eff_succeeds() {
        let mut h = ValidatorKeyHistory::new([nid(1)]);
        let commit_view = 50;
        let r = rot(nid(1), nid(10), commit_view + V_EFF_MIN_DELAY);
        h.apply_rotation(&r, commit_view).unwrap();
        assert_eq!(
            h.key_at(&nid(1), commit_view + V_EFF_MIN_DELAY),
            Some(nid(10))
        );
    }

    #[test]
    fn rejection_does_not_mutate_state() {
        let mut h = ValidatorKeyHistory::new([nid(1), nid(2)]);
        h.apply_rotation(&rot(nid(1), nid(10), 100), 50).unwrap();

        let snapshot_before_reject = (
            h.key_at(&nid(1), 1_000),
            h.key_at(&nid(2), 1_000),
            h.current_key(&nid(10)),
        );

        // Trigger every rejection path against the populated history.
        let _ = h.apply_rotation(&rot(nid(99), nid(200), 300), 100);
        let _ = h.apply_rotation(&rot(nid(10), nid(2), 300), 100);
        let _ = h.apply_rotation(&rot(nid(10), nid(200), 100), 100);
        let _ = h.apply_rotation(&rot(nid(10), nid(200), 50), 100);

        let snapshot_after_reject = (
            h.key_at(&nid(1), 1_000),
            h.key_at(&nid(2), 1_000),
            h.current_key(&nid(10)),
        );
        assert_eq!(snapshot_before_reject, snapshot_after_reject);
    }
}
