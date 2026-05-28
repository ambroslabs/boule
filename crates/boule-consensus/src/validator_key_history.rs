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

use serde::{Deserialize, Serialize};

use crate::View;
use crate::validator_history::ValidatorSetHistory;
use crate::validator_rotation::{RotationStructuralError, ValidatorKeyRotation};
use crate::validator_set::{Pubkey, ValidatorId};
use boule::identity::NodeId;

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
    /// Build a history seeded with each genesis validator's stable id
    /// active from view 0. The validator's stable id is also their
    /// initial signing pubkey (genesis pubkey == stable id by
    /// convention). The supplied iterator may yield duplicates; they
    /// are deduplicated, matching `ValidatorSet`'s convention.
    pub fn new(genesis_validators: impl IntoIterator<Item = ValidatorId>) -> Self {
        let mut h = Self::default();
        for v in genesis_validators {
            let bytes: NodeId = v.into_node_id();
            // `or_insert_with` skips duplicates: a validator can't be
            // re-registered at genesis with a different history.
            h.by_stable_id.entry(bytes).or_insert_with(|| {
                vec![KeyEntry {
                    v_eff: View::ZERO,
                    pubkey: bytes,
                }]
            });
            h.pubkey_to_stable_id.insert(bytes, bytes);
        }
        h
    }

    /// Reconstruct a key history that mirrors the boundaries of
    /// `set_history`, treating each validator's join view as their
    /// initial entry. Used at startup when the persisted set history
    /// has been rebuilt but no rotation history is yet persisted —
    /// the result is correct as long as no rotations have committed
    /// (which is true today; persistence of rotations is a follow-up).
    ///
    /// Walks the set history boundaries in order. The first time a
    /// validator pubkey appears in any boundary's set, an entry is
    /// recorded at that boundary's `v_eff`; subsequent boundaries
    /// don't overwrite. This means a validator that was in the genesis
    /// set has a `v_eff = 0` entry, while a validator added via a
    /// reconfig at view `R` has a `v_eff = R` entry — matching when
    /// they actually started being a valid signer.
    pub fn from_set_history(set_history: &ValidatorSetHistory) -> Self {
        let mut h = Self::default();
        for (v_eff, set) in set_history.iter() {
            for member in set.iter() {
                let bytes: NodeId = member.into_node_id();
                if let std::collections::btree_map::Entry::Vacant(slot) =
                    h.by_stable_id.entry(bytes)
                {
                    slot.insert(vec![KeyEntry {
                        v_eff,
                        pubkey: bytes,
                    }]);
                    h.pubkey_to_stable_id.insert(bytes, bytes);
                }
            }
        }
        h
    }

    /// Register a validator that joins via reconfig at `v_eff`. The
    /// new validator's stable id is the supplied pubkey — same
    /// identity model as genesis-seeded validators — and it becomes a
    /// valid signer starting at view `v_eff`.
    ///
    /// Takes a [`Pubkey`] because the wire-layer reconfig command
    /// arrives carrying raw `NodeId` bytes (re-tagged as a `Pubkey` at
    /// the seam); this method is what *promotes* those bytes to a
    /// fresh stable id, so it intentionally accepts the un-promoted
    /// form. Rejects if the pubkey is already known to this history
    /// under any validator (collision with the reverse index would
    /// make [`Self::validator_for`] ambiguous). Use
    /// [`Self::apply_rotation`] for the case where a known validator
    /// is changing keys.
    pub fn add_validator(
        &mut self,
        pubkey: Pubkey,
        v_eff: impl Into<View>,
    ) -> Result<(), HistoryError> {
        let v_eff = v_eff.into();
        let bytes: NodeId = pubkey.into_node_id();
        if let Some(owner) = self.pubkey_to_stable_id.get(&bytes) {
            return Err(HistoryError::NewKeyCollidesWithOtherValidator {
                new_pubkey: bytes,
                owner: *owner,
            });
        }
        self.by_stable_id.insert(
            bytes,
            vec![KeyEntry {
                v_eff,
                pubkey: bytes,
            }],
        );
        self.pubkey_to_stable_id.insert(bytes, bytes);
        Ok(())
    }

    /// Resolve any pubkey ever used by a validator (genesis, current,
    /// or any historical key it has rotated through) to that
    /// validator's stable identifier. Returns `None` if the pubkey is
    /// not associated with any validator.
    ///
    /// This is the lookup the verification path uses to bridge
    /// "signer pubkey on the wire" to "validator's stable id in the
    /// validator set" — without it, the post-rotation key wouldn't be
    /// recognizable as belonging to the same validator that was
    /// originally seated. It is also the **only** way to land in
    /// [`ValidatorId`] outside of the genesis-seeding constructor — the
    /// load-bearing guard for #328.
    pub fn validator_for(&self, pubkey: &Pubkey) -> Option<ValidatorId> {
        self.pubkey_to_stable_id
            .get(pubkey.as_node_id())
            .copied()
            .map(ValidatorId::from_genesis_pubkey)
    }

    /// The active signing key for `validator`, evaluated as of view
    /// `view`. Takes the validator's stable id directly — callers that
    /// only have a wire pubkey first resolve it via
    /// [`Self::validator_for`].
    ///
    /// Returns `None` if the validator is not present in this history,
    /// or (defensively) if no entry covers `view`. Spanning votes (a
    /// late vote at an older view) verify against whichever pubkey was
    /// active at that older view, which is what this method returns.
    pub fn key_at(&self, validator: &ValidatorId, view: impl Into<View>) -> Option<Pubkey> {
        let view = view.into();
        let entries = self.by_stable_id.get(validator.as_node_id())?;
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
        Some(Pubkey::from_node_id(entries[idx - 1].pubkey))
    }

    /// Same as [`Self::key_at`] but resolves the validator from any
    /// pubkey it has ever used. Convenience for call sites that only
    /// have a wire pubkey — equivalent to
    /// `validator_for(p).and_then(|v| key_at(&v, view))`.
    pub fn key_at_for_pubkey(
        &self,
        pubkey_anywhere: &Pubkey,
        view: impl Into<View>,
    ) -> Option<Pubkey> {
        let view = view.into();
        let validator = self.validator_for(pubkey_anywhere)?;
        self.key_at(&validator, view)
    }

    /// The validator's current (most recently effective) signing key
    /// regardless of view. Convenience wrapper over the latest entry —
    /// useful for code paths that don't have a view in hand, like an
    /// admission-time check that the rotation tx is signed by *the*
    /// current key. Resolves the validator from any pubkey it has ever
    /// used.
    pub fn current_key(&self, pubkey_anywhere_in_history: &Pubkey) -> Option<Pubkey> {
        let stable_id = self
            .pubkey_to_stable_id
            .get(pubkey_anywhere_in_history.as_node_id())?;
        let entries = self.by_stable_id.get(stable_id)?;
        entries.last().map(|e| Pubkey::from_node_id(e.pubkey))
    }

    /// Iterate over the stable identifiers of every validator in this
    /// history, in stable byte-lexicographic order.
    pub fn validators(&self) -> impl Iterator<Item = ValidatorId> + '_ {
        self.by_stable_id
            .keys()
            .copied()
            .map(ValidatorId::from_genesis_pubkey)
    }

    /// Iterate every validator's full key timeline in stable
    /// byte-lexicographic order of stable id. For each validator, the
    /// inner iterator yields `(v_eff, pubkey)` entries in chronological
    /// order — `entries.next()` is always the genesis (or
    /// reconfig-add) entry. Intended for operator-facing introspection
    /// (`/consensus/status`, #314); the verification path uses
    /// [`Self::key_at`] / [`Self::validator_for`] instead.
    pub fn iter(
        &self,
    ) -> impl Iterator<Item = (ValidatorId, impl Iterator<Item = (View, NodeId)> + '_)> + '_ {
        self.by_stable_id.iter().map(|(stable_id, entries)| {
            (
                ValidatorId::from_genesis_pubkey(*stable_id),
                entries.iter().map(|e| (e.v_eff, e.pubkey)),
            )
        })
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
        commit_view: impl Into<View>,
    ) -> Result<(), HistoryError> {
        let commit_view = commit_view.into();
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

    /// Snapshot the history into a serializable wire form, suitable for
    /// durable persistence (#260 follow-up). Mirrors
    /// [`ValidatorSetHistory::to_persisted`]: encode every validator's
    /// timeline as a flat list so recovery is a single read + decode.
    pub fn to_persisted(&self) -> PersistedValidatorKeyHistory {
        let validators = self
            .by_stable_id
            .iter()
            .map(|(stable_id, entries)| PersistedValidator {
                stable_id: *stable_id,
                entries: entries
                    .iter()
                    .map(|e| PersistedKeyEntry {
                        v_eff: e.v_eff,
                        pubkey: e.pubkey,
                    })
                    .collect(),
            })
            .collect();
        PersistedValidatorKeyHistory { validators }
    }

    /// Rebuild a history from its persisted form. Validates that every
    /// validator has at least one entry, that entries are in
    /// strictly-increasing `v_eff` order, that the first entry's pubkey
    /// matches the stable identifier (the validator's genesis pubkey),
    /// and that no pubkey is claimed by two distinct validators.
    pub fn from_persisted(persisted: PersistedValidatorKeyHistory) -> anyhow::Result<Self> {
        let mut h = Self::default();
        for v in persisted.validators {
            if v.entries.is_empty() {
                anyhow::bail!(
                    "persisted validator {} has no entries",
                    hex::encode(v.stable_id)
                );
            }
            // The first entry's pubkey must equal the stable id —
            // that's the convention `new` and `add_validator` set up,
            // and `apply_rotation` only appends, so any deviation here
            // means the persisted form was tampered with or
            // hand-constructed inconsistently.
            if v.entries[0].pubkey != v.stable_id {
                anyhow::bail!(
                    "persisted validator {}'s first entry pubkey {} does not match stable id",
                    hex::encode(v.stable_id),
                    hex::encode(v.entries[0].pubkey),
                );
            }
            let mut last_v_eff: Option<View> = None;
            let mut local_entries: Vec<KeyEntry> = Vec::with_capacity(v.entries.len());
            for entry in v.entries {
                if let Some(prev) = last_v_eff
                    && entry.v_eff <= prev
                {
                    anyhow::bail!(
                        "persisted validator {}'s entries not strictly v_eff-increasing: \
                         got {} after {}",
                        hex::encode(v.stable_id),
                        entry.v_eff,
                        prev,
                    );
                }
                last_v_eff = Some(entry.v_eff);
                if let Some(owner) = h.pubkey_to_stable_id.get(&entry.pubkey)
                    && *owner != v.stable_id
                {
                    anyhow::bail!(
                        "persisted pubkey {} claimed by both validator {} and {}",
                        hex::encode(entry.pubkey),
                        hex::encode(owner),
                        hex::encode(v.stable_id),
                    );
                }
                h.pubkey_to_stable_id.insert(entry.pubkey, v.stable_id);
                local_entries.push(KeyEntry {
                    v_eff: entry.v_eff,
                    pubkey: entry.pubkey,
                });
            }
            h.by_stable_id.insert(v.stable_id, local_entries);
        }
        Ok(h)
    }
}

/// One entry in the persisted (wire) form of a validator's key timeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedKeyEntry {
    pub v_eff: View,
    pub pubkey: NodeId,
}

/// One validator's full timeline in the persisted form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedValidator {
    pub stable_id: NodeId,
    pub entries: Vec<PersistedKeyEntry>,
}

/// Serializable snapshot of a [`ValidatorKeyHistory`] (#260). Encoded
/// via postcard at storage write time, written under
/// `boule_node::consensus_node::persistence::STORAGE_KEY_VALIDATOR_KEY_HISTORY`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedValidatorKeyHistory {
    pub validators: Vec<PersistedValidator>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator_rotation::V_EFF_MIN_DELAY;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn vid(b: u8) -> ValidatorId {
        ValidatorId::from_genesis_pubkey(nid(b))
    }

    fn pk(b: u8) -> Pubkey {
        Pubkey::from_node_id(nid(b))
    }

    fn rot(validator: NodeId, new_pubkey: NodeId, v_eff: impl Into<View>) -> ValidatorKeyRotation {
        let v_eff = v_eff.into();
        ValidatorKeyRotation {
            validator,
            new_pubkey,
            v_eff,
            new_bls_pubkey: None,
            new_bls_pop: None,
        }
    }

    // ── construction ──────────────────────────────────────────────────────

    #[test]
    fn new_seeds_each_genesis_validator_at_view_0() {
        let h = ValidatorKeyHistory::new([vid(1), vid(2), vid(3)]);
        for b in [1u8, 2, 3] {
            assert_eq!(h.key_at(&vid(b), 0), Some(pk(b)));
            assert_eq!(h.key_at(&vid(b), 1_000), Some(pk(b)));
            assert_eq!(h.current_key(&pk(b)), Some(pk(b)));
        }
    }

    #[test]
    fn new_deduplicates_identical_genesis_entries() {
        let h = ValidatorKeyHistory::new([vid(1), vid(1), vid(2)]);
        assert_eq!(h.validators().count(), 2);
    }

    #[test]
    fn iter_yields_full_timeline_per_validator_in_stable_order() {
        // Powers the operator-facing `validator_keys` field on
        // `/consensus/status` (#314): for each validator, the inner
        // iterator yields the genesis entry first followed by every
        // applied rotation, in chronological order.
        let mut h = ValidatorKeyHistory::new([vid(2), vid(1)]);
        h.apply_rotation(&rot(nid(1), nid(10), 100), 50).unwrap();
        h.apply_rotation(&rot(nid(10), nid(20), 200), 150).unwrap();

        let collected: Vec<(ValidatorId, Vec<(View, NodeId)>)> = h
            .iter()
            .map(|(v, entries)| (v, entries.collect()))
            .collect();

        // Outer order is stable byte-lexicographic, matching `validators()`.
        assert_eq!(collected[0].0, vid(1));
        assert_eq!(collected[1].0, vid(2));

        // Validator 1 has its genesis entry plus two rotations.
        assert_eq!(
            collected[0].1,
            vec![
                (View(0), nid(1)),
                (View(100), nid(10)),
                (View(200), nid(20)),
            ],
        );
        // Validator 2 has only its genesis entry.
        assert_eq!(collected[1].1, vec![(View(0), nid(2))]);
    }

    #[test]
    fn validators_iterates_in_byte_lexicographic_order() {
        let h = ValidatorKeyHistory::new([vid(3), vid(1), vid(2)]);
        let collected: Vec<_> = h.validators().collect();
        assert_eq!(collected, vec![vid(1), vid(2), vid(3)]);
    }

    #[test]
    fn key_at_returns_none_for_unknown_pubkey() {
        let h = ValidatorKeyHistory::new([vid(1)]);
        assert_eq!(h.key_at(&vid(99), 0), None);
        assert_eq!(h.key_at(&vid(99), 1_000), None);
        assert_eq!(h.current_key(&pk(99)), None);
    }

    // ── single rotation ───────────────────────────────────────────────────

    #[test]
    fn apply_rotation_records_new_key_at_v_eff() {
        let mut h = ValidatorKeyHistory::new([vid(1)]);
        let r = rot(nid(1), nid(10), 100);
        h.apply_rotation(&r, 50).unwrap();

        // Strictly before v_eff, the old key is still active.
        assert_eq!(h.key_at(&vid(1), 99), Some(pk(1)));
        // At v_eff and after, the new key is active.
        assert_eq!(h.key_at(&vid(1), 100), Some(pk(10)));
        assert_eq!(h.key_at(&vid(1), 1_000), Some(pk(10)));
    }

    #[test]
    fn lookup_resolves_through_either_old_or_new_pubkey_after_rotation() {
        let mut h = ValidatorKeyHistory::new([vid(1)]);
        h.apply_rotation(&rot(nid(1), nid(10), 100), 50).unwrap();

        // Spanning-vote scenario: a vote for view 50 was signed by
        // pk(1); the verifier calls key_at(vid(1), 50) and gets back
        // pk(1). validator_for(pk(10)) also resolves to vid(1) — same
        // stable id, same answer.
        assert_eq!(h.key_at(&vid(1), 50), Some(pk(1)));
        assert_eq!(h.validator_for(&pk(10)), Some(vid(1)));
        assert_eq!(h.key_at_for_pubkey(&pk(10), 50), Some(pk(1)));

        // Current-view lookup via either pubkey returns the new key.
        assert_eq!(h.key_at(&vid(1), 200), Some(pk(10)));
        assert_eq!(h.key_at_for_pubkey(&pk(10), 200), Some(pk(10)));

        // Convenience accessor agrees.
        assert_eq!(h.current_key(&pk(1)), Some(pk(10)));
        assert_eq!(h.current_key(&pk(10)), Some(pk(10)));
    }

    // ── rejection paths ───────────────────────────────────────────────────

    #[test]
    fn apply_rotation_rejects_structurally_invalid() {
        let mut h = ValidatorKeyHistory::new([vid(1)]);
        // v_eff too soon (< commit_view + V_EFF_MIN_DELAY)
        let r = rot(nid(1), nid(10), 50);
        let err = h.apply_rotation(&r, 50).unwrap_err();
        assert!(matches!(err, HistoryError::Structural(_)));
    }

    #[test]
    fn apply_rotation_rejects_unknown_validator() {
        let mut h = ValidatorKeyHistory::new([vid(1)]);
        let r = rot(nid(99), nid(10), 100);
        assert_eq!(
            h.apply_rotation(&r, 50),
            Err(HistoryError::UnknownValidator { validator: nid(99) })
        );
    }

    #[test]
    fn apply_rotation_rejects_v_eff_equal_to_previous() {
        let mut h = ValidatorKeyHistory::new([vid(1)]);
        h.apply_rotation(&rot(nid(1), nid(10), 100), 50).unwrap();
        // Second rotation must address the validator by its current
        // active key (nid(10)) and have a strictly-greater v_eff.
        assert_eq!(
            h.apply_rotation(&rot(nid(10), nid(20), 100), 50),
            Err(HistoryError::VeffNotStrictlyIncreasing {
                last_v_eff: View(100),
                v_eff: View(100),
            })
        );
    }

    #[test]
    fn apply_rotation_rejects_v_eff_less_than_previous() {
        let mut h = ValidatorKeyHistory::new([vid(1)]);
        h.apply_rotation(&rot(nid(1), nid(10), 200), 50).unwrap();
        assert_eq!(
            h.apply_rotation(&rot(nid(10), nid(20), 150), 50),
            Err(HistoryError::VeffNotStrictlyIncreasing {
                last_v_eff: View(200),
                v_eff: View(150),
            })
        );
    }

    #[test]
    fn apply_rotation_rejects_new_key_owned_by_other_validator() {
        let mut h = ValidatorKeyHistory::new([vid(1), vid(2)]);
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
        let mut h = ValidatorKeyHistory::new([vid(1), vid(2)]);
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
        let mut h = ValidatorKeyHistory::new([vid(1)]);
        h.apply_rotation(&rot(nid(1), nid(10), 100), 50).unwrap();
        h.apply_rotation(&rot(nid(10), nid(1), 200), 150).unwrap();
        assert_eq!(h.key_at(&vid(1), 50), Some(pk(1)));
        assert_eq!(h.key_at(&vid(1), 150), Some(pk(10)));
        assert_eq!(h.key_at(&vid(1), 250), Some(pk(1)));
        assert_eq!(h.current_key(&pk(1)), Some(pk(1)));
        assert_eq!(h.current_key(&pk(10)), Some(pk(1)));
    }

    // ── multi-rotation timeline ───────────────────────────────────────────

    #[test]
    fn three_consecutive_rotations_keep_full_timeline_visible() {
        let mut h = ValidatorKeyHistory::new([vid(1)]);
        h.apply_rotation(&rot(nid(1), nid(10), 100), 50).unwrap();
        h.apply_rotation(&rot(nid(10), nid(20), 200), 150).unwrap();
        h.apply_rotation(&rot(nid(20), nid(30), 300), 250).unwrap();

        // Spanning-vote lookups for each historical era return the
        // right key, regardless of which pubkey the caller queries by.
        for query in [pk(1), pk(10), pk(20), pk(30)] {
            assert_eq!(h.key_at_for_pubkey(&query, 0), Some(pk(1)));
            assert_eq!(h.key_at_for_pubkey(&query, 99), Some(pk(1)));
            assert_eq!(h.key_at_for_pubkey(&query, 100), Some(pk(10)));
            assert_eq!(h.key_at_for_pubkey(&query, 199), Some(pk(10)));
            assert_eq!(h.key_at_for_pubkey(&query, 200), Some(pk(20)));
            assert_eq!(h.key_at_for_pubkey(&query, 299), Some(pk(20)));
            assert_eq!(h.key_at_for_pubkey(&query, 300), Some(pk(30)));
            assert_eq!(h.key_at_for_pubkey(&query, 1_000), Some(pk(30)));
            assert_eq!(h.current_key(&query), Some(pk(30)));
        }
    }

    #[test]
    fn unknown_pubkey_after_rotations_still_returns_none() {
        let mut h = ValidatorKeyHistory::new([vid(1)]);
        h.apply_rotation(&rot(nid(1), nid(10), 100), 50).unwrap();
        h.apply_rotation(&rot(nid(10), nid(20), 200), 150).unwrap();
        // A pubkey nobody has used must not accidentally resolve to a
        // validator just because rotations happened in the meantime.
        assert_eq!(h.validator_for(&pk(99)), None);
        assert_eq!(h.current_key(&pk(99)), None);
    }

    // ── edge cases on the timeline ────────────────────────────────────────

    #[test]
    fn key_at_view_zero_returns_genesis_key() {
        let mut h = ValidatorKeyHistory::new([vid(7)]);
        h.apply_rotation(&rot(nid(7), nid(70), 100), 50).unwrap();
        // No matter how many rotations happen later, view 0 always
        // resolves to the genesis key — important for verifying the
        // very first QC ever produced.
        assert_eq!(h.key_at(&vid(7), 0), Some(pk(7)));
        assert_eq!(h.key_at_for_pubkey(&pk(70), 0), Some(pk(7)));
    }

    #[test]
    fn key_at_returns_old_key_at_v_eff_minus_one_and_new_at_v_eff() {
        // Boundary check: the contract is "active starting at v_eff",
        // i.e. inclusive at v_eff and exclusive below.
        let mut h = ValidatorKeyHistory::new([vid(1)]);
        let r = rot(nid(1), nid(10), 100);
        h.apply_rotation(&r, 50).unwrap();
        assert_eq!(h.key_at(&vid(1), 99), Some(pk(1)));
        assert_eq!(h.key_at(&vid(1), 100), Some(pk(10)));
    }

    #[test]
    fn apply_rotation_at_minimum_legal_v_eff_succeeds() {
        let mut h = ValidatorKeyHistory::new([vid(1)]);
        let commit_view = View(50);
        let r = rot(nid(1), nid(10), commit_view + V_EFF_MIN_DELAY);
        h.apply_rotation(&r, commit_view).unwrap();
        assert_eq!(
            h.key_at(&vid(1), commit_view + V_EFF_MIN_DELAY),
            Some(pk(10))
        );
    }

    #[test]
    fn rejection_does_not_mutate_state() {
        let mut h = ValidatorKeyHistory::new([vid(1), vid(2)]);
        h.apply_rotation(&rot(nid(1), nid(10), 100), 50).unwrap();

        let snapshot_before_reject = (
            h.key_at(&vid(1), 1_000),
            h.key_at(&vid(2), 1_000),
            h.current_key(&pk(10)),
        );

        // Trigger every rejection path against the populated history.
        let _ = h.apply_rotation(&rot(nid(99), nid(200), 300), 100);
        let _ = h.apply_rotation(&rot(nid(10), nid(2), 300), 100);
        let _ = h.apply_rotation(&rot(nid(10), nid(200), 100), 100);
        let _ = h.apply_rotation(&rot(nid(10), nid(200), 50), 100);

        let snapshot_after_reject = (
            h.key_at(&vid(1), 1_000),
            h.key_at(&vid(2), 1_000),
            h.current_key(&pk(10)),
        );
        assert_eq!(snapshot_before_reject, snapshot_after_reject);
    }

    // ── validator_for ─────────────────────────────────────────────────────

    #[test]
    fn validator_for_resolves_genesis_pubkey() {
        let h = ValidatorKeyHistory::new([vid(1), vid(2)]);
        assert_eq!(h.validator_for(&pk(1)), Some(vid(1)));
        assert_eq!(h.validator_for(&pk(2)), Some(vid(2)));
        assert_eq!(h.validator_for(&pk(99)), None);
    }

    #[test]
    fn validator_for_resolves_post_rotation_pubkey_to_stable_id() {
        let mut h = ValidatorKeyHistory::new([vid(1)]);
        h.apply_rotation(&rot(nid(1), nid(10), 100), 50).unwrap();
        h.apply_rotation(&rot(nid(10), nid(20), 200), 150).unwrap();
        // Every key the validator has ever used resolves to the same
        // stable id — that's what bridges spanning-vote verification
        // back to the validator's identity in the validator set.
        assert_eq!(h.validator_for(&pk(1)), Some(vid(1)));
        assert_eq!(h.validator_for(&pk(10)), Some(vid(1)));
        assert_eq!(h.validator_for(&pk(20)), Some(vid(1)));
        assert_eq!(h.validator_for(&pk(99)), None);
    }

    // ── add_validator ─────────────────────────────────────────────────────

    #[test]
    fn add_validator_makes_node_a_valid_signer_starting_at_v_eff() {
        let mut h = ValidatorKeyHistory::new([vid(1)]);
        h.add_validator(pk(2), 10).unwrap();
        // Before they joined, the validator has no active key.
        assert_eq!(h.key_at(&vid(2), 9), None);
        // From v_eff onwards, they're a valid signer using their own
        // pubkey as the initial key.
        assert_eq!(h.key_at(&vid(2), 10), Some(pk(2)));
        assert_eq!(h.key_at(&vid(2), 1_000), Some(pk(2)));
        // And the reverse index resolves them.
        assert_eq!(h.validator_for(&pk(2)), Some(vid(2)));
    }

    #[test]
    fn add_validator_rejects_pubkey_already_known() {
        let mut h = ValidatorKeyHistory::new([vid(1)]);
        // Genesis validator's pubkey collides.
        let err = h.add_validator(pk(1), 10).unwrap_err();
        assert!(matches!(
            err,
            HistoryError::NewKeyCollidesWithOtherValidator { .. }
        ));
    }

    #[test]
    fn add_validator_then_apply_rotation_works_for_added_validator() {
        let mut h = ValidatorKeyHistory::new([vid(1)]);
        h.add_validator(pk(2), 10).unwrap();
        // Newly-added validator can subsequently rotate keys.
        h.apply_rotation(&rot(nid(2), nid(20), 100), 50).unwrap();
        assert_eq!(h.key_at(&vid(2), 50), Some(pk(2)));
        assert_eq!(h.key_at(&vid(2), 100), Some(pk(20)));
        assert_eq!(h.validator_for(&pk(20)), Some(vid(2)));
    }

    // ── from_set_history ──────────────────────────────────────────────────

    #[test]
    fn from_set_history_genesis_only_matches_new() {
        use crate::validator_set::ValidatorSet;
        let vs = ValidatorSet::new(vec![vid(1), vid(2), vid(3)]);
        let sh = ValidatorSetHistory::from_genesis(vs);

        let h = ValidatorKeyHistory::from_set_history(&sh);
        for b in [1u8, 2, 3] {
            assert_eq!(h.key_at(&vid(b), 0), Some(pk(b)));
            assert_eq!(h.key_at(&vid(b), 1_000), Some(pk(b)));
            assert_eq!(h.validator_for(&pk(b)), Some(vid(b)));
        }
    }

    #[test]
    fn from_set_history_picks_up_validators_added_via_reconfig() {
        use crate::validator_set::ValidatorSet;
        let mut sh = ValidatorSetHistory::from_genesis(ValidatorSet::new(vec![vid(1), vid(2)]));
        sh.insert_boundary(10, ValidatorSet::new(vec![vid(1), vid(2), vid(3)]))
            .unwrap();

        let h = ValidatorKeyHistory::from_set_history(&sh);
        // Genesis validators get entries at v_eff = 0.
        assert_eq!(h.key_at(&vid(1), 0), Some(pk(1)));
        assert_eq!(h.key_at(&vid(2), 0), Some(pk(2)));
        // Reconfig-added validator only becomes a valid signer at v_eff.
        assert_eq!(h.key_at(&vid(3), 9), None);
        assert_eq!(h.key_at(&vid(3), 10), Some(pk(3)));
        assert_eq!(h.key_at(&vid(3), 1_000), Some(pk(3)));
        // Validators that left the set (none in this test) would still
        // appear in key history forever — they're tracked for spanning
        // votes against their tenure, even if removed later.
    }

    #[test]
    fn from_set_history_does_not_re_add_validators_present_in_multiple_boundaries() {
        use crate::validator_set::ValidatorSet;
        let mut sh = ValidatorSetHistory::from_genesis(ValidatorSet::new(vec![vid(1), vid(2)]));
        sh.insert_boundary(10, ValidatorSet::new(vec![vid(1), vid(2), vid(3)]))
            .unwrap();
        sh.insert_boundary(20, ValidatorSet::new(vec![vid(1), vid(3)]))
            .unwrap(); // vid(2) removed

        let h = ValidatorKeyHistory::from_set_history(&sh);
        // vid(1) appears in every boundary; the entry stays at v_eff = 0
        // (its earliest appearance), not bumped forward by later
        // boundaries.
        assert_eq!(h.key_at(&vid(1), 0), Some(pk(1)));
        // vid(2) was in genesis + first reconfig but removed at 20.
        // The key history retains its entry at v_eff = 0 — needed so
        // late spanning votes from view < 20 still verify.
        assert_eq!(h.key_at(&vid(2), 0), Some(pk(2)));
        assert_eq!(h.key_at(&vid(2), 19), Some(pk(2)));
        // vid(3) joined at 10.
        assert_eq!(h.key_at(&vid(3), 10), Some(pk(3)));
    }

    // ── persistence (#260) ────────────────────────────────────────────────

    #[test]
    fn round_trips_through_persisted_form_genesis_only() {
        let h = ValidatorKeyHistory::new([vid(1), vid(2), vid(3)]);
        let persisted = h.to_persisted();
        let bytes = postcard::to_stdvec(&persisted).unwrap();
        let decoded: PersistedValidatorKeyHistory = postcard::from_bytes(&bytes).unwrap();
        let restored = ValidatorKeyHistory::from_persisted(decoded).unwrap();

        // Same lookups as the original.
        for b in [1u8, 2, 3] {
            assert_eq!(restored.key_at(&vid(b), 0), Some(pk(b)));
            assert_eq!(restored.key_at(&vid(b), 1_000), Some(pk(b)));
            assert_eq!(restored.validator_for(&pk(b)), Some(vid(b)));
        }
    }

    #[test]
    fn round_trips_through_persisted_form_with_rotations() {
        let mut h = ValidatorKeyHistory::new([vid(1), vid(2)]);
        h.apply_rotation(&rot(nid(1), nid(10), 100), 50).unwrap();
        h.apply_rotation(&rot(nid(10), nid(20), 200), 150).unwrap();
        h.apply_rotation(&rot(nid(2), nid(30), 300), 250).unwrap();

        let persisted = h.to_persisted();
        let bytes = postcard::to_stdvec(&persisted).unwrap();
        let decoded: PersistedValidatorKeyHistory = postcard::from_bytes(&bytes).unwrap();
        let restored = ValidatorKeyHistory::from_persisted(decoded).unwrap();

        // Spanning queries reach back through every era.
        for query in [pk(1), pk(10), pk(20)] {
            assert_eq!(restored.key_at_for_pubkey(&query, 0), Some(pk(1)));
            assert_eq!(restored.key_at_for_pubkey(&query, 99), Some(pk(1)));
            assert_eq!(restored.key_at_for_pubkey(&query, 100), Some(pk(10)));
            assert_eq!(restored.key_at_for_pubkey(&query, 199), Some(pk(10)));
            assert_eq!(restored.key_at_for_pubkey(&query, 200), Some(pk(20)));
        }
        for query in [pk(2), pk(30)] {
            assert_eq!(restored.key_at_for_pubkey(&query, 0), Some(pk(2)));
            assert_eq!(restored.key_at_for_pubkey(&query, 299), Some(pk(2)));
            assert_eq!(restored.key_at_for_pubkey(&query, 300), Some(pk(30)));
        }
    }

    #[test]
    fn from_persisted_rejects_validator_with_no_entries() {
        let bad = PersistedValidatorKeyHistory {
            validators: vec![PersistedValidator {
                stable_id: nid(1),
                entries: vec![],
            }],
        };
        let err = ValidatorKeyHistory::from_persisted(bad).unwrap_err();
        assert!(err.to_string().contains("no entries"));
    }

    #[test]
    fn from_persisted_rejects_first_entry_pubkey_mismatch() {
        // Genesis entry's pubkey must equal the stable_id (that's the
        // invariant `new` and `add_validator` set up). A persisted blob
        // claiming otherwise is structurally bogus.
        let bad = PersistedValidatorKeyHistory {
            validators: vec![PersistedValidator {
                stable_id: nid(1),
                entries: vec![PersistedKeyEntry {
                    v_eff: View(0),
                    pubkey: nid(99),
                }],
            }],
        };
        let err = ValidatorKeyHistory::from_persisted(bad).unwrap_err();
        assert!(err.to_string().contains("does not match stable id"));
    }

    #[test]
    fn from_persisted_rejects_non_monotone_v_eff_within_a_validator() {
        let bad = PersistedValidatorKeyHistory {
            validators: vec![PersistedValidator {
                stable_id: nid(1),
                entries: vec![
                    PersistedKeyEntry {
                        v_eff: View(0),
                        pubkey: nid(1),
                    },
                    PersistedKeyEntry {
                        v_eff: View(100),
                        pubkey: nid(10),
                    },
                    PersistedKeyEntry {
                        v_eff: View(50),
                        pubkey: nid(20),
                    },
                ],
            }],
        };
        let err = ValidatorKeyHistory::from_persisted(bad).unwrap_err();
        assert!(err.to_string().contains("not strictly v_eff-increasing"));
    }

    #[test]
    fn from_persisted_rejects_pubkey_collision_across_validators() {
        // Two distinct validators claiming the same pubkey would break
        // the reverse index — a single key can only belong to one
        // validator at a time.
        let bad = PersistedValidatorKeyHistory {
            validators: vec![
                PersistedValidator {
                    stable_id: nid(1),
                    entries: vec![
                        PersistedKeyEntry {
                            v_eff: View(0),
                            pubkey: nid(1),
                        },
                        PersistedKeyEntry {
                            v_eff: View(100),
                            pubkey: nid(50),
                        },
                    ],
                },
                PersistedValidator {
                    stable_id: nid(2),
                    entries: vec![
                        PersistedKeyEntry {
                            v_eff: View(0),
                            pubkey: nid(2),
                        },
                        PersistedKeyEntry {
                            v_eff: View(200),
                            pubkey: nid(50),
                        },
                    ],
                },
            ],
        };
        let err = ValidatorKeyHistory::from_persisted(bad).unwrap_err();
        assert!(err.to_string().contains("claimed by both"));
    }
}
