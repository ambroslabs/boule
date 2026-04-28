//! Per-historical-view BLS pubkey retention (#294).
//!
//! Mirrors [`crate::consensus::validator_key_history::ValidatorKeyHistory`]
//! but tracks each validator's *BLS* pubkey over time, not its Ed25519
//! one. On BLS chains every validator has both: an Ed25519 NodeId for
//! the network/TLS layer (the "stable id" used here) and a BLS12-381
//! pubkey for QC signing.
//!
//! # Why a parallel structure
//!
//! `ValidatorKeyHistory` stores `(stable_id, [(v_eff, NodeId)])`. Reusing
//! it for BLS would force every entry to widen to
//! `(NodeId, Option<BlsPublicKey>)` and bleed `Option` checks through
//! every Ed25519 lookup site. A parallel structure keeps Ed25519
//! retrievals unchanged and makes the BLS history opt-in: chains that
//! select Ed25519 at genesis (#288) never construct one.
//!
//! # Lookup semantics
//!
//! - `key_at(stable_id, view)`: which BLS pubkey was active for
//!   validator `stable_id` at view `view`? Used when verifying an old
//!   QC's BLS aggregate against the validator set authoritative at
//!   that QC's view, even after later rotations.
//! - `current_key(stable_id)`: most recent BLS pubkey for the validator.
//!   Used by leaders building today's QCs.
//!
//! # Mutation
//!
//! - `register(stable_id, v_eff, bls_pubkey)`: when a reconfig commits
//!   that adds a new BLS validator, the integration layer feeds the
//!   `(NodeId, BLS pubkey)` pair plus the boundary view here. PoP is
//!   verified upstream (in [`crate::consensus::reconfig`]); this
//!   structure trusts validated registrations.
//! - `apply_rotation(stable_id, v_eff, new_bls_pubkey)`: a validator
//!   rotates their BLS key. Same monotonic-`v_eff` invariant as
//!   `ValidatorKeyHistory`.
//!
//! # Out of scope for #294
//!
//! Wiring this through the live reconfig commit path lives with the
//! broader BLS-engine integration (the follow-up to #293). This PR
//! ships the structure + tests demonstrating retention across
//! boundaries so the integration PR can plug it in mechanically.

use std::collections::BTreeMap;

use crate::consensus::View;
use crate::crypto::sig_scheme::BlsPublicKey;
use crate::p2p::NodeId;

/// One entry in a validator's BLS key timeline: at view `v_eff` the
/// validator began signing QCs with `bls_pubkey`. Per-validator entries
/// are stored sorted by `v_eff` (monotonic increasing), with the
/// genesis entry always at index 0 with `v_eff = 0`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BlsKeyEntry {
    v_eff: View,
    bls_pubkey: BlsPublicKey,
}

/// Per-validator history of BLS consensus signing keys.
///
/// Stable ID = validator's Ed25519 NodeId (the network identity).
/// Validators register a BLS pubkey at genesis (or via reconfig) and
/// may rotate it later via the same path. Old QCs verify against the
/// pubkey that was active at the QC's view.
#[derive(Debug, Clone, Default)]
pub struct BlsKeyHistory {
    by_stable_id: BTreeMap<NodeId, Vec<BlsKeyEntry>>,
}

/// Reasons [`BlsKeyHistory::register`] or [`BlsKeyHistory::apply_rotation`]
/// can refuse an update.
#[derive(Debug, PartialEq, Eq)]
pub enum BlsHistoryError {
    /// The validator is already registered. `register` is for new
    /// additions only; existing validators rotate via `apply_rotation`.
    AlreadyRegistered { stable_id: NodeId },
    /// The validator was never registered. `apply_rotation` requires
    /// an existing entry to rotate from.
    UnknownValidator { stable_id: NodeId },
    /// `v_eff` is not strictly greater than the most recent entry.
    /// Mirrors `ValidatorKeyHistory`'s monotonic-`v_eff` rule so old
    /// QCs always have a unique pubkey-at-view answer.
    VeffNotStrictlyIncreasing { last_v_eff: View, v_eff: View },
}

impl std::fmt::Display for BlsHistoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyRegistered { stable_id } => write!(
                f,
                "BLS pubkey for validator {} already registered",
                hex::encode(stable_id),
            ),
            Self::UnknownValidator { stable_id } => {
                write!(f, "no BLS history for validator {}", hex::encode(stable_id),)
            }
            Self::VeffNotStrictlyIncreasing { last_v_eff, v_eff } => write!(
                f,
                "BLS rotation v_eff {v_eff} must be strictly > last v_eff {last_v_eff}",
            ),
        }
    }
}

impl std::error::Error for BlsHistoryError {}

impl BlsKeyHistory {
    /// Empty history. Genesis validators are then added via
    /// [`Self::register`] with `v_eff = 0`, mirroring how
    /// `ValidatorKeyHistory::new` seeds Ed25519 keys.
    pub fn new() -> Self {
        Self::default()
    }

    /// Convenience constructor: build a history pre-populated with
    /// genesis validators, all at `v_eff = 0`. Mirrors
    /// `ValidatorKeyHistory::new(iter)`.
    pub fn with_genesis(genesis: impl IntoIterator<Item = (NodeId, BlsPublicKey)>) -> Self {
        let mut h = Self::new();
        for (stable_id, bls_pubkey) in genesis {
            h.by_stable_id.insert(
                stable_id,
                vec![BlsKeyEntry {
                    v_eff: 0,
                    bls_pubkey,
                }],
            );
        }
        h
    }

    /// Register a brand-new validator with their initial BLS pubkey,
    /// effective at `v_eff`. Used when a reconfig commit adds a
    /// validator whose `bls_pop` payload was already verified upstream
    /// (#291).
    pub fn register(
        &mut self,
        stable_id: NodeId,
        v_eff: View,
        bls_pubkey: BlsPublicKey,
    ) -> Result<(), BlsHistoryError> {
        if self.by_stable_id.contains_key(&stable_id) {
            return Err(BlsHistoryError::AlreadyRegistered { stable_id });
        }
        self.by_stable_id
            .insert(stable_id, vec![BlsKeyEntry { v_eff, bls_pubkey }]);
        Ok(())
    }

    /// Apply a BLS-key rotation for an already-registered validator.
    /// `v_eff` must be strictly greater than the most recent entry's
    /// `v_eff` so a single view never has an ambiguous pubkey.
    pub fn apply_rotation(
        &mut self,
        stable_id: NodeId,
        v_eff: View,
        new_bls_pubkey: BlsPublicKey,
    ) -> Result<(), BlsHistoryError> {
        let entries = self
            .by_stable_id
            .get_mut(&stable_id)
            .ok_or(BlsHistoryError::UnknownValidator { stable_id })?;
        let last = entries
            .last()
            .expect("by_stable_id is never inserted with an empty Vec");
        if v_eff <= last.v_eff {
            return Err(BlsHistoryError::VeffNotStrictlyIncreasing {
                last_v_eff: last.v_eff,
                v_eff,
            });
        }
        entries.push(BlsKeyEntry {
            v_eff,
            bls_pubkey: new_bls_pubkey,
        });
        Ok(())
    }

    /// Whether `stable_id` is registered as a BLS validator at any
    /// historical view.
    pub fn contains(&self, stable_id: &NodeId) -> bool {
        self.by_stable_id.contains_key(stable_id)
    }

    /// BLS pubkey active for `stable_id` at `view`. Returns `None` if
    /// the validator was not yet registered (or never was).
    pub fn key_at(&self, stable_id: &NodeId, view: View) -> Option<BlsPublicKey> {
        let entries = self.by_stable_id.get(stable_id)?;
        // Binary-search the last entry whose v_eff <= view.
        let i = entries.partition_point(|e| e.v_eff <= view);
        if i == 0 {
            return None;
        }
        Some(entries[i - 1].bls_pubkey)
    }

    /// The most recent BLS pubkey on file for `stable_id`. Used by the
    /// live leader path.
    pub fn current_key(&self, stable_id: &NodeId) -> Option<BlsPublicKey> {
        self.by_stable_id
            .get(stable_id)?
            .last()
            .map(|e| e.bls_pubkey)
    }

    /// Number of distinct stable IDs ever registered.
    pub fn len(&self) -> usize {
        self.by_stable_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_stable_id.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn pk(b: u8) -> BlsPublicKey {
        let mut out = [0u8; 48];
        out.fill(b);
        out
    }

    #[test]
    fn empty_history_has_no_entries() {
        let h = BlsKeyHistory::new();
        assert!(h.is_empty());
        assert_eq!(h.len(), 0);
        assert!(h.key_at(&nid(1), 5).is_none());
    }

    #[test]
    fn with_genesis_seeds_each_validator_at_view_zero() {
        let h = BlsKeyHistory::with_genesis([(nid(1), pk(0xA1)), (nid(2), pk(0xA2))]);
        assert_eq!(h.len(), 2);
        assert_eq!(h.key_at(&nid(1), 0), Some(pk(0xA1)));
        assert_eq!(h.key_at(&nid(2), 0), Some(pk(0xA2)));
        assert_eq!(h.key_at(&nid(1), 1000), Some(pk(0xA1)));
        assert!(h.key_at(&nid(99), 0).is_none());
    }

    #[test]
    fn register_adds_new_validator_at_v_eff() {
        let mut h = BlsKeyHistory::new();
        h.register(nid(5), 10, pk(0x55)).unwrap();
        assert_eq!(h.key_at(&nid(5), 9), None, "before v_eff is None");
        assert_eq!(h.key_at(&nid(5), 10), Some(pk(0x55)));
        assert_eq!(h.key_at(&nid(5), 100), Some(pk(0x55)));
    }

    #[test]
    fn register_rejects_double_registration() {
        let mut h = BlsKeyHistory::new();
        h.register(nid(5), 10, pk(0x55)).unwrap();
        let err = h.register(nid(5), 11, pk(0x66)).unwrap_err();
        assert_eq!(
            err,
            BlsHistoryError::AlreadyRegistered { stable_id: nid(5) }
        );
    }

    #[test]
    fn apply_rotation_extends_timeline() {
        let mut h = BlsKeyHistory::with_genesis([(nid(1), pk(0xA1))]);
        h.apply_rotation(nid(1), 100, pk(0xB1)).unwrap();
        // Pre-rotation views still resolve to genesis key.
        assert_eq!(h.key_at(&nid(1), 0), Some(pk(0xA1)));
        assert_eq!(h.key_at(&nid(1), 99), Some(pk(0xA1)));
        // From v_eff onward, new key.
        assert_eq!(h.key_at(&nid(1), 100), Some(pk(0xB1)));
        assert_eq!(h.key_at(&nid(1), 1000), Some(pk(0xB1)));
        assert_eq!(h.current_key(&nid(1)), Some(pk(0xB1)));
    }

    #[test]
    fn apply_rotation_rejects_unknown_validator() {
        let mut h = BlsKeyHistory::new();
        let err = h.apply_rotation(nid(99), 10, pk(0x99)).unwrap_err();
        assert_eq!(
            err,
            BlsHistoryError::UnknownValidator { stable_id: nid(99) }
        );
    }

    #[test]
    fn apply_rotation_rejects_non_monotonic_v_eff() {
        let mut h = BlsKeyHistory::with_genesis([(nid(1), pk(0xA1))]);
        h.apply_rotation(nid(1), 100, pk(0xB1)).unwrap();
        // Same v_eff: rejected.
        let err = h.apply_rotation(nid(1), 100, pk(0xC1)).unwrap_err();
        assert!(matches!(
            err,
            BlsHistoryError::VeffNotStrictlyIncreasing {
                last_v_eff: 100,
                v_eff: 100
            }
        ));
        // Lower v_eff: rejected.
        let err = h.apply_rotation(nid(1), 50, pk(0xC1)).unwrap_err();
        assert!(matches!(
            err,
            BlsHistoryError::VeffNotStrictlyIncreasing {
                last_v_eff: 100,
                v_eff: 50
            }
        ));
        // Strictly greater: accepted.
        h.apply_rotation(nid(1), 200, pk(0xC1)).unwrap();
        assert_eq!(h.key_at(&nid(1), 200), Some(pk(0xC1)));
    }

    #[test]
    fn rotations_compose_correctly_across_multiple_boundaries() {
        // Validator 1 rotates at view 100, then again at view 200.
        // QCs from each era must verify against the era's key.
        let mut h = BlsKeyHistory::with_genesis([(nid(1), pk(0xA1))]);
        h.apply_rotation(nid(1), 100, pk(0xB1)).unwrap();
        h.apply_rotation(nid(1), 200, pk(0xC1)).unwrap();

        // View 50: still genesis key.
        assert_eq!(h.key_at(&nid(1), 50), Some(pk(0xA1)));
        // View 100: first rotation in effect.
        assert_eq!(h.key_at(&nid(1), 100), Some(pk(0xB1)));
        // View 150: still first-rotation key.
        assert_eq!(h.key_at(&nid(1), 150), Some(pk(0xB1)));
        // View 200: second rotation.
        assert_eq!(h.key_at(&nid(1), 200), Some(pk(0xC1)));
        // View 999: still second-rotation key (it's the latest).
        assert_eq!(h.key_at(&nid(1), 999), Some(pk(0xC1)));
    }

    #[test]
    fn registration_after_reconfig_does_not_retroactively_apply() {
        // Validator 5 is added by a reconfig that commits at view N
        // with v_eff = N + 2. QCs at views [0, N+1] must NOT find a
        // BLS pubkey for validator 5 — it didn't exist yet.
        let mut h = BlsKeyHistory::with_genesis([(nid(1), pk(0xA1))]);
        h.register(nid(5), 102, pk(0x55)).unwrap();
        for v in 0..102 {
            assert!(h.key_at(&nid(5), v).is_none(), "view {v} pre-registration");
        }
        assert_eq!(h.key_at(&nid(5), 102), Some(pk(0x55)));
        assert_eq!(h.key_at(&nid(5), 103), Some(pk(0x55)));
    }
}
