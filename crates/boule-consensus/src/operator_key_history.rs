//! Per-validator **operator-key** history (#549).
//!
//! Every validator has, alongside its consensus *signing* key
//! ([`ValidatorKeyHistory`](crate::validator_key_history::ValidatorKeyHistory)),
//! an **operator key**: the cold-storage / multi-sig key identifying the
//! human or organisation running the validator, distinct from the hot key
//! that signs votes. The operator key's authority is administrative, not
//! consensus:
//!
//! - It can rotate the *signing* key **without the old signing key** — the
//!   recovery-from-loss path (#549). If a validator's signing key is
//!   destroyed (HSM failure, lost single share), the operator key is what
//!   lets it back into the set; without it the validator is bricked forever.
//! - It self-rotates (dual-signed old + new operator) like the signing key.
//! - Future: it authorises governance approvals (#548), endpoint updates
//!   (#546), and withdrawal-address changes.
//!
//! This module is the **data structure** half of that work: a per-validator
//! timeline of operator keys, mirroring
//! [`BlsKeyHistory`](crate::bls_key_history::BlsKeyHistory) in shape (a
//! validator's stable [`ValidatorId`] → a `v_eff`-ordered list of operator
//! pubkeys). The lookup semantics are the same as the other key histories:
//! an operator-signed action at view `V` verifies against the operator key
//! that was active *at `V`*, so an action remains verifiable across later
//! operator-key rotations.
//!
//! # Scope of this PR
//!
//! The pure structure plus its genesis constructor, lookups
//! ([`OperatorKeyHistory::key_at`] / [`OperatorKeyHistory::current_key`]),
//! the rotation mutator ([`OperatorKeyHistory::apply_rotation`]), and the
//! persisted form — landed standalone,
//! the way `BlsKeyHistory` (#294) shipped ahead of its integration. Wiring
//! it into the commit path (operator-signed signing-key recovery, operator
//! self-rotation, the anti-rollback commitment) lands in follow-up PRs.
//!
//! # Stable identifier
//!
//! Keyed by the validator's stable [`ValidatorId`] (its genesis pubkey, the
//! same stable id `ValidatorKeyHistory` and `BlsKeyHistory` use), *not* by
//! the operator pubkey — operators may run many validators (#549 q4), so the
//! operator pubkey is not a unique key.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::View;
use crate::validator_set::ValidatorId;
use boule_core::identity::NodeId;

/// One entry in a validator's operator-key timeline: at view `v_eff` the
/// validator's operator key became `operator_pubkey`. Per-validator entries
/// are stored sorted by `v_eff` (monotonic increasing), with the genesis
/// entry always at index 0 with `v_eff = 0`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OperatorKeyEntry {
    v_eff: View,
    operator_pubkey: NodeId,
}

/// Per-validator history of operator keys over time.
///
/// Stable ID = the validator's stable [`ValidatorId`] (genesis pubkey).
/// Validators declare an operator key at genesis and may rotate it later via
/// a dual-signed operator-rotation tx (a follow-up PR). Operator-signed
/// actions verify against the operator key active at the action's view.
#[derive(Debug, Clone, Default)]
pub struct OperatorKeyHistory {
    by_stable_id: BTreeMap<NodeId, Vec<OperatorKeyEntry>>,
}

/// Reasons [`OperatorKeyHistory::apply_rotation`] can refuse an operator-key
/// rotation. Mirrors `BlsHistoryError`'s post-commit validation failures.
#[derive(Debug, PartialEq, Eq)]
pub enum OperatorHistoryError {
    /// The validator has no operator-key history — it was never seeded at
    /// genesis (or added with an operator key).
    UnknownValidator { stable_id: NodeId },
    /// `v_eff` is not strictly greater than the most recent entry's, which
    /// would make a single view's operator key ambiguous. Same
    /// monotonic-`v_eff` rule as the signing-key and BLS histories; it also
    /// provides replay protection for operator-signed rotations.
    VeffNotStrictlyIncreasing { last_v_eff: View, v_eff: View },
}

impl std::fmt::Display for OperatorHistoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownValidator { stable_id } => write!(
                f,
                "no operator-key history for validator {}",
                hex::encode(stable_id),
            ),
            Self::VeffNotStrictlyIncreasing { last_v_eff, v_eff } => write!(
                f,
                "operator-key rotation v_eff {v_eff} must be strictly > last v_eff {last_v_eff}",
            ),
        }
    }
}

impl std::error::Error for OperatorHistoryError {}

impl OperatorKeyHistory {
    /// Empty history. Genesis validators are added via [`Self::with_genesis`]
    /// (or one-by-one through the persisted form), each at `v_eff = 0`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a history pre-populated with genesis validators' operator keys,
    /// all effective at `v_eff = 0`. Mirrors
    /// [`BlsKeyHistory::with_genesis`](crate::bls_key_history::BlsKeyHistory::with_genesis).
    /// A duplicate `validator` in the iterator keeps the first entry (matching
    /// `ValidatorSet`/`ValidatorKeyHistory` genesis dedup).
    pub fn with_genesis(genesis: impl IntoIterator<Item = (ValidatorId, NodeId)>) -> Self {
        let mut h = Self::new();
        for (validator, operator_pubkey) in genesis {
            h.by_stable_id
                .entry(validator.into_node_id())
                .or_insert_with(|| {
                    vec![OperatorKeyEntry {
                        v_eff: View::ZERO,
                        operator_pubkey,
                    }]
                });
        }
        h
    }

    /// Apply an operator-key rotation for an already-seeded validator.
    /// `v_eff` must be strictly greater than the most recent entry's `v_eff`
    /// so a single view never has an ambiguous operator key (also the replay
    /// guard). Used by the operator self-rotation commit path (a follow-up
    /// PR).
    pub fn apply_rotation(
        &mut self,
        stable_id: &ValidatorId,
        v_eff: impl Into<View>,
        new_operator_pubkey: NodeId,
    ) -> Result<(), OperatorHistoryError> {
        let v_eff = v_eff.into();
        let stable_id = stable_id.into_node_id();
        let entries = self
            .by_stable_id
            .get_mut(&stable_id)
            .ok_or(OperatorHistoryError::UnknownValidator { stable_id })?;
        let last = entries
            .last()
            .expect("by_stable_id is never inserted with an empty Vec");
        if v_eff <= last.v_eff {
            return Err(OperatorHistoryError::VeffNotStrictlyIncreasing {
                last_v_eff: last.v_eff,
                v_eff,
            });
        }
        entries.push(OperatorKeyEntry {
            v_eff,
            operator_pubkey: new_operator_pubkey,
        });
        Ok(())
    }

    /// Whether `validator` has an operator-key history.
    pub fn contains(&self, validator: &ValidatorId) -> bool {
        self.by_stable_id.contains_key(validator.as_node_id())
    }

    /// The operator key active for `validator` at `view` — the entry with the
    /// largest `v_eff <= view`. `None` if the validator has no operator-key
    /// history. An operator-signed action committing at view `V` verifies
    /// against `key_at(validator, V)`.
    pub fn key_at(&self, validator: &ValidatorId, view: impl Into<View>) -> Option<NodeId> {
        let view = view.into();
        let entries = self.by_stable_id.get(validator.as_node_id())?;
        let i = entries.partition_point(|e| e.v_eff <= view);
        if i == 0 {
            return None;
        }
        Some(entries[i - 1].operator_pubkey)
    }

    /// The most recent operator key on file for `validator`.
    pub fn current_key(&self, validator: &ValidatorId) -> Option<NodeId> {
        self.by_stable_id
            .get(validator.as_node_id())?
            .last()
            .map(|e| e.operator_pubkey)
    }

    /// Number of validators with an operator-key history.
    pub fn len(&self) -> usize {
        self.by_stable_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_stable_id.is_empty()
    }

    /// Snapshot into a serializable wire form for durable persistence. Mirrors
    /// the other histories' `to_persisted` so all three flush side-by-side.
    pub fn to_persisted(&self) -> PersistedOperatorKeyHistory {
        let validators = self
            .by_stable_id
            .iter()
            .map(|(stable_id, entries)| PersistedOperatorValidator {
                stable_id: *stable_id,
                entries: entries
                    .iter()
                    .map(|e| PersistedOperatorKeyEntry {
                        v_eff: e.v_eff,
                        operator_pubkey: e.operator_pubkey,
                    })
                    .collect(),
            })
            .collect();
        PersistedOperatorKeyHistory { validators }
    }

    /// Rebuild from the persisted form. Validates that every validator has at
    /// least one entry and that entries are strictly `v_eff`-increasing.
    pub fn from_persisted(persisted: PersistedOperatorKeyHistory) -> anyhow::Result<Self> {
        let mut h = Self::new();
        for v in persisted.validators {
            if v.entries.is_empty() {
                anyhow::bail!(
                    "persisted operator validator {} has no entries",
                    hex::encode(v.stable_id),
                );
            }
            let mut last_v_eff: Option<View> = None;
            let mut local: Vec<OperatorKeyEntry> = Vec::with_capacity(v.entries.len());
            for entry in v.entries {
                if let Some(prev) = last_v_eff
                    && entry.v_eff <= prev
                {
                    anyhow::bail!(
                        "persisted operator validator {}'s entries not strictly \
                         v_eff-increasing: got {} after {}",
                        hex::encode(v.stable_id),
                        entry.v_eff,
                        prev,
                    );
                }
                last_v_eff = Some(entry.v_eff);
                local.push(OperatorKeyEntry {
                    v_eff: entry.v_eff,
                    operator_pubkey: entry.operator_pubkey,
                });
            }
            h.by_stable_id.insert(v.stable_id, local);
        }
        Ok(h)
    }
}

/// Serializable form of an [`OperatorKeyHistory`] (postcard-stable: no maps,
/// no floats), mirroring `PersistedBlsKeyHistory`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedOperatorKeyHistory {
    pub validators: Vec<PersistedOperatorValidator>,
}

/// One validator's operator-key timeline in persisted form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedOperatorValidator {
    pub stable_id: NodeId,
    pub entries: Vec<PersistedOperatorKeyEntry>,
}

/// One `(v_eff, operator_pubkey)` entry in persisted form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedOperatorKeyEntry {
    pub v_eff: View,
    pub operator_pubkey: NodeId,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vid(b: u8) -> ValidatorId {
        ValidatorId::from_genesis_pubkey([b; 32])
    }
    fn opk(b: u8) -> NodeId {
        [b; 32]
    }

    #[test]
    fn genesis_seeds_operator_keys_active_from_view_zero() {
        let h = OperatorKeyHistory::with_genesis([(vid(1), opk(0x11)), (vid(2), opk(0x22))]);
        assert_eq!(h.len(), 2);
        assert_eq!(h.key_at(&vid(1), 0u64), Some(opk(0x11)));
        assert_eq!(h.key_at(&vid(1), 99u64), Some(opk(0x11)));
        assert_eq!(h.current_key(&vid(2)), Some(opk(0x22)));
        assert!(h.contains(&vid(1)));
        assert!(!h.contains(&vid(3)));
        // A validator with no history resolves to nothing.
        assert_eq!(h.key_at(&vid(3), 5u64), None);
    }

    #[test]
    fn genesis_dedups_a_repeated_validator() {
        let h = OperatorKeyHistory::with_genesis([(vid(1), opk(0x11)), (vid(1), opk(0xff))]);
        assert_eq!(h.len(), 1);
        // First entry wins, matching ValidatorSet/key-history genesis dedup.
        assert_eq!(h.current_key(&vid(1)), Some(opk(0x11)));
    }

    #[test]
    fn rotation_appends_and_lookup_is_view_scoped() {
        let mut h = OperatorKeyHistory::with_genesis([(vid(1), opk(0x11))]);
        h.apply_rotation(&vid(1), 10u64, opk(0x22)).unwrap();
        // Before v_eff: still the genesis key. At/after: the new key.
        assert_eq!(h.key_at(&vid(1), 9u64), Some(opk(0x11)));
        assert_eq!(h.key_at(&vid(1), 10u64), Some(opk(0x22)));
        assert_eq!(h.key_at(&vid(1), 11u64), Some(opk(0x22)));
        assert_eq!(h.current_key(&vid(1)), Some(opk(0x22)));
    }

    #[test]
    fn rotation_rejects_non_monotonic_v_eff_and_unknown_validator() {
        let mut h = OperatorKeyHistory::with_genesis([(vid(1), opk(0x11))]);
        h.apply_rotation(&vid(1), 10u64, opk(0x22)).unwrap();
        // v_eff not strictly increasing (== last) is rejected (replay guard).
        assert_eq!(
            h.apply_rotation(&vid(1), 10u64, opk(0x33)),
            Err(OperatorHistoryError::VeffNotStrictlyIncreasing {
                last_v_eff: View(10),
                v_eff: View(10),
            }),
        );
        // Unknown validator.
        assert_eq!(
            h.apply_rotation(&vid(9), 1u64, opk(0x99)),
            Err(OperatorHistoryError::UnknownValidator {
                stable_id: [9u8; 32],
            }),
        );
    }

    #[test]
    fn persisted_roundtrip_preserves_the_timeline() {
        let mut h = OperatorKeyHistory::with_genesis([(vid(1), opk(0x11)), (vid(2), opk(0x22))]);
        h.apply_rotation(&vid(1), 7u64, opk(0xaa)).unwrap();
        let restored = OperatorKeyHistory::from_persisted(h.to_persisted()).unwrap();
        assert_eq!(restored.key_at(&vid(1), 6u64), Some(opk(0x11)));
        assert_eq!(restored.key_at(&vid(1), 7u64), Some(opk(0xaa)));
        assert_eq!(restored.current_key(&vid(2)), Some(opk(0x22)));
        assert_eq!(restored.to_persisted(), h.to_persisted());
    }

    #[test]
    fn from_persisted_rejects_non_monotonic_entries() {
        let bad = PersistedOperatorKeyHistory {
            validators: vec![PersistedOperatorValidator {
                stable_id: [1u8; 32],
                entries: vec![
                    PersistedOperatorKeyEntry {
                        v_eff: View(0),
                        operator_pubkey: opk(0x11),
                    },
                    PersistedOperatorKeyEntry {
                        v_eff: View(0),
                        operator_pubkey: opk(0x22),
                    },
                ],
            }],
        };
        assert!(OperatorKeyHistory::from_persisted(bad).is_err());
    }
}
