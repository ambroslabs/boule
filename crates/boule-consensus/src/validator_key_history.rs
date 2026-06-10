use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::View;
use crate::validator_history::ValidatorSetHistory;
use crate::validator_rotation::{RotationStructuralError, ValidatorKeyRotation};
use crate::validator_set::{Pubkey, ValidatorId};
use boule_core::identity::NodeId;

#[derive(Debug, Clone, PartialEq, Eq)]
struct KeyEntry {
    v_eff: View,
    pubkey: NodeId,
}

#[derive(Debug, Clone, Default)]
pub struct ValidatorKeyHistory {
    by_stable_id: BTreeMap<NodeId, Vec<KeyEntry>>,
    pubkey_to_stable_id: BTreeMap<NodeId, NodeId>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum HistoryError {
    Structural(RotationStructuralError),

    UnknownValidator {
        validator: NodeId,
    },

    VeffNotStrictlyIncreasing {
        last_v_eff: View,
        v_eff: View,
    },

    NewKeyCollidesWithOtherValidator {
        new_pubkey: NodeId,
        owner: NodeId,
    },

    NoPendingRotationToCancel {
        validator: NodeId,
        cancelling_v_eff: View,
    },
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
            Self::NoPendingRotationToCancel {
                validator,
                cancelling_v_eff,
            } => write!(
                f,
                "no pending rotation at v_eff={cancelling_v_eff} to cancel for validator {}",
                hex::encode(validator),
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
    pub fn new(genesis_validators: impl IntoIterator<Item = ValidatorId>) -> Self {
        let mut h = Self::default();
        for v in genesis_validators {
            let bytes: NodeId = v.into_node_id();

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

    pub fn validator_for(&self, pubkey: &Pubkey) -> Option<ValidatorId> {
        self.pubkey_to_stable_id
            .get(pubkey.as_node_id())
            .copied()
            .map(ValidatorId::from_genesis_pubkey)
    }

    pub fn key_at(&self, validator: &ValidatorId, view: impl Into<View>) -> Option<Pubkey> {
        let view = view.into();
        let entries = self.by_stable_id.get(validator.as_node_id())?;

        let idx = entries.partition_point(|e| e.v_eff <= view);
        if idx == 0 {
            return None;
        }
        Some(Pubkey::from_node_id(entries[idx - 1].pubkey))
    }

    pub fn key_at_for_pubkey(
        &self,
        pubkey_anywhere: &Pubkey,
        view: impl Into<View>,
    ) -> Option<Pubkey> {
        let view = view.into();
        let validator = self.validator_for(pubkey_anywhere)?;
        self.key_at(&validator, view)
    }

    pub fn current_key(&self, pubkey_anywhere_in_history: &Pubkey) -> Option<Pubkey> {
        let stable_id = self
            .pubkey_to_stable_id
            .get(pubkey_anywhere_in_history.as_node_id())?;
        let entries = self.by_stable_id.get(stable_id)?;
        entries.last().map(|e| Pubkey::from_node_id(e.pubkey))
    }

    pub fn validators(&self) -> impl Iterator<Item = ValidatorId> + '_ {
        self.by_stable_id
            .keys()
            .copied()
            .map(ValidatorId::from_genesis_pubkey)
    }

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

    pub fn pending_rotation_new_key(
        &self,
        validator: &Pubkey,
        cancelling_v_eff: View,
        commit_view: View,
    ) -> Option<Pubkey> {
        let stable_id = self.pubkey_to_stable_id.get(validator.as_node_id())?;
        let last = self.by_stable_id.get(stable_id)?.last()?;
        (last.v_eff == cancelling_v_eff && cancelling_v_eff > commit_view)
            .then(|| Pubkey::from_node_id(last.pubkey))
    }

    pub fn cancel_pending_rotation(
        &mut self,
        validator: &Pubkey,
        cancelling_v_eff: View,
        commit_view: View,
    ) -> Result<Pubkey, HistoryError> {
        let no_pending = || HistoryError::NoPendingRotationToCancel {
            validator: *validator.as_node_id(),
            cancelling_v_eff,
        };
        let stable_id = *self
            .pubkey_to_stable_id
            .get(validator.as_node_id())
            .ok_or_else(no_pending)?;
        let entries = self
            .by_stable_id
            .get_mut(&stable_id)
            .expect("reverse index points to a stable_id with no history");
        let last = entries.last().expect("history list is non-empty");
        if last.v_eff != cancelling_v_eff || cancelling_v_eff <= commit_view {
            return Err(no_pending());
        }
        let removed = entries.pop().expect("checked non-empty").pubkey;
        self.pubkey_to_stable_id.remove(&removed);
        Ok(Pubkey::from_node_id(removed))
    }

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

    pub fn from_persisted(persisted: PersistedValidatorKeyHistory) -> anyhow::Result<Self> {
        let mut h = Self::default();
        for v in persisted.validators {
            if v.entries.is_empty() {
                anyhow::bail!(
                    "persisted validator {} has no entries",
                    hex::encode(v.stable_id)
                );
            }

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedKeyEntry {
    pub v_eff: View,
    pub pubkey: NodeId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedValidator {
    pub stable_id: NodeId,
    pub entries: Vec<PersistedKeyEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedValidatorKeyHistory {
    pub validators: Vec<PersistedValidator>,
}
