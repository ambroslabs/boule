use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::View;
use crate::validator_set::ValidatorId;
use boule_core::identity::NodeId;

#[derive(Debug, Clone, PartialEq, Eq)]
struct OperatorKeyEntry {
    v_eff: View,
    operator_pubkey: NodeId,
}

#[derive(Debug, Clone, Default)]
pub struct OperatorKeyHistory {
    by_stable_id: BTreeMap<NodeId, Vec<OperatorKeyEntry>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum OperatorHistoryError {
    UnknownValidator { stable_id: NodeId },

    VeffNotStrictlyIncreasing { last_v_eff: View, v_eff: View },

    AlreadyRegistered { stable_id: NodeId },
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
            Self::AlreadyRegistered { stable_id } => write!(
                f,
                "operator key for validator {} already registered",
                hex::encode(stable_id),
            ),
        }
    }
}

impl std::error::Error for OperatorHistoryError {}

impl OperatorKeyHistory {
    pub fn new() -> Self {
        Self::default()
    }

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

    pub fn register(
        &mut self,
        validator: &ValidatorId,
        v_eff: impl Into<View>,
        operator_pubkey: NodeId,
    ) -> Result<(), OperatorHistoryError> {
        let v_eff = v_eff.into();
        let stable_id = validator.into_node_id();
        if self.by_stable_id.contains_key(&stable_id) {
            return Err(OperatorHistoryError::AlreadyRegistered { stable_id });
        }
        self.by_stable_id.insert(
            stable_id,
            vec![OperatorKeyEntry {
                v_eff,
                operator_pubkey,
            }],
        );
        Ok(())
    }

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

    pub fn contains(&self, validator: &ValidatorId) -> bool {
        self.by_stable_id.contains_key(validator.as_node_id())
    }

    pub fn key_at(&self, validator: &ValidatorId, view: impl Into<View>) -> Option<NodeId> {
        let view = view.into();
        let entries = self.by_stable_id.get(validator.as_node_id())?;
        let i = entries.partition_point(|e| e.v_eff <= view);
        if i == 0 {
            return None;
        }
        Some(entries[i - 1].operator_pubkey)
    }

    pub fn current_key(&self, validator: &ValidatorId) -> Option<NodeId> {
        self.by_stable_id
            .get(validator.as_node_id())?
            .last()
            .map(|e| e.operator_pubkey)
    }

    pub fn len(&self) -> usize {
        self.by_stable_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_stable_id.is_empty()
    }

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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedOperatorKeyHistory {
    pub validators: Vec<PersistedOperatorValidator>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedOperatorValidator {
    pub stable_id: NodeId,
    pub entries: Vec<PersistedOperatorKeyEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedOperatorKeyEntry {
    pub v_eff: View,
    pub operator_pubkey: NodeId,
}
