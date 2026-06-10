use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::View;
use crate::validator_set::ValidatorSet;
use boule_core::crypto::sig_scheme::BlsPublicKey;
use boule_core::identity::NodeId;

#[derive(Debug, Clone, PartialEq, Eq)]
struct BlsKeyEntry {
    v_eff: View,
    bls_pubkey: BlsPublicKey,
}

#[derive(Debug, Clone, Default)]
pub struct BlsKeyHistory {
    by_stable_id: BTreeMap<NodeId, Vec<BlsKeyEntry>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum BlsHistoryError {
    AlreadyRegistered { stable_id: NodeId },

    UnknownValidator { stable_id: NodeId },

    VeffNotStrictlyIncreasing { last_v_eff: View, v_eff: View },

    NoPendingRotationToCancel { stable_id: NodeId, v_eff: View },
}

#[derive(Debug, PartialEq, Eq)]
pub struct MissingBlsPubkey {
    pub stable_id: NodeId,
    pub view: View,
}

impl std::fmt::Display for MissingBlsPubkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "no BLS pubkey for validator {} at view {}",
            hex::encode(self.stable_id),
            self.view,
        )
    }
}

impl std::error::Error for MissingBlsPubkey {}

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
            Self::NoPendingRotationToCancel { stable_id, v_eff } => write!(
                f,
                "no pending BLS rotation at v_eff {v_eff} to cancel for validator {}",
                hex::encode(stable_id),
            ),
        }
    }
}

impl std::error::Error for BlsHistoryError {}

impl BlsKeyHistory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_genesis(genesis: impl IntoIterator<Item = (NodeId, BlsPublicKey)>) -> Self {
        let mut h = Self::new();
        for (stable_id, bls_pubkey) in genesis {
            h.by_stable_id.insert(
                stable_id,
                vec![BlsKeyEntry {
                    v_eff: View::ZERO,
                    bls_pubkey,
                }],
            );
        }
        h
    }

    pub fn register(
        &mut self,
        stable_id: NodeId,
        v_eff: impl Into<View>,
        bls_pubkey: BlsPublicKey,
    ) -> Result<(), BlsHistoryError> {
        let v_eff = v_eff.into();
        if self.by_stable_id.contains_key(&stable_id) {
            return Err(BlsHistoryError::AlreadyRegistered { stable_id });
        }
        self.by_stable_id
            .insert(stable_id, vec![BlsKeyEntry { v_eff, bls_pubkey }]);
        Ok(())
    }

    pub fn apply_rotation(
        &mut self,
        stable_id: NodeId,
        v_eff: impl Into<View>,
        new_bls_pubkey: BlsPublicKey,
    ) -> Result<(), BlsHistoryError> {
        let v_eff = v_eff.into();
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

    pub fn cancel_pending_rotation(
        &mut self,
        stable_id: NodeId,
        cancelling_v_eff: View,
        commit_view: View,
    ) -> Result<(), BlsHistoryError> {
        let entries = self
            .by_stable_id
            .get_mut(&stable_id)
            .ok_or(BlsHistoryError::UnknownValidator { stable_id })?;
        let last = entries
            .last()
            .expect("by_stable_id never holds an empty Vec");
        if last.v_eff != cancelling_v_eff || cancelling_v_eff <= commit_view {
            return Err(BlsHistoryError::NoPendingRotationToCancel {
                stable_id,
                v_eff: cancelling_v_eff,
            });
        }
        entries.pop();
        Ok(())
    }

    pub fn contains(&self, stable_id: &NodeId) -> bool {
        self.by_stable_id.contains_key(stable_id)
    }

    pub fn key_at(&self, stable_id: &NodeId, view: impl Into<View>) -> Option<BlsPublicKey> {
        let view = view.into();
        let entries = self.by_stable_id.get(stable_id)?;

        let i = entries.partition_point(|e| e.v_eff <= view);
        if i == 0 {
            return None;
        }
        Some(entries[i - 1].bls_pubkey)
    }

    pub fn pubkeys_for_set(
        &self,
        set: &ValidatorSet,
        view: impl Into<View>,
    ) -> Result<Vec<BlsPublicKey>, MissingBlsPubkey> {
        let view = view.into();
        let mut out = Vec::with_capacity(set.len());
        for stable_id in set.iter() {
            let bytes = stable_id.as_node_id();
            match self.key_at(bytes, view) {
                Some(pk) => out.push(pk),
                None => {
                    return Err(MissingBlsPubkey {
                        stable_id: *bytes,
                        view,
                    });
                }
            }
        }
        Ok(out)
    }

    pub fn current_key(&self, stable_id: &NodeId) -> Option<BlsPublicKey> {
        self.by_stable_id
            .get(stable_id)?
            .last()
            .map(|e| e.bls_pubkey)
    }

    pub fn len(&self) -> usize {
        self.by_stable_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_stable_id.is_empty()
    }

    pub fn to_persisted(&self) -> PersistedBlsKeyHistory {
        let validators = self
            .by_stable_id
            .iter()
            .map(|(stable_id, entries)| PersistedBlsValidator {
                stable_id: *stable_id,
                entries: entries
                    .iter()
                    .map(|e| PersistedBlsKeyEntry {
                        v_eff: e.v_eff,
                        bls_pubkey: e.bls_pubkey,
                    })
                    .collect(),
            })
            .collect();
        PersistedBlsKeyHistory { validators }
    }

    pub fn from_persisted(persisted: PersistedBlsKeyHistory) -> anyhow::Result<Self> {
        let mut h = Self::default();
        for v in persisted.validators {
            if v.entries.is_empty() {
                anyhow::bail!(
                    "persisted BLS validator {} has no entries",
                    hex::encode(v.stable_id),
                );
            }
            let mut last_v_eff: Option<View> = None;
            let mut local: Vec<BlsKeyEntry> = Vec::with_capacity(v.entries.len());
            for entry in v.entries {
                if let Some(prev) = last_v_eff
                    && entry.v_eff <= prev
                {
                    anyhow::bail!(
                        "persisted BLS validator {}'s entries not strictly v_eff-increasing: \
                         got {} after {}",
                        hex::encode(v.stable_id),
                        entry.v_eff,
                        prev,
                    );
                }
                last_v_eff = Some(entry.v_eff);
                local.push(BlsKeyEntry {
                    v_eff: entry.v_eff,
                    bls_pubkey: entry.bls_pubkey,
                });
            }
            h.by_stable_id.insert(v.stable_id, local);
        }
        Ok(h)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedBlsKeyEntry {
    pub v_eff: View,

    #[serde(with = "serde_bls_pubkey")]
    pub bls_pubkey: BlsPublicKey,
}

mod serde_bls_pubkey {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(pk: &[u8; 48], s: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&pk[..], s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 48], D::Error> {
        let v: Vec<u8> = Vec::<u8>::deserialize(d)?;
        v.as_slice()
            .try_into()
            .map_err(|_| D::Error::custom("BLS pubkey must be exactly 48 bytes"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedBlsValidator {
    pub stable_id: NodeId,
    pub entries: Vec<PersistedBlsKeyEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedBlsKeyHistory {
    pub validators: Vec<PersistedBlsValidator>,
}
