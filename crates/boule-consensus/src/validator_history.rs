use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::View;
use crate::validator_set::{ValidatorId, ValidatorSet};
use boule_core::identity::NodeId;

#[derive(Debug, Clone)]
struct Boundary {
    v_eff: View,
    set: Arc<ValidatorSet>,
}

#[derive(Debug, Clone)]
pub struct ValidatorSetHistory {
    boundaries: Vec<Boundary>,
}

impl ValidatorSetHistory {
    pub fn from_genesis(genesis: ValidatorSet) -> Self {
        Self {
            boundaries: vec![Boundary {
                v_eff: View::ZERO,
                set: Arc::new(genesis),
            }],
        }
    }

    pub fn set_at(&self, view: impl Into<View>) -> ValidatorSetAt {
        let view = view.into();
        let idx = match self.boundaries.binary_search_by_key(&view, |b| b.v_eff) {
            Ok(i) => i,

            Err(i) => i.saturating_sub(1),
        };
        ValidatorSetAt {
            view,
            set: self.boundaries[idx].set.clone(),
        }
    }

    pub fn insert_boundary(
        &mut self,
        v_eff: impl Into<View>,
        set: ValidatorSet,
    ) -> anyhow::Result<()> {
        let v_eff = v_eff.into();
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

    pub fn current_set(&self) -> Arc<ValidatorSet> {
        self.boundaries
            .last()
            .expect("history is non-empty by invariant")
            .set
            .clone()
    }

    pub fn boundary_count(&self) -> usize {
        self.boundaries.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (View, &Arc<ValidatorSet>)> {
        self.boundaries.iter().map(|b| (b.v_eff, &b.set))
    }

    pub fn to_persisted(&self) -> PersistedValidatorHistory {
        let boundaries: Vec<PersistedBoundary> = self
            .iter()
            .map(|(v_eff, set)| PersistedBoundary {
                v_eff,
                members: set.iter().map(|v| v.into_node_id()).collect(),
                weights: set.weights().to_vec(),
            })
            .collect();
        PersistedValidatorHistory { boundaries }
    }

    pub fn from_persisted(persisted: PersistedValidatorHistory) -> anyhow::Result<Self> {
        let mut iter = persisted.boundaries.into_iter();
        let genesis = iter
            .next()
            .ok_or_else(|| anyhow::anyhow!("persisted history is empty"))?;
        if genesis.v_eff != View::ZERO {
            anyhow::bail!(
                "persisted history's first boundary must be at v_eff = 0, got {}",
                genesis.v_eff
            );
        }
        let mut history = Self::from_genesis(boundary_to_set(genesis)?);
        for boundary in iter {
            let v_eff = boundary.v_eff;
            history.insert_boundary(v_eff, boundary_to_set(boundary)?)?;
        }
        Ok(history)
    }
}

fn boundary_to_set(b: PersistedBoundary) -> anyhow::Result<ValidatorSet> {
    if b.members.len() != b.weights.len() {
        anyhow::bail!(
            "persisted boundary at v_eff {}: members.len() {} != weights.len() {}",
            b.v_eff,
            b.members.len(),
            b.weights.len(),
        );
    }
    let entries: Vec<(ValidatorId, u64)> = b
        .members
        .into_iter()
        .map(ValidatorId::from_genesis_pubkey)
        .zip(b.weights)
        .collect();
    ValidatorSet::with_weights(entries)
        .map_err(|e| anyhow::anyhow!("persisted boundary at v_eff {}: {e}", b.v_eff))
}

#[derive(Debug, Clone)]
pub struct ValidatorSetAt {
    view: View,
    set: Arc<ValidatorSet>,
}

impl ValidatorSetAt {
    pub fn for_view(&self, view: impl Into<View>) -> &ValidatorSet {
        let view = view.into();
        debug_assert_eq!(
            self.view, view,
            "validator-set scope mismatch: looked up at view {}, used at view {}",
            self.view, view,
        );
        &self.set
    }

    pub fn view(&self) -> View {
        self.view
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedBoundary {
    pub v_eff: View,
    pub members: Vec<NodeId>,
    pub weights: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedValidatorHistory {
    pub boundaries: Vec<PersistedBoundary>,
}
