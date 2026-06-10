use std::sync::Arc;

use serde::{Deserialize, Serialize};

use boule_core::identity::NodeId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
#[repr(transparent)]
pub struct ValidatorId(NodeId);

impl ValidatorId {
    pub const fn from_genesis_pubkey(node_id: NodeId) -> Self {
        Self(node_id)
    }

    pub const fn as_node_id(&self) -> &NodeId {
        &self.0
    }

    pub const fn into_node_id(self) -> NodeId {
        self.0
    }
}

impl From<ValidatorId> for NodeId {
    fn from(v: ValidatorId) -> NodeId {
        v.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
#[repr(transparent)]
pub struct Pubkey(NodeId);

impl Pubkey {
    pub const fn from_node_id(node_id: NodeId) -> Self {
        Self(node_id)
    }

    pub const fn as_node_id(&self) -> &NodeId {
        &self.0
    }

    pub const fn into_node_id(self) -> NodeId {
        self.0
    }
}

impl From<NodeId> for Pubkey {
    fn from(n: NodeId) -> Pubkey {
        Pubkey(n)
    }
}

impl From<Pubkey> for NodeId {
    fn from(p: Pubkey) -> NodeId {
        p.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorSet {
    members: Arc<[ValidatorId]>,
    weights: Arc<[u64]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WeightedSetError {
    ZeroWeight { index: usize },
}

impl std::fmt::Display for WeightedSetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WeightedSetError::ZeroWeight { index } => write!(
                f,
                "validator at input index {index} has weight 0; weight 0 is reserved — \
                 remove the validator via reconfig instead"
            ),
        }
    }
}

impl std::error::Error for WeightedSetError {}

impl ValidatorSet {
    pub fn new(mut members: Vec<ValidatorId>) -> Self {
        members.sort_unstable();
        members.dedup();
        let n = members.len();
        Self {
            members: members.into(),
            weights: vec![1u64; n].into(),
        }
    }

    pub fn with_weights(mut entries: Vec<(ValidatorId, u64)>) -> Result<Self, WeightedSetError> {
        for (i, (_, w)) in entries.iter().enumerate() {
            if *w == 0 {
                return Err(WeightedSetError::ZeroWeight { index: i });
            }
        }

        entries.sort_by_key(|e| e.0);
        entries.dedup_by(|a, b| a.0 == b.0);
        let mut members = Vec::with_capacity(entries.len());
        let mut weights = Vec::with_capacity(entries.len());
        for (id, w) in entries {
            members.push(id);
            weights.push(w);
        }
        Ok(Self {
            members: members.into(),
            weights: weights.into(),
        })
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    pub fn get(&self, idx: usize) -> Option<&ValidatorId> {
        self.members.get(idx)
    }

    pub fn contains(&self, id: &ValidatorId) -> bool {
        self.members.binary_search(id).is_ok()
    }

    pub fn index_of(&self, id: &ValidatorId) -> Option<usize> {
        self.members.binary_search(id).ok()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, ValidatorId> {
        self.members.iter()
    }

    pub fn weight_at(&self, idx: usize) -> u64 {
        self.weights[idx]
    }

    pub fn weight_for(&self, id: &ValidatorId) -> Option<u64> {
        self.index_of(id).map(|i| self.weights[i])
    }

    pub fn total_weight(&self) -> u128 {
        self.weights.iter().map(|w| u128::from(*w)).sum()
    }

    pub fn iter_weighted(&self) -> impl Iterator<Item = (&ValidatorId, u64)> + '_ {
        self.members.iter().zip(self.weights.iter().copied())
    }

    pub fn weights(&self) -> &[u64] {
        &self.weights
    }
}
