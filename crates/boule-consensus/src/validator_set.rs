//! The ordered, deduplicated committee that participates in consensus.
//!
//! [`ValidatorSet::new`] sorts and deduplicates on construction, so two
//! sets over the same [`ValidatorId`]s are byte-identical and index
//! identically. Selectors such as
//! [`super::pacemaker::leader::RoundRobinSelector`] rely on this stable
//! indexing (`validators[view % len]`) to pick the same leader on every
//! replica.
//!
//! # Stable identity vs ephemeral signing key
//!
//! [`ValidatorId`] and [`Pubkey`] are distinct newtypes over [`NodeId`]:
//!
//! - [`ValidatorId`] — a validator's stable identity, equal to the
//!   founding key it joined the set with (at chain genesis or a later
//!   reconfig) and fixed for its lifetime regardless of key rotations.
//!   This is what [`ValidatorSet`] membership and slashing evidence key
//!   on.
//! - [`Pubkey`] — the consensus signing key a validator uses at a given
//!   view, which changes on rotation.
//!
//! The split is a type-system guard: a function taking a [`ValidatorId`]
//! cannot be passed an ephemeral [`Pubkey`] by mistake. A [`ValidatorId`]
//! can only be obtained from a genesis pubkey
//! ([`ValidatorId::from_genesis_pubkey`]) or via the reverse-index lookup
//! [`super::validator_key_history::ValidatorKeyHistory::validator_for`];
//! there is no conversion from arbitrary bytes or from [`Pubkey`].
//!
//! Both newtypes are `#[serde(transparent)]` over [`NodeId`], so wire
//! format and storage are identical to the raw `NodeId`.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use boule_core::identity::NodeId;

/// A validator's stable identity: the pubkey it joined the set with (at
/// chain genesis or a later reconfig add), fixed for its lifetime across
/// any number of key rotations.
///
/// Two [`ValidatorId`]s are equal iff they refer to the same validator.
/// This is the type used for [`ValidatorSet`] membership and slashing
/// evidence; it is not the type carried on the wire (that is [`Pubkey`]).
///
/// # Constructors
///
/// - [`Self::from_genesis_pubkey`] — the only constructor taking raw
///   bytes; valid only for a founding key, before any rotation.
/// - [`super::validator_key_history::ValidatorKeyHistory::validator_for`]
///   — maps any pubkey a validator has ever used to its stable id.
///
/// There is no `From<NodeId>` or `From<Pubkey>`: arbitrary bytes cannot
/// be promoted to a stable identity without going through one of the
/// constructors above. The doctest below enforces this.
///
/// `Serialize`/`Deserialize` are `#[serde(transparent)]`, so the postcard
/// bytes match those of the inner [`NodeId`].
///
/// ```compile_fail
/// # use boule_consensus::validator_set::{ValidatorId, Pubkey};
/// # use boule_core::identity::NodeId;
/// let pk: Pubkey = NodeId::default().into();
/// let _: ValidatorId = pk.into(); // no such conversion
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
#[repr(transparent)]
pub struct ValidatorId(NodeId);

impl ValidatorId {
    /// Promote a founding pubkey to a stable validator id. The only
    /// constructor taking raw bytes; valid only when a validator first
    /// joins the set (chain genesis or a reconfig add), before any
    /// rotation has separated the stable id from the signing key.
    pub const fn from_genesis_pubkey(node_id: NodeId) -> Self {
        Self(node_id)
    }

    /// Borrow the underlying `NodeId` bytes.
    pub const fn as_node_id(&self) -> &NodeId {
        &self.0
    }

    /// Move out the underlying `NodeId` bytes.
    pub const fn into_node_id(self) -> NodeId {
        self.0
    }
}

impl From<ValidatorId> for NodeId {
    fn from(v: ValidatorId) -> NodeId {
        v.0
    }
}

/// A validator's consensus signing key at a given view. Changes on key
/// rotation; distinct from the stable [`ValidatorId`] so the two cannot
/// be confused in a function signature.
///
/// Converts freely to and from [`NodeId`] in both directions
/// (`From<NodeId>` / [`Self::from_node_id`] and `From<Pubkey>`); a
/// `NodeId` on the wire is already a pubkey, so the conversion is an
/// unvalidated re-tag. Same wire shape as [`NodeId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
#[repr(transparent)]
pub struct Pubkey(NodeId);

impl Pubkey {
    /// Re-tag a `NodeId` as a `Pubkey`. Cheap, no validation — a
    /// `NodeId` on the wire **is** a pubkey.
    pub const fn from_node_id(node_id: NodeId) -> Self {
        Self(node_id)
    }

    /// Borrow the underlying `NodeId` bytes.
    pub const fn as_node_id(&self) -> &NodeId {
        &self.0
    }

    /// Move out the underlying `NodeId` bytes.
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

/// An ordered, deduplicated set of [`ValidatorId`]s, each with a `u64`
/// voting weight.
///
/// Members are sorted ascending (byte-lexicographic over the inner
/// `NodeId`) with no duplicates. Weights are a parallel array indexed
/// identically: `weight_at(i)` is the weight of `members[i]`. Both arrays
/// are `Arc`-backed, so `Clone` is zero-cost.
///
/// Constructors that don't take explicit weights default every member to
/// weight `1`, under which weighted quorum reduces to count-based quorum.
///
/// A weight of `0` is rejected at construction
/// ([`WeightedSetError::ZeroWeight`]): the only representation of "not
/// voting" is absence from the set, and `0` would also be a
/// divide-by-zero hazard for stake-proportional math.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorSet {
    members: Arc<[ValidatorId]>,
    weights: Arc<[u64]>,
}

/// Errors returned by [`ValidatorSet::with_weights`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WeightedSetError {
    /// A weight entry was zero. Use the reconfig "remove" path instead.
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
    /// Construct a validator set from `members`, sorted ascending and
    /// deduplicated. Every weight defaults to `1`. Inputs differing only
    /// in order produce equal sets.
    pub fn new(mut members: Vec<ValidatorId>) -> Self {
        members.sort_unstable();
        members.dedup();
        let n = members.len();
        Self {
            members: members.into(),
            weights: vec![1u64; n].into(),
        }
    }

    /// Construct a weighted validator set. `entries` is sorted by
    /// [`ValidatorId`] and deduplicated, keeping the first weight
    /// supplied for each id. Returns [`WeightedSetError::ZeroWeight`] if
    /// any entry has weight `0`.
    pub fn with_weights(mut entries: Vec<(ValidatorId, u64)>) -> Result<Self, WeightedSetError> {
        for (i, (_, w)) in entries.iter().enumerate() {
            if *w == 0 {
                return Err(WeightedSetError::ZeroWeight { index: i });
            }
        }
        // Stable sort so first-wins on dedup is well-defined: equal
        // ValidatorIds keep the order they were supplied in.
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

    /// Voting weight at sorted index `idx`. Panics if out of range.
    pub fn weight_at(&self, idx: usize) -> u64 {
        self.weights[idx]
    }

    /// Voting weight for `id`, or `None` if not a member.
    pub fn weight_for(&self, id: &ValidatorId) -> Option<u64> {
        self.index_of(id).map(|i| self.weights[i])
    }

    /// Sum of all member weights, as `u128` so near-`u64::MAX` weights
    /// don't wrap.
    pub fn total_weight(&self) -> u128 {
        self.weights.iter().map(|w| u128::from(*w)).sum()
    }

    /// Iterate `(&ValidatorId, u64)` pairs in sorted order.
    pub fn iter_weighted(&self) -> impl Iterator<Item = (&ValidatorId, u64)> + '_ {
        self.members.iter().zip(self.weights.iter().copied())
    }

    /// Borrow the parallel weights slice. Same length and ordering as
    /// the member slice.
    pub fn weights(&self) -> &[u64] {
        &self.weights
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vid(b: u8) -> ValidatorId {
        ValidatorId::from_genesis_pubkey([b; 32])
    }

    #[test]
    fn new_sorts_and_dedups() {
        let v = ValidatorSet::new(vec![vid(3), vid(1), vid(2), vid(1)]);
        assert_eq!(v.len(), 3);
        assert_eq!(v.get(0), Some(&vid(1)));
        assert_eq!(v.get(1), Some(&vid(2)));
        assert_eq!(v.get(2), Some(&vid(3)));
    }

    #[test]
    fn equal_sets_from_different_input_orders() {
        let a = ValidatorSet::new(vec![vid(3), vid(1), vid(2)]);
        let b = ValidatorSet::new(vec![vid(1), vid(2), vid(3)]);
        assert_eq!(a, b);
    }

    #[test]
    fn empty_set() {
        let v = ValidatorSet::new(vec![]);
        assert!(v.is_empty());
        assert_eq!(v.len(), 0);
        assert_eq!(v.get(0), None);
        assert!(!v.contains(&vid(0)));
        assert_eq!(v.index_of(&vid(0)), None);
    }

    #[test]
    fn contains_and_index_of_are_consistent() {
        let v = ValidatorSet::new(vec![vid(10), vid(20), vid(30)]);
        for i in 0..v.len() {
            let m = v.get(i).unwrap();
            assert!(v.contains(m));
            assert_eq!(v.index_of(m), Some(i));
        }
        assert!(!v.contains(&vid(99)));
        assert_eq!(v.index_of(&vid(99)), None);
    }

    #[test]
    fn iter_yields_sorted_order() {
        let v = ValidatorSet::new(vec![vid(5), vid(2), vid(8)]);
        let collected: Vec<_> = v.iter().copied().collect();
        assert_eq!(collected, vec![vid(2), vid(5), vid(8)]);
    }

    /// `#[serde(transparent)]` makes the postcard bytes of `ValidatorId`
    /// identical to those of the inner `NodeId`.
    #[test]
    fn validator_id_serializes_as_inner_node_id() {
        let id: ValidatorId = ValidatorId::from_genesis_pubkey([0xAB; 32]);
        let inner: NodeId = [0xAB; 32];
        assert_eq!(
            postcard::to_stdvec(&id).unwrap(),
            postcard::to_stdvec(&inner).unwrap(),
        );
    }

    #[test]
    fn pubkey_serializes_as_inner_node_id() {
        let pk: Pubkey = Pubkey::from_node_id([0x77; 32]);
        let inner: NodeId = [0x77; 32];
        assert_eq!(
            postcard::to_stdvec(&pk).unwrap(),
            postcard::to_stdvec(&inner).unwrap(),
        );
    }

    // ── per-validator weight ────────────────────────────────────────────

    #[test]
    fn new_defaults_all_weights_to_one() {
        let v = ValidatorSet::new(vec![vid(3), vid(1), vid(2)]);
        for i in 0..v.len() {
            assert_eq!(v.weight_at(i), 1);
        }
        assert_eq!(v.total_weight(), 3u128);
    }

    #[test]
    fn with_weights_sorts_and_aligns_weights() {
        // Insertion-order weights paired with arbitrary ValidatorIds:
        // after sort by id, weights must follow the members.
        let v = ValidatorSet::with_weights(vec![(vid(3), 30), (vid(1), 10), (vid(2), 20)]).unwrap();
        assert_eq!(v.get(0), Some(&vid(1)));
        assert_eq!(v.get(1), Some(&vid(2)));
        assert_eq!(v.get(2), Some(&vid(3)));
        assert_eq!(v.weight_at(0), 10);
        assert_eq!(v.weight_at(1), 20);
        assert_eq!(v.weight_at(2), 30);
        assert_eq!(v.weight_for(&vid(2)), Some(20));
        assert_eq!(v.weight_for(&vid(99)), None);
        assert_eq!(v.total_weight(), 60u128);
    }

    #[test]
    fn with_weights_dedups_keeping_first_weight_supplied() {
        // First-wins on duplicates. Stable sort preserves input order
        // among equal ValidatorIds, so the first input weight survives.
        let v = ValidatorSet::with_weights(vec![(vid(1), 7), (vid(1), 99), (vid(2), 5)]).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v.weight_at(0), 7); // not 99
        assert_eq!(v.weight_at(1), 5);
    }

    #[test]
    fn with_weights_rejects_zero_weight() {
        let err =
            ValidatorSet::with_weights(vec![(vid(1), 1), (vid(2), 0), (vid(3), 1)]).unwrap_err();
        assert!(matches!(err, WeightedSetError::ZeroWeight { index: 1 }));
    }

    #[test]
    fn total_weight_is_u128_and_does_not_wrap_near_u64_max() {
        // Two u64::MAX weights sum to 2 * u64::MAX, which fits in u128.
        // Asserting against the literal u128 sum rules out a u64 wrap.
        let v =
            ValidatorSet::with_weights(vec![(vid(1), u64::MAX), (vid(2), u64::MAX), (vid(3), 1)])
                .unwrap();
        let expected: u128 = (u64::MAX as u128) * 2 + 1;
        assert_eq!(v.total_weight(), expected);
    }

    #[test]
    fn iter_weighted_yields_sorted_pairs() {
        let v = ValidatorSet::with_weights(vec![(vid(5), 50), (vid(2), 20), (vid(8), 80)]).unwrap();
        let pairs: Vec<(ValidatorId, u64)> = v.iter_weighted().map(|(id, w)| (*id, w)).collect();
        assert_eq!(pairs, vec![(vid(2), 20), (vid(5), 50), (vid(8), 80)]);
    }

    #[test]
    fn weights_slice_matches_members_slice_length() {
        let v = ValidatorSet::with_weights(vec![(vid(1), 1), (vid(2), 7)]).unwrap();
        assert_eq!(v.weights().len(), v.len());
        assert_eq!(v.weights(), &[1, 7]);
    }
}
