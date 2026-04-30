//! The ordered, deduplicated committee that participates in consensus.
//!
//! A [`ValidatorSet`] is the identity of a consensus committee: two sets
//! over the same underlying [`ValidatorId`]s have byte-identical
//! representation because [`ValidatorSet::new`] sorts and deduplicates on
//! construction. This invariant lets selectors like
//! [`super::pacemaker::leader::RoundRobinSelector`] rely on stable indexing
//! (`validators[view % len]`) — every honest replica picks the same
//! leader for a given view.
//!
//! # Stable identity vs ephemeral signing key (#328)
//!
//! [`ValidatorId`] and [`Pubkey`] are two newtypes around [`NodeId`] that
//! the consensus crate uses to keep "the slashing-correct stable
//! identity of a validator" distinct in the type system from "whatever
//! pubkey that validator is currently signing under". The runtime has
//! always observed this distinction (every call site that needs the
//! stable id goes through
//! [`super::validator_key_history::ValidatorKeyHistory::validator_for`]),
//! but until #328 the two were the same Rust type and a future slashing
//! implementation taking a [`NodeId`] could not tell at compile time
//! whether it had received a stable id or an ephemeral pubkey — exactly
//! the condition under which CometBFT's cross-key double-sign bug
//! reproduces.
//!
//! The bytes are still a [`NodeId`] under the hood, so wire format and
//! storage are unchanged. The newtypes apply at the API boundary: a
//! function that wants a stable id takes a [`ValidatorId`], and a
//! function that wants the on-the-wire signer pubkey takes a [`Pubkey`].
//! The only way to land in [`ValidatorId`] is through
//! [`ValidatorId::from_genesis_pubkey`] at config time or via the
//! [`super::validator_key_history::ValidatorKeyHistory`] reverse-index
//! lookup — there is deliberately no `From<Pubkey> for ValidatorId`
//! impl.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::p2p::NodeId;

/// Stable, unchanging identifier for a validator. Equal to its genesis
/// pubkey. The slashing-correct identity (#328 / audit finding 5-F1).
///
/// Two [`ValidatorId`]s are equal iff they refer to the same validator
/// across the validator's entire lifetime, even if that validator has
/// rotated its consensus signing key any number of times. This is the
/// type that appears in [`ValidatorSet`] membership and that a future
/// slashing path will key its evidence on; it is **not** the type the
/// wire envelope carries (that's [`Pubkey`]).
///
/// # Constructors
///
/// - [`Self::from_genesis_pubkey`] — at config-load / genesis-seeding
///   time, before any rotations could have separated stable and
///   ephemeral identities.
/// - [`super::validator_key_history::ValidatorKeyHistory::validator_for`]
///   — given any pubkey the validator has ever used (genesis, current,
///   or any rotated key), returns the stable id.
///
/// There is deliberately **no** `From<NodeId> for ValidatorId` and **no**
/// `From<Pubkey> for ValidatorId` — those would let arbitrary bytes be
/// promoted to a stable identity without going through the lookup, which
/// is the load-bearing guard for #328.
///
/// # Wire format
///
/// `Serialize`/`Deserialize` are `#[serde(transparent)]`, so the postcard
/// bytes for `ValidatorId` are byte-identical to those for the inner
/// `NodeId`. Existing on-disk and on-the-wire shapes are unchanged.
///
/// ```compile_fail
/// # use ambros_p2p::consensus::validator_set::{ValidatorId, Pubkey};
/// # use ambros_p2p::p2p::NodeId;
/// // The compile_fail guard for #328: arbitrary bytes must not be
/// // promotable to a stable validator id without going through a
/// // lookup. If a future PR adds `From<Pubkey> for ValidatorId` (or
/// // `From<NodeId> for ValidatorId`) this doctest will compile and
/// // tip the guard over.
/// let pk: Pubkey = NodeId::default().into();
/// let _: ValidatorId = pk.into();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
#[repr(transparent)]
pub struct ValidatorId(NodeId);

impl ValidatorId {
    /// Promote a genesis pubkey to a stable validator id.
    ///
    /// This is the only public constructor that takes raw bytes; the
    /// name documents that it is allowed here because we are at network
    /// birth, before any rotations could have separated stable and
    /// ephemeral identities. Production code should call this only at
    /// config-load time when seeding [`ValidatorSet`] and
    /// [`super::validator_key_history::ValidatorKeyHistory`]; tests are
    /// free to use it for fresh fixtures.
    pub const fn from_genesis_pubkey(node_id: NodeId) -> Self {
        Self(node_id)
    }

    /// Borrow the underlying `NodeId` bytes. The bytes are reusable for
    /// storage, wire framing, and signature-verification preimages —
    /// the typestate guards function signatures, not byte storage.
    pub const fn as_node_id(&self) -> &NodeId {
        &self.0
    }

    /// Move out the underlying `NodeId` bytes. Equivalent to
    /// `From::<ValidatorId>::from(...)` but keeps `self` consumed by
    /// value at the call site.
    pub const fn into_node_id(self) -> NodeId {
        self.0
    }
}

impl From<ValidatorId> for NodeId {
    fn from(v: ValidatorId) -> NodeId {
        v.0
    }
}

/// Ephemeral consensus signing key — whatever pubkey the validator is
/// currently (or, in spanning lookups, *was*) signing under at a given
/// view.
///
/// Distinct from [`ValidatorId`] so a slashing path that takes a stable
/// id cannot be passed an ephemeral key by mistake. Same wire shape as
/// [`NodeId`].
///
/// # Constructors
///
/// `From<NodeId>` and [`Self::from_node_id`] both accept raw bytes:
/// every pubkey on the wire arrives as a `NodeId`, and converting to
/// `Pubkey` is a cheap re-tag with no validation. Going the other way
/// is also free via `From<Pubkey> for NodeId`.
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

/// An ordered, deduplicated set of [`ValidatorId`]s with a `u64`
/// voting weight per member.
///
/// Members are sorted ascending (byte-lexicographic over the underlying
/// `NodeId` bytes) and contain no duplicates. Weights live in a parallel
/// array indexed identically to `members`: `weight_at(i)` is the weight
/// of `members[i]`. Clone is zero-cost — both arrays are `Arc`-backed —
/// so callers can hold `Arc<ValidatorSet>` on hot paths without copying.
///
/// # Weights
///
/// Subtask 1 of #144 (weighted voting power). The data structure carries
/// per-validator weights, but every protocol predicate (`has_quorum`,
/// `honesty_threshold`, leader rotation) is still count-based at this
/// point — the predicates switch to weight-based in subtask 2 (#461).
/// Until that lands, every constructor that doesn't take explicit
/// weights defaults each member's weight to `1`, which is the degenerate
/// case where weighted quorum reduces exactly to count-based quorum.
///
/// # Why weight 0 is forbidden at construction
///
/// `ValidatorSet::with_weights` returns `Err(WeightedSetError::ZeroWeight)`
/// for any weight of zero. The reconfig payload (#462) already has an
/// explicit "remove" path; allowing `weight = 0` would create a second
/// way to spell removal and a divide-by-zero footgun for future
/// stake-proportional features. The codebase has one canonical
/// representation of "this validator is no longer voting": it is not in
/// the set.
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
    /// Construct a validator set from `members`, sorting ascending and
    /// removing duplicates. Every member's weight defaults to `1`, so
    /// the weighted-quorum predicate reduces exactly to the count-based
    /// `2n/3 + 1` form. Two calls with the same underlying nodes in
    /// different input orders produce equal sets.
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
    /// [`ValidatorId`] and deduplicated; on collision the *first*
    /// entry's weight wins (deterministic).
    ///
    /// Returns [`WeightedSetError::ZeroWeight`] if any entry has weight
    /// 0; see the type-level docs for why zero is forbidden.
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

    /// Voting weight at sorted index `idx`. Panics on out-of-range,
    /// mirroring the `members[idx]` convention.
    pub fn weight_at(&self, idx: usize) -> u64 {
        self.weights[idx]
    }

    /// Voting weight for `id`, or `None` if not a member.
    pub fn weight_for(&self, id: &ValidatorId) -> Option<u64> {
        self.index_of(id).map(|i| self.weights[i])
    }

    /// Sum of all member weights. Returns `u128` so weights summing
    /// near `u64::MAX` (the issue's overflow case) don't wrap.
    pub fn total_weight(&self) -> u128 {
        self.weights.iter().map(|w| u128::from(*w)).sum()
    }

    /// Iterate `(&ValidatorId, u64)` pairs in sorted order. Used by the
    /// weighted-quorum predicate (subtask 2) and by persistence.
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

    /// Wire format is byte-identical between `ValidatorId` /
    /// `Pubkey` / inner `NodeId` because the newtypes derive
    /// `#[serde(transparent)]`. The on-disk and on-the-wire shapes
    /// produced by `postcard::to_stdvec` must therefore match the
    /// pre-#328 baseline (just the 32 bytes of the inner `NodeId`).
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

    // ── #460: per-validator weight ──────────────────────────────────────

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
