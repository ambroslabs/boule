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

/// An ordered, deduplicated set of [`ValidatorId`]s.
///
/// Members are sorted ascending (byte-lexicographic over the underlying
/// `NodeId` bytes) and contain no duplicates. Clone is zero-cost — the
/// set is `Arc`-backed — so callers can hold `Arc<ValidatorSet>` on hot
/// paths without copying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorSet {
    members: Arc<[ValidatorId]>,
}

impl ValidatorSet {
    /// Construct a validator set from `members`, sorting ascending and
    /// removing duplicates. Two calls with the same underlying nodes in
    /// different input orders produce equal sets.
    pub fn new(mut members: Vec<ValidatorId>) -> Self {
        members.sort_unstable();
        members.dedup();
        Self {
            members: members.into(),
        }
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
}
