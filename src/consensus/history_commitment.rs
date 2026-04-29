//! Cryptographic commitment over the validator-history triple (#325).
//!
//! `validator_history_commitment_v1` is a 32-byte SHA-256 hash that
//! folds the persisted forms of [`ValidatorSetHistory`],
//! [`ValidatorKeyHistory`], and (on BLS chains) [`BlsKeyHistory`] into
//! a single opaque tag. The hash is stamped into every block's
//! [`BlockHeader::validator_history_commitment`] so a replica's
//! persisted history blob can be cross-checked against what the chain's
//! latest committed block claims (audit finding 7-F2; closes the
//! anti-rollback substrate referenced by the parent issue #323).
//!
//! # Determinism
//!
//! The hash is built from `postcard`-serialized persisted forms. Each
//! history's [`to_persisted`] method produces a fixed-shape struct
//! (no maps, no floats), so postcard output is byte-stable across
//! processes and architectures. The flat-hash format is fixed at v1 so
//! every replica computes the same bytes from the same input — a hash
//! version bump (v2, v3, …) would land as a separate function name to
//! preserve verifiability of historical blocks.
//!
//! # Domain separation
//!
//! The hash starts with the byte string `b"ambros.history_commitment.v1"`
//! followed by a versioning byte. Versioning lets a future v2 — for
//! instance, one that adds a fourth history table — be computed
//! distinguishably even on inputs the v1 code would also accept.
//!
//! # Section framing
//!
//! Each section is length-prefixed (`be_u64` of byte length) before its
//! bytes are folded in. This prevents canonicalization ambiguity at
//! section boundaries: without the length prefix, an attacker who
//! controlled enough of two adjacent sections could shift bytes between
//! them and produce the same hash.
//!
//! [`to_persisted`]: ValidatorSetHistory::to_persisted
//! [`BlockHeader::validator_history_commitment`]: crate::replication::block::BlockHeader::validator_history_commitment

use sha2::{Digest, Sha256};

use crate::consensus::bls_key_history::BlsKeyHistory;
use crate::consensus::validator_history::ValidatorSetHistory;
use crate::consensus::validator_key_history::ValidatorKeyHistory;

/// Domain tag mixed into the leading bytes of the v1 commitment. Bumped
/// alongside the function name on any future shape change.
const DOMAIN_V1: &[u8] = b"ambros.history_commitment.v1";

/// Compute the v1 commitment over a `(set_history, key_history,
/// bls_key_history?)` triple. See the module-level docs for framing.
///
/// `bls_key_history` is `Some(_)` on BLS chains and `None` on Ed25519
/// chains. The `Some`/`None` discriminant is mixed into the hash, so an
/// Ed25519 chain cannot accidentally hash the same as a BLS chain that
/// happens to have an empty BLS history.
pub fn validator_history_commitment_v1(
    set_history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
    bls_key_history: Option<&BlsKeyHistory>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();

    // Domain tag — see module docs.
    hasher.update(DOMAIN_V1);

    let set_bytes = postcard::to_stdvec(&set_history.to_persisted())
        .expect("postcard encoding of PersistedValidatorHistory cannot fail");
    feed_section(&mut hasher, &set_bytes);

    let key_bytes = postcard::to_stdvec(&key_history.to_persisted())
        .expect("postcard encoding of PersistedValidatorKeyHistory cannot fail");
    feed_section(&mut hasher, &key_bytes);

    // Mix the BLS-presence discriminant before the BLS section bytes
    // so an Ed25519 chain (no BLS history) hashes differently from a
    // hypothetical BLS chain whose history is empty. Without this, the
    // length prefix alone would let an empty-BLS-history BLS chain
    // collide with an Ed25519 chain on the same set/key history.
    match bls_key_history {
        Some(bls) => {
            hasher.update([1u8]);
            let bls_bytes = postcard::to_stdvec(&bls.to_persisted())
                .expect("postcard encoding of PersistedBlsKeyHistory cannot fail");
            feed_section(&mut hasher, &bls_bytes);
        }
        None => {
            hasher.update([0u8]);
        }
    }

    hasher.finalize().into()
}

/// Length-prefix `bytes` into the running hash. The prefix is fixed-size
/// `be_u64` so the framing is unambiguous regardless of section length.
fn feed_section(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::validator_set::ValidatorSet;
    use crate::p2p::NodeId;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn fresh_histories(ids: &[NodeId]) -> (ValidatorSetHistory, ValidatorKeyHistory) {
        let vs = ValidatorSet::new(ids.to_vec());
        let set = ValidatorSetHistory::from_genesis(vs);
        let keys = ValidatorKeyHistory::new(ids.iter().copied());
        (set, keys)
    }

    /// Determinism: identical inputs → identical hash, every call.
    #[test]
    fn v1_is_deterministic() {
        let (s, k) = fresh_histories(&[nid(1), nid(2), nid(3), nid(4)]);
        let h1 = validator_history_commitment_v1(&s, &k, None);
        let h2 = validator_history_commitment_v1(&s, &k, None);
        assert_eq!(h1, h2);
    }

    /// Distinct genesis sets → distinct commitments (this is the whole
    /// point of the field).
    #[test]
    fn v1_distinguishes_distinct_genesis_sets() {
        let (s_a, k_a) = fresh_histories(&[nid(1), nid(2), nid(3), nid(4)]);
        let (s_b, k_b) = fresh_histories(&[nid(1), nid(2), nid(3), nid(5)]);
        let h_a = validator_history_commitment_v1(&s_a, &k_a, None);
        let h_b = validator_history_commitment_v1(&s_b, &k_b, None);
        assert_ne!(h_a, h_b);
    }

    /// Adding a boundary changes the commitment. This is the
    /// rollback-detection property: a replica whose persisted history
    /// is rolled back past a reconfig will compute a different
    /// commitment than the chain recorded.
    #[test]
    fn v1_distinguishes_after_boundary_insert() {
        let (mut s, k) = fresh_histories(&[nid(1), nid(2), nid(3), nid(4)]);
        let before = validator_history_commitment_v1(&s, &k, None);
        s.insert_boundary(10, ValidatorSet::new(vec![nid(1), nid(2), nid(3), nid(5)]))
            .unwrap();
        let after = validator_history_commitment_v1(&s, &k, None);
        assert_ne!(before, after);
    }

    /// The `Option<BlsKeyHistory>` discriminant must be mixed into the
    /// hash. An Ed25519 chain (`None`) and a BLS chain with empty
    /// history (`Some(empty)`) must produce distinct commitments even
    /// when the set and key histories agree.
    #[test]
    fn v1_distinguishes_bls_presence_from_absence() {
        let ids = [nid(1), nid(2), nid(3), nid(4)];
        let (s, k) = fresh_histories(&ids);
        let h_none = validator_history_commitment_v1(&s, &k, None);

        let bls_empty = BlsKeyHistory::new();
        let h_some_empty = validator_history_commitment_v1(&s, &k, Some(&bls_empty));
        assert_ne!(
            h_none, h_some_empty,
            "Ed25519 chain (None) must hash differently from BLS chain with empty history",
        );
    }
}
