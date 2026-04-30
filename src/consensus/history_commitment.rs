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

use crate::consensus::View;
use crate::consensus::bls_key_history::BlsKeyHistory;
use crate::consensus::validator_history::ValidatorSetHistory;
use crate::consensus::validator_key_history::ValidatorKeyHistory;
use crate::consensus::validator_set::ValidatorSet;
use crate::crypto::sig_scheme::SignatureSchemeChoice;
use crate::crypto::signed::ChainId;
use crate::replication::block::Block;

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

// ── Pure history-apply functions (#325 PR B) ─────────────────────────────────
//
// `ConsensusNode::apply_committed_reconfigs` and
// `apply_committed_rotations` mutate `self`, the safety core, the
// pacemaker, and storage. The pure functions below replay the same
// validation rules but only mutate the histories — used by the
// recovery-time rebuild path (and potentially future call sites that
// need to rebuild histories from a chain of committed blocks without
// touching live consensus state).
//
// **Invariant**: the validation behavior must match the production
// code byte-for-byte. If a reconfig at view V was rejected at commit
// time, it must also be rejected here. Otherwise the rebuild produces
// a different history than what was persisted, and the "did this blob
// match the chain?" check will fire spurious mismatches on perfectly
// healthy storage.
//
// The corresponding wrappers in `node.rs` call these and then layer
// the side-effects (mirror into safety core, re-install pacemaker,
// persist, log) on top.

/// Apply any reconfig commands in `block` to `set_history` (and to
/// `key_history` for any newly-added validators). Mirrors the
/// validation rules in
/// [`crate::consensus::node::ConsensusNode::apply_committed_reconfigs`]
/// but without side effects on the safety core, pacemaker, or storage.
///
/// `key_history` is updated to add a fresh entry at `cmd.v_eff` for
/// every validator the reconfig adds. This mirrors what
/// [`crate::consensus::validator_key_history::ValidatorKeyHistory::from_set_history`]
/// produces at recover time when no rotation has yet been committed
/// for that validator — keeping the rebuild's `key_history` identical
/// to what `recover` loads.
///
/// Used at recovery rebuild time (#325 PR B). Validation failures are
/// silently dropped — the production code logs them and drops, and the
/// rebuild path needs to drop in the same places to produce an
/// identical history.
pub fn apply_reconfig_commands_to_set_history(
    block: &Block,
    set_history: &mut ValidatorSetHistory,
    key_history: &mut ValidatorKeyHistory,
    scheme: SignatureSchemeChoice,
    min_v_eff_delay: View,
) {
    use crate::consensus::reconfig::ReconfigCommand;

    let block_view = block.header.view;
    for cmd_bytes in &block.commands {
        if !ReconfigCommand::is_reconfig_payload(cmd_bytes) {
            continue;
        }
        let cmd = match ReconfigCommand::decode(cmd_bytes) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Validate against the set authoritative at the block's view.
        let current_set_at = set_history.set_at(block_view);
        let next_members = match cmd.validate_against_with_delay_and_scheme(
            current_set_at.for_view(block_view),
            block_view,
            min_v_eff_delay,
            scheme,
        ) {
            Ok(m) => m,
            Err(_) => continue,
        };

        // Conflict guard: only one reconfig may be pending at a time.
        // Mirrors the production check exactly — the boundary at
        // v_eff == 0 (genesis) is allowed, but any later boundary
        // whose v_eff is strictly past the committing block's view
        // means a previously committed reconfig has not yet taken
        // effect.
        let conflict = set_history
            .iter()
            .any(|(v_eff, _)| v_eff != 0 && v_eff > block_view);
        if conflict {
            continue;
        }

        let next_members_vid: Vec<crate::consensus::validator_set::ValidatorId> = next_members
            .into_iter()
            .map(crate::consensus::validator_set::ValidatorId::from_genesis_pubkey)
            .collect();
        let new_set = ValidatorSet::new(next_members_vid);
        // Snapshot the post-reconfig members for the key_history
        // mirror so we don't double-borrow `set_history` after the
        // boundary is inserted.
        let new_members: Vec<crate::consensus::validator_set::ValidatorId> =
            new_set.iter().copied().collect();
        if set_history.insert_boundary(cmd.v_eff, new_set).is_err() {
            continue;
        }
        // Mirror new validators into key_history at the same v_eff.
        // Failures (collision with an existing pubkey) are dropped
        // silently — `from_set_history` would skip them too.
        for member in new_members {
            if !key_history.validators().any(|id| id == member) {
                let pubkey =
                    crate::consensus::validator_set::Pubkey::from_node_id(member.into_node_id());
                let _ = key_history.add_validator(pubkey, cmd.v_eff);
            }
        }
    }
}

/// Apply any rotation commands in `block` to `key_history` and
/// `bls_key_history` (where present). Mirrors the validation in
/// [`crate::consensus::node::ConsensusNode::apply_committed_rotations`].
///
/// `set_history` is borrowed read-only — rotations don't change set
/// membership but the production validation looks up the validator's
/// current key against `validator_key_history`, which is what we
/// mutate here. `chain_id` is required to re-verify the dual-signed
/// envelope; the rebuild path must run the same check the original
/// commit-time code did so a forged rotation that snuck past the
/// production check (or, more relevantly here, a tampered
/// `validator_key_history` blob) would not be silently accepted by
/// the rebuild.
pub fn apply_rotation_commands_to_histories(
    block: &Block,
    _set_history: &ValidatorSetHistory,
    key_history: &mut ValidatorKeyHistory,
    mut bls_key_history: Option<&mut BlsKeyHistory>,
    chain_id: &ChainId,
    scheme: SignatureSchemeChoice,
) {
    use crate::consensus::validator_rotation::DualSignedRotation;

    let block_view = block.header.view;
    for cmd_bytes in &block.commands {
        if !DualSignedRotation::is_rotation_payload(cmd_bytes) {
            continue;
        }
        let envelope = match DualSignedRotation::decode_command(cmd_bytes) {
            Ok(env) => env,
            Err(_) => continue,
        };

        let validator_pk =
            crate::consensus::validator_set::Pubkey::from_node_id(envelope.payload.validator);
        let current_key = match key_history.current_key(&validator_pk) {
            Some(k) => k,
            None => continue,
        };

        if envelope.verify(current_key.as_node_id(), chain_id).is_err() {
            continue;
        }

        if envelope
            .payload
            .validate_scheme_consistency(scheme)
            .is_err()
        {
            continue;
        }

        // Snapshot stable_id before mutating — same ordering as the
        // production code so the rebuild's branch is identical even
        // when validate_scheme_consistency fails after the lookup.
        let stable_id = key_history.validator_for(&validator_pk);

        if key_history
            .apply_rotation(&envelope.payload, block_view)
            .is_err()
        {
            continue;
        }

        if scheme == SignatureSchemeChoice::BlsAggregated {
            let new_bls_pk = match envelope.payload.new_bls_pubkey {
                Some(pk) => pk,
                None => {
                    // Should have been caught by validate_scheme_consistency
                    // above on a BLS chain, but mirror the production
                    // code's expect-style guard with a soft drop here:
                    // if we got this far, the production code panicked,
                    // so the persisted history could not have included
                    // this rotation either.
                    continue;
                }
            };
            let bls_history = match bls_key_history.as_deref_mut() {
                Some(h) => h,
                None => {
                    // Same reasoning: the production code would have
                    // panicked, so this rotation never landed in the
                    // persisted history. Drop on the rebuild path.
                    continue;
                }
            };
            let stable_id = match stable_id {
                Some(id) => id,
                None => continue,
            };
            // Production logs and continues (does not roll back) on
            // BLS-history apply failure after the Ed25519 history
            // already mutated. We do the same — the Ed25519 mutation
            // already happened, leaving the rebuild in the same shape
            // the production code left it in.
            let _ = bls_history.apply_rotation(
                stable_id.into_node_id(),
                envelope.payload.v_eff,
                new_bls_pk,
            );
        }
    }
}

/// Compute the v1 commitment over the **post-block** state: forks the
/// given histories, applies any reconfig/rotation commands in `block`,
/// and hashes (#325 PR C).
///
/// The same value is computed by:
///
/// - the leader at proposal-build time, to stamp the block's
///   [`crate::replication::block::BlockHeader::validator_history_commitment`]
///   field;
/// - the follower at proposal-receive time (in
///   [`crate::consensus::dispatch::ingress`]), to verify the leader's
///   stamped value matches what the follower would compute over its
///   own histories under the proposed block's commands.
///
/// Soundness-of-comparison rests on this function being a pure
/// deterministic function of `(block, current_histories, chain_id,
/// scheme, min_v_eff_delay)`: any honest replica fed the same inputs
/// produces the same output. Disagreement between leader and follower
/// can only come from a Byzantine leader stamping a value its own
/// post-block state would not produce, or from divergent state
/// histories (which is itself the rollback condition #325 PR B
/// catches at recovery).
///
/// **Why post-block, not pre-block.** A pre-block stamp's value
/// depends on the producer's commit position — a leader that has
/// committed an extra ancestor produces a different pre-block hash
/// than a follower at a less-advanced commit position, even when both
/// are honest. Post-block hashing over the same chain content makes
/// the commitment a function of the block content alone, so
/// follower-side verification is sound regardless of the relative
/// commit positions of leader and follower.
pub fn compute_post_block_commitment(
    block: &Block,
    set_history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
    bls_key_history: Option<&BlsKeyHistory>,
    chain_id: &ChainId,
    scheme: SignatureSchemeChoice,
    min_v_eff_delay: View,
) -> [u8; 32] {
    let mut set = set_history.clone();
    let mut key = key_history.clone();
    let mut bls = bls_key_history.cloned();
    apply_reconfig_commands_to_set_history(block, &mut set, &mut key, scheme, min_v_eff_delay);
    apply_rotation_commands_to_histories(block, &set, &mut key, bls.as_mut(), chain_id, scheme);
    validator_history_commitment_v1(&set, &key, bls.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::validator_set::ValidatorSet;
    use crate::p2p::NodeId;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn vid(b: u8) -> crate::consensus::validator_set::ValidatorId {
        crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(nid(b))
    }

    fn fresh_histories(ids: &[NodeId]) -> (ValidatorSetHistory, ValidatorKeyHistory) {
        let vids: Vec<_> = ids
            .iter()
            .copied()
            .map(crate::consensus::validator_set::ValidatorId::from_genesis_pubkey)
            .collect();
        let vs = ValidatorSet::new(vids.clone());
        let set = ValidatorSetHistory::from_genesis(vs);
        let keys = ValidatorKeyHistory::new(vids);
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
        s.insert_boundary(10, ValidatorSet::new(vec![vid(1), vid(2), vid(3), vid(5)]))
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
