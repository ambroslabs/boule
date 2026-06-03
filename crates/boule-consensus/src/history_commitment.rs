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
//! The hash starts with the byte string `b"boule.history_commitment.v1"`
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

use crate::View;
use crate::bls_key_history::BlsKeyHistory;
use crate::operator_key_history::OperatorKeyHistory;
use crate::replication::block::Block;
use crate::validator_history::ValidatorSetHistory;
use crate::validator_key_history::ValidatorKeyHistory;
use crate::validator_set::{Pubkey, ValidatorSet};
use boule_core::crypto::sig_scheme::SignatureSchemeChoice;
use boule_core::crypto::signed::ChainId;

/// Why a committed rotation-cancel (#317) did not apply. The block stays
/// committed regardless — the caller logs and drops.
#[derive(Debug)]
pub enum RotationCancelError {
    /// The tagged payload did not decode.
    Malformed(String),
    /// The named validator is not in the key history.
    UnknownValidator,
    /// No most-recent pending (not-yet-effective) rotation matches the named
    /// `cancelling_v_eff` — nothing to cancel, or it has already taken effect.
    NoPendingRotation,
    /// A signature did not verify (`sig_old` under the current key or `sig_new`
    /// under the pending rotation's new key).
    Verify(crate::validator_rotation::RotationVerifyError),
    /// The key history rejected the removal.
    History(crate::validator_key_history::HistoryError),
}

impl std::fmt::Display for RotationCancelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(e) => write!(f, "rotation-cancel payload malformed: {e}"),
            Self::UnknownValidator => {
                f.write_str("rotation-cancel references an unknown validator")
            }
            Self::NoPendingRotation => {
                f.write_str("no pending rotation matches the cancel's v_eff")
            }
            Self::Verify(e) => write!(f, "rotation-cancel signature verification failed: {e}"),
            Self::History(e) => write!(f, "rotation-cancel history removal failed: {e}"),
        }
    }
}

impl std::error::Error for RotationCancelError {}

/// Apply a single committed rotation-cancel command (#317) to the key
/// histories, if `cmd_bytes` is one. Shared by the production commit path and
/// the recovery rebuild so both reproduce identical state — which the
/// rotation-apply parity assert depends on.
///
/// Returns `Ok(true)` if a cancel applied, `Ok(false)` if `cmd_bytes` is not a
/// cancel payload, and `Err` if it is a cancel that failed validation.
pub fn apply_rotation_cancel_command(
    key_history: &mut ValidatorKeyHistory,
    bls_key_history: Option<&mut BlsKeyHistory>,
    cmd_bytes: &[u8],
    chain_id: &ChainId,
    scheme: SignatureSchemeChoice,
    commit_view: View,
) -> Result<bool, RotationCancelError> {
    use crate::validator_rotation::DualSignedRotationCancel;

    if !DualSignedRotationCancel::is_cancel_payload(cmd_bytes) {
        return Ok(false);
    }
    let cancel = DualSignedRotationCancel::decode_command(cmd_bytes)
        .map_err(|e| RotationCancelError::Malformed(e.to_string()))?;
    let validator_pk = Pubkey::from_node_id(cancel.payload.validator);
    let cancelling_v_eff = cancel.payload.cancelling_v_eff;

    // The pending rotation's new key — its presence confirms a not-yet-
    // effective rotation at `cancelling_v_eff`; `sig_new` is checked against it.
    let pending_new = key_history
        .pending_rotation_new_key(&validator_pk, cancelling_v_eff, commit_view)
        .ok_or(RotationCancelError::NoPendingRotation)?;
    // The validator's currently-active key (pre-rotation, since the pending
    // rotation's v_eff is still in the future); `sig_old` is checked against it.
    let stable = key_history
        .validator_for(&validator_pk)
        .ok_or(RotationCancelError::UnknownValidator)?;
    let current_key = key_history
        .key_at(&stable, commit_view)
        .ok_or(RotationCancelError::UnknownValidator)?;

    cancel
        .verify(current_key.as_node_id(), pending_new.as_node_id(), chain_id)
        .map_err(RotationCancelError::Verify)?;

    key_history
        .cancel_pending_rotation(&validator_pk, cancelling_v_eff, commit_view)
        .map_err(RotationCancelError::History)?;
    // Mirror into the BLS history on BLS chains (best-effort, like the rotation
    // apply: a BLS mismatch after the Ed25519 cancel is not rolled back).
    if scheme == SignatureSchemeChoice::BlsAggregated {
        if let Some(bls) = bls_key_history {
            let _ =
                bls.cancel_pending_rotation(stable.into_node_id(), cancelling_v_eff, commit_view);
        }
    }
    Ok(true)
}

/// Why a committed operator-signed signing-key rotation (#549) did not apply.
/// The block stays committed regardless — the caller logs and drops.
#[derive(Debug)]
pub enum OperatorRotationError {
    /// The tagged payload did not decode.
    Malformed(String),
    /// The named validator is not in the key history.
    UnknownValidator,
    /// The validator has no operator key on file at the commit view, so no
    /// operator could have authorised the rotation (operator keys are
    /// optional — a validator without one has no recovery path).
    NoOperatorKey,
    /// A signature did not verify (`sig_operator` under the active operator
    /// key, or `sig_new` under the new signing key).
    Verify(crate::validator_rotation::RotationVerifyError),
    /// The rotation's BLS fields are inconsistent with the chain's scheme.
    Scheme(crate::validator_rotation::RotationStructuralError),
    /// The key history rejected the rotation (unknown validator, non-monotone
    /// `v_eff`, or a cross-validator key collision).
    History(crate::validator_key_history::HistoryError),
}

impl std::fmt::Display for OperatorRotationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(e) => write!(f, "operator-rotation payload malformed: {e}"),
            Self::UnknownValidator => {
                f.write_str("operator-rotation references an unknown validator")
            }
            Self::NoOperatorKey => {
                f.write_str("operator-rotation: validator has no operator key on file")
            }
            Self::Verify(e) => write!(f, "operator-rotation signature verification failed: {e}"),
            Self::Scheme(e) => write!(f, "operator-rotation scheme-consistency failed: {e}"),
            Self::History(e) => write!(f, "operator-rotation history apply failed: {e}"),
        }
    }
}

impl std::error::Error for OperatorRotationError {}

/// Apply a single committed **operator-signed** signing-key rotation (#549) to
/// the key histories, if `cmd_bytes` is one. The recovery-from-loss path: the
/// authorising signature is the validator's operator key (active at
/// `commit_view`), not its old signing key, so a validator whose signing key
/// was destroyed can still rotate to a fresh one.
///
/// Shared by the production commit path and the recovery rebuild so both
/// reproduce identical state — which the rotation-apply parity assert depends
/// on. The committed effect on [`ValidatorKeyHistory`] is identical to a
/// dual-signed rotation ([`ValidatorKeyHistory::apply_rotation`]); only the
/// authorisation differs.
///
/// Returns `Ok(true)` if an operator rotation applied, `Ok(false)` if
/// `cmd_bytes` is not an operator-rotation payload, and `Err` if it is one that
/// failed validation.
pub fn apply_operator_rotation_command(
    key_history: &mut ValidatorKeyHistory,
    bls_key_history: Option<&mut BlsKeyHistory>,
    operator_key_history: &OperatorKeyHistory,
    cmd_bytes: &[u8],
    chain_id: &ChainId,
    scheme: SignatureSchemeChoice,
    commit_view: View,
) -> Result<bool, OperatorRotationError> {
    use crate::validator_rotation::OperatorSignedRotation;

    if !OperatorSignedRotation::is_operator_rotation_payload(cmd_bytes) {
        return Ok(false);
    }
    let env = OperatorSignedRotation::decode_command(cmd_bytes)
        .map_err(|e| OperatorRotationError::Malformed(e.to_string()))?;

    // Resolve the validator's stable id (the operator-key history is keyed by
    // it). `payload.validator` is normally the stable id itself — a recovering
    // validator references itself by the genesis pubkey, which never leaves the
    // history — but any historical key resolves to the same stable id.
    let validator_pk = Pubkey::from_node_id(env.payload.validator);
    let stable = key_history
        .validator_for(&validator_pk)
        .ok_or(OperatorRotationError::UnknownValidator)?;

    // The operator key active for this validator at the commit view authorises
    // the rotation; `sig_operator` is checked against it.
    let operator_pk = operator_key_history
        .key_at(&stable, commit_view)
        .ok_or(OperatorRotationError::NoOperatorKey)?;

    env.verify(&operator_pk, chain_id)
        .map_err(OperatorRotationError::Verify)?;

    env.payload
        .validate_scheme_consistency(scheme, chain_id)
        .map_err(OperatorRotationError::Scheme)?;

    key_history
        .apply_rotation(&env.payload, commit_view)
        .map_err(OperatorRotationError::History)?;

    // BLS chains rotate both keys atomically (#358), mirroring the dual-signed
    // path: best-effort, a BLS mismatch after the Ed25519 apply is not rolled
    // back (the Ed25519 mutation already happened).
    if scheme == SignatureSchemeChoice::BlsAggregated {
        if let (Some(bls), Some(new_bls_pk)) = (bls_key_history, env.payload.new_bls_pubkey) {
            let _ = bls.apply_rotation(stable.into_node_id(), env.payload.v_eff, new_bls_pk);
        }
    }
    Ok(true)
}

/// Why a committed operator-key self-rotation (#549) did not apply. The block
/// stays committed regardless — the caller logs and drops.
#[derive(Debug)]
pub enum OperatorKeyRotationError {
    /// The tagged payload did not decode.
    Malformed(String),
    /// The validator has no operator key on file at the commit view, so there
    /// is no current operator key to authorise (and verify `sig_old` against).
    NoOperatorKey,
    /// A signature did not verify (`sig_old` under the current operator key,
    /// or `sig_new` under the new operator key).
    Verify(crate::validator_rotation::RotationVerifyError),
    /// The operator-key history rejected the rotation (unknown validator or
    /// non-monotone `v_eff`).
    History(crate::operator_key_history::OperatorHistoryError),
}

impl std::fmt::Display for OperatorKeyRotationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(e) => write!(f, "operator-key-rotation payload malformed: {e}"),
            Self::NoOperatorKey => {
                f.write_str("operator-key-rotation: validator has no operator key on file")
            }
            Self::Verify(e) => {
                write!(
                    f,
                    "operator-key-rotation signature verification failed: {e}"
                )
            }
            Self::History(e) => write!(f, "operator-key-rotation history apply failed: {e}"),
        }
    }
}

impl std::error::Error for OperatorKeyRotationError {}

/// Apply a single committed **operator-key self-rotation** (#549) to the
/// operator-key history, if `cmd_bytes` is one. The validator rotates its own
/// operator key, dual-signed by the old (authorising, active at `commit_view`)
/// and new operator keys.
///
/// Shared by the production commit path and the recovery/commitment rebuild so
/// both reproduce identical state — which the rotation-apply parity assert and
/// the anti-rollback `validator_history_commitment` (v2) depend on.
///
/// Returns `Ok(true)` if a self-rotation applied, `Ok(false)` if `cmd_bytes` is
/// not an operator-key-rotation payload, and `Err` if it is one that failed
/// validation.
pub fn apply_operator_key_rotation_command(
    operator_key_history: &mut OperatorKeyHistory,
    cmd_bytes: &[u8],
    chain_id: &ChainId,
    commit_view: View,
) -> Result<bool, OperatorKeyRotationError> {
    use crate::validator_rotation::DualSignedOperatorRotation;

    if !DualSignedOperatorRotation::is_operator_key_rotation_payload(cmd_bytes) {
        return Ok(false);
    }
    let env = DualSignedOperatorRotation::decode_command(cmd_bytes)
        .map_err(|e| OperatorKeyRotationError::Malformed(e.to_string()))?;

    let validator = crate::validator_set::ValidatorId::from_genesis_pubkey(env.payload.validator);
    // The operator key active at the commit view authorises the change;
    // `sig_old` is checked against it. (The self-rotation's `v_eff` is in the
    // future, so `key_at(commit_view)` is the pre-rotation operator key.)
    let current_operator = operator_key_history
        .key_at(&validator, commit_view)
        .ok_or(OperatorKeyRotationError::NoOperatorKey)?;

    env.verify(&current_operator, chain_id)
        .map_err(OperatorKeyRotationError::Verify)?;

    operator_key_history
        .apply_rotation(
            &validator,
            env.payload.v_eff,
            env.payload.new_operator_pubkey,
        )
        .map_err(OperatorKeyRotationError::History)?;
    Ok(true)
}

/// Domain tag mixed into the leading bytes of the v1 commitment. Bumped
/// alongside the function name on any future shape change.
const DOMAIN_V1: &[u8] = b"boule.history_commitment.v1";

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

/// Domain tag for the v2 commitment — a distinct function/domain from v1
/// because it folds in a *fourth* history table (the operator-key history,
/// #549), per the module-doc versioning convention.
const DOMAIN_V2: &[u8] = b"boule.history_commitment.v2";

/// Compute the v2 commitment over the `(set, key, bls?, operator?)` quad
/// (#549). Identical framing to [`validator_history_commitment_v1`] for the
/// first three sections, then appends the operator-key history with the same
/// presence-discriminant scheme as the BLS section, under a distinct domain
/// tag so a v1 and a v2 hash over the same first three histories never
/// collide.
///
/// `operator_key_history` is `Some(_)` on chains that declared operator keys
/// (possibly an empty history) and `None` otherwise; the discriminant is
/// mixed in so the two cases hash distinctly.
pub fn validator_history_commitment_v2(
    set_history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
    bls_key_history: Option<&BlsKeyHistory>,
    operator_key_history: Option<&OperatorKeyHistory>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_V2);

    let set_bytes = postcard::to_stdvec(&set_history.to_persisted())
        .expect("postcard encoding of PersistedValidatorHistory cannot fail");
    feed_section(&mut hasher, &set_bytes);

    let key_bytes = postcard::to_stdvec(&key_history.to_persisted())
        .expect("postcard encoding of PersistedValidatorKeyHistory cannot fail");
    feed_section(&mut hasher, &key_bytes);

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

    // Operator-key history (#549): unlike BLS (where "Ed25519 chain, no BLS"
    // and "BLS chain, empty history" are genuinely different chains and so
    // need a presence discriminant), "no operator keys" *is* "empty operator
    // history" — there is no separate operator-key scheme. So we always fold
    // the (possibly-empty) persisted form, treating `None` as an empty
    // history. This keeps `None` and `Some(empty)` byte-identical, so a caller
    // that passes one can't diverge from a caller that passes the other.
    let op_persisted = operator_key_history
        .map(|op| op.to_persisted())
        .unwrap_or_default();
    let op_bytes = postcard::to_stdvec(&op_persisted)
        .expect("postcard encoding of PersistedOperatorKeyHistory cannot fail");
    feed_section(&mut hasher, &op_bytes);

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
/// `boule_node::consensus_node::ConsensusNode::apply_committed_reconfigs`
/// but without side effects on the safety core, pacemaker, or storage.
///
/// `key_history` is updated to add a fresh entry at `cmd.v_eff` for
/// every validator the reconfig adds. This mirrors what
/// [`crate::validator_key_history::ValidatorKeyHistory::from_set_history`]
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
    chain_id: &ChainId,
) {
    use crate::reconfig::ReconfigCommand;

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
            chain_id,
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
            .any(|(v_eff, _)| v_eff != View::ZERO && v_eff > block_view);
        if conflict {
            continue;
        }

        let next_entries: Vec<(crate::validator_set::ValidatorId, u64)> = next_members
            .into_iter()
            .map(|(n, w)| (crate::validator_set::ValidatorId::from_genesis_pubkey(n), w))
            .collect();
        let new_set = match ValidatorSet::with_weights(next_entries) {
            Ok(s) => s,
            Err(_) => continue,
        };
        // Snapshot the post-reconfig members for the key_history
        // mirror so we don't double-borrow `set_history` after the
        // boundary is inserted.
        let new_members: Vec<crate::validator_set::ValidatorId> = new_set.iter().copied().collect();
        if set_history.insert_boundary(cmd.v_eff, new_set).is_err() {
            continue;
        }
        // Mirror new validators into key_history at the same v_eff.
        // Failures (collision with an existing pubkey) are dropped
        // silently — `from_set_history` would skip them too.
        for member in new_members {
            if !key_history.validators().any(|id| id == member) {
                let pubkey = crate::validator_set::Pubkey::from_node_id(member.into_node_id());
                let _ = key_history.add_validator(pubkey, cmd.v_eff);
            }
        }
    }
}

/// Apply any rotation commands in `block` to `key_history` and
/// `bls_key_history` (where present). Mirrors the validation in
/// `boule_node::consensus_node::ConsensusNode::apply_committed_rotations`.
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
    operator_key_history: Option<&mut OperatorKeyHistory>,
    chain_id: &ChainId,
    scheme: SignatureSchemeChoice,
) {
    use crate::validator_rotation::DualSignedRotation;

    let block_view = block.header.view;
    for cmd_bytes in &block.commands {
        if !DualSignedRotation::is_rotation_payload(cmd_bytes) {
            continue;
        }
        let envelope = match DualSignedRotation::decode_command(cmd_bytes) {
            Ok(env) => env,
            Err(_) => continue,
        };

        let validator_pk = crate::validator_set::Pubkey::from_node_id(envelope.payload.validator);
        let current_key = match key_history.current_key(&validator_pk) {
            Some(k) => k,
            None => continue,
        };

        if envelope.verify(current_key.as_node_id(), chain_id).is_err() {
            continue;
        }

        if envelope
            .payload
            .validate_scheme_consistency(scheme, chain_id)
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

    // #317: process any rotation-cancel commands after the rotations. A cancel
    // always targets a rotation from an earlier block, so this block's
    // rotations and cancels never alias. Silent on failure — the rebuild must
    // reach the same final state the (logging) production path did.
    for cmd_bytes in &block.commands {
        let _ = apply_rotation_cancel_command(
            key_history,
            bls_key_history.as_deref_mut(),
            cmd_bytes,
            chain_id,
            scheme,
            block_view,
        );
    }

    // #549: process operator-signed signing-key recovery rotations. They
    // mutate the same key history a dual-signed rotation would, so they must
    // be reproduced here for the commitment/recovery rebuild to match the
    // live commit path (the parity invariant). Verifying them needs the
    // operator-key history; with none available (no operator keys on this
    // chain) they are skipped, exactly as the live path drops them. Silent on
    // failure — the rebuild matches the (logging) production path's final state.
    if let Some(op) = operator_key_history.as_deref() {
        for cmd_bytes in &block.commands {
            let _ = apply_operator_rotation_command(
                key_history,
                bls_key_history.as_deref_mut(),
                op,
                cmd_bytes,
                chain_id,
                scheme,
                block_view,
            );
        }
    }

    // #549: operator-key self-rotations mutate the operator-key history. Run
    // after the recovery rotations above (which read the *current* operator
    // key) — a self-rotation's `v_eff` is in the future, so it never changes
    // `key_at(commit_view)` for this block's recovery rotations regardless of
    // order. Silent on failure, like the other rebuild loops.
    if let Some(op) = operator_key_history {
        for cmd_bytes in &block.commands {
            let _ = apply_operator_key_rotation_command(op, cmd_bytes, chain_id, block_view);
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
///   [`crate::dispatch::ingress_with_qc_verification`]),
///   to verify the leader's
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
#[allow(clippy::too_many_arguments)] // the post-block commitment is a pure
// function of all four histories + chain/scheme/delay; bundling them into a
// struct would obscure the call sites more than it clarifies.
pub fn compute_post_block_commitment(
    block: &Block,
    set_history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
    bls_key_history: Option<&BlsKeyHistory>,
    operator_key_history: Option<&OperatorKeyHistory>,
    chain_id: &ChainId,
    scheme: SignatureSchemeChoice,
    min_v_eff_delay: View,
) -> [u8; 32] {
    let mut set = set_history.clone();
    let mut key = key_history.clone();
    let mut bls = bls_key_history.cloned();
    // #549: fork the operator-key history too, so this block's operator-key
    // self-rotations are reflected in the post-block hash without mutating the
    // caller's history.
    let mut operator = operator_key_history.cloned();
    apply_reconfig_commands_to_set_history(
        block,
        &mut set,
        &mut key,
        scheme,
        min_v_eff_delay,
        chain_id,
    );
    apply_rotation_commands_to_histories(
        block,
        &set,
        &mut key,
        bls.as_mut(),
        operator.as_mut(),
        chain_id,
        scheme,
    );
    validator_history_commitment_v2(&set, &key, bls.as_ref(), operator.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator_set::ValidatorSet;
    use boule_core::identity::NodeId;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn vid(b: u8) -> crate::validator_set::ValidatorId {
        crate::validator_set::ValidatorId::from_genesis_pubkey(nid(b))
    }

    fn fresh_histories(ids: &[NodeId]) -> (ValidatorSetHistory, ValidatorKeyHistory) {
        let vids: Vec<_> = ids
            .iter()
            .copied()
            .map(crate::validator_set::ValidatorId::from_genesis_pubkey)
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

    // ── validator_history_commitment_v2 (#549) ─────────────────────────

    /// v2 and v1 over the same first three histories never collide — the
    /// domain tag differs, so a v1-stamped chain can't be confused for v2.
    #[test]
    fn v2_is_domain_separated_from_v1() {
        let (s, k) = fresh_histories(&[nid(1), nid(2), nid(3), nid(4)]);
        let h_v1 = validator_history_commitment_v1(&s, &k, None);
        let h_v2 = validator_history_commitment_v2(&s, &k, None, None);
        assert_ne!(h_v1, h_v2);
    }

    /// The trap-avoidance invariant: `None` and `Some(empty)` operator
    /// histories hash identically, so a caller passing one can't diverge from
    /// one passing the other (genesis stamps with `None`-when-keyless; block
    /// stamping passes `Some(&self.operator_key_history)`).
    #[test]
    fn v2_treats_none_and_empty_operator_history_identically() {
        let (s, k) = fresh_histories(&[nid(1), nid(2), nid(3), nid(4)]);
        let empty_op = OperatorKeyHistory::new();
        let h_none = validator_history_commitment_v2(&s, &k, None, None);
        let h_empty = validator_history_commitment_v2(&s, &k, None, Some(&empty_op));
        assert_eq!(
            h_none, h_empty,
            "None and Some(empty) operator history must hash identically",
        );
    }

    /// v2 distinguishes distinct operator histories — the whole point of
    /// folding it in for anti-rollback.
    #[test]
    fn v2_distinguishes_distinct_operator_histories() {
        let (s, k) = fresh_histories(&[nid(1), nid(2), nid(3), nid(4)]);
        let op_a = OperatorKeyHistory::with_genesis([(vid(1), nid(0x11))]);
        let op_b = OperatorKeyHistory::with_genesis([(vid(1), nid(0x22))]);
        let h_a = validator_history_commitment_v2(&s, &k, None, Some(&op_a));
        let h_b = validator_history_commitment_v2(&s, &k, None, Some(&op_b));
        assert_ne!(
            h_a, h_b,
            "distinct operator keys must produce distinct commitments",
        );
    }

    // ── apply_operator_rotation_command (#549) ─────────────────────────

    use crate::validator_rotation::{OperatorSignedRotation, ValidatorKeyRotation};
    use boule_core::crypto::signed::{ChainId, NodeSigner, Signer};

    fn fresh_signer() -> NodeSigner {
        use boule_core::identity::NodeIdentity;
        use rcgen::{KeyPair as RcgenKeyPair, PKCS_ED25519};
        use zeroize::Zeroizing;
        let kp = RcgenKeyPair::generate_for(&PKCS_ED25519).unwrap();
        let id = NodeIdentity {
            pkcs8_der: Zeroizing::new(kp.serialize_der()),
        };
        NodeSigner::from_identity(&id).unwrap()
    }

    /// One validator (its genesis pubkey = stable id) with an operator key,
    /// plus signers for a recovery rotation to `new`.
    fn operator_recovery_fixture() -> (
        ValidatorKeyHistory,
        OperatorKeyHistory,
        crate::validator_set::ValidatorId,
        NodeSigner, // operator
        NodeSigner, // new signing key
    ) {
        let validator = fresh_signer();
        let operator = fresh_signer();
        let new = fresh_signer();
        let v_id = crate::validator_set::ValidatorId::from_genesis_pubkey(validator.node_id());
        let keys = ValidatorKeyHistory::new(vec![v_id]);
        let ops = OperatorKeyHistory::with_genesis([(v_id, operator.node_id())]);
        (keys, ops, v_id, operator, new)
    }

    fn recovery_payload(
        v_id: &crate::validator_set::ValidatorId,
        new: &NodeSigner,
    ) -> ValidatorKeyRotation {
        ValidatorKeyRotation {
            validator: v_id.into_node_id(),
            new_pubkey: new.node_id(),
            v_eff: View(10),
            new_bls_pubkey: None,
            new_bls_pop: None,
        }
    }

    #[test]
    fn operator_rotation_applies_with_a_valid_operator_signature() {
        let (mut keys, ops, v_id, operator, new) = operator_recovery_fixture();
        let env = OperatorSignedRotation::sign(
            recovery_payload(&v_id, &new),
            &operator,
            &new,
            &ChainId::TEST,
        )
        .unwrap();
        let applied = apply_operator_rotation_command(
            &mut keys,
            None,
            &ops,
            &env.encode_command(),
            &ChainId::TEST,
            SignatureSchemeChoice::Ed25519Collected,
            View(5),
        )
        .unwrap();
        assert!(applied);
        // The new signing key is active at v_eff; the genesis key before it.
        assert_eq!(
            keys.key_at(&v_id, View(10)),
            Some(Pubkey::from_node_id(new.node_id()))
        );
        assert_eq!(
            keys.key_at(&v_id, View(9)),
            Some(Pubkey::from_node_id(v_id.into_node_id())),
        );
    }

    #[test]
    fn operator_rotation_rejects_a_signature_from_the_wrong_operator_key() {
        let (mut keys, ops, v_id, _operator, new) = operator_recovery_fixture();
        // Signed by an attacker key, not the validator's real operator key.
        let attacker = fresh_signer();
        let env = OperatorSignedRotation::sign(
            recovery_payload(&v_id, &new),
            &attacker,
            &new,
            &ChainId::TEST,
        )
        .unwrap();
        let r = apply_operator_rotation_command(
            &mut keys,
            None,
            &ops,
            &env.encode_command(),
            &ChainId::TEST,
            SignatureSchemeChoice::Ed25519Collected,
            View(5),
        );
        assert!(matches!(r, Err(OperatorRotationError::Verify(_))));
        // The key history is unchanged — the forged recovery is a no-op.
        assert_eq!(
            keys.key_at(&v_id, View(10)),
            Some(Pubkey::from_node_id(v_id.into_node_id())),
        );
    }

    #[test]
    fn operator_rotation_rejects_when_the_validator_has_no_operator_key() {
        let (mut keys, _ops, v_id, operator, new) = operator_recovery_fixture();
        let empty_ops = OperatorKeyHistory::new();
        let env = OperatorSignedRotation::sign(
            recovery_payload(&v_id, &new),
            &operator,
            &new,
            &ChainId::TEST,
        )
        .unwrap();
        let r = apply_operator_rotation_command(
            &mut keys,
            None,
            &empty_ops,
            &env.encode_command(),
            &ChainId::TEST,
            SignatureSchemeChoice::Ed25519Collected,
            View(5),
        );
        assert!(matches!(r, Err(OperatorRotationError::NoOperatorKey)));
    }

    #[test]
    fn apply_operator_rotation_command_ignores_non_operator_payloads() {
        let (mut keys, ops, _v_id, _operator, _new) = operator_recovery_fixture();
        // A garbage / non-operator-rotation command is a clean Ok(false).
        let applied = apply_operator_rotation_command(
            &mut keys,
            None,
            &ops,
            b"not an operator rotation",
            &ChainId::TEST,
            SignatureSchemeChoice::Ed25519Collected,
            View(5),
        )
        .unwrap();
        assert!(!applied);
    }

    // ── apply_operator_key_rotation_command (#549 self-rotation) ───────

    use crate::validator_rotation::{DualSignedOperatorRotation, OperatorKeyRotation};

    #[test]
    fn operator_key_rotation_applies_with_a_valid_dual_operator_signature() {
        let validator = fresh_signer();
        let old_op = fresh_signer();
        let new_op = fresh_signer();
        let v_id = crate::validator_set::ValidatorId::from_genesis_pubkey(validator.node_id());
        let mut ops = OperatorKeyHistory::with_genesis([(v_id, old_op.node_id())]);

        let payload = OperatorKeyRotation {
            validator: v_id.into_node_id(),
            new_operator_pubkey: new_op.node_id(),
            v_eff: View(30),
        };
        let env =
            DualSignedOperatorRotation::sign(payload, &old_op, &new_op, &ChainId::TEST).unwrap();
        let applied = apply_operator_key_rotation_command(
            &mut ops,
            &env.encode_command(),
            &ChainId::TEST,
            View(5),
        )
        .unwrap();
        assert!(applied);
        // The new operator key is active at v_eff; the old one before it.
        assert_eq!(ops.key_at(&v_id, View(30)), Some(new_op.node_id()));
        assert_eq!(ops.key_at(&v_id, View(29)), Some(old_op.node_id()));
    }

    #[test]
    fn operator_key_rotation_rejects_a_signature_from_the_wrong_old_operator_key() {
        let validator = fresh_signer();
        let old_op = fresh_signer();
        let new_op = fresh_signer();
        let attacker = fresh_signer();
        let v_id = crate::validator_set::ValidatorId::from_genesis_pubkey(validator.node_id());
        let mut ops = OperatorKeyHistory::with_genesis([(v_id, old_op.node_id())]);

        let payload = OperatorKeyRotation {
            validator: v_id.into_node_id(),
            new_operator_pubkey: new_op.node_id(),
            v_eff: View(30),
        };
        // Signed by an attacker, not the validator's current operator key.
        let env =
            DualSignedOperatorRotation::sign(payload, &attacker, &new_op, &ChainId::TEST).unwrap();
        let r = apply_operator_key_rotation_command(
            &mut ops,
            &env.encode_command(),
            &ChainId::TEST,
            View(5),
        );
        assert!(matches!(r, Err(OperatorKeyRotationError::Verify(_))));
        // Operator key unchanged.
        assert_eq!(ops.key_at(&v_id, View(30)), Some(old_op.node_id()));
    }

    #[test]
    fn operator_key_rotation_rejects_when_validator_has_no_operator_key() {
        let old_op = fresh_signer();
        let new_op = fresh_signer();
        let v_id = crate::validator_set::ValidatorId::from_genesis_pubkey([0x42; 32]);
        // Empty operator history — the validator has no operator key.
        let mut ops = OperatorKeyHistory::new();
        let payload = OperatorKeyRotation {
            validator: v_id.into_node_id(),
            new_operator_pubkey: new_op.node_id(),
            v_eff: View(30),
        };
        let env =
            DualSignedOperatorRotation::sign(payload, &old_op, &new_op, &ChainId::TEST).unwrap();
        let r = apply_operator_key_rotation_command(
            &mut ops,
            &env.encode_command(),
            &ChainId::TEST,
            View(5),
        );
        assert!(matches!(r, Err(OperatorKeyRotationError::NoOperatorKey)));
    }

    #[test]
    fn apply_operator_key_rotation_command_ignores_non_payloads() {
        let mut ops = OperatorKeyHistory::new();
        let applied = apply_operator_key_rotation_command(
            &mut ops,
            b"not an operator-key rotation",
            &ChainId::TEST,
            View(5),
        )
        .unwrap();
        assert!(!applied);
    }
}
