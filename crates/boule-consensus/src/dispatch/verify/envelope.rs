//! Envelope-level signature verifiers.
//!
//! - [`verify_signer_at`]: resolve the wire signer pubkey to a stable
//!   [`ValidatorId`], confirm membership in the validator set
//!   authoritative at `view`, and confirm the signer is the
//!   authoritative key for that validator at that view.
//! - [`verify_sig`]: verify the Ed25519 signature on a
//!   [`Signed<T>`] envelope.

use crate::View;
use crate::validator_history::ValidatorSetHistory;
use crate::validator_key_history::ValidatorKeyHistory;
use crate::validator_set::{Pubkey, ValidatorId};
use boule_core::crypto::signed::{ChainId, Signed, SignedMessage};
use boule_core::identity::NodeId;

use super::super::IngressError;

/// Check that `signer` is the validator's currently-active signing key
/// at view `view`, where the validator must be a member of the
/// validator set authoritative at `view`.
///
/// The check has three steps:
/// 1. Resolve `signer` to a stable identifier via the key history's
///    reverse index. If `signer` has never been associated with any
///    validator (genesis, current, or any prior rotation key), the
///    message is from an outright unknown party.
/// 2. The stable identifier must appear in the validator set at `view`.
///    A vote signed by a known-but-removed validator at a view after
///    they were removed must be rejected.
/// 3. `signer` must equal the active signing key for that validator at
///    `view`. A vote signed under a stale key (the validator has since
///    rotated) or a future key (the rotation hasn't taken effect yet)
///    is rejected — the verifier always checks against whatever was
///    actually authoritative at the message's view.
///
/// All three failure modes report `UnknownSigner` for now: external
/// observers shouldn't be able to distinguish "you aren't in the set"
/// from "you used the wrong key for this view" — both indicate the
/// message has no business being processed. Splitting the variants for
/// internal telemetry is a follow-up.
///
/// On success, returns the stable [`ValidatorId`] the wire signer
/// pubkey resolves to. The dispatch arms thread this id through
/// [`super::super::Verified::wrap_after_verify_with_signer`] so the
/// safety core can look up the bitmap index by the same stable id
/// ingress validated against — closing the post-rotation hazard #394
/// names where `from_genesis_pubkey(signed.signer)` would silently
/// drop a vote signed under the validator's freshly-rotated active
/// key.
pub(in crate::dispatch) fn verify_signer_at(
    signer: NodeId,
    view: View,
    history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
) -> Result<ValidatorId, IngressError> {
    // Wire envelopes carry a `NodeId` as their `signer` field; at this
    // boundary we re-tag the bytes as a `Pubkey` (the typed
    // representation of "this is an ephemeral consensus signing key,
    // not a stable validator id") and route through the key history's
    // reverse index to land in the typed `ValidatorId` world.
    let signer_pk = Pubkey::from_node_id(signer);
    let stable_id = key_history
        .validator_for(&signer_pk)
        .ok_or(IngressError::UnknownSigner(signer))?;

    if history
        .set_at(view)
        .for_view(view)
        .index_of(&stable_id)
        .is_none()
    {
        return Err(IngressError::UnknownSigner(signer));
    }

    let active = key_history
        .key_at(&stable_id, view)
        .expect("validator with reverse-index entry has a non-empty history list");
    if active != signer_pk {
        return Err(IngressError::UnknownSigner(signer));
    }

    Ok(stable_id)
}

/// Verify the Ed25519 signature on a `Signed<T>` envelope.
pub(in crate::dispatch) fn verify_sig<T>(
    signed: &Signed<T>,
    chain_id: &ChainId,
) -> Result<(), IngressError>
where
    T: serde::Serialize + SignedMessage,
{
    signed
        .verify(&signed.signer, chain_id)
        .map_err(IngressError::InvalidSignature)
}
