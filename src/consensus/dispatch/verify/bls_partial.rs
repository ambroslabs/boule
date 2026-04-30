//! BLS partial-signature gate on inbound Vote frames.
//!
//! On `bls_aggregated` chains, every Vote must arrive carrying a
//! valid BLS partial under the signer's historical BLS pubkey at
//! `view`. Folding a Vote with a missing or invalid partial into a
//! QC's BLS aggregate would later cause `verify_aggregate_bls` to
//! fail, so we reject up-front at ingress with a dedicated
//! [`IngressError::InvalidBlsPartial`] variant for log triage.

use crate::consensus::hotstuff::qc::Vote;
use crate::crypto::sig_scheme::SignatureSchemeChoice;
use crate::crypto::signed::{ChainId, Signed};

use super::super::{IngressError, QcVerification};
use super::domain::vote_preimage;

/// On `bls_aggregated` chains, require an attached BLS partial signature
/// on every inbound `Vote` and verify it against the signer's BLS pubkey
/// at `signed.payload.view`. On `ed25519_collected` chains (or under
/// [`QcVerification::Skip`]) the optional partial is ignored.
///
/// The BLS partial signs the same canonical pre-image that the QC
/// aggregate verifier reconstructs over `(view, block_hash)`: the
/// domain-separated `postcard(Vote { view, block_hash })` bytes (see
/// [`crate::crypto::signed::preimage`]). Folding a partial that doesn't
/// verify into the aggregate would later cause `verify_aggregate_bls`
/// to fail on the formed QC, so we reject up-front at ingress with a
/// dedicated [`IngressError::InvalidBlsPartial`] variant for log
/// triage.
pub(in crate::consensus::dispatch) fn verify_bls_partial_if_required(
    signed: &Signed<Vote>,
    bls_partial: Option<&crate::crypto::sig_scheme::BlsPartialSig>,
    qc_verification: &QcVerification<'_>,
    chain_id: &ChainId,
) -> Result<(), IngressError> {
    let QcVerification::Verify {
        scheme,
        bls_key_history,
        min_v_eff_delay: _,
    } = qc_verification
    else {
        return Ok(());
    };
    if *scheme != SignatureSchemeChoice::BlsAggregated {
        return Ok(());
    }

    let Some(partial) = bls_partial else {
        return Err(IngressError::InvalidBlsPartial {
            view: signed.payload.view,
            signer: signed.signer,
        });
    };

    let bls_history = bls_key_history.ok_or(IngressError::InvalidBlsPartial {
        view: signed.payload.view,
        signer: signed.signer,
    })?;

    let bls_pubkey = bls_history
        .key_at(&signed.signer, signed.payload.view)
        .ok_or(IngressError::InvalidBlsPartial {
            view: signed.payload.view,
            signer: signed.signer,
        })?;

    let preimage_bytes = vote_preimage(signed.payload.view, signed.payload.block_hash, chain_id)
        .map_err(|_| IngressError::InvalidBlsPartial {
            view: signed.payload.view,
            signer: signed.signer,
        })?;

    crate::crypto::sig_scheme::BlsAggregated::verify_partial(&bls_pubkey, &preimage_bytes, partial)
        .map_err(|_| IngressError::InvalidBlsPartial {
            view: signed.payload.view,
            signer: signed.signer,
        })?;
    Ok(())
}
