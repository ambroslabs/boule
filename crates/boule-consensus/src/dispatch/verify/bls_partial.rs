use crate::hotstuff::qc::Vote;
use boule_core::crypto::signed::{ChainId, Signed};

use super::super::{IngressError, QcVerification};
use super::domain::vote_preimage;

pub(in crate::dispatch) fn verify_bls_partial_if_required(
    signed: &Signed<Vote>,
    bls_partial: Option<&boule_core::crypto::sig_scheme::BlsPartialSig>,
    qc_verification: &QcVerification<'_>,
    chain_id: &ChainId,
) -> Result<(), IngressError> {
    let bls_key_history = match qc_verification {
        QcVerification::Verify {
            bls_key_history,
            operator_key_history: _,
            min_v_eff_delay: _,
            genesis_hash: _,
        } => bls_key_history,
    };

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

    boule_core::crypto::sig_scheme::BlsAggregated::verify_partial(
        &bls_pubkey,
        &preimage_bytes,
        partial,
    )
    .map_err(|_| IngressError::InvalidBlsPartial {
        view: signed.payload.view,
        signer: signed.signer,
    })?;
    Ok(())
}
