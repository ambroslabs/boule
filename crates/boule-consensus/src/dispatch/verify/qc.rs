use crate::View;
use crate::hotstuff::qc::QuorumCertificate;
use crate::validator_history::ValidatorSetHistory;
use crate::validator_key_history::ValidatorKeyHistory;
use boule_core::crypto::sig_scheme::{BlsAggregated, SignatureScheme};
use boule_core::crypto::signed::ChainId;

use super::super::{IngressError, QcVerification};
use super::domain::vote_preimage;

pub(in crate::dispatch) fn verify_qc_if_requested(
    qc: &QuorumCertificate,
    history: &ValidatorSetHistory,
    _key_history: &ValidatorKeyHistory,
    qc_verification: &QcVerification<'_>,
    chain_id: &ChainId,
) -> Result<(), IngressError> {
    let (bls_key_history, genesis_hash) = match qc_verification {
        QcVerification::Verify {
            bls_key_history,
            operator_key_history: _,
            min_v_eff_delay: _,
            genesis_hash,
        } => (bls_key_history, genesis_hash),
    };

    if qc.view == View::ZERO && qc.block_hash != *genesis_hash {
        return Err(IngressError::InvalidQcAggregate {
            view: View::ZERO,
            scheme: BlsAggregated::NAME,
        });
    }

    if qc.view == View::ZERO || qc.signer_count() == 0 {
        return Ok(());
    }

    let vs_at = history.set_at(qc.view);
    let vs = vs_at.for_view(qc.view);

    let preimage_bytes = vote_preimage(qc.view, qc.block_hash, chain_id).map_err(|_| {
        IngressError::InvalidQcAggregate {
            view: qc.view,
            scheme: BlsAggregated::NAME,
        }
    })?;

    if !qc.is_bls() {
        return Err(IngressError::InvalidQcAggregate {
            view: qc.view,
            scheme: BlsAggregated::NAME,
        });
    }
    let bls_history = bls_key_history.ok_or(IngressError::InvalidQcAggregate {
        view: qc.view,
        scheme: BlsAggregated::NAME,
    })?;
    let pubkeys =
        bls_history
            .pubkeys_for_set(vs, qc.view)
            .map_err(|_| IngressError::InvalidQcAggregate {
                view: qc.view,
                scheme: BlsAggregated::NAME,
            })?;
    qc.verify_aggregate_bls(&preimage_bytes, &pubkeys)
        .map_err(|_| IngressError::InvalidQcAggregate {
            view: qc.view,
            scheme: BlsAggregated::NAME,
        })?;
    Ok(())
}

pub(in crate::dispatch) fn verify_high_qc_piggyback(
    high_qc: Option<&QuorumCertificate>,
    history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
    qc_verification: &QcVerification<'_>,
    chain_id: &ChainId,
) -> bool {
    let Some(qc) = high_qc else {
        return true;
    };

    let vs_at = history.set_at(qc.view);
    if !qc.is_well_formed(vs_at.for_view(qc.view)) {
        return false;
    }
    verify_qc_if_requested(qc, history, key_history, qc_verification, chain_id).is_ok()
}
