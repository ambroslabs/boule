use crate::validator_history::ValidatorSetHistory;
use crate::validator_key_history::ValidatorKeyHistory;
use boule_core::crypto::signed::ChainId;

use super::super::{IngressError, QcVerification};

pub(in crate::dispatch) fn verify_proposal_history_commitment_if_requested(
    block: &crate::replication::block::Block,
    history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
    qc_verification: &QcVerification<'_>,
    chain_id: &ChainId,
) -> Result<(), IngressError> {
    let (bls_key_history, operator_key_history, min_v_eff_delay) = match qc_verification {
        QcVerification::Verify {
            bls_key_history,
            operator_key_history,
            min_v_eff_delay,
            genesis_hash: _,
        } => (bls_key_history, operator_key_history, min_v_eff_delay),
    };
    let actual = crate::history_commitment::compute_post_block_commitment(
        block,
        history,
        key_history,
        *bls_key_history,
        *operator_key_history,
        chain_id,
        *min_v_eff_delay,
    );
    if actual != block.header.validator_history_commitment {
        return Err(IngressError::InvalidValidatorHistoryCommitment {
            view: block.header.view,
            height: block.header.height,
            claimed: block.header.validator_history_commitment,
            actual,
        });
    }
    Ok(())
}
