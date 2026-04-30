//! Proposal-receive `validator_history_commitment` check (#325 PR C).
//!
//! Verifies the leader's stamped post-block commitment matches what a
//! follower would compute over the block's reconfig/rotation
//! commands. Catches a Byzantine leader who proposes blocks with a
//! forged commitment, before any honest replica votes on the block.
//! PR B catches the same class of forgery at recovery time; PR C
//! closes the window between propose and restart.

use crate::consensus::validator_history::ValidatorSetHistory;
use crate::consensus::validator_key_history::ValidatorKeyHistory;
use crate::crypto::signed::ChainId;

use super::super::{IngressError, QcVerification};

/// Verify a `Proposal`'s stamped `validator_history_commitment`
/// matches what the follower would compute over the block's
/// reconfig/rotation commands (#325 PR C).
///
/// The check is gated by [`QcVerification`] so the same dispatch path
/// exercised by tests with placeholder commitments (the `Skip`
/// variant) does not require every test fixture to compute the real
/// hash. Production wires `Verify` and runs the check.
///
/// Soundness: [`crate::consensus::history_commitment::compute_post_block_commitment`]
/// is a deterministic function of `(block, current_histories,
/// chain_id, scheme, min_v_eff_delay)`. Any honest follower with the
/// same histories and chain config produces the same value. A
/// Byzantine leader who stamps a value its own post-block state
/// would not produce is rejected here. A follower whose histories
/// diverge from the leader's (e.g., rolled-back blob, different
/// commit position with reconfig in flight) would also reject — but
/// that's the rollback condition #325 PR B catches at recovery, so
/// such a follower would have refused to start anyway.
pub(in crate::consensus::dispatch) fn verify_proposal_history_commitment_if_requested(
    block: &crate::replication::block::Block,
    history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
    qc_verification: &QcVerification<'_>,
    chain_id: &ChainId,
) -> Result<(), IngressError> {
    let (scheme, bls_key_history, min_v_eff_delay) = match qc_verification {
        #[cfg(test)]
        QcVerification::Skip => return Ok(()),
        QcVerification::Verify {
            scheme,
            bls_key_history,
            min_v_eff_delay,
        } => (scheme, bls_key_history, min_v_eff_delay),
    };
    let actual = crate::consensus::history_commitment::compute_post_block_commitment(
        block,
        history,
        key_history,
        *bls_key_history,
        chain_id,
        *scheme,
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
