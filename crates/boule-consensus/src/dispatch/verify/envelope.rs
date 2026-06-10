use crate::View;
use crate::validator_history::ValidatorSetHistory;
use crate::validator_key_history::ValidatorKeyHistory;
use crate::validator_set::{Pubkey, ValidatorId};
use boule_core::crypto::signed::{ChainId, Signed, SignedMessage};
use boule_core::identity::NodeId;

use super::super::IngressError;

pub(in crate::dispatch) fn verify_signer_at(
    signer: NodeId,
    view: View,
    history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
) -> Result<ValidatorId, IngressError> {
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
