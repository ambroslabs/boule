use boule_core::crypto::signed::{ChainId, Signed, SignedMessage};
use serde::{Deserialize, Serialize};

use super::envelope::{verify_sig, verify_signer_at};
use crate::View;
use crate::hotstuff::qc::{Proposal, Vote};
use crate::replication::block::BlockHash;
use crate::validator_history::ValidatorSetHistory;
use crate::validator_key_history::ValidatorKeyHistory;
use crate::validator_set::ValidatorId;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EquivocationProof {
    DoubleVote(Box<Signed<Vote>>, Box<Signed<Vote>>),

    DoubleProposal(Box<Signed<Proposal>>, Box<Signed<Proposal>>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EquivocationError {
    DifferentViews,

    NotConflicting,

    InvalidSignature,

    BadSigner,

    DifferentValidators,
}

impl std::fmt::Display for EquivocationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::DifferentViews => "messages are at different views",
            Self::NotConflicting => "messages name the same block (not a conflict)",
            Self::InvalidSignature => "a signature failed to verify",
            Self::BadSigner => "a signer is unknown or used a key not active at that view",
            Self::DifferentValidators => "messages were signed by different validators",
        };
        f.write_str(s)
    }
}

impl std::error::Error for EquivocationError {}

impl EquivocationProof {
    pub fn view(&self) -> View {
        match self {
            Self::DoubleVote(a, _) => a.payload.view,
            Self::DoubleProposal(a, _) => a.payload.block.header.view,
        }
    }
}

pub fn verify_equivocation_proof(
    proof: &EquivocationProof,
    history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
    chain_id: &ChainId,
) -> Result<ValidatorId, EquivocationError> {
    match proof {
        EquivocationProof::DoubleVote(a, b) => verify_conflicting_pair(
            a,
            b,
            a.payload.view,
            b.payload.view,
            a.payload.block_hash,
            b.payload.block_hash,
            history,
            key_history,
            chain_id,
        ),
        EquivocationProof::DoubleProposal(a, b) => verify_conflicting_pair(
            a,
            b,
            a.payload.block.header.view,
            b.payload.block.header.view,
            a.payload.block.hash(),
            b.payload.block.hash(),
            history,
            key_history,
            chain_id,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_conflicting_pair<T>(
    a: &Signed<T>,
    b: &Signed<T>,
    view_a: View,
    view_b: View,
    block_a: BlockHash,
    block_b: BlockHash,
    history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
    chain_id: &ChainId,
) -> Result<ValidatorId, EquivocationError>
where
    T: Serialize + SignedMessage,
{
    if view_a != view_b {
        return Err(EquivocationError::DifferentViews);
    }
    if block_a == block_b {
        return Err(EquivocationError::NotConflicting);
    }

    verify_sig(a, chain_id).map_err(|_| EquivocationError::InvalidSignature)?;
    verify_sig(b, chain_id).map_err(|_| EquivocationError::InvalidSignature)?;

    let id_a = verify_signer_at(a.signer, view_a, history, key_history)
        .map_err(|_| EquivocationError::BadSigner)?;
    let id_b = verify_signer_at(b.signer, view_b, history, key_history)
        .map_err(|_| EquivocationError::BadSigner)?;
    if id_a != id_b {
        return Err(EquivocationError::DifferentValidators);
    }
    Ok(id_a)
}
