use crate::hotstuff::NewView;
use crate::hotstuff::qc::{TimeoutVote, Vote};
use crate::hotstuff::{Proposal, step::Event as SafetyEvent};
use crate::pacemaker;
use crate::replication::block::BlockHash;
use crate::replication::snapshot::SnapshotManifest;
use crate::validator_history::ValidatorSetHistory;
use crate::validator_key_history::ValidatorKeyHistory;
use crate::wire::WireMessage;
use boule_core::crypto::signed::{ChainId, Signed};
use boule_core::identity::NodeId;

use super::codec;
use super::verify::bls_partial::verify_bls_partial_if_required;
use super::verify::envelope::{verify_sig, verify_signer_at};
use super::verify::proposal_history::verify_proposal_history_commitment_if_requested;
use super::verify::qc::{verify_high_qc_piggyback, verify_qc_if_requested};
use super::{Dispatch, IngressError, QcVerification, Verified};

pub fn ingress_with_qc_verification(
    from: NodeId,
    bytes: &[u8],
    history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
    qc_verification: &QcVerification<'_>,
    chain_id: &ChainId,
) -> Result<Vec<Dispatch>, IngressError> {
    let msg = codec::decode(bytes)?;
    ingress_wire_with_qc_verification(from, msg, history, key_history, qc_verification, chain_id)
}

pub fn ingress_wire_with_qc_verification(
    from: NodeId,
    msg: WireMessage,
    history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
    qc_verification: &QcVerification<'_>,
    chain_id: &ChainId,
) -> Result<Vec<Dispatch>, IngressError> {
    match msg {
        WireMessage::Proposal(signed) => {
            ingress_proposal(signed, history, key_history, qc_verification, chain_id)
        }
        WireMessage::Vote(signed, bls_partial) => ingress_vote(
            signed,
            bls_partial,
            history,
            key_history,
            qc_verification,
            chain_id,
        ),
        WireMessage::NewView(signed) => {
            ingress_new_view(signed, history, key_history, qc_verification, chain_id)
        }
        WireMessage::TimeoutVote(signed) => {
            ingress_timeout_vote(signed, history, key_history, qc_verification, chain_id)
        }
        WireMessage::Status { committed_height } => Ok(vec![Dispatch::PeerStatus {
            from,
            height: committed_height,
        }]),
        WireMessage::BlockRequest(hash) => Ok(ingress_block_request(hash, from)),
        WireMessage::BlockResponse(signed) => {
            ingress_block_response(signed, from, key_history, chain_id)
        }
        WireMessage::SnapshotManifestRequest { height } => {
            Ok(ingress_snapshot_manifest_request(height, from))
        }
        WireMessage::SnapshotManifestResponse(manifest) => {
            Ok(ingress_snapshot_manifest_response(manifest, from))
        }
        WireMessage::SnapshotChunkRequest { height, chunk_idx } => {
            Ok(ingress_snapshot_chunk_request(height, chunk_idx, from))
        }
        WireMessage::SnapshotChunkResponse {
            height,
            chunk_idx,
            payload,
        } => Ok(ingress_snapshot_chunk_response(
            height, chunk_idx, payload, from,
        )),
        WireMessage::BlockRangeRequest {
            from_height,
            to_height,
        } => Ok(ingress_block_range_request(from_height, to_height, from)),
        WireMessage::BlockRangeResponse(signed) => {
            ingress_block_range_response(signed, from, key_history, chain_id)
        }
        WireMessage::EquivocationEvidence(proof) => {
            ingress_equivocation_evidence(proof, history, key_history, chain_id)
        }
    }
}

pub fn ingress_proposal(
    signed: Signed<Proposal>,
    history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
    qc_verification: &QcVerification<'_>,
    chain_id: &ChainId,
) -> Result<Vec<Dispatch>, IngressError> {
    let view = signed.payload.block.header.view;
    let justify_view = signed.payload.justify.view;
    let signer_validator_id = verify_signer_at(signed.signer, view, history, key_history)?;
    verify_sig(&signed, chain_id)?;
    verify_qc_if_requested(
        &signed.payload.justify,
        history,
        key_history,
        qc_verification,
        chain_id,
    )?;

    verify_proposal_history_commitment_if_requested(
        &signed.payload.block,
        history,
        key_history,
        qc_verification,
        chain_id,
    )?;
    Ok(vec![
        Dispatch::Safety(SafetyEvent::ProposalReceived(
            Verified::wrap_after_verify_with_signer(signed, signer_validator_id),
        )),
        Dispatch::Pacemaker(pacemaker::Event::OnProposalReceived(view)),
        Dispatch::Pacemaker(pacemaker::Event::OnQc(justify_view)),
    ])
}

pub fn ingress_vote(
    signed: Signed<Vote>,
    bls_partial: Option<boule_core::crypto::sig_scheme::BlsPartialSig>,
    history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
    qc_verification: &QcVerification<'_>,
    chain_id: &ChainId,
) -> Result<Vec<Dispatch>, IngressError> {
    let signer_validator_id =
        verify_signer_at(signed.signer, signed.payload.view, history, key_history)?;
    verify_sig(&signed, chain_id)?;
    verify_bls_partial_if_required(&signed, bls_partial.as_ref(), qc_verification, chain_id)?;

    let verified = Verified::wrap_after_verify_with_signer(signed, signer_validator_id);
    let variant = crate::hotstuff::step::VoteVariant::from_optional_partial(verified, bls_partial);
    Ok(vec![Dispatch::Safety(SafetyEvent::VoteReceived(variant))])
}

pub fn ingress_new_view(
    signed: Signed<NewView>,
    history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
    qc_verification: &QcVerification<'_>,
    chain_id: &ChainId,
) -> Result<Vec<Dispatch>, IngressError> {
    let high_qc_view = signed.payload.high_qc.view;
    let signer_validator_id = verify_signer_at(signed.signer, high_qc_view, history, key_history)?;
    verify_sig(&signed, chain_id)?;

    let vs = history.set_at(high_qc_view);
    if !signed
        .payload
        .high_qc
        .is_well_formed(vs.for_view(high_qc_view))
    {
        return Err(IngressError::MalformedHighQc { view: high_qc_view });
    }
    verify_qc_if_requested(
        &signed.payload.high_qc,
        history,
        key_history,
        qc_verification,
        chain_id,
    )?;
    Ok(vec![
        Dispatch::Safety(SafetyEvent::NewViewReceived(
            Verified::wrap_after_verify_with_signer(signed, signer_validator_id),
        )),
        Dispatch::Pacemaker(pacemaker::Event::OnQc(high_qc_view)),
    ])
}

pub fn ingress_timeout_vote(
    signed: Signed<TimeoutVote>,
    history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
    qc_verification: &QcVerification<'_>,
    chain_id: &ChainId,
) -> Result<Vec<Dispatch>, IngressError> {
    verify_signer_at(signed.signer, signed.payload.view, history, key_history)?;
    verify_sig(&signed, chain_id)?;
    let high_qc_trusted = verify_high_qc_piggyback(
        signed.payload.high_qc.as_ref(),
        history,
        key_history,
        qc_verification,
        chain_id,
    );
    Ok(vec![Dispatch::TimeoutVote {
        signed,
        high_qc_trusted,
    }])
}

pub fn ingress_block_request(hash: BlockHash, from: NodeId) -> Vec<Dispatch> {
    vec![Dispatch::ServeBlock { hash, to: from }]
}

pub fn ingress_block_response(
    signed: Signed<crate::wire::BlockResponsePayload>,
    from: NodeId,
    _key_history: &ValidatorKeyHistory,
    chain_id: &ChainId,
) -> Result<Vec<Dispatch>, IngressError> {
    verify_sig(&signed, chain_id)?;
    let crate::wire::BlockResponsePayload {
        requested_hash,
        block,
    } = signed.payload;
    Ok(vec![Dispatch::ReceiveBlock {
        requested_hash,
        block,
        from,
    }])
}

pub fn ingress_block_range_request(
    from_height: crate::Height,
    to_height: crate::Height,
    from: NodeId,
) -> Vec<Dispatch> {
    vec![Dispatch::ServeBlockRange {
        from_height,
        to_height,
        to: from,
    }]
}

pub fn ingress_block_range_response(
    signed: Signed<crate::wire::BlockRangeResponsePayload>,
    from: NodeId,
    _key_history: &ValidatorKeyHistory,
    chain_id: &ChainId,
) -> Result<Vec<Dispatch>, IngressError> {
    verify_sig(&signed, chain_id)?;
    let crate::wire::BlockRangeResponsePayload {
        from_height,
        to_height,
        blocks,
    } = signed.payload;
    Ok(vec![Dispatch::ReceiveBlockRange {
        from_height,
        to_height,
        blocks,
        from,
    }])
}

pub fn ingress_snapshot_manifest_request(height: Option<u64>, from: NodeId) -> Vec<Dispatch> {
    vec![Dispatch::ServeSnapshotManifest { height, to: from }]
}

pub fn ingress_snapshot_manifest_response(
    manifest: Option<SnapshotManifest>,
    from: NodeId,
) -> Vec<Dispatch> {
    vec![Dispatch::ReceiveSnapshotManifest { manifest, from }]
}

pub fn ingress_snapshot_chunk_request(height: u64, chunk_idx: u32, from: NodeId) -> Vec<Dispatch> {
    vec![Dispatch::ServeSnapshotChunk {
        height: crate::Height(height),
        chunk_idx,
        to: from,
    }]
}

pub fn ingress_snapshot_chunk_response(
    height: u64,
    chunk_idx: u32,
    payload: Option<bytes::Bytes>,
    from: NodeId,
) -> Vec<Dispatch> {
    vec![Dispatch::ReceiveSnapshotChunk {
        height: crate::Height(height),
        chunk_idx,
        payload,
        from,
    }]
}

pub fn ingress_equivocation_evidence(
    proof: super::EquivocationProof,
    history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
    chain_id: &ChainId,
) -> Result<Vec<Dispatch>, IngressError> {
    match super::verify_equivocation_proof(&proof, history, key_history, chain_id) {
        Ok(validator_id) => Ok(vec![Dispatch::ReceiveEquivocationEvidence {
            proof,
            validator_id,
        }]),
        Err(e) => Err(IngressError::InvalidEquivocationEvidence(e)),
    }
}
