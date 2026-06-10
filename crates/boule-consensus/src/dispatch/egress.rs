use bytes::Bytes;

use crate::hotstuff::ConsensusMsg;
use crate::hotstuff::qc::Vote;
use crate::hotstuff::step::Action as SafetyAction;
use crate::pacemaker;
use crate::replication::block::{Block, BlockHash};
use crate::replication::snapshot::SnapshotManifest;
use crate::validator_key_history::ValidatorKeyHistory;
use crate::validator_set::{Pubkey, ValidatorId};
use crate::wire::WireMessage;
use boule_core::crypto::signed::{ChainId, Signed, Signer, preimage};
use boule_core::identity::NodeId;

use super::codec;
use super::{Dispatch, Outbound, Verified};

pub fn egress_safety(
    action: &SafetyAction,
    signer: &dyn Signer,
    bls_signer: Option<
        &dyn boule_core::crypto::signed::PartialSigner<
            boule_core::crypto::sig_scheme::BlsAggregated,
        >,
    >,
    chain_id: &ChainId,
) -> anyhow::Result<Option<Outbound>> {
    match action {
        SafetyAction::Broadcast(msg) => {
            let wire = sign_consensus_msg(msg, signer, bls_signer, chain_id)?;
            let payload = codec::encode(&wire).map_err(anyhow::Error::from)?;
            Ok(Some(Outbound::Broadcast(payload)))
        }

        SafetyAction::RequestBlock { hash, peer, .. } => {
            Ok(Some(egress_block_request(*hash, *peer)))
        }

        SafetyAction::Persist(_)
        | SafetyAction::Commit(_)
        | SafetyAction::EquivocationEvidence { .. }
        | SafetyAction::ProposalEquivocationEvidence { .. }
        | SafetyAction::BuildProposal { .. } => Ok(None),
    }
}

pub fn egress_block_request(hash: BlockHash, to: NodeId) -> Outbound {
    let wire = WireMessage::BlockRequest(hash);
    let payload = codec::encode(&wire).expect("BlockRequest encoding must not fail");
    Outbound::SendTo { to, payload }
}

pub fn egress_equivocation_evidence(proof: super::EquivocationProof) -> Outbound {
    let wire = WireMessage::EquivocationEvidence(proof);
    let payload = codec::encode(&wire).expect("EquivocationEvidence encoding must not fail");
    Outbound::Broadcast(payload)
}

pub fn egress_status(committed_height: crate::Height) -> Outbound {
    let wire = WireMessage::Status { committed_height };
    let payload = codec::encode(&wire).expect("Status encoding must not fail");
    Outbound::Broadcast(payload)
}

pub fn egress_block_response(
    requested_hash: BlockHash,
    block: Option<Block>,
    to: NodeId,
    signer: &dyn Signer,
    chain_id: &ChainId,
) -> anyhow::Result<Outbound> {
    let payload = crate::wire::BlockResponsePayload {
        requested_hash,
        block,
    };
    let signed = Signed::sign(payload, signer, chain_id)?;
    let wire = WireMessage::BlockResponse(signed);
    let payload = codec::encode(&wire).map_err(anyhow::Error::from)?;
    Ok(Outbound::SendTo { to, payload })
}

pub fn egress_block_range_request(
    from_height: crate::Height,
    to_height: crate::Height,
    to: NodeId,
) -> Outbound {
    let wire = WireMessage::BlockRangeRequest {
        from_height,
        to_height,
    };
    let payload = codec::encode(&wire).expect("BlockRangeRequest encoding must not fail");
    Outbound::SendTo { to, payload }
}

pub fn egress_block_range_response(
    from_height: crate::Height,
    to_height: crate::Height,
    blocks: Vec<Block>,
    to: NodeId,
    signer: &dyn Signer,
    chain_id: &ChainId,
) -> anyhow::Result<Outbound> {
    let payload = crate::wire::BlockRangeResponsePayload {
        from_height,
        to_height,
        blocks,
    };
    let signed = Signed::sign(payload, signer, chain_id)?;
    let wire = WireMessage::BlockRangeResponse(signed);
    let payload = codec::encode(&wire).map_err(anyhow::Error::from)?;
    Ok(Outbound::SendTo { to, payload })
}

pub fn egress_snapshot_manifest_request(height: Option<u64>, to: NodeId) -> Outbound {
    let wire = WireMessage::SnapshotManifestRequest { height };
    let payload = codec::encode(&wire).expect("SnapshotManifestRequest encoding must not fail");
    Outbound::SendTo { to, payload }
}

pub fn egress_snapshot_manifest_response(
    manifest: Option<SnapshotManifest>,
    to: NodeId,
) -> Outbound {
    let wire = WireMessage::SnapshotManifestResponse(manifest);
    let payload = codec::encode(&wire).expect("SnapshotManifestResponse encoding must not fail");
    Outbound::SendTo { to, payload }
}

pub fn egress_snapshot_chunk_request(height: u64, chunk_idx: u32, to: NodeId) -> Outbound {
    let wire = WireMessage::SnapshotChunkRequest { height, chunk_idx };
    let payload = codec::encode(&wire).expect("SnapshotChunkRequest encoding must not fail");
    Outbound::SendTo { to, payload }
}

pub fn egress_snapshot_chunk_response(
    height: u64,
    chunk_idx: u32,
    payload: Option<Bytes>,
    to: NodeId,
) -> Outbound {
    let wire = WireMessage::SnapshotChunkResponse {
        height,
        chunk_idx,
        payload,
    };
    let payload = codec::encode(&wire).expect("SnapshotChunkResponse encoding must not fail");
    Outbound::SendTo { to, payload }
}

pub(in crate::dispatch) fn sign_consensus_msg(
    msg: &ConsensusMsg,
    signer: &dyn Signer,
    bls_signer: Option<
        &dyn boule_core::crypto::signed::PartialSigner<
            boule_core::crypto::sig_scheme::BlsAggregated,
        >,
    >,
    chain_id: &ChainId,
) -> anyhow::Result<WireMessage> {
    match msg {
        ConsensusMsg::Proposal(p) => {
            let signed = Signed::sign(p.clone(), signer, chain_id)?;
            Ok(WireMessage::Proposal(signed))
        }
        ConsensusMsg::Vote(v) => {
            let signed = Signed::sign(v.clone(), signer, chain_id)?;
            let bls_partial = match bls_signer {
                Some(bs) => {
                    let bytes = preimage::<Vote>(v, chain_id)?;
                    Some(bs.sign_partial(&bytes))
                }
                None => None,
            };
            Ok(WireMessage::Vote(signed, bls_partial))
        }
        ConsensusMsg::NewView(nv) => {
            let signed = Signed::sign(nv.clone(), signer, chain_id)?;
            Ok(WireMessage::NewView(signed))
        }
    }
}

pub fn egress_consensus_msg_with_loopback(
    msg: &ConsensusMsg,
    signer: &dyn Signer,
    bls_signer: Option<
        &dyn boule_core::crypto::signed::PartialSigner<
            boule_core::crypto::sig_scheme::BlsAggregated,
        >,
    >,
    key_history: &ValidatorKeyHistory,
    chain_id: &ChainId,
) -> anyhow::Result<(Bytes, Vec<Dispatch>)> {
    let wire = sign_consensus_msg(msg, signer, bls_signer, chain_id)?;
    let payload = codec::encode(&wire).map_err(anyhow::Error::from)?;

    let signer_pk = Pubkey::from_node_id(signer.node_id());
    let signer_validator_id = key_history
        .validator_for(&signer_pk)
        .unwrap_or_else(|| ValidatorId::from_genesis_pubkey(signer.node_id()));
    let dispatches = match wire {
        WireMessage::Proposal(signed) => {
            let view = signed.payload.block.header.view;
            let justify_view = signed.payload.justify.view;
            vec![
                Dispatch::Safety(crate::hotstuff::step::Event::ProposalReceived(
                    Verified::wrap_after_verify_with_signer(signed, signer_validator_id),
                )),
                Dispatch::Pacemaker(pacemaker::Event::OnProposalReceived(view)),
                Dispatch::Pacemaker(pacemaker::Event::OnQc(justify_view)),
            ]
        }
        WireMessage::Vote(signed, bls_partial) => {
            let verified = Verified::wrap_after_verify_with_signer(signed, signer_validator_id);
            let variant =
                crate::hotstuff::step::VoteVariant::from_optional_partial(verified, bls_partial);
            vec![Dispatch::Safety(
                crate::hotstuff::step::Event::VoteReceived(variant),
            )]
        }
        WireMessage::NewView(signed) => {
            let high_qc_view = signed.payload.high_qc.view;
            vec![
                Dispatch::Safety(crate::hotstuff::step::Event::NewViewReceived(
                    Verified::wrap_after_verify_with_signer(signed, signer_validator_id),
                )),
                Dispatch::Pacemaker(pacemaker::Event::OnQc(high_qc_view)),
            ]
        }

        WireMessage::TimeoutVote(_)
        | WireMessage::BlockRequest(_)
        | WireMessage::BlockResponse(_)
        | WireMessage::SnapshotManifestRequest { .. }
        | WireMessage::SnapshotManifestResponse(_)
        | WireMessage::SnapshotChunkRequest { .. }
        | WireMessage::SnapshotChunkResponse { .. }
        | WireMessage::BlockRangeRequest { .. }
        | WireMessage::BlockRangeResponse(_)
        | WireMessage::EquivocationEvidence(_)
        | WireMessage::Status { .. } => {
            unreachable!("sign_consensus_msg always produces Proposal/Vote/NewView wire variants")
        }
    };
    Ok((payload, dispatches))
}
