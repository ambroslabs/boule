//! Egress: signing helpers and [`WireMessage`] encoders.
//!
//! - [`sign_consensus_msg`]: turn a [`ConsensusMsg`] into the
//!   matching signed [`WireMessage`] (Proposal / Vote /
//!   NewView). Used by [`egress_safety`] and the local-loopback path.
//! - [`egress_safety`]: translate a HotStuff safety-core
//!   [`SafetyAction`] into an [`Outbound`] frame.
//! - [`egress_consensus_msg_with_loopback`]: sign a
//!   [`ConsensusMsg`], encode it for the wire, and produce the
//!   matching [`Dispatch`] items so this node's own state machines
//!   see the message even though the p2p layer doesn't loop sends
//!   back to the sender (#118).
//! - `egress_block_*` / `egress_snapshot_*`: thin encoders for the
//!   non-signed wire variants.

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

/// Translate a HotStuff safety-core [`SafetyAction`] into an [`Outbound`]
/// frame.
///
/// Returns `None` for actions that have no wire representation
/// (`Persist`, `Commit`, `RequestBlock` uses its own path).
/// `RequestBlock` is handled separately — call [`egress_block_request`].
///
/// The caller must ensure `signer.node_id()` is the node's identity; the
/// produced [`WireMessage`] will carry that as the `signer` field.
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

        // Non-wire actions: handled by the event loop directly.
        // `BuildProposal` (#606) is consumed by `apply_safety_actions`, which
        // runs the builder and re-applies the resulting Broadcast(Proposal);
        // it never reaches the wire as itself.
        SafetyAction::Persist(_)
        | SafetyAction::Commit(_)
        | SafetyAction::EquivocationEvidence { .. }
        | SafetyAction::ProposalEquivocationEvidence { .. }
        | SafetyAction::BuildProposal { .. } => Ok(None),
    }
}

/// Encode a [`BlockRequest`] as a `SendTo` outbound frame.
///
/// [`BlockRequest`]: WireMessage::BlockRequest
pub fn egress_block_request(hash: BlockHash, to: NodeId) -> Outbound {
    let wire = WireMessage::BlockRequest(hash);
    let payload = codec::encode(&wire).expect("BlockRequest encoding must not fail");
    Outbound::SendTo { to, payload }
}

/// Encode gossiped equivocation evidence (#657b) as a `Broadcast` frame. The
/// proof is self-authenticating, so nothing is signed here — the receiver
/// re-verifies the proof itself at ingress.
pub fn egress_equivocation_evidence(proof: super::EquivocationProof) -> Outbound {
    let wire = WireMessage::EquivocationEvidence(proof);
    let payload = codec::encode(&wire).expect("EquivocationEvidence encoding must not fail");
    Outbound::Broadcast(payload)
}

/// Encode a [`Status`](WireMessage::Status) height advertisement (#857) as a
/// `Broadcast` frame. Unsigned — a routing hint only; the overlay
/// authenticates the sender.
pub fn egress_status(committed_height: crate::Height) -> Outbound {
    let wire = WireMessage::Status { committed_height };
    let payload = codec::encode(&wire).expect("Status encoding must not fail");
    Outbound::Broadcast(payload)
}

/// Encode a [`BlockResponse`] as a `SendTo` outbound frame, signing
/// the payload so a wrong-hash response is non-repudiable evidence
/// (#434).
///
/// `requested_hash` is the hash the requester named in the matching
/// `BlockRequest`. `block` is what we found (or `None` if we didn't
/// find it). The signed envelope binds both together: a Byzantine
/// responder who returns a different block under a wrong-hash claim
/// can be later slashed once that machinery lands.
///
/// [`BlockResponse`]: WireMessage::BlockResponse
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

/// Encode a [`BlockRangeRequest`] as a `SendTo` outbound frame (#514).
///
/// [`BlockRangeRequest`]: WireMessage::BlockRangeRequest
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

/// Encode a [`BlockRangeResponse`] as a `SendTo` outbound frame (#514),
/// signing the payload so an out-of-range or wrong-shape response is
/// non-repudiable evidence — same trust model as
/// [`egress_block_response`].
///
/// `from_height` / `to_height` echo the matching `BlockRangeRequest`.
/// `blocks` is the contiguous run the responder is serving, in
/// strictly ascending height order; the caller is responsible for
/// having capped the slice at
/// [`crate::wire::BLOCK_RANGE_RESPONSE_MAX_BLOCKS`].
///
/// [`BlockRangeResponse`]: WireMessage::BlockRangeResponse
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

/// Encode a [`SnapshotManifestRequest`] as a `SendTo` outbound frame.
///
/// [`SnapshotManifestRequest`]: WireMessage::SnapshotManifestRequest
pub fn egress_snapshot_manifest_request(height: Option<u64>, to: NodeId) -> Outbound {
    let wire = WireMessage::SnapshotManifestRequest { height };
    let payload = codec::encode(&wire).expect("SnapshotManifestRequest encoding must not fail");
    Outbound::SendTo { to, payload }
}

/// Encode a [`SnapshotManifestResponse`] as a `SendTo` outbound frame.
///
/// [`SnapshotManifestResponse`]: WireMessage::SnapshotManifestResponse
pub fn egress_snapshot_manifest_response(
    manifest: Option<SnapshotManifest>,
    to: NodeId,
) -> Outbound {
    let wire = WireMessage::SnapshotManifestResponse(manifest);
    let payload = codec::encode(&wire).expect("SnapshotManifestResponse encoding must not fail");
    Outbound::SendTo { to, payload }
}

/// Encode a [`SnapshotChunkRequest`] as a `SendTo` outbound frame.
///
/// [`SnapshotChunkRequest`]: WireMessage::SnapshotChunkRequest
pub fn egress_snapshot_chunk_request(height: u64, chunk_idx: u32, to: NodeId) -> Outbound {
    let wire = WireMessage::SnapshotChunkRequest { height, chunk_idx };
    let payload = codec::encode(&wire).expect("SnapshotChunkRequest encoding must not fail");
    Outbound::SendTo { to, payload }
}

/// Encode a [`SnapshotChunkResponse`] as a `SendTo` outbound frame.
///
/// [`SnapshotChunkResponse`]: WireMessage::SnapshotChunkResponse
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

/// Sign a [`ConsensusMsg`] and wrap it in the appropriate [`WireMessage`]
/// variant.
///
/// On `bls_aggregated` chains, `bls_signer` must be `Some(_)` and is
/// consulted whenever a `Vote` is being signed: the BLS partial is
/// produced over the same canonical pre-image that the QC-aggregate
/// verifier reconstructs over `(view, block_hash)` — i.e.
/// [`preimage`]`(&Vote { view, block_hash })`. On `ed25519_collected`
/// chains, `bls_signer` is `None` and the optional second wire field
/// is left empty.
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

/// Sign `msg` and return both the wire payload and the [`Dispatch`] items
/// that a peer would produce on receiving that wire frame.
///
/// The integration layer uses this to drive a single source of truth for
/// self-addressed consensus actions: the same signed envelope is shipped
/// on the wire (for peers) and fed back through the local dispatcher
/// (for this node's own safety core / pacemaker). Production p2p
/// broadcasts and point-to-point sends do not loop back to the sender,
/// so without this local feed the leader of view `v` would never vote
/// on its own proposal and the leader of view `v+1` would never count
/// its own vote — see issue #118.
///
/// Signature verification is skipped for the local-loopback dispatches:
/// the envelope was just produced by `signer`, so re-verifying is
/// redundant work. `key_history` is still consulted to resolve the
/// signer pubkey to its stable [`ValidatorId`] (#394), which is
/// stamped on the [`crate::dispatch::Verified`] envelope so the safety core's bitmap
/// lookup matches the wire path's resolution after a rotation. The
/// returned `Dispatch` items otherwise match the output of
/// `ingress_wire` for this frame arriving from `signer.node_id()`.
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
    // Resolve `signer.node_id()` to its stable `ValidatorId` exactly
    // as the wire path does in `verify_signer_at`. Using
    // `from_genesis_pubkey` directly would silently desync from the
    // wire path after a rotation: on Ed25519 chains the leader's
    // self-vote wouldn't fold into the QC bucket because the
    // bitmap-index lookup would compute the wrong stable id (#394).
    //
    // The fallback to `from_genesis_pubkey` covers tests where the
    // local signer's pubkey is not registered in `key_history` (e.g.
    // a `fresh_signer` whose bytes were never seeded into the
    // genesis set). Pre-#394 the loopback always re-tagged, so the
    // safety core would compute a `ValidatorId` whose bytes are not
    // in the validator set and silently drop the message at the
    // bitmap lookup. Falling back here preserves that
    // byte-identical behaviour: production validators are always
    // registered (their genesis pubkey seeds the key history at
    // boot), so the registered branch is taken; tests with an
    // unregistered local signer follow the same drop-at-safety-core
    // path they always did.
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
                    // Loopback: we just signed `signed` ourselves via
                    // `sign_consensus_msg`, so it is verified by
                    // construction (the doc comment above explicitly
                    // notes signature verification is skipped on
                    // loopback). Wrap to satisfy the typestate, with
                    // the same `ValidatorId` resolution the wire path
                    // would compute.
                    Verified::wrap_after_verify_with_signer(signed, signer_validator_id),
                )),
                Dispatch::Pacemaker(pacemaker::Event::OnProposalReceived(view)),
                // Mirror the wire ingress path: emit OnQc(justify.view)
                // so a future-view proposal whose QC we never saw
                // directly still advances the pacemaker (#436). On the
                // leader's own loopback `justify.view == current_view -
                // 1`, which the pacemaker treats as stale and ignores.
                Dispatch::Pacemaker(pacemaker::Event::OnQc(justify_view)),
            ]
        }
        WireMessage::Vote(signed, bls_partial) => {
            // Carry the BLS partial through the loopback so the
            // self-vote on a BLS chain folds the partial into the
            // leader's QC bucket — the next-view leader voting on
            // its own proposal must contribute its BLS partial just
            // like any peer's vote (#118 + #354 step 2). The variant
            // mirrors the wire path: presence of a partial means BLS;
            // absence means Ed25519 (#372).
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
        // sign_consensus_msg only ever produces Proposal/Vote/NewView.
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
