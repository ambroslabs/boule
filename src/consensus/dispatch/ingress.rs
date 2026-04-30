//! Per-[`WireMessage`] ingress routing.
//!
//! [`ingress_wire_with_qc_verification`] dispatches to one
//! `ingress_<variant>` function per [`WireMessage`] variant rather
//! than nesting verifier calls inside a single match. The split makes
//! the call sites in [`crate::consensus::node`]'s event loop testable
//! in isolation — each variant function takes the already-decoded
//! payload plus chain context and returns the [`Dispatch`] items
//! that variant produces.

use crate::consensus::hotstuff::NewView;
use crate::consensus::hotstuff::qc::{TimeoutVote, Vote};
use crate::consensus::hotstuff::{Proposal, step::Event as SafetyEvent};
use crate::consensus::node::WireMessage;
use crate::consensus::pacemaker;
use crate::consensus::validator_history::ValidatorSetHistory;
use crate::consensus::validator_key_history::ValidatorKeyHistory;
use crate::crypto::signed::{ChainId, Signed};
use crate::p2p::NodeId;
use crate::replication::block::{Block, BlockHash};
use crate::replication::snapshot::SnapshotManifest;

use super::codec;
use super::verify::bls_partial::verify_bls_partial_if_required;
use super::verify::envelope::{verify_sig, verify_signer_at};
use super::verify::proposal_history::verify_proposal_history_commitment_if_requested;
use super::verify::qc::{verify_high_qc_piggyback, verify_qc_if_requested};
use super::{Dispatch, IngressError, QcVerification, Verified};

/// Decode and verify a raw wire frame, producing zero or more [`Dispatch`]
/// items.
///
/// `bytes` is the raw payload from [`crate::p2p::ProtocolEvent::Message`]
/// (protocol tag and length prefix already stripped).
///
/// `history` is the per-view validator-set lookup. Each consensus message
/// is verified against the set authoritative at that message's own view:
/// proposals at `block.header.view`, votes and timeout votes at their
/// `view` field, and NewView at `high_qc.view`. With history holding only
/// the genesis boundary this matches the prior single-set behaviour
/// exactly; once reconfiguration boundaries land via #253, signers get
/// validated against the right set on either side of each boundary.
///
/// `key_history` is the per-validator signing-key lookup. The signer
/// pubkey on the wire is bridged through [`ValidatorKeyHistory::validator_for`](crate::consensus::validator_key_history::ValidatorKeyHistory::validator_for)
/// to the validator's stable identifier (the one that appears in the
/// validator set), so a vote signed under a post-rotation key is still
/// recognized as belonging to the same validator that was originally
/// seated. Spanning votes — late votes for older views — verify against
/// whichever key was active at *that* view, which is also looked up
/// here. Without rotations applied, every validator's only entry is
/// their genesis key, so this matches the prior behaviour exactly.
///
/// Returns [`Err(IngressError)`] if the frame can't be decoded or fails
/// signature verification. The event loop should log and drop on error;
/// the state machines are never touched.
pub fn ingress(
    from: NodeId,
    bytes: &[u8],
    history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
    chain_id: &ChainId,
) -> Result<Vec<Dispatch>, IngressError> {
    ingress_with_qc_verification(
        from,
        bytes,
        history,
        key_history,
        &QcVerification::Skip,
        chain_id,
    )
}

/// Decode + verify a wire frame, additionally checking embedded QC
/// aggregates per `qc_verification`. Production callers pass
/// [`QcVerification::Verify`] with the chain's scheme; tests that
/// construct QCs with placeholder signatures pass [`QcVerification::Skip`].
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

/// Same as [`ingress`] but takes an already-decoded [`WireMessage`].
///
/// Exposed for unit tests that construct wire messages directly.
pub fn ingress_wire(
    from: NodeId,
    msg: WireMessage,
    history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
    chain_id: &ChainId,
) -> Result<Vec<Dispatch>, IngressError> {
    ingress_wire_with_qc_verification(
        from,
        msg,
        history,
        key_history,
        &QcVerification::Skip,
        chain_id,
    )
}

/// QC-verifying counterpart to [`ingress_wire`]. See [`QcVerification`]
/// for the scheme-aware verification policy.
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
        WireMessage::BlockRequest(hash) => Ok(ingress_block_request(hash, from)),
        WireMessage::BlockResponse(block) => Ok(ingress_block_response(block, from)),
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
    }
}

/// Verify a `Signed<Proposal>` envelope and emit the safety-core
/// `ProposalReceived` event plus the pacemaker `OnProposalReceived`
/// liveness signal. Runs (in order) signer membership, envelope
/// signature, the `Proposal.justify` QC aggregate, and the
/// `validator_history_commitment` post-block check.
pub fn ingress_proposal(
    signed: Signed<Proposal>,
    history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
    qc_verification: &QcVerification<'_>,
    chain_id: &ChainId,
) -> Result<Vec<Dispatch>, IngressError> {
    let view = signed.payload.block.header.view;
    let signer_validator_id = verify_signer_at(signed.signer, view, history, key_history)?;
    verify_sig(&signed, chain_id)?;
    verify_qc_if_requested(
        &signed.payload.justify,
        history,
        key_history,
        qc_verification,
        chain_id,
    )?;
    // #325 PR C: verify the leader's stamped
    // `validator_history_commitment` matches what we would compute
    // over the proposed block's reconfig/rotation commands. Catches
    // a Byzantine leader who proposes blocks with a forged
    // commitment, before any honest replica votes on the block.
    // PR B catches the same class of forgery at recovery time;
    // PR C closes the window between propose and restart.
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
    ])
}

/// Verify a `Signed<Vote>` envelope (plus the optional BLS partial)
/// and emit the safety-core `VoteReceived` event.
pub fn ingress_vote(
    signed: Signed<Vote>,
    bls_partial: Option<crate::crypto::sig_scheme::BlsPartialSig>,
    history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
    qc_verification: &QcVerification<'_>,
    chain_id: &ChainId,
) -> Result<Vec<Dispatch>, IngressError> {
    let signer_validator_id =
        verify_signer_at(signed.signer, signed.payload.view, history, key_history)?;
    verify_sig(&signed, chain_id)?;
    verify_bls_partial_if_required(&signed, bls_partial.as_ref(), qc_verification, chain_id)?;
    // After `verify_bls_partial_if_required` succeeds, BLS chains
    // have a `Some` partial and Ed25519 chains have a `None`. Encode
    // that invariant in the `VoteVariant` enum (#372) so the safety
    // core can dispatch on the type instead of a defensive runtime
    // check.
    let verified = Verified::wrap_after_verify_with_signer(signed, signer_validator_id);
    let variant =
        crate::consensus::hotstuff::step::VoteVariant::from_optional_partial(verified, bls_partial);
    Ok(vec![Dispatch::Safety(SafetyEvent::VoteReceived(variant))])
}

/// Verify a `Signed<NewView>` envelope and emit the safety-core
/// `NewViewReceived` event plus the pacemaker `OnQc` signal at the
/// piggybacked `high_qc.view`.
pub fn ingress_new_view(
    signed: Signed<NewView>,
    history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
    qc_verification: &QcVerification<'_>,
    chain_id: &ChainId,
) -> Result<Vec<Dispatch>, IngressError> {
    // The wire envelope doesn't carry an explicit "current view"
    // field — the closest signal we have is `high_qc.view`. The
    // signer at the receiving boundary is whoever entered the
    // *next* view armed with this high_qc, so we look up against
    // the set at `high_qc.view`. The `high_qc` itself was minted
    // at `high_qc.view` under the same set (#250) — so its
    // bitmap shape, signature count, and quorum threshold must
    // all match the historical set, not the current one.
    let high_qc_view = signed.payload.high_qc.view;
    let signer_validator_id = verify_signer_at(signed.signer, high_qc_view, history, key_history)?;
    verify_sig(&signed, chain_id)?;
    // #250: well-formedness of the embedded high_qc against the
    // set authoritative at `high_qc.view`. A NewView whose
    // high_qc was constructed against a different set size
    // (e.g. minted under the new set after a reconfig but
    // claimed at a pre-boundary view) is rejected here before
    // it can pollute the safety core's `state.high_qc`.
    let vs = history.set_at(high_qc_view);
    if !signed.payload.high_qc.is_well_formed(&vs) {
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
        // Inform the pacemaker that we've seen a QC up to `high_qc_view`.
        // It ignores stale events, so this is always safe to emit.
        Dispatch::Pacemaker(pacemaker::Event::OnQc(high_qc_view)),
    ])
}

/// Verify a `Signed<TimeoutVote>` envelope, soft-verify the optional
/// `high_qc` piggyback, and emit the [`Dispatch::TimeoutVote`] frame.
///
/// The round-sync hint that closes the #218 wedge fires at the
/// integration layer (`on_timeout_vote`), not here: it only kicks in
/// once the local timeout bucket has accumulated `f + 1` distinct
/// signers for the same view, ensuring at least one honest peer
/// agrees. A single-signer hint at this layer would let a Byzantine
/// `TimeoutSpammer` (see `sim_byzantine`) drag honest replicas'
/// `current_view` arbitrarily forward by broadcasting
/// `TimeoutVote(view = u64::MAX)`. The bucket-driven path keeps the
/// trust gradient honest.
///
/// The piggybacked `high_qc` *is* checked here (audit finding 10-F3,
/// issue #321): a Byzantine voter who attaches a forged fresher-view
/// QC to an otherwise honest timeout vote would otherwise launder the
/// QC through the bucket's `best_high_qc` and the TC self-NewView
/// loopback straight into the safety core's `state.high_qc`. We
/// verify the piggyback at ingress and surface the result as
/// `high_qc_trusted` rather than rejecting the envelope: dropping the
/// whole timeout vote on a bad piggyback would hand a Byzantine peer
/// a way to suppress honest timeout signal by attaching garbage to it.
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

/// Convert an inbound `BlockRequest` into a [`Dispatch::ServeBlock`]
/// for the integration layer to satisfy.
pub fn ingress_block_request(hash: BlockHash, from: NodeId) -> Vec<Dispatch> {
    vec![Dispatch::ServeBlock { hash, to: from }]
}

/// Convert an inbound `BlockResponse` into a [`Dispatch::ReceiveBlock`].
pub fn ingress_block_response(block: Option<Block>, from: NodeId) -> Vec<Dispatch> {
    vec![Dispatch::ReceiveBlock { block, from }]
}

/// Convert an inbound `SnapshotManifestRequest` into a
/// [`Dispatch::ServeSnapshotManifest`].
pub fn ingress_snapshot_manifest_request(height: Option<u64>, from: NodeId) -> Vec<Dispatch> {
    vec![Dispatch::ServeSnapshotManifest { height, to: from }]
}

/// Convert an inbound `SnapshotManifestResponse` into a
/// [`Dispatch::ReceiveSnapshotManifest`].
pub fn ingress_snapshot_manifest_response(
    manifest: Option<SnapshotManifest>,
    from: NodeId,
) -> Vec<Dispatch> {
    vec![Dispatch::ReceiveSnapshotManifest { manifest, from }]
}

/// Convert an inbound `SnapshotChunkRequest` into a
/// [`Dispatch::ServeSnapshotChunk`].
pub fn ingress_snapshot_chunk_request(height: u64, chunk_idx: u32, from: NodeId) -> Vec<Dispatch> {
    vec![Dispatch::ServeSnapshotChunk {
        height,
        chunk_idx,
        to: from,
    }]
}

/// Convert an inbound `SnapshotChunkResponse` into a
/// [`Dispatch::ReceiveSnapshotChunk`].
pub fn ingress_snapshot_chunk_response(
    height: u64,
    chunk_idx: u32,
    payload: Option<bytes::Bytes>,
    from: NodeId,
) -> Vec<Dispatch> {
    vec![Dispatch::ReceiveSnapshotChunk {
        height,
        chunk_idx,
        payload,
        from,
    }]
}
