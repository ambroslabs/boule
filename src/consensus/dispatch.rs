//! Ingress/egress helpers and the unified `NodeEvent` / `Dispatch` enums.
//!
//! These are the "translation layer" between the raw p2p bytes and the pure
//! state machines ([`HotStuffCore`] / [`Pacemaker`]):
//!
//! - [`NodeEvent`]: unified event produced by the event loop's `select!` arms.
//! - [`Dispatch`]: what the event loop should route after ingress.
//! - [`Outbound`]: a ready-to-send frame for the p2p layer.
//! - [`ingress`]: decode + verify a raw wire frame into zero or more
//!   [`Dispatch`] items.
//! - [`egress_safety`]: translate a HotStuff safety-core [`Action`] into an
//!   [`Outbound`] frame (returns `None` for non-wire actions like
//!   `Persist` / `Commit`).
//!
//! # Signature verification
//!
//! [`ingress`] checks that the claimed signer is a member of the validator
//! set **and** that the Ed25519 signature is valid over the domain-separated
//! pre-image before producing any `Dispatch` item. Invalid or unknown signers
//! yield [`IngressError::InvalidSignature`] / [`IngressError::UnknownSigner`];
//! the event loop should log and drop those frames.
//!
//! # Pacemaker co-events
//!
//! Several inbound messages are relevant to *both* the safety core and the
//! pacemaker (e.g. a Proposal advances the pacemaker's liveness timer; a
//! NewView may advance the view if its high_qc is fresh). [`ingress`] emits
//! both events when applicable — the event loop feeds each to its state
//! machine in order.

#![allow(dead_code)]

use bytes::Bytes;

use crate::consensus::View;
use crate::consensus::hotstuff::ConsensusMsg;
use crate::consensus::hotstuff::qc::TimeoutVote;
use crate::consensus::hotstuff::step::Action as SafetyAction;
use crate::consensus::node::WireMessage;
use crate::consensus::pacemaker;
use crate::consensus::validator_history::ValidatorSetHistory;
use crate::consensus::validator_key_history::ValidatorKeyHistory;
use crate::crypto::signed::{Signed, SignedMessage, Signer};
use crate::p2p::NodeId;
use crate::replication::block::{Block, BlockHash};
use crate::replication::snapshot::SnapshotManifest;

// ── NodeEvent ────────────────────────────────────────────────────────────────

/// Unified event produced by each arm of the event loop's `select!`.
///
/// The event loop decodes raw [`WireMessage`] bytes into this enum before
/// dispatching — the state machines never see raw bytes.
#[derive(Debug)]
pub enum NodeEvent {
    /// A decoded frame arrived from `from`. Signature has not yet been
    /// verified — [`ingress`] does that before yielding [`Dispatch`] items.
    Inbound { from: NodeId, msg: Box<WireMessage> },
    /// The view timer fired for this view. Feed as
    /// [`pacemaker::Event::OnTimeout`] to the pacemaker.
    ViewTimerFired(View),
    /// A new peer completed the TLS handshake and is reachable.
    PeerConnected(NodeId),
    /// A peer disconnected.
    PeerDisconnected(NodeId),
    /// Graceful shutdown signal.
    Shutdown,
}

// ── Dispatch ─────────────────────────────────────────────────────────────────

/// What the event loop should route after a successful [`ingress`] call.
///
/// A single inbound message can produce more than one `Dispatch` item
/// (e.g. a Proposal yields both a safety-core event and a pacemaker
/// event). The event loop applies them in slice order.
#[derive(Debug)]
pub enum Dispatch {
    /// Route to [`HotStuffCore::step`].
    Safety(crate::consensus::hotstuff::step::Event),
    /// Route to [`Pacemaker::step`].
    Pacemaker(pacemaker::Event),
    /// Peer requested the block with this hash; serve it if held.
    ServeBlock { hash: BlockHash, to: NodeId },
    /// Peer replied to our [`WireMessage::BlockRequest`].
    ReceiveBlock { block: Option<Block>, from: NodeId },
    /// A signed [`TimeoutVote`] arrived. The integration layer feeds
    /// it into its timeout-certificate bucket; on reaching quorum the
    /// bucket emits [`pacemaker::Event::OnTimeoutCert`] directly.
    TimeoutVote(Signed<TimeoutVote>),
    /// Peer asked for a snapshot manifest (latest if `height = None`,
    /// or at exact height). The integration layer looks the manifest
    /// up in its [`crate::replication::SnapshotStore`] and replies
    /// with [`WireMessage::SnapshotManifestResponse`].
    ServeSnapshotManifest { height: Option<u64>, to: NodeId },
    /// Peer replied to our [`WireMessage::SnapshotManifestRequest`].
    /// The joiner-side state machine (issue #229) consumes this; the
    /// run loop in this PR logs and drops, since no joiner is wired
    /// in yet.
    ReceiveSnapshotManifest {
        manifest: Option<SnapshotManifest>,
        from: NodeId,
    },
    /// Peer asked for chunk `chunk_idx` of the snapshot at `height`.
    /// The integration layer looks the chunk up and replies with
    /// [`WireMessage::SnapshotChunkResponse`].
    ServeSnapshotChunk {
        height: u64,
        chunk_idx: u32,
        to: NodeId,
    },
    /// Peer replied to our [`WireMessage::SnapshotChunkRequest`].
    /// Same joiner-side note as for [`Dispatch::ReceiveSnapshotManifest`].
    ReceiveSnapshotChunk {
        height: u64,
        chunk_idx: u32,
        payload: Option<bytes::Bytes>,
        from: NodeId,
    },
}

// ── Outbound ─────────────────────────────────────────────────────────────────

/// A postcard-encoded, ready-to-send frame for the p2p layer.
///
/// Wraps the same shape as [`crate::p2p::ProtocolOutbound`] but without
/// the tokio channel dependency — the event loop converts this to
/// `ProtocolOutbound` when sending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outbound {
    /// Broadcast to every currently connected peer.
    Broadcast(Bytes),
    /// Send to a single peer.
    SendTo { to: NodeId, payload: Bytes },
}

// ── IngressError ─────────────────────────────────────────────────────────────

/// Reasons an inbound frame can be rejected without feeding any event to the
/// state machines. The event loop should log these and drop the frame.
#[derive(Debug)]
pub enum IngressError {
    Decode(postcard::Error),
    UnknownSigner(NodeId),
    InvalidSignature(anyhow::Error),
    /// A NewView's `high_qc` is not well-formed under the validator set
    /// authoritative at `high_qc.view` (bitmap length mismatch, stray
    /// bits, or signature/bit count divergence). Carries the
    /// `high_qc.view` so logs and tests can distinguish boundaries.
    MalformedHighQc {
        view: View,
    },
}

impl std::fmt::Display for IngressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IngressError::Decode(e) => write!(f, "postcard decode failed: {e}"),
            IngressError::UnknownSigner(id) => {
                write!(f, "signer {id:?} is not in the validator set")
            }
            IngressError::InvalidSignature(e) => write!(f, "signature verification failed: {e}"),
            IngressError::MalformedHighQc { view } => write!(
                f,
                "NewView's high_qc at view {view} is not well-formed under the historical validator set",
            ),
        }
    }
}

impl std::error::Error for IngressError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            IngressError::Decode(e) => Some(e),
            IngressError::InvalidSignature(e) => Some(e.as_ref()),
            IngressError::UnknownSigner(_) | IngressError::MalformedHighQc { .. } => None,
        }
    }
}

impl From<postcard::Error> for IngressError {
    fn from(e: postcard::Error) -> Self {
        IngressError::Decode(e)
    }
}

// ── ingress ───────────────────────────────────────────────────────────────────

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
/// pubkey on the wire is bridged through [`ValidatorKeyHistory::validator_for`]
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
) -> Result<Vec<Dispatch>, IngressError> {
    let msg: WireMessage = postcard::from_bytes(bytes)?;
    ingress_wire(from, msg, history, key_history)
}

/// Same as [`ingress`] but takes an already-decoded [`WireMessage`].
///
/// Exposed for unit tests that construct wire messages directly.
pub fn ingress_wire(
    from: NodeId,
    msg: WireMessage,
    history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
) -> Result<Vec<Dispatch>, IngressError> {
    match msg {
        WireMessage::Proposal(signed) => {
            let view = signed.payload.block.header.view;
            verify_signer_at(signed.signer, view, history, key_history)?;
            verify_sig(&signed)?;
            Ok(vec![
                Dispatch::Safety(crate::consensus::hotstuff::step::Event::ProposalReceived(
                    signed,
                )),
                Dispatch::Pacemaker(pacemaker::Event::OnProposalReceived(view)),
            ])
        }

        WireMessage::Vote(signed) => {
            verify_signer_at(signed.signer, signed.payload.view, history, key_history)?;
            verify_sig(&signed)?;
            Ok(vec![Dispatch::Safety(
                crate::consensus::hotstuff::step::Event::VoteReceived(signed),
            )])
        }

        WireMessage::NewView(signed) => {
            // The wire envelope doesn't carry an explicit "current view"
            // field — the closest signal we have is `high_qc.view`. The
            // signer at the receiving boundary is whoever entered the
            // *next* view armed with this high_qc, so we look up against
            // the set at `high_qc.view`. The `high_qc` itself was minted
            // at `high_qc.view` under the same set (#250) — so its
            // bitmap shape, signature count, and quorum threshold must
            // all match the historical set, not the current one.
            let high_qc_view = signed.payload.high_qc.view;
            verify_signer_at(signed.signer, high_qc_view, history, key_history)?;
            verify_sig(&signed)?;
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
            Ok(vec![
                Dispatch::Safety(crate::consensus::hotstuff::step::Event::NewViewReceived(
                    signed,
                )),
                // Inform the pacemaker that we've seen a QC up to `high_qc_view`.
                // It ignores stale events, so this is always safe to emit.
                Dispatch::Pacemaker(pacemaker::Event::OnQc(high_qc_view)),
            ])
        }

        WireMessage::TimeoutVote(signed) => {
            verify_signer_at(signed.signer, signed.payload.view, history, key_history)?;
            verify_sig(&signed)?;
            // The round-sync hint that closes the #218 wedge fires
            // at the integration layer (`on_timeout_vote`), not here:
            // it only kicks in once the local timeout bucket has
            // accumulated `f + 1` distinct signers for the same view,
            // ensuring at least one honest peer agrees. A
            // single-signer hint at this layer would let a Byzantine
            // `TimeoutSpammer` (see `sim_byzantine`) drag honest
            // replicas' `current_view` arbitrarily forward by
            // broadcasting `TimeoutVote(view = u64::MAX)`. The
            // bucket-driven path keeps the trust gradient honest.
            Ok(vec![Dispatch::TimeoutVote(signed)])
        }

        WireMessage::BlockRequest(hash) => Ok(vec![Dispatch::ServeBlock { hash, to: from }]),

        WireMessage::BlockResponse(block) => Ok(vec![Dispatch::ReceiveBlock { block, from }]),

        WireMessage::SnapshotManifestRequest { height } => {
            Ok(vec![Dispatch::ServeSnapshotManifest { height, to: from }])
        }

        WireMessage::SnapshotManifestResponse(manifest) => {
            Ok(vec![Dispatch::ReceiveSnapshotManifest { manifest, from }])
        }

        WireMessage::SnapshotChunkRequest { height, chunk_idx } => {
            Ok(vec![Dispatch::ServeSnapshotChunk {
                height,
                chunk_idx,
                to: from,
            }])
        }

        WireMessage::SnapshotChunkResponse {
            height,
            chunk_idx,
            payload,
        } => Ok(vec![Dispatch::ReceiveSnapshotChunk {
            height,
            chunk_idx,
            payload,
            from,
        }]),
    }
}

/// Check that `signer` is the validator's currently-active signing key
/// at view `view`, where the validator must be a member of the
/// validator set authoritative at `view`.
///
/// The check has three steps:
/// 1. Resolve `signer` to a stable identifier via the key history's
///    reverse index. If `signer` has never been associated with any
///    validator (genesis, current, or any prior rotation key), the
///    message is from an outright unknown party.
/// 2. The stable identifier must appear in the validator set at `view`.
///    A vote signed by a known-but-removed validator at a view after
///    they were removed must be rejected.
/// 3. `signer` must equal the active signing key for that validator at
///    `view`. A vote signed under a stale key (the validator has since
///    rotated) or a future key (the rotation hasn't taken effect yet)
///    is rejected — the verifier always checks against whatever was
///    actually authoritative at the message's view.
///
/// All three failure modes report `UnknownSigner` for now: external
/// observers shouldn't be able to distinguish "you aren't in the set"
/// from "you used the wrong key for this view" — both indicate the
/// message has no business being processed. Splitting the variants for
/// internal telemetry is a follow-up.
fn verify_signer_at(
    signer: NodeId,
    view: View,
    history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
) -> Result<(), IngressError> {
    let stable_id = key_history
        .validator_for(&signer)
        .ok_or(IngressError::UnknownSigner(signer))?;

    if history.set_at(view).index_of(&stable_id).is_none() {
        return Err(IngressError::UnknownSigner(signer));
    }

    let active = key_history
        .key_at(&stable_id, view)
        .expect("validator with reverse-index entry has a non-empty history list");
    if active != signer {
        return Err(IngressError::UnknownSigner(signer));
    }

    Ok(())
}

/// Verify the Ed25519 signature on a `Signed<T>` envelope.
fn verify_sig<T>(signed: &Signed<T>) -> Result<(), IngressError>
where
    T: serde::Serialize + SignedMessage,
{
    signed
        .verify(&signed.signer)
        .map_err(IngressError::InvalidSignature)
}

// ── egress_safety ─────────────────────────────────────────────────────────────

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
) -> anyhow::Result<Option<Outbound>> {
    match action {
        SafetyAction::Broadcast(msg) => {
            let wire = sign_consensus_msg(msg, signer)?;
            let payload = postcard::to_stdvec(&wire)
                .map(Bytes::from)
                .map_err(anyhow::Error::from)?;
            Ok(Some(Outbound::Broadcast(payload)))
        }

        SafetyAction::SendTo(target, msg) => {
            let wire = sign_consensus_msg(msg, signer)?;
            let payload = postcard::to_stdvec(&wire)
                .map(Bytes::from)
                .map_err(anyhow::Error::from)?;
            Ok(Some(Outbound::SendTo {
                to: *target,
                payload,
            }))
        }

        SafetyAction::RequestBlock { hash, peer, .. } => {
            Ok(Some(egress_block_request(*hash, *peer)))
        }

        // Non-wire actions: handled by the event loop directly.
        SafetyAction::Persist(_) | SafetyAction::Commit(_) => Ok(None),
    }
}

/// Encode a [`BlockRequest`] as a `SendTo` outbound frame.
///
/// [`BlockRequest`]: WireMessage::BlockRequest
pub fn egress_block_request(hash: BlockHash, to: NodeId) -> Outbound {
    let wire = WireMessage::BlockRequest(hash);
    let payload = postcard::to_stdvec(&wire)
        .map(Bytes::from)
        .expect("BlockRequest encoding must not fail");
    Outbound::SendTo { to, payload }
}

/// Encode a [`BlockResponse`] as a `SendTo` outbound frame.
///
/// [`BlockResponse`]: WireMessage::BlockResponse
pub fn egress_block_response(block: Option<Block>, to: NodeId) -> Outbound {
    let wire = WireMessage::BlockResponse(block);
    let payload = postcard::to_stdvec(&wire)
        .map(Bytes::from)
        .expect("BlockResponse encoding must not fail");
    Outbound::SendTo { to, payload }
}

/// Encode a [`SnapshotManifestRequest`] as a `SendTo` outbound frame.
///
/// [`SnapshotManifestRequest`]: WireMessage::SnapshotManifestRequest
pub fn egress_snapshot_manifest_request(height: Option<u64>, to: NodeId) -> Outbound {
    let wire = WireMessage::SnapshotManifestRequest { height };
    let payload = postcard::to_stdvec(&wire)
        .map(Bytes::from)
        .expect("SnapshotManifestRequest encoding must not fail");
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
    let payload = postcard::to_stdvec(&wire)
        .map(Bytes::from)
        .expect("SnapshotManifestResponse encoding must not fail");
    Outbound::SendTo { to, payload }
}

/// Encode a [`SnapshotChunkRequest`] as a `SendTo` outbound frame.
///
/// [`SnapshotChunkRequest`]: WireMessage::SnapshotChunkRequest
pub fn egress_snapshot_chunk_request(height: u64, chunk_idx: u32, to: NodeId) -> Outbound {
    let wire = WireMessage::SnapshotChunkRequest { height, chunk_idx };
    let payload = postcard::to_stdvec(&wire)
        .map(Bytes::from)
        .expect("SnapshotChunkRequest encoding must not fail");
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
    let payload = postcard::to_stdvec(&wire)
        .map(Bytes::from)
        .expect("SnapshotChunkResponse encoding must not fail");
    Outbound::SendTo { to, payload }
}

/// Sign a [`ConsensusMsg`] and wrap it in the appropriate [`WireMessage`]
/// variant.
fn sign_consensus_msg(msg: &ConsensusMsg, signer: &dyn Signer) -> anyhow::Result<WireMessage> {
    match msg {
        ConsensusMsg::Proposal(p) => {
            let signed = Signed::sign(p.clone(), signer)?;
            Ok(WireMessage::Proposal(signed))
        }
        ConsensusMsg::Vote(v) => {
            let signed = Signed::sign(v.clone(), signer)?;
            Ok(WireMessage::Vote(signed))
        }
        ConsensusMsg::NewView(nv) => {
            let signed = Signed::sign(nv.clone(), signer)?;
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
/// redundant work. The returned `Dispatch` items otherwise match the
/// output of [`ingress_wire`] for this frame arriving from
/// `signer.node_id()`.
pub fn egress_consensus_msg_with_loopback(
    msg: &ConsensusMsg,
    signer: &dyn Signer,
) -> anyhow::Result<(Bytes, Vec<Dispatch>)> {
    let wire = sign_consensus_msg(msg, signer)?;
    let payload = postcard::to_stdvec(&wire)
        .map(Bytes::from)
        .map_err(anyhow::Error::from)?;
    let dispatches = match &wire {
        WireMessage::Proposal(signed) => {
            let view = signed.payload.block.header.view;
            vec![
                Dispatch::Safety(crate::consensus::hotstuff::step::Event::ProposalReceived(
                    signed.clone(),
                )),
                Dispatch::Pacemaker(pacemaker::Event::OnProposalReceived(view)),
            ]
        }
        WireMessage::Vote(signed) => {
            vec![Dispatch::Safety(
                crate::consensus::hotstuff::step::Event::VoteReceived(signed.clone()),
            )]
        }
        WireMessage::NewView(signed) => {
            let high_qc_view = signed.payload.high_qc.view;
            vec![
                Dispatch::Safety(crate::consensus::hotstuff::step::Event::NewViewReceived(
                    signed.clone(),
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
        | WireMessage::SnapshotChunkResponse { .. } => {
            unreachable!("sign_consensus_msg always produces Proposal/Vote/NewView wire variants")
        }
    };
    Ok((payload, dispatches))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use rcgen::KeyPair as RcgenKeyPair;
    use rcgen::PKCS_ED25519;
    use zeroize::Zeroizing;

    use super::*;
    use crate::consensus::hotstuff::qc::Vote;
    use crate::consensus::hotstuff::step::Event as SafetyEvent;
    use crate::consensus::hotstuff::{NewView, Proposal, QuorumCertificate};
    use crate::consensus::validator_set::ValidatorSet;
    use crate::crypto::signed::{NodeSigner, Signed};
    use crate::p2p::identity::NodeIdentity;
    use crate::replication::block::Block;

    fn fresh_signer() -> NodeSigner {
        let kp = RcgenKeyPair::generate_for(&PKCS_ED25519).unwrap();
        let identity = NodeIdentity {
            pkcs8_der: Zeroizing::new(kp.serialize_der()),
        };
        NodeSigner::from_identity(&identity).unwrap()
    }

    fn genesis() -> Block {
        Block::genesis([0u8; 32])
    }

    fn sample_qc() -> QuorumCertificate {
        QuorumCertificate::new(0, genesis().hash(), 4)
    }

    fn make_vs_with_signers(signers: &[&NodeSigner]) -> ValidatorSet {
        let ids: Vec<NodeId> = signers.iter().map(|s| s.node_id()).collect();
        ValidatorSet::new(ids)
    }

    /// Test helper: build a [`ValidatorKeyHistory`] that mirrors the
    /// boundaries of `set_history` with no rotations applied. This is
    /// what every test in this module wants by default — the production
    /// path will mutate the key history when rotation txs commit
    /// (#260), but the ingress-layer tests below all set up their
    /// histories by hand.
    fn key_history_for(set_history: &ValidatorSetHistory) -> ValidatorKeyHistory {
        ValidatorKeyHistory::from_set_history(set_history)
    }

    /// Convenience: mirror of [`key_history_for`] for tests that have a
    /// single static [`ValidatorSet`] rather than a history.
    fn key_history_from_set(vs: &ValidatorSet) -> ValidatorKeyHistory {
        ValidatorKeyHistory::new(vs.iter().copied())
    }

    /// Test-only sugar: invoke [`ingress`] with the validator set
    /// pinned at genesis and a key history mirroring it. Most ingress
    /// tests don't care about reconfiguration boundaries — they just
    /// want "this `vs` is the only validator set the verifier should
    /// know about."
    fn ingress_with_genesis_set(
        from: NodeId,
        bytes: &[u8],
        vs: &ValidatorSet,
    ) -> Result<Vec<Dispatch>, IngressError> {
        let history = ValidatorSetHistory::from_genesis(vs.clone());
        let key_history = key_history_from_set(vs);
        ingress(from, bytes, &history, &key_history)
    }

    // ── ingress: Proposal ────────────────────────────────────────────────────

    #[test]
    fn ingress_proposal_happy_path() {
        let signer = fresh_signer();
        let vs = make_vs_with_signers(&[&signer]);

        let proposal = Proposal {
            block: genesis(),
            justify: sample_qc(),
        };
        let signed = Signed::sign(proposal.clone(), &signer).unwrap();
        let wire = WireMessage::Proposal(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let dispatches = ingress_with_genesis_set(signer.node_id(), &bytes, &vs).unwrap();
        assert_eq!(dispatches.len(), 2);
        assert!(matches!(
            dispatches[0],
            Dispatch::Safety(SafetyEvent::ProposalReceived(_))
        ));
        assert!(matches!(
            dispatches[1],
            Dispatch::Pacemaker(pacemaker::Event::OnProposalReceived(0))
        ));
    }

    #[test]
    fn ingress_proposal_unknown_signer_rejected() {
        let signer = fresh_signer();
        let other = fresh_signer();
        let vs = make_vs_with_signers(&[&other]); // signer not in VS

        let proposal = Proposal {
            block: genesis(),
            justify: sample_qc(),
        };
        let signed = Signed::sign(proposal, &signer).unwrap();
        let wire = WireMessage::Proposal(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let err = ingress_with_genesis_set(signer.node_id(), &bytes, &vs).unwrap_err();
        assert!(matches!(err, IngressError::UnknownSigner(_)));
    }

    #[test]
    fn ingress_proposal_bad_signature_rejected() {
        let signer = fresh_signer();
        let vs = make_vs_with_signers(&[&signer]);

        let proposal = Proposal {
            block: genesis(),
            justify: sample_qc(),
        };
        let mut signed = Signed::sign(proposal, &signer).unwrap();
        signed.sig[0] ^= 0xFF; // corrupt the signature

        let wire = WireMessage::Proposal(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let err = ingress_with_genesis_set(signer.node_id(), &bytes, &vs).unwrap_err();
        assert!(matches!(err, IngressError::InvalidSignature(_)));
    }

    // ── ingress: Vote ────────────────────────────────────────────────────────

    #[test]
    fn ingress_vote_happy_path() {
        let signer = fresh_signer();
        let vs = make_vs_with_signers(&[&signer]);

        let vote = Vote {
            view: 3,
            block_hash: [0xAB; 32],
        };
        let signed = Signed::sign(vote, &signer).unwrap();
        let wire = WireMessage::Vote(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let dispatches = ingress_with_genesis_set(signer.node_id(), &bytes, &vs).unwrap();
        assert_eq!(dispatches.len(), 1);
        assert!(matches!(
            dispatches[0],
            Dispatch::Safety(SafetyEvent::VoteReceived(_))
        ));
    }

    // ── ingress: NewView ─────────────────────────────────────────────────────

    #[test]
    fn ingress_new_view_emits_pacemaker_on_qc() {
        let signer = fresh_signer();
        let vs = make_vs_with_signers(&[&signer]);

        let mut high_qc = QuorumCertificate::new(7, [0xCD; 32], 1);
        high_qc.add_signature(0, [0x11; 64]);
        let nv = NewView { high_qc };
        let signed = Signed::sign(nv, &signer).unwrap();
        let wire = WireMessage::NewView(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let dispatches = ingress_with_genesis_set(signer.node_id(), &bytes, &vs).unwrap();
        assert_eq!(dispatches.len(), 2);
        assert!(matches!(
            dispatches[0],
            Dispatch::Safety(SafetyEvent::NewViewReceived(_))
        ));
        assert!(matches!(
            dispatches[1],
            Dispatch::Pacemaker(pacemaker::Event::OnQc(7))
        ));
    }

    // ── ingress: TimeoutVote ────────────────────────────────────────────────

    #[test]
    fn ingress_timeout_vote_happy_path() {
        let signer = fresh_signer();
        let vs = make_vs_with_signers(&[&signer]);

        let tv = TimeoutVote {
            view: 7,
            high_qc: Some(sample_qc()),
        };
        let signed = Signed::sign(tv, &signer).unwrap();
        let wire = WireMessage::TimeoutVote(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let dispatches = ingress_with_genesis_set(signer.node_id(), &bytes, &vs).unwrap();
        assert_eq!(dispatches.len(), 1);
        assert!(matches!(dispatches[0], Dispatch::TimeoutVote(_)));
    }

    #[test]
    fn ingress_timeout_vote_unknown_signer_rejected() {
        let signer = fresh_signer();
        let other = fresh_signer();
        let vs = make_vs_with_signers(&[&other]);

        let tv = TimeoutVote {
            view: 3,
            high_qc: None,
        };
        let signed = Signed::sign(tv, &signer).unwrap();
        let wire = WireMessage::TimeoutVote(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let err = ingress_with_genesis_set(signer.node_id(), &bytes, &vs).unwrap_err();
        assert!(matches!(err, IngressError::UnknownSigner(_)));
    }

    #[test]
    fn ingress_timeout_vote_bad_signature_rejected() {
        let signer = fresh_signer();
        let vs = make_vs_with_signers(&[&signer]);

        let tv = TimeoutVote {
            view: 1,
            high_qc: None,
        };
        let mut signed = Signed::sign(tv, &signer).unwrap();
        signed.sig[0] ^= 0xFF;
        let wire = WireMessage::TimeoutVote(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let err = ingress_with_genesis_set(signer.node_id(), &bytes, &vs).unwrap_err();
        assert!(matches!(err, IngressError::InvalidSignature(_)));
    }

    // ── ingress: BlockRequest / BlockResponse ────────────────────────────────

    #[test]
    fn ingress_block_request_no_signature_needed() {
        let from = [0x01u8; 32];
        let hash = [0xBBu8; 32];
        let vs = ValidatorSet::new(vec![]); // empty VS — block requests bypass auth
        let wire = WireMessage::BlockRequest(hash);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let dispatches = ingress_with_genesis_set(from, &bytes, &vs).unwrap();
        assert_eq!(dispatches.len(), 1);
        assert!(matches!(
            &dispatches[0],
            Dispatch::ServeBlock { hash: h, to } if h == &[0xBBu8; 32] && to == &from,
        ));
    }

    #[test]
    fn ingress_block_response_no_signature_needed() {
        let from = [0x02u8; 32];
        let vs = ValidatorSet::new(vec![]);
        let wire = WireMessage::BlockResponse(Some(genesis()));
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let dispatches = ingress_with_genesis_set(from, &bytes, &vs).unwrap();
        assert_eq!(dispatches.len(), 1);
        assert!(matches!(
            &dispatches[0],
            Dispatch::ReceiveBlock { block: Some(_), from: f } if f == &from,
        ));
    }

    #[test]
    fn ingress_garbage_bytes_returns_decode_error() {
        let from = [0x01u8; 32];
        let vs = ValidatorSet::new(vec![]);
        let err = ingress_with_genesis_set(from, &[0xFFu8; 16], &vs).unwrap_err();
        assert!(matches!(err, IngressError::Decode(_)));
    }

    // ── egress_safety ────────────────────────────────────────────────────────

    #[test]
    fn egress_broadcast_encodes_signed_proposal() {
        let signer = fresh_signer();
        let qc = sample_qc();

        let proposal = Proposal {
            block: genesis(),
            justify: qc.clone(),
        };
        let action = SafetyAction::Broadcast(ConsensusMsg::Proposal(proposal));

        let out = egress_safety(&action, &signer).unwrap().unwrap();
        let Outbound::Broadcast(payload) = out else {
            panic!("expected Broadcast");
        };
        let decoded: WireMessage = postcard::from_bytes(&payload).unwrap();
        assert!(matches!(decoded, WireMessage::Proposal(_)));
    }

    #[test]
    fn egress_send_to_encodes_vote() {
        let signer = fresh_signer();
        let target: NodeId = [0x55u8; 32];

        let vote = Vote {
            view: 5,
            block_hash: [0x77; 32],
        };
        let action = SafetyAction::SendTo(target, ConsensusMsg::Vote(vote));

        let out = egress_safety(&action, &signer).unwrap().unwrap();
        let Outbound::SendTo { to, payload } = out else {
            panic!("expected SendTo");
        };
        assert_eq!(to, target);
        let decoded: WireMessage = postcard::from_bytes(&payload).unwrap();
        assert!(matches!(decoded, WireMessage::Vote(_)));
    }

    #[test]
    fn egress_persist_returns_none() {
        let signer = fresh_signer();
        use crate::consensus::hotstuff::step::StateUpdate;
        let action = SafetyAction::Persist(StateUpdate::VotedInView { view: 1 });
        let out = egress_safety(&action, &signer).unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn egress_commit_returns_none() {
        let signer = fresh_signer();
        let action = SafetyAction::Commit(genesis());
        let out = egress_safety(&action, &signer).unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn egress_request_block_yields_send_to() {
        let signer = fresh_signer();
        let hash = [0xAAu8; 32];
        let peer: NodeId = [0x33u8; 32];
        let action = SafetyAction::RequestBlock {
            hash,
            peer,
            expected_height: 41,
            reason: crate::consensus::hotstuff::step::BlockSyncReason::UnknownParentOnProposal,
        };
        let out = egress_safety(&action, &signer).unwrap().unwrap();
        let Outbound::SendTo { to, payload } = out else {
            panic!("expected SendTo");
        };
        assert_eq!(to, peer);
        let decoded: WireMessage = postcard::from_bytes(&payload).unwrap();
        assert!(matches!(decoded, WireMessage::BlockRequest(_)));
    }

    // ── egress round-trip: signed payloads are verifiable ────────────────────

    #[test]
    fn egress_broadcast_proposal_is_verifiable() {
        let signer = fresh_signer();
        let vs = make_vs_with_signers(&[&signer]);

        let proposal = Proposal {
            block: genesis(),
            justify: sample_qc(),
        };
        let action = SafetyAction::Broadcast(ConsensusMsg::Proposal(proposal.clone()));
        let Outbound::Broadcast(payload) = egress_safety(&action, &signer).unwrap().unwrap() else {
            panic!("expected Broadcast");
        };

        // Run through ingress — should succeed.
        let dispatches = ingress_with_genesis_set(signer.node_id(), &payload, &vs).unwrap();
        assert_eq!(dispatches.len(), 2);
        match &dispatches[0] {
            Dispatch::Safety(SafetyEvent::ProposalReceived(s)) => {
                assert_eq!(s.payload.block, proposal.block);
            }
            other => panic!("unexpected first dispatch: {other:?}"),
        }
    }

    // ── Snapshot wire protocol (#228) ─────────────────────────────────────

    fn sample_quorum_qc(vs_len: usize, block_hash: [u8; 32]) -> QuorumCertificate {
        let mut qc = QuorumCertificate::new(0, block_hash, vs_len);
        for i in 0..crate::consensus::hotstuff::qc::quorum_size(vs_len) {
            qc.add_signature(i, [0u8; 64]);
        }
        qc
    }

    fn sample_manifest_for_dispatch() -> SnapshotManifest {
        use crate::replication::block::{Block, BlockHeader};
        let vs = ValidatorSet::new(vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]]);
        let parent_hash = Block::genesis([0u8; 32]).hash();
        let commands: Vec<bytes::Bytes> = Vec::new();
        let block = Block {
            header: BlockHeader {
                parent_hash,
                height: 42,
                view: 7,
                proposer: [0u8; 32],
                state_commitment: [0xCD; 32],
                commands_commitment: Block::commands_commitment(&commands),
            },
            commands,
        };
        let qc = sample_quorum_qc(vs.len(), block.hash());
        let payload = b"chunky payload".repeat(8);
        let chunks = crate::replication::snapshot::chunk_snapshot(&payload, 32);
        let chunk_hashes: Vec<[u8; 32]> = chunks.iter().map(|(_, h)| *h).collect();
        SnapshotManifest::build(block, &vs, 32, chunk_hashes, qc, 1_700_000_000)
    }

    #[test]
    fn ingress_snapshot_manifest_request_no_signature_needed() {
        let from = [0x01u8; 32];
        let vs = ValidatorSet::new(vec![]);
        let wire = WireMessage::SnapshotManifestRequest { height: Some(1234) };
        let bytes = postcard::to_stdvec(&wire).unwrap();
        let dispatches = ingress_with_genesis_set(from, &bytes, &vs).unwrap();
        assert_eq!(dispatches.len(), 1);
        assert!(matches!(
            &dispatches[0],
            Dispatch::ServeSnapshotManifest { height: Some(1234), to } if to == &from,
        ));
    }

    #[test]
    fn ingress_snapshot_manifest_request_latest_round_trips() {
        let from = [0x02u8; 32];
        let vs = ValidatorSet::new(vec![]);
        let wire = WireMessage::SnapshotManifestRequest { height: None };
        let bytes = postcard::to_stdvec(&wire).unwrap();
        let dispatches = ingress_with_genesis_set(from, &bytes, &vs).unwrap();
        assert!(matches!(
            &dispatches[0],
            Dispatch::ServeSnapshotManifest { height: None, to } if to == &from,
        ));
    }

    #[test]
    fn ingress_snapshot_manifest_response_carries_manifest() {
        let from = [0x03u8; 32];
        let vs = ValidatorSet::new(vec![]);
        let manifest = sample_manifest_for_dispatch();
        let wire = WireMessage::SnapshotManifestResponse(Some(manifest.clone()));
        let bytes = postcard::to_stdvec(&wire).unwrap();
        let dispatches = ingress_with_genesis_set(from, &bytes, &vs).unwrap();
        assert_eq!(dispatches.len(), 1);
        match &dispatches[0] {
            Dispatch::ReceiveSnapshotManifest {
                manifest: Some(m),
                from: f,
            } => {
                assert_eq!(m, &manifest);
                assert_eq!(f, &from);
            }
            other => panic!("unexpected dispatch: {other:?}"),
        }
    }

    #[test]
    fn ingress_snapshot_chunk_request_carries_height_and_index() {
        let from = [0x04u8; 32];
        let vs = ValidatorSet::new(vec![]);
        let wire = WireMessage::SnapshotChunkRequest {
            height: 555,
            chunk_idx: 7,
        };
        let bytes = postcard::to_stdvec(&wire).unwrap();
        let dispatches = ingress_with_genesis_set(from, &bytes, &vs).unwrap();
        assert!(matches!(
            &dispatches[0],
            Dispatch::ServeSnapshotChunk { height: 555, chunk_idx: 7, to } if to == &from,
        ));
    }

    #[test]
    fn ingress_snapshot_chunk_response_carries_payload() {
        let from = [0x05u8; 32];
        let vs = ValidatorSet::new(vec![]);
        let payload = bytes::Bytes::from_static(b"hello chunk");
        let wire = WireMessage::SnapshotChunkResponse {
            height: 99,
            chunk_idx: 3,
            payload: Some(payload.clone()),
        };
        let bytes_vec = postcard::to_stdvec(&wire).unwrap();
        let dispatches = ingress_with_genesis_set(from, &bytes_vec, &vs).unwrap();
        match &dispatches[0] {
            Dispatch::ReceiveSnapshotChunk {
                height: 99,
                chunk_idx: 3,
                payload: Some(p),
                from: f,
            } => {
                assert_eq!(p.as_ref(), payload.as_ref());
                assert_eq!(f, &from);
            }
            other => panic!("unexpected dispatch: {other:?}"),
        }
    }

    #[test]
    fn snapshot_wire_round_trip_postcard_stable() {
        // Encode/decode each new wire message; bytes round-trip and
        // first-byte tag matches the layout pinned by
        // `wire_tag_layout_locked` in p2p::limits.
        let manifest = sample_manifest_for_dispatch();
        let cases: Vec<WireMessage> = vec![
            WireMessage::SnapshotManifestRequest { height: None },
            WireMessage::SnapshotManifestRequest { height: Some(42) },
            WireMessage::SnapshotManifestResponse(None),
            WireMessage::SnapshotManifestResponse(Some(manifest.clone())),
            WireMessage::SnapshotChunkRequest {
                height: 1,
                chunk_idx: 0,
            },
            WireMessage::SnapshotChunkResponse {
                height: 1,
                chunk_idx: 0,
                payload: None,
            },
            WireMessage::SnapshotChunkResponse {
                height: 1,
                chunk_idx: 0,
                payload: Some(bytes::Bytes::from_static(b"abc")),
            },
        ];
        for msg in cases {
            let bytes = postcard::to_stdvec(&msg).unwrap();
            let decoded: WireMessage = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(decoded, msg);
        }
    }

    #[test]
    fn egress_snapshot_manifest_response_round_trips_via_ingress() {
        let from = [0x66u8; 32];
        let vs = ValidatorSet::new(vec![]);
        let manifest = sample_manifest_for_dispatch();
        let out = egress_snapshot_manifest_response(Some(manifest.clone()), from);
        let Outbound::SendTo { to, payload } = out else {
            panic!("expected SendTo");
        };
        assert_eq!(to, from);
        let dispatches = ingress_with_genesis_set(from, &payload, &vs).unwrap();
        match &dispatches[0] {
            Dispatch::ReceiveSnapshotManifest {
                manifest: Some(m), ..
            } => {
                assert_eq!(m, &manifest);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn snapshot_chunk_response_fits_under_max_frame_bytes_at_1mib() {
        // Frame-size budget: a 1 MiB chunk plus the
        // `SnapshotChunkResponse` envelope must comfortably fit
        // inside the consensus protocol's `MAX_FRAME_BYTES` cap so
        // production-default chunks never get truncated mid-flight.
        // Use a 1 MiB payload whose entropy defeats any compression
        // assumption: postcard does no compression, so we're really
        // just checking framing overhead.
        let payload = bytes::Bytes::from(vec![0xA5u8; 1024 * 1024]);
        let wire = WireMessage::SnapshotChunkResponse {
            height: 0xDEAD_BEEF,
            chunk_idx: u32::MAX,
            payload: Some(payload),
        };
        let encoded = postcard::to_stdvec(&wire).unwrap();
        let max = crate::consensus::node::MAX_FRAME_BYTES;
        assert!(
            encoded.len() < max,
            "encoded SnapshotChunkResponse ({} bytes) must fit under MAX_FRAME_BYTES ({}) at 1 MiB chunks",
            encoded.len(),
            max,
        );
        // The envelope adds at most a few bytes (tag + varints +
        // length prefix). Lock that the overhead is trivially small,
        // so a future change that bloats the envelope without
        // reducing the chunk size hits this test before it hits the
        // wire frame cap.
        let overhead = encoded.len() - 1024 * 1024;
        assert!(
            overhead < 64,
            "envelope overhead grew unexpectedly: {overhead} bytes",
        );
    }

    #[test]
    fn egress_block_request_ingress_roundtrip() {
        let from = [0x01u8; 32];
        let vs = ValidatorSet::new(vec![]);
        let hash = [0xCCu8; 32];
        let peer: NodeId = [0x22u8; 32];

        let out = egress_block_request(hash, peer);
        let Outbound::SendTo { to, payload } = out else {
            panic!("expected SendTo");
        };
        assert_eq!(to, peer);

        let dispatches = ingress_with_genesis_set(from, &payload, &vs).unwrap();
        assert_eq!(dispatches.len(), 1);
        assert!(matches!(
            &dispatches[0],
            Dispatch::ServeBlock { hash: h, to: t } if h == &[0xCCu8; 32] && t == &from,
        ));
    }

    // ── ingress: ValidatorSetHistory boundary semantics (#249) ───────────────

    /// A vote at view `v_eff`, signed by a validator that is **only** in
    /// the new (post-boundary) set, must verify against the
    /// post-boundary set — not against the genesis set.
    #[test]
    fn vote_at_v_eff_verifies_against_post_boundary_set() {
        let old_signer = fresh_signer();
        let new_signer = fresh_signer();
        let old_set = make_vs_with_signers(&[&old_signer]);
        let new_set = make_vs_with_signers(&[&old_signer, &new_signer]);

        let v_eff: View = 5;
        let mut history = ValidatorSetHistory::from_genesis(old_set);
        history.insert_boundary(v_eff, new_set).unwrap();

        let vote = Vote {
            view: v_eff,
            block_hash: [0xAB; 32],
        };
        let signed = Signed::sign(vote, &new_signer).unwrap();
        let wire = WireMessage::Vote(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        // Succeeds against the history that contains the boundary.
        let key_history = key_history_for(&history);
        let dispatches = ingress(new_signer.node_id(), &bytes, &history, &key_history).unwrap();
        assert!(matches!(
            dispatches[0],
            Dispatch::Safety(SafetyEvent::VoteReceived(_))
        ));
    }

    /// The same vote rejected when the history is missing the boundary —
    /// the post-boundary signer is not yet a member at any view.
    #[test]
    fn vote_at_v_eff_rejected_without_boundary() {
        let old_signer = fresh_signer();
        let new_signer = fresh_signer();
        let old_set = make_vs_with_signers(&[&old_signer]);

        let history_without_boundary = ValidatorSetHistory::from_genesis(old_set);
        let key_history = key_history_for(&history_without_boundary);

        let vote = Vote {
            view: 5,
            block_hash: [0xAB; 32],
        };
        let signed = Signed::sign(vote, &new_signer).unwrap();
        let wire = WireMessage::Vote(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let err = ingress(
            new_signer.node_id(),
            &bytes,
            &history_without_boundary,
            &key_history,
        )
        .unwrap_err();
        assert!(
            matches!(err, IngressError::UnknownSigner(_)),
            "expected UnknownSigner, got {err:?}"
        );
    }

    /// A vote at view `v_eff - 1` must still verify against the **old**
    /// set even after the new boundary exists — historical messages do
    /// not get retroactively re-validated against the newer committee.
    #[test]
    fn vote_before_boundary_verifies_against_pre_boundary_set() {
        let old_signer = fresh_signer();
        let new_signer = fresh_signer();
        let old_set = make_vs_with_signers(&[&old_signer]);
        // Critically, `new_set` does *not* contain `old_signer`.
        let new_set = make_vs_with_signers(&[&new_signer]);

        let v_eff: View = 10;
        let mut history = ValidatorSetHistory::from_genesis(old_set);
        history.insert_boundary(v_eff, new_set).unwrap();
        let key_history = key_history_for(&history);

        let vote = Vote {
            view: v_eff - 1,
            block_hash: [0xCD; 32],
        };
        let signed = Signed::sign(vote, &old_signer).unwrap();
        let wire = WireMessage::Vote(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let dispatches = ingress(old_signer.node_id(), &bytes, &history, &key_history).unwrap();
        assert!(matches!(
            dispatches[0],
            Dispatch::Safety(SafetyEvent::VoteReceived(_))
        ));
    }

    /// A proposal at the boundary view: the proposer is a post-boundary
    /// member only. Verification picks the right set.
    #[test]
    fn proposal_at_v_eff_verifies_against_post_boundary_set() {
        let old_signer = fresh_signer();
        let new_signer = fresh_signer();
        let old_set = make_vs_with_signers(&[&old_signer]);
        let new_set = make_vs_with_signers(&[&old_signer, &new_signer]);

        let v_eff: View = 7;
        let mut history = ValidatorSetHistory::from_genesis(old_set);
        history.insert_boundary(v_eff, new_set).unwrap();
        let key_history = key_history_for(&history);

        // Build a block at the boundary view; the proposer is the
        // post-boundary-only validator.
        let parent = genesis();
        let header = crate::replication::block::BlockHeader {
            parent_hash: parent.hash(),
            height: parent.header.height + 1,
            view: v_eff,
            proposer: new_signer.node_id(),
            state_commitment: [0u8; 32],
            commands_commitment: Block::commands_commitment(&[]),
        };
        let block = Block {
            header,
            commands: vec![],
        };

        let proposal = Proposal {
            block,
            justify: sample_qc(),
        };
        let signed = Signed::sign(proposal, &new_signer).unwrap();
        let wire = WireMessage::Proposal(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let dispatches = ingress(new_signer.node_id(), &bytes, &history, &key_history).unwrap();
        assert!(matches!(
            dispatches[0],
            Dispatch::Safety(SafetyEvent::ProposalReceived(_))
        ));
    }

    // ── ingress: NewView high_qc cross-boundary semantics (#250) ─────────────

    /// A NewView straddling a reconfig boundary: high_qc.view = v_eff - 1
    /// (still under the old set), envelope signer is in the old set,
    /// high_qc bitmap shape matches the old set. Must be accepted —
    /// historical messages do not get retroactively re-validated against
    /// the newer committee.
    #[test]
    fn new_view_with_pre_boundary_high_qc_under_old_set_accepted() {
        let old_a = fresh_signer();
        let old_b = fresh_signer();
        let new_only = fresh_signer();
        let old_set = make_vs_with_signers(&[&old_a, &old_b]);
        let new_set = make_vs_with_signers(&[&old_a, &old_b, &new_only]);

        let v_eff: View = 5;
        let mut history = ValidatorSetHistory::from_genesis(old_set.clone());
        history.insert_boundary(v_eff, new_set).unwrap();
        let key_history = key_history_for(&history);

        // high_qc minted at view v_eff - 1 against the *old* set.
        let mut high_qc = QuorumCertificate::new(v_eff - 1, [0xAB; 32], old_set.len());
        for i in 0..old_set.len() {
            high_qc.add_signature(i, [0xCC; 64]);
        }
        assert!(high_qc.is_well_formed(&old_set));

        let nv = NewView { high_qc };
        let signed = Signed::sign(nv, &old_a).unwrap();
        let wire = WireMessage::NewView(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let dispatches = ingress(old_a.node_id(), &bytes, &history, &key_history).unwrap();
        assert_eq!(dispatches.len(), 2);
        assert!(matches!(
            dispatches[0],
            Dispatch::Safety(SafetyEvent::NewViewReceived(_))
        ));
        assert!(matches!(
            dispatches[1],
            Dispatch::Pacemaker(pacemaker::Event::OnQc(v)) if v == v_eff - 1
        ));
    }

    /// A NewView claiming a pre-boundary high_qc.view but whose high_qc
    /// bitmap is sized against the *new* (post-boundary) set: rejected
    /// with `MalformedHighQc`. The new set is larger here, so the bitmap
    /// length doesn't match `set_at(high_qc.view) = old_set` and
    /// well-formedness fails.
    #[test]
    fn new_view_with_high_qc_minted_against_new_set_rejected_at_pre_boundary_view() {
        let old_a = fresh_signer();
        let old_b = fresh_signer();
        let new_only = fresh_signer();
        let old_set = make_vs_with_signers(&[&old_a, &old_b]);
        let new_set = make_vs_with_signers(&[&old_a, &old_b, &new_only]);

        let v_eff: View = 5;
        let mut history = ValidatorSetHistory::from_genesis(old_set.clone());
        history.insert_boundary(v_eff, new_set.clone()).unwrap();
        let key_history = key_history_for(&history);

        // high_qc minted against the *new* (larger) set, but claimed at
        // a pre-boundary view. The bitmap length will be `new_set.len()`,
        // which doesn't match `set_at(v_eff - 1) = old_set`.
        let mut high_qc = QuorumCertificate::new(v_eff - 1, [0xAB; 32], new_set.len());
        for i in 0..new_set.len() {
            high_qc.add_signature(i, [0xDD; 64]);
        }
        assert!(high_qc.is_well_formed(&new_set));
        assert!(!high_qc.is_well_formed(&old_set));

        // Envelope signer must verify first; pick someone in the old set
        // so we exercise the high_qc check rather than the signer check.
        let nv = NewView { high_qc };
        let signed = Signed::sign(nv, &old_a).unwrap();
        let wire = WireMessage::NewView(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let err = ingress(old_a.node_id(), &bytes, &history, &key_history).unwrap_err();
        assert!(
            matches!(err, IngressError::MalformedHighQc { view } if view == v_eff - 1),
            "expected MalformedHighQc at v_eff - 1, got {err:?}",
        );
    }

    /// Sanity: the existing single-set `ingress_new_view_emits_pacemaker_on_qc`
    /// test exercises the genesis-only path. Mirror that here with an
    /// explicit history of length 1, so a regression in the well-formedness
    /// check catches both flavors.
    #[test]
    fn new_view_under_genesis_only_history_round_trips() {
        let signer = fresh_signer();
        let vs = make_vs_with_signers(&[&signer]);
        let history = ValidatorSetHistory::from_genesis(vs.clone());
        let key_history = key_history_for(&history);

        let mut high_qc = QuorumCertificate::new(7, [0xCD; 32], vs.len());
        high_qc.add_signature(0, [0x11; 64]);
        let nv = NewView { high_qc };
        let signed = Signed::sign(nv, &signer).unwrap();
        let wire = WireMessage::NewView(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let dispatches = ingress(signer.node_id(), &bytes, &history, &key_history).unwrap();
        assert_eq!(dispatches.len(), 2);
        assert!(matches!(
            dispatches[0],
            Dispatch::Safety(SafetyEvent::NewViewReceived(_))
        ));
        assert!(matches!(
            dispatches[1],
            Dispatch::Pacemaker(pacemaker::Event::OnQc(7))
        ));
    }

    // ── ingress: ValidatorKeyHistory rotation semantics (#259 part 2) ────────
    //
    // Each test below builds a single-validator setup so the failure
    // mode is unambiguous — every rejection is about which key the
    // verifier accepts at which view, not about whether the validator
    // happens to be in the set. Multi-validator interactions are
    // covered by the sim-level tests in #260 / #261.

    use crate::consensus::validator_rotation::ValidatorKeyRotation;

    /// Helper: build a key history that mirrors `vs` and then applies a
    /// rotation for `validator` to `new_pubkey` taking effect at
    /// `v_eff`. The rotation is committed at `commit_view = v_eff - 2`
    /// (the minimum allowed by `V_EFF_MIN_DELAY`).
    fn key_history_with_rotation(
        vs: &ValidatorSet,
        validator: NodeId,
        new_pubkey: NodeId,
        v_eff: View,
    ) -> ValidatorKeyHistory {
        let mut kh = key_history_from_set(vs);
        // Reverse-index lookup must succeed for the test setup —
        // always rotate from a validator that's actually in `vs`.
        kh.apply_rotation(
            &ValidatorKeyRotation {
                validator,
                new_pubkey,
                v_eff,
            },
            v_eff - 2,
        )
        .expect("test rotation must apply cleanly");
        kh
    }

    /// After a rotation takes effect at `v_eff`, a vote at view `v_eff`
    /// signed by the *new* key is accepted: the verifier resolves the
    /// new pubkey to the validator's stable id and confirms it's the
    /// active key for that view.
    #[test]
    fn vote_after_rotation_signed_with_new_key_accepted() {
        let old = fresh_signer();
        let new = fresh_signer();
        let vs = make_vs_with_signers(&[&old]);
        let history = ValidatorSetHistory::from_genesis(vs.clone());
        let key_history = key_history_with_rotation(&vs, old.node_id(), new.node_id(), 100);

        let vote = Vote {
            view: 100,
            block_hash: [0xAB; 32],
        };
        let signed = Signed::sign(vote, &new).unwrap();
        let wire = WireMessage::Vote(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let dispatches = ingress(new.node_id(), &bytes, &history, &key_history).unwrap();
        assert!(matches!(
            dispatches[0],
            Dispatch::Safety(SafetyEvent::VoteReceived(_))
        ));
    }

    /// Spanning vote: a late vote for a *pre-rotation* view, signed by
    /// the old key. Must still verify even though the validator's
    /// current key has changed — old QCs stay verifiable forever, and
    /// in-flight votes for older views can't be retroactively invalidated
    /// by a rotation that happened later.
    #[test]
    fn spanning_vote_pre_rotation_view_signed_with_old_key_accepted() {
        let old = fresh_signer();
        let new = fresh_signer();
        let vs = make_vs_with_signers(&[&old]);
        let history = ValidatorSetHistory::from_genesis(vs.clone());
        let key_history = key_history_with_rotation(&vs, old.node_id(), new.node_id(), 100);

        // Vote for a view *before* the rotation's v_eff, signed by the
        // pre-rotation key.
        let vote = Vote {
            view: 50,
            block_hash: [0xCD; 32],
        };
        let signed = Signed::sign(vote, &old).unwrap();
        let wire = WireMessage::Vote(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let dispatches = ingress(old.node_id(), &bytes, &history, &key_history).unwrap();
        assert!(matches!(
            dispatches[0],
            Dispatch::Safety(SafetyEvent::VoteReceived(_))
        ));
    }

    /// A vote at view `>= v_eff` signed by the *old* key is rejected:
    /// the validator has rotated and the old key is no longer the
    /// active signing key at that view. Without this check, a
    /// compromised old key could continue to vote indefinitely.
    #[test]
    fn vote_after_rotation_signed_with_stale_old_key_rejected() {
        let old = fresh_signer();
        let new = fresh_signer();
        let vs = make_vs_with_signers(&[&old]);
        let history = ValidatorSetHistory::from_genesis(vs.clone());
        let key_history = key_history_with_rotation(&vs, old.node_id(), new.node_id(), 100);

        // View at/after v_eff, but signed under the now-stale old key.
        let vote = Vote {
            view: 100,
            block_hash: [0xEF; 32],
        };
        let signed = Signed::sign(vote, &old).unwrap();
        let wire = WireMessage::Vote(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let err = ingress(old.node_id(), &bytes, &history, &key_history).unwrap_err();
        assert!(
            matches!(err, IngressError::UnknownSigner(_)),
            "expected UnknownSigner for stale-key vote, got {err:?}"
        );
    }

    /// A vote at view `< v_eff` signed by the *new* key is rejected:
    /// the rotation hasn't taken effect at that view, so the new key
    /// isn't yet the validator's authoritative signer. This prevents a
    /// proposed-but-not-yet-effective key from being used early.
    #[test]
    fn vote_before_rotation_signed_with_future_new_key_rejected() {
        let old = fresh_signer();
        let new = fresh_signer();
        let vs = make_vs_with_signers(&[&old]);
        let history = ValidatorSetHistory::from_genesis(vs.clone());
        let key_history = key_history_with_rotation(&vs, old.node_id(), new.node_id(), 100);

        // View before v_eff, signed by the future key.
        let vote = Vote {
            view: 50,
            block_hash: [0x12; 32],
        };
        let signed = Signed::sign(vote, &new).unwrap();
        let wire = WireMessage::Vote(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let err = ingress(new.node_id(), &bytes, &history, &key_history).unwrap_err();
        assert!(
            matches!(err, IngressError::UnknownSigner(_)),
            "expected UnknownSigner for future-key vote, got {err:?}"
        );
    }

    /// A vote signed by an entirely unrelated pubkey — never associated
    /// with any validator in the key history — is rejected with
    /// `UnknownSigner`. This is the regression test that the
    /// reverse-index lookup actually guards the gate.
    #[test]
    fn vote_signed_by_unrelated_key_rejected() {
        let old = fresh_signer();
        let attacker = fresh_signer();
        let vs = make_vs_with_signers(&[&old]);
        let history = ValidatorSetHistory::from_genesis(vs.clone());
        let key_history = key_history_from_set(&vs);

        let vote = Vote {
            view: 5,
            block_hash: [0x77; 32],
        };
        let signed = Signed::sign(vote, &attacker).unwrap();
        let wire = WireMessage::Vote(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let err = ingress(attacker.node_id(), &bytes, &history, &key_history).unwrap_err();
        assert!(matches!(err, IngressError::UnknownSigner(_)));
    }

    /// Every ingress arm goes through the same `verify_signer_at`
    /// helper, but the test above only exercises Vote. Mirror it for
    /// Proposal, NewView, and TimeoutVote so a regression in any one
    /// arm is caught — the post-rotation key is accepted in all four.
    #[test]
    fn proposal_after_rotation_signed_with_new_key_accepted() {
        let old = fresh_signer();
        let new = fresh_signer();
        let vs = make_vs_with_signers(&[&old]);
        let history = ValidatorSetHistory::from_genesis(vs.clone());
        let key_history = key_history_with_rotation(&vs, old.node_id(), new.node_id(), 100);

        let parent = genesis();
        let header = crate::replication::block::BlockHeader {
            parent_hash: parent.hash(),
            height: parent.header.height + 1,
            view: 100,
            proposer: new.node_id(),
            state_commitment: [0u8; 32],
            commands_commitment: Block::commands_commitment(&[]),
        };
        let proposal = Proposal {
            block: Block {
                header,
                commands: vec![],
            },
            justify: sample_qc(),
        };
        let signed = Signed::sign(proposal, &new).unwrap();
        let wire = WireMessage::Proposal(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let dispatches = ingress(new.node_id(), &bytes, &history, &key_history).unwrap();
        assert!(matches!(
            dispatches[0],
            Dispatch::Safety(SafetyEvent::ProposalReceived(_))
        ));
    }

    #[test]
    fn timeout_vote_after_rotation_signed_with_new_key_accepted() {
        let old = fresh_signer();
        let new = fresh_signer();
        let vs = make_vs_with_signers(&[&old]);
        let history = ValidatorSetHistory::from_genesis(vs.clone());
        let key_history = key_history_with_rotation(&vs, old.node_id(), new.node_id(), 100);

        let tv = TimeoutVote {
            view: 100,
            high_qc: None,
        };
        let signed = Signed::sign(tv, &new).unwrap();
        let wire = WireMessage::TimeoutVote(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let dispatches = ingress(new.node_id(), &bytes, &history, &key_history).unwrap();
        assert!(matches!(dispatches[0], Dispatch::TimeoutVote(_)));
    }

    /// NewView at view >= v_eff signed by the new key: signer check
    /// against `set_at(high_qc.view)` succeeds via the reverse index.
    /// Use a high_qc.view at the rotation point to keep the test focused
    /// on the key-history check (not the high_qc bitmap, which uses
    /// the old set size for both pre- and post-rotation since the
    /// validator set itself didn't change).
    #[test]
    fn new_view_after_rotation_signed_with_new_key_accepted() {
        let old = fresh_signer();
        let new = fresh_signer();
        let vs = make_vs_with_signers(&[&old]);
        let history = ValidatorSetHistory::from_genesis(vs.clone());
        let key_history = key_history_with_rotation(&vs, old.node_id(), new.node_id(), 100);

        let mut high_qc = QuorumCertificate::new(100, [0xCD; 32], vs.len());
        high_qc.add_signature(0, [0x11; 64]);
        let nv = NewView { high_qc };
        let signed = Signed::sign(nv, &new).unwrap();
        let wire = WireMessage::NewView(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let dispatches = ingress(new.node_id(), &bytes, &history, &key_history).unwrap();
        assert_eq!(dispatches.len(), 2);
        assert!(matches!(
            dispatches[0],
            Dispatch::Safety(SafetyEvent::NewViewReceived(_))
        ));
    }

    /// A validator that was removed via reconfig at `v_eff` cannot
    /// vote at views >= v_eff even if the verifier still has their
    /// pubkey in the key history (the history retains every validator
    /// forever for spanning-vote support). The set-membership check
    /// rejects them.
    #[test]
    fn vote_from_removed_validator_after_v_eff_rejected() {
        let kept = fresh_signer();
        let removed = fresh_signer();
        let old_set = make_vs_with_signers(&[&kept, &removed]);
        let new_set = make_vs_with_signers(&[&kept]); // removed gone

        let v_eff: View = 5;
        let mut history = ValidatorSetHistory::from_genesis(old_set);
        history.insert_boundary(v_eff, new_set).unwrap();
        let key_history = key_history_for(&history);

        // Vote at view >= v_eff signed by the removed validator.
        let vote = Vote {
            view: v_eff,
            block_hash: [0xAB; 32],
        };
        let signed = Signed::sign(vote, &removed).unwrap();
        let wire = WireMessage::Vote(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let err = ingress(removed.node_id(), &bytes, &history, &key_history).unwrap_err();
        assert!(matches!(err, IngressError::UnknownSigner(_)));

        // Spanning vote at view < v_eff is still accepted — the
        // validator was authoritative back then.
        let vote = Vote {
            view: v_eff - 1,
            block_hash: [0xCD; 32],
        };
        let signed = Signed::sign(vote, &removed).unwrap();
        let wire = WireMessage::Vote(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let dispatches = ingress(removed.node_id(), &bytes, &history, &key_history).unwrap();
        assert!(matches!(
            dispatches[0],
            Dispatch::Safety(SafetyEvent::VoteReceived(_))
        ));
    }
}
