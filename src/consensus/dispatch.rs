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
use crate::consensus::validator_set::ValidatorSet;
use crate::crypto::signed::{Signed, SignedMessage, Signer};
use crate::p2p::NodeId;
use crate::replication::block::{Block, BlockHash};

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
}

impl std::fmt::Display for IngressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IngressError::Decode(e) => write!(f, "postcard decode failed: {e}"),
            IngressError::UnknownSigner(id) => {
                write!(f, "signer {id:?} is not in the validator set")
            }
            IngressError::InvalidSignature(e) => write!(f, "signature verification failed: {e}"),
        }
    }
}

impl std::error::Error for IngressError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            IngressError::Decode(e) => Some(e),
            IngressError::InvalidSignature(e) => Some(e.as_ref()),
            IngressError::UnknownSigner(_) => None,
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
/// Returns [`Err(IngressError)`] if the frame can't be decoded or fails
/// signature verification. The event loop should log and drop on error;
/// the state machines are never touched.
pub fn ingress(
    from: NodeId,
    bytes: &[u8],
    vs: &ValidatorSet,
) -> Result<Vec<Dispatch>, IngressError> {
    let msg: WireMessage = postcard::from_bytes(bytes)?;
    ingress_wire(from, msg, vs)
}

/// Same as [`ingress`] but takes an already-decoded [`WireMessage`].
///
/// Exposed for unit tests that construct wire messages directly.
pub fn ingress_wire(
    from: NodeId,
    msg: WireMessage,
    vs: &ValidatorSet,
) -> Result<Vec<Dispatch>, IngressError> {
    match msg {
        WireMessage::Proposal(signed) => {
            verify_signer(signed.signer, vs)?;
            verify_sig(&signed)?;
            let view = signed.payload.block.header.view;
            Ok(vec![
                Dispatch::Safety(crate::consensus::hotstuff::step::Event::ProposalReceived(
                    signed,
                )),
                Dispatch::Pacemaker(pacemaker::Event::OnProposalReceived(view)),
            ])
        }

        WireMessage::Vote(signed) => {
            verify_signer(signed.signer, vs)?;
            verify_sig(&signed)?;
            Ok(vec![Dispatch::Safety(
                crate::consensus::hotstuff::step::Event::VoteReceived(signed),
            )])
        }

        WireMessage::NewView(signed) => {
            verify_signer(signed.signer, vs)?;
            verify_sig(&signed)?;
            let high_qc_view = signed.payload.high_qc.view;
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
            verify_signer(signed.signer, vs)?;
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
    }
}

/// Check that `signer` is a member of the validator set.
fn verify_signer(signer: NodeId, vs: &ValidatorSet) -> Result<(), IngressError> {
    if vs.index_of(&signer).is_none() {
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
        | WireMessage::BlockResponse(_) => {
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

        let dispatches = ingress(signer.node_id(), &bytes, &vs).unwrap();
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

        let err = ingress(signer.node_id(), &bytes, &vs).unwrap_err();
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

        let err = ingress(signer.node_id(), &bytes, &vs).unwrap_err();
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

        let dispatches = ingress(signer.node_id(), &bytes, &vs).unwrap();
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

        let dispatches = ingress(signer.node_id(), &bytes, &vs).unwrap();
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

        let dispatches = ingress(signer.node_id(), &bytes, &vs).unwrap();
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

        let err = ingress(signer.node_id(), &bytes, &vs).unwrap_err();
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

        let err = ingress(signer.node_id(), &bytes, &vs).unwrap_err();
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

        let dispatches = ingress(from, &bytes, &vs).unwrap();
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

        let dispatches = ingress(from, &bytes, &vs).unwrap();
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
        let err = ingress(from, &[0xFFu8; 16], &vs).unwrap_err();
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
        let dispatches = ingress(signer.node_id(), &payload, &vs).unwrap();
        assert_eq!(dispatches.len(), 2);
        match &dispatches[0] {
            Dispatch::Safety(SafetyEvent::ProposalReceived(s)) => {
                assert_eq!(s.payload.block, proposal.block);
            }
            other => panic!("unexpected first dispatch: {other:?}"),
        }
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

        let dispatches = ingress(from, &payload, &vs).unwrap();
        assert_eq!(dispatches.len(), 1);
        assert!(matches!(
            &dispatches[0],
            Dispatch::ServeBlock { hash: h, to: t } if h == &[0xCCu8; 32] && t == &from,
        ));
    }
}
