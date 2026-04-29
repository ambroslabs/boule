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
use crate::consensus::bls_key_history::BlsKeyHistory;
use crate::consensus::hotstuff::ConsensusMsg;
use crate::consensus::hotstuff::qc::{QuorumCertificate, TimeoutVote, Vote};
use crate::consensus::hotstuff::step::Action as SafetyAction;
use crate::consensus::node::WireMessage;
use crate::consensus::pacemaker;
use crate::consensus::validator_history::ValidatorSetHistory;
use crate::consensus::validator_key_history::ValidatorKeyHistory;
use crate::crypto::sig_scheme::SignatureSchemeChoice;
use crate::crypto::signed::{ChainId, Signed, SignedMessage, Signer, preimage};
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
    ///
    /// `high_qc_trusted` says whether the integration layer may consume
    /// `signed.payload.high_qc` (true) or must treat the piggyback as
    /// untrusted noise and ignore it (false). Ingress verifies the
    /// piggybacked QC's well-formedness and aggregate signature against
    /// the validator set authoritative at `high_qc.view`; on failure the
    /// flag is cleared but the envelope is still emitted, because the
    /// timeout-vote *signal* itself is signed by a known validator and
    /// must not be suppressible by attaching a forged piggyback (audit
    /// finding 10-F3, issue #321). On
    /// [`QcVerification::Skip`] the flag is always `true`, preserving
    /// the historical contract for test fixtures that build QCs with
    /// placeholder signatures.
    TimeoutVote {
        signed: Signed<TimeoutVote>,
        high_qc_trusted: bool,
    },
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
    /// A QC's aggregate signature failed verification under the
    /// per-historical-view validator set. Catches a Byzantine leader
    /// who ships a Proposal whose `justify` aggregate doesn't actually
    /// commit a quorum, or a Byzantine peer who forwards a NewView with
    /// a forged `high_qc`. `scheme` names which variant rejected the QC.
    InvalidQcAggregate {
        view: View,
        scheme: &'static str,
    },
    /// On a `bls_aggregated` chain, a [`WireMessage::Vote`] frame either
    /// omitted the BLS partial signature (the optional second tuple
    /// field was `None`) or carried one that did not verify against the
    /// signer's BLS pubkey at `view` over the canonical
    /// `(view, block_hash)` pre-image. Catches a Byzantine voter who
    /// ships a vote with no usable BLS contribution — folding such a
    /// vote into the aggregate would later make the QC fail
    /// `verify_aggregate_bls`, so we reject up-front at ingress.
    InvalidBlsPartial {
        view: View,
        signer: NodeId,
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
            IngressError::InvalidQcAggregate { view, scheme } => write!(
                f,
                "QC at view {view} ({scheme}) failed aggregate verification under the historical validator set",
            ),
            IngressError::InvalidBlsPartial { view, signer } => write!(
                f,
                "BLS partial on Vote at view {view} from signer {signer:?} is missing or did not verify under the historical BLS pubkey",
            ),
        }
    }
}

impl std::error::Error for IngressError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            IngressError::Decode(e) => Some(e),
            IngressError::InvalidSignature(e) => Some(e.as_ref()),
            IngressError::UnknownSigner(_)
            | IngressError::MalformedHighQc { .. }
            | IngressError::InvalidQcAggregate { .. }
            | IngressError::InvalidBlsPartial { .. } => None,
        }
    }
}

/// QC-aggregate verification policy for [`ingress_with_qc_verification`].
///
/// `Skip` is the default for tests that construct QCs with placeholder
/// signatures (no actual cryptographic content) and for the legacy
/// [`ingress`] entry point.
///
/// `Verify` is what production wires: every QC's aggregate is checked
/// against the per-historical-view validator pubkeys before any
/// `Dispatch` is emitted. This closes the Byzantine-leader-ships-a-bogus
/// QC vector regardless of scheme.
pub enum QcVerification<'a> {
    Skip,
    Verify {
        scheme: SignatureSchemeChoice,
        /// Required on BLS chains; ignored on Ed25519 chains. The
        /// per-historical-view BLS pubkey lookup
        /// [`QuorumCertificate::verify_aggregate_bls`] indexes through.
        bls_key_history: Option<&'a BlsKeyHistory>,
    },
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
    let msg: WireMessage = postcard::from_bytes(bytes)?;
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
            let view = signed.payload.block.header.view;
            verify_signer_at(signed.signer, view, history, key_history)?;
            verify_sig(&signed, chain_id)?;
            verify_qc_if_requested(
                &signed.payload.justify,
                history,
                key_history,
                qc_verification,
                chain_id,
            )?;
            Ok(vec![
                Dispatch::Safety(crate::consensus::hotstuff::step::Event::ProposalReceived(
                    signed,
                )),
                Dispatch::Pacemaker(pacemaker::Event::OnProposalReceived(view)),
            ])
        }

        WireMessage::Vote(signed, bls_partial) => {
            verify_signer_at(signed.signer, signed.payload.view, history, key_history)?;
            verify_sig(&signed, chain_id)?;
            verify_bls_partial_if_required(
                &signed,
                bls_partial.as_ref(),
                qc_verification,
                chain_id,
            )?;
            Ok(vec![Dispatch::Safety(
                crate::consensus::hotstuff::step::Event::VoteReceived(signed, bls_partial),
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
            verify_sig(&signed, chain_id)?;
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
            //
            // The piggybacked `high_qc` *is* checked here (audit
            // finding 10-F3, issue #321): a Byzantine voter who
            // attaches a forged fresher-view QC to an otherwise honest
            // timeout vote would otherwise launder the QC through the
            // bucket's `best_high_qc` and the TC self-NewView loopback
            // straight into the safety core's `state.high_qc`. We
            // verify the piggyback at ingress and surface the result
            // as `high_qc_trusted` rather than rejecting the envelope:
            // dropping the whole timeout vote on a bad piggyback would
            // hand a Byzantine peer a way to suppress honest timeout
            // signal by attaching garbage to it.
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
fn verify_sig<T>(signed: &Signed<T>, chain_id: &ChainId) -> Result<(), IngressError>
where
    T: serde::Serialize + SignedMessage,
{
    signed
        .verify(&signed.signer, chain_id)
        .map_err(IngressError::InvalidSignature)
}

/// On `bls_aggregated` chains, require an attached BLS partial signature
/// on every inbound `Vote` and verify it against the signer's BLS pubkey
/// at `signed.payload.view`. On `ed25519_collected` chains (or under
/// [`QcVerification::Skip`]) the optional partial is ignored.
///
/// The BLS partial signs the same canonical pre-image that the QC
/// aggregate verifier reconstructs over `(view, block_hash)`: the
/// domain-separated `postcard(Vote { view, block_hash })` bytes (see
/// [`crate::crypto::signed::preimage`]). Folding a partial that doesn't
/// verify into the aggregate would later cause `verify_aggregate_bls`
/// to fail on the formed QC, so we reject up-front at ingress with a
/// dedicated [`IngressError::InvalidBlsPartial`] variant for log
/// triage.
fn verify_bls_partial_if_required(
    signed: &Signed<Vote>,
    bls_partial: Option<&crate::crypto::sig_scheme::BlsPartialSig>,
    qc_verification: &QcVerification<'_>,
    chain_id: &ChainId,
) -> Result<(), IngressError> {
    let QcVerification::Verify {
        scheme,
        bls_key_history,
    } = qc_verification
    else {
        return Ok(());
    };
    if *scheme != SignatureSchemeChoice::BlsAggregated {
        return Ok(());
    }

    let Some(partial) = bls_partial else {
        return Err(IngressError::InvalidBlsPartial {
            view: signed.payload.view,
            signer: signed.signer,
        });
    };

    let bls_history = bls_key_history.ok_or(IngressError::InvalidBlsPartial {
        view: signed.payload.view,
        signer: signed.signer,
    })?;

    let bls_pubkey = bls_history
        .key_at(&signed.signer, signed.payload.view)
        .ok_or(IngressError::InvalidBlsPartial {
            view: signed.payload.view,
            signer: signed.signer,
        })?;

    let vote_preimage = preimage::<Vote>(&signed.payload, chain_id).map_err(|_| {
        IngressError::InvalidBlsPartial {
            view: signed.payload.view,
            signer: signed.signer,
        }
    })?;

    crate::crypto::sig_scheme::BlsAggregated::verify_partial(&bls_pubkey, &vote_preimage, partial)
        .map_err(|_| IngressError::InvalidBlsPartial {
            view: signed.payload.view,
            signer: signed.signer,
        })?;
    Ok(())
}

/// Verify a QC's aggregate signature per the requested
/// [`QcVerification`] policy. Genesis-shaped QCs (no signers) are
/// accepted unconditionally — the genesis QC is by construction
/// signature-free, and rejecting it here would refuse to bootstrap.
///
/// On `Skip`, returns `Ok(())` without inspecting the QC. On `Verify`,
/// the QC's scheme must match `scheme`; the per-historical-view
/// validator pubkeys are resolved at `qc.view` via `key_history`
/// (Ed25519) or `bls_key_history` (BLS); the corresponding
/// `verify_aggregate` / `verify_aggregate_bls` is called against the
/// canonical Vote pre-image `(qc.view, qc.block_hash)`.
fn verify_qc_if_requested(
    qc: &QuorumCertificate,
    history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
    qc_verification: &QcVerification<'_>,
    chain_id: &ChainId,
) -> Result<(), IngressError> {
    let QcVerification::Verify {
        scheme,
        bls_key_history,
    } = qc_verification
    else {
        return Ok(());
    };

    // Genesis QCs are a convention, not a cryptographic commitment:
    // every honest replica builds the same QC at view 0 over the
    // genesis block hash with all-zero placeholder signatures (see
    // `crate::consensus::hotstuff::qc::genesis_qc`). Aggregate
    // verification cannot succeed against placeholder sigs, and the
    // safety core checks the QC's block_hash against the genesis hash
    // downstream, so skipping at view 0 is safe.
    //
    // QCs with no signers at any other view also have nothing to
    // verify cryptographically — accept them and let the safety core
    // decide whether to act on a no-quorum QC.
    if qc.view == 0 || qc.signer_count() == 0 {
        return Ok(());
    }

    let vs = history.set_at(qc.view);
    // Each partial in the QC is the Ed25519 / BLS signature on the
    // domain-separated Signed<Vote> envelope preimage — the same bytes
    // the voter signed in `Signed::sign(vote, signer)`. Reconstruct
    // that preimage here so verify_aggregate sees what the signer saw.
    let vote = Vote {
        view: qc.view,
        block_hash: qc.block_hash,
    };
    let vote_preimage =
        preimage::<Vote>(&vote, chain_id).map_err(|_| IngressError::InvalidQcAggregate {
            view: qc.view,
            scheme: scheme.name(),
        })?;

    match scheme {
        SignatureSchemeChoice::Ed25519Collected => {
            if !qc.is_ed25519() {
                return Err(IngressError::InvalidQcAggregate {
                    view: qc.view,
                    scheme: scheme.name(),
                });
            }
            // The verifier needs one Ed25519 pubkey per validator slot
            // at qc.view — the same pubkey under which a vote at that
            // view would have been signed. Resolve through the
            // per-historical-view key history so post-rotation lookups
            // pick up the right key.
            let pubkeys: Vec<NodeId> = vs
                .iter()
                .map(|stable_id| key_history.key_at(stable_id, qc.view).unwrap_or(*stable_id))
                .collect();
            qc.verify_aggregate(&vote_preimage, &pubkeys).map_err(|_| {
                IngressError::InvalidQcAggregate {
                    view: qc.view,
                    scheme: scheme.name(),
                }
            })?;
        }
        SignatureSchemeChoice::BlsAggregated => {
            if !qc.is_bls() {
                return Err(IngressError::InvalidQcAggregate {
                    view: qc.view,
                    scheme: scheme.name(),
                });
            }
            let bls_history = bls_key_history.ok_or(IngressError::InvalidQcAggregate {
                view: qc.view,
                scheme: scheme.name(),
            })?;
            let pubkeys = bls_history.pubkeys_for_set(&vs, qc.view).map_err(|_| {
                IngressError::InvalidQcAggregate {
                    view: qc.view,
                    scheme: scheme.name(),
                }
            })?;
            qc.verify_aggregate_bls(&vote_preimage, &pubkeys)
                .map_err(|_| IngressError::InvalidQcAggregate {
                    view: qc.view,
                    scheme: scheme.name(),
                })?;
        }
    }
    Ok(())
}

/// Soft-verify the `high_qc` piggyback on a [`TimeoutVote`].
///
/// Returns `true` if the piggyback is either absent, accompanied by a
/// [`QcVerification::Skip`] policy (legacy / test fixture path), or
/// passes both well-formedness and aggregate-signature verification
/// against the validator set authoritative at `qc.view`. Returns
/// `false` if the piggyback is structurally malformed or fails
/// aggregate verification — the caller must then drop the piggyback
/// (treat it as if the timeout vote carried `high_qc: None`) but
/// **not** the envelope itself.
///
/// Why soft: an attacker who broadcasts `TimeoutVote { view, high_qc:
/// Some(forged) }` over their genuine timeout signal must not be able
/// to suppress that signal by attaching garbage. The envelope is
/// already authenticated by [`verify_signer_at`] and [`verify_sig`];
/// the piggyback is the additional, separable, cryptographically
/// scoped object — and it's the *only* part the bucket logic
/// in `on_timeout_vote` propagates into safety-core state. Refusing
/// the bad piggyback while accepting the timeout-quorum signal keeps
/// `state.high_qc` honest without giving a Byzantine voter a DoS
/// vector against the round-advance machinery.
fn verify_high_qc_piggyback(
    high_qc: Option<&QuorumCertificate>,
    history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
    qc_verification: &QcVerification<'_>,
    chain_id: &ChainId,
) -> bool {
    let Some(qc) = high_qc else {
        return true;
    };
    if matches!(qc_verification, QcVerification::Skip) {
        return true;
    }
    // The piggyback's bitmap is sized for the validator set authoritative
    // at `qc.view` (the same set that voted to mint the QC). Reject
    // bitmap-shape divergence before paying for an aggregate verify.
    let vs = history.set_at(qc.view);
    if !qc.is_well_formed(&vs) {
        return false;
    }
    verify_qc_if_requested(qc, history, key_history, qc_verification, chain_id).is_ok()
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
    bls_signer: Option<
        &dyn crate::crypto::signed::PartialSigner<crate::crypto::sig_scheme::BlsAggregated>,
    >,
    chain_id: &ChainId,
) -> anyhow::Result<Option<Outbound>> {
    match action {
        SafetyAction::Broadcast(msg) => {
            let wire = sign_consensus_msg(msg, signer, bls_signer, chain_id)?;
            let payload = postcard::to_stdvec(&wire)
                .map(Bytes::from)
                .map_err(anyhow::Error::from)?;
            Ok(Some(Outbound::Broadcast(payload)))
        }

        SafetyAction::SendTo(target, msg) => {
            let wire = sign_consensus_msg(msg, signer, bls_signer, chain_id)?;
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
///
/// On `bls_aggregated` chains, `bls_signer` must be `Some(_)` and is
/// consulted whenever a `Vote` is being signed: the BLS partial is
/// produced over the same canonical pre-image that the QC-aggregate
/// verifier reconstructs over `(view, block_hash)` — i.e.
/// [`preimage`]`(&Vote { view, block_hash })`. On `ed25519_collected`
/// chains, `bls_signer` is `None` and the optional second wire field
/// is left empty.
fn sign_consensus_msg(
    msg: &ConsensusMsg,
    signer: &dyn Signer,
    bls_signer: Option<
        &dyn crate::crypto::signed::PartialSigner<crate::crypto::sig_scheme::BlsAggregated>,
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
/// redundant work. The returned `Dispatch` items otherwise match the
/// output of [`ingress_wire`] for this frame arriving from
/// `signer.node_id()`.
pub fn egress_consensus_msg_with_loopback(
    msg: &ConsensusMsg,
    signer: &dyn Signer,
    bls_signer: Option<
        &dyn crate::crypto::signed::PartialSigner<crate::crypto::sig_scheme::BlsAggregated>,
    >,
    chain_id: &ChainId,
) -> anyhow::Result<(Bytes, Vec<Dispatch>)> {
    let wire = sign_consensus_msg(msg, signer, bls_signer, chain_id)?;
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
        WireMessage::Vote(signed, bls_partial) => {
            // Carry the BLS partial through the loopback so the
            // self-vote on a BLS chain folds the partial into the
            // leader's QC bucket — the next-view leader voting on
            // its own proposal must contribute its BLS partial just
            // like any peer's vote (#118 + #354 step 2).
            vec![Dispatch::Safety(
                crate::consensus::hotstuff::step::Event::VoteReceived(signed.clone(), *bls_partial),
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
        Block::genesis([0u8; 32], [0; 32])
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
        ingress(from, bytes, &history, &key_history, &ChainId::TEST)
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
        let signed = Signed::sign(proposal.clone(), &signer, &ChainId::TEST).unwrap();
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
        let signed = Signed::sign(proposal, &signer, &ChainId::TEST).unwrap();
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
        let mut signed = Signed::sign(proposal, &signer, &ChainId::TEST).unwrap();
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
        let signed = Signed::sign(vote, &signer, &ChainId::TEST).unwrap();
        let wire = WireMessage::Vote(signed, None);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let dispatches = ingress_with_genesis_set(signer.node_id(), &bytes, &vs).unwrap();
        assert_eq!(dispatches.len(), 1);
        assert!(matches!(
            dispatches[0],
            Dispatch::Safety(SafetyEvent::VoteReceived(_, _))
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
        let signed = Signed::sign(nv, &signer, &ChainId::TEST).unwrap();
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
        let signed = Signed::sign(tv, &signer, &ChainId::TEST).unwrap();
        let wire = WireMessage::TimeoutVote(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let dispatches = ingress_with_genesis_set(signer.node_id(), &bytes, &vs).unwrap();
        assert_eq!(dispatches.len(), 1);
        assert!(matches!(
            dispatches[0],
            Dispatch::TimeoutVote {
                high_qc_trusted: true,
                ..
            }
        ));
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
        let signed = Signed::sign(tv, &signer, &ChainId::TEST).unwrap();
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
        let mut signed = Signed::sign(tv, &signer, &ChainId::TEST).unwrap();
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

        let out = egress_safety(&action, &signer, None, &ChainId::TEST)
            .unwrap()
            .unwrap();
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

        let out = egress_safety(&action, &signer, None, &ChainId::TEST)
            .unwrap()
            .unwrap();
        let Outbound::SendTo { to, payload } = out else {
            panic!("expected SendTo");
        };
        assert_eq!(to, target);
        let decoded: WireMessage = postcard::from_bytes(&payload).unwrap();
        assert!(matches!(decoded, WireMessage::Vote(_, _)));
    }

    #[test]
    fn egress_persist_returns_none() {
        let signer = fresh_signer();
        use crate::consensus::hotstuff::step::StateUpdate;
        let action = SafetyAction::Persist(StateUpdate::VotedInView { view: 1 });
        let out = egress_safety(&action, &signer, None, &ChainId::TEST).unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn egress_commit_returns_none() {
        let signer = fresh_signer();
        let action = SafetyAction::Commit(genesis());
        let out = egress_safety(&action, &signer, None, &ChainId::TEST).unwrap();
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
        let out = egress_safety(&action, &signer, None, &ChainId::TEST)
            .unwrap()
            .unwrap();
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
        let Outbound::Broadcast(payload) = egress_safety(&action, &signer, None, &ChainId::TEST)
            .unwrap()
            .unwrap()
        else {
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
        let parent_hash = Block::genesis([0u8; 32], [0; 32]).hash();
        let commands: Vec<bytes::Bytes> = Vec::new();
        let block = Block {
            header: BlockHeader {
                parent_hash,
                height: 42,
                view: 7,
                proposer: [0u8; 32],
                state_commitment: [0xCD; 32],
                commands_commitment: Block::commands_commitment(&commands),
                validator_history_commitment: [0; 32],
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
        let signed = Signed::sign(vote, &new_signer, &ChainId::TEST).unwrap();
        let wire = WireMessage::Vote(signed, None);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        // Succeeds against the history that contains the boundary.
        let key_history = key_history_for(&history);
        let dispatches = ingress(
            new_signer.node_id(),
            &bytes,
            &history,
            &key_history,
            &ChainId::TEST,
        )
        .unwrap();
        assert!(matches!(
            dispatches[0],
            Dispatch::Safety(SafetyEvent::VoteReceived(_, _))
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
        let signed = Signed::sign(vote, &new_signer, &ChainId::TEST).unwrap();
        let wire = WireMessage::Vote(signed, None);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let err = ingress(
            new_signer.node_id(),
            &bytes,
            &history_without_boundary,
            &key_history,
            &ChainId::TEST,
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
        let signed = Signed::sign(vote, &old_signer, &ChainId::TEST).unwrap();
        let wire = WireMessage::Vote(signed, None);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let dispatches = ingress(
            old_signer.node_id(),
            &bytes,
            &history,
            &key_history,
            &ChainId::TEST,
        )
        .unwrap();
        assert!(matches!(
            dispatches[0],
            Dispatch::Safety(SafetyEvent::VoteReceived(_, _))
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
            validator_history_commitment: [0; 32],
        };
        let block = Block {
            header,
            commands: vec![],
        };

        let proposal = Proposal {
            block,
            justify: sample_qc(),
        };
        let signed = Signed::sign(proposal, &new_signer, &ChainId::TEST).unwrap();
        let wire = WireMessage::Proposal(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let dispatches = ingress(
            new_signer.node_id(),
            &bytes,
            &history,
            &key_history,
            &ChainId::TEST,
        )
        .unwrap();
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
        let signed = Signed::sign(nv, &old_a, &ChainId::TEST).unwrap();
        let wire = WireMessage::NewView(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let dispatches = ingress(
            old_a.node_id(),
            &bytes,
            &history,
            &key_history,
            &ChainId::TEST,
        )
        .unwrap();
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
        let signed = Signed::sign(nv, &old_a, &ChainId::TEST).unwrap();
        let wire = WireMessage::NewView(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let err = ingress(
            old_a.node_id(),
            &bytes,
            &history,
            &key_history,
            &ChainId::TEST,
        )
        .unwrap_err();
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
        let signed = Signed::sign(nv, &signer, &ChainId::TEST).unwrap();
        let wire = WireMessage::NewView(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let dispatches = ingress(
            signer.node_id(),
            &bytes,
            &history,
            &key_history,
            &ChainId::TEST,
        )
        .unwrap();
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
                new_bls_pubkey: None,
                new_bls_pop: None,
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
        let signed = Signed::sign(vote, &new, &ChainId::TEST).unwrap();
        let wire = WireMessage::Vote(signed, None);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let dispatches = ingress(
            new.node_id(),
            &bytes,
            &history,
            &key_history,
            &ChainId::TEST,
        )
        .unwrap();
        assert!(matches!(
            dispatches[0],
            Dispatch::Safety(SafetyEvent::VoteReceived(_, _))
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
        let signed = Signed::sign(vote, &old, &ChainId::TEST).unwrap();
        let wire = WireMessage::Vote(signed, None);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let dispatches = ingress(
            old.node_id(),
            &bytes,
            &history,
            &key_history,
            &ChainId::TEST,
        )
        .unwrap();
        assert!(matches!(
            dispatches[0],
            Dispatch::Safety(SafetyEvent::VoteReceived(_, _))
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
        let signed = Signed::sign(vote, &old, &ChainId::TEST).unwrap();
        let wire = WireMessage::Vote(signed, None);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let err = ingress(
            old.node_id(),
            &bytes,
            &history,
            &key_history,
            &ChainId::TEST,
        )
        .unwrap_err();
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
        let signed = Signed::sign(vote, &new, &ChainId::TEST).unwrap();
        let wire = WireMessage::Vote(signed, None);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let err = ingress(
            new.node_id(),
            &bytes,
            &history,
            &key_history,
            &ChainId::TEST,
        )
        .unwrap_err();
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
        let signed = Signed::sign(vote, &attacker, &ChainId::TEST).unwrap();
        let wire = WireMessage::Vote(signed, None);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let err = ingress(
            attacker.node_id(),
            &bytes,
            &history,
            &key_history,
            &ChainId::TEST,
        )
        .unwrap_err();
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
            validator_history_commitment: [0; 32],
        };
        let proposal = Proposal {
            block: Block {
                header,
                commands: vec![],
            },
            justify: sample_qc(),
        };
        let signed = Signed::sign(proposal, &new, &ChainId::TEST).unwrap();
        let wire = WireMessage::Proposal(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let dispatches = ingress(
            new.node_id(),
            &bytes,
            &history,
            &key_history,
            &ChainId::TEST,
        )
        .unwrap();
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
        let signed = Signed::sign(tv, &new, &ChainId::TEST).unwrap();
        let wire = WireMessage::TimeoutVote(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let dispatches = ingress(
            new.node_id(),
            &bytes,
            &history,
            &key_history,
            &ChainId::TEST,
        )
        .unwrap();
        assert!(matches!(dispatches[0], Dispatch::TimeoutVote { .. }));
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
        let signed = Signed::sign(nv, &new, &ChainId::TEST).unwrap();
        let wire = WireMessage::NewView(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let dispatches = ingress(
            new.node_id(),
            &bytes,
            &history,
            &key_history,
            &ChainId::TEST,
        )
        .unwrap();
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
        let signed = Signed::sign(vote, &removed, &ChainId::TEST).unwrap();
        let wire = WireMessage::Vote(signed, None);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let err = ingress(
            removed.node_id(),
            &bytes,
            &history,
            &key_history,
            &ChainId::TEST,
        )
        .unwrap_err();
        assert!(matches!(err, IngressError::UnknownSigner(_)));

        // Spanning vote at view < v_eff is still accepted — the
        // validator was authoritative back then.
        let vote = Vote {
            view: v_eff - 1,
            block_hash: [0xCD; 32],
        };
        let signed = Signed::sign(vote, &removed, &ChainId::TEST).unwrap();
        let wire = WireMessage::Vote(signed, None);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let dispatches = ingress(
            removed.node_id(),
            &bytes,
            &history,
            &key_history,
            &ChainId::TEST,
        )
        .unwrap();
        assert!(matches!(
            dispatches[0],
            Dispatch::Safety(SafetyEvent::VoteReceived(_, _))
        ));
    }

    // ── ingress: QC aggregate verification (#332) ────────────────────────────

    /// Build a 4-validator setup, hand-fold real Vote signatures into a
    /// QC over `(view, block_hash)`, and return the bundle the
    /// verification tests below use.
    fn build_real_ed25519_qc(
        view: View,
        block_hash: BlockHash,
    ) -> (Vec<NodeSigner>, ValidatorSet, QuorumCertificate) {
        let signers: Vec<NodeSigner> = (0..4).map(|_| fresh_signer()).collect();
        let vs = ValidatorSet::new(signers.iter().map(|s| s.node_id()).collect());

        let vote = Vote { view, block_hash };
        let mut qc = QuorumCertificate::new(view, block_hash, vs.len());
        // Fold the first 3 validators' signatures (n=4 → quorum=3) in
        // sorted-NodeId order to match the bitmap layout the verifier
        // assumes.
        for stable_id in vs.iter().take(quorum_size_for_n(vs.len())) {
            let signer = signers.iter().find(|s| &s.node_id() == stable_id).unwrap();
            let signed = Signed::sign(vote.clone(), signer, &ChainId::TEST).unwrap();
            let idx = vs.index_of(stable_id).unwrap();
            qc.add_signature(idx, signed.sig);
        }
        (signers, vs, qc)
    }

    fn quorum_size_for_n(n: usize) -> usize {
        // Mirror crate::consensus::hotstuff::qc::quorum_size: ceil(2n/3).
        n.div_ceil(3) * 2 - if n % 3 == 0 { 1 } else { 0 }
    }

    #[test]
    fn ingress_with_verify_accepts_real_ed25519_qc_inside_proposal() {
        let view: View = 5;
        let block_hash = [0x55; 32];
        let (signers, vs, qc) = build_real_ed25519_qc(view, block_hash);
        let leader = &signers[0];

        // Build a proposal at the next view that justifies on this QC.
        let block = Block {
            header: crate::replication::block::BlockHeader {
                parent_hash: block_hash,
                height: 1,
                view: view + 1,
                proposer: leader.node_id(),
                state_commitment: [0; 32],
                commands_commitment: [0; 32],
                validator_history_commitment: [0; 32],
            },
            commands: vec![],
        };
        let proposal = Proposal { block, justify: qc };
        let signed = Signed::sign(proposal, leader, &ChainId::TEST).unwrap();
        let wire = WireMessage::Proposal(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let history = ValidatorSetHistory::from_genesis(vs.clone());
        let key_history = key_history_from_set(&vs);
        let qc_verify = QcVerification::Verify {
            scheme: SignatureSchemeChoice::Ed25519Collected,
            bls_key_history: None,
        };
        let dispatches = ingress_with_qc_verification(
            leader.node_id(),
            &bytes,
            &history,
            &key_history,
            &qc_verify,
            &ChainId::TEST,
        )
        .expect("real Ed25519 QC must verify under the genesis pubkeys");
        assert_eq!(dispatches.len(), 2);
    }

    #[test]
    fn ingress_with_verify_rejects_tampered_ed25519_qc_inside_proposal() {
        let view: View = 5;
        let block_hash = [0x55; 32];
        let (signers, vs, mut qc) = build_real_ed25519_qc(view, block_hash);
        let leader = &signers[0];

        // Tamper the first signature inside the QC.
        if let crate::consensus::hotstuff::qc::QcSignatures::Ed25519Collected(sigs) =
            &mut qc.signatures
        {
            sigs[0][0] ^= 0xFF;
        }

        let block = Block {
            header: crate::replication::block::BlockHeader {
                parent_hash: block_hash,
                height: 1,
                view: view + 1,
                proposer: leader.node_id(),
                state_commitment: [0; 32],
                commands_commitment: [0; 32],
                validator_history_commitment: [0; 32],
            },
            commands: vec![],
        };
        let proposal = Proposal { block, justify: qc };
        let signed = Signed::sign(proposal, leader, &ChainId::TEST).unwrap();
        let wire = WireMessage::Proposal(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let history = ValidatorSetHistory::from_genesis(vs.clone());
        let key_history = key_history_from_set(&vs);
        let qc_verify = QcVerification::Verify {
            scheme: SignatureSchemeChoice::Ed25519Collected,
            bls_key_history: None,
        };
        let err = ingress_with_qc_verification(
            leader.node_id(),
            &bytes,
            &history,
            &key_history,
            &qc_verify,
            &ChainId::TEST,
        )
        .expect_err("tampered QC must be rejected");
        assert!(matches!(
            err,
            IngressError::InvalidQcAggregate {
                view: 5,
                scheme: "ed25519_collected"
            }
        ));
    }

    #[test]
    fn ingress_with_verify_rejects_tampered_ed25519_qc_inside_newview() {
        let view: View = 7;
        let block_hash = [0x77; 32];
        let (signers, vs, mut high_qc) = build_real_ed25519_qc(view, block_hash);
        let messenger = &signers[1];

        if let crate::consensus::hotstuff::qc::QcSignatures::Ed25519Collected(sigs) =
            &mut high_qc.signatures
        {
            sigs[1][3] ^= 0xAA;
        }

        let nv = NewView { high_qc };
        let signed = Signed::sign(nv, messenger, &ChainId::TEST).unwrap();
        let wire = WireMessage::NewView(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let history = ValidatorSetHistory::from_genesis(vs.clone());
        let key_history = key_history_from_set(&vs);
        let qc_verify = QcVerification::Verify {
            scheme: SignatureSchemeChoice::Ed25519Collected,
            bls_key_history: None,
        };
        let err = ingress_with_qc_verification(
            messenger.node_id(),
            &bytes,
            &history,
            &key_history,
            &qc_verify,
            &ChainId::TEST,
        )
        .expect_err("tampered high_qc must be rejected");
        assert!(matches!(
            err,
            IngressError::InvalidQcAggregate {
                view: 7,
                scheme: "ed25519_collected"
            }
        ));
    }

    /// Happy path for the TimeoutVote piggyback verifier (issue #321):
    /// a real, properly-aggregated `high_qc` rides along on a timeout
    /// vote and ingress flags it as trusted so `on_timeout_vote` will
    /// fold it into the bucket's `best_high_qc`.
    #[test]
    fn ingress_with_verify_accepts_real_ed25519_qc_inside_timeout_vote_piggyback() {
        let qc_view: View = 4;
        let block_hash = [0x44; 32];
        let (signers, vs, qc) = build_real_ed25519_qc(qc_view, block_hash);
        let voter = &signers[0];

        // Timeout vote at a *later* view than its piggybacked QC — the
        // typical pattern: the voter is timing out at the current view
        // and reporting the freshest QC they've seen so far.
        let tv = TimeoutVote {
            view: qc_view + 3,
            high_qc: Some(qc),
        };
        let signed = Signed::sign(tv, voter, &ChainId::TEST).unwrap();
        let wire = WireMessage::TimeoutVote(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let history = ValidatorSetHistory::from_genesis(vs.clone());
        let key_history = key_history_from_set(&vs);
        let qc_verify = QcVerification::Verify {
            scheme: SignatureSchemeChoice::Ed25519Collected,
            bls_key_history: None,
        };
        let dispatches = ingress_with_qc_verification(
            voter.node_id(),
            &bytes,
            &history,
            &key_history,
            &qc_verify,
            &ChainId::TEST,
        )
        .expect("real Ed25519 piggyback must verify under the genesis pubkeys");
        assert_eq!(dispatches.len(), 1);
        assert!(
            matches!(
                dispatches[0],
                Dispatch::TimeoutVote {
                    high_qc_trusted: true,
                    ..
                }
            ),
            "real piggyback must be flagged trusted, got {:?}",
            dispatches[0]
        );
    }

    /// Defence-in-depth for the TimeoutVote piggyback verifier (issue
    /// #321): a Byzantine voter attaches a tampered aggregate to a
    /// genuine timeout vote. The envelope is still emitted (suppressing
    /// the timeout signal would let an attacker mute honest replicas
    /// by attaching garbage), but `high_qc_trusted` is `false`, so
    /// `on_timeout_vote` will not adopt the forged QC into
    /// `bucket.best_high_qc` — closing the TC self-NewView loopback
    /// laundering vector.
    #[test]
    fn ingress_with_verify_drops_tampered_ed25519_qc_inside_timeout_vote_piggyback() {
        let qc_view: View = 4;
        let block_hash = [0x44; 32];
        let (signers, vs, mut qc) = build_real_ed25519_qc(qc_view, block_hash);
        let voter = &signers[0];

        // Tamper one byte of the first signature in the aggregate. The
        // bitmap and signature count remain consistent, so this slips
        // past `is_well_formed` and only fails at `verify_aggregate`.
        if let crate::consensus::hotstuff::qc::QcSignatures::Ed25519Collected(sigs) =
            &mut qc.signatures
        {
            sigs[0][0] ^= 0xFF;
        }

        let tv = TimeoutVote {
            view: qc_view + 3,
            high_qc: Some(qc),
        };
        let signed = Signed::sign(tv, voter, &ChainId::TEST).unwrap();
        let wire = WireMessage::TimeoutVote(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let history = ValidatorSetHistory::from_genesis(vs.clone());
        let key_history = key_history_from_set(&vs);
        let qc_verify = QcVerification::Verify {
            scheme: SignatureSchemeChoice::Ed25519Collected,
            bls_key_history: None,
        };
        let dispatches = ingress_with_qc_verification(
            voter.node_id(),
            &bytes,
            &history,
            &key_history,
            &qc_verify,
            &ChainId::TEST,
        )
        .expect("envelope must still be accepted even when the piggyback is forged");
        assert_eq!(dispatches.len(), 1);
        match &dispatches[0] {
            Dispatch::TimeoutVote {
                signed: emitted,
                high_qc_trusted,
            } => {
                assert!(!high_qc_trusted, "tampered piggyback must not be trusted");
                assert_eq!(
                    emitted.payload.view,
                    qc_view + 3,
                    "the timeout vote envelope must reach the integration layer unchanged",
                );
            }
            other => panic!("expected Dispatch::TimeoutVote, got {other:?}"),
        }
    }

    /// Structural malformation of the piggyback (bitmap shape doesn't
    /// match the validator set authoritative at `high_qc.view`) takes
    /// the same drop-piggyback-keep-envelope branch as a tampered
    /// aggregate. This ensures the `is_well_formed` gate inside
    /// `verify_high_qc_piggyback` actually runs — without it, a stray
    /// bitmap could panic the aggregate verifier (or pass the wrong
    /// number of pubkeys through).
    #[test]
    fn ingress_with_verify_drops_malformed_high_qc_in_timeout_vote_piggyback() {
        let qc_view: View = 4;
        let block_hash = [0x44; 32];
        let (signers, vs, qc) = build_real_ed25519_qc(qc_view, block_hash);
        let voter = &signers[0];

        // Construct a wrongly-sized QC for the same view — the bitmap
        // is 1 bit wide rather than `vs.len()` (= 4) bits. Real-set
        // ingress will see a bitmap-set-mismatch on `is_well_formed`.
        let mut malformed = QuorumCertificate::new(qc_view, block_hash, 1);
        malformed.add_signature(0, [0u8; 64]);
        // Sanity: the aggregate from the real QC also exists, but we
        // don't reuse its sigs — the verifier never gets that far.
        drop(qc);

        let tv = TimeoutVote {
            view: qc_view + 3,
            high_qc: Some(malformed),
        };
        let signed = Signed::sign(tv, voter, &ChainId::TEST).unwrap();
        let wire = WireMessage::TimeoutVote(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let history = ValidatorSetHistory::from_genesis(vs.clone());
        let key_history = key_history_from_set(&vs);
        let qc_verify = QcVerification::Verify {
            scheme: SignatureSchemeChoice::Ed25519Collected,
            bls_key_history: None,
        };
        let dispatches = ingress_with_qc_verification(
            voter.node_id(),
            &bytes,
            &history,
            &key_history,
            &qc_verify,
            &ChainId::TEST,
        )
        .expect("envelope must still be accepted even when the piggyback is malformed");
        assert!(
            matches!(
                dispatches[0],
                Dispatch::TimeoutVote {
                    high_qc_trusted: false,
                    ..
                }
            ),
            "malformed piggyback must clear high_qc_trusted, got {:?}",
            dispatches[0]
        );
    }

    /// `high_qc: None` is the common pre-genesis-seed case: a peer
    /// timing out before they've seen any QC. Verification is vacuous
    /// and `high_qc_trusted` is `true`. Codifying this so a future
    /// refactor doesn't accidentally flip `None`-piggyback flagging.
    #[test]
    fn ingress_with_verify_emits_high_qc_trusted_for_timeout_vote_with_no_piggyback() {
        let voter = fresh_signer();
        let vs = make_vs_with_signers(&[&voter]);

        let tv = TimeoutVote {
            view: 9,
            high_qc: None,
        };
        let signed = Signed::sign(tv, &voter, &ChainId::TEST).unwrap();
        let wire = WireMessage::TimeoutVote(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let history = ValidatorSetHistory::from_genesis(vs.clone());
        let key_history = key_history_from_set(&vs);
        let qc_verify = QcVerification::Verify {
            scheme: SignatureSchemeChoice::Ed25519Collected,
            bls_key_history: None,
        };
        let dispatches = ingress_with_qc_verification(
            voter.node_id(),
            &bytes,
            &history,
            &key_history,
            &qc_verify,
            &ChainId::TEST,
        )
        .unwrap();
        assert!(matches!(
            dispatches[0],
            Dispatch::TimeoutVote {
                high_qc_trusted: true,
                ..
            }
        ));
    }

    #[test]
    fn ingress_with_verify_accepts_genesis_empty_qc_inside_proposal() {
        // The view-1 leader proposes with an empty justify == genesis QC.
        // That QC has no signers; the verifier must let it through
        // unchanged or no chain ever boots.
        let signer = fresh_signer();
        let vs = make_vs_with_signers(&[&signer]);
        let proposal = Proposal {
            block: genesis(),
            justify: sample_qc(),
        };
        let signed = Signed::sign(proposal, &signer, &ChainId::TEST).unwrap();
        let wire = WireMessage::Proposal(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let history = ValidatorSetHistory::from_genesis(vs.clone());
        let key_history = key_history_from_set(&vs);
        let qc_verify = QcVerification::Verify {
            scheme: SignatureSchemeChoice::Ed25519Collected,
            bls_key_history: None,
        };
        let dispatches = ingress_with_qc_verification(
            signer.node_id(),
            &bytes,
            &history,
            &key_history,
            &qc_verify,
            &ChainId::TEST,
        )
        .expect("genesis QC (no signers) must pass aggregate verification");
        assert_eq!(dispatches.len(), 2);
    }

    #[test]
    fn ingress_with_verify_rejects_bls_qc_on_ed25519_chain() {
        // A QC carrying the BLS variant arriving on an Ed25519 chain is
        // a structural mismatch — reject before pairing-check.
        let view: View = 3;
        let block_hash = [0x33; 32];
        let signer = fresh_signer();
        let vs = make_vs_with_signers(&[&signer]);
        // Build a real-shaped BLS QC so it survives is_well_formed:
        // sign with a real BLS key and fold the partial in normally.
        // The dispatch-layer scheme mismatch (Ed25519 chain receiving
        // a BLS QC) is what we're exercising, not bytes-level forgery.
        let mut ikm = [0u8; 32];
        ikm[0] = 0xAB;
        let (sk, _pk) = crate::crypto::sig_scheme::BlsAggregated::keygen(&ikm).unwrap();
        let real_partial =
            crate::crypto::sig_scheme::BlsAggregated::sign_partial(&sk, b"x").unwrap();
        let mut bls_qc = QuorumCertificate::new_bls(view, block_hash, vs.len());
        bls_qc.add_bls_partial(0, real_partial);

        let block = Block {
            header: crate::replication::block::BlockHeader {
                parent_hash: block_hash,
                height: 1,
                view: view + 1,
                proposer: signer.node_id(),
                state_commitment: [0; 32],
                commands_commitment: [0; 32],
                validator_history_commitment: [0; 32],
            },
            commands: vec![],
        };
        let proposal = Proposal {
            block,
            justify: bls_qc,
        };
        let signed = Signed::sign(proposal, &signer, &ChainId::TEST).unwrap();
        let wire = WireMessage::Proposal(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let history = ValidatorSetHistory::from_genesis(vs.clone());
        let key_history = key_history_from_set(&vs);
        let qc_verify = QcVerification::Verify {
            scheme: SignatureSchemeChoice::Ed25519Collected,
            bls_key_history: None,
        };
        let err = ingress_with_qc_verification(
            signer.node_id(),
            &bytes,
            &history,
            &key_history,
            &qc_verify,
            &ChainId::TEST,
        )
        .expect_err("BLS QC on Ed25519 chain must be rejected");
        assert!(matches!(
            err,
            IngressError::InvalidQcAggregate {
                scheme: "ed25519_collected",
                ..
            }
        ));
    }

    // ── ingress: BLS partial on Vote (#354 step 1) ───────────────────────────

    /// Build a BLS-keyed signer pair: an Ed25519 NodeSigner for the
    /// envelope plus a BLS keypair registered against that signer's
    /// NodeId. Returns `(ed25519_signer, bls_secret, bls_pubkey)`.
    fn fresh_bls_signer(
        seed: u8,
    ) -> (
        NodeSigner,
        crate::crypto::sig_scheme::BlsSecretKey,
        crate::crypto::sig_scheme::BlsPublicKey,
    ) {
        let signer = fresh_signer();
        let mut ikm = [0u8; 32];
        ikm.fill(seed);
        let (sk, pk) = crate::crypto::sig_scheme::BlsAggregated::keygen(&ikm).unwrap();
        (signer, sk, pk)
    }

    /// Signed vote + valid BLS partial under `bls_sk` over the canonical
    /// Vote pre-image.
    fn make_signed_vote_with_bls_partial(
        signer: &NodeSigner,
        bls_sk: &crate::crypto::sig_scheme::BlsSecretKey,
        view: View,
        block_hash: BlockHash,
    ) -> (Signed<Vote>, crate::crypto::sig_scheme::BlsPartialSig) {
        let vote = Vote { view, block_hash };
        let preimage = preimage::<Vote>(&vote, &ChainId::TEST).unwrap();
        let partial =
            crate::crypto::sig_scheme::BlsAggregated::sign_partial(bls_sk, &preimage).unwrap();
        let signed = Signed::sign(vote, signer, &ChainId::TEST).unwrap();
        (signed, partial)
    }

    #[test]
    fn ingress_vote_on_bls_chain_accepts_valid_bls_partial() {
        let (signer, bls_sk, bls_pk) = fresh_bls_signer(0x11);
        let vs = make_vs_with_signers(&[&signer]);
        let view: View = 5;
        let block_hash = [0xAA; 32];

        let (signed, partial) =
            make_signed_vote_with_bls_partial(&signer, &bls_sk, view, block_hash);
        let wire = WireMessage::Vote(signed, Some(partial));
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let history = ValidatorSetHistory::from_genesis(vs.clone());
        let key_history = key_history_from_set(&vs);
        let bls_history = BlsKeyHistory::with_genesis([(signer.node_id(), bls_pk)]);
        let qc_verify = QcVerification::Verify {
            scheme: SignatureSchemeChoice::BlsAggregated,
            bls_key_history: Some(&bls_history),
        };

        let dispatches = ingress_with_qc_verification(
            signer.node_id(),
            &bytes,
            &history,
            &key_history,
            &qc_verify,
            &ChainId::TEST,
        )
        .expect("valid BLS partial must pass ingress on a BLS chain");
        assert_eq!(dispatches.len(), 1);
        assert!(matches!(
            dispatches[0],
            Dispatch::Safety(SafetyEvent::VoteReceived(_, _))
        ));
    }

    #[test]
    fn ingress_vote_on_bls_chain_rejects_missing_bls_partial() {
        let (signer, _bls_sk, bls_pk) = fresh_bls_signer(0x22);
        let vs = make_vs_with_signers(&[&signer]);
        let view: View = 4;
        let block_hash = [0xBB; 32];

        // Vote with no BLS partial attached (None).
        let vote = Vote { view, block_hash };
        let signed = Signed::sign(vote, &signer, &ChainId::TEST).unwrap();
        let wire = WireMessage::Vote(signed, None);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let history = ValidatorSetHistory::from_genesis(vs.clone());
        let key_history = key_history_from_set(&vs);
        let bls_history = BlsKeyHistory::with_genesis([(signer.node_id(), bls_pk)]);
        let qc_verify = QcVerification::Verify {
            scheme: SignatureSchemeChoice::BlsAggregated,
            bls_key_history: Some(&bls_history),
        };

        let err = ingress_with_qc_verification(
            signer.node_id(),
            &bytes,
            &history,
            &key_history,
            &qc_verify,
            &ChainId::TEST,
        )
        .expect_err("missing BLS partial on BLS chain must be rejected");
        let expected_signer = signer.node_id();
        assert!(matches!(
            err,
            IngressError::InvalidBlsPartial { view: 4, signer: s } if s == expected_signer,
        ));
    }

    #[test]
    fn ingress_vote_on_bls_chain_rejects_tampered_bls_partial() {
        let (signer, bls_sk, bls_pk) = fresh_bls_signer(0x33);
        let vs = make_vs_with_signers(&[&signer]);
        let view: View = 6;
        let block_hash = [0xCC; 32];

        let (signed, mut partial) =
            make_signed_vote_with_bls_partial(&signer, &bls_sk, view, block_hash);
        partial[10] ^= 0xFF;
        let wire = WireMessage::Vote(signed, Some(partial));
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let history = ValidatorSetHistory::from_genesis(vs.clone());
        let key_history = key_history_from_set(&vs);
        let bls_history = BlsKeyHistory::with_genesis([(signer.node_id(), bls_pk)]);
        let qc_verify = QcVerification::Verify {
            scheme: SignatureSchemeChoice::BlsAggregated,
            bls_key_history: Some(&bls_history),
        };

        let err = ingress_with_qc_verification(
            signer.node_id(),
            &bytes,
            &history,
            &key_history,
            &qc_verify,
            &ChainId::TEST,
        )
        .expect_err("tampered BLS partial must be rejected");
        assert!(matches!(
            err,
            IngressError::InvalidBlsPartial { view: 6, .. }
        ));
    }

    #[test]
    fn ingress_vote_on_bls_chain_rejects_partial_signed_by_wrong_key() {
        // Voter's NodeId is the legitimate one, the envelope's Ed25519
        // sig is real, but the BLS partial was produced under some
        // other validator's BLS secret. Aggregating it would later make
        // the QC fail `verify_aggregate_bls`, so we reject up-front.
        let (signer, _bls_sk_a, bls_pk_a) = fresh_bls_signer(0x44);
        let (_, bls_sk_b, _bls_pk_b) = fresh_bls_signer(0x45);
        let vs = make_vs_with_signers(&[&signer]);
        let view: View = 8;
        let block_hash = [0xDD; 32];

        let (signed, _) = make_signed_vote_with_bls_partial(&signer, &bls_sk_b, view, block_hash);
        let preimage = preimage::<Vote>(&signed.payload, &ChainId::TEST).unwrap();
        let partial =
            crate::crypto::sig_scheme::BlsAggregated::sign_partial(&bls_sk_b, &preimage).unwrap();
        let wire = WireMessage::Vote(signed, Some(partial));
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let history = ValidatorSetHistory::from_genesis(vs.clone());
        let key_history = key_history_from_set(&vs);
        // History only knows the legitimate signer's pubkey (pk_a), but
        // the partial was produced under sk_b — verify_partial under
        // pk_a must reject.
        let bls_history = BlsKeyHistory::with_genesis([(signer.node_id(), bls_pk_a)]);
        let qc_verify = QcVerification::Verify {
            scheme: SignatureSchemeChoice::BlsAggregated,
            bls_key_history: Some(&bls_history),
        };

        let err = ingress_with_qc_verification(
            signer.node_id(),
            &bytes,
            &history,
            &key_history,
            &qc_verify,
            &ChainId::TEST,
        )
        .expect_err("partial signed under the wrong BLS key must be rejected");
        assert!(matches!(
            err,
            IngressError::InvalidBlsPartial { view: 8, .. }
        ));
    }

    #[test]
    fn ingress_vote_on_ed25519_chain_ignores_bls_partial_field() {
        // On an Ed25519 chain, the optional BLS partial is metadata —
        // present or absent, valid or junk, ingress accepts the vote.
        // (The QC verifier only consults the inner Ed25519 sig.)
        let signer = fresh_signer();
        let vs = make_vs_with_signers(&[&signer]);
        let view: View = 9;
        let block_hash = [0xEE; 32];

        // Ship a junk BLS partial alongside the vote — it must be ignored.
        let vote = Vote { view, block_hash };
        let signed = Signed::sign(vote, &signer, &ChainId::TEST).unwrap();
        let wire = WireMessage::Vote(signed, Some([0xFFu8; 96]));
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let history = ValidatorSetHistory::from_genesis(vs.clone());
        let key_history = key_history_from_set(&vs);
        let qc_verify = QcVerification::Verify {
            scheme: SignatureSchemeChoice::Ed25519Collected,
            bls_key_history: None,
        };

        let dispatches = ingress_with_qc_verification(
            signer.node_id(),
            &bytes,
            &history,
            &key_history,
            &qc_verify,
            &ChainId::TEST,
        )
        .expect("Ed25519 chain must ignore the optional BLS partial field");
        assert_eq!(dispatches.len(), 1);
        assert!(matches!(
            dispatches[0],
            Dispatch::Safety(SafetyEvent::VoteReceived(_, _))
        ));
    }

    #[test]
    fn ingress_vote_on_bls_chain_rejects_when_bls_history_absent() {
        // Defense-in-depth: a BLS chain misconfigured to ship
        // `QcVerification::Verify` without a `bls_key_history` must not
        // silently let votes through. The verifier rejects because it
        // can't resolve the signer's historical BLS pubkey.
        let (signer, bls_sk, _bls_pk) = fresh_bls_signer(0x55);
        let vs = make_vs_with_signers(&[&signer]);
        let view: View = 11;
        let block_hash = [0x11; 32];

        let (signed, partial) =
            make_signed_vote_with_bls_partial(&signer, &bls_sk, view, block_hash);
        let wire = WireMessage::Vote(signed, Some(partial));
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let history = ValidatorSetHistory::from_genesis(vs.clone());
        let key_history = key_history_from_set(&vs);
        let qc_verify = QcVerification::Verify {
            scheme: SignatureSchemeChoice::BlsAggregated,
            bls_key_history: None,
        };

        let err = ingress_with_qc_verification(
            signer.node_id(),
            &bytes,
            &history,
            &key_history,
            &qc_verify,
            &ChainId::TEST,
        )
        .expect_err("BLS chain without bls_key_history must reject");
        assert!(matches!(
            err,
            IngressError::InvalidBlsPartial { view: 11, .. }
        ));
    }

    #[test]
    fn ingress_vote_with_skip_does_not_validate_bls_partial() {
        // The Skip policy means tests construct QCs with placeholder
        // bytes — it must also tolerate junk BLS partials on Vote
        // frames. Document that tightening this would break the
        // existing test fixtures.
        let signer = fresh_signer();
        let vs = make_vs_with_signers(&[&signer]);

        let vote = Vote {
            view: 2,
            block_hash: [0x77; 32],
        };
        let signed = Signed::sign(vote, &signer, &ChainId::TEST).unwrap();
        // Junk BLS partial — would not verify under any pubkey.
        let wire = WireMessage::Vote(signed, Some([0u8; 96]));
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let dispatches = ingress_with_genesis_set(signer.node_id(), &bytes, &vs)
            .expect("Skip policy must not exercise BLS partial verification");
        assert_eq!(dispatches.len(), 1);
    }

    #[test]
    fn ingress_with_skip_lets_invalid_aggregate_through() {
        // The default ingress path is `Skip` to preserve existing test
        // fixtures that construct QCs with placeholder bytes. Document
        // that behaviour explicitly so a future change doesn't tighten
        // it without us noticing.
        let signer = fresh_signer();
        let vs = make_vs_with_signers(&[&signer]);
        let mut bogus_qc = QuorumCertificate::new(0, sample_qc().block_hash, vs.len());
        bogus_qc.add_signature(0, [0xCC; 64]); // not a real Ed25519 sig
        let proposal = Proposal {
            block: genesis(),
            justify: bogus_qc,
        };
        let signed = Signed::sign(proposal, &signer, &ChainId::TEST).unwrap();
        let wire = WireMessage::Proposal(signed);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        let history = ValidatorSetHistory::from_genesis(vs.clone());
        let key_history = key_history_from_set(&vs);
        // Default ingress → QcVerification::Skip → no aggregate check.
        let dispatches = ingress(
            signer.node_id(),
            &bytes,
            &history,
            &key_history,
            &ChainId::TEST,
        )
        .expect("Skip policy must not exercise aggregate verification");
        assert_eq!(dispatches.len(), 2);
    }
}
