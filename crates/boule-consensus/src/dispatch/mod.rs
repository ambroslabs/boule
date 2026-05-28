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
//! # Module layout (#369)
//!
//! The module is carved into focused submodules so each new audit-cluster
//! verifier can land as one file rather than another match arm in a
//! 3000-line monolith:
//!
//! - [`codec`]: postcard encode/decode for [`WireMessage`] frames.
//! - [`verify`]: per-concern verifiers (envelope sig, QC aggregate,
//!   BLS partial, chain-id pre-image binding, proposal-history
//!   commitment).
//! - [`ingress`]: per-variant routing — one fn per [`WireMessage`]
//!   variant so node.rs's event loop can call them in isolation.
//! - [`egress`]: signing + encoding helpers for outbound frames.
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

use crate::hotstuff::qc::TimeoutVote;
use crate::replication::block::{Block, BlockHash};
use crate::replication::snapshot::SnapshotManifest;
use crate::validator_set::ValidatorId;
use crate::{Height, View};
use boule::crypto::sig_scheme::SignatureSchemeChoice;
use boule::crypto::signed::Signed;
use boule::identity::NodeId;

pub mod codec;
pub mod egress;
pub mod ingress;
pub mod verify;

pub use egress::{
    egress_block_range_request, egress_block_range_response, egress_block_request,
    egress_block_response, egress_consensus_msg_with_loopback, egress_safety,
    egress_snapshot_chunk_request, egress_snapshot_chunk_response,
    egress_snapshot_manifest_request, egress_snapshot_manifest_response,
};
#[cfg(any(test, feature = "testing"))]
pub use ingress::{ingress, ingress_wire};
pub use ingress::{
    ingress_block_range_request, ingress_block_range_response, ingress_block_request,
    ingress_block_response, ingress_new_view, ingress_proposal, ingress_snapshot_chunk_request,
    ingress_snapshot_chunk_response, ingress_snapshot_manifest_request,
    ingress_snapshot_manifest_response, ingress_timeout_vote, ingress_vote,
    ingress_wire_with_qc_verification, ingress_with_qc_verification,
};

// Re-imports referenced from doc-comments above.
#[allow(unused_imports)]
use crate::wire::WireMessage;

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
    /// [`pacemaker::Event::OnTimeout`](crate::pacemaker::Event::OnTimeout)
    /// to the pacemaker.
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
    /// Route to [`HotStuffCore::step`](crate::hotstuff::HotStuffCore::step).
    Safety(crate::hotstuff::step::Event),
    /// Route to [`Pacemaker::step`](crate::pacemaker::Pacemaker::step).
    Pacemaker(crate::pacemaker::Event),
    /// Peer requested the block with this hash; serve it if held.
    ServeBlock { hash: BlockHash, to: NodeId },
    /// Peer replied to our [`WireMessage::BlockRequest`].
    ///
    /// `requested_hash` is the hash the responder claims to be
    /// answering, copied from the matching
    /// [`WireMessage::BlockRequest`]. It is signed alongside `block`
    /// so a wrong-hash answer is non-repudiable. The integration
    /// layer must drop responses where `block`'s actual hash differs
    /// from `requested_hash`, or where `requested_hash` does not
    /// match an outstanding `block_sync_inflight` entry.
    ReceiveBlock {
        requested_hash: BlockHash,
        block: Option<Block>,
        from: NodeId,
    },
    /// A signed [`TimeoutVote`] arrived. The integration layer feeds
    /// it into its timeout-certificate bucket; on reaching quorum the
    /// bucket emits [`pacemaker::Event::OnTimeoutCert`](crate::pacemaker::Event::OnTimeoutCert) directly.
    ///
    /// `high_qc_trusted` says whether the integration layer may consume
    /// `signed.payload.high_qc` (true) or must treat the piggyback as
    /// untrusted noise and ignore it (false). Ingress verifies the
    /// piggybacked QC's well-formedness and aggregate signature against
    /// the validator set authoritative at `high_qc.view`; on failure the
    /// flag is cleared but the envelope is still emitted, because the
    /// timeout-vote *signal* itself is signed by a known validator and
    /// must not be suppressible by attaching a forged piggyback (audit
    /// finding 10-F3, issue #321). Under the `cfg(test)`-only
    /// `QcVerification::Skip` policy the flag is always `true`,
    /// preserving the historical contract for test fixtures that
    /// build QCs with placeholder signatures.
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
        height: Height,
        chunk_idx: u32,
        to: NodeId,
    },
    /// Peer replied to our [`WireMessage::SnapshotChunkRequest`].
    /// Same joiner-side note as for [`Dispatch::ReceiveSnapshotManifest`].
    ReceiveSnapshotChunk {
        height: Height,
        chunk_idx: u32,
        payload: Option<bytes::Bytes>,
        from: NodeId,
    },
    /// Peer asked for a contiguous block range (#514). The
    /// integration layer serves blocks in `[from_height, to_height]`
    /// from `pending_blocks` plus durable storage, capping the
    /// response at
    /// [`crate::wire::BLOCK_RANGE_RESPONSE_MAX_BLOCKS`].
    ServeBlockRange {
        from_height: Height,
        to_height: Height,
        to: NodeId,
    },
    /// Peer replied to our [`WireMessage::BlockRangeRequest`] (#514).
    ///
    /// `from_height` / `to_height` echo the matching range request.
    /// `blocks` is the contiguous run the responder served, in
    /// ascending height order. The integration layer validates
    /// each block's height falls inside the echoed range, drops
    /// blocks outside it as ill-formed, and inserts the rest into
    /// `pending_blocks`. The requester-side state machine that
    /// pipelines further range requests lives in #515.
    ReceiveBlockRange {
        from_height: Height,
        to_height: Height,
        blocks: Vec<crate::replication::block::Block>,
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
    /// A `Proposal`'s stamped `validator_history_commitment` does not
    /// match what the follower would compute over the block's
    /// reconfig/rotation commands (#325 PR C, audit finding 7-F2).
    /// Catches a Byzantine leader who proposes blocks with a forged
    /// commitment, before any honest replica votes — PR B's recovery
    /// check would catch the same class at restart, but rejecting at
    /// ingress closes the window between propose and restart.
    InvalidValidatorHistoryCommitment {
        view: View,
        height: Height,
        claimed: [u8; 32],
        actual: [u8; 32],
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
            IngressError::InvalidValidatorHistoryCommitment {
                view,
                height,
                claimed,
                actual,
            } => write!(
                f,
                "validator_history_commitment mismatch on Proposal at height={height} view={view}: \
                 leader stamped {} but follower computes {} over the block's reconfig/rotation \
                 commands (audit #325/7-F2)",
                hex::encode(claimed),
                hex::encode(actual),
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
            | IngressError::InvalidBlsPartial { .. }
            | IngressError::InvalidValidatorHistoryCommitment { .. } => None,
        }
    }
}

impl From<postcard::Error> for IngressError {
    fn from(e: postcard::Error) -> Self {
        IngressError::Decode(e)
    }
}

// ── Verified<T> ──────────────────────────────────────────────────────────────

/// Compile-time witness that a wire-driven payload has passed
/// [`ingress`]'s verification gates **and** that the signer has been
/// resolved to a stable [`ValidatorId`] (#371, #394).
///
/// `Verified<T>` is constructed only by:
///
/// - the dispatch verifiers (`ingress` / `ingress_with_qc_verification`
///   and friends) on their way out — these wrap their fully-verified
///   `Signed<Proposal>`, `Signed<Vote>`, and `Signed<NewView>` values
///   via [`Verified::wrap_after_verify_with_signer`] before
///   constructing the corresponding
///   [`crate::hotstuff::step::Event`] variant. The signer
///   id is the [`ValidatorId`] that
///   [`verify::envelope::verify_signer_at`] resolved through
///   [`ValidatorKeyHistory::validator_for`](crate::validator_key_history::ValidatorKeyHistory::validator_for),
///   so a vote signed under a post-rotation key is still recognized as
///   belonging to the validator originally seated;
/// - explicit [`Verified::unchecked`] /
///   [`Verified::unchecked_with_signer`] calls in unit tests that
///   bypass ingress for test-fixture reasons (locally-built proposals,
///   hand-crafted Vote events feeding the safety core directly).
///
/// The audit's runtime-invariant-promoted-to-types pattern: the
/// [`Event`](crate::hotstuff::step::Event) variants that
/// originate on the wire take `Verified<...>`, so a future ingress
/// path that skipped a check (or a refactor that reordered
/// verification) cannot construct them and will fail to compile. The
/// stamped [`ValidatorId`] further ensures the safety core consumes
/// the already-resolved stable id rather than re-deriving from raw
/// wire bytes — the post-rotation hazard #394 names. Sibling of #328
/// (ValidatorId / Pubkey typestate) on a different axis: verification
/// status rather than identity kind.
///
/// # Compile-time enforcement
///
/// Constructing [`Event::ProposalReceived`](crate::hotstuff::step::Event::ProposalReceived)
/// from a raw `Signed<Proposal>` fails to compile — only
/// `Verified<Signed<Proposal>>` is accepted by the variant. The
/// `compile_fail` doctest below pins this property: it passes if and
/// only if the snippet fails to compile. Treat any future change that
/// makes this snippet compile as a regression of the typestate gate.
///
/// ```compile_fail
/// use boule::consensus::hotstuff::Proposal;
/// use boule::consensus::hotstuff::step::Event;
/// use boule::crypto::signed::Signed;
/// fn forbidden(signed: Signed<Proposal>) -> Event {
///     // expected `Verified<Signed<Proposal>>`, found `Signed<Proposal>`
///     Event::ProposalReceived(signed)
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified<T> {
    value: T,
    signer_validator_id: ValidatorId,
}

impl<T> Verified<T> {
    /// Wrap `value` as verified, recording the stable [`ValidatorId`]
    /// resolved by [`verify::envelope::verify_signer_at`]. Crate-private —
    /// only the dispatch verifiers call this on the way out, after every
    /// gate (`verify_signer_at`, `verify_sig`, `verify_qc_if_requested`,
    /// `verify_proposal_history_commitment_if_requested`,
    /// `verify_bls_partial_if_required`) has returned `Ok`. Outside
    /// the crate, callers must go through [`ingress`] to land here.
    pub fn wrap_after_verify_with_signer(value: T, signer_validator_id: ValidatorId) -> Self {
        Self {
            value,
            signer_validator_id,
        }
    }

    /// Construct a `Verified<T>` without running any verification,
    /// stamping the caller-provided [`ValidatorId`]. Reserved for
    /// unit tests that bypass ingress for test-fixture reasons — e.g.
    /// a post-rotation regression test that wants to demonstrate the
    /// safety core consuming a stable id whose bytes differ from the
    /// wire signer pubkey.
    ///
    /// **Production code MUST NOT call this.** Every call site is
    /// auditable by name, and a code review or grep can catch any
    /// production caller that snuck in.
    pub fn unchecked_with_signer(value: T, signer_validator_id: ValidatorId) -> Self {
        Self {
            value,
            signer_validator_id,
        }
    }

    /// Borrow the inner value.
    pub fn inner(&self) -> &T {
        &self.value
    }

    /// Consume and unwrap. Used by the safety core's `step()` to
    /// pull the wire payload out before dispatching to the matching
    /// `on_*_received` handler.
    pub fn into_inner(self) -> T {
        self.value
    }

    /// The stable [`ValidatorId`] resolved by ingress (via
    /// [`ValidatorKeyHistory::validator_for`](crate::validator_key_history::ValidatorKeyHistory::validator_for))
    /// for the signer of this payload. The safety core reads this directly
    /// to look up the signer's bitmap index — instead of re-deriving from
    /// wire bytes, which would silently drop post-rotation votes (#394).
    pub fn signer_validator_id(&self) -> ValidatorId {
        self.signer_validator_id
    }

    /// Consume and split into payload + resolved signer id.
    pub fn into_parts(self) -> (T, ValidatorId) {
        (self.value, self.signer_validator_id)
    }
}

impl<T> Verified<Signed<T>> {
    /// Test convenience: derive `signer_validator_id` from the wire
    /// signer pubkey via [`ValidatorId::from_genesis_pubkey`]. Matches
    /// the pre-rotation identity convention every existing test
    /// fixture relies on (the validator set's stable ids are
    /// byte-equal to the genesis pubkey). For the post-rotation case,
    /// where the wire signer is a freshly-rotated key whose bytes
    /// differ from the stable id, use
    /// [`Verified::unchecked_with_signer`] explicitly.
    ///
    /// **Production code MUST NOT call this** — same audit gate as
    /// [`Verified::unchecked_with_signer`].
    pub fn unchecked(value: Signed<T>) -> Self {
        let signer_validator_id = ValidatorId::from_genesis_pubkey(value.signer);
        Self::unchecked_with_signer(value, signer_validator_id)
    }
}

// ── QcVerification ───────────────────────────────────────────────────────────

/// Chain-level verification context for [`ingress_with_qc_verification`].
///
/// `Verify` is the only variant production wires: every QC's aggregate
/// is checked against the per-historical-view validator pubkeys before
/// any `Dispatch` is emitted (closes the Byzantine-leader-ships-a-bogus-QC
/// vector regardless of scheme), and every `Proposal`'s
/// `validator_history_commitment` is checked against what the follower
/// would compute over the block's reconfig/rotation commands (#325 PR
/// C; closes the Byzantine-leader-ships-a-bogus-history-commitment
/// vector before any vote is cast).
///
/// `Skip` is gated to `cfg(test)` (audit finding 10-4, issue #413) so
/// no production code path can silently disable embedded-QC aggregate
/// verification by selecting it. Test fixtures that construct QCs with
/// placeholder signatures (no actual cryptographic content) — and the
/// legacy [`ingress`] / [`ingress_wire`] convenience wrappers, which
/// are themselves `cfg(test)` — are the only callers that ever
/// observe it.
///
/// The historical name reflects QC verification, but the variant
/// carries every chain-level parameter needed for both checks:
/// `scheme`, `bls_key_history`, `min_v_eff_delay`, and `genesis_hash`
/// are all read by the proposal-receive validator alongside the QC
/// verifier.
pub enum QcVerification<'a> {
    #[cfg(any(test, feature = "testing"))]
    Skip,
    Verify {
        scheme: SignatureSchemeChoice,
        /// Required on BLS chains; ignored on Ed25519 chains. Used by
        /// both the QC aggregate verifier and the proposal-receive
        /// history-commitment verifier (#325 PR C).
        bls_key_history: Option<&'a crate::bls_key_history::BlsKeyHistory>,
        /// Minimum gap between a reconfig-carrying block's view and
        /// the reconfig's `v_eff`. Used by the proposal-receive
        /// history-commitment verifier (#325 PR C) so its
        /// fork-and-apply mirror of `apply_committed_reconfigs`
        /// rejects/accepts reconfigs identically. In production this
        /// is `crate::reconfig::MIN_V_EFF_DELAY`; tests
        /// may pass a different value to exercise edge cases.
        min_v_eff_delay: View,
        /// The chain's genesis block hash. Used by the QC aggregate
        /// verifier (audit finding 7-4, issue #418) to reject view-0
        /// QCs whose `block_hash` is anything other than `genesis_hash`.
        /// The genesis-QC convention skips aggregate verification at
        /// `view == 0` (placeholder Ed25519 sigs / empty BLS aggregate
        /// sentinel), but that skip would otherwise also accept a
        /// forged QC at view 0 over an attacker-chosen block hash.
        /// The safety core's parent walk would catch this downstream,
        /// but defense-in-depth says reject the malformed envelope at
        /// the boundary.
        genesis_hash: BlockHash,
    },
}

#[cfg(test)]
mod tests;
