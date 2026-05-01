//! Wire protocol envelope for the consensus integration layer.
//!
//! Every byte travelling on the consensus channel — proposals, votes,
//! NewView messages, timeout votes, block-sync, and snapshot-sync — is
//! one variant of [`WireMessage`], postcard-encoded. Variant order is
//! wire-stable; see the type's doc-comment for the ordering rule.

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::consensus::Height;
use crate::consensus::hotstuff::qc::TimeoutVote;
use crate::crypto::signed::{Signed, SignedMessage};
use crate::replication::block::{Block, BlockHash};

/// Protocol ID registered with the p2p multiplexer for consensus traffic.
/// Gossip uses `0x01`, ping-RPC uses `0x02`.
pub const PROTOCOL_ID: u8 = 0x03;

/// Maximum encoded frame size accepted from the wire for this protocol.
/// Sized to accommodate a full block with up to ~1000 moderate-sized
/// commands; production tuning can raise this without protocol changes.
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024; // 4 MiB

/// Signed payload of a [`WireMessage::BlockResponse`].
///
/// `requested_hash` is the hash the requester named in the matching
/// `BlockRequest`. Including it inside the signed envelope binds the
/// responder's signature to a specific request: a Byzantine peer who
/// returns a different block (or no block) under a wrong-hash claim
/// is non-repudiable evidence — the requester can later present
/// `(BlockResponsePayload, signature)` for slashing once that
/// machinery lands.
///
/// Receivers must drop a response whose `block.hash() != requested_hash`,
/// or whose `requested_hash` does not match an outstanding
/// `block_sync_inflight` entry. See the
/// [`Dispatch::ReceiveBlock`](crate::consensus::dispatch::Dispatch::ReceiveBlock)
/// handler in `apply_dispatch` for the gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockResponsePayload {
    /// The hash from the matching `BlockRequest` this response answers.
    pub requested_hash: BlockHash,
    /// The block matching `requested_hash`, or `None` if the responder
    /// doesn't have it.
    pub block: Option<Block>,
}

impl SignedMessage for BlockResponsePayload {
    const DOMAIN: &'static str = "ambros.consensus.block_response.v1";
}

/// Maximum number of blocks a single
/// [`WireMessage::BlockRangeResponse`] may carry. Sized to keep a
/// realistic response under [`MAX_FRAME_BYTES`] even when individual
/// blocks are at the higher end of typical sizes (see issue #185 for
/// the bulk-range RPC design). Requesters that need a wider span
/// pipeline subsequent range requests once the first response lands.
pub const BLOCK_RANGE_RESPONSE_MAX_BLOCKS: usize = 64;

/// Signed payload of a [`WireMessage::BlockRangeResponse`].
///
/// `from_height` and `to_height` echo the matching
/// [`WireMessage::BlockRangeRequest`] so the responder's signature
/// commits to the exact range it claims to be serving — a Byzantine
/// responder who fills the response with blocks outside the requested
/// span (or with the wrong contiguous run) is non-repudiable evidence
/// for slashing under the same model as
/// [`BlockResponsePayload`].
///
/// `blocks` is the contiguous run of blocks in **ascending height
/// order**; gaps inside the requested span are encoded by the
/// responder simply not including those heights (the requester can
/// follow up with a tighter request or a single-block
/// [`WireMessage::BlockRequest`] for any specific gap). The vector
/// is capped at [`BLOCK_RANGE_RESPONSE_MAX_BLOCKS`] regardless of how
/// wide the request is.
///
/// Receivers must drop a response whose blocks fall outside
/// `[from_height, to_height]`, whose height ordering is not strictly
/// ascending, or whose `from_height`/`to_height` do not match an
/// outstanding range-inflight entry (the requester-side
/// implementation in #515 enforces this gate).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockRangeResponsePayload {
    /// First height of the requested span (inclusive).
    pub from_height: Height,
    /// Last height of the requested span (inclusive).
    pub to_height: Height,
    /// Contiguous blocks in ascending height order. Empty when the
    /// responder holds nothing inside `[from_height, to_height]`;
    /// truncated to [`BLOCK_RANGE_RESPONSE_MAX_BLOCKS`] when the
    /// requested span is wider than the per-response cap. The
    /// requester pipelines the next range starting at
    /// `blocks.last().header.height + 1` in that case.
    pub blocks: Vec<Block>,
}

impl SignedMessage for BlockRangeResponsePayload {
    const DOMAIN: &'static str = "ambros.consensus.block_range_response.v1";
}

/// Every message sent over the `PROTOCOL_ID` channel is one of these
/// variants, postcard-encoded.
///
/// The three consensus variants carry a [`Signed`] envelope whose
/// signature the integration layer verifies against the claimed signer
/// **before** feeding the payload into [`crate::consensus::hotstuff::step::HotStuffCore::step`].
///
/// `BlockRequest` / `BlockResponse` are the block-sync sub-protocol:
/// when the safety core emits `Action::RequestBlock(hash, peer)`, the
/// integration layer sends `BlockRequest`; the peer replies with
/// `BlockResponse` (carrying the block if it has it, `None` otherwise).
///
/// `SnapshotManifestRequest` / `SnapshotManifestResponse` /
/// `SnapshotChunkRequest` / `SnapshotChunkResponse` are the snapshot
/// sub-protocol (#228): a joiner asks a peer for a manifest (latest or
/// at a specific height), then for each chunk by `(height, idx)`.
/// Issue #229 builds the joiner-side state machine on top.
///
/// **Variant order is wire-stable.** Postcard encodes the discriminant
/// as a varint at byte 0; reordering breaks every running peer.
/// Adding new variants at the end is fine. The
/// [`crate::p2p::limits::MessageKind`] enum mirrors this order and is
/// pinned by `wire_tag_layout_locked`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireMessage {
    Proposal(Signed<crate::consensus::hotstuff::Proposal>),
    /// A signed vote, optionally carrying a BLS partial signature
    /// alongside the Ed25519 envelope.
    ///
    /// The optional second field carries one validator's contribution to
    /// a future BLS QC aggregate. It is `Some(_)` on `bls_aggregated`
    /// chains and `None` on `ed25519_collected` chains. The partial sits
    /// **outside** the [`Signed<Vote>`] envelope so the postcard bytes
    /// of `Vote { view, block_hash }` — and therefore the canonical
    /// signing pre-image — stay byte-stable across schemes. Persisted
    /// `last_voted_view` envelopes and snapshot QCs continue to verify
    /// unchanged. See [`crate::consensus::dispatch`] for the ingress
    /// validation rule that enforces presence per chain scheme.
    Vote(
        Signed<crate::consensus::hotstuff::qc::Vote>,
        #[serde(with = "serde_optional_bls_partial")]
        Option<crate::crypto::sig_scheme::BlsPartialSig>,
        /// Leader endorsement (#506): a self-attributing
        /// `Signed<LeaderEndorsement>` envelope the proposer minted
        /// over `LeaderEndorsement { view, block_hash }` and that the
        /// voter copied verbatim from the proposal it is responding to.
        /// Sits **outside** the inner [`Signed<Vote>`] envelope for the
        /// same byte-stability reason as the BLS partial — a QC
        /// aggregate verifier reconstructs the canonical
        /// `(view, block_hash)` Vote pre-image and must not see this
        /// extra payload.
        Signed<crate::consensus::hotstuff::qc::LeaderEndorsement>,
    ),
    NewView(Signed<crate::consensus::hotstuff::NewView>),
    /// A replica's signed notice that it is giving up on a view. A
    /// quorum of these forms the timeout certificate that advances
    /// `view + 1` even when the leader never proposes.
    TimeoutVote(Signed<TimeoutVote>),
    /// Ask a peer for the block with this content-hash.
    BlockRequest(BlockHash),
    /// Reply to a `BlockRequest`. The signed payload commits to the
    /// hash the requester originally named so a Byzantine responder
    /// who returns the wrong block (or nothing) is non-repudiable
    /// evidence the responder can later be slashed for (#434).
    BlockResponse(Signed<BlockResponsePayload>),
    /// Ask a peer for a snapshot manifest. `None` means "your latest";
    /// `Some(h)` means "the snapshot at exact height `h`".
    SnapshotManifestRequest {
        height: Option<u64>,
    },
    /// Reply to a [`WireMessage::SnapshotManifestRequest`]. `None`
    /// means "I have no matching snapshot".
    SnapshotManifestResponse(Option<crate::replication::snapshot::SnapshotManifest>),
    /// Ask a peer for chunk `chunk_idx` of the snapshot at `height`.
    SnapshotChunkRequest {
        height: u64,
        chunk_idx: u32,
    },
    /// Reply to a [`WireMessage::SnapshotChunkRequest`]. `payload =
    /// None` means "I have no such chunk" (snapshot pruned, chunk
    /// index out of range, or never had this snapshot).
    SnapshotChunkResponse {
        height: u64,
        chunk_idx: u32,
        payload: Option<Bytes>,
    },
    /// Ask a peer for a contiguous run of blocks by height (issue
    /// #185 / #514). Compresses the catch-up window: a recovering
    /// node that detects a multi-block gap issues one range request
    /// instead of N sequential single-block [`WireMessage::BlockRequest`]
    /// emissions.
    ///
    /// The responder caps the reply at
    /// [`BLOCK_RANGE_RESPONSE_MAX_BLOCKS`] regardless of how wide the
    /// requested span is; requesters pipeline the next range starting
    /// at the last-received height + 1.
    ///
    /// Inclusive on both ends. `from_height > to_height` is an
    /// ill-formed request and the responder replies with an empty
    /// `blocks` vector.
    BlockRangeRequest {
        from_height: Height,
        to_height: Height,
    },
    /// Reply to a [`WireMessage::BlockRangeRequest`]. The signed
    /// payload echoes `from_height` / `to_height` so a Byzantine
    /// responder who serves blocks outside the requested span is
    /// non-repudiable evidence for slashing — same discipline as
    /// [`BlockResponsePayload`].
    BlockRangeResponse(Signed<BlockRangeResponsePayload>),
}

/// Serde adapter for `Option<BlsPartialSig>` — a 96-byte fixed array that
/// serde does not auto-derive past N=32. Mirrors the byte-sequence
/// shape used by [`crate::crypto::sig_scheme::BlsPop`] so the two BLS
/// wire fields encode the same way (length-prefixed byte sequence
/// inside an `Option`).
mod serde_optional_bls_partial {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    use crate::crypto::sig_scheme::BlsPartialSig;

    pub fn serialize<S: Serializer>(opt: &Option<BlsPartialSig>, s: S) -> Result<S::Ok, S::Error> {
        match opt {
            Some(sig) => s.serialize_some(&sig[..]),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<BlsPartialSig>, D::Error> {
        let opt: Option<Vec<u8>> = Option::deserialize(d)?;
        match opt {
            Some(v) => v
                .as_slice()
                .try_into()
                .map(Some)
                .map_err(|_| D::Error::custom("BLS partial must be exactly 96 bytes")),
            None => Ok(None),
        }
    }
}
