//! Consensus message-kind taxonomy for the p2p rate limiter.
//!
//! [`MessageKind`] mirrors the postcard variant tags of
//! [`crate::wire::WireMessage`]. Both the wire schema and this mirror
//! live in this crate, so the lockstep invariant is an intra-crate unit
//! test (`tests::wire_tag_layout_locked`) rather than a cross-crate one.
//!
//! `MessageKind` implements
//! [`boule_core::transport::limits::RateLimitKind`], so the foundational
//! crate's generic [`RateLimiter`](boule_core::transport::limits::RateLimiter)
//! can bucket consensus traffic without naming any consensus message
//! type. The builders here ([`message_rate_limits`],
//! [`production_message_rate_limits`], [`unbounded_message_rate_limits`])
//! project the named `[p2p.limits.rate]` config into the index-ordered
//! per-kind vector the generic limiter expects.

use std::time::Duration;

use boule_core::config::P2pLimitsConfig;
use boule_core::transport::limits::{RateLimitKind, RateLimiter, RateLimitsConfig};

/// One classification per consensus wire-message type.
///
/// The [`index`](RateLimitKind::index) of each kind matches the postcard
/// variant tag emitted at byte 0 of a serialized
/// [`crate::wire::WireMessage`] (postcard encodes enum discriminants as a
/// varint in declaration order; for these twelve variants the tag fits
/// in a single byte). The lockstep with `WireMessage` is pinned by the
/// `tests::wire_tag_layout_locked` unit test — reordering `WireMessage`
/// without updating this enum is a test failure, not a silent miscount.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageKind {
    /// `WireMessage::Proposal` — postcard tag 0.
    Proposal,
    /// `WireMessage::Vote` — postcard tag 1.
    Vote,
    /// `WireMessage::NewView` — postcard tag 2.
    NewView,
    /// `WireMessage::TimeoutVote` — postcard tag 3.
    TimeoutVote,
    /// `WireMessage::BlockRequest` — postcard tag 4.
    RequestBlock,
    /// `WireMessage::BlockResponse` — postcard tag 5.
    ReceiveBlock,
    /// `WireMessage::SnapshotManifestRequest` — postcard tag 6.
    SnapshotManifestRequest,
    /// `WireMessage::SnapshotManifestResponse` — postcard tag 7.
    SnapshotManifestResponse,
    /// `WireMessage::SnapshotChunkRequest` — postcard tag 8.
    SnapshotChunkRequest,
    /// `WireMessage::SnapshotChunkResponse` — postcard tag 9.
    SnapshotChunkResponse,
    /// `WireMessage::BlockRangeRequest` — postcard tag 10. Bulk-range
    /// catch-up RPC introduced in #514 (parent #185).
    BlockRangeRequest,
    /// `WireMessage::BlockRangeResponse` — postcard tag 11.
    BlockRangeResponse,
    /// `WireMessage::EquivocationEvidence` — postcard tag 12 (#657b).
    EquivocationEvidence,
}

impl MessageKind {
    /// Every kind, in declaration / postcard-tag order.
    pub const ALL: [MessageKind; 13] = [
        MessageKind::Proposal,
        MessageKind::Vote,
        MessageKind::NewView,
        MessageKind::TimeoutVote,
        MessageKind::RequestBlock,
        MessageKind::ReceiveBlock,
        MessageKind::SnapshotManifestRequest,
        MessageKind::SnapshotManifestResponse,
        MessageKind::SnapshotChunkRequest,
        MessageKind::SnapshotChunkResponse,
        MessageKind::BlockRangeRequest,
        MessageKind::BlockRangeResponse,
        MessageKind::EquivocationEvidence,
    ];

    /// Map a [`WireMessage`](crate::wire::WireMessage)'s first postcard
    /// byte to a `MessageKind`. Returns `None` for unknown tags so
    /// callers can fall through to the existing `dispatch::ingress`
    /// decoder (which then surfaces the proper `IngressError::Decode`).
    pub fn from_wire_tag(tag: u8) -> Option<Self> {
        Some(match tag {
            0 => Self::Proposal,
            1 => Self::Vote,
            2 => Self::NewView,
            3 => Self::TimeoutVote,
            4 => Self::RequestBlock,
            5 => Self::ReceiveBlock,
            6 => Self::SnapshotManifestRequest,
            7 => Self::SnapshotManifestResponse,
            8 => Self::SnapshotChunkRequest,
            9 => Self::SnapshotChunkResponse,
            10 => Self::BlockRangeRequest,
            11 => Self::BlockRangeResponse,
            12 => Self::EquivocationEvidence,
            _ => return None,
        })
    }
}

impl RateLimitKind for MessageKind {
    fn all() -> &'static [Self] {
        &Self::ALL
    }

    fn index(self) -> usize {
        self as usize
    }

    fn label(self) -> &'static str {
        match self {
            Self::Proposal => "Proposal",
            Self::Vote => "Vote",
            Self::NewView => "NewView",
            Self::TimeoutVote => "TimeoutVote",
            Self::RequestBlock => "RequestBlock",
            Self::ReceiveBlock => "ReceiveBlock",
            Self::SnapshotManifestRequest => "SnapshotManifestRequest",
            Self::SnapshotManifestResponse => "SnapshotManifestResponse",
            Self::SnapshotChunkRequest => "SnapshotChunkRequest",
            Self::SnapshotChunkResponse => "SnapshotChunkResponse",
            Self::BlockRangeRequest => "BlockRangeRequest",
            Self::BlockRangeResponse => "BlockRangeResponse",
            Self::EquivocationEvidence => "EquivocationEvidence",
        }
    }
}

/// A [`RateLimiter`] over the consensus [`MessageKind`] taxonomy.
pub type MessageRateLimiter = RateLimiter<MessageKind>;

/// Per-kind rate vector keyed by [`MessageKind::index`], built by index
/// assignment so a future `MessageKind` reorder can't silently misroute
/// a rate to the wrong bucket.
fn per_kind_vec(set: impl Fn(MessageKind) -> f64) -> Vec<f64> {
    let mut v = vec![0.0; MessageKind::ALL.len()];
    for k in MessageKind::ALL {
        v[k.index()] = set(k);
    }
    v
}

/// Project the parsed `[p2p.limits]` rate + violation fields into the
/// runtime [`RateLimitsConfig`] (per-kind rates in `MessageKind` index
/// order). Was `RateLimitsConfig::from_config` before the rate limiter
/// became generic.
pub fn message_rate_limits(c: &P2pLimitsConfig) -> RateLimitsConfig {
    RateLimitsConfig {
        per_kind_per_sec: per_kind_vec(|k| match k {
            MessageKind::Proposal => c.rate.proposal_per_sec,
            MessageKind::Vote => c.rate.vote_per_sec,
            MessageKind::NewView => c.rate.new_view_per_sec,
            MessageKind::TimeoutVote => c.rate.timeout_vote_per_sec,
            MessageKind::RequestBlock => c.rate.request_block_per_sec,
            MessageKind::ReceiveBlock => c.rate.receive_block_per_sec,
            MessageKind::SnapshotManifestRequest => c.rate.snapshot_manifest_request_per_sec,
            MessageKind::SnapshotManifestResponse => c.rate.snapshot_manifest_response_per_sec,
            MessageKind::SnapshotChunkRequest => c.rate.snapshot_chunk_request_per_sec,
            MessageKind::SnapshotChunkResponse => c.rate.snapshot_chunk_response_per_sec,
            MessageKind::BlockRangeRequest => c.rate.block_range_request_per_sec,
            MessageKind::BlockRangeResponse => c.rate.block_range_response_per_sec,
            MessageKind::EquivocationEvidence => c.rate.equivocation_evidence_per_sec,
        }),
        bytes_per_sec: c.rate.bytes_per_sec,
        outbound_bytes_per_sec: c.rate.outbound_bytes_per_sec,
        burst_seconds: c.rate.burst_seconds,
        violation_window: Duration::from_secs(c.violations.window_secs),
        max_violations: c.violations.max_violations,
    }
}

/// Permissive config that effectively disables rate limiting. Used by
/// the consensus property tests and the simulator's happy-path harness
/// so an unrelated rate spike never perturbs the assertion under test.
pub fn unbounded_message_rate_limits() -> RateLimitsConfig {
    const HUGE: f64 = 1.0e12;
    RateLimitsConfig {
        per_kind_per_sec: vec![HUGE; MessageKind::ALL.len()],
        bytes_per_sec: HUGE,
        outbound_bytes_per_sec: HUGE,
        burst_seconds: 1.0,
        violation_window: Duration::from_secs(10),
        max_violations: u32::MAX,
    }
}

/// Defaults baked into the binary when the operator omits
/// `[p2p.limits.rate]`. Sized generously above honest steady-state for a
/// four-validator cluster; see issue #134 for the design rationale.
pub fn production_message_rate_limits() -> RateLimitsConfig {
    RateLimitsConfig {
        per_kind_per_sec: per_kind_vec(|k| match k {
            MessageKind::Proposal => 16.0,
            MessageKind::Vote => 256.0,
            MessageKind::NewView => 64.0,
            MessageKind::TimeoutVote => 64.0,
            MessageKind::RequestBlock => 8.0,
            MessageKind::ReceiveBlock => 8.0,
            // Snapshot rates: bursty but rare. A joiner fetching a 1 GiB
            // snapshot at 1 MiB chunks issues ~1024 chunk requests;
            // 32/sec lets the fetch complete in ~30s without tripping
            // the limiter. Manifest exchanges happen O(1) per fetch; cap
            // them tighter to bound a Byzantine manifest-flood.
            MessageKind::SnapshotManifestRequest => 4.0,
            MessageKind::SnapshotManifestResponse => 4.0,
            MessageKind::SnapshotChunkRequest => 32.0,
            MessageKind::SnapshotChunkResponse => 32.0,
            // Block-range RPC: bursty during catch-up but rare in steady
            // state; 8/s leaves headroom for rotation across peers
            // without inviting a flood vector.
            MessageKind::BlockRangeRequest => 8.0,
            MessageKind::BlockRangeResponse => 8.0,
            // Equivocation-evidence gossip (#657b): one proof per
            // equivocator, so genuine traffic is tiny; 8/s caps a
            // bogus-proof flood (each costs the receiver a verification).
            MessageKind::EquivocationEvidence => 8.0,
        }),
        bytes_per_sec: 1024.0 * 1024.0,
        outbound_bytes_per_sec: 1024.0 * 1024.0,
        burst_seconds: 1.0,
        violation_window: Duration::from_secs(10),
        max_violations: 100,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{BlockResponsePayload, WireMessage};
    use boule_core::crypto::signed::Signed;

    /// Lockstep invariant: each `WireMessage` variant's postcard tag
    /// must equal the matching `MessageKind`'s index, and
    /// `from_wire_tag` must invert it. Moved next to `WireMessage` (was
    /// a cross-crate test in `boule-node`) now that `MessageKind` lives
    /// in this crate.
    #[test]
    fn wire_tag_layout_locked() {
        let req = WireMessage::BlockRequest([0u8; 32]);
        let bytes = postcard::to_allocvec(&req).expect("encode");
        assert_eq!(bytes[0], 4, "BlockRequest must serialize at tag 4");

        let resp = WireMessage::BlockResponse(Signed {
            payload: BlockResponsePayload {
                requested_hash: [0u8; 32],
                block: None,
            },
            signer: [0u8; 32],
            sig: [0u8; 64],
        });
        let bytes = postcard::to_allocvec(&resp).expect("encode");
        assert_eq!(bytes[0], 5, "BlockResponse must serialize at tag 5");

        let req = WireMessage::SnapshotManifestRequest { height: None };
        let bytes = postcard::to_allocvec(&req).expect("encode");
        assert_eq!(
            bytes[0], 6,
            "SnapshotManifestRequest must serialize at tag 6"
        );

        let resp = WireMessage::SnapshotManifestResponse(None);
        let bytes = postcard::to_allocvec(&resp).expect("encode");
        assert_eq!(
            bytes[0], 7,
            "SnapshotManifestResponse must serialize at tag 7"
        );

        let req = WireMessage::SnapshotChunkRequest {
            height: 0,
            chunk_idx: 0,
        };
        let bytes = postcard::to_allocvec(&req).expect("encode");
        assert_eq!(bytes[0], 8, "SnapshotChunkRequest must serialize at tag 8");

        let resp = WireMessage::SnapshotChunkResponse {
            height: 0,
            chunk_idx: 0,
            payload: None,
        };
        let bytes = postcard::to_allocvec(&resp).expect("encode");
        assert_eq!(bytes[0], 9, "SnapshotChunkResponse must serialize at tag 9");

        let req = WireMessage::BlockRangeRequest {
            from_height: crate::Height(0),
            to_height: crate::Height(0),
        };
        let bytes = postcard::to_allocvec(&req).expect("encode");
        assert_eq!(bytes[0], 10, "BlockRangeRequest must serialize at tag 10");

        let resp = WireMessage::BlockRangeResponse(Signed {
            payload: crate::wire::BlockRangeResponsePayload {
                from_height: crate::Height(0),
                to_height: crate::Height(0),
                blocks: Vec::new(),
            },
            signer: [0u8; 32],
            sig: [0u8; 64],
        });
        let bytes = postcard::to_allocvec(&resp).expect("encode");
        assert_eq!(bytes[0], 11, "BlockRangeResponse must serialize at tag 11");

        let ev = WireMessage::EquivocationEvidence(crate::dispatch::EquivocationProof::DoubleVote(
            Box::new(Signed {
                payload: crate::hotstuff::qc::Vote {
                    view: crate::View(0),
                    block_hash: [0u8; 32],
                },
                signer: [0u8; 32],
                sig: [0u8; 64],
            }),
            Box::new(Signed {
                payload: crate::hotstuff::qc::Vote {
                    view: crate::View(0),
                    block_hash: [1u8; 32],
                },
                signer: [0u8; 32],
                sig: [0u8; 64],
            }),
        ));
        let bytes = postcard::to_allocvec(&ev).expect("encode");
        assert_eq!(
            bytes[0], 12,
            "EquivocationEvidence must serialize at tag 12"
        );

        for (tag, kind) in [
            (0, MessageKind::Proposal),
            (1, MessageKind::Vote),
            (2, MessageKind::NewView),
            (3, MessageKind::TimeoutVote),
            (4, MessageKind::RequestBlock),
            (5, MessageKind::ReceiveBlock),
            (6, MessageKind::SnapshotManifestRequest),
            (7, MessageKind::SnapshotManifestResponse),
            (8, MessageKind::SnapshotChunkRequest),
            (9, MessageKind::SnapshotChunkResponse),
            (10, MessageKind::BlockRangeRequest),
            (11, MessageKind::BlockRangeResponse),
            (12, MessageKind::EquivocationEvidence),
        ] {
            assert_eq!(MessageKind::from_wire_tag(tag), Some(kind));
            // index() must equal the postcard tag.
            assert_eq!(kind.index(), tag as usize);
        }
        assert_eq!(MessageKind::from_wire_tag(13), None);
        assert_eq!(MessageKind::from_wire_tag(0xFF), None);
    }
}
