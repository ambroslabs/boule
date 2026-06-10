use std::time::Duration;

use boule_core::config::P2pLimitsConfig;
use boule_core::transport::limits::{RateLimitKind, RateLimiter, RateLimitsConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageKind {
    Proposal,

    Vote,

    NewView,

    TimeoutVote,

    RequestBlock,

    ReceiveBlock,

    SnapshotManifestRequest,

    SnapshotManifestResponse,

    SnapshotChunkRequest,

    SnapshotChunkResponse,

    BlockRangeRequest,

    BlockRangeResponse,

    EquivocationEvidence,

    Status,
}

impl MessageKind {
    pub const ALL: [MessageKind; 14] = [
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
        MessageKind::Status,
    ];

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
            13 => Self::Status,
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
            Self::Status => "Status",
        }
    }
}

pub type MessageRateLimiter = RateLimiter<MessageKind>;

fn per_kind_vec(set: impl Fn(MessageKind) -> f64) -> Vec<f64> {
    let mut v = vec![0.0; MessageKind::ALL.len()];
    for k in MessageKind::ALL {
        v[k.index()] = set(k);
    }
    v
}

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

            MessageKind::Status => 64.0,
        }),
        bytes_per_sec: c.rate.bytes_per_sec,
        outbound_bytes_per_sec: c.rate.outbound_bytes_per_sec,
        burst_seconds: c.rate.burst_seconds,
        violation_window: Duration::from_secs(c.violations.window_secs),
        max_violations: c.violations.max_violations,
    }
}

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

pub fn production_message_rate_limits() -> RateLimitsConfig {
    RateLimitsConfig {
        per_kind_per_sec: per_kind_vec(|k| match k {
            MessageKind::Proposal => 16.0,
            MessageKind::Vote => 256.0,
            MessageKind::NewView => 64.0,
            MessageKind::TimeoutVote => 64.0,
            MessageKind::RequestBlock => 8.0,
            MessageKind::ReceiveBlock => 8.0,

            MessageKind::SnapshotManifestRequest => 4.0,
            MessageKind::SnapshotManifestResponse => 4.0,
            MessageKind::SnapshotChunkRequest => 32.0,
            MessageKind::SnapshotChunkResponse => 32.0,

            MessageKind::BlockRangeRequest => 8.0,
            MessageKind::BlockRangeResponse => 8.0,

            MessageKind::EquivocationEvidence => 8.0,
            MessageKind::Status => 64.0,
        }),
        bytes_per_sec: 1024.0 * 1024.0,
        outbound_bytes_per_sec: 1024.0 * 1024.0,
        burst_seconds: 1.0,
        violation_window: Duration::from_secs(10),
        max_violations: 100,
    }
}
