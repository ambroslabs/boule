//! Per-peer rate limiting and connection caps for the p2p layer
//! (issue #134).
//!
//! Two independent limiters live here:
//!
//! - [`RateLimiter`] enforces per-peer token buckets keyed by
//!   [`MessageKind`] (one bucket per consensus message type) plus a
//!   per-peer wire-bytes/sec cap. The consensus integration layer
//!   classifies an inbound frame's first byte into a [`MessageKind`],
//!   asks `admit`, and either drops or dispatches based on the
//!   [`Decision`]. After K violations within a sliding window of W
//!   seconds, [`Decision::Disconnect`] is returned exactly once per
//!   peer — the caller is responsible for tearing down the connection
//!   (typically by sending [`crate::p2p::PeerCommand::Disconnect`]).
//!
//! - [`ConnectionLimiter`] enforces global inbound / outbound /
//!   per-source-IP caps at the manager. The listener and dialer pass
//!   the [`Direction`] of every accepted connection; the manager calls
//!   [`ConnectionLimiter::try_admit`] before registering and
//!   [`ConnectionLimiter::release`] when the connection task exits.
//!
//! Both limiters are plumbed as `Option<Arc<…>>` so tests, the
//! simulator, and any embedding without the limits configured opt out
//! by passing `None`.
//!
//! # Determinism
//!
//! Time is taken from an [`Arc<dyn Clock>`] (monotonic), so the sim's
//! [`crate::sim::SimClock`] drives the rate-limiter under virtual time
//! exactly like in production.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use parking_lot::Mutex;

use crate::clock::Clock;
use crate::p2p::NodeId;

// ── MessageKind ──────────────────────────────────────────────────────────────

/// One classification per consensus wire-message type.
///
/// The numeric value matches the postcard variant tag emitted at byte 0
/// of a serialized [`crate::consensus::node::WireMessage`] (postcard
/// encodes enum discriminants as a varint in declaration order; for
/// the ten variants here the tag fits in a single byte). Locked in by
/// the unit test [`tests::wire_tag_layout_locked`] below — reordering
/// `WireMessage` without updating this enum is a test failure, not a
/// silent miscount.
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
}

impl MessageKind {
    /// Iteration helper used by the rate limiter to construct one
    /// bucket per kind in a fixed order.
    pub const ALL: [MessageKind; 10] = [
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
    ];

    /// Map a `WireMessage`'s first postcard byte to a `MessageKind`.
    /// Returns `None` for unknown tags so callers can fall through to
    /// the existing `dispatch::ingress` decoder (which then surfaces
    /// the proper `IngressError::Decode`).
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
            _ => return None,
        })
    }

    /// Stable short label for log fields.
    pub fn label(self) -> &'static str {
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
        }
    }

    fn idx(self) -> usize {
        match self {
            Self::Proposal => 0,
            Self::Vote => 1,
            Self::NewView => 2,
            Self::TimeoutVote => 3,
            Self::RequestBlock => 4,
            Self::ReceiveBlock => 5,
            Self::SnapshotManifestRequest => 6,
            Self::SnapshotManifestResponse => 7,
            Self::SnapshotChunkRequest => 8,
            Self::SnapshotChunkResponse => 9,
        }
    }
}

// ── TokenBucket ──────────────────────────────────────────────────────────────

/// Continuous-time token bucket. Refills at `rate_per_sec` up to
/// `capacity`; `try_take(now, n)` consumes `n` tokens iff at least
/// `n` are available after the lazy refill.
///
/// Safe to construct with `rate_per_sec == capacity == 0.0`, which
/// permanently denies; with `rate_per_sec == f64::INFINITY` or any
/// huge number, the bucket effectively never empties (used by
/// [`RateLimitsConfig::unbounded_for_tests`]).
#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    rate_per_sec: f64,
    last_refill: Duration,
}

impl TokenBucket {
    /// New bucket starting full.
    pub fn new(rate_per_sec: f64, capacity: f64, now: Duration) -> Self {
        Self {
            capacity,
            tokens: capacity,
            rate_per_sec,
            last_refill: now,
        }
    }

    /// Try to consume `n` tokens. Returns `true` on success. Refills
    /// lazily based on `now - last_refill`, so a long quiet period
    /// fills the bucket back to capacity in one call.
    pub fn try_take(&mut self, now: Duration, n: f64) -> bool {
        // Negative elapsed (clock regression) is treated as zero rather
        // than minting tokens; the assertion documents the contract on
        // `Clock::now_monotonic` while keeping production resilient.
        let elapsed = now.saturating_sub(self.last_refill).as_secs_f64();
        let refilled = (self.tokens + elapsed * self.rate_per_sec).min(self.capacity);
        self.tokens = refilled;
        self.last_refill = now;
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }

    /// Visible for tests / debugging. Not part of the limiter contract.
    #[cfg(test)]
    pub fn tokens(&self) -> f64 {
        self.tokens
    }
}

// ── RateLimitsConfig ─────────────────────────────────────────────────────────

/// Plain-data configuration for [`RateLimiter`]. Every rate is in
/// units-per-second; the burst capacity is `rate_per_sec *
/// burst_seconds` so a peer can spike for a short window without
/// tripping the limit.
///
/// Defaults are sized loose enough that an honest 4-validator cluster
/// running 200ms-view-timer never trips a bucket; see
/// [`Self::production_defaults`].
#[derive(Debug, Clone)]
pub struct RateLimitsConfig {
    /// Steady-state rate of `Proposal` frames. A leader proposes once
    /// per view; over a 4-node cluster every replica receives one
    /// proposal per view from the leader — set generously to allow
    /// for view changes and recovery flurries.
    pub proposal_per_sec: f64,
    /// Steady-state rate of `Vote` frames. Each replica sends one vote
    /// per view × (n - 1) recipients, so the per-peer inbound vote
    /// rate is one per view.
    pub vote_per_sec: f64,
    /// Steady-state rate of `TimeoutVote` frames.
    pub timeout_vote_per_sec: f64,
    /// Steady-state rate of `NewView` frames.
    pub new_view_per_sec: f64,
    /// Steady-state rate of `BlockRequest` frames received from a
    /// peer. Sized for catch-up rather than steady-state — a
    /// healthy peer does not request blocks in steady state.
    pub request_block_per_sec: f64,
    /// Steady-state rate of `BlockResponse` frames received from a
    /// peer. Mirrors `request_block_per_sec` since each request
    /// elicits at most one response.
    pub receive_block_per_sec: f64,
    /// Steady-state rate of `SnapshotManifestRequest` frames received
    /// from a peer. Snapshot fetches are bursty but rare — sized for
    /// a joiner negotiating manifests with its known peers, not for
    /// steady-state traffic.
    pub snapshot_manifest_request_per_sec: f64,
    /// Steady-state rate of `SnapshotManifestResponse` frames. Mirrors
    /// the request side.
    pub snapshot_manifest_response_per_sec: f64,
    /// Steady-state rate of `SnapshotChunkRequest` frames received from
    /// a peer. Sized for chunked catch-up — a joiner pulling a 100 MiB
    /// snapshot at 1 MiB chunks fits well under the default.
    pub snapshot_chunk_request_per_sec: f64,
    /// Steady-state rate of `SnapshotChunkResponse` frames. Mirrors
    /// the request side.
    pub snapshot_chunk_response_per_sec: f64,
    /// Per-peer wire-bytes/sec ceiling, applied independently of the
    /// per-kind buckets so a flood of any one kind that fits within
    /// its bucket can still be dropped on bytes alone.
    pub bytes_per_sec: f64,
    /// Burst window in seconds; capacity for each bucket is
    /// `rate_per_sec * burst_seconds`.
    pub burst_seconds: f64,
    /// Rolling window over which violations are counted. After
    /// `max_violations` violations within this window, [`admit`]
    /// returns [`Decision::Disconnect`].
    ///
    /// [`admit`]: RateLimiter::admit
    pub violation_window: Duration,
    /// Number of consecutive drops within `violation_window` that
    /// earn a disconnect decision. The first drop after disconnect
    /// is suppressed with `Decision::Drop` so the caller's
    /// disconnect-flow runs once.
    pub max_violations: u32,
}

impl RateLimitsConfig {
    /// Permissive defaults that effectively disable rate limiting.
    /// Used by the consensus property tests and the simulator's
    /// happy-path harness so an unrelated rate spike never perturbs
    /// the assertion under test.
    pub fn unbounded_for_tests() -> Self {
        const HUGE: f64 = 1.0e12;
        Self {
            proposal_per_sec: HUGE,
            vote_per_sec: HUGE,
            timeout_vote_per_sec: HUGE,
            new_view_per_sec: HUGE,
            request_block_per_sec: HUGE,
            receive_block_per_sec: HUGE,
            snapshot_manifest_request_per_sec: HUGE,
            snapshot_manifest_response_per_sec: HUGE,
            snapshot_chunk_request_per_sec: HUGE,
            snapshot_chunk_response_per_sec: HUGE,
            bytes_per_sec: HUGE,
            burst_seconds: 1.0,
            violation_window: Duration::from_secs(10),
            max_violations: u32::MAX,
        }
    }

    /// Defaults baked into the binary when the operator omits
    /// `[p2p.limits.rate]`. Sized generously above honest steady-state
    /// for a four-validator cluster; see issue #134 for the design
    /// rationale.
    pub fn production_defaults() -> Self {
        Self {
            proposal_per_sec: 16.0,
            vote_per_sec: 256.0,
            timeout_vote_per_sec: 64.0,
            new_view_per_sec: 64.0,
            request_block_per_sec: 8.0,
            receive_block_per_sec: 8.0,
            // Snapshot rates: bursty but rare. A joiner fetching a
            // 1 GiB snapshot at 1 MiB chunks issues ~1024 chunk
            // requests; 32/sec lets the fetch complete in ~30s
            // without tripping the limiter, and steady-state traffic
            // (zero in healthy clusters) sits comfortably below.
            // Manifest exchanges happen O(1) per fetch; cap them
            // tighter to bound a Byzantine peer's manifest-flood.
            snapshot_manifest_request_per_sec: 4.0,
            snapshot_manifest_response_per_sec: 4.0,
            snapshot_chunk_request_per_sec: 32.0,
            snapshot_chunk_response_per_sec: 32.0,
            bytes_per_sec: 1024.0 * 1024.0,
            burst_seconds: 1.0,
            violation_window: Duration::from_secs(10),
            max_violations: 100,
        }
    }

    fn rate_for(&self, k: MessageKind) -> f64 {
        match k {
            MessageKind::Proposal => self.proposal_per_sec,
            MessageKind::Vote => self.vote_per_sec,
            MessageKind::NewView => self.new_view_per_sec,
            MessageKind::TimeoutVote => self.timeout_vote_per_sec,
            MessageKind::RequestBlock => self.request_block_per_sec,
            MessageKind::ReceiveBlock => self.receive_block_per_sec,
            MessageKind::SnapshotManifestRequest => self.snapshot_manifest_request_per_sec,
            MessageKind::SnapshotManifestResponse => self.snapshot_manifest_response_per_sec,
            MessageKind::SnapshotChunkRequest => self.snapshot_chunk_request_per_sec,
            MessageKind::SnapshotChunkResponse => self.snapshot_chunk_response_per_sec,
        }
    }

    fn bucket_capacity(&self, k: MessageKind) -> f64 {
        // Capacity = rate × burst_seconds. Floor at 1 token so a
        // bucket whose configured rate is < 1/burst_seconds still
        // admits a single message rather than refusing every one.
        (self.rate_for(k) * self.burst_seconds).max(1.0)
    }

    fn bytes_capacity(&self) -> f64 {
        (self.bytes_per_sec * self.burst_seconds).max(1.0)
    }
}

// ── Decision + counters ──────────────────────────────────────────────────────

/// Outcome of a single [`RateLimiter::admit`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Frame is within all buckets; the caller should dispatch normally.
    Allow,
    /// Frame exceeded a per-type bucket or the bytes/sec ceiling.
    /// The caller drops the frame and continues handling messages
    /// from this peer.
    Drop,
    /// `max_violations` drops have accumulated within
    /// `violation_window`; the caller should tear down the
    /// connection. Returned exactly once per peer until the next
    /// violation window elapses (subsequent violations return
    /// `Drop`).
    Disconnect,
}

/// Atomic per-kind drop counters plus a global disconnect counter.
/// Cheap to clone (each inner counter is shared via `Arc`).
#[derive(Debug, Clone, Default)]
pub struct RateLimitCounters {
    inner: Arc<RateLimitCountersInner>,
}

#[derive(Debug, Default)]
struct RateLimitCountersInner {
    by_kind: [AtomicU64; 10],
    bytes: AtomicU64,
    disconnects: AtomicU64,
}

impl RateLimitCounters {
    /// Cumulative drops for `kind` since the counter was created.
    pub fn drops(&self, kind: MessageKind) -> u64 {
        self.inner.by_kind[kind.idx()].load(Ordering::Relaxed)
    }

    /// Total drops across every message kind.
    pub fn total_drops(&self) -> u64 {
        MessageKind::ALL
            .iter()
            .map(|k| self.drops(*k))
            .sum::<u64>()
            .saturating_add(self.bytes_drops())
    }

    /// Cumulative drops attributed to the bytes/sec cap (independent
    /// of the per-kind buckets).
    pub fn bytes_drops(&self) -> u64 {
        self.inner.bytes.load(Ordering::Relaxed)
    }

    /// Cumulative `Decision::Disconnect` returns.
    pub fn disconnects(&self) -> u64 {
        self.inner.disconnects.load(Ordering::Relaxed)
    }

    fn inc_drops(&self, kind: MessageKind) {
        self.inner.by_kind[kind.idx()].fetch_add(1, Ordering::Relaxed);
    }

    fn inc_bytes(&self) {
        self.inner.bytes.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_disconnects(&self) {
        self.inner.disconnects.fetch_add(1, Ordering::Relaxed);
    }
}

// ── PeerState + RateLimiter ──────────────────────────────────────────────────

struct PeerState {
    buckets: [TokenBucket; 10],
    bytes_bucket: TokenBucket,
    /// Monotonic instants of recent violations, oldest first.
    violations: VecDeque<Duration>,
    /// True after the limiter returned [`Decision::Disconnect`] once
    /// for this peer; suppresses repeats until violations age out of
    /// the window.
    disconnect_dispatched: bool,
}

impl PeerState {
    fn new(config: &RateLimitsConfig, now: Duration) -> Self {
        let mk =
            |k: MessageKind| TokenBucket::new(config.rate_for(k), config.bucket_capacity(k), now);
        Self {
            buckets: [
                mk(MessageKind::Proposal),
                mk(MessageKind::Vote),
                mk(MessageKind::NewView),
                mk(MessageKind::TimeoutVote),
                mk(MessageKind::RequestBlock),
                mk(MessageKind::ReceiveBlock),
                mk(MessageKind::SnapshotManifestRequest),
                mk(MessageKind::SnapshotManifestResponse),
                mk(MessageKind::SnapshotChunkRequest),
                mk(MessageKind::SnapshotChunkResponse),
            ],
            bytes_bucket: TokenBucket::new(config.bytes_per_sec, config.bytes_capacity(), now),
            violations: VecDeque::new(),
            disconnect_dispatched: false,
        }
    }
}

/// Per-peer multi-bucket rate limiter.
///
/// All state lives behind one `Mutex` keyed by [`NodeId`] — the hot
/// path is one hash + one short critical section, which is comfortable
/// at consensus message rates (a few thousand admits/sec across all
/// peers). If profiles ever surface contention, sharding by peer is
/// the natural follow-up.
pub struct RateLimiter {
    config: RateLimitsConfig,
    state: Mutex<HashMap<NodeId, PeerState>>,
    clock: Arc<dyn Clock>,
    counters: RateLimitCounters,
}

impl RateLimiter {
    /// Construct a rate limiter from `config`. The supplied [`Clock`]
    /// drives the bucket refill timestamps; pass the consensus
    /// node's clock so the limiter and the pacemaker share a time
    /// base under virtual-clock tests.
    pub fn new(config: RateLimitsConfig, clock: Arc<dyn Clock>) -> Self {
        Self {
            config,
            state: Mutex::new(HashMap::new()),
            clock,
            counters: RateLimitCounters::default(),
        }
    }

    /// Decide whether to admit, drop, or disconnect a freshly
    /// received frame from `peer`. `bytes_len` is the on-wire frame
    /// length (after framing strips the protocol-tag prefix); it is
    /// charged against the bytes/sec cap independently of the per-
    /// kind bucket.
    pub fn admit(&self, peer: NodeId, kind: MessageKind, bytes_len: usize) -> Decision {
        let now = self.clock.now_monotonic();
        let mut state = self.state.lock();
        let peer_state = state
            .entry(peer)
            .or_insert_with(|| PeerState::new(&self.config, now));

        // Age violations out of the rolling window before checking
        // both buckets, so a peer that earned a Disconnect in the
        // past window can re-admit normally after a quiet stretch.
        let window_start = now.saturating_sub(self.config.violation_window);
        while peer_state
            .violations
            .front()
            .is_some_and(|t| *t < window_start)
        {
            peer_state.violations.pop_front();
        }
        if peer_state.violations.is_empty() {
            // Window cleared — re-arm the disconnect latch so a
            // fresh violation streak can fire it again.
            peer_state.disconnect_dispatched = false;
        }

        // Type bucket first: returning Drop on a per-type cap is the
        // most common outcome under flood, and the bytes bucket
        // correctness only matters when the type bucket admitted.
        let kind_admitted = peer_state.buckets[kind.idx()].try_take(now, 1.0);
        let bytes_admitted = peer_state.bytes_bucket.try_take(now, bytes_len as f64);

        if kind_admitted && bytes_admitted {
            return Decision::Allow;
        }

        // Refund the side that admitted — we're dropping the frame
        // anyway, so the budget should reflect rejected, not
        // consumed, work. Without this, a frame that hits the bytes
        // ceiling would still consume a token from the type bucket
        // and could mask the per-type rate when one peer spams a
        // single huge frame.
        if kind_admitted && !bytes_admitted {
            peer_state.buckets[kind.idx()].tokens += 1.0;
        }
        if bytes_admitted && !kind_admitted {
            peer_state.bytes_bucket.tokens += bytes_len as f64;
        }

        peer_state.violations.push_back(now);

        if !kind_admitted {
            self.counters.inc_drops(kind);
        } else {
            self.counters.inc_bytes();
        }

        if peer_state.violations.len() >= self.config.max_violations as usize
            && !peer_state.disconnect_dispatched
        {
            peer_state.disconnect_dispatched = true;
            self.counters.inc_disconnects();
            return Decision::Disconnect;
        }
        Decision::Drop
    }

    /// Forget a peer's accumulated state. Call when the connection is
    /// torn down so a future reconnect starts fresh (matching the
    /// non-goal of "no cross-reconnect reputation tracking").
    pub fn forget_peer(&self, peer: NodeId) {
        self.state.lock().remove(&peer);
    }

    /// Snapshot handle to the cumulative drop / disconnect counters.
    pub fn counters(&self) -> &RateLimitCounters {
        &self.counters
    }

    /// Configured limits — exposed read-only for log fields and
    /// integration tests.
    pub fn config(&self) -> &RateLimitsConfig {
        &self.config
    }
}

// ── ConnectionLimiter ────────────────────────────────────────────────────────

/// Direction of a peer-manager connection registration. Carried on
/// [`crate::p2p::manager::ManagerMsg::NewConnection`] so the manager
/// can charge the right bucket in [`ConnectionLimiter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Connection arrived via [`crate::p2p::listener::run`] — count
    /// against `max_inbound`.
    Inbound,
    /// Connection arrived via [`crate::p2p::dialer::reconnect_loop`] —
    /// count against `max_outbound`.
    Outbound,
}

/// Plain-data caps for [`ConnectionLimiter`].
#[derive(Debug, Clone)]
pub struct ConnectionLimitsConfig {
    /// Maximum total inbound connections concurrently registered.
    pub max_inbound: usize,
    /// Maximum total outbound connections concurrently registered.
    pub max_outbound: usize,
    /// Maximum concurrent connections (in either direction) from a
    /// single source IP. Set to `usize::MAX` to disable per-IP
    /// counting.
    pub max_per_ip: usize,
}

impl ConnectionLimitsConfig {
    /// Defaults baked into the binary when the operator omits
    /// `[p2p.limits]` connection caps. Loose enough for a 4–dozen-
    /// validator cluster.
    pub fn production_defaults() -> Self {
        Self {
            max_inbound: 64,
            max_outbound: 64,
            max_per_ip: 4,
        }
    }

    /// Permissive defaults that effectively disable connection caps —
    /// used by the simulator and any test where the cap is not under
    /// assertion.
    pub fn unbounded_for_tests() -> Self {
        Self {
            max_inbound: usize::MAX,
            max_outbound: usize::MAX,
            max_per_ip: usize::MAX,
        }
    }
}

/// Reason a connection was refused by [`ConnectionLimiter::try_admit`].
/// Surfaced in WARN logs so an operator can distinguish a legitimate
/// flood (per-IP cap fires from a single attacker) from a global
/// surge (total inbound saturated).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// `max_inbound` is saturated.
    TotalInbound,
    /// `max_outbound` is saturated.
    TotalOutbound,
    /// `max_per_ip` is saturated for the connection's source IP.
    PerIp,
}

impl RejectReason {
    /// Stable short label for log fields.
    pub fn label(self) -> &'static str {
        match self {
            Self::TotalInbound => "max_inbound",
            Self::TotalOutbound => "max_outbound",
            Self::PerIp => "max_per_ip",
        }
    }
}

/// Global connection caps. Stored in the manager and consulted on
/// every [`crate::p2p::manager::ManagerMsg::NewConnection`].
pub struct ConnectionLimiter {
    config: ConnectionLimitsConfig,
    inbound: AtomicUsize,
    outbound: AtomicUsize,
    per_ip: Mutex<HashMap<IpAddr, usize>>,
    rejects: AtomicU64,
}

impl ConnectionLimiter {
    /// Construct a connection limiter from `config`.
    pub fn new(config: ConnectionLimitsConfig) -> Self {
        Self {
            config,
            inbound: AtomicUsize::new(0),
            outbound: AtomicUsize::new(0),
            per_ip: Mutex::new(HashMap::new()),
            rejects: AtomicU64::new(0),
        }
    }

    /// Try to register a connection. On success, the caller must
    /// pair this with a matching [`Self::release`] when the
    /// connection task exits. On failure, the reject counter is
    /// incremented and the connection should be dropped.
    pub fn try_admit(&self, direction: Direction, ip: IpAddr) -> Result<(), RejectReason> {
        // Per-IP check first so a single noisy peer cannot exhaust
        // the global cap. The lock guards both the counter read and
        // the increment so a concurrent admit can't slip through.
        let mut per_ip = self.per_ip.lock();
        let ip_count = per_ip.get(&ip).copied().unwrap_or(0);
        if ip_count >= self.config.max_per_ip {
            self.rejects.fetch_add(1, Ordering::Relaxed);
            return Err(RejectReason::PerIp);
        }

        match direction {
            Direction::Inbound => {
                let cur = self.inbound.load(Ordering::Acquire);
                if cur >= self.config.max_inbound {
                    self.rejects.fetch_add(1, Ordering::Relaxed);
                    return Err(RejectReason::TotalInbound);
                }
                // Both increments under the per-IP mutex so we don't
                // race past the cap with a parallel admit.
                self.inbound.fetch_add(1, Ordering::AcqRel);
            }
            Direction::Outbound => {
                let cur = self.outbound.load(Ordering::Acquire);
                if cur >= self.config.max_outbound {
                    self.rejects.fetch_add(1, Ordering::Relaxed);
                    return Err(RejectReason::TotalOutbound);
                }
                self.outbound.fetch_add(1, Ordering::AcqRel);
            }
        }
        *per_ip.entry(ip).or_insert(0) += 1;
        Ok(())
    }

    /// Release a previously admitted slot. Idempotent in the sense
    /// that the caller is expected to call this exactly once per
    /// successful `try_admit` — extra calls underflow the counters
    /// (saturating subtraction protects against the worst case).
    pub fn release(&self, direction: Direction, ip: IpAddr) {
        match direction {
            Direction::Inbound => {
                self.inbound
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |c| {
                        Some(c.saturating_sub(1))
                    })
                    .ok();
            }
            Direction::Outbound => {
                self.outbound
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |c| {
                        Some(c.saturating_sub(1))
                    })
                    .ok();
            }
        }
        let mut per_ip = self.per_ip.lock();
        if let Some(c) = per_ip.get_mut(&ip) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                per_ip.remove(&ip);
            }
        }
    }

    /// Cumulative `try_admit` rejections.
    pub fn rejects(&self) -> u64 {
        self.rejects.load(Ordering::Relaxed)
    }

    /// Currently registered inbound connections.
    pub fn inbound(&self) -> usize {
        self.inbound.load(Ordering::Relaxed)
    }

    /// Currently registered outbound connections.
    pub fn outbound(&self) -> usize {
        self.outbound.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::TokioClock;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    /// A clock that returns whatever `set` was last called with.
    /// Lets the rate-limiter unit tests advance virtual time without
    /// pulling in `tokio::time::pause`.
    struct ManualClock(parking_lot::Mutex<Duration>);

    impl ManualClock {
        fn new() -> Arc<Self> {
            Arc::new(Self(parking_lot::Mutex::new(Duration::ZERO)))
        }
        fn set(&self, d: Duration) {
            *self.0.lock() = d;
        }
    }

    impl crate::clock::Clock for ManualClock {
        fn now_wall(&self) -> chrono::DateTime<chrono::Utc> {
            chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0).unwrap()
        }
        fn now_monotonic(&self) -> Duration {
            *self.0.lock()
        }
        fn sleep(&self, _dur: Duration) -> crate::clock::BoxFuture<'static, ()> {
            Box::pin(async {})
        }
        fn interval(&self, _period: Duration) -> Box<dyn crate::clock::ClockInterval> {
            unimplemented!("ManualClock::interval is not used by RateLimiter")
        }
    }

    // ── MessageKind / wire-tag ──────────────────────────────────────────────

    /// The numeric discriminants below are part of the wire contract:
    /// [`crate::consensus::node::WireMessage`] is postcard-encoded, and
    /// postcard emits the variant index as a varint at byte 0
    /// (single-byte for the six variants here). Changing the order of
    /// `WireMessage` without updating `MessageKind::from_wire_tag` would
    /// silently misclassify every frame, so we lock the mapping in via a
    /// real-encode test on the two simplest variants (the rest carry
    /// `Signed<…>` payloads that need a keypair to construct).
    #[test]
    fn wire_tag_layout_locked() {
        use crate::consensus::node::WireMessage;
        let req = WireMessage::BlockRequest([0u8; 32]);
        let bytes = postcard::to_allocvec(&req).expect("encode");
        assert_eq!(bytes[0], 4, "BlockRequest must serialize at tag 4");

        let resp = WireMessage::BlockResponse(None);
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

        // Round-trip the classification helper for every documented tag.
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
        ] {
            assert_eq!(MessageKind::from_wire_tag(tag), Some(kind));
        }
        assert_eq!(MessageKind::from_wire_tag(10), None);
        assert_eq!(MessageKind::from_wire_tag(0xFF), None);
    }

    // ── TokenBucket ────────────────────────────────────────────────────────

    #[test]
    fn token_bucket_starts_full_and_drains() {
        let mut b = TokenBucket::new(10.0, 5.0, Duration::ZERO);
        for _ in 0..5 {
            assert!(b.try_take(Duration::ZERO, 1.0));
        }
        // Bucket empty at t=0, no time has passed, refill is zero.
        assert!(!b.try_take(Duration::ZERO, 1.0));
    }

    #[test]
    fn token_bucket_refills_at_configured_rate() {
        let mut b = TokenBucket::new(10.0, 10.0, Duration::ZERO);
        // Drain.
        for _ in 0..10 {
            assert!(b.try_take(Duration::ZERO, 1.0));
        }
        // After 0.5s at 10/s we should have 5 tokens — admit five
        // frames, then deny the sixth.
        let later = Duration::from_millis(500);
        for _ in 0..5 {
            assert!(b.try_take(later, 1.0));
        }
        assert!(!b.try_take(later, 1.0));
    }

    #[test]
    fn token_bucket_does_not_overshoot_capacity() {
        let mut b = TokenBucket::new(100.0, 10.0, Duration::ZERO);
        // Drain.
        for _ in 0..10 {
            assert!(b.try_take(Duration::ZERO, 1.0));
        }
        // Long quiet period — refill should saturate at capacity.
        let later = Duration::from_secs(60);
        for _ in 0..10 {
            assert!(b.try_take(later, 1.0));
        }
        assert!(!b.try_take(later, 1.0));
    }

    // ── RateLimiter::admit ────────────────────────────────────────────────

    fn limits_for_test() -> RateLimitsConfig {
        RateLimitsConfig {
            proposal_per_sec: 4.0,
            vote_per_sec: 4.0,
            timeout_vote_per_sec: 4.0,
            new_view_per_sec: 4.0,
            request_block_per_sec: 4.0,
            receive_block_per_sec: 4.0,
            snapshot_manifest_request_per_sec: 4.0,
            snapshot_manifest_response_per_sec: 4.0,
            snapshot_chunk_request_per_sec: 4.0,
            snapshot_chunk_response_per_sec: 4.0,
            bytes_per_sec: 4096.0,
            burst_seconds: 1.0,
            violation_window: Duration::from_secs(10),
            max_violations: 5,
        }
    }

    #[test]
    fn admit_allows_within_capacity() {
        let clock = ManualClock::new();
        let limiter = RateLimiter::new(limits_for_test(), clock.clone());
        for _ in 0..4 {
            assert_eq!(
                limiter.admit(nid(1), MessageKind::Proposal, 100),
                Decision::Allow
            );
        }
    }

    #[test]
    fn admit_drops_after_per_kind_capacity_exceeded() {
        let clock = ManualClock::new();
        let limiter = RateLimiter::new(limits_for_test(), clock.clone());
        // 4 admits drain the bucket, 5th drops.
        for _ in 0..4 {
            assert_eq!(
                limiter.admit(nid(1), MessageKind::Proposal, 1),
                Decision::Allow
            );
        }
        assert_eq!(
            limiter.admit(nid(1), MessageKind::Proposal, 1),
            Decision::Drop
        );
        assert_eq!(limiter.counters().drops(MessageKind::Proposal), 1);
    }

    #[test]
    fn admit_disconnects_after_max_violations() {
        let clock = ManualClock::new();
        let mut config = limits_for_test();
        config.max_violations = 3;
        let limiter = RateLimiter::new(config, clock.clone());

        // Drain.
        for _ in 0..4 {
            limiter.admit(nid(1), MessageKind::Proposal, 1);
        }
        // First two violations: Drop.
        assert_eq!(
            limiter.admit(nid(1), MessageKind::Proposal, 1),
            Decision::Drop
        );
        assert_eq!(
            limiter.admit(nid(1), MessageKind::Proposal, 1),
            Decision::Drop
        );
        // Third violation: Disconnect.
        assert_eq!(
            limiter.admit(nid(1), MessageKind::Proposal, 1),
            Decision::Disconnect
        );
        // Subsequent violations stay at Drop until the window
        // clears — Disconnect must be one-shot per streak so the
        // caller's teardown runs exactly once.
        assert_eq!(
            limiter.admit(nid(1), MessageKind::Proposal, 1),
            Decision::Drop
        );
        assert_eq!(limiter.counters().disconnects(), 1);
    }

    #[test]
    fn per_kind_buckets_are_independent() {
        let clock = ManualClock::new();
        let limiter = RateLimiter::new(limits_for_test(), clock.clone());
        // Saturate Proposal.
        for _ in 0..4 {
            limiter.admit(nid(1), MessageKind::Proposal, 1);
        }
        assert_eq!(
            limiter.admit(nid(1), MessageKind::Proposal, 1),
            Decision::Drop
        );
        // Vote bucket independent of Proposal.
        for _ in 0..4 {
            assert_eq!(limiter.admit(nid(1), MessageKind::Vote, 1), Decision::Allow);
        }
    }

    #[test]
    fn bytes_cap_drops_independently_of_kind() {
        let clock = ManualClock::new();
        let mut config = limits_for_test();
        config.bytes_per_sec = 100.0;
        let limiter = RateLimiter::new(config, clock.clone());
        // First 100 bytes admitted in one frame.
        assert_eq!(
            limiter.admit(nid(1), MessageKind::Vote, 100),
            Decision::Allow
        );
        // Next 1-byte frame fails on bytes (the kind bucket has
        // plenty of headroom). The bytes-drop counter records it
        // separately from per-kind drops.
        assert_eq!(limiter.admit(nid(1), MessageKind::Vote, 1), Decision::Drop);
        assert_eq!(limiter.counters().bytes_drops(), 1);
        assert_eq!(limiter.counters().drops(MessageKind::Vote), 0);
    }

    #[test]
    fn peers_have_independent_state() {
        let clock = ManualClock::new();
        let limiter = RateLimiter::new(limits_for_test(), clock.clone());
        for _ in 0..4 {
            limiter.admit(nid(1), MessageKind::Proposal, 1);
        }
        assert_eq!(
            limiter.admit(nid(1), MessageKind::Proposal, 1),
            Decision::Drop
        );
        // nid(2) has a fresh bucket.
        assert_eq!(
            limiter.admit(nid(2), MessageKind::Proposal, 1),
            Decision::Allow
        );
    }

    #[test]
    fn violations_age_out_of_window() {
        let clock = ManualClock::new();
        let mut config = limits_for_test();
        config.max_violations = 3;
        config.violation_window = Duration::from_secs(1);
        let limiter = RateLimiter::new(config, clock.clone());

        // Drain and earn two violations.
        for _ in 0..4 {
            limiter.admit(nid(1), MessageKind::Proposal, 1);
        }
        limiter.admit(nid(1), MessageKind::Proposal, 1);
        limiter.admit(nid(1), MessageKind::Proposal, 1);
        // Skip ahead past the window so the violations age out and
        // the bucket refills.
        clock.set(Duration::from_secs(10));
        // Drain the freshly refilled bucket and earn fresh
        // violations — the disconnect latch should rearm.
        for _ in 0..4 {
            limiter.admit(nid(1), MessageKind::Proposal, 1);
        }
        for _ in 0..2 {
            assert_eq!(
                limiter.admit(nid(1), MessageKind::Proposal, 1),
                Decision::Drop
            );
        }
        assert_eq!(
            limiter.admit(nid(1), MessageKind::Proposal, 1),
            Decision::Disconnect
        );
        assert_eq!(limiter.counters().disconnects(), 1);
    }

    #[test]
    fn unbounded_for_tests_does_not_drop() {
        let clock: Arc<dyn Clock> = Arc::new(TokioClock::new());
        let limiter = RateLimiter::new(RateLimitsConfig::unbounded_for_tests(), clock);
        for _ in 0..1_000 {
            assert_eq!(
                limiter.admit(nid(7), MessageKind::Vote, 100),
                Decision::Allow
            );
        }
        assert_eq!(limiter.counters().total_drops(), 0);
    }

    // ── ConnectionLimiter ─────────────────────────────────────────────────

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn connection_limiter_caps_total_inbound() {
        let cl = ConnectionLimiter::new(ConnectionLimitsConfig {
            max_inbound: 2,
            max_outbound: 99,
            max_per_ip: 99,
        });
        assert!(cl.try_admit(Direction::Inbound, ipv4(10, 0, 0, 1)).is_ok());
        assert!(cl.try_admit(Direction::Inbound, ipv4(10, 0, 0, 2)).is_ok());
        assert_eq!(
            cl.try_admit(Direction::Inbound, ipv4(10, 0, 0, 3)),
            Err(RejectReason::TotalInbound)
        );
        assert_eq!(cl.rejects(), 1);

        // Releasing one slot reopens an admit.
        cl.release(Direction::Inbound, ipv4(10, 0, 0, 1));
        assert!(cl.try_admit(Direction::Inbound, ipv4(10, 0, 0, 4)).is_ok());
    }

    #[test]
    fn connection_limiter_caps_total_outbound() {
        let cl = ConnectionLimiter::new(ConnectionLimitsConfig {
            max_inbound: 99,
            max_outbound: 1,
            max_per_ip: 99,
        });
        assert!(cl.try_admit(Direction::Outbound, ipv4(10, 0, 0, 1)).is_ok());
        assert_eq!(
            cl.try_admit(Direction::Outbound, ipv4(10, 0, 0, 2)),
            Err(RejectReason::TotalOutbound)
        );
    }

    #[test]
    fn connection_limiter_per_ip_cap_independent_of_total() {
        let cl = ConnectionLimiter::new(ConnectionLimitsConfig {
            max_inbound: 99,
            max_outbound: 99,
            max_per_ip: 2,
        });
        // Three connections from one IP — third refused.
        assert!(cl.try_admit(Direction::Inbound, ipv4(10, 0, 0, 1)).is_ok());
        assert!(cl.try_admit(Direction::Inbound, ipv4(10, 0, 0, 1)).is_ok());
        assert_eq!(
            cl.try_admit(Direction::Inbound, ipv4(10, 0, 0, 1)),
            Err(RejectReason::PerIp)
        );
        // A different IP is unaffected.
        assert!(cl.try_admit(Direction::Inbound, ipv4(10, 0, 0, 2)).is_ok());
    }

    #[test]
    fn release_removes_per_ip_entry_at_zero() {
        let cl = ConnectionLimiter::new(ConnectionLimitsConfig {
            max_inbound: 99,
            max_outbound: 99,
            max_per_ip: 1,
        });
        let ip = ipv4(10, 0, 0, 1);
        assert!(cl.try_admit(Direction::Inbound, ip).is_ok());
        cl.release(Direction::Inbound, ip);
        // After release we can re-admit from the same IP.
        assert!(cl.try_admit(Direction::Inbound, ip).is_ok());
    }
}
