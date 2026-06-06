//! Per-peer rate limiting and connection caps for the p2p layer
//! (issue #134; egress cap added in #553).
//!
//! Two independent limiters live here:
//!
//! - [`RateLimiter`] enforces per-peer token buckets keyed by a
//!   [`RateLimitKind`] (one bucket per message kind), a per-peer
//!   **inbound** wire-bytes/sec cap, and a per-peer **outbound**
//!   wire-bytes/sec cap (#553). It is generic over the kind taxonomy
//!   `K`; the concrete consensus taxonomy (`boule_consensus`'s
//!   `MessageKind`, mirroring the wire schema) is supplied by the
//!   consensus layer, which classifies an inbound frame's first byte
//!   into a kind, asks [`RateLimiter::admit`], and either drops or
//!   dispatches based on the [`Decision`]. After K violations within a
//!   sliding window of W seconds, [`Decision::Disconnect`] is returned
//!   exactly once per peer — the caller is responsible for tearing down
//!   the connection (typically by sending
//!   `boule_transport_tcp::PeerCommand::Disconnect`). On egress, every
//!   directed frame is charged against the recipient peer's outbound
//!   bucket via [`RateLimiter::admit_outbound`]; on overflow the caller
//!   skips the send. The outbound cap defends against the
//!   request/response amplification vector where a Byzantine peer sends
//!   tiny range-requests at low ingress cost and pulls hundreds of KB of
//!   range-responses out of the responder per request.
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
//! Time is taken from an [`Arc<dyn Clock>`] (monotonic), so a virtual
//! `SimClock` drives the rate-limiter under virtual time exactly like
//! in production.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use parking_lot::Mutex;

use crate::clock::Clock;
use crate::identity::NodeId;

// ── RateLimitKind ────────────────────────────────────────────────────────────

/// A message-kind taxonomy the [`RateLimiter`] buckets traffic by.
///
/// Implementors supply a dense `0..N` index for array-backed per-kind
/// storage and a stable label for logs. The concrete consensus taxonomy
/// — `boule_consensus`'s `MessageKind`, which mirrors the `WireMessage`
/// postcard tags — lives next to that wire schema, so this foundational
/// crate stays free of higher-layer message definitions: the rate
/// limiter is generic over whatever kind enum its owner supplies.
pub trait RateLimitKind: Copy + Eq + std::hash::Hash + 'static {
    /// Every kind, in [`index`](RateLimitKind::index) order. Its length
    /// sizes the per-kind bucket and counter arrays, so it must be
    /// stable for a given `Self` and the returned `index()` values must
    /// densely cover `0..all().len()`.
    fn all() -> &'static [Self];

    /// Dense index in `0..all().len()` for array-backed per-kind storage.
    fn index(self) -> usize;

    /// Stable short label for log fields.
    fn label(self) -> &'static str;
}

// ── TokenBucket ──────────────────────────────────────────────────────────────

/// Continuous-time token bucket. Refills at `rate_per_sec` up to
/// `capacity`; `try_take(now, n)` consumes `n` tokens iff at least
/// `n` are available after the lazy refill.
///
/// Safe to construct with `rate_per_sec == capacity == 0.0`, which
/// permanently denies; with `rate_per_sec == f64::INFINITY` or any
/// huge number, the bucket effectively never empties (the shape a
/// test "unbounded" config uses to disable rate limiting).
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

/// Plain-data configuration for [`RateLimiter`]. Rates are in
/// units-per-second; the burst capacity is `rate × burst_seconds` so a
/// peer can spike for a short window without tripping the limit.
///
/// The per-kind rates live in `per_kind_per_sec`, indexed by
/// [`RateLimitKind::index`] — slot `i` is the steady-state rate for the
/// kind whose `index()` is `i`. The owner of the concrete kind enum
/// (the consensus crate) builds this vector from its named
/// `[p2p.limits.rate]` config; this crate never names a concrete kind.
#[derive(Debug, Clone)]
pub struct RateLimitsConfig {
    /// Per-kind steady-state rates (units/sec), indexed by
    /// [`RateLimitKind::index`]. Length must equal `K::all().len()` for
    /// the `K` the [`RateLimiter`] is built with.
    pub per_kind_per_sec: Vec<f64>,
    /// Per-peer inbound wire-bytes/sec ceiling, applied independently of
    /// the per-kind buckets so a flood of any one kind that fits within
    /// its bucket can still be dropped on bytes alone.
    pub bytes_per_sec: f64,
    /// Per-peer outbound wire-bytes/sec ceiling (#553). Symmetric to
    /// [`Self::bytes_per_sec`] but charged on egress: every directed
    /// frame the node hands to the transport is consulted against the
    /// recipient peer's outbound bucket. Defends against the
    /// request/response amplification vector where a Byzantine peer
    /// sends tiny range-requests at low ingress cost and pulls hundreds
    /// of KB of range-responses out of the responder per request — the
    /// ingress bucket sees only the cheap requests while egress goes
    /// uncapped.
    pub outbound_bytes_per_sec: f64,
    /// Burst window in seconds; capacity for each bucket is
    /// `rate × burst_seconds`.
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
    /// Capacity for the per-kind bucket at `index`. Capacity = rate ×
    /// burst_seconds, floored at 1 token so a bucket whose configured
    /// rate is < 1/burst_seconds still admits a single message rather
    /// than refusing every one.
    fn bucket_capacity(&self, index: usize) -> f64 {
        (self.per_kind_per_sec[index] * self.burst_seconds).max(1.0)
    }

    fn bytes_capacity(&self) -> f64 {
        (self.bytes_per_sec * self.burst_seconds).max(1.0)
    }

    fn outbound_bytes_capacity(&self) -> f64 {
        (self.outbound_bytes_per_sec * self.burst_seconds).max(1.0)
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

/// Atomic per-kind drop counters plus global byte / disconnect
/// counters. Cheap to clone (the inner state is shared via `Arc`).
///
/// Per-kind drops are read via [`drops`](Self::drops), keyed by the
/// kind's [`RateLimitKind::index`].
#[derive(Debug, Clone)]
pub struct RateLimitCounters {
    inner: Arc<RateLimitCountersInner>,
}

#[derive(Debug)]
struct RateLimitCountersInner {
    /// One drop counter per kind, indexed by [`RateLimitKind::index`].
    by_kind: Vec<AtomicU64>,
    bytes: AtomicU64,
    outbound_bytes: AtomicU64,
    disconnects: AtomicU64,
}

impl RateLimitCounters {
    /// Build counters for a taxonomy of `kind_count` kinds.
    fn with_kinds(kind_count: usize) -> Self {
        Self {
            inner: Arc::new(RateLimitCountersInner {
                by_kind: (0..kind_count).map(|_| AtomicU64::new(0)).collect(),
                bytes: AtomicU64::new(0),
                outbound_bytes: AtomicU64::new(0),
                disconnects: AtomicU64::new(0),
            }),
        }
    }

    /// Cumulative drops for the kind at `kind_index`
    /// ([`RateLimitKind::index`]). Returns 0 for an out-of-range index.
    pub fn drops(&self, kind_index: usize) -> u64 {
        self.inner
            .by_kind
            .get(kind_index)
            .map_or(0, |c| c.load(Ordering::Relaxed))
    }

    /// Total drops across every message kind.
    pub fn total_drops(&self) -> u64 {
        self.inner
            .by_kind
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .sum::<u64>()
            .saturating_add(self.bytes_drops())
    }

    /// Cumulative drops attributed to the bytes/sec cap (independent
    /// of the per-kind buckets).
    pub fn bytes_drops(&self) -> u64 {
        self.inner.bytes.load(Ordering::Relaxed)
    }

    /// Cumulative drops attributed to the outbound bytes/sec cap (#553).
    /// Each increment is one egress frame the limiter declined to hand
    /// to the transport because the recipient peer's outbound bucket
    /// was empty — typically a fat range-response the responder skipped
    /// to stop a Byzantine peer from amplifying tiny requests into
    /// hundreds of KB/sec of egress.
    pub fn outbound_drops_total(&self) -> u64 {
        self.inner.outbound_bytes.load(Ordering::Relaxed)
    }

    /// Cumulative `Decision::Disconnect` returns.
    pub fn disconnects(&self) -> u64 {
        self.inner.disconnects.load(Ordering::Relaxed)
    }

    fn inc_drops(&self, kind_index: usize) {
        if let Some(c) = self.inner.by_kind.get(kind_index) {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn inc_bytes(&self) {
        self.inner.bytes.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_outbound_bytes(&self) {
        self.inner.outbound_bytes.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_disconnects(&self) {
        self.inner.disconnects.fetch_add(1, Ordering::Relaxed);
    }
}

// ── PeerState + RateLimiter ──────────────────────────────────────────────────

struct PeerState {
    /// One token bucket per kind, indexed by [`RateLimitKind::index`].
    /// Length equals the config's `per_kind_per_sec.len()`.
    buckets: Vec<TokenBucket>,
    bytes_bucket: TokenBucket,
    /// Per-peer egress bytes/sec ceiling (#553). Independent of
    /// `bytes_bucket` so the inbound-vs-outbound budgets do not
    /// cross-contaminate — a peer that floods cheap requests cannot
    /// drain its own ingress budget AND our egress budget out of the
    /// same pool.
    outbound_bytes_bucket: TokenBucket,
    /// Monotonic instants of recent violations, oldest first.
    violations: VecDeque<Duration>,
    /// True after the limiter returned [`Decision::Disconnect`] once
    /// for this peer; suppresses repeats until violations age out of
    /// the window.
    disconnect_dispatched: bool,
}

impl PeerState {
    fn new(config: &RateLimitsConfig, now: Duration) -> Self {
        let buckets = config
            .per_kind_per_sec
            .iter()
            .enumerate()
            .map(|(i, &rate)| TokenBucket::new(rate, config.bucket_capacity(i), now))
            .collect();
        Self {
            buckets,
            bytes_bucket: TokenBucket::new(config.bytes_per_sec, config.bytes_capacity(), now),
            outbound_bytes_bucket: TokenBucket::new(
                config.outbound_bytes_per_sec,
                config.outbound_bytes_capacity(),
                now,
            ),
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
pub struct RateLimiter<K: RateLimitKind> {
    config: RateLimitsConfig,
    state: Mutex<HashMap<NodeId, PeerState>>,
    clock: Arc<dyn Clock>,
    counters: RateLimitCounters,
    _kind: std::marker::PhantomData<fn() -> K>,
}

impl<K: RateLimitKind> RateLimiter<K> {
    /// Construct a rate limiter from `config`. The supplied [`Clock`]
    /// drives the bucket refill timestamps; pass the consensus
    /// node's clock so the limiter and the pacemaker share a time
    /// base under virtual-clock tests.
    ///
    /// # Panics
    ///
    /// Panics if `config.per_kind_per_sec.len() != K::all().len()` — the
    /// per-kind rate vector must have exactly one entry per kind.
    pub fn new(config: RateLimitsConfig, clock: Arc<dyn Clock>) -> Self {
        assert_eq!(
            config.per_kind_per_sec.len(),
            K::all().len(),
            "RateLimitsConfig.per_kind_per_sec length must equal the kind count",
        );
        let counters = RateLimitCounters::with_kinds(K::all().len());
        Self {
            config,
            state: Mutex::new(HashMap::new()),
            clock,
            counters,
            _kind: std::marker::PhantomData,
        }
    }

    /// Decide whether to admit, drop, or disconnect a freshly
    /// received frame from `peer`. `bytes_len` is the on-wire frame
    /// length (after framing strips the protocol-tag prefix); it is
    /// charged against the bytes/sec cap independently of the per-
    /// kind bucket.
    pub fn admit(&self, peer: NodeId, kind: K, bytes_len: usize) -> Decision {
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
        let kind_admitted = peer_state.buckets[kind.index()].try_take(now, 1.0);
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
            peer_state.buckets[kind.index()].tokens += 1.0;
        }
        if bytes_admitted && !kind_admitted {
            peer_state.bytes_bucket.tokens += bytes_len as f64;
        }

        peer_state.violations.push_back(now);

        if !kind_admitted {
            self.counters.inc_drops(kind.index());
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

    /// Decide whether to admit or drop an outbound frame addressed to
    /// `peer` (#553). `bytes_len` is charged against the recipient
    /// peer's `outbound_bytes_bucket`; on overflow the caller skips
    /// the send and the [`RateLimitCounters::outbound_drops_total`]
    /// counter is incremented.
    ///
    /// Returns either [`Decision::Allow`] or [`Decision::Drop`]; the
    /// outbound path never returns [`Decision::Disconnect`] because
    /// dropping our own outbound frames does not warrant tearing down
    /// the connection — the inbound limiter is the canonical
    /// disconnect trigger.
    ///
    /// Dropping a directed response (e.g. a bulk range-response) is safe
    /// under the existing protocol: the requester's inflight/timeout
    /// state machine treats the silence identically to a packet loss
    /// event and re-requests on its own cadence.
    pub fn admit_outbound(&self, peer: NodeId, bytes_len: usize) -> Decision {
        let now = self.clock.now_monotonic();
        let mut state = self.state.lock();
        let peer_state = state
            .entry(peer)
            .or_insert_with(|| PeerState::new(&self.config, now));
        if peer_state
            .outbound_bytes_bucket
            .try_take(now, bytes_len as f64)
        {
            Decision::Allow
        } else {
            self.counters.inc_outbound_bytes();
            Decision::Drop
        }
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
/// `boule_transport_tcp::manager::ManagerMsg::NewConnection` so the manager
/// can charge the right bucket in [`ConnectionLimiter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Connection arrived via `boule_transport_tcp::listener::run` — count
    /// against `max_inbound`.
    Inbound,
    /// Connection arrived via `boule_transport_tcp::dialer::reconnect_loop` —
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
    /// Hard ceiling on total registered connections regardless of
    /// direction (#187 / `[overlay].total_max`). Set to `usize::MAX`
    /// to disable. Acts as a safety net above `max_inbound +
    /// max_outbound` so a misconfigured operator cannot accidentally
    /// admit more direct peers than the overlay was sized for.
    pub max_total: usize,
}

impl ConnectionLimitsConfig {
    /// Project the parsed `[p2p.limits]` connection-cap fields into the
    /// runtime shape. The overlay-layer `max_total` cap (#187) is not
    /// sourced from `[p2p.limits]`; callers that want the merged view
    /// (combining `[overlay].total_max`) build the runtime config in
    /// the node wiring's `build_connection_limiter`.
    pub fn from_config(c: &crate::config::P2pLimitsConfig) -> Self {
        Self {
            max_inbound: c.max_inbound_connections,
            max_outbound: c.max_outbound_connections,
            max_per_ip: c.max_connections_per_ip,
            max_total: usize::MAX,
        }
    }

    /// Defaults baked into the binary when the operator omits
    /// `[p2p.limits]` connection caps. Sized for **public exposure** as
    /// part of the MVP-public-testnet work (#805): a validator runs a
    /// small trusted committee but the listener now also fronts an
    /// open population of non-validating full/RPC nodes (#802), so the
    /// inbound ceiling is raised an order of magnitude over the old
    /// "~dozen-validator cluster" sizing (`max_inbound: 64`).
    ///
    /// - `max_inbound: 512` — room for a few hundred follower nodes to
    ///   subscribe to gossip + sync without the cap firing on honest
    ///   demand. The per-connection memory cost (one framing task + two
    ///   bounded channels) is small, and the in-flight handshake bound
    ///   ([`HandshakeLimitsConfig`]) — not this number — is what caps
    ///   pre-admission resource use under a flood.
    /// - `max_outbound: 64` — a node still only *dials* its configured
    ///   peer set + bootstrap; outbound fan-out is not driven by the
    ///   public population, so this stays at the cluster sizing.
    /// - `max_per_ip: 8` — a single source IP (e.g. a NAT fronting a
    ///   couple of honest nodes, or a load balancer) gets a little
    ///   headroom, but not enough for one address to monopolise the
    ///   inbound budget. The pre-handshake per-IP guard
    ///   ([`HandshakeLimitsConfig::max_inflight_per_ip`]) backstops this
    ///   *before* the handshake completes.
    pub fn production_defaults() -> Self {
        Self {
            max_inbound: 512,
            max_outbound: 64,
            max_per_ip: 8,
            // No total cap by default at the `[p2p.limits]` layer; the
            // overlay-layer cap from #187 lands a tighter limit when
            // it's plumbed through `node.rs`.
            max_total: usize::MAX,
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
            max_total: usize::MAX,
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
    /// `max_total` (overlay total ceiling, #187) is saturated.
    Total,
}

impl RejectReason {
    /// Stable short label for log fields.
    pub fn label(self) -> &'static str {
        match self {
            Self::TotalInbound => "max_inbound",
            Self::TotalOutbound => "max_outbound",
            Self::PerIp => "max_per_ip",
            Self::Total => "max_total",
        }
    }
}

/// Global connection caps. Stored in the manager and consulted on
/// every `boule_transport_tcp::manager::ManagerMsg::NewConnection`.
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

    /// Like [`Self::try_admit`], but bypasses the inbound caps for an
    /// *unconditional* peer (sentry-topology, #827).
    ///
    /// When `node_id` is present and listed in `unconditional`, an
    /// **inbound** connection is registered unconditionally — the
    /// per-IP, total, and per-direction inbound caps are skipped — so a
    /// validator↔sentry link is always accepted regardless of load (cf.
    /// Tendermint `unconditional_peer_ids`). The slot is still counted
    /// (so a later [`Self::release`] balances) but never refused.
    /// Outbound connections, and connections whose peer is not in the
    /// set, fall through to the normal [`Self::try_admit`] caps.
    pub fn try_admit_peer(
        &self,
        direction: Direction,
        ip: IpAddr,
        node_id: Option<&NodeId>,
        unconditional: &HashSet<NodeId>,
    ) -> Result<(), RejectReason> {
        let is_unconditional = matches!(direction, Direction::Inbound)
            && node_id.is_some_and(|id| unconditional.contains(id));
        if is_unconditional {
            // Register the slot without consulting any cap. Both
            // increments happen under the per-IP mutex to match the
            // accounting discipline of `try_admit`.
            let mut per_ip = self.per_ip.lock();
            self.inbound.fetch_add(1, Ordering::AcqRel);
            *per_ip.entry(ip).or_insert(0) += 1;
            return Ok(());
        }
        self.try_admit(direction, ip)
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

        // Total ceiling (#187). Checked before the per-direction caps
        // so an inbound admit doesn't briefly bump the counter past
        // `max_total` even if the per-direction cap would have caught
        // it on its own.
        let inbound_cur = self.inbound.load(Ordering::Acquire);
        let outbound_cur = self.outbound.load(Ordering::Acquire);
        if inbound_cur.saturating_add(outbound_cur) >= self.config.max_total {
            self.rejects.fetch_add(1, Ordering::Relaxed);
            return Err(RejectReason::Total);
        }

        match direction {
            Direction::Inbound => {
                if inbound_cur >= self.config.max_inbound {
                    self.rejects.fetch_add(1, Ordering::Relaxed);
                    return Err(RejectReason::TotalInbound);
                }
                // Both increments under the per-IP mutex so we don't
                // race past the cap with a parallel admit.
                self.inbound.fetch_add(1, Ordering::AcqRel);
            }
            Direction::Outbound => {
                if outbound_cur >= self.config.max_outbound {
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

    /// Currently registered connections in either direction. Counts
    /// against `max_total` (#187).
    pub fn total(&self) -> usize {
        self.inbound().saturating_add(self.outbound())
    }
}

// ── HandshakeLimiter ─────────────────────────────────────────────────────────

/// Pre-admission bounds on in-flight (un-admitted) inbound TLS
/// handshakes (#805).
///
/// The [`ConnectionLimiter`] above is charged only **after** a
/// handshake completes and a [`Direction::Inbound`] `NewConnection` is
/// registered. That leaves a window — accept the TCP socket, run the
/// TLS handshake — that is entirely **un**-bounded: a slowloris-style
/// flood of half-open TLS handshakes from many source IPs spawns one
/// accept task each and pins kernel sockets + handshake buffers without
/// ever tripping the post-admission caps. This limiter closes that hole
/// by bounding the number of handshakes the listener will run
/// concurrently, both globally and per source IP, **before** any TLS
/// work begins. Paired with a wall-clock handshake timeout in the
/// listener, a half-open peer can hold a handshake slot for at most
/// `timeout`, so the flood's steady-state resource use is bounded by
/// `max_inflight` regardless of how many IPs participate.
#[derive(Debug, Clone)]
pub struct HandshakeLimitsConfig {
    /// Maximum inbound handshakes running concurrently across all
    /// source IPs. A flood can pin at most this many accept tasks at
    /// once; once the budget is full the listener *refuses* further
    /// accepts outright (drops the socket without running TLS) rather
    /// than queueing them, so a flood cannot build an unbounded backlog
    /// of pending handshakes. Set to `usize::MAX` to disable.
    pub max_inflight: usize,
    /// Maximum concurrent in-flight handshakes from a single source IP.
    /// Fires *before* the TLS handshake runs, so one address cannot
    /// monopolise the global `max_inflight` budget with half-open
    /// handshakes. Set to `usize::MAX` to disable per-IP counting.
    pub max_inflight_per_ip: usize,
    /// Wall-clock ceiling on a single inbound TLS handshake. The
    /// listener wraps `acceptor.accept(..)` in this timeout; a peer
    /// that stalls mid-handshake (slowloris) is dropped at the deadline
    /// and its handshake slot freed. Applied by the listener, carried
    /// here so the bound and its budget live in one config.
    pub timeout: Duration,
}

impl HandshakeLimitsConfig {
    /// Public-exposure defaults (#805). `max_inflight` is generous
    /// enough that a burst of honest reconnects (e.g. after a leader
    /// rotation, every follower redials) clears quickly, while still
    /// being a hard ceiling a flood cannot exceed. `max_inflight_per_ip`
    /// is tight: an honest peer completes a handshake in well under a
    /// second, so even a NAT fronting several nodes rarely has more than
    /// a couple in flight at once. The 10s `timeout` is comfortably
    /// above a real TLS round-trip on a slow link yet short enough that
    /// a slowloris peer cannot pin a slot for long.
    pub fn production_defaults() -> Self {
        Self {
            max_inflight: 256,
            max_inflight_per_ip: 4,
            timeout: Duration::from_secs(10),
        }
    }

    /// Permissive defaults that effectively disable the handshake bound
    /// — used by the simulator and tests where it is not under
    /// assertion.
    pub fn unbounded_for_tests() -> Self {
        Self {
            max_inflight: usize::MAX,
            max_inflight_per_ip: usize::MAX,
            // A very long timeout never fires in a fast test; the
            // handshake-timeout tests construct their own short value.
            timeout: Duration::from_secs(3600),
        }
    }
}

/// Outcome of a refused [`HandshakeLimiter::try_acquire`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeReject {
    /// Global `max_inflight` is saturated.
    TotalInflight,
    /// `max_inflight_per_ip` is saturated for the connection's IP.
    PerIpInflight,
}

impl HandshakeReject {
    /// Stable short label for log fields.
    pub fn label(self) -> &'static str {
        match self {
            Self::TotalInflight => "max_inflight",
            Self::PerIpInflight => "max_inflight_per_ip",
        }
    }
}

/// Counts in-flight inbound handshakes globally and per source IP, and
/// hands out an RAII [`HandshakePermit`] that releases its slot on drop.
/// One instance is shared by the listener across all accept tasks.
pub struct HandshakeLimiter {
    config: HandshakeLimitsConfig,
    inflight: AtomicUsize,
    per_ip: Mutex<HashMap<IpAddr, usize>>,
    rejects: AtomicU64,
}

impl HandshakeLimiter {
    /// Construct a handshake limiter from `config`.
    pub fn new(config: HandshakeLimitsConfig) -> Self {
        Self {
            config,
            inflight: AtomicUsize::new(0),
            per_ip: Mutex::new(HashMap::new()),
            rejects: AtomicU64::new(0),
        }
    }

    /// The configured handshake wall-clock timeout — the listener reads
    /// this to bound a single `acceptor.accept(..)`.
    pub fn timeout(&self) -> Duration {
        self.config.timeout
    }

    /// Try to reserve a handshake slot for an inbound connection from
    /// `ip`. On success returns a [`HandshakePermit`] whose `Drop`
    /// releases the slot — the listener holds it for the duration of the
    /// (timed) handshake. On failure the reject counter is incremented
    /// and the caller drops the socket without running TLS.
    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Result<HandshakePermit, HandshakeReject> {
        // Per-IP first so a single source can't drive the global counter
        // up to its ceiling on its own. The lock guards both the read
        // and the increment so concurrent accepts can't race past it.
        let mut per_ip = self.per_ip.lock();
        let ip_count = per_ip.get(&ip).copied().unwrap_or(0);
        if ip_count >= self.config.max_inflight_per_ip {
            self.rejects.fetch_add(1, Ordering::Relaxed);
            return Err(HandshakeReject::PerIpInflight);
        }
        if self.inflight.load(Ordering::Acquire) >= self.config.max_inflight {
            self.rejects.fetch_add(1, Ordering::Relaxed);
            return Err(HandshakeReject::TotalInflight);
        }
        self.inflight.fetch_add(1, Ordering::AcqRel);
        *per_ip.entry(ip).or_insert(0) += 1;
        Ok(HandshakePermit {
            limiter: Arc::clone(self),
            ip,
        })
    }

    fn release(&self, ip: IpAddr) {
        self.inflight
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |c| {
                Some(c.saturating_sub(1))
            })
            .ok();
        let mut per_ip = self.per_ip.lock();
        if let Some(c) = per_ip.get_mut(&ip) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                per_ip.remove(&ip);
            }
        }
    }

    /// Cumulative `try_acquire` rejections (pre-handshake floods).
    pub fn rejects(&self) -> u64 {
        self.rejects.load(Ordering::Relaxed)
    }

    /// Handshakes currently in flight (acquired but not yet released).
    pub fn inflight(&self) -> usize {
        self.inflight.load(Ordering::Relaxed)
    }
}

/// RAII permit for one in-flight handshake. Releasing on `Drop` means
/// the slot is freed on **every** exit path — handshake success, TLS
/// error, *and* the timeout branch — without the listener having to
/// remember to release explicitly.
pub struct HandshakePermit {
    limiter: Arc<HandshakeLimiter>,
    ip: IpAddr,
}

impl Drop for HandshakePermit {
    fn drop(&mut self) {
        self.limiter.release(self.ip);
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

    /// A small kind taxonomy for exercising the generic limiter in
    /// isolation. The concrete `MessageKind` (mirroring the wire schema)
    /// lives in the consensus crate; three distinct kinds is enough to
    /// test per-kind bucket independence here.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    enum TestKind {
        A,
        B,
        C,
    }

    impl RateLimitKind for TestKind {
        fn all() -> &'static [Self] {
            &[TestKind::A, TestKind::B, TestKind::C]
        }
        fn index(self) -> usize {
            self as usize
        }
        fn label(self) -> &'static str {
            match self {
                TestKind::A => "A",
                TestKind::B => "B",
                TestKind::C => "C",
            }
        }
    }

    #[test]
    fn connection_limits_from_config_projects_p2p_limits() {
        let cfg = crate::config::P2pLimitsConfig::default();
        let conn = ConnectionLimitsConfig::from_config(&cfg);
        assert_eq!(conn.max_inbound, cfg.max_inbound_connections);
        assert_eq!(conn.max_outbound, cfg.max_outbound_connections);
        assert_eq!(conn.max_per_ip, cfg.max_connections_per_ip);
        assert_eq!(conn.max_total, usize::MAX);
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
            per_kind_per_sec: vec![4.0; TestKind::all().len()],
            bytes_per_sec: 4096.0,
            outbound_bytes_per_sec: 4096.0,
            burst_seconds: 1.0,
            violation_window: Duration::from_secs(10),
            max_violations: 5,
        }
    }

    #[test]
    fn admit_allows_within_capacity() {
        let clock = ManualClock::new();
        let limiter = RateLimiter::<TestKind>::new(limits_for_test(), clock.clone());
        for _ in 0..4 {
            assert_eq!(limiter.admit(nid(1), TestKind::A, 100), Decision::Allow);
        }
    }

    #[test]
    fn admit_drops_after_per_kind_capacity_exceeded() {
        let clock = ManualClock::new();
        let limiter = RateLimiter::<TestKind>::new(limits_for_test(), clock.clone());
        // 4 admits drain the bucket, 5th drops.
        for _ in 0..4 {
            assert_eq!(limiter.admit(nid(1), TestKind::A, 1), Decision::Allow);
        }
        assert_eq!(limiter.admit(nid(1), TestKind::A, 1), Decision::Drop);
        assert_eq!(limiter.counters().drops(TestKind::A.index()), 1);
    }

    #[test]
    fn admit_disconnects_after_max_violations() {
        let clock = ManualClock::new();
        let mut config = limits_for_test();
        config.max_violations = 3;
        let limiter = RateLimiter::<TestKind>::new(config, clock.clone());

        // Drain.
        for _ in 0..4 {
            limiter.admit(nid(1), TestKind::A, 1);
        }
        // First two violations: Drop.
        assert_eq!(limiter.admit(nid(1), TestKind::A, 1), Decision::Drop);
        assert_eq!(limiter.admit(nid(1), TestKind::A, 1), Decision::Drop);
        // Third violation: Disconnect.
        assert_eq!(limiter.admit(nid(1), TestKind::A, 1), Decision::Disconnect);
        // Subsequent violations stay at Drop until the window
        // clears — Disconnect must be one-shot per streak so the
        // caller's teardown runs exactly once.
        assert_eq!(limiter.admit(nid(1), TestKind::A, 1), Decision::Drop);
        assert_eq!(limiter.counters().disconnects(), 1);
    }

    #[test]
    fn per_kind_buckets_are_independent() {
        let clock = ManualClock::new();
        let limiter = RateLimiter::<TestKind>::new(limits_for_test(), clock.clone());
        // Saturate Proposal.
        for _ in 0..4 {
            limiter.admit(nid(1), TestKind::A, 1);
        }
        assert_eq!(limiter.admit(nid(1), TestKind::A, 1), Decision::Drop);
        // Vote bucket independent of Proposal.
        for _ in 0..4 {
            assert_eq!(limiter.admit(nid(1), TestKind::B, 1), Decision::Allow);
        }
    }

    #[test]
    fn bytes_cap_drops_independently_of_kind() {
        let clock = ManualClock::new();
        let mut config = limits_for_test();
        config.bytes_per_sec = 100.0;
        let limiter = RateLimiter::<TestKind>::new(config, clock.clone());
        // First 100 bytes admitted in one frame.
        assert_eq!(limiter.admit(nid(1), TestKind::B, 100), Decision::Allow);
        // Next 1-byte frame fails on bytes (the kind bucket has
        // plenty of headroom). The bytes-drop counter records it
        // separately from per-kind drops.
        assert_eq!(limiter.admit(nid(1), TestKind::B, 1), Decision::Drop);
        assert_eq!(limiter.counters().bytes_drops(), 1);
        assert_eq!(limiter.counters().drops(TestKind::B.index()), 0);
    }

    /// #553 acceptance: a tiny outbound budget drains after a single
    /// over-cap response and the limiter returns `Decision::Drop` on
    /// subsequent egress; budget refills with time.
    #[test]
    fn admit_outbound_drains_then_refills() {
        let clock = ManualClock::new();
        let mut config = limits_for_test();
        config.outbound_bytes_per_sec = 100.0;
        let limiter = RateLimiter::<TestKind>::new(config, clock.clone());

        // First 100 bytes admitted.
        assert_eq!(limiter.admit_outbound(nid(1), 100), Decision::Allow);
        // Bucket empty — next byte denied.
        assert_eq!(limiter.admit_outbound(nid(1), 1), Decision::Drop);
        assert_eq!(limiter.counters().outbound_drops_total(), 1);
        // Per-kind / inbound-bytes counters are not touched.
        assert_eq!(limiter.counters().bytes_drops(), 0);

        // Refill: 1 second at 100 B/s rate brings the bucket back.
        clock.set(Duration::from_secs(1));
        assert_eq!(limiter.admit_outbound(nid(1), 100), Decision::Allow);
    }

    /// #553 acceptance: outbound bucket is independent of the inbound
    /// bytes bucket — a peer that drains its ingress budget by sending
    /// large frames still has its outbound bucket intact, and vice
    /// versa.
    #[test]
    fn admit_outbound_independent_of_inbound_bytes_bucket() {
        let clock = ManualClock::new();
        let mut config = limits_for_test();
        config.bytes_per_sec = 100.0;
        config.outbound_bytes_per_sec = 100.0;
        let limiter = RateLimiter::<TestKind>::new(config, clock.clone());

        // Drain inbound bytes by ingressing 100 bytes.
        assert_eq!(limiter.admit(nid(1), TestKind::B, 100), Decision::Allow);
        // Outbound budget is still full.
        assert_eq!(limiter.admit_outbound(nid(1), 100), Decision::Allow);
        // Both buckets now drained — inbound-byte and outbound-byte
        // drops increment independently.
        assert_eq!(limiter.admit(nid(1), TestKind::B, 1), Decision::Drop);
        assert_eq!(limiter.admit_outbound(nid(1), 1), Decision::Drop);
        assert_eq!(limiter.counters().bytes_drops(), 1);
        assert_eq!(limiter.counters().outbound_drops_total(), 1);
    }

    /// #553: a Byzantine peer sending tiny inbound `BlockRangeRequest`s
    /// at low ingress cost cannot pull more egress out of the responder
    /// than `outbound_bytes_per_sec` allows. Models the responder's
    /// per-peer outbound bucket directly: simulate one cheap request
    /// (16 bytes ingress) eliciting a fat response (8 KB egress) and
    /// assert the response budget bounds total egress to roughly the
    /// configured cap regardless of how many requests arrive.
    #[test]
    fn admit_outbound_bounds_block_range_amplification() {
        let clock = ManualClock::new();
        let mut config = limits_for_test();
        // 16 KiB/sec outbound budget — large enough to admit two 8 KiB
        // responses per second, the third drops.
        config.outbound_bytes_per_sec = 16_384.0;
        // Generous inbound buckets so the request side never trips.
        config.bytes_per_sec = 1.0e9;
        config.per_kind_per_sec[TestKind::C.index()] = 1_000.0;
        let limiter = RateLimiter::<TestKind>::new(config, clock.clone());
        let attacker = nid(7);

        // Attacker sends 100 cheap range requests; ingress admits all.
        for _ in 0..100 {
            assert_eq!(limiter.admit(attacker, TestKind::C, 16), Decision::Allow);
        }
        // Responder tries to serve each at 8 KiB; the first two pass
        // (16 KiB capacity at t=0), the rest are dropped at the
        // outbound cap.
        let response_bytes = 8 * 1024;
        let mut admitted = 0u64;
        let mut dropped = 0u64;
        for _ in 0..100 {
            match limiter.admit_outbound(attacker, response_bytes) {
                Decision::Allow => admitted += 1,
                Decision::Drop => dropped += 1,
                Decision::Disconnect => panic!("egress path must not Disconnect"),
            }
        }
        assert_eq!(
            admitted, 2,
            "outbound budget admits exactly two 8 KiB frames"
        );
        assert_eq!(dropped, 98);
        assert_eq!(limiter.counters().outbound_drops_total(), 98);
    }

    #[test]
    fn peers_have_independent_state() {
        let clock = ManualClock::new();
        let limiter = RateLimiter::<TestKind>::new(limits_for_test(), clock.clone());
        for _ in 0..4 {
            limiter.admit(nid(1), TestKind::A, 1);
        }
        assert_eq!(limiter.admit(nid(1), TestKind::A, 1), Decision::Drop);
        // nid(2) has a fresh bucket.
        assert_eq!(limiter.admit(nid(2), TestKind::A, 1), Decision::Allow);
    }

    #[test]
    fn violations_age_out_of_window() {
        let clock = ManualClock::new();
        let mut config = limits_for_test();
        config.max_violations = 3;
        config.violation_window = Duration::from_secs(1);
        let limiter = RateLimiter::<TestKind>::new(config, clock.clone());

        // Drain and earn two violations.
        for _ in 0..4 {
            limiter.admit(nid(1), TestKind::A, 1);
        }
        limiter.admit(nid(1), TestKind::A, 1);
        limiter.admit(nid(1), TestKind::A, 1);
        // Skip ahead past the window so the violations age out and
        // the bucket refills.
        clock.set(Duration::from_secs(10));
        // Drain the freshly refilled bucket and earn fresh
        // violations — the disconnect latch should rearm.
        for _ in 0..4 {
            limiter.admit(nid(1), TestKind::A, 1);
        }
        for _ in 0..2 {
            assert_eq!(limiter.admit(nid(1), TestKind::A, 1), Decision::Drop);
        }
        assert_eq!(limiter.admit(nid(1), TestKind::A, 1), Decision::Disconnect);
        assert_eq!(limiter.counters().disconnects(), 1);
    }

    #[test]
    fn unbounded_config_does_not_drop() {
        const HUGE: f64 = 1.0e12;
        let config = RateLimitsConfig {
            per_kind_per_sec: vec![HUGE; TestKind::all().len()],
            bytes_per_sec: HUGE,
            outbound_bytes_per_sec: HUGE,
            burst_seconds: 1.0,
            violation_window: Duration::from_secs(10),
            max_violations: u32::MAX,
        };
        let clock: Arc<dyn Clock> = Arc::new(TokioClock::new());
        let limiter = RateLimiter::<TestKind>::new(config, clock);
        for _ in 0..1_000 {
            assert_eq!(limiter.admit(nid(7), TestKind::B, 100), Decision::Allow);
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
            max_total: usize::MAX,
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
            max_total: usize::MAX,
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
            max_total: usize::MAX,
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
    fn unconditional_peer_admitted_past_inbound_cap() {
        // A persistent/unconditional validator↔sentry link is admitted
        // even when the inbound (and total, and per-IP) caps are
        // saturated (#827).
        let cl = ConnectionLimiter::new(ConnectionLimitsConfig {
            max_inbound: 1,
            max_outbound: 99,
            max_per_ip: 99,
            max_total: usize::MAX,
        });
        let validator = nid(42);
        let unconditional: HashSet<NodeId> = [validator].into_iter().collect();

        // Saturate the inbound cap with a normal peer.
        assert!(cl.try_admit(Direction::Inbound, ipv4(10, 0, 0, 1)).is_ok());
        // A normal inbound is now refused (inbound cap reached).
        assert_eq!(
            cl.try_admit(Direction::Inbound, ipv4(10, 0, 0, 2)),
            Err(RejectReason::TotalInbound)
        );
        // The unconditional peer is admitted anyway.
        assert!(
            cl.try_admit_peer(
                Direction::Inbound,
                ipv4(10, 0, 0, 5),
                Some(&validator),
                &unconditional,
            )
            .is_ok(),
            "unconditional peer must bypass the inbound cap",
        );
        // It is still counted, so release balances the books.
        assert_eq!(cl.inbound(), 2);
        cl.release(Direction::Inbound, ipv4(10, 0, 0, 5));
        assert_eq!(cl.inbound(), 1);
    }

    #[test]
    fn non_unconditional_peer_still_capped() {
        // A peer *not* in the unconditional set goes through the normal
        // caps even via try_admit_peer.
        let cl = ConnectionLimiter::new(ConnectionLimitsConfig {
            max_inbound: 1,
            max_outbound: 99,
            max_per_ip: 99,
            max_total: usize::MAX,
        });
        let unconditional: HashSet<NodeId> = [nid(42)].into_iter().collect();
        assert!(
            cl.try_admit_peer(
                Direction::Inbound,
                ipv4(10, 0, 0, 1),
                Some(&nid(7)),
                &unconditional,
            )
            .is_ok()
        );
        assert_eq!(
            cl.try_admit_peer(
                Direction::Inbound,
                ipv4(10, 0, 0, 2),
                Some(&nid(8)),
                &unconditional,
            ),
            Err(RejectReason::TotalInbound),
        );
    }

    /// #187 / #511 acceptance: `max_total` is enforced before the
    /// per-direction caps so an inbound flood that fits within
    /// `max_inbound` still gets refused once the cluster's total
    /// direct-peer ceiling is hit.
    #[test]
    fn connection_limiter_caps_total_across_directions() {
        let cl = ConnectionLimiter::new(ConnectionLimitsConfig {
            max_inbound: 99,
            max_outbound: 99,
            max_per_ip: 99,
            max_total: 3,
        });
        // One outbound + two inbound saturates max_total = 3.
        assert!(cl.try_admit(Direction::Outbound, ipv4(10, 0, 0, 1)).is_ok());
        assert!(cl.try_admit(Direction::Inbound, ipv4(10, 0, 0, 2)).is_ok());
        assert!(cl.try_admit(Direction::Inbound, ipv4(10, 0, 0, 3)).is_ok());
        assert_eq!(cl.total(), 3);
        // Fourth (regardless of direction) is refused with the new
        // RejectReason::Total even though both per-direction caps
        // still have headroom.
        assert_eq!(
            cl.try_admit(Direction::Inbound, ipv4(10, 0, 0, 4)),
            Err(RejectReason::Total)
        );
        assert_eq!(
            cl.try_admit(Direction::Outbound, ipv4(10, 0, 0, 5)),
            Err(RejectReason::Total)
        );
        // Releasing one slot reopens admission.
        cl.release(Direction::Inbound, ipv4(10, 0, 0, 2));
        assert!(cl.try_admit(Direction::Inbound, ipv4(10, 0, 0, 6)).is_ok());
    }

    #[test]
    fn release_removes_per_ip_entry_at_zero() {
        let cl = ConnectionLimiter::new(ConnectionLimitsConfig {
            max_inbound: 99,
            max_outbound: 99,
            max_per_ip: 1,
            max_total: usize::MAX,
        });
        let ip = ipv4(10, 0, 0, 1);
        assert!(cl.try_admit(Direction::Inbound, ip).is_ok());
        cl.release(Direction::Inbound, ip);
        // After release we can re-admit from the same IP.
        assert!(cl.try_admit(Direction::Inbound, ip).is_ok());
    }

    // ── HandshakeLimiter ──────────────────────────────────────────────────

    fn hs_config(max_inflight: usize, max_inflight_per_ip: usize) -> HandshakeLimitsConfig {
        HandshakeLimitsConfig {
            max_inflight,
            max_inflight_per_ip,
            timeout: Duration::from_secs(10),
        }
    }

    /// Assert a [`HandshakeLimiter::try_acquire`] was refused with the
    /// expected reason. `HandshakePermit` is intentionally not
    /// `Debug`/`PartialEq` (it carries an `Arc` and runs `Drop`), so the
    /// `Result` can't go through `assert_eq!`.
    fn assert_hs_rejected(
        result: Result<HandshakePermit, HandshakeReject>,
        expected: HandshakeReject,
    ) {
        match result {
            Err(reason) => assert_eq!(reason, expected),
            Ok(_) => panic!("expected handshake reject {}, got Ok", expected.label()),
        }
    }

    /// #805 acceptance: a half-open flood from many IPs cannot pin more
    /// than `max_inflight` handshake slots — the global ceiling holds
    /// even when no single IP trips the per-IP cap.
    #[test]
    fn handshake_limiter_caps_global_inflight() {
        let hl = Arc::new(HandshakeLimiter::new(hs_config(3, 99)));
        // Three half-open handshakes from distinct IPs fill the global
        // budget; the permits are held (not dropped) to model in-flight.
        let _p1 = hl.try_acquire(ipv4(10, 0, 0, 1)).expect("slot 1");
        let _p2 = hl.try_acquire(ipv4(10, 0, 0, 2)).expect("slot 2");
        let _p3 = hl.try_acquire(ipv4(10, 0, 0, 3)).expect("slot 3");
        assert_eq!(hl.inflight(), 3);
        // Fourth from yet another IP is refused on the global cap.
        assert_hs_rejected(
            hl.try_acquire(ipv4(10, 0, 0, 4)),
            HandshakeReject::TotalInflight,
        );
        assert_eq!(hl.rejects(), 1);
    }

    /// A single source IP can hold at most `max_inflight_per_ip`
    /// half-open handshakes regardless of global headroom — so one
    /// attacker can't monopolise the handshake budget.
    #[test]
    fn handshake_limiter_caps_per_ip_inflight() {
        let hl = Arc::new(HandshakeLimiter::new(hs_config(99, 2)));
        let ip = ipv4(10, 0, 0, 1);
        let _p1 = hl.try_acquire(ip).expect("slot 1");
        let _p2 = hl.try_acquire(ip).expect("slot 2");
        assert_hs_rejected(hl.try_acquire(ip), HandshakeReject::PerIpInflight);
        // A different IP still has its own budget.
        assert!(hl.try_acquire(ipv4(10, 0, 0, 2)).is_ok());
    }

    /// Dropping a permit (handshake finished, errored, or timed out)
    /// frees both the global and per-IP slot so the next accept proceeds.
    #[test]
    fn handshake_permit_releases_slot_on_drop() {
        let hl = Arc::new(HandshakeLimiter::new(hs_config(1, 1)));
        let ip = ipv4(10, 0, 0, 1);
        {
            let _p = hl.try_acquire(ip).expect("slot");
            assert_eq!(hl.inflight(), 1);
            // Budget exhausted while the permit is alive.
            assert_hs_rejected(hl.try_acquire(ip), HandshakeReject::PerIpInflight);
        }
        // Permit dropped at end of scope — slot is free again.
        assert_eq!(hl.inflight(), 0);
        assert!(hl.try_acquire(ip).is_ok());
    }

    #[test]
    fn handshake_limiter_timeout_is_readable() {
        let hl = Arc::new(HandshakeLimiter::new(hs_config(1, 1)));
        assert_eq!(hl.timeout(), Duration::from_secs(10));
    }
}
