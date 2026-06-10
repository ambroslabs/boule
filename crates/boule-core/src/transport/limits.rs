use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use parking_lot::Mutex;

use crate::clock::Clock;
use crate::identity::NodeId;

pub trait RateLimitKind: Copy + Eq + std::hash::Hash + 'static {
    fn all() -> &'static [Self];

    fn index(self) -> usize;

    fn label(self) -> &'static str;
}

#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    rate_per_sec: f64,
    last_refill: Duration,
}

impl TokenBucket {
    pub fn new(rate_per_sec: f64, capacity: f64, now: Duration) -> Self {
        Self {
            capacity,
            tokens: capacity,
            rate_per_sec,
            last_refill: now,
        }
    }

    pub fn try_take(&mut self, now: Duration, n: f64) -> bool {
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
}

#[derive(Debug, Clone)]
pub struct RateLimitsConfig {
    pub per_kind_per_sec: Vec<f64>,

    pub bytes_per_sec: f64,

    pub outbound_bytes_per_sec: f64,

    pub burst_seconds: f64,

    pub violation_window: Duration,

    pub max_violations: u32,
}

impl RateLimitsConfig {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,

    Drop,

    Disconnect,
}

#[derive(Debug, Clone)]
pub struct RateLimitCounters {
    inner: Arc<RateLimitCountersInner>,
}

#[derive(Debug)]
struct RateLimitCountersInner {
    by_kind: Vec<AtomicU64>,
    bytes: AtomicU64,
    outbound_bytes: AtomicU64,
    disconnects: AtomicU64,
}

impl RateLimitCounters {
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

    pub fn drops(&self, kind_index: usize) -> u64 {
        self.inner
            .by_kind
            .get(kind_index)
            .map_or(0, |c| c.load(Ordering::Relaxed))
    }

    pub fn total_drops(&self) -> u64 {
        self.inner
            .by_kind
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .sum::<u64>()
            .saturating_add(self.bytes_drops())
    }

    pub fn bytes_drops(&self) -> u64 {
        self.inner.bytes.load(Ordering::Relaxed)
    }

    pub fn outbound_drops_total(&self) -> u64 {
        self.inner.outbound_bytes.load(Ordering::Relaxed)
    }

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

struct PeerState {
    buckets: Vec<TokenBucket>,
    bytes_bucket: TokenBucket,

    outbound_bytes_bucket: TokenBucket,

    violations: VecDeque<Duration>,

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

pub struct RateLimiter<K: RateLimitKind> {
    config: RateLimitsConfig,
    state: Mutex<HashMap<NodeId, PeerState>>,
    clock: Arc<dyn Clock>,
    counters: RateLimitCounters,
    _kind: std::marker::PhantomData<fn() -> K>,
}

impl<K: RateLimitKind> RateLimiter<K> {
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

    pub fn admit(&self, peer: NodeId, kind: K, bytes_len: usize) -> Decision {
        let now = self.clock.now_monotonic();
        let mut state = self.state.lock();
        let peer_state = state
            .entry(peer)
            .or_insert_with(|| PeerState::new(&self.config, now));

        let window_start = now.saturating_sub(self.config.violation_window);
        while peer_state
            .violations
            .front()
            .is_some_and(|t| *t < window_start)
        {
            peer_state.violations.pop_front();
        }
        if peer_state.violations.is_empty() {
            peer_state.disconnect_dispatched = false;
        }

        let kind_admitted = peer_state.buckets[kind.index()].try_take(now, 1.0);
        let bytes_admitted = peer_state.bytes_bucket.try_take(now, bytes_len as f64);

        if kind_admitted && bytes_admitted {
            return Decision::Allow;
        }

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

    pub fn forget_peer(&self, peer: NodeId) {
        self.state.lock().remove(&peer);
    }

    pub fn counters(&self) -> &RateLimitCounters {
        &self.counters
    }

    pub fn config(&self) -> &RateLimitsConfig {
        &self.config
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,

    Outbound,
}

#[derive(Debug, Clone)]
pub struct ConnectionLimitsConfig {
    pub max_inbound: usize,

    pub max_outbound: usize,

    pub max_per_ip: usize,

    pub max_total: usize,
}

impl ConnectionLimitsConfig {
    pub fn from_config(c: &crate::config::P2pLimitsConfig) -> Self {
        Self {
            max_inbound: c.max_inbound_connections,
            max_outbound: c.max_outbound_connections,
            max_per_ip: c.max_connections_per_ip,
            max_total: usize::MAX,
        }
    }

    pub fn production_defaults() -> Self {
        Self {
            max_inbound: 512,
            max_outbound: 64,
            max_per_ip: 8,

            max_total: usize::MAX,
        }
    }

    pub fn unbounded_for_tests() -> Self {
        Self {
            max_inbound: usize::MAX,
            max_outbound: usize::MAX,
            max_per_ip: usize::MAX,
            max_total: usize::MAX,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    TotalInbound,

    TotalOutbound,

    PerIp,

    Total,
}

impl RejectReason {
    pub fn label(self) -> &'static str {
        match self {
            Self::TotalInbound => "max_inbound",
            Self::TotalOutbound => "max_outbound",
            Self::PerIp => "max_per_ip",
            Self::Total => "max_total",
        }
    }
}

pub struct ConnectionLimiter {
    config: ConnectionLimitsConfig,
    inbound: AtomicUsize,
    outbound: AtomicUsize,
    per_ip: Mutex<HashMap<IpAddr, usize>>,
    rejects: AtomicU64,
}

impl ConnectionLimiter {
    pub fn new(config: ConnectionLimitsConfig) -> Self {
        Self {
            config,
            inbound: AtomicUsize::new(0),
            outbound: AtomicUsize::new(0),
            per_ip: Mutex::new(HashMap::new()),
            rejects: AtomicU64::new(0),
        }
    }

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
            let mut per_ip = self.per_ip.lock();
            self.inbound.fetch_add(1, Ordering::AcqRel);
            *per_ip.entry(ip).or_insert(0) += 1;
            return Ok(());
        }
        self.try_admit(direction, ip)
    }

    pub fn try_admit(&self, direction: Direction, ip: IpAddr) -> Result<(), RejectReason> {
        let mut per_ip = self.per_ip.lock();
        let ip_count = per_ip.get(&ip).copied().unwrap_or(0);
        if ip_count >= self.config.max_per_ip {
            self.rejects.fetch_add(1, Ordering::Relaxed);
            return Err(RejectReason::PerIp);
        }

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

    pub fn rejects(&self) -> u64 {
        self.rejects.load(Ordering::Relaxed)
    }

    pub fn inbound(&self) -> usize {
        self.inbound.load(Ordering::Relaxed)
    }

    pub fn outbound(&self) -> usize {
        self.outbound.load(Ordering::Relaxed)
    }

    pub fn total(&self) -> usize {
        self.inbound().saturating_add(self.outbound())
    }
}

#[derive(Debug, Clone)]
pub struct HandshakeLimitsConfig {
    pub max_inflight: usize,

    pub max_inflight_per_ip: usize,

    pub timeout: Duration,
}

impl HandshakeLimitsConfig {
    pub fn production_defaults() -> Self {
        Self {
            max_inflight: 256,
            max_inflight_per_ip: 4,
            timeout: Duration::from_secs(10),
        }
    }

    pub fn unbounded_for_tests() -> Self {
        Self {
            max_inflight: usize::MAX,
            max_inflight_per_ip: usize::MAX,

            timeout: Duration::from_secs(3600),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeReject {
    TotalInflight,

    PerIpInflight,
}

impl HandshakeReject {
    pub fn label(self) -> &'static str {
        match self {
            Self::TotalInflight => "max_inflight",
            Self::PerIpInflight => "max_inflight_per_ip",
        }
    }
}

pub struct HandshakeLimiter {
    config: HandshakeLimitsConfig,
    inflight: AtomicUsize,
    per_ip: Mutex<HashMap<IpAddr, usize>>,
    rejects: AtomicU64,
}

impl HandshakeLimiter {
    pub fn new(config: HandshakeLimitsConfig) -> Self {
        Self {
            config,
            inflight: AtomicUsize::new(0),
            per_ip: Mutex::new(HashMap::new()),
            rejects: AtomicU64::new(0),
        }
    }

    pub fn timeout(&self) -> Duration {
        self.config.timeout
    }

    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Result<HandshakePermit, HandshakeReject> {
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

    pub fn rejects(&self) -> u64 {
        self.rejects.load(Ordering::Relaxed)
    }

    pub fn inflight(&self) -> usize {
        self.inflight.load(Ordering::Relaxed)
    }
}

pub struct HandshakePermit {
    limiter: Arc<HandshakeLimiter>,
    ip: IpAddr,
}

impl Drop for HandshakePermit {
    fn drop(&mut self) {
        self.limiter.release(self.ip);
    }
}
