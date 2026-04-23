//! Central event-queue scheduler and per-link state for the simulator.
//!
//! Each directional link `(from, to)` between two nodes has its own
//! [`LinkConfig`] (latency distribution, drop rate, partition state, optional
//! reorder window, optional bandwidth cap). When [`SimStream::poll_write`]
//! pushes bytes, the network samples the link config (using the seeded
//! `ChaCha20Rng`) and either drops the bytes, schedules a future
//! [`Event::Deliver`], or stages them in a per-link reorder buffer.
//!
//! The driver pumps the queue: pop the earliest event, advance virtual time
//! to its scheduled instant, and deliver bytes to the destination inbox
//! (waking its reader). Determinism comes from the
//! `(virtual_time, seq)` heap key plus the seeded RNG.

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use rand::Rng as _;
use rand::seq::SliceRandom as _;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng as _;

use crate::p2p::NodeId;

use super::stream::Inbox;

/// How latency on a link is sampled per write. Defaults to `Constant(0)`.
#[derive(Debug, Clone)]
pub enum LatencyDist {
    Constant(Duration),
    /// Uniform over `[min, max]`, inclusive.
    Uniform {
        min: Duration,
        max: Duration,
    },
    /// Truncated normal (re-sampled until non-negative).
    Normal {
        mean: Duration,
        std_dev: Duration,
    },
}

impl Default for LatencyDist {
    fn default() -> Self {
        Self::Constant(Duration::ZERO)
    }
}

impl LatencyDist {
    fn sample(&self, rng: &mut ChaCha20Rng) -> Duration {
        match *self {
            Self::Constant(d) => d,
            Self::Uniform { min, max } => {
                let lo = min.as_micros() as u64;
                let hi = max.as_micros().max(min.as_micros()) as u64;
                if hi == lo {
                    return Duration::from_micros(lo);
                }
                let us = rng.random_range(lo..=hi);
                Duration::from_micros(us)
            }
            Self::Normal { mean, std_dev } => {
                let mean_us = mean.as_micros() as f64;
                let sd_us = std_dev.as_micros() as f64;
                // Box–Muller, reject negatives.
                for _ in 0..16 {
                    let u1: f64 = rng.random();
                    let u2: f64 = rng.random();
                    let z = (-2.0 * (u1.max(f64::MIN_POSITIVE)).ln()).sqrt()
                        * (2.0 * std::f64::consts::PI * u2).cos();
                    let val = mean_us + sd_us * z;
                    if val >= 0.0 {
                        return Duration::from_micros(val as u64);
                    }
                }
                // Rejection failed (extreme tail); clamp.
                Duration::from_micros(mean_us.max(0.0) as u64)
            }
        }
    }
}

/// Per-directional-link configuration. Defaults reproduce an ideal network
/// (no latency, no drops, link up, no reorder, no bandwidth cap).
#[derive(Debug, Clone, Default)]
pub struct LinkConfig {
    pub latency: LatencyDist,
    /// Probability a write is silently dropped. `0.0` = never, `1.0` = always.
    pub drop_rate: f64,
    /// `false` = link partitioned; writes are dropped silently.
    /// Initially `true`.
    pub up: bool,
    /// If set, every byte costs an additional `1.0 / bandwidth_bps` virtual
    /// seconds of latency on top of the sampled latency.
    pub bandwidth_bps: Option<u64>,
    /// If non-zero, writes are batched into groups of this size and shuffled
    /// before being scheduled. Useful for testing reorder tolerance.
    pub reorder_window: usize,
}

impl LinkConfig {
    pub fn ideal() -> Self {
        Self {
            latency: LatencyDist::Constant(Duration::ZERO),
            drop_rate: 0.0,
            up: true,
            bandwidth_bps: None,
            reorder_window: 0,
        }
    }
}

struct Event {
    time: DateTime<Utc>,
    seq: u64,
    /// Where the bytes go on delivery.
    inbox: Arc<Mutex<Inbox>>,
    bytes: Vec<u8>,
}

// `BinaryHeap` is a max-heap; reverse the Ord so the earliest time wins.
impl Ord for Event {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .time
            .cmp(&self.time)
            .then_with(|| other.seq.cmp(&self.seq))
    }
}
impl PartialOrd for Event {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Eq for Event {}
impl PartialEq for Event {
    fn eq(&self, other: &Self) -> bool {
        self.time == other.time && self.seq == other.seq
    }
}

pub struct SimNetwork {
    inner: Mutex<Inner>,
}

struct Inner {
    rng: ChaCha20Rng,
    queue: BinaryHeap<Event>,
    seq: u64,
    now: DateTime<Utc>,
    links: HashMap<(NodeId, NodeId), LinkConfig>,
    inboxes: HashMap<(NodeId, NodeId), Arc<Mutex<Inbox>>>,
    default_link: LinkConfig,
    /// Per-link reorder staging: bytes wait here until the buffer fills, then
    /// get shuffled and scheduled.
    reorder_buffers: HashMap<(NodeId, NodeId), Vec<StagedWrite>>,
}

struct StagedWrite {
    seq: u64,
    time: DateTime<Utc>,
    inbox: Arc<Mutex<Inbox>>,
    bytes: Vec<u8>,
}

impl SimNetwork {
    pub fn new(seed: u64, start_now: DateTime<Utc>) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                rng: ChaCha20Rng::seed_from_u64(seed),
                queue: BinaryHeap::new(),
                seq: 0,
                now: start_now,
                links: HashMap::new(),
                inboxes: HashMap::new(),
                default_link: LinkConfig::ideal(),
                reorder_buffers: HashMap::new(),
            }),
        })
    }

    /// Register `inbox` as the destination for bytes flowing `from → to`.
    pub fn register_inbox(&self, from: NodeId, to: NodeId, inbox: Arc<Mutex<Inbox>>) {
        let mut inner = self.inner.lock().unwrap();
        inner.inboxes.insert((from, to), inbox);
    }

    /// Set per-directional-link config. Affects future writes only.
    pub fn set_link(&self, from: NodeId, to: NodeId, config: LinkConfig) {
        let mut inner = self.inner.lock().unwrap();
        inner.links.insert((from, to), config);
    }

    /// Take down both directions of the (a ↔ b) link.
    pub fn partition(&self, a: NodeId, b: NodeId) {
        self.set_link_up(a, b, false);
        self.set_link_up(b, a, false);
    }

    /// Re-enable both directions of the (a ↔ b) link.
    pub fn heal(&self, a: NodeId, b: NodeId) {
        self.set_link_up(a, b, true);
        self.set_link_up(b, a, true);
    }

    fn set_link_up(&self, from: NodeId, to: NodeId, up: bool) {
        let mut inner = self.inner.lock().unwrap();
        let default = inner.default_link.clone();
        let cfg = inner.links.entry((from, to)).or_insert(default);
        cfg.up = up;
    }

    /// Called by `SimStream::poll_write`. Always accepts the full slice;
    /// drops/partitions/reorder are handled internally. Returns the byte
    /// count for the caller's `poll_write` reply.
    pub(crate) fn enqueue_write(&self, from: NodeId, to: NodeId, buf: &[u8]) -> usize {
        let mut inner = self.inner.lock().unwrap();
        let cfg = inner
            .links
            .get(&(from, to))
            .cloned()
            .unwrap_or_else(|| inner.default_link.clone());

        if !cfg.up {
            // Partition: bytes vanish silently. Real TCP would queue them
            // locally and TLS would eventually error; that nuance is left to
            // the adversary API (sub-task #31).
            return buf.len();
        }
        if cfg.drop_rate > 0.0 && inner.rng.random::<f64>() < cfg.drop_rate {
            return buf.len();
        }

        let inbox = match inner.inboxes.get(&(from, to)).cloned() {
            Some(i) => i,
            None => return buf.len(), // not wired up; should not happen with the driver
        };

        let latency = cfg.latency.sample(&mut inner.rng);
        let bandwidth_extra = match cfg.bandwidth_bps {
            Some(bps) if bps > 0 => {
                let secs = buf.len() as f64 / bps as f64;
                Duration::from_secs_f64(secs)
            }
            _ => Duration::ZERO,
        };

        let total = latency + bandwidth_extra;
        let chrono_total = chrono::Duration::from_std(total).unwrap_or_else(|_| {
            // Saturate at i64::MAX nanos if pathological.
            chrono::Duration::nanoseconds(i64::MAX)
        });
        let time = inner.now + chrono_total;

        inner.seq += 1;
        let staged = StagedWrite {
            seq: inner.seq,
            time,
            inbox,
            bytes: buf.to_vec(),
        };

        if cfg.reorder_window <= 1 {
            push_event(&mut inner.queue, staged);
        } else {
            let buf = inner.reorder_buffers.entry((from, to)).or_default();
            buf.push(staged);
            if buf.len() >= cfg.reorder_window {
                let mut taken = std::mem::take(buf);
                taken.shuffle(&mut inner.rng);
                // Reassign times monotonically over the original window so
                // shuffled events still respect the per-link latency budget.
                let (min_time, max_seq) = taken
                    .iter()
                    .fold((DateTime::<Utc>::MAX_UTC, 0u64), |(t, s), w| {
                        (t.min(w.time), s.max(w.seq))
                    });
                let _ = max_seq; // staged seqs already unique
                for (i, mut w) in taken.into_iter().enumerate() {
                    // Spread shuffled events from min_time forward at 1µs
                    // intervals to keep the heap order well-defined.
                    w.time = min_time + chrono::Duration::microseconds(i as i64);
                    push_event(&mut inner.queue, w);
                }
            }
        }

        buf.len()
    }

    /// Pop the earliest scheduled event, advance virtual time to its
    /// scheduled instant, deliver bytes, wake the reader.
    /// Returns `Some(time_advanced_to)` if an event was delivered, `None` if
    /// the queue is empty (and no reorder buffer needs flushing).
    pub(crate) fn try_deliver_one(&self) -> Option<DateTime<Utc>> {
        let mut inner = self.inner.lock().unwrap();
        let event = inner.queue.pop()?;
        let new_now = event.time.max(inner.now);
        inner.now = new_now;
        // Drop the network lock before grabbing the inbox lock so a reader
        // task can't ever observe network-then-inbox order vs. inbox-then-
        // network on the writer side.
        drop(inner);

        let mut inbox = event.inbox.lock().unwrap();
        inbox.bytes.extend_from_slice(&event.bytes);
        if let Some(waker) = inbox.waker.take() {
            waker.wake();
        }
        Some(new_now)
    }

    /// Force any partially-filled reorder buffers to flush (shuffle + enqueue).
    /// Called by the driver when it suspects all writes have completed and
    /// wants to make sure no bytes are stranded.
    pub(crate) fn flush_reorder_buffers(&self) {
        let mut inner = self.inner.lock().unwrap();
        let keys: Vec<_> = inner.reorder_buffers.keys().copied().collect();
        for key in keys {
            if let Some(mut buf) = inner.reorder_buffers.get_mut(&key).map(std::mem::take) {
                if buf.is_empty() {
                    continue;
                }
                buf.shuffle(&mut inner.rng);
                let min_time = buf
                    .iter()
                    .map(|w| w.time)
                    .min()
                    .unwrap_or_else(|| inner.now);
                for (i, mut w) in buf.into_iter().enumerate() {
                    w.time = min_time + chrono::Duration::microseconds(i as i64);
                    push_event(&mut inner.queue, w);
                }
            }
        }
    }

    pub(crate) fn now(&self) -> DateTime<Utc> {
        self.inner.lock().unwrap().now
    }

    pub(crate) fn set_now(&self, t: DateTime<Utc>) {
        self.inner.lock().unwrap().now = t;
    }

    /// Number of in-flight scheduled events. Includes events whose time has
    /// already passed (the driver hasn't called `try_deliver_one` yet).
    /// Useful for the driver's quiescence check.
    pub(crate) fn queue_len(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.queue.len()
            + inner
                .reorder_buffers
                .values()
                .map(|v| v.len())
                .sum::<usize>()
    }
}

fn push_event(queue: &mut BinaryHeap<Event>, w: StagedWrite) {
    queue.push(Event {
        time: w.time,
        seq: w.seq,
        inbox: w.inbox,
        bytes: w.bytes,
    });
}
