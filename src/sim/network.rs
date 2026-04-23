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
//!
//! This module also owns the adversary API plumbing (pause/resume/kill,
//! deliver-specific-event, duplicate) and the trace recorder used by the
//! byte-identical-determinism test.

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
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
                Duration::from_micros(mean_us.max(0.0) as u64)
            }
        }
    }
}

/// Per-directional-link configuration.
#[derive(Debug, Clone, Default)]
pub struct LinkConfig {
    pub latency: LatencyDist,
    pub drop_rate: f64,
    pub up: bool,
    pub bandwidth_bps: Option<u64>,
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

/// Stable identifier for a scheduled event. Assigned monotonically at
/// enqueue time; unique per `SimNetwork`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EventId(pub u64);

/// Snapshot of one in-flight event, for adversary API introspection.
#[derive(Debug, Clone)]
pub struct InFlightEvent {
    pub id: EventId,
    pub time: DateTime<Utc>,
    pub from: NodeId,
    pub to: NodeId,
    pub byte_len: usize,
}

/// One delivered-event entry in the trace. The trace is the byte-identical
/// fingerprint used to verify simulator determinism.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceEntry {
    pub time: DateTime<Utc>,
    pub id: EventId,
    pub from: NodeId,
    pub to: NodeId,
    pub byte_len: usize,
}

struct Event {
    id: EventId,
    time: DateTime<Utc>,
    from: NodeId,
    to: NodeId,
    inbox: Arc<Mutex<Inbox>>,
    bytes: Vec<u8>,
}

impl Ord for Event {
    fn cmp(&self, other: &Self) -> Ordering {
        // `BinaryHeap` is a max-heap; reverse so earliest time pops first.
        other
            .time
            .cmp(&self.time)
            .then_with(|| other.id.cmp(&self.id))
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
        self.time == other.time && self.id == other.id
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
    reorder_buffers: HashMap<(NodeId, NodeId), Vec<StagedWrite>>,
    /// Nodes currently paused: inbound events are delivered to their inbox
    /// but no waker is fired (the node's reader blocks until resume);
    /// outbound writes are silently dropped (task is notionally frozen).
    paused: HashSet<NodeId>,
    /// Nodes that have been killed. Writes from and deliveries to killed
    /// nodes are dropped; their peer-facing inboxes are marked closed so
    /// remote `connection::run` tasks see EOF and clean up.
    killed: HashSet<NodeId>,
    /// Ordered log of delivered events, used as the determinism fingerprint.
    trace: Vec<TraceEntry>,
}

struct StagedWrite {
    id: EventId,
    time: DateTime<Utc>,
    from: NodeId,
    to: NodeId,
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
                paused: HashSet::new(),
                killed: HashSet::new(),
                trace: Vec::new(),
            }),
        })
    }

    pub fn register_inbox(&self, from: NodeId, to: NodeId, inbox: Arc<Mutex<Inbox>>) {
        let mut inner = self.inner.lock().unwrap();
        inner.inboxes.insert((from, to), inbox);
    }

    pub fn set_link(&self, from: NodeId, to: NodeId, config: LinkConfig) {
        let mut inner = self.inner.lock().unwrap();
        inner.links.insert((from, to), config);
    }

    pub fn partition(&self, a: NodeId, b: NodeId) {
        self.set_link_up(a, b, false);
        self.set_link_up(b, a, false);
    }

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

    // ---- Adversary API ----

    /// Freeze `node`: inbound bytes still accumulate in its inboxes but the
    /// reader is not woken; outbound writes from this node are dropped.
    pub fn pause(&self, node: NodeId) {
        let mut inner = self.inner.lock().unwrap();
        inner.paused.insert(node);
    }

    /// Un-freeze `node` and wake its inbox readers so any bytes that
    /// accumulated during the pause can be consumed.
    pub fn resume(&self, node: NodeId) {
        let mut inner = self.inner.lock().unwrap();
        inner.paused.remove(&node);
        let inboxes: Vec<_> = inner
            .inboxes
            .iter()
            .filter_map(|((_, to), ibx)| if *to == node { Some(ibx.clone()) } else { None })
            .collect();
        drop(inner);
        for ibx in inboxes {
            let mut guard = ibx.lock().unwrap();
            if let Some(w) = guard.waker.take() {
                w.wake();
            }
        }
    }

    /// Mark `node` as permanently offline for the rest of the sim run.
    /// Closes every inbox this node writes to (so peers see EOF) and every
    /// inbox this node reads from (so the node's own tasks unwind). The
    /// caller is responsible for aborting the node's task handles.
    pub fn kill(&self, node: NodeId) {
        let mut inner = self.inner.lock().unwrap();
        inner.killed.insert(node);
        let relevant: Vec<_> = inner
            .inboxes
            .iter()
            .filter_map(|((from, to), ibx)| {
                if *from == node || *to == node {
                    Some(ibx.clone())
                } else {
                    None
                }
            })
            .collect();
        drop(inner);
        for ibx in relevant {
            let mut guard = ibx.lock().unwrap();
            guard.closed = true;
            if let Some(w) = guard.waker.take() {
                w.wake();
            }
        }
    }

    /// Non-destructive snapshot of every event currently in the main heap.
    /// Reorder-staged writes are not included.
    pub fn in_flight_events(&self) -> Vec<InFlightEvent> {
        let inner = self.inner.lock().unwrap();
        inner
            .queue
            .iter()
            .map(|e| InFlightEvent {
                id: e.id,
                time: e.time,
                from: e.from,
                to: e.to,
                byte_len: e.bytes.len(),
            })
            .collect()
    }

    /// Pop the event with `id` and deliver it now, ignoring its scheduled
    /// time. Returns `true` if the event was found and delivered.
    pub fn deliver_event_now(&self, id: EventId) -> bool {
        let event = {
            let mut inner = self.inner.lock().unwrap();
            let taken: Vec<Event> = std::mem::take(&mut inner.queue).into_vec();
            let mut found = None;
            for e in taken {
                if e.id == id && found.is_none() {
                    found = Some(e);
                } else {
                    inner.queue.push(e);
                }
            }
            found
        };
        match event {
            Some(e) => {
                self.deliver(e, /* record_trace */ true);
                true
            }
            None => false,
        }
    }

    /// Find the event with `id` and enqueue a clone of it at the same
    /// scheduled time with a fresh id. Returns the new event's id if found.
    pub fn duplicate_event(&self, id: EventId) -> Option<EventId> {
        let mut inner = self.inner.lock().unwrap();
        let source = inner.queue.iter().find(|e| e.id == id);
        let (time, from, to, inbox, bytes) = match source {
            Some(e) => (e.time, e.from, e.to, Arc::clone(&e.inbox), e.bytes.clone()),
            None => return None,
        };
        inner.seq += 1;
        let new_id = EventId(inner.seq);
        inner.queue.push(Event {
            id: new_id,
            time,
            from,
            to,
            inbox,
            bytes,
        });
        Some(new_id)
    }

    // ---- Trace ----

    pub fn trace_snapshot(&self) -> Vec<TraceEntry> {
        self.inner.lock().unwrap().trace.clone()
    }

    pub fn drain_trace(&self) -> Vec<TraceEntry> {
        std::mem::take(&mut self.inner.lock().unwrap().trace)
    }

    // ---- Write / deliver path ----

    pub(crate) fn enqueue_write(&self, from: NodeId, to: NodeId, buf: &[u8]) -> usize {
        let mut inner = self.inner.lock().unwrap();

        if inner.killed.contains(&from) || inner.killed.contains(&to) {
            return buf.len();
        }
        if inner.paused.contains(&from) {
            return buf.len();
        }

        let cfg = inner
            .links
            .get(&(from, to))
            .cloned()
            .unwrap_or_else(|| inner.default_link.clone());

        if !cfg.up {
            return buf.len();
        }
        if cfg.drop_rate > 0.0 && inner.rng.random::<f64>() < cfg.drop_rate {
            return buf.len();
        }

        let inbox = match inner.inboxes.get(&(from, to)).cloned() {
            Some(i) => i,
            None => return buf.len(),
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
        let chrono_total = chrono::Duration::from_std(total)
            .unwrap_or_else(|_| chrono::Duration::nanoseconds(i64::MAX));
        let time = inner.now + chrono_total;

        inner.seq += 1;
        let id = EventId(inner.seq);
        let staged = StagedWrite {
            id,
            time,
            from,
            to,
            inbox,
            bytes: buf.to_vec(),
        };

        if cfg.reorder_window <= 1 {
            push_event(&mut inner.queue, staged);
        } else {
            let buffer = inner.reorder_buffers.entry((from, to)).or_default();
            buffer.push(staged);
            if buffer.len() >= cfg.reorder_window {
                let mut taken = std::mem::take(buffer);
                taken.shuffle(&mut inner.rng);
                let min_time = taken
                    .iter()
                    .map(|w| w.time)
                    .min()
                    .unwrap_or_else(|| inner.now);
                for (i, mut w) in taken.into_iter().enumerate() {
                    w.time = min_time + chrono::Duration::microseconds(i as i64);
                    push_event(&mut inner.queue, w);
                }
            }
        }

        buf.len()
    }

    /// Pop the earliest scheduled event and deliver it.
    pub(crate) fn try_deliver_one(&self) -> Option<DateTime<Utc>> {
        let event = {
            let mut inner = self.inner.lock().unwrap();
            inner.queue.pop()?
        };
        Some(self.deliver(event, /* record_trace */ true))
    }

    fn deliver(&self, event: Event, record_trace: bool) -> DateTime<Utc> {
        let new_now = {
            let mut inner = self.inner.lock().unwrap();
            let now = event.time.max(inner.now);
            inner.now = now;
            if record_trace {
                inner.trace.push(TraceEntry {
                    time: now,
                    id: event.id,
                    from: event.from,
                    to: event.to,
                    byte_len: event.bytes.len(),
                });
            }
            now
        };

        // Check paused state outside the main lock to minimise hold time.
        let destination_paused = self.inner.lock().unwrap().paused.contains(&event.to);

        let mut inbox = event.inbox.lock().unwrap();
        inbox.bytes.extend_from_slice(&event.bytes);
        if !destination_paused {
            if let Some(waker) = inbox.waker.take() {
                waker.wake();
            }
        }
        new_now
    }

    pub(crate) fn flush_reorder_buffers(&self) {
        let mut inner = self.inner.lock().unwrap();
        let keys: Vec<_> = inner.reorder_buffers.keys().copied().collect();
        for key in keys {
            if let Some(mut buf) = inner.reorder_buffers.get_mut(&key).map(std::mem::take) {
                if buf.is_empty() {
                    continue;
                }
                buf.shuffle(&mut inner.rng);
                let min_time = buf.iter().map(|w| w.time).min().unwrap_or(inner.now);
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
        id: w.id,
        time: w.time,
        from: w.from,
        to: w.to,
        inbox: w.inbox,
        bytes: w.bytes,
    });
}
