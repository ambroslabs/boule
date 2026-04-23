//! [`Clock`] implementation backed by tokio's paused timer plus a virtual
//! wall-clock cursor that the driver advances.
//!
//! Tests that use [`SimClock`] must run on a `current_thread` runtime started
//! with `start_paused = true` (e.g. `#[tokio::test(flavor = "current_thread",
//! start_paused = true)]`). Under that mode, `tokio::time::sleep` and
//! `tokio::time::interval` only fire when the test (or [`SimDriver::advance`])
//! advances tokio's clock — which keeps consensus-adjacent code deterministic
//! without us re-implementing tokio's executor.
//!
//! # Per-node clock skew
//!
//! Real replicas do not share a clock. [`SimClock::for_node`] returns a view
//! whose [`Clock::now_wall`] reports `shared_now + offset`. The tokio paused
//! timer advances every node's view at the same rate, so a sleep of `d` still
//! takes `d` of virtual time regardless of offset — but a timer scheduled to
//! the node's *local* instant `t` fires at `shared = t - offset` (the node
//! computes a shorter or longer duration from its own `now_wall`). Offsets
//! are fixed at driver construction and seeded from the driver's RNG so runs
//! stay deterministic.
//!
//! [`SimDriver::advance`]: super::driver::SimDriver::advance

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::clock::{BoxFuture, Clock, ClockInterval};
use crate::p2p::NodeId;

#[derive(Clone)]
pub struct SimClock {
    wall: Arc<Mutex<DateTime<Utc>>>,
    /// Monotonic virtual time since sim start. Advances in lockstep with
    /// [`SimClock::advance_wall`] but never moves backward even if/when
    /// the harness starts simulating backward wall-clock jumps, matching
    /// the [`Clock::now_monotonic`] contract.
    monotonic: Arc<Mutex<Duration>>,
    /// Per-node offsets from shared time, fixed at construction. Nodes
    /// without an entry (or present with `Duration::ZERO`) see the shared
    /// clock unskewed.
    offsets: Arc<HashMap<NodeId, Duration>>,
}

impl SimClock {
    /// Construct a [`SimClock`] anchored at the given virtual wall time with
    /// no per-node skew.
    pub fn new(start: DateTime<Utc>) -> Self {
        Self {
            wall: Arc::new(Mutex::new(start)),
            monotonic: Arc::new(Mutex::new(Duration::ZERO)),
            offsets: Arc::new(HashMap::new()),
        }
    }

    /// Construct a [`SimClock`] with the given per-node offsets. Nodes
    /// missing from the map observe the shared clock directly.
    pub fn with_offsets(start: DateTime<Utc>, offsets: HashMap<NodeId, Duration>) -> Self {
        Self {
            wall: Arc::new(Mutex::new(start)),
            monotonic: Arc::new(Mutex::new(Duration::ZERO)),
            offsets: Arc::new(offsets),
        }
    }

    /// Return a per-node view of this clock. The view's [`Clock::now_wall`]
    /// reports `shared_now + offset`; [`Clock::sleep`] and
    /// [`Clock::interval`] delegate to the shared tokio paused timer so
    /// virtual time still advances at the same rate for every node.
    pub fn for_node(self: &Arc<Self>, id: NodeId) -> Arc<dyn Clock> {
        let offset = self.offsets.get(&id).copied().unwrap_or(Duration::ZERO);
        if offset.is_zero() {
            Arc::clone(self) as Arc<dyn Clock>
        } else {
            Arc::new(SimClockView {
                shared: Arc::clone(self),
                offset,
            })
        }
    }

    /// Offset for `id`, or [`Duration::ZERO`] if none was configured. Useful
    /// for tests that want to reason about a node's local timeline.
    pub fn offset_for(&self, id: NodeId) -> Duration {
        self.offsets.get(&id).copied().unwrap_or(Duration::ZERO)
    }

    /// Advance the virtual wall clock by `dur`. Tokio's paused timer must be
    /// advanced separately (the [`SimDriver`] does both together).
    ///
    /// [`SimDriver`]: super::driver::SimDriver
    pub(crate) fn advance_wall(&self, dur: Duration) {
        let mut w = self.wall.lock().unwrap();
        *w += chrono::Duration::from_std(dur).expect("duration fits");
        let mut m = self.monotonic.lock().unwrap();
        *m = m.saturating_add(dur);
    }
}

impl Clock for SimClock {
    fn now_wall(&self) -> DateTime<Utc> {
        *self.wall.lock().unwrap()
    }

    fn now_monotonic(&self) -> Duration {
        *self.monotonic.lock().unwrap()
    }

    fn sleep(&self, dur: Duration) -> BoxFuture<'static, ()> {
        Box::pin(tokio::time::sleep(dur))
    }

    fn interval(&self, period: Duration) -> Box<dyn ClockInterval> {
        Box::new(SimInterval(tokio::time::interval(period)))
    }
}

/// Per-node view of a [`SimClock`]: reports a skewed `now_wall` while
/// delegating timers to the shared tokio paused timer.
pub struct SimClockView {
    shared: Arc<SimClock>,
    offset: Duration,
}

impl Clock for SimClockView {
    fn now_wall(&self) -> DateTime<Utc> {
        let shared_now = *self.shared.wall.lock().unwrap();
        shared_now
            + chrono::Duration::from_std(self.offset).expect("per-node offset fits in chrono")
    }

    fn now_monotonic(&self) -> Duration {
        // Per-node offsets model wall-clock skew (NTP disagreement); the
        // monotonic clock is about elapsed time since sim start and is
        // shared across all nodes.
        self.shared.now_monotonic()
    }

    fn sleep(&self, dur: Duration) -> BoxFuture<'static, ()> {
        Box::pin(tokio::time::sleep(dur))
    }

    fn interval(&self, period: Duration) -> Box<dyn ClockInterval> {
        Box::new(SimInterval(tokio::time::interval(period)))
    }
}

struct SimInterval(tokio::time::Interval);

impl ClockInterval for SimInterval {
    fn tick(&mut self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.0.tick().await;
        })
    }
}
