//! [`Clock`] implementation backed by tokio's paused timer plus a virtual
//! wall-clock cursor that the driver advances.
//!
//! Tests that use [`SimClock`] must run on a `current_thread` runtime started
//! with `start_paused = true` (e.g. `#[tokio::test(flavor = "current_thread",
//! start_paused = true)]`). Under that mode, `tokio::time::sleep` and
//! `tokio::time::interval` only fire when the test (or [`SimDriver::advance`])
//! advances tokio's clock — which keeps consensus-adjacent code deterministic
//! without us re-implementing tokio's executor.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::clock::{BoxFuture, Clock, ClockInterval};

#[derive(Clone)]
pub struct SimClock {
    wall: Arc<Mutex<DateTime<Utc>>>,
}

impl SimClock {
    /// Construct a [`SimClock`] anchored at the given virtual wall time.
    pub fn new(start: DateTime<Utc>) -> Self {
        Self {
            wall: Arc::new(Mutex::new(start)),
        }
    }

    /// Advance the virtual wall clock by `dur`. Tokio's paused timer must be
    /// advanced separately (the [`SimDriver`] does both together).
    pub(crate) fn advance_wall(&self, dur: Duration) {
        let mut w = self.wall.lock().unwrap();
        *w += chrono::Duration::from_std(dur).expect("duration fits");
    }
}

impl Clock for SimClock {
    fn now_wall(&self) -> DateTime<Utc> {
        *self.wall.lock().unwrap()
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
