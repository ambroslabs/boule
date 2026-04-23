//! Production [`Clock`] implementation backed by tokio's runtime,
//! [`chrono::Utc::now`], and [`std::time::Instant`].

use std::time::{Duration, Instant};

use super::{BoxFuture, Clock, ClockInterval};

#[derive(Debug, Clone, Copy)]
pub struct TokioClock {
    #[allow(dead_code)] // Read through `now_monotonic`; see `Clock` trait.
    start: Instant,
}

impl TokioClock {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl Default for TokioClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for TokioClock {
    fn now_wall(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }

    fn now_monotonic(&self) -> Duration {
        Instant::now().saturating_duration_since(self.start)
    }

    fn sleep(&self, dur: Duration) -> BoxFuture<'static, ()> {
        Box::pin(tokio::time::sleep(dur))
    }

    fn interval(&self, period: Duration) -> Box<dyn ClockInterval> {
        Box::new(TokioInterval(tokio::time::interval(period)))
    }
}

struct TokioInterval(tokio::time::Interval);

impl ClockInterval for TokioInterval {
    fn tick(&mut self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.0.tick().await;
        })
    }
}
