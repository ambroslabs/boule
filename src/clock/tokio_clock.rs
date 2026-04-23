//! Production [`Clock`] implementation backed by tokio's runtime and
//! [`chrono::Utc::now`].

use std::time::Duration;

use super::{BoxFuture, Clock, ClockInterval};

#[derive(Default, Debug, Clone, Copy)]
pub struct TokioClock;

impl TokioClock {
    pub fn new() -> Self {
        Self
    }
}

impl Clock for TokioClock {
    fn now_wall(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
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
