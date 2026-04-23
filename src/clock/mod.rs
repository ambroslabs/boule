//! Clock abstraction for consensus-adjacent code.
//!
//! Production code uses [`tokio_clock::TokioClock`]; the deterministic
//! simulator (see `src/sim`) plugs in its own implementation that advances
//! virtual time under driver control. The trait is object-safe — callers hold
//! `Arc<dyn Clock>` rather than a generic parameter — to keep the blast radius
//! of the abstraction small.

pub mod tokio_clock;

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

pub use tokio_clock::TokioClock;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait Clock: Send + Sync + 'static {
    /// Current wall-clock time as a UTC datetime.
    fn now_wall(&self) -> chrono::DateTime<chrono::Utc>;

    /// Sleep for `dur`.
    fn sleep(&self, dur: Duration) -> BoxFuture<'static, ()>;

    /// An interval that yields a tick every `period`. The first tick fires
    /// immediately; consumers typically discard it (matching `tokio::time::interval`).
    fn interval(&self, period: Duration) -> Box<dyn ClockInterval>;
}

pub trait ClockInterval: Send {
    /// Wait for the next tick.
    fn tick(&mut self) -> BoxFuture<'_, ()>;
}

/// Returned by [`timeout`] when the deadline elapses before the inner future
/// completes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elapsed;

impl std::fmt::Display for Elapsed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("deadline elapsed")
    }
}

impl std::error::Error for Elapsed {}

/// Race `fut` against the clock's sleep for `dur`. Free function (rather than a
/// trait method) so the clock trait stays object-safe.
pub async fn timeout<F: Future>(
    clock: &dyn Clock,
    dur: Duration,
    fut: F,
) -> Result<F::Output, Elapsed> {
    tokio::pin!(fut);
    tokio::select! {
        biased;
        out = &mut fut => Ok(out),
        _ = clock.sleep(dur) => Err(Elapsed),
    }
}
