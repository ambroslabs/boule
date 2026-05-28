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
    ///
    /// **Not monotonic.** NTP adjustments, leap-second smearing, VM
    /// suspend/resume, and plain operator error can make this jump
    /// backward by seconds or more. Use [`Clock::now_monotonic`] for
    /// any duration math in consensus-adjacent code (pacemaker view
    /// timers, safety-core "has the timeout elapsed?" checks, retry
    /// backoffs). `now_wall` is for human-readable fields only:
    /// log timestamps, gossip-message expiry, serialized wire
    /// timestamps, etc.
    fn now_wall(&self) -> chrono::DateTime<chrono::Utc>;

    /// Elapsed duration since an implementation-defined epoch that is
    /// fixed for the lifetime of this `Clock` instance (process start
    /// for [`TokioClock`], sim-start for `SimClock`).
    ///
    /// Guaranteed to never return a smaller value than a prior call on
    /// the same instance. Intended for consensus and pacemaker code
    /// that needs to compute `elapsed = now_monotonic() - earlier` and
    /// compare against a timeout without worrying about wall-clock
    /// adjustments.
    #[allow(dead_code)] // Wired for pacemaker/safety-core work in #22 and #23.
    fn now_monotonic(&self) -> Duration;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokio_clock_monotonic_is_non_decreasing() {
        let clock = TokioClock::new();
        let mut last = clock.now_monotonic();
        for _ in 0..1000 {
            let next = clock.now_monotonic();
            assert!(next >= last, "monotonic went backward: {next:?} < {last:?}");
            last = next;
        }
    }

    #[test]
    fn tokio_clock_monotonic_advances_across_a_real_sleep() {
        let clock = TokioClock::new();
        let before = clock.now_monotonic();
        std::thread::sleep(Duration::from_millis(5));
        let after = clock.now_monotonic();
        assert!(
            after > before,
            "monotonic did not advance across a 5ms real sleep: {before:?} -> {after:?}"
        );
    }
}
