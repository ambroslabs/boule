//! Cancellable wall-clock timer for the dedicated block-sync retry
//! path (#512).
//!
//! Block-sync retries today only fire on
//! [`pacemaker::Event::OnTimeout`](crate::pacemaker::Event::OnTimeout)
//! → [`HotStuffCore::on_pacemaker_advance`](super::hotstuff::HotStuffCore::on_pacemaker_advance):
//! a single-shot `RequestBlock` lost in flight has to wait a full view
//! timeout before the next retry attempt. On a healthy fast cluster
//! that is `O(view_timeout) ≈ O(seconds)`, even though the underlying
//! gossip mesh would deliver the next request in milliseconds.
//!
//! This timer decouples retry cadence from view cadence. The
//! integration layer arms it when the safety core has at least one
//! [`block_sync_inflight`](super::hotstuff::HotStuffCore::has_any_block_sync_inflight)
//! entry; on each fire the integration layer dispatches
//! [`HotStuffCore::step_block_sync_retry_tick`](super::hotstuff::HotStuffCore::step_block_sync_retry_tick)
//! and re-arms with exponential backoff up to a cap. When the inflight
//! tracker drains the timer is cancelled.
//!
//! # Cancellation
//!
//! Same discipline as [`crate::view_timer::ViewTimer`]:
//! [`BlockSyncRetryTimer::arm`] aborts the previous tokio task before
//! spawning the new one, so a stale tick never reaches the event loop
//! after the timer has been re-armed or cancelled.

#![allow(dead_code)]

use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::sleep;

/// Default initial delay between successive block-sync retry ticks.
/// Sized to the order of a single mesh round-trip plus a small jitter
/// margin so a typical sparse-mesh single-shot loss recovers in well
/// under one view timeout.
pub const DEFAULT_INITIAL_DELAY: Duration = Duration::from_millis(200);

/// Default cap on the per-tick delay. Keeps the backoff schedule from
/// pushing the next retry past the next pacemaker tick on a slow
/// cluster — beyond which the existing pacemaker-driven retry path
/// (#178) would catch the parent anyway, so further wall-clock backoff
/// has diminishing returns.
pub const DEFAULT_MAX_DELAY: Duration = Duration::from_millis(2_000);

/// A cancellable, single-shot block-sync retry timer driven by tokio.
///
/// Construct with [`BlockSyncRetryTimer::new`], passing the `fired_tx`
/// channel that the event loop's `select!` receives `()` events from.
/// Call [`BlockSyncRetryTimer::arm`] when the safety core has at least
/// one `block_sync_inflight` entry; call [`BlockSyncRetryTimer::cancel`]
/// when the tracker drains.
///
/// The timer is *single-shot*: the integration layer must call
/// [`BlockSyncRetryTimer::arm`] again after each fire to keep ticking.
/// This mirrors the [`ViewTimer`](crate::view_timer::ViewTimer)
/// shape so the two timers can be reasoned about identically.
pub struct BlockSyncRetryTimer {
    /// Outbound channel; the sleeping task sends `()` on this when it
    /// wakes.
    fired_tx: mpsc::Sender<()>,
    /// Handle to the currently-running sleep task, if any.
    current: Option<JoinHandle<()>>,
}

impl BlockSyncRetryTimer {
    /// Create a new timer. Pass the *sender* half of an `mpsc` channel;
    /// the event loop holds the receiver and polls it in `select!`.
    pub fn new(fired_tx: mpsc::Sender<()>) -> Self {
        Self {
            fired_tx,
            current: None,
        }
    }

    /// Cancel any in-flight timer and arm a new one that fires after
    /// `duration`.
    pub fn arm(&mut self, duration: Duration) {
        self.cancel();
        let tx = self.fired_tx.clone();
        let handle = tokio::spawn(async move {
            sleep(duration).await;
            // Best-effort: if the channel is closed the event loop is
            // shutting down and the tick is no longer relevant.
            let _ = tx.send(()).await;
        });
        self.current = Some(handle);
    }

    /// Cancel the in-flight timer (if any). After this call the
    /// `fired_tx` channel will not receive any event from the
    /// previously armed timer.
    pub fn cancel(&mut self) {
        if let Some(handle) = self.current.take() {
            handle.abort();
        }
    }

    /// Whether a timer is currently armed.
    pub fn is_armed(&self) -> bool {
        self.current.is_some()
    }
}

impl Drop for BlockSyncRetryTimer {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// Compute the next per-tick delay from the prior delay and the cap,
/// using a binary-exponential schedule. `prior == None` returns the
/// initial delay; subsequent calls double the prior delay and saturate
/// at `max`. Pure so the integration layer can unit-test its arming
/// logic without standing up a tokio runtime.
pub fn next_delay(prior: Option<Duration>, initial: Duration, max: Duration) -> Duration {
    match prior {
        None => initial.min(max),
        Some(p) => p.saturating_mul(2).min(max),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::sync::mpsc;
    use tokio::time;

    use super::*;

    #[tokio::test]
    async fn timer_fires_after_duration() {
        time::pause();
        let (tx, mut rx) = mpsc::channel(4);
        let mut timer = BlockSyncRetryTimer::new(tx);

        timer.arm(Duration::from_millis(200));
        assert!(timer.is_armed());

        time::advance(Duration::from_millis(201)).await;

        rx.recv().await.expect("timer must fire");
    }

    #[tokio::test]
    async fn arm_cancels_previous_timer() {
        time::pause();
        let (tx, mut rx) = mpsc::channel(4);
        let mut timer = BlockSyncRetryTimer::new(tx);

        timer.arm(Duration::from_millis(100));
        timer.arm(Duration::from_millis(300));

        time::advance(Duration::from_millis(150)).await;
        assert!(rx.try_recv().is_err(), "cancelled timer must not fire");

        time::advance(Duration::from_millis(200)).await;
        rx.recv().await.expect("re-armed timer must fire");
    }

    #[tokio::test]
    async fn cancel_prevents_fire() {
        time::pause();
        let (tx, mut rx) = mpsc::channel(4);
        let mut timer = BlockSyncRetryTimer::new(tx);

        timer.arm(Duration::from_millis(50));
        timer.cancel();
        assert!(!timer.is_armed());

        time::advance(Duration::from_millis(100)).await;
        assert!(rx.try_recv().is_err(), "cancelled timer must not fire");
    }

    #[test]
    fn next_delay_starts_at_initial_then_doubles_to_cap() {
        let initial = Duration::from_millis(200);
        let max = Duration::from_millis(2_000);

        // First arm: prior == None → initial.
        let d0 = next_delay(None, initial, max);
        assert_eq!(d0, initial);
        // Subsequent arms: double, saturating at max.
        let d1 = next_delay(Some(d0), initial, max);
        assert_eq!(d1, Duration::from_millis(400));
        let d2 = next_delay(Some(d1), initial, max);
        assert_eq!(d2, Duration::from_millis(800));
        let d3 = next_delay(Some(d2), initial, max);
        assert_eq!(d3, Duration::from_millis(1_600));
        let d4 = next_delay(Some(d3), initial, max);
        assert_eq!(d4, max, "saturates at max");
        let d5 = next_delay(Some(d4), initial, max);
        assert_eq!(d5, max, "stays at max once saturated");
    }

    #[test]
    fn next_delay_clamps_initial_above_max() {
        // Pathological config (initial > max). Treat max as the
        // floor so callers can't accidentally arm past their cap.
        let initial = Duration::from_secs(10);
        let max = Duration::from_secs(1);
        let d = next_delay(None, initial, max);
        assert_eq!(d, max);
    }
}
