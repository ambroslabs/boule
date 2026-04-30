//! Cancellable view timer for the consensus event loop.
//!
//! The HotStuff pacemaker emits [`pacemaker::Action::ResetTimer(Duration)`]
//! when it wants the local timer re-armed. The event loop translates that by
//! calling [`ViewTimer::reset`], which cancels any in-flight task and spawns
//! a new one that sleeps for the requested duration and then sends
//! [`ViewTimerFired(view)`] on the shared channel.
//!
//! The timer fires with the *view it was armed for* so the event loop can
//! pass that view to [`pacemaker::Event::OnTimeout(view)`] without keeping
//! additional state.
//!
//! # Cancellation
//!
//! [`ViewTimer::reset`] aborts the previous tokio task before spawning the
//! new one. Aborting a task is guaranteed to prevent its send from reaching
//! the channel, so the event loop will never see a stale `ViewTimerFired`
//! for a past view after `reset` returns.
//!
//! [`pacemaker::Action::ResetTimer`]: crate::consensus::pacemaker::Action::ResetTimer

#![allow(dead_code)]

use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::sleep;

use crate::consensus::View;

/// A cancellable, single-shot view timer driven by tokio.
///
/// Construct with [`ViewTimer::new`], passing the `fired_tx` channel that
/// the event loop's `select!` receives [`View`] events from. Call
/// [`reset`] whenever the pacemaker asks; call [`cancel`] on shutdown or
/// when entering a committed state where the timer is no longer relevant.
///
/// [`reset`]: ViewTimer::reset
/// [`cancel`]: ViewTimer::cancel
pub struct ViewTimer {
    /// Outbound channel; the sleeping task sends the view on this when it wakes.
    fired_tx: mpsc::Sender<View>,
    /// Handle to the currently-running sleep task, if any.
    current: Option<(View, JoinHandle<()>)>,
}

impl ViewTimer {
    /// Create a new timer. Pass the *sender* half of an `mpsc` channel; the
    /// event loop holds the receiver and polls it in `select!`.
    pub fn new(fired_tx: mpsc::Sender<View>) -> Self {
        Self {
            fired_tx,
            current: None,
        }
    }

    /// Cancel any in-flight timer and arm a new one that fires after `duration`.
    ///
    /// When the sleep expires, `view` is sent on the `fired_tx` channel.
    /// If the event loop has dropped the receiver, the send silently fails —
    /// which is correct (the event loop is gone, so the timer no longer
    /// matters).
    pub fn reset(&mut self, view: View, duration: Duration) {
        // Cancel the previous task first.
        self.cancel();

        let tx = self.fired_tx.clone();
        let handle = tokio::spawn(async move {
            sleep(duration).await;
            // Best-effort send: if the channel is closed, we're shutting down.
            let _ = tx.send(view).await;
        });
        self.current = Some((view, handle));
    }

    /// Cancel the in-flight timer (if any). After this call the `fired_tx`
    /// channel will not receive any event from the previously armed timer.
    pub fn cancel(&mut self) {
        if let Some((_, handle)) = self.current.take() {
            handle.abort();
        }
    }

    /// Return the view the timer is currently armed for, or `None` if no
    /// timer is active.
    pub fn armed_for(&self) -> Option<View> {
        self.current.as_ref().map(|(v, _)| *v)
    }
}

impl Drop for ViewTimer {
    fn drop(&mut self) {
        self.cancel();
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
        let mut timer = ViewTimer::new(tx);

        timer.reset(View(3), Duration::from_millis(100));
        assert_eq!(timer.armed_for(), Some(View(3)));

        time::advance(Duration::from_millis(101)).await;

        let fired = rx.recv().await.expect("timer must fire");
        assert_eq!(fired, View(3));
    }

    #[tokio::test]
    async fn reset_cancels_previous_timer() {
        time::pause();
        let (tx, mut rx) = mpsc::channel(4);
        let mut timer = ViewTimer::new(tx);

        // Arm for view 1, then immediately re-arm for view 2.
        timer.reset(View(1), Duration::from_millis(100));
        timer.reset(View(2), Duration::from_millis(200));
        assert_eq!(timer.armed_for(), Some(View(2)));

        // Advance past the original deadline for view 1.
        time::advance(Duration::from_millis(150)).await;
        // View 1 task was aborted; no event for view 1.
        assert!(rx.try_recv().is_err(), "cancelled timer must not fire");

        // Advance past the view-2 deadline.
        time::advance(Duration::from_millis(60)).await;
        let fired = rx.recv().await.expect("view 2 timer must fire");
        assert_eq!(fired, View(2));
    }

    #[tokio::test]
    async fn cancel_prevents_fire() {
        time::pause();
        let (tx, mut rx) = mpsc::channel(4);
        let mut timer = ViewTimer::new(tx);

        timer.reset(View(5), Duration::from_millis(50));
        timer.cancel();
        assert!(timer.armed_for().is_none());

        time::advance(Duration::from_millis(100)).await;
        assert!(rx.try_recv().is_err(), "cancelled timer must not fire");
    }

    #[tokio::test]
    async fn no_timer_armed_on_construction() {
        let (tx, _rx) = mpsc::channel(4);
        let timer = ViewTimer::new(tx);
        assert!(timer.armed_for().is_none());
    }

    #[tokio::test]
    async fn multiple_resets_fire_only_last() {
        time::pause();
        let (tx, mut rx) = mpsc::channel(8);
        let mut timer = ViewTimer::new(tx);

        for v in 0..5u64 {
            timer.reset(View(v), Duration::from_millis(50));
        }
        assert_eq!(timer.armed_for(), Some(View(4)));

        time::advance(Duration::from_millis(60)).await;

        let fired = rx.recv().await.unwrap();
        assert_eq!(fired, View(4));
        // Channel must be empty — only the final view fires.
        assert!(rx.try_recv().is_err());
    }
}
