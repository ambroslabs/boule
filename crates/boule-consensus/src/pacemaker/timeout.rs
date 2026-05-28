//! Pluggable timeout policy for the HotStuff pacemaker.
//!
//! A [`TimeoutPolicy`] computes how long to wait in the current view
//! before declaring it failed, given how many *consecutive* prior views
//! timed out. The default [`ExponentialBackoff`] doubles the base duration
//! per consecutive failure up to a configured cap — fast recovery when
//! the cluster is healthy, bounded waits during sustained partitions.
//!
//! The trait is stateless on purpose: the pacemaker owns the failure
//! count and passes it in. One [`TimeoutPolicy`] instance can serve any
//! number of pacemakers without per-instance bookkeeping, and swapping a
//! policy doesn't require migrating state.

use std::time::Duration;

/// Given a count of consecutive failed views, return how long to wait in
/// the *next* view before declaring it failed too.
///
/// # Contract
///
/// - Pure: must not mutate state and must be safe to call from any thread.
/// - Total: must return a [`Duration`] for every `u32` input without
///   panicking, including `u32::MAX`.
/// - Monotonic (strongly recommended): `timeout(n)` should be
///   non-decreasing in `n`. The pacemaker's exponential backoff guarantee
///   — slow down when the cluster is flaky — depends on this.
pub trait TimeoutPolicy: Send + Sync {
    fn timeout(&self, consecutive_failures: u32) -> Duration;
}

/// `timeout(n) = min(max, base * 2^n)`, saturating on overflow.
///
/// With `base = 500 ms` and `max = 30 s`, a string of timeouts produces
/// 500 ms, 1 s, 2 s, 4 s, 8 s, 16 s, 30 s, 30 s, ....
#[derive(Debug, Clone, Copy)]
pub struct ExponentialBackoff {
    base: Duration,
    max: Duration,
}

impl ExponentialBackoff {
    /// `base` must not exceed `max` — otherwise the first call with
    /// `consecutive_failures = 0` would already be saturated at `max`,
    /// which is almost certainly a configuration mistake.
    pub fn new(base: Duration, max: Duration) -> Self {
        debug_assert!(base <= max, "ExponentialBackoff requires base <= max");
        Self { base, max }
    }
}

impl TimeoutPolicy for ExponentialBackoff {
    fn timeout(&self, consecutive_failures: u32) -> Duration {
        // Cap the shift at 32 so `1u64 << shift` can't overflow; beyond
        // that the factor has already grown past anything `base` can
        // scale to without saturating `max` anyway.
        let shift = consecutive_failures.min(32);
        let factor: u32 = 1u64
            .checked_shl(shift)
            .and_then(|f| u32::try_from(f).ok())
            .unwrap_or(u32::MAX);
        self.base
            .checked_mul(factor)
            .unwrap_or(self.max)
            .min(self.max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bo(base_ms: u64, max_ms: u64) -> ExponentialBackoff {
        ExponentialBackoff::new(
            Duration::from_millis(base_ms),
            Duration::from_millis(max_ms),
        )
    }

    #[test]
    fn zero_failures_returns_base() {
        let p = bo(500, 30_000);
        assert_eq!(p.timeout(0), Duration::from_millis(500));
    }

    #[test]
    fn doubles_each_step() {
        let p = bo(500, 30_000);
        assert_eq!(p.timeout(1), Duration::from_millis(1_000));
        assert_eq!(p.timeout(2), Duration::from_millis(2_000));
        assert_eq!(p.timeout(3), Duration::from_millis(4_000));
        assert_eq!(p.timeout(4), Duration::from_millis(8_000));
        assert_eq!(p.timeout(5), Duration::from_millis(16_000));
    }

    #[test]
    fn saturates_at_max() {
        let p = bo(500, 30_000);
        // 500 * 2^6 = 32_000 > 30_000 -> saturates at max.
        assert_eq!(p.timeout(6), Duration::from_millis(30_000));
        assert_eq!(p.timeout(10), Duration::from_millis(30_000));
    }

    #[test]
    fn extreme_failure_count_does_not_panic() {
        let p = bo(500, 30_000);
        assert_eq!(p.timeout(u32::MAX), Duration::from_millis(30_000));
    }

    #[test]
    fn base_equals_max_returns_max_for_every_input() {
        let p = bo(1_000, 1_000);
        for n in [0u32, 1, 5, 42, 10_000, u32::MAX] {
            assert_eq!(p.timeout(n), Duration::from_millis(1_000));
        }
    }

    #[test]
    fn timeout_is_monotonic_non_decreasing() {
        let p = bo(50, 10_000);
        let mut prev = Duration::ZERO;
        for n in 0..40u32 {
            let cur = p.timeout(n);
            assert!(cur >= prev, "non-monotonic at n={n}: {prev:?} -> {cur:?}");
            prev = cur;
        }
    }
}
