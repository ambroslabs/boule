use std::time::Duration;

pub trait TimeoutPolicy: Send + Sync {
    fn timeout(&self, consecutive_failures: u32) -> Duration;
}

#[derive(Debug, Clone, Copy)]
pub struct ExponentialBackoff {
    base: Duration,
    max: Duration,
}

impl ExponentialBackoff {
    pub fn new(base: Duration, max: Duration) -> Self {
        debug_assert!(base <= max, "ExponentialBackoff requires base <= max");
        Self { base, max }
    }
}

impl TimeoutPolicy for ExponentialBackoff {
    fn timeout(&self, consecutive_failures: u32) -> Duration {
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
