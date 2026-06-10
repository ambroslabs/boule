pub mod tokio_clock;

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

pub use tokio_clock::TokioClock;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait Clock: Send + Sync + 'static {
    fn now_wall(&self) -> chrono::DateTime<chrono::Utc>;

    #[allow(dead_code)]
    fn now_monotonic(&self) -> Duration;

    fn sleep(&self, dur: Duration) -> BoxFuture<'static, ()>;

    fn interval(&self, period: Duration) -> Box<dyn ClockInterval>;
}

pub trait ClockInterval: Send {
    fn tick(&mut self) -> BoxFuture<'_, ()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elapsed;

impl std::fmt::Display for Elapsed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("deadline elapsed")
    }
}

impl std::error::Error for Elapsed {}

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
