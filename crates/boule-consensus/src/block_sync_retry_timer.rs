#![allow(dead_code)]
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::sleep;

pub const DEFAULT_INITIAL_DELAY: Duration = Duration::from_millis(200);

pub const DEFAULT_MAX_DELAY: Duration = Duration::from_millis(2_000);

pub struct BlockSyncRetryTimer {
    fired_tx: mpsc::Sender<()>,

    current: Option<JoinHandle<()>>,
}

impl BlockSyncRetryTimer {
    pub fn new(fired_tx: mpsc::Sender<()>) -> Self {
        Self {
            fired_tx,
            current: None,
        }
    }

    pub fn arm(&mut self, duration: Duration) {
        self.cancel();
        let tx = self.fired_tx.clone();
        let handle = tokio::spawn(async move {
            sleep(duration).await;

            let _ = tx.send(()).await;
        });
        self.current = Some(handle);
    }

    pub fn cancel(&mut self) {
        if let Some(handle) = self.current.take() {
            handle.abort();
        }
    }

    pub fn is_armed(&self) -> bool {
        self.current.is_some()
    }
}

impl Drop for BlockSyncRetryTimer {
    fn drop(&mut self) {
        self.cancel();
    }
}

pub fn next_delay(prior: Option<Duration>, initial: Duration, max: Duration) -> Duration {
    match prior {
        None => initial.min(max),
        Some(p) => p.saturating_mul(2).min(max),
    }
}
