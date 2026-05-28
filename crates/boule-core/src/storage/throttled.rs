//! Throttled [`Storage`] / [`Wal`] adapters that delay every write by a
//! configurable wall-clock duration. The deterministic-sim back-pressure
//! tests in #163 / #496 use these to exercise the "consensus blocks
//! when storage is slow, never drops persists" property of the
//! safety-action loop.
//!
//! # Why wall-clock?
//!
//! The [`Storage`] trait is sync. Tokio's virtual clock
//! (`tokio::time::pause()`) is async — there's no way to advance virtual
//! time from inside a synchronous trait impl without rewriting the trait
//! and every caller. Wall-clock `std::thread::sleep` is the path of
//! least resistance: tests that use it run in real time and accept
//! larger wall-clock budgets (still well under the project's
//! 15-second-per-test cap).
//!
//! # Threading
//!
//! Under tokio's `current_thread` runtime (which the sim uses), a
//! `std::thread::sleep` inside a `Storage::put` blocks the executor for
//! the entire delay. That is in fact what we want to model: under
//! production, a slow disk backs the consensus event loop up because
//! `apply_safety_actions` calls `persist_updates` synchronously. The
//! sim should reproduce the same shape.
//!
//! # Reads vs. writes
//!
//! Only the *write* paths are throttled (`put`, `delete`, `apply_batch`,
//! `compare_and_swap`, WAL `append` + `flush`). Reads (`get`,
//! `scan_prefix`, `iter_from`) pass through unmodified — back-pressure
//! tests care about the persist-blocks-consensus shape, and a slow
//! reader is a different failure class.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

use super::{Lsn, Storage, Wal, WalIter, WriteBatch};

/// Wraps an [`Arc<dyn Storage>`] and inserts `write_delay` of
/// `std::thread::sleep` before every mutating call. Construct via
/// [`ThrottledStorage::new`]; `Arc<ThrottledStorage>` implements
/// [`Storage`] so it can stand in anywhere `Arc<dyn Storage>` is
/// expected.
pub struct ThrottledStorage {
    inner: Arc<dyn Storage>,
    write_delay: Duration,
}

impl ThrottledStorage {
    /// Wrap `inner` and delay every write by `write_delay`. Reads pass
    /// through unchanged.
    pub fn new(inner: Arc<dyn Storage>, write_delay: Duration) -> Self {
        Self { inner, write_delay }
    }
}

impl Storage for ThrottledStorage {
    fn get(&self, key: &[u8]) -> anyhow::Result<Option<Bytes>> {
        self.inner.get(key)
    }

    fn put(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
        std::thread::sleep(self.write_delay);
        self.inner.put(key, value)
    }

    fn delete(&self, key: &[u8]) -> anyhow::Result<()> {
        std::thread::sleep(self.write_delay);
        self.inner.delete(key)
    }

    fn scan_prefix(&self, prefix: &[u8]) -> anyhow::Result<Vec<(Bytes, Bytes)>> {
        self.inner.scan_prefix(prefix)
    }

    fn apply_batch(&self, batch: WriteBatch) -> anyhow::Result<()> {
        std::thread::sleep(self.write_delay);
        self.inner.apply_batch(batch)
    }

    fn compare_and_swap(
        &self,
        key: &[u8],
        expected: Option<&[u8]>,
        new: Option<&[u8]>,
    ) -> anyhow::Result<bool> {
        std::thread::sleep(self.write_delay);
        self.inner.compare_and_swap(key, expected, new)
    }
}

/// WAL counterpart of [`ThrottledStorage`]. Delays `append` + `flush` by
/// the configured duration; iteration is unmodified.
pub struct ThrottledWal {
    inner: Arc<dyn Wal>,
    write_delay: Duration,
}

impl ThrottledWal {
    pub fn new(inner: Arc<dyn Wal>, write_delay: Duration) -> Self {
        Self { inner, write_delay }
    }
}

impl Wal for ThrottledWal {
    fn append(&self, entry: &[u8]) -> anyhow::Result<Lsn> {
        std::thread::sleep(self.write_delay);
        self.inner.append(entry)
    }

    fn flush(&self) -> anyhow::Result<()> {
        std::thread::sleep(self.write_delay);
        self.inner.flush()
    }

    fn iter_from(&self, lsn: Lsn) -> anyhow::Result<WalIter<'_>> {
        self.inner.iter_from(lsn)
    }

    fn truncate_before(&self, lsn: Lsn) -> anyhow::Result<()> {
        std::thread::sleep(self.write_delay);
        self.inner.truncate_before(lsn)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::storage::{MemoryStorage, MemoryWal, StorageExt};

    #[test]
    fn put_blocks_for_at_least_the_configured_delay() {
        let inner: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let throttled = ThrottledStorage::new(Arc::clone(&inner), Duration::from_millis(50));

        let start = Instant::now();
        throttled.put(b"key", b"value").unwrap();
        let elapsed = start.elapsed();

        assert!(
            elapsed >= Duration::from_millis(50),
            "put should block ≥ 50ms, observed {elapsed:?}",
        );
        // Sanity: the value actually landed.
        assert_eq!(inner.get(b"key").unwrap().unwrap().as_ref(), b"value");
    }

    #[test]
    fn get_is_not_throttled() {
        // Reads must remain fast — the slow-disk shape we model only
        // back-pressures consensus on writes (persist-before-send).
        let inner: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        inner.put(b"key", b"value").unwrap();
        let throttled = ThrottledStorage::new(Arc::clone(&inner), Duration::from_secs(60));

        let start = Instant::now();
        let got = throttled.get(b"key").unwrap();
        let elapsed = start.elapsed();

        assert_eq!(got.unwrap().as_ref(), b"value");
        assert!(
            elapsed < Duration::from_millis(100),
            "get should not be throttled, observed {elapsed:?}",
        );
    }

    #[test]
    fn apply_batch_blocks_for_the_configured_delay() {
        let inner: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let throttled = ThrottledStorage::new(Arc::clone(&inner), Duration::from_millis(50));

        let start = Instant::now();
        throttled
            .batch(|b| {
                b.put(b"k1", b"v1");
                b.put(b"k2", b"v2");
                Ok(())
            })
            .unwrap();
        let elapsed = start.elapsed();

        assert!(
            elapsed >= Duration::from_millis(50),
            "apply_batch should block ≥ 50ms, observed {elapsed:?}",
        );
        // Both writes landed atomically under the inner backend.
        assert_eq!(inner.get(b"k1").unwrap().unwrap().as_ref(), b"v1");
        assert_eq!(inner.get(b"k2").unwrap().unwrap().as_ref(), b"v2");
    }

    #[test]
    fn wal_append_blocks_for_the_configured_delay() {
        let inner: Arc<dyn Wal> = Arc::new(MemoryWal::new());
        let throttled = ThrottledWal::new(Arc::clone(&inner), Duration::from_millis(50));

        let start = Instant::now();
        let lsn = throttled.append(b"entry").unwrap();
        let elapsed = start.elapsed();

        assert!(
            elapsed >= Duration::from_millis(50),
            "wal append should block ≥ 50ms, observed {elapsed:?}",
        );
        assert_eq!(lsn, Lsn::from_raw(1));
    }
}
