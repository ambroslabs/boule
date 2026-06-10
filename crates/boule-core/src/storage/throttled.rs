use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

use super::{Lsn, Storage, Wal, WalIter, WriteBatch};

pub struct ThrottledStorage {
    inner: Arc<dyn Storage>,
    write_delay: Duration,
}

impl ThrottledStorage {
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
