use std::collections::BTreeMap;

use bytes::Bytes;
use parking_lot::RwLock;

use super::{Lsn, Storage, Wal, WalIter, WriteBatch, WriteOp};

pub struct MemoryStorage {
    inner: RwLock<BTreeMap<Vec<u8>, Bytes>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(BTreeMap::new()),
        }
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl Storage for MemoryStorage {
    fn get(&self, key: &[u8]) -> anyhow::Result<Option<Bytes>> {
        Ok(self.inner.read().get(key).cloned())
    }

    fn put(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
        self.inner
            .write()
            .insert(key.to_vec(), Bytes::copy_from_slice(value));
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> anyhow::Result<()> {
        self.inner.write().remove(key);
        Ok(())
    }

    fn scan_prefix(&self, prefix: &[u8]) -> anyhow::Result<Vec<(Bytes, Bytes)>> {
        let map = self.inner.read();
        Ok(map
            .range(prefix.to_vec()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (Bytes::copy_from_slice(k), v.clone()))
            .collect())
    }

    fn apply_batch(&self, batch: WriteBatch) -> anyhow::Result<()> {
        let mut map = self.inner.write();
        for op in batch.ops {
            match op {
                WriteOp::Put(k, v) => {
                    map.insert(k, Bytes::from(v));
                }
                WriteOp::Delete(k) => {
                    map.remove(&k);
                }
            }
        }
        Ok(())
    }

    fn compare_and_swap(
        &self,
        key: &[u8],
        expected: Option<&[u8]>,
        new: Option<&[u8]>,
    ) -> anyhow::Result<bool> {
        let mut map = self.inner.write();
        let current: Option<&[u8]> = map.get(key).map(|b| b.as_ref());
        if current != expected {
            return Ok(false);
        }
        match new {
            Some(v) => {
                map.insert(key.to_vec(), Bytes::copy_from_slice(v));
            }
            None => {
                map.remove(key);
            }
        }
        Ok(true)
    }
}

pub struct MemoryWal {
    inner: RwLock<WalInner>,
}

struct WalInner {
    next_lsn: u64,

    entries: Vec<(Lsn, Bytes)>,
}

impl MemoryWal {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(WalInner {
                next_lsn: 0,
                entries: Vec::new(),
            }),
        }
    }
}

impl Default for MemoryWal {
    fn default() -> Self {
        Self::new()
    }
}

impl Wal for MemoryWal {
    fn append(&self, entry: &[u8]) -> anyhow::Result<Lsn> {
        let mut inner = self.inner.write();
        inner.next_lsn += 1;
        let lsn = Lsn(inner.next_lsn);
        inner.entries.push((lsn, Bytes::copy_from_slice(entry)));
        Ok(lsn)
    }

    fn flush(&self) -> anyhow::Result<()> {
        Ok(())
    }

    fn iter_from(&self, lsn: Lsn) -> anyhow::Result<WalIter<'_>> {
        let inner = self.inner.read();

        let start = inner.entries.partition_point(|(l, _)| *l < lsn);
        let snapshot: Vec<(Lsn, Bytes)> = inner.entries[start..].to_vec();
        Ok(Box::new(snapshot.into_iter().map(Ok)))
    }

    fn truncate_before(&self, lsn: Lsn) -> anyhow::Result<()> {
        let mut inner = self.inner.write();
        let cut = inner.entries.partition_point(|(l, _)| *l < lsn);
        inner.entries.drain(..cut);
        Ok(())
    }
}
