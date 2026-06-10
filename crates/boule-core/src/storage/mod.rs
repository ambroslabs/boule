#![allow(dead_code)]
pub mod disk;
pub mod memory;
pub mod throttled;

use bytes::Bytes;

#[allow(unused_imports)]
pub use disk::{DiskStorage, DiskWal};
#[allow(unused_imports)]
pub use memory::{MemoryStorage, MemoryWal};
#[allow(unused_imports)]
pub use throttled::{ThrottledStorage, ThrottledWal};

pub type WalIter<'a> = Box<dyn Iterator<Item = anyhow::Result<(Lsn, Bytes)>> + Send + 'a>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Lsn(u64);

impl Lsn {
    pub const ZERO: Lsn = Lsn(0);

    pub fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub fn raw(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for Lsn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "lsn:{}", self.0)
    }
}

pub trait Storage: Send + Sync {
    fn get(&self, key: &[u8]) -> anyhow::Result<Option<Bytes>>;

    fn put(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()>;

    fn delete(&self, key: &[u8]) -> anyhow::Result<()>;

    fn scan_prefix(&self, prefix: &[u8]) -> anyhow::Result<Vec<(Bytes, Bytes)>>;

    fn apply_batch(&self, batch: WriteBatch) -> anyhow::Result<()>;

    fn compare_and_swap(
        &self,
        key: &[u8],
        expected: Option<&[u8]>,
        new: Option<&[u8]>,
    ) -> anyhow::Result<bool>;
}

pub trait StorageExt: Storage {
    fn batch<F>(&self, f: F) -> anyhow::Result<()>
    where
        F: FnOnce(&mut WriteBatch) -> anyhow::Result<()>,
    {
        let mut batch = WriteBatch::default();
        f(&mut batch)?;
        self.apply_batch(batch)
    }
}

impl<S: Storage + ?Sized> StorageExt for S {}

#[derive(Default, Debug)]
pub struct WriteBatch {
    pub(crate) ops: Vec<WriteOp>,
}

#[derive(Debug)]
pub enum WriteOp {
    Put(Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
}

impl WriteBatch {
    pub fn put(&mut self, key: &[u8], value: &[u8]) {
        self.ops.push(WriteOp::Put(key.to_vec(), value.to_vec()));
    }

    pub fn delete(&mut self, key: &[u8]) {
        self.ops.push(WriteOp::Delete(key.to_vec()));
    }

    pub fn ops(&self) -> &[WriteOp] {
        &self.ops
    }

    pub fn len(&self) -> usize {
        self.ops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

pub trait Wal: Send + Sync {
    fn append(&self, entry: &[u8]) -> anyhow::Result<Lsn>;

    fn flush(&self) -> anyhow::Result<()>;

    fn iter_from(&self, lsn: Lsn) -> anyhow::Result<WalIter<'_>>;

    fn truncate_before(&self, lsn: Lsn) -> anyhow::Result<()>;
}
