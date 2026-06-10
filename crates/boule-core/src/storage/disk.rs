use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use parking_lot::Mutex;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use sha2::{Digest, Sha256};

use super::{Lsn, Storage, Wal, WalIter, WriteBatch, WriteOp};

const WAL_CHECKSUM_LEN: usize = 8;

fn wal_checksum(payload: &[u8]) -> [u8; WAL_CHECKSUM_LEN] {
    let digest = Sha256::digest(payload);
    let mut out = [0u8; WAL_CHECKSUM_LEN];
    out.copy_from_slice(&digest[..WAL_CHECKSUM_LEN]);
    out
}

const KV_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("kv");
const WAL_ENTRIES: TableDefinition<u64, &[u8]> = TableDefinition::new("wal_entries");
const WAL_META: TableDefinition<&str, u64> = TableDefinition::new("wal_meta");

const META_NEXT_LSN: &str = "next_lsn";

pub struct DiskStorage {
    db: Arc<Database>,
}

impl DiskStorage {
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let mut db = Database::create(path.as_ref())?;

        let _was_clean = db.check_integrity()?;

        let txn = db.begin_write()?;
        {
            let _ = txn.open_table(KV_TABLE)?;
        }
        txn.commit()?;
        Ok(Self { db: Arc::new(db) })
    }
}

impl Storage for DiskStorage {
    fn get(&self, key: &[u8]) -> anyhow::Result<Option<Bytes>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(KV_TABLE)?;
        Ok(table.get(key)?.map(|g| Bytes::copy_from_slice(g.value())))
    }

    fn put(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(KV_TABLE)?;
            table.insert(key, value)?;
        }
        txn.commit()?;
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> anyhow::Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(KV_TABLE)?;
            table.remove(key)?;
        }
        txn.commit()?;
        Ok(())
    }

    fn scan_prefix(&self, prefix: &[u8]) -> anyhow::Result<Vec<(Bytes, Bytes)>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(KV_TABLE)?;
        let mut out = Vec::new();
        for row in table.range(prefix..)? {
            let (k, v) = row?;
            let key = k.value();
            if !key.starts_with(prefix) {
                break;
            }
            out.push((
                Bytes::copy_from_slice(key),
                Bytes::copy_from_slice(v.value()),
            ));
        }
        Ok(out)
    }

    fn apply_batch(&self, batch: WriteBatch) -> anyhow::Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(KV_TABLE)?;
            for op in batch.ops {
                match op {
                    WriteOp::Put(k, v) => {
                        table.insert(k.as_slice(), v.as_slice())?;
                    }
                    WriteOp::Delete(k) => {
                        table.remove(k.as_slice())?;
                    }
                }
            }
        }
        txn.commit()?;
        Ok(())
    }

    fn compare_and_swap(
        &self,
        key: &[u8],
        expected: Option<&[u8]>,
        new: Option<&[u8]>,
    ) -> anyhow::Result<bool> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(KV_TABLE)?;
            let current = table.get(key)?;
            let current_bytes: Option<&[u8]> = current.as_ref().map(|g| g.value());
            if current_bytes != expected {
                return Ok(false);
            }
            drop(current);
            match new {
                Some(v) => {
                    table.insert(key, v)?;
                }
                None => {
                    table.remove(key)?;
                }
            }
        }
        txn.commit()?;
        Ok(true)
    }
}

pub struct DiskWal {
    db: Arc<Database>,
    state: Mutex<WalState>,
}

struct WalState {
    next_lsn: u64,

    buffer: Vec<(Lsn, Bytes)>,
}

impl DiskWal {
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let db = Database::create(path.as_ref())?;

        {
            let txn = db.begin_write()?;
            {
                let _ = txn.open_table(WAL_ENTRIES)?;
                let _ = txn.open_table(WAL_META)?;
            }
            txn.commit()?;
        }

        let next_lsn = {
            let txn = db.begin_read()?;
            let meta = txn.open_table(WAL_META)?;
            if let Some(g) = meta.get(META_NEXT_LSN)? {
                g.value()
            } else {
                let entries = txn.open_table(WAL_ENTRIES)?;
                match entries.last()? {
                    Some((k, _)) => k.value().saturating_add(1),
                    None => 1,
                }
            }
        };

        Ok(Self {
            db: Arc::new(db),
            state: Mutex::new(WalState {
                next_lsn,
                buffer: Vec::new(),
            }),
        })
    }
}

impl Wal for DiskWal {
    fn append(&self, entry: &[u8]) -> anyhow::Result<Lsn> {
        let mut state = self.state.lock();
        let lsn = Lsn::from_raw(state.next_lsn);
        state.next_lsn += 1;
        state.buffer.push((lsn, Bytes::copy_from_slice(entry)));
        Ok(lsn)
    }

    fn flush(&self) -> anyhow::Result<()> {
        let (to_flush, target_next_lsn) = {
            let state = self.state.lock();
            if state.buffer.is_empty() {
                return Ok(());
            }
            (state.buffer.clone(), state.next_lsn)
        };

        let txn = self.db.begin_write()?;
        {
            let mut entries = txn.open_table(WAL_ENTRIES)?;

            let mut buf: Vec<u8> = Vec::new();
            for (lsn, payload) in &to_flush {
                let checksum = wal_checksum(payload);
                buf.clear();
                buf.reserve(WAL_CHECKSUM_LEN + payload.len());
                buf.extend_from_slice(&checksum);
                buf.extend_from_slice(payload);
                entries.insert(lsn.raw(), buf.as_slice())?;
            }
        }
        {
            let mut meta = txn.open_table(WAL_META)?;
            meta.insert(META_NEXT_LSN, target_next_lsn)?;
        }
        txn.commit()?;

        let mut state = self.state.lock();
        state.buffer.retain(|(lsn, _)| lsn.raw() >= target_next_lsn);
        Ok(())
    }

    fn iter_from(&self, lsn: Lsn) -> anyhow::Result<WalIter<'_>> {
        let mut out: Vec<(Lsn, Bytes)> = Vec::new();

        let txn = self.db.begin_read()?;
        let entries = txn.open_table(WAL_ENTRIES)?;
        for row in entries.range(lsn.raw()..)? {
            let (k, v) = row?;
            let raw = v.value();

            if raw.len() < WAL_CHECKSUM_LEN {
                anyhow::bail!(
                    "WAL entry at lsn={} is too short ({} bytes) to contain a checksum",
                    k.value(),
                    raw.len(),
                );
            }
            let (stored, payload) = raw.split_at(WAL_CHECKSUM_LEN);
            let computed = wal_checksum(payload);
            if stored != computed {
                anyhow::bail!(
                    "WAL entry at lsn={} failed checksum verification: storage corruption",
                    k.value(),
                );
            }
            out.push((Lsn::from_raw(k.value()), Bytes::copy_from_slice(payload)));
        }

        let buffer_snapshot = {
            let state = self.state.lock();
            state.buffer.clone()
        };
        for (l, b) in buffer_snapshot {
            if l >= lsn {
                out.push((l, b));
            }
        }

        out.sort_by_key(|(l, _)| *l);
        out.dedup_by_key(|(l, _)| *l);

        Ok(Box::new(out.into_iter().map(Ok)))
    }

    fn truncate_before(&self, lsn: Lsn) -> anyhow::Result<()> {
        if lsn == Lsn::ZERO {
            return Ok(());
        }

        let txn = self.db.begin_write()?;
        {
            let mut entries = txn.open_table(WAL_ENTRIES)?;
            let keys: Vec<u64> = entries
                .range(..lsn.raw())?
                .map(|r| r.map(|(k, _)| k.value()))
                .collect::<Result<Vec<_>, _>>()?;
            for k in keys {
                entries.remove(k)?;
            }
        }
        txn.commit()?;

        let mut state = self.state.lock();
        state.buffer.retain(|(l, _)| *l >= lsn);
        Ok(())
    }
}
