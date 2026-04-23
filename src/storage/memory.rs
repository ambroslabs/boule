//! In-memory implementations of [`Storage`] and [`Wal`] for tests and the
//! deterministic simulator.

use std::collections::BTreeMap;
use std::sync::RwLock;

use bytes::Bytes;

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
        Ok(self.inner.read().unwrap().get(key).cloned())
    }

    fn put(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
        self.inner
            .write()
            .unwrap()
            .insert(key.to_vec(), Bytes::copy_from_slice(value));
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> anyhow::Result<()> {
        self.inner.write().unwrap().remove(key);
        Ok(())
    }

    fn scan_prefix(&self, prefix: &[u8]) -> anyhow::Result<Vec<(Bytes, Bytes)>> {
        let map = self.inner.read().unwrap();
        Ok(map
            .range(prefix.to_vec()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (Bytes::copy_from_slice(k), v.clone()))
            .collect())
    }

    fn apply_batch(&self, batch: WriteBatch) -> anyhow::Result<()> {
        // Hold the write lock across all ops so concurrent readers see the
        // batch as an atomic snapshot.
        let mut map = self.inner.write().unwrap();
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
}

pub struct MemoryWal {
    inner: RwLock<WalInner>,
}

struct WalInner {
    next_lsn: u64,
    // Append-only, ordered by LSN by construction.
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
        let mut inner = self.inner.write().unwrap();
        inner.next_lsn += 1;
        let lsn = Lsn(inner.next_lsn);
        inner.entries.push((lsn, Bytes::copy_from_slice(entry)));
        Ok(lsn)
    }

    fn flush(&self) -> anyhow::Result<()> {
        // Nothing to fsync — entries are already observable. The in-memory
        // WAL trivially satisfies the durability contract because there is
        // no buffering layer below `append`.
        Ok(())
    }

    fn iter_from(&self, lsn: Lsn) -> anyhow::Result<WalIter<'_>> {
        let inner = self.inner.read().unwrap();
        // Snapshot into a Vec so the iterator doesn't hold the lock.
        let start = inner.entries.partition_point(|(l, _)| *l < lsn);
        let snapshot: Vec<(Lsn, Bytes)> = inner.entries[start..].to_vec();
        Ok(Box::new(snapshot.into_iter().map(Ok)))
    }

    fn truncate_before(&self, lsn: Lsn) -> anyhow::Result<()> {
        let mut inner = self.inner.write().unwrap();
        let cut = inner.entries.partition_point(|(l, _)| *l < lsn);
        inner.entries.drain(..cut);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::storage::StorageExt;

    // ── Storage tests ──────────────────────────────────────────────────────

    #[test]
    fn put_get_round_trip() {
        let s = MemoryStorage::new();
        s.put(b"k1", b"v1").unwrap();
        s.put(b"k2", b"v2").unwrap();
        assert_eq!(s.get(b"k1").unwrap().as_deref(), Some(&b"v1"[..]));
        assert_eq!(s.get(b"k2").unwrap().as_deref(), Some(&b"v2"[..]));
        assert_eq!(s.get(b"missing").unwrap(), None);
    }

    #[test]
    fn delete_removes_key() {
        let s = MemoryStorage::new();
        s.put(b"k", b"v").unwrap();
        s.delete(b"k").unwrap();
        assert_eq!(s.get(b"k").unwrap(), None);
        // Idempotent.
        s.delete(b"k").unwrap();
    }

    #[test]
    fn scan_prefix_returns_only_matching_keys_in_order() {
        let s = MemoryStorage::new();
        // Deliberately insert out of order.
        for (k, v) in [
            ("consensus/b", "B"),
            ("other/x", "X"),
            ("consensus/a", "A"),
            ("consensus/c", "C"),
            ("consensut", "boundary"),
        ] {
            s.put(k.as_bytes(), v.as_bytes()).unwrap();
        }

        let hits = s.scan_prefix(b"consensus/").unwrap();
        let keys: Vec<&[u8]> = hits.iter().map(|(k, _)| k.as_ref()).collect();
        assert_eq!(
            keys,
            vec![
                b"consensus/a".as_ref(),
                b"consensus/b".as_ref(),
                b"consensus/c".as_ref(),
            ]
        );
        // "consensut" shares "consensu" but not "consensus/", must be excluded.
        assert!(hits.iter().all(|(k, _)| k.starts_with(b"consensus/")));
    }

    #[test]
    fn scan_prefix_empty_prefix_returns_all() {
        let s = MemoryStorage::new();
        s.put(b"a", b"1").unwrap();
        s.put(b"b", b"2").unwrap();
        assert_eq!(s.scan_prefix(b"").unwrap().len(), 2);
    }

    #[test]
    fn batch_applies_all_ops_on_ok() {
        let s = MemoryStorage::new();
        s.put(b"existing", b"old").unwrap();

        s.batch(|b| {
            b.put(b"new", b"val");
            b.delete(b"existing");
            Ok(())
        })
        .unwrap();

        assert_eq!(s.get(b"new").unwrap().as_deref(), Some(&b"val"[..]));
        assert_eq!(s.get(b"existing").unwrap(), None);
    }

    #[test]
    fn batch_applies_nothing_when_closure_errors() {
        let s = MemoryStorage::new();
        s.put(b"existing", b"old").unwrap();

        let res: anyhow::Result<()> = s.batch(|b| {
            b.put(b"new", b"val");
            b.delete(b"existing");
            anyhow::bail!("user aborted");
        });
        assert!(res.is_err());
        // Pre-batch state is intact.
        assert_eq!(s.get(b"new").unwrap(), None);
        assert_eq!(s.get(b"existing").unwrap().as_deref(), Some(&b"old"[..]));
    }

    #[test]
    fn batch_is_atomic_for_concurrent_readers() {
        // Invariant: at any observable moment, either both keys are in their
        // pre-batch state, or both are in their post-batch state. A reader
        // must never see one updated and the other not.
        let s = Arc::new(MemoryStorage::new());
        s.put(b"a", b"0").unwrap();
        s.put(b"b", b"0").unwrap();

        let writer = {
            let s = Arc::clone(&s);
            std::thread::spawn(move || {
                for i in 1..200u32 {
                    let val = i.to_string();
                    let val_bytes = val.as_bytes();
                    s.batch(|b| {
                        b.put(b"a", val_bytes);
                        b.put(b"b", val_bytes);
                        Ok(())
                    })
                    .unwrap();
                }
            })
        };

        let reader = {
            let s = Arc::clone(&s);
            std::thread::spawn(move || {
                for _ in 0..500 {
                    // scan_prefix takes a single read lock, so a and b come
                    // from the same snapshot.
                    let hits = s.scan_prefix(b"").unwrap();
                    let a = hits.iter().find(|(k, _)| k.as_ref() == b"a").unwrap();
                    let b = hits.iter().find(|(k, _)| k.as_ref() == b"b").unwrap();
                    assert_eq!(a.1, b.1, "atomic batch should keep a and b in lockstep");
                }
            })
        };

        writer.join().unwrap();
        reader.join().unwrap();
    }

    #[test]
    fn storage_is_object_safe_via_arc_dyn() {
        // Compile-time check: the call site consensus will use.
        fn use_it(s: &dyn Storage) -> anyhow::Result<()> {
            s.put(b"k", b"v")?;
            s.batch(|b| {
                b.put(b"x", b"1");
                Ok(())
            })?;
            Ok(())
        }
        let s: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        use_it(&*s).unwrap();
    }

    // ── Wal tests ──────────────────────────────────────────────────────────

    #[test]
    fn append_assigns_strictly_monotonic_lsns_starting_above_zero() {
        let w = MemoryWal::new();
        let a = w.append(b"one").unwrap();
        let b = w.append(b"two").unwrap();
        let c = w.append(b"three").unwrap();
        assert!(a > Lsn::ZERO);
        assert!(a < b && b < c);
        // First LSN is 1 by construction.
        assert_eq!(a.raw(), 1);
    }

    #[test]
    fn iter_from_zero_yields_all_entries_in_order() {
        let w = MemoryWal::new();
        for payload in [b"a".as_ref(), b"bb", b"ccc"] {
            w.append(payload).unwrap();
        }
        let collected: Vec<(Lsn, Bytes)> = w
            .iter_from(Lsn::ZERO)
            .unwrap()
            .collect::<anyhow::Result<_>>()
            .unwrap();
        assert_eq!(collected.len(), 3);
        assert_eq!(collected[0].1.as_ref(), b"a");
        assert_eq!(collected[1].1.as_ref(), b"bb");
        assert_eq!(collected[2].1.as_ref(), b"ccc");
        // LSNs strictly increasing.
        assert!(collected[0].0 < collected[1].0);
        assert!(collected[1].0 < collected[2].0);
    }

    #[test]
    fn iter_from_midpoint_starts_at_that_lsn() {
        let w = MemoryWal::new();
        let _l1 = w.append(b"a").unwrap();
        let l2 = w.append(b"b").unwrap();
        let _l3 = w.append(b"c").unwrap();

        let from_l2: Vec<_> = w
            .iter_from(l2)
            .unwrap()
            .collect::<anyhow::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(from_l2.len(), 2);
        assert_eq!(from_l2[0].0, l2);
        assert_eq!(from_l2[0].1.as_ref(), b"b");
        assert_eq!(from_l2[1].1.as_ref(), b"c");
    }

    #[test]
    fn iter_from_beyond_last_lsn_is_empty() {
        let w = MemoryWal::new();
        let last = w.append(b"x").unwrap();
        let beyond = Lsn(last.raw() + 1);
        let tail: Vec<_> = w
            .iter_from(beyond)
            .unwrap()
            .collect::<anyhow::Result<Vec<_>>>()
            .unwrap();
        assert!(tail.is_empty());
    }

    #[test]
    fn truncate_before_drops_earlier_and_keeps_later() {
        let w = MemoryWal::new();
        let _l1 = w.append(b"a").unwrap();
        let _l2 = w.append(b"b").unwrap();
        let l3 = w.append(b"c").unwrap();
        let _l4 = w.append(b"d").unwrap();

        w.truncate_before(l3).unwrap();

        let remaining: Vec<_> = w
            .iter_from(Lsn::ZERO)
            .unwrap()
            .collect::<anyhow::Result<Vec<_>>>()
            .unwrap();
        let payloads: Vec<&[u8]> = remaining.iter().map(|(_, v)| v.as_ref()).collect();
        assert_eq!(payloads, vec![b"c".as_ref(), b"d".as_ref()]);
    }

    #[test]
    fn truncate_before_zero_is_noop() {
        let w = MemoryWal::new();
        w.append(b"a").unwrap();
        w.append(b"b").unwrap();
        w.truncate_before(Lsn::ZERO).unwrap();
        let n = w
            .iter_from(Lsn::ZERO)
            .unwrap()
            .collect::<anyhow::Result<Vec<_>>>()
            .unwrap()
            .len();
        assert_eq!(n, 2);
    }

    #[test]
    fn append_preserves_lsn_monotonicity_after_truncate() {
        // Truncation must not reset the LSN counter: later appends must
        // still produce LSNs strictly greater than any previously returned
        // LSN, even ones we just dropped.
        let w = MemoryWal::new();
        let _l1 = w.append(b"a").unwrap();
        let l2 = w.append(b"b").unwrap();
        w.truncate_before(l2).unwrap();
        let l3 = w.append(b"c").unwrap();
        assert!(l3 > l2);
    }

    #[test]
    fn flush_is_callable_and_idempotent() {
        let w = MemoryWal::new();
        w.flush().unwrap();
        w.append(b"x").unwrap();
        w.flush().unwrap();
        w.flush().unwrap();
    }

    #[test]
    fn wal_is_object_safe_via_arc_dyn() {
        fn use_it(w: &dyn Wal) -> anyhow::Result<Lsn> {
            let l = w.append(b"entry")?;
            w.flush()?;
            Ok(l)
        }
        let w: Arc<dyn Wal> = Arc::new(MemoryWal::new());
        let l = use_it(&*w).unwrap();
        assert!(l > Lsn::ZERO);
    }
}
