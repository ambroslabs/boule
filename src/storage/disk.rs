//! On-disk [`Storage`] and [`Wal`] implementations backed by `redb`.
//!
//! # Backend choice
//!
//! `redb` is pure Rust with no background threads and no compaction daemon,
//! giving us predictable tail latency — an important property for a
//! consensus node where a pause can look like a timeout. `redb` commits
//! default to `Durability::Immediate`, which fsyncs the underlying file
//! before returning.
//!
//! # Wal layout
//!
//! Two tables share the `Wal`'s database:
//! - `wal_entries`, keyed by the raw `u64` LSN, value is the opaque payload
//!   bytes.
//! - `wal_meta`, a small KV used only to persist `next_lsn` across reopens
//!   (so truncation that drops every entry doesn't reset the counter and
//!   violate LSN monotonicity across a reopen).
//!
//! # Buffering & flush semantics
//!
//! [`DiskWal::append`] buffers entries in memory; [`DiskWal::flush`] drains
//! the buffer into a single `redb` write transaction and commits (fsync).
//! Within a live process, [`DiskWal::iter_from`] observes both persisted
//! and buffered entries — across a crash, only flushed entries survive.

use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use parking_lot::Mutex;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use super::{Lsn, Storage, Wal, WalIter, WriteBatch, WriteOp};

const KV_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("kv");
const WAL_ENTRIES: TableDefinition<u64, &[u8]> = TableDefinition::new("wal_entries");
const WAL_META: TableDefinition<&str, u64> = TableDefinition::new("wal_meta");

const META_NEXT_LSN: &str = "next_lsn";

// ── DiskStorage ────────────────────────────────────────────────────────────

pub struct DiskStorage {
    db: Arc<Database>,
}

impl DiskStorage {
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let db = Database::create(path.as_ref())?;
        // Ensure the table exists so read transactions don't fail on a fresh db.
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
}

// ── DiskWal ────────────────────────────────────────────────────────────────

pub struct DiskWal {
    db: Arc<Database>,
    state: Mutex<WalState>,
}

struct WalState {
    next_lsn: u64,
    // Entries appended but not yet flushed. Sorted by LSN by construction.
    buffer: Vec<(Lsn, Bytes)>,
}

impl DiskWal {
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let db = Database::create(path.as_ref())?;

        // Initialize tables so subsequent reads never hit "table not found".
        {
            let txn = db.begin_write()?;
            {
                let _ = txn.open_table(WAL_ENTRIES)?;
                let _ = txn.open_table(WAL_META)?;
            }
            txn.commit()?;
        }

        // Recover next_lsn: meta wins; otherwise fall back to max persisted key + 1;
        // otherwise start at 1.
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

    /// For tests: the current in-memory `next_lsn`.
    #[cfg(test)]
    fn next_lsn_for_tests(&self) -> u64 {
        self.state.lock().next_lsn
    }

    #[cfg(test)]
    fn panic_holding_state_lock(&self) -> ! {
        let _guard = self.state.lock();
        panic!("intentional panic while holding WAL state mutex");
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
        // Snapshot what to flush under the lock without draining: if the commit
        // fails, we need to be able to retry. The target next_lsn is captured
        // alongside so subsequent appends that race with the commit don't get
        // written twice.
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
            for (lsn, payload) in &to_flush {
                entries.insert(lsn.raw(), payload.as_ref())?;
            }
        }
        {
            let mut meta = txn.open_table(WAL_META)?;
            meta.insert(META_NEXT_LSN, target_next_lsn)?;
        }
        txn.commit()?;

        // Success: drop the entries we just flushed, keeping any that were
        // appended while we were committing.
        let mut state = self.state.lock();
        state.buffer.retain(|(lsn, _)| lsn.raw() >= target_next_lsn);
        Ok(())
    }

    fn iter_from(&self, lsn: Lsn) -> anyhow::Result<WalIter<'_>> {
        // Snapshot both persisted and buffered entries into a single sorted Vec
        // so the returned iterator is self-contained and doesn't hold any
        // database or lock guards.
        let mut out: Vec<(Lsn, Bytes)> = Vec::new();

        let txn = self.db.begin_read()?;
        let entries = txn.open_table(WAL_ENTRIES)?;
        for row in entries.range(lsn.raw()..)? {
            let (k, v) = row?;
            out.push((Lsn::from_raw(k.value()), Bytes::copy_from_slice(v.value())));
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

        // Persisted rows come out sorted; buffered entries are strictly newer
        // than any persisted entry (LSNs are monotonic and only assigned on
        // append), so the combined vector is already sorted. A final sort is
        // cheap insurance against edge cases (e.g. a flush racing with this
        // read that ends up persisting an entry also present in our buffer
        // snapshot — dedup below handles that too).
        out.sort_by_key(|(l, _)| *l);
        out.dedup_by_key(|(l, _)| *l);

        Ok(Box::new(out.into_iter().map(Ok)))
    }

    fn truncate_before(&self, lsn: Lsn) -> anyhow::Result<()> {
        if lsn == Lsn::ZERO {
            return Ok(());
        }

        // Drop from persisted storage in a single transaction.
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

        // Drop matching entries from the in-memory buffer.
        let mut state = self.state.lock();
        state.buffer.retain(|(l, _)| *l >= lsn);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::process::Command;
    use std::sync::Arc;

    use tempfile::TempDir;

    use super::*;
    use crate::storage::StorageExt;

    // ── Unit tests: basic disk operations ─────────────────────────────────

    #[test]
    fn disk_storage_put_get_delete_round_trip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("kv.redb");
        let s = DiskStorage::open(&path).unwrap();

        s.put(b"k", b"v").unwrap();
        assert_eq!(s.get(b"k").unwrap().as_deref(), Some(&b"v"[..]));
        s.delete(b"k").unwrap();
        assert_eq!(s.get(b"k").unwrap(), None);
    }

    #[test]
    fn disk_storage_scan_prefix_respects_boundary() {
        let tmp = TempDir::new().unwrap();
        let s = DiskStorage::open(tmp.path().join("kv.redb")).unwrap();
        for (k, v) in [
            ("consensus/a", "A"),
            ("consensus/b", "B"),
            ("consensut", "boundary"),
            ("other", "X"),
        ] {
            s.put(k.as_bytes(), v.as_bytes()).unwrap();
        }
        let hits = s.scan_prefix(b"consensus/").unwrap();
        let keys: Vec<&[u8]> = hits.iter().map(|(k, _)| k.as_ref()).collect();
        assert_eq!(keys, vec![b"consensus/a".as_ref(), b"consensus/b".as_ref()]);
    }

    #[test]
    fn disk_storage_batch_commits_atomically() {
        let tmp = TempDir::new().unwrap();
        let s = DiskStorage::open(tmp.path().join("kv.redb")).unwrap();
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
    fn disk_storage_batch_closure_error_commits_nothing() {
        let tmp = TempDir::new().unwrap();
        let s = DiskStorage::open(tmp.path().join("kv.redb")).unwrap();
        s.put(b"existing", b"old").unwrap();

        let res: anyhow::Result<()> = s.batch(|b| {
            b.put(b"new", b"val");
            b.delete(b"existing");
            anyhow::bail!("user aborted");
        });
        assert!(res.is_err());
        assert_eq!(s.get(b"new").unwrap(), None);
        assert_eq!(s.get(b"existing").unwrap().as_deref(), Some(&b"old"[..]));
    }

    #[test]
    fn disk_storage_reopen_idempotency() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("kv.redb");

        let s = DiskStorage::open(&path).unwrap();
        s.put(b"k1", b"v1").unwrap();
        s.put(b"k2", b"v2").unwrap();
        drop(s);

        let s = DiskStorage::open(&path).unwrap();
        assert_eq!(s.get(b"k1").unwrap().as_deref(), Some(&b"v1"[..]));
        assert_eq!(s.get(b"k2").unwrap().as_deref(), Some(&b"v2"[..]));
    }

    // ── Unit tests: Wal basic behavior ────────────────────────────────────

    #[test]
    fn disk_wal_append_is_visible_to_same_process_before_flush() {
        let tmp = TempDir::new().unwrap();
        let w = DiskWal::open(tmp.path().join("wal.redb")).unwrap();
        let l1 = w.append(b"a").unwrap();
        let l2 = w.append(b"b").unwrap();
        assert_eq!(l1.raw(), 1);
        assert_eq!(l2.raw(), 2);

        let entries: Vec<_> = w
            .iter_from(Lsn::ZERO)
            .unwrap()
            .collect::<anyhow::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].1.as_ref(), b"a");
        assert_eq!(entries[1].1.as_ref(), b"b");
    }

    #[test]
    fn disk_wal_flushed_entries_survive_reopen() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("wal.redb");

        let w = DiskWal::open(&path).unwrap();
        w.append(b"x").unwrap();
        w.append(b"y").unwrap();
        w.flush().unwrap();
        drop(w);

        let w = DiskWal::open(&path).unwrap();
        let entries: Vec<_> = w
            .iter_from(Lsn::ZERO)
            .unwrap()
            .collect::<anyhow::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].1.as_ref(), b"x");
        assert_eq!(entries[1].1.as_ref(), b"y");
        // Next append must get an Lsn strictly greater than the last recovered one.
        let l3 = w.append(b"z").unwrap();
        assert_eq!(l3.raw(), 3);
    }

    #[test]
    fn disk_wal_unflushed_entries_are_lost_on_reopen() {
        // Clean reopen (no crash) — Drop before flush means the buffer is gone,
        // so nothing is recovered. This pins "flush is the durability barrier".
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("wal.redb");

        let w = DiskWal::open(&path).unwrap();
        w.append(b"gone").unwrap();
        drop(w);

        let w = DiskWal::open(&path).unwrap();
        let entries: Vec<_> = w
            .iter_from(Lsn::ZERO)
            .unwrap()
            .collect::<anyhow::Result<Vec<_>>>()
            .unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn disk_wal_truncate_before_drops_persisted_and_buffered() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("wal.redb");

        let w = DiskWal::open(&path).unwrap();
        let _l1 = w.append(b"a").unwrap();
        let l2 = w.append(b"b").unwrap();
        let _l3 = w.append(b"c").unwrap();
        w.flush().unwrap();
        // Add one more, unflushed.
        let _l4 = w.append(b"d").unwrap();

        w.truncate_before(l2).unwrap();

        let remaining: Vec<_> = w
            .iter_from(Lsn::ZERO)
            .unwrap()
            .collect::<anyhow::Result<Vec<_>>>()
            .unwrap();
        let payloads: Vec<&[u8]> = remaining.iter().map(|(_, v)| v.as_ref()).collect();
        assert_eq!(payloads, vec![b"b".as_ref(), b"c", b"d"]);
    }

    #[test]
    fn disk_wal_next_lsn_persists_across_total_truncation() {
        // If we append, flush, then truncate everything, reopen must NOT reset
        // next_lsn back to 1 — doing so would violate LSN monotonicity for a
        // restarted consensus replica whose peers may have observed higher LSNs.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("wal.redb");

        let w = DiskWal::open(&path).unwrap();
        w.append(b"a").unwrap();
        w.append(b"b").unwrap();
        w.flush().unwrap();
        w.truncate_before(Lsn::from_raw(100)).unwrap();
        drop(w);

        let w = DiskWal::open(&path).unwrap();
        assert_eq!(w.next_lsn_for_tests(), 3);
        let l = w.append(b"c").unwrap();
        assert_eq!(l.raw(), 3);
    }

    #[test]
    fn disk_wal_state_mutex_is_not_poisoned_after_panic() {
        // Regression test mirroring gossip's (#42 / PR #55): a thread that
        // panics while holding the WAL state mutex must not prevent subsequent
        // acquisition. `parking_lot::Mutex` provides this by construction;
        // this test pins it so a future regression back to `std::sync::Mutex`
        // (whose poisoning kills the WAL for the lifetime of the process,
        // violating HotStuff's `last_voted_view` / `locked_qc` safety
        // invariants) would fail loudly.
        let tmp = TempDir::new().unwrap();
        let w = Arc::new(DiskWal::open(tmp.path().join("wal.redb")).unwrap());

        let w_panic = Arc::clone(&w);
        let joined = std::thread::spawn(move || {
            w_panic.panic_holding_state_lock();
        })
        .join();
        assert!(joined.is_err(), "panic thread should have unwound");

        // A subsequent append from another thread must still succeed.
        let l = w.append(b"post-panic").unwrap();
        assert_eq!(l.raw(), 1);
        w.flush().unwrap();
        let entries: Vec<_> = w
            .iter_from(Lsn::ZERO)
            .unwrap()
            .collect::<anyhow::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1.as_ref(), b"post-panic");
    }

    #[test]
    fn disk_wal_is_object_safe_via_arc_dyn() {
        let tmp = TempDir::new().unwrap();
        let w: Arc<dyn Wal> = Arc::new(DiskWal::open(tmp.path().join("wal.redb")).unwrap());
        let l = w.append(b"entry").unwrap();
        w.flush().unwrap();
        assert!(l > Lsn::ZERO);
    }

    // ── Crash-safety harness ──────────────────────────────────────────────
    //
    // Pattern: each crash test runs in two modes.
    //
    //   1. Parent mode (no env var): spawns the test binary with the crash
    //      env vars set, asserts the child died non-zero, reopens the db
    //      files, and asserts the durability contract.
    //   2. Child mode (env var set): performs the write sequence and then
    //      `std::process::abort()`s to simulate a crash.
    //
    // We re-exec the test binary via `env::current_exe()` with `--exact
    // <test_name>` so only the target test runs in the child. The env-var
    // check is the very first thing the test does; the parent-mode logic
    // never runs in the child, preventing infinite recursion.

    const CRASH_MODE: &str = "AMBROS_STORAGE_CRASH_MODE";
    const CRASH_DB_PATH: &str = "AMBROS_STORAGE_CRASH_DB_PATH";

    fn spawn_crash_child(
        test_name: &str,
        mode: &str,
        db_path: &std::path::Path,
    ) -> std::process::ExitStatus {
        Command::new(env::current_exe().unwrap())
            .env(CRASH_MODE, mode)
            .env(CRASH_DB_PATH, db_path)
            .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
            .status()
            .expect("failed to spawn crash child")
    }

    #[test]
    fn wal_survives_crash_after_flush() {
        let test_name = "storage::disk::tests::wal_survives_crash_after_flush";
        if let Ok(_mode) = env::var(CRASH_MODE) {
            // Child: append, flush, abort. Flushed entries must survive.
            let path = env::var(CRASH_DB_PATH).unwrap();
            let w = DiskWal::open(&path).unwrap();
            for i in 0..5u32 {
                w.append(format!("entry-{i}").as_bytes()).unwrap();
            }
            w.flush().unwrap();
            std::process::abort();
        }

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("wal.redb");
        let status = spawn_crash_child(test_name, "after_flush", &path);
        assert!(!status.success(), "child should have aborted");

        let w = DiskWal::open(&path).unwrap();
        let entries: Vec<_> = w
            .iter_from(Lsn::ZERO)
            .unwrap()
            .collect::<anyhow::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(entries.len(), 5, "all 5 flushed entries must survive");
        for (i, (_, payload)) in entries.iter().enumerate() {
            assert_eq!(payload.as_ref(), format!("entry-{i}").as_bytes());
        }
    }

    #[test]
    fn wal_loses_unflushed_entries_on_crash() {
        let test_name = "storage::disk::tests::wal_loses_unflushed_entries_on_crash";
        if let Ok(_mode) = env::var(CRASH_MODE) {
            // Child: flush 3, append 5 more, abort WITHOUT flushing the extra 5.
            // Post-crash, only the first 3 must survive.
            let path = env::var(CRASH_DB_PATH).unwrap();
            let w = DiskWal::open(&path).unwrap();
            for i in 0..3u32 {
                w.append(format!("flushed-{i}").as_bytes()).unwrap();
            }
            w.flush().unwrap();
            for i in 0..5u32 {
                w.append(format!("unflushed-{i}").as_bytes()).unwrap();
            }
            std::process::abort();
        }

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("wal.redb");
        let status = spawn_crash_child(test_name, "before_flush", &path);
        assert!(!status.success(), "child should have aborted");

        let w = DiskWal::open(&path).unwrap();
        let entries: Vec<_> = w
            .iter_from(Lsn::ZERO)
            .unwrap()
            .collect::<anyhow::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(entries.len(), 3, "only flushed entries must survive");
        for (i, (_, payload)) in entries.iter().enumerate() {
            assert_eq!(payload.as_ref(), format!("flushed-{i}").as_bytes());
        }
        // After recovery, the next LSN resumes from last_flushed + 1. Unflushed
        // LSNs (4..=8) were never durable, so it's correct for them to be
        // reassigned — the durability contract only covers flushed entries.
        let l = w.append(b"post-crash").unwrap();
        assert_eq!(l.raw(), 4, "next LSN must resume from last_flushed + 1");
    }

    #[test]
    fn storage_batch_is_durable_across_crash() {
        let test_name = "storage::disk::tests::storage_batch_is_durable_across_crash";
        if let Ok(_mode) = env::var(CRASH_MODE) {
            // Child: apply a batch (which commits internally), then abort.
            // The batch must survive.
            let path = env::var(CRASH_DB_PATH).unwrap();
            let s = DiskStorage::open(&path).unwrap();
            s.batch(|b| {
                b.put(b"a", b"1");
                b.put(b"b", b"2");
                b.put(b"c", b"3");
                Ok(())
            })
            .unwrap();
            std::process::abort();
        }

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("kv.redb");
        let status = spawn_crash_child(test_name, "after_batch", &path);
        assert!(!status.success(), "child should have aborted");

        let s = DiskStorage::open(&path).unwrap();
        assert_eq!(s.get(b"a").unwrap().as_deref(), Some(&b"1"[..]));
        assert_eq!(s.get(b"b").unwrap().as_deref(), Some(&b"2"[..]));
        assert_eq!(s.get(b"c").unwrap().as_deref(), Some(&b"3"[..]));
    }

    #[test]
    fn storage_batch_closure_error_is_not_persisted_across_crash() {
        let test_name =
            "storage::disk::tests::storage_batch_closure_error_is_not_persisted_across_crash";
        if let Ok(_mode) = env::var(CRASH_MODE) {
            // Child: seed one key, then start a batch that errors mid-build
            // (so apply_batch is never called). Abort. Post-crash, the batch
            // must have had no effect; the seeded key remains.
            let path = env::var(CRASH_DB_PATH).unwrap();
            let s = DiskStorage::open(&path).unwrap();
            s.put(b"seed", b"original").unwrap();
            let _ = s.batch(|b| {
                b.put(b"seed", b"overwritten");
                b.put(b"new", b"val");
                anyhow::bail!("user aborted inside closure");
            });
            std::process::abort();
        }

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("kv.redb");
        let status = spawn_crash_child(test_name, "batch_closure_err", &path);
        assert!(!status.success(), "child should have aborted");

        let s = DiskStorage::open(&path).unwrap();
        assert_eq!(s.get(b"seed").unwrap().as_deref(), Some(&b"original"[..]));
        assert_eq!(s.get(b"new").unwrap(), None);
    }
}
