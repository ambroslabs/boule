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
//! - `wal_entries`, keyed by the raw `u64` LSN, value is `[checksum:8][payload]`.
//!   The 8-byte prefix is a SHA-256 of the payload truncated to its first 8
//!   bytes; `iter_from` recomputes and verifies it on every read so a bit
//!   flip inside a payload page that escapes redb's per-page xxhash3
//!   surfaces as a storage error rather than as a confused decode at the
//!   consensus layer (issue #233).
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
//!
//! # Corruption detection
//!
//! `redb` writes per-page xxhash3 checksums on commit but does **not**
//! verify them on normal reads (only during the post-crash repair scan and
//! the explicit [`redb::Database::check_integrity`] call). To catch a
//! tampered or bit-flipped page that nonetheless deserializes cleanly,
//! `DiskStorage::open` calls `check_integrity` once at startup (the
//! HotStuff control-plane KV is small enough that a full scan is cheap)
//! and `DiskWal` wraps each entry with its own 8-byte checksum that's
//! verified per-read in [`DiskWal::iter_from`].

use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use parking_lot::Mutex;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use sha2::{Digest, Sha256};

use super::{Lsn, Storage, Wal, WalIter, WriteBatch, WriteOp};

/// Length of the per-WAL-entry checksum prefix.
const WAL_CHECKSUM_LEN: usize = 8;

/// 8-byte WAL-entry checksum: SHA-256 of `payload` truncated to its first
/// 8 bytes. SHA-256 is overkill for tamper detection here (we're guarding
/// against bit flips, not adversarial collisions — the page is on local
/// disk), but `sha2` is already a dependency and ~1 µs per typical
/// entry on modern hardware is comfortably below consensus's per-step
/// budget. See `WAL_CHECKSUM_LEN` for the prefix length.
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

// ── DiskStorage ────────────────────────────────────────────────────────────

pub struct DiskStorage {
    db: Arc<Database>,
}

impl DiskStorage {
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let mut db = Database::create(path.as_ref())?;
        // Defense-in-depth (issue #233): redb writes a per-page xxhash3 on
        // commit but does not verify it on normal reads. The KV file holds
        // HotStuff's control-plane state (last-voted view, locked QC,
        // high QC, plus the blocks they reference) — bounded in size by
        // design, so a full integrity scan at startup is cheap. This
        // catches a flipped byte deep in a redb page before it can surface
        // as a malformed-payload error at the consensus layer.
        //
        // Returns `Ok(true)` if the file was already clean, `Ok(false)` if
        // redb had to repair it from a torn write — both are acceptable
        // post-conditions; any actual corruption surfaces as `Err`.
        let _was_clean = db.check_integrity()?;
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

    fn compare_and_swap(
        &self,
        key: &[u8],
        expected: Option<&[u8]>,
        new: Option<&[u8]>,
    ) -> anyhow::Result<bool> {
        // redb serializes write transactions, so the entire read-compare-write
        // below is linearizable against concurrent writers without any extra
        // locking. On mismatch we drop the txn (abort) instead of committing,
        // skipping the fsync on the hot "someone else won the race" path.
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
            // Prepend an 8-byte SHA-256-truncated checksum of the payload
            // to each entry. iter_from verifies it on every read so a
            // bit-flipped page that escapes redb's per-page xxhash3
            // surfaces as a storage-layer Err. See module-level
            // "Corruption detection" docs and issue #233.
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
            let raw = v.value();
            // Verify the per-entry checksum prepended on flush. A mismatch
            // means redb returned a value that was tampered with after
            // commit but before this read — typically a bit flip deep in
            // a payload page that escaped redb's per-page xxhash3 (which
            // is only verified during repair, not on every read).
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

    // ── CAS tests ──────────────────────────────────────────────────────────

    #[test]
    fn cas_succeeds_when_expected_matches_and_sets_new_value() {
        let tmp = TempDir::new().unwrap();
        let s = DiskStorage::open(tmp.path().join("kv.redb")).unwrap();
        s.put(b"k", b"old").unwrap();
        let swapped = s
            .compare_and_swap(b"k", Some(b"old"), Some(b"new"))
            .unwrap();
        assert!(swapped);
        assert_eq!(s.get(b"k").unwrap().as_deref(), Some(&b"new"[..]));
    }

    #[test]
    fn cas_succeeds_when_expected_is_none_and_key_absent_and_sets_new_value() {
        let tmp = TempDir::new().unwrap();
        let s = DiskStorage::open(tmp.path().join("kv.redb")).unwrap();
        let swapped = s.compare_and_swap(b"k", None, Some(b"v")).unwrap();
        assert!(swapped);
        assert_eq!(s.get(b"k").unwrap().as_deref(), Some(&b"v"[..]));
    }

    #[test]
    fn cas_fails_when_expected_is_some_but_key_absent() {
        let tmp = TempDir::new().unwrap();
        let s = DiskStorage::open(tmp.path().join("kv.redb")).unwrap();
        let swapped = s.compare_and_swap(b"k", Some(b"v"), Some(b"new")).unwrap();
        assert!(!swapped);
        assert_eq!(s.get(b"k").unwrap(), None);
    }

    #[test]
    fn cas_fails_when_expected_is_none_but_key_present() {
        let tmp = TempDir::new().unwrap();
        let s = DiskStorage::open(tmp.path().join("kv.redb")).unwrap();
        s.put(b"k", b"existing").unwrap();
        let swapped = s.compare_and_swap(b"k", None, Some(b"new")).unwrap();
        assert!(!swapped);
        assert_eq!(s.get(b"k").unwrap().as_deref(), Some(&b"existing"[..]));
    }

    #[test]
    fn cas_fails_when_expected_does_not_match_current() {
        let tmp = TempDir::new().unwrap();
        let s = DiskStorage::open(tmp.path().join("kv.redb")).unwrap();
        s.put(b"k", b"actual").unwrap();
        let swapped = s
            .compare_and_swap(b"k", Some(b"different"), Some(b"new"))
            .unwrap();
        assert!(!swapped);
        assert_eq!(s.get(b"k").unwrap().as_deref(), Some(&b"actual"[..]));
    }

    #[test]
    fn cas_deletes_key_when_new_is_none_and_expected_matches() {
        let tmp = TempDir::new().unwrap();
        let s = DiskStorage::open(tmp.path().join("kv.redb")).unwrap();
        s.put(b"k", b"v").unwrap();
        let swapped = s.compare_and_swap(b"k", Some(b"v"), None).unwrap();
        assert!(swapped);
        assert_eq!(s.get(b"k").unwrap(), None);
    }

    #[test]
    fn cas_noop_when_expected_and_new_are_both_none_and_key_absent() {
        let tmp = TempDir::new().unwrap();
        let s = DiskStorage::open(tmp.path().join("kv.redb")).unwrap();
        let swapped = s.compare_and_swap(b"k", None, None).unwrap();
        assert!(swapped);
        assert_eq!(s.get(b"k").unwrap(), None);
    }

    #[test]
    fn cas_does_not_modify_state_on_mismatch() {
        let tmp = TempDir::new().unwrap();
        let s = DiskStorage::open(tmp.path().join("kv.redb")).unwrap();
        s.put(b"k", b"v0").unwrap();
        s.put(b"other", b"untouched").unwrap();
        let swapped = s
            .compare_and_swap(b"k", Some(b"wrong"), Some(b"v1"))
            .unwrap();
        assert!(!swapped);
        assert_eq!(s.get(b"k").unwrap().as_deref(), Some(&b"v0"[..]));
        assert_eq!(s.get(b"other").unwrap().as_deref(), Some(&b"untouched"[..]));
    }

    #[test]
    fn cas_via_arc_dyn_storage() {
        let tmp = TempDir::new().unwrap();
        let s: Arc<dyn Storage> = Arc::new(DiskStorage::open(tmp.path().join("kv.redb")).unwrap());
        s.put(b"k", b"v").unwrap();
        assert!(s.compare_and_swap(b"k", Some(b"v"), Some(b"v2")).unwrap());
    }

    #[test]
    fn cas_is_atomic_vs_concurrent_writers() {
        // Modest thread/iter count: every disk CAS fsyncs on success, so
        // contention is a real cost here. Enough to catch a broken
        // serialization contract without slowing down the suite.
        const THREADS: usize = 4;
        const ITERS_PER_THREAD: u64 = 50;
        let tmp = TempDir::new().unwrap();
        let s = Arc::new(DiskStorage::open(tmp.path().join("kv.redb")).unwrap());
        s.put(b"counter", &0u64.to_be_bytes()).unwrap();

        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let s = Arc::clone(&s);
                std::thread::spawn(move || {
                    for _ in 0..ITERS_PER_THREAD {
                        loop {
                            let current = s.get(b"counter").unwrap().unwrap();
                            let mut buf = [0u8; 8];
                            buf.copy_from_slice(&current);
                            let n = u64::from_be_bytes(buf);
                            let next = (n + 1).to_be_bytes();
                            if s.compare_and_swap(b"counter", Some(&current), Some(&next))
                                .unwrap()
                            {
                                break;
                            }
                        }
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let final_bytes = s.get(b"counter").unwrap().unwrap();
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&final_bytes);
        assert_eq!(u64::from_be_bytes(buf), (THREADS as u64) * ITERS_PER_THREAD,);
    }

    #[test]
    fn disk_cas_survives_reopen() {
        // Regression guard: a successful CAS must actually commit so the
        // value survives a clean close/reopen.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("kv.redb");

        let s = DiskStorage::open(&path).unwrap();
        s.put(b"k", b"v0").unwrap();
        assert!(s.compare_and_swap(b"k", Some(b"v0"), Some(b"v1")).unwrap());
        drop(s);

        let s = DiskStorage::open(&path).unwrap();
        assert_eq!(s.get(b"k").unwrap().as_deref(), Some(&b"v1"[..]));
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

    const CRASH_MODE: &str = "BOULE_STORAGE_CRASH_MODE";
    const CRASH_DB_PATH: &str = "BOULE_STORAGE_CRASH_DB_PATH";

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

    #[test]
    fn storage_cas_is_durable_across_crash() {
        let test_name = "storage::disk::tests::storage_cas_is_durable_across_crash";
        if let Ok(_mode) = env::var(CRASH_MODE) {
            // Child: seed a key, run a successful CAS, then abort. The CAS'd
            // value must survive (parity with apply_batch durability).
            let path = env::var(CRASH_DB_PATH).unwrap();
            let s = DiskStorage::open(&path).unwrap();
            s.put(b"k", b"v0").unwrap();
            let swapped = s.compare_and_swap(b"k", Some(b"v0"), Some(b"v1")).unwrap();
            assert!(swapped);
            std::process::abort();
        }

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("kv.redb");
        let status = spawn_crash_child(test_name, "after_cas", &path);
        assert!(!status.success(), "child should have aborted");

        let s = DiskStorage::open(&path).unwrap();
        assert_eq!(s.get(b"k").unwrap().as_deref(), Some(&b"v1"[..]));
    }

    // ── Disk-full / corruption / SIGKILL audits (issue #136) ──────────────
    //
    // These tests exercise the failure modes the persist-before-send
    // invariant in `consensus::node::apply_safety_actions` ultimately
    // depends on:
    //
    //   - ENOSPC: when the underlying filesystem can't accept the write,
    //     `flush` / `apply_batch` must surface the error rather than
    //     silently dropping data. The consensus loop propagates that error
    //     up and the node exits — fail-stop is the correct safety
    //     behavior.
    //   - SIGKILL mid-write: even if the process dies during a redb
    //     commit, the next reopen must observe a contiguous prefix of
    //     LSNs (the god-byte protocol guarantees the previous commit slot
    //     remains valid).
    //   - Corruption: a flipped byte or truncated tail must either be
    //     repaired transparently by redb or produce a clear error on
    //     open / read — never silently change recovered state.
    //
    // ENOSPC and SIGKILL tests use the child-process re-exec pattern
    // already established for the abort-based crash tests; corruption
    // tests do not need a child since they manipulate the file in-place
    // after a clean close.

    const CRASH_MARKER_PATH: &str = "BOULE_STORAGE_CRASH_MARKER_PATH";

    #[cfg(unix)]
    #[test]
    fn wal_disk_full_returns_error_and_preserves_durable_prefix() {
        // ENOSPC / EFBIG audit: every flush that returned `Ok` is durable;
        // a flush that returns `Err` does not silently advance state.
        //
        // The child sets `RLIMIT_FSIZE` to a value just above redb's
        // initial allocation, ignores `SIGXFSZ` (so writes that exceed
        // the limit return `EFBIG` instead of killing the process), then
        // appends + flushes 8 KiB payloads one at a time, recording the
        // last successfully flushed LSN to the marker file. When `flush`
        // finally errors, the child exits 0; the parent reopens the WAL
        // and asserts the recovered LSNs are exactly `1..=last_durable`.
        let test_name =
            "storage::disk::tests::wal_disk_full_returns_error_and_preserves_durable_prefix";

        if env::var(CRASH_MODE).is_ok() {
            disk_full_child();
            return;
        }

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("wal.redb");
        let marker = tmp.path().join("marker");
        let status = Command::new(env::current_exe().unwrap())
            .env(CRASH_MODE, "disk_full")
            .env(CRASH_DB_PATH, &path)
            .env(CRASH_MARKER_PATH, &marker)
            .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
            .status()
            .expect("failed to spawn disk-full child");
        assert!(
            status.success(),
            "child must observe a flush error and exit cleanly (got {status:?})",
        );

        let last_durable: u64 = std::fs::read_to_string(&marker)
            .expect("child should have written the marker before flush failed")
            .trim()
            .parse()
            .expect("marker must be a number");
        assert!(
            last_durable >= 1,
            "child must have flushed at least one entry before hitting ENOSPC (got {last_durable})",
        );

        let w = DiskWal::open(&path).expect("WAL must reopen cleanly after ENOSPC");
        let entries: Vec<_> = w
            .iter_from(Lsn::ZERO)
            .unwrap()
            .collect::<anyhow::Result<Vec<_>>>()
            .unwrap();
        let recovered: Vec<u64> = entries.iter().map(|(l, _)| l.raw()).collect();
        let expected: Vec<u64> = (1..=last_durable).collect();
        assert_eq!(
            recovered, expected,
            "recovered LSNs must equal the contiguous prefix of fully-flushed LSNs",
        );
    }

    #[cfg(unix)]
    fn disk_full_child() {
        // 64 KiB payload + 4 MiB ceiling: redb's initial layout is ~1 MiB;
        // we'll get a few flushes through before hitting EFBIG.
        const PAYLOAD_BYTES: usize = 64 * 1024;
        const FILE_SIZE_LIMIT: u64 = 4 * 1024 * 1024;
        // Hard cap the loop so a future redb that grows past the limit
        // gracefully (e.g. via compression) doesn't hang the test forever.
        const MAX_ITERS: u64 = 10_000;

        let path = env::var(CRASH_DB_PATH).unwrap();
        let marker_path = env::var(CRASH_MARKER_PATH).unwrap();

        // SAFETY: setrlimit / signal are ffi syscalls with simple integer
        // arguments and no aliasing concerns. The signal handler is
        // installed once before any flush; no other thread or signal path
        // touches SIGXFSZ in this test.
        unsafe {
            let lim = libc::rlimit {
                rlim_cur: FILE_SIZE_LIMIT,
                rlim_max: FILE_SIZE_LIMIT,
            };
            assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &lim), 0);
            // Ignore SIGXFSZ so the over-limit write returns EFBIG to
            // userspace instead of killing the process (the default
            // disposition).
            libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
        }

        // Seed the marker with 0 so the parent always finds a file (even
        // if the very first flush errors).
        std::fs::write(&marker_path, "0").unwrap();

        let w = DiskWal::open(&path).expect("WAL must open before rlimit kicks in");
        let payload = vec![0xABu8; PAYLOAD_BYTES];
        for i in 1..=MAX_ITERS {
            w.append(&payload)
                .expect("append is in-memory and cannot fail");
            match w.flush() {
                Ok(()) => {
                    std::fs::write(&marker_path, i.to_string()).unwrap();
                }
                Err(_) => {
                    // Surfaced cleanly. Done.
                    std::process::exit(0);
                }
            }
        }
        panic!("never hit ENOSPC after {MAX_ITERS} iterations — increase payload or lower limit");
    }

    #[cfg(unix)]
    #[test]
    fn storage_disk_full_returns_error_for_apply_batch() {
        // Same audit as the WAL test, but for the kv-store batch path
        // that consensus's `persist_updates` actually uses.
        let test_name = "storage::disk::tests::storage_disk_full_returns_error_for_apply_batch";

        if env::var(CRASH_MODE).is_ok() {
            storage_disk_full_child();
            return;
        }

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("kv.redb");
        let marker = tmp.path().join("marker");
        let status = Command::new(env::current_exe().unwrap())
            .env(CRASH_MODE, "storage_disk_full")
            .env(CRASH_DB_PATH, &path)
            .env(CRASH_MARKER_PATH, &marker)
            .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
            .status()
            .expect("failed to spawn storage disk-full child");
        assert!(
            status.success(),
            "child must observe an apply_batch error and exit cleanly (got {status:?})",
        );

        let last_durable: u64 = std::fs::read_to_string(&marker)
            .expect("child should have written the marker before apply_batch failed")
            .trim()
            .parse()
            .expect("marker must be a number");
        assert!(
            last_durable >= 1,
            "child must have committed at least one batch"
        );

        let s = DiskStorage::open(&path).expect("storage must reopen cleanly after ENOSPC");
        for i in 1..=last_durable {
            let key = format!("k{i:08}");
            assert!(
                s.get(key.as_bytes()).unwrap().is_some(),
                "key {key} from a successful batch must survive",
            );
        }
    }

    #[cfg(unix)]
    fn storage_disk_full_child() {
        const PAYLOAD_BYTES: usize = 64 * 1024;
        const FILE_SIZE_LIMIT: u64 = 4 * 1024 * 1024;
        const MAX_ITERS: u64 = 10_000;

        let path = env::var(CRASH_DB_PATH).unwrap();
        let marker_path = env::var(CRASH_MARKER_PATH).unwrap();

        // SAFETY: see disk_full_child().
        unsafe {
            let lim = libc::rlimit {
                rlim_cur: FILE_SIZE_LIMIT,
                rlim_max: FILE_SIZE_LIMIT,
            };
            assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &lim), 0);
            libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
        }

        std::fs::write(&marker_path, "0").unwrap();

        let s = DiskStorage::open(&path).expect("storage must open before rlimit kicks in");
        let payload = vec![0xCDu8; PAYLOAD_BYTES];
        for i in 1..=MAX_ITERS {
            let key = format!("k{i:08}");
            let res = s.batch(|b| {
                b.put(key.as_bytes(), &payload);
                Ok(())
            });
            match res {
                Ok(()) => {
                    std::fs::write(&marker_path, i.to_string()).unwrap();
                }
                Err(_) => std::process::exit(0),
            }
        }
        panic!("never hit ENOSPC after {MAX_ITERS} iterations");
    }

    #[cfg(unix)]
    #[test]
    fn wal_opens_cleanly_after_sigkill_during_writes() {
        // Partial-write audit: a SIGKILL while the WAL is in the middle
        // of `flush()` (the only path that hits redb commit) must not
        // corrupt the file. The next open must succeed and surface a
        // contiguous prefix of LSNs whose count is at least the
        // last-marker'd LSN the child reported (it may be larger if a
        // commit slot flipped in the kernel after the marker write).
        let test_name = "storage::disk::tests::wal_opens_cleanly_after_sigkill_during_writes";

        if env::var(CRASH_MODE).is_ok() {
            sigkill_child();
            return;
        }

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("wal.redb");
        let marker = tmp.path().join("marker");
        let mut child = Command::new(env::current_exe().unwrap())
            .env(CRASH_MODE, "sigkill_during_writes")
            .env(CRASH_DB_PATH, &path)
            .env(CRASH_MARKER_PATH, &marker)
            .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("failed to spawn sigkill child");

        // Poll the marker rather than sleeping a fixed interval.
        // Child needs ~100-300ms to spin up the test runner + open
        // redb in debug builds; once it's flushing, the marker
        // updates on every successful flush. Kill as soon as we
        // see a few flushes, keeping wall-clock low and avoiding
        // a sleep that's too short on a loaded machine.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut observed: u64 = 0;
        while std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(50));
            if let Ok(s) = std::fs::read_to_string(&marker)
                && let Ok(n) = s.trim().parse::<u64>()
            {
                observed = n;
                if n >= 5 {
                    break;
                }
            }
        }
        child.kill().expect("kill should succeed");
        let _ = child.wait();

        let last_durable: u64 = std::fs::read_to_string(&marker)
            .expect("child should have written at least the seed marker")
            .trim()
            .parse()
            .expect("marker must be a number");
        assert!(
            last_durable >= 1,
            "child should have flushed at least once (poll observed {observed}, marker={last_durable})",
        );

        let w = DiskWal::open(&path).expect("WAL must reopen cleanly after SIGKILL");
        let entries: Vec<_> = w
            .iter_from(Lsn::ZERO)
            .unwrap()
            .collect::<anyhow::Result<Vec<_>>>()
            .unwrap();
        let recovered: Vec<u64> = entries.iter().map(|(l, _)| l.raw()).collect();

        for (idx, &lsn) in recovered.iter().enumerate() {
            assert_eq!(
                lsn,
                (idx as u64) + 1,
                "recovered LSNs must form a contiguous prefix starting at 1",
            );
        }
        assert!(
            (recovered.len() as u64) >= last_durable,
            "recovered count ({}) must be >= last marker'd LSN ({})",
            recovered.len(),
            last_durable,
        );
    }

    #[cfg(unix)]
    fn sigkill_child() {
        let path = env::var(CRASH_DB_PATH).unwrap();
        let marker_path = env::var(CRASH_MARKER_PATH).unwrap();

        // Seed so the parent always finds the marker file even if SIGKILL
        // hits before the first flush.
        write_marker_atomically(&marker_path, "0").unwrap();

        let w = DiskWal::open(&path).unwrap();
        for i in 1u64.. {
            w.append(format!("entry-{i}").as_bytes()).unwrap();
            w.flush().unwrap();
            // Best-effort marker; an intervening SIGKILL is the whole point,
            // so `_ =` rather than `.unwrap()`. The write is atomic (temp +
            // rename) so a SIGKILL mid-write can never leave the parent a
            // torn value to parse.
            let _ = write_marker_atomically(&marker_path, &i.to_string());
        }
    }

    /// Write `value` to `marker_path` atomically: stage it in a sibling temp
    /// file, then `rename()` it into place. rename is atomic on a single
    /// filesystem, so a reader (the parent) only ever observes the previous
    /// complete value or the new complete value — never a partial write left
    /// behind by a SIGKILL that lands mid-`write`.
    #[cfg(unix)]
    fn write_marker_atomically(marker_path: &str, value: &str) -> std::io::Result<()> {
        let tmp = format!("{marker_path}.tmp");
        std::fs::write(&tmp, value)?;
        std::fs::rename(&tmp, marker_path)
    }

    #[test]
    fn wal_open_rejects_garbled_header() {
        // Corruption audit, level 1: a flipped byte in the redb file
        // header (the very first page, which holds the magic bytes,
        // the layout, and the god-byte) must be caught at open. This
        // is the strongest corruption-detection guarantee redb gives
        // us: if the WAL is corrupt, the node will refuse to start.
        use std::io::{Read, Seek, SeekFrom, Write};

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("wal.redb");

        let w = DiskWal::open(&path).unwrap();
        for i in 0..16u32 {
            w.append(format!("entry-{i}").as_bytes()).unwrap();
        }
        w.flush().unwrap();
        drop(w);

        // Corrupt several bytes inside the magic-number / header
        // region at offset 0. A single-byte flip is enough in
        // practice (the magic number check fails), but we flip a
        // small range to be robust to future redb header layout
        // changes.
        {
            let mut f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            f.seek(SeekFrom::Start(0)).unwrap();
            let mut buf = [0u8; 16];
            f.read_exact(&mut buf).unwrap();
            for b in &mut buf {
                *b ^= 0xFF;
            }
            f.seek(SeekFrom::Start(0)).unwrap();
            f.write_all(&buf).unwrap();
            f.sync_all().unwrap();
        }

        // Open MUST fail — either with `Err` or by panicking from
        // inside redb (we accept both as "fail-loud"; the operator
        // sees the node refuse to start). Silently returning an
        // empty/recovered WAL would be a safety bug.
        let result = std::panic::catch_unwind(|| DiskWal::open(&path));
        if let Ok(Ok(_)) = result {
            panic!("DiskWal::open must reject a header-corrupted file (got Ok)");
        }
    }

    #[test]
    fn wal_open_after_random_garbage_overwrite_does_not_silently_succeed() {
        // Corruption audit, level 2: overwrite the entire file with
        // a deterministic-but-invalid pattern. redb's magic-number
        // and layout checks should reject it at open; no path should
        // return a wrongly-recovered set of entries.
        use std::io::{Seek, SeekFrom, Write};

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("wal.redb");

        let w = DiskWal::open(&path).unwrap();
        for i in 0..16u32 {
            w.append(format!("entry-{i}").as_bytes()).unwrap();
        }
        w.flush().unwrap();
        drop(w);

        let len = std::fs::metadata(&path).unwrap().len();
        {
            let mut f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            f.seek(SeekFrom::Start(0)).unwrap();
            let garbage: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            f.write_all(&garbage).unwrap();
            f.sync_all().unwrap();
        }

        let result = std::panic::catch_unwind(|| DiskWal::open(&path));
        if let Ok(Ok(_)) = result {
            panic!("DiskWal::open must reject a fully overwritten file");
        }
    }

    #[test]
    fn wal_iter_detects_byte_flip_inside_payload_data_page() {
        // Issue #233 regression: a flipped byte deep inside a *payload*
        // data page (not the header / god-byte region) used to silently
        // round-trip through `iter_from`. redb writes a per-page xxhash3
        // on commit but only verifies it during the post-crash repair
        // scan / explicit `check_integrity`, never on a normal read. The
        // per-entry checksum prepended on flush is the read-time backstop
        // — without it, the consensus layer would catch the corruption
        // later as a malformed-message decode error, which is much harder
        // to diagnose as "storage corrupted".
        use std::io::{Read, Seek, SeekFrom, Write};

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("wal.redb");

        // Use a long, distinctive marker as the payload so we can locate
        // it byte-for-byte in the on-disk file. 0xAB is unlikely to
        // appear naturally in redb's b-tree pointers / page metadata.
        let marker_payload: Vec<u8> = vec![0xABu8; 4096];

        let w = DiskWal::open(&path).unwrap();
        w.append(&marker_payload).unwrap();
        w.flush().unwrap();
        drop(w);

        // Locate the payload in the on-disk file and flip a byte well
        // inside its interior (not at the boundaries, where a future
        // redb layout change might overlap framing bytes).
        let bytes = std::fs::read(&path).unwrap();
        let pos = bytes
            .windows(marker_payload.len())
            .position(|w| w == marker_payload.as_slice())
            .expect("payload must appear verbatim in the on-disk WAL file");
        let flip_at = pos + marker_payload.len() / 2;

        {
            let mut f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            f.seek(SeekFrom::Start(flip_at as u64)).unwrap();
            let mut byte = [0u8; 1];
            f.read_exact(&mut byte).unwrap();
            byte[0] ^= 0x01;
            f.seek(SeekFrom::Start(flip_at as u64)).unwrap();
            f.write_all(&byte).unwrap();
            f.sync_all().unwrap();
        }

        // Open succeeds (the redb structural pages are intact). The
        // corruption MUST surface when iter_from reads the entry and
        // recomputes the checksum — either as `iter_from` returning
        // `Err`, or as the iterator yielding `Err` on the bad row.
        let w = DiskWal::open(&path).expect("structural redb open should still succeed");
        let result: anyhow::Result<Vec<_>> = w.iter_from(Lsn::ZERO).and_then(|it| it.collect());
        assert!(
            result.is_err(),
            "iter_from must surface the flipped payload byte as an Err (got Ok)",
        );
    }

    #[test]
    fn storage_open_check_integrity_accepts_clean_file() {
        // The check_integrity() call we added on DiskStorage::open
        // (issue #233) must not regress the happy path — a cleanly
        // closed file must reopen successfully and surface its
        // committed contents.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("kv.redb");

        let s = DiskStorage::open(&path).unwrap();
        s.put(b"k", b"v").unwrap();
        s.batch(|b| {
            b.put(b"a", b"1");
            b.put(b"b", b"2");
            Ok(())
        })
        .unwrap();
        drop(s);

        let s = DiskStorage::open(&path).expect("clean reopen with integrity check");
        assert_eq!(s.get(b"k").unwrap().as_deref(), Some(&b"v"[..]));
        assert_eq!(s.get(b"a").unwrap().as_deref(), Some(&b"1"[..]));
        assert_eq!(s.get(b"b").unwrap().as_deref(), Some(&b"2"[..]));
    }

    /// One-off benchmark backing the open-time cost claim for
    /// `Database::check_integrity()` (issue #233). Gated with `#[ignore]`
    /// so it does not run on CI;
    /// invoke explicitly via:
    ///
    /// ```sh
    /// cargo test --release --lib storage::disk::tests::bench_check_integrity \
    ///     -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore]
    fn bench_check_integrity_open_cost() {
        use std::time::Instant;

        for n in [10usize, 100, 1_000, 10_000] {
            let tmp = TempDir::new().unwrap();
            let path = tmp.path().join("kv.redb");

            let s = DiskStorage::open(&path).unwrap();
            let block_payload = vec![0xCDu8; 1024];
            for i in 0..n {
                let key = format!("blocks/{i:08}");
                s.batch(|b| {
                    b.put(key.as_bytes(), &block_payload);
                    Ok(())
                })
                .unwrap();
            }
            s.put(b"last_voted_view", &42u64.to_be_bytes()).unwrap();
            s.put(b"locked_qc_hash", &[0xABu8; 32]).unwrap();
            s.put(b"high_qc_hash", &[0xCDu8; 32]).unwrap();
            drop(s);

            let size_bytes = std::fs::metadata(&path).unwrap().len();
            let start = Instant::now();
            let s = DiskStorage::open(&path).unwrap();
            let elapsed = start.elapsed();
            drop(s);

            eprintln!(
                "n={n:>6} blocks  file_size={size_bytes:>10}  open_with_integrity={elapsed:?}",
            );
        }
    }

    #[test]
    fn storage_open_check_integrity_detects_payload_page_corruption() {
        // Issue #233: a flipped byte inside a redb data page that
        // happens to land in the KV file (not the header) used to
        // round-trip silently through `get` / `scan_prefix`. With
        // `check_integrity()` on open, redb walks every page and
        // verifies its xxhash3, so the corruption surfaces at startup.
        use std::io::{Read, Seek, SeekFrom, Write};

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("kv.redb");

        let s = DiskStorage::open(&path).unwrap();
        // Use a distinctive value pattern we can locate in the file.
        let marker: Vec<u8> = vec![0xCDu8; 4096];
        s.put(b"k", &marker).unwrap();
        drop(s);

        let bytes = std::fs::read(&path).unwrap();
        let pos = bytes
            .windows(marker.len())
            .position(|w| w == marker.as_slice())
            .expect("value must appear verbatim in the on-disk KV file");
        let flip_at = pos + marker.len() / 2;

        {
            let mut f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            f.seek(SeekFrom::Start(flip_at as u64)).unwrap();
            let mut byte = [0u8; 1];
            f.read_exact(&mut byte).unwrap();
            byte[0] ^= 0x01;
            f.seek(SeekFrom::Start(flip_at as u64)).unwrap();
            f.write_all(&byte).unwrap();
            f.sync_all().unwrap();
        }

        // check_integrity() must reject the file. Either Err from open
        // or a panic from inside redb is acceptable — both fail loud.
        let result = std::panic::catch_unwind(|| DiskStorage::open(&path));
        if let Ok(Ok(_)) = result {
            panic!("DiskStorage::open must reject a payload-byte-flipped file (got Ok)");
        }
    }
}
