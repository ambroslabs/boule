//! Persistent state abstraction for consensus.
//!
//! HotStuff safety requires that a replica never forget its last-voted view
//! or its locked QC across crashes (see issue #20). This module defines two
//! object-safe traits that consensus will sit on top of:
//!
//! - [`Storage`]: a small KV surface for "control-plane state" — the pieces
//!   of state that mutate over time (last-voted view, locked QC). Callers
//!   group related writes into atomic batches via [`StorageExt::batch`].
//! - [`Wal`]: a thin append-only log for "log state" — blocks, decisions,
//!   anything the replica replays on startup. [`Wal::flush`] is the only
//!   durability barrier; [`Wal::append`] may buffer.
//!
//! Two backends ship here: [`memory`] for unit tests and the deterministic
//! simulator, and [`disk`] backed by `redb` for production. See the [`disk`]
//! module docs for the backend choice rationale and the crash-safety
//! guarantees it upholds.
//!
//! Both traits are consumed as `Arc<dyn Storage>` / `Arc<dyn Wal>`, matching
//! the `Clock` abstraction in [`crate::clock`] — backends are swapped at the
//! edges, not plumbed through generics.

// Traits and types defined here are consumed by future consensus milestones
// (#20 sub-tasks and beyond). Allow dead code until then, following the
// pattern established in `crypto/mod.rs`.
#![allow(dead_code)]

pub mod disk;
pub mod memory;
pub mod throttled;

use bytes::Bytes;

// Re-export the backends from the crate-root path. The `#[allow]` is needed
// because nothing in the binary consumes these yet; future consensus
// milestones will.
#[allow(unused_imports)]
pub use disk::{DiskStorage, DiskWal};
#[allow(unused_imports)]
pub use memory::{MemoryStorage, MemoryWal};
#[allow(unused_imports)]
pub use throttled::{ThrottledStorage, ThrottledWal};

/// A boxed iterator over WAL entries. Used in [`Wal::iter_from`].
pub type WalIter<'a> = Box<dyn Iterator<Item = anyhow::Result<(Lsn, Bytes)>> + Send + 'a>;

/// Log Sequence Number. Monotonically increasing, assigned by the WAL on
/// append. [`Lsn::ZERO`] is reserved to mean "before any appended entry"
/// and is the conventional argument to [`Wal::iter_from`] when replaying
/// the entire log.
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

/// Key-value storage for small, mutable "control-plane" state.
///
/// Implementations must be safe to share across threads. Single-key methods
/// (`put`, `delete`) are their own atomic unit; multi-key atomicity goes
/// through [`Storage::apply_batch`] (typically via the [`StorageExt::batch`]
/// closure helper).
pub trait Storage: Send + Sync {
    fn get(&self, key: &[u8]) -> anyhow::Result<Option<Bytes>>;

    fn put(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()>;

    fn delete(&self, key: &[u8]) -> anyhow::Result<()>;

    /// Return every `(key, value)` whose key begins with `prefix`, in
    /// ascending key order.
    fn scan_prefix(&self, prefix: &[u8]) -> anyhow::Result<Vec<(Bytes, Bytes)>>;

    /// Apply `batch` atomically: on `Ok`, every op is visible; on `Err`,
    /// no op is visible. Concurrent readers see either the pre-batch state
    /// or the post-batch state, never a partial one.
    fn apply_batch(&self, batch: WriteBatch) -> anyhow::Result<()>;

    /// Atomically compare-and-swap the value at `key`.
    ///
    /// Semantics:
    /// - `expected == None` succeeds only if the key is absent;
    ///   `expected == Some(v)` succeeds only if the current value is exactly `v`.
    /// - `new == None` deletes the key on success;
    ///   `new == Some(v)` writes `v` on success.
    ///
    /// Returns `Ok(true)` if the swap happened, or `Ok(false)` if `expected`
    /// did not match the current value (no change was made). `Err` is reserved
    /// for backend failures (I/O, corruption); a bare "expected mismatched"
    /// outcome is never an error.
    ///
    /// The entire read-compare-write is atomic: concurrent readers see either
    /// the pre-swap state or the post-swap state, never a partial one;
    /// concurrent writers are linearized against this call.
    ///
    /// The degenerate call `compare_and_swap(key, None, None)` against an
    /// absent key returns `Ok(true)` — the observed state already equals the
    /// desired state, so the condition is satisfied and no write is performed.
    ///
    /// The typical HotStuff use is guarding `last_voted_view` against a
    /// racing timeout path: only update the view if it matches the value we
    /// observed when we decided to vote.
    ///
    /// # Example
    ///
    /// ```
    /// use ambros_p2p::storage::{MemoryStorage, Storage};
    ///
    /// let store = MemoryStorage::new();
    /// store.put(b"view", &7u64.to_be_bytes()).unwrap();
    ///
    /// // Match: swap succeeds and the new value is observable.
    /// let ok = store
    ///     .compare_and_swap(b"view", Some(&7u64.to_be_bytes()), Some(&8u64.to_be_bytes()))
    ///     .unwrap();
    /// assert!(ok);
    /// assert_eq!(
    ///     store.get(b"view").unwrap().unwrap().as_ref(),
    ///     &8u64.to_be_bytes(),
    /// );
    ///
    /// // Mismatch: no change, returns Ok(false).
    /// let ok = store
    ///     .compare_and_swap(b"view", Some(&7u64.to_be_bytes()), Some(&9u64.to_be_bytes()))
    ///     .unwrap();
    /// assert!(!ok);
    /// assert_eq!(
    ///     store.get(b"view").unwrap().unwrap().as_ref(),
    ///     &8u64.to_be_bytes(),
    /// );
    /// ```
    fn compare_and_swap(
        &self,
        key: &[u8],
        expected: Option<&[u8]>,
        new: Option<&[u8]>,
    ) -> anyhow::Result<bool>;
}

/// Ergonomic closure wrapper around [`Storage::apply_batch`]. Blanket-impl'd
/// for any `Storage` (including `dyn Storage`), so callers holding an
/// `Arc<dyn Storage>` can write `s.batch(|b| { b.put(...); Ok(()) })`.
///
/// # Example
///
/// Atomically write HotStuff-style "last voted view" and "locked QC hash"
/// against the in-memory backend:
///
/// ```
/// use std::sync::Arc;
///
/// use ambros_p2p::storage::{MemoryStorage, Storage, StorageExt};
///
/// let store: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
///
/// store
///     .batch(|b| {
///         b.put(b"last_voted_view", &42u64.to_be_bytes());
///         b.put(b"locked_qc_hash", &[0xAB; 32]);
///         Ok(())
///     })
///     .unwrap();
///
/// assert_eq!(
///     store.get(b"last_voted_view").unwrap().unwrap().as_ref(),
///     &42u64.to_be_bytes(),
/// );
/// ```
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

/// A group of writes that will be applied atomically by [`Storage::apply_batch`].
#[derive(Default, Debug)]
pub struct WriteBatch {
    pub(crate) ops: Vec<WriteOp>,
}

#[derive(Debug)]
pub(crate) enum WriteOp {
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

    pub fn len(&self) -> usize {
        self.ops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

/// Append-only log for "log state" (blocks, decisions, anything consensus
/// replays on startup).
///
/// Durability contract: [`Wal::flush`] must fsync before returning. After a
/// successful `flush()`, every entry whose `append` returned before the
/// `flush()` is guaranteed to survive a crash. Entries appended but not yet
/// flushed may or may not survive.
pub trait Wal: Send + Sync {
    /// Append `entry`. Returns the assigned [`Lsn`], which is strictly
    /// greater than every previously returned LSN within this process
    /// (and strictly greater than [`Lsn::ZERO`]). May buffer; call
    /// [`Wal::flush`] to force durability.
    ///
    /// Across a crash, LSNs assigned to unflushed entries may be reused —
    /// the only LSNs that are durably reserved are those whose `append`
    /// returned before a successful `flush`.
    fn append(&self, entry: &[u8]) -> anyhow::Result<Lsn>;

    /// fsync the log. See the trait-level durability contract.
    fn flush(&self) -> anyhow::Result<()>;

    /// Iterate entries in ascending LSN order, starting with the first
    /// entry whose LSN is `>= lsn`. Pass [`Lsn::ZERO`] to iterate from the
    /// beginning. The returned iterator may borrow from `self`; iteration
    /// observes a point-in-time snapshot and does not include entries
    /// appended after it begins.
    fn iter_from(&self, lsn: Lsn) -> anyhow::Result<WalIter<'_>>;

    /// Drop every entry whose LSN is `< lsn`. Entries with LSN `>= lsn` are
    /// retained. `truncate_before(Lsn::ZERO)` is a no-op.
    fn truncate_before(&self, lsn: Lsn) -> anyhow::Result<()>;
}
