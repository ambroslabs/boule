//! The [`Mempool`] trait: pending application commands a leader can draw
//! from when proposing a block.
//!
//! # Scope
//!
//! Consensus cares about three things and nothing more: *get me some
//! commands to propose* ([`Mempool::propose`]), *these commands just
//! committed so stop proposing them* ([`Mempool::remove_committed`]), and
//! *is there anything to do?* ([`Mempool::len`]). Mempool gossip, eviction
//! policies, priority/fee ordering, and cross-node sync are intentionally
//! outside this trait — they're application concerns that different
//! networks will answer differently.
//!
//! # Interior mutability
//!
//! All methods take `&self` so a [`Mempool`] can be held as
//! `Arc<dyn Mempool>` alongside `Arc<dyn Storage>` in the consensus node.
//! Implementations are responsible for their own synchronization;
//! [`super::impls::InMemoryMempool`] uses `parking_lot::Mutex` internally.

use bytes::Bytes;

/// A pool of pending application commands that hasn't yet been committed
/// by consensus.
///
/// # Invariants for implementations
///
/// - `propose(limit)` MUST NOT return the same command twice across
///   successive calls *if* [`Mempool::remove_committed`] is called with
///   the proposed commands between them. This is the only ordering
///   guarantee consensus relies on (the issue #21 verification criterion).
/// - `len()` MUST equal the number of commands a subsequent
///   `propose(usize::MAX)` would return, assuming no concurrent mutation.
/// - Duplicate inserts (`insert` of a command already present) MUST NOT
///   grow the pool; the trait returns `Ok(false)` in that case.
///
/// The trait intentionally does NOT promise strict FIFO order — only
/// "FIFO-ish by arrival" — so implementations are free to batch, reorder
/// within a batch, or apply limits. Consensus never depends on a specific
/// ordering.
pub trait Mempool: Send + Sync {
    /// Admit `cmd` into the pool.
    ///
    /// Returns `Ok(true)` if the command was newly added; `Ok(false)` if
    /// it was already present (a duplicate — no-op). `Err` is reserved
    /// for structural failures such as a bounded pool being full; see
    /// the implementation's docs for backpressure semantics.
    fn insert(&self, cmd: Bytes) -> anyhow::Result<bool>;

    /// Return up to `limit` commands the caller can propose in the next
    /// block, in FIFO-ish-by-arrival order.
    ///
    /// `propose` does NOT remove commands from the pool — they remain
    /// visible to subsequent callers (and to subsequent `propose` calls)
    /// until [`Mempool::remove_committed`] is invoked after a block that
    /// contains them commits.
    fn propose(&self, limit: usize) -> Vec<Bytes>;

    /// Evict commands that just committed in a block.
    ///
    /// Unknown commands in `cmds` (never seen, or already evicted) are
    /// silently ignored — this is expected when replaying history or
    /// catching up from a snapshot.
    fn remove_committed(&self, cmds: &[Bytes]);

    /// Number of commands currently held.
    fn len(&self) -> usize;

    /// Convenience: `len() == 0`.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
