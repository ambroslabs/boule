//! Per-peer credit window for the block-sync responder (#498).
//!
//! Defense-in-depth above the per-peer rate limiter (#134). The rate
//! limiter caps the *rate* of `RequestBlock` ingress (default 8/sec).
//! This module caps *concurrency* — how many requests from a single
//! peer can be in flight at the responder at once.
//!
//! On the synchronous run-loop path that ships today, the count never
//! exceeds 1 (the run loop awaits each `ServeBlock` to completion
//! before pulling the next event). The cap therefore never fires in
//! production. It exists to:
//!
//! 1. Make the contract explicit — "at most K block-sync serves per
//!    peer in flight" is a property a future async responder
//!    (e.g. one that spawns serves as detached tasks) needs to honour
//!    without re-deriving the limit.
//! 2. Surface the policy in `ConsensusStatus.backpressure.
//!    block_sync_serve_drops_total` so an operator can spot the
//!    moment the count flips non-zero (which would indicate someone
//!    bypassed the synchronous gate).
//! 3. Bound the worst case if a future caller batches multiple
//!    `Dispatch::ServeBlock` actions from a single ingress event.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;

use crate::p2p::tls::NodeId;

/// Per-peer concurrency cap on `RequestBlock` serves. Sized small —
/// the synchronous responder never reaches even 2 concurrent serves,
/// and a future async responder shouldn't burst much higher than a
/// few in flight per peer (the rate limiter caps inbound at 8/sec by
/// default, so an async responder serving in <1s produces a steady
/// state under this cap).
pub const BLOCK_SYNC_OUTSTANDING_PER_PEER: u32 = 4;

/// Tracks per-peer outstanding `RequestBlock` serves and counts drops
/// when a peer would exceed [`BLOCK_SYNC_OUTSTANDING_PER_PEER`].
///
/// Construct via [`BlockSyncCreditWindow::new`]. Wrap callers in
/// [`BlockSyncCreditWindow::try_acquire`]: a successful call returns a
/// [`CreditGuard`] whose `Drop` releases the credit. The atomic
/// `drops` counter is `Arc`-shared with `ConsensusStatus` so
/// operators can read it via the `/consensus/status` endpoint.
pub struct BlockSyncCreditWindow {
    cap: u32,
    state: Mutex<HashMap<NodeId, u32>>,
    drops: Arc<AtomicU64>,
}

impl BlockSyncCreditWindow {
    pub fn new() -> Self {
        Self::with_cap(BLOCK_SYNC_OUTSTANDING_PER_PEER)
    }

    pub fn with_cap(cap: u32) -> Self {
        Self {
            cap,
            state: Mutex::new(HashMap::new()),
            drops: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Shared handle to the cumulative drop counter. Wired through to
    /// `ConsensusStatus.backpressure.block_sync_serve_drops_total`.
    pub fn drops_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.drops)
    }

    /// Try to acquire one outstanding-serve credit for `peer`. Returns
    /// `Some(CreditGuard)` on success — the guard's `Drop` releases
    /// the credit. Returns `None` (and increments the drops counter)
    /// when `peer` already has [`BLOCK_SYNC_OUTSTANDING_PER_PEER`]
    /// (or [`Self::with_cap`]'s cap) serves in flight.
    pub fn try_acquire(self: &Arc<Self>, peer: NodeId) -> Option<CreditGuard> {
        let mut state = self.state.lock();
        let count = state.entry(peer).or_insert(0);
        if *count >= self.cap {
            self.drops.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        *count += 1;
        Some(CreditGuard {
            window: Arc::clone(self),
            peer,
        })
    }

    fn release(&self, peer: NodeId) {
        let mut state = self.state.lock();
        if let Some(count) = state.get_mut(&peer) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.remove(&peer);
            }
        }
    }
}

impl Default for BlockSyncCreditWindow {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII guard returned by [`BlockSyncCreditWindow::try_acquire`].
/// Releases the credit when dropped.
pub struct CreditGuard {
    window: Arc<BlockSyncCreditWindow>,
    peer: NodeId,
}

impl Drop for CreditGuard {
    fn drop(&mut self) {
        self.window.release(self.peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(byte: u8) -> NodeId {
        [byte; 32]
    }

    #[test]
    fn acquire_and_release_round_trip() {
        let w = Arc::new(BlockSyncCreditWindow::with_cap(2));
        {
            let _g1 = w.try_acquire(nid(1)).expect("first acquire");
            let _g2 = w.try_acquire(nid(1)).expect("second acquire");
            // Past the cap — drop with counter increment.
            assert!(w.try_acquire(nid(1)).is_none());
            assert_eq!(w.drops.load(Ordering::Relaxed), 1);
        }
        // Both guards dropped — credits returned, next acquire succeeds.
        assert!(w.try_acquire(nid(1)).is_some());
        assert_eq!(w.drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn cap_is_per_peer_not_global() {
        let w = Arc::new(BlockSyncCreditWindow::with_cap(1));
        let _a1 = w.try_acquire(nid(1)).expect("peer 1 first");
        // Peer 2 has its own bucket.
        let _b1 = w.try_acquire(nid(2)).expect("peer 2 first");
        // Peer 1's bucket is full.
        assert!(w.try_acquire(nid(1)).is_none());
        // Peer 2's bucket is full.
        assert!(w.try_acquire(nid(2)).is_none());
        assert_eq!(w.drops.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn drops_counter_is_shared_via_arc() {
        let w = Arc::new(BlockSyncCreditWindow::with_cap(0));
        let counter = w.drops_counter();
        // cap=0 means every acquire fails.
        assert!(w.try_acquire(nid(1)).is_none());
        assert!(w.try_acquire(nid(2)).is_none());
        assert_eq!(counter.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn release_only_removes_entry_at_zero() {
        let w = Arc::new(BlockSyncCreditWindow::with_cap(3));
        let g1 = w.try_acquire(nid(1)).unwrap();
        let g2 = w.try_acquire(nid(1)).unwrap();
        // Drop one guard; the other still holds a credit.
        drop(g1);
        // Cap=3, count=1 → still room for two more.
        let _g3 = w.try_acquire(nid(1)).expect("post-release acquire");
        let _g4 = w.try_acquire(nid(1)).expect("third acquire");
        // Now at cap.
        assert!(w.try_acquire(nid(1)).is_none());
        drop(g2);
    }
}
