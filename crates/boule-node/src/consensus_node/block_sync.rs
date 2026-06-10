use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;

use boule_core::identity::NodeId;

pub const BLOCK_SYNC_OUTSTANDING_PER_PEER: u32 = 4;

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

    pub fn drops_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.drops)
    }

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

pub struct CreditGuard {
    window: Arc<BlockSyncCreditWindow>,
    peer: NodeId,
}

impl Drop for CreditGuard {
    fn drop(&mut self) {
        self.window.release(self.peer);
    }
}
