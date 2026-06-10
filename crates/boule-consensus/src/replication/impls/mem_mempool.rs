use std::collections::{HashSet, VecDeque};

use bytes::Bytes;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};

use crate::replication::mempool::Mempool;

pub struct InMemoryMempool {
    max_size: usize,
    inner: Mutex<Inner>,
}

struct Inner {
    order: VecDeque<Bytes>,
    seen: HashSet<[u8; 32]>,
}

impl InMemoryMempool {
    pub fn new(max_size: usize) -> Self {
        Self {
            max_size,
            inner: Mutex::new(Inner {
                order: VecDeque::new(),
                seen: HashSet::new(),
            }),
        }
    }

    fn digest(bytes: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hasher.finalize().into()
    }
}

impl Mempool for InMemoryMempool {
    fn insert(&self, cmd: Bytes) -> anyhow::Result<bool> {
        let key = Self::digest(&cmd);
        let mut g = self.inner.lock();
        if g.seen.contains(&key) {
            return Ok(false);
        }
        if g.order.len() >= self.max_size {
            anyhow::bail!(
                "mempool full: {} entries at max_size {}",
                g.order.len(),
                self.max_size,
            );
        }
        g.order.push_back(cmd);
        g.seen.insert(key);
        Ok(true)
    }

    fn propose(&self, limit: usize) -> Vec<Bytes> {
        let g = self.inner.lock();
        g.order.iter().take(limit).cloned().collect()
    }

    fn remove_committed(&self, cmds: &[Bytes]) {
        if cmds.is_empty() {
            return;
        }
        let keys: HashSet<[u8; 32]> = cmds.iter().map(|c| Self::digest(c)).collect();
        let mut g = self.inner.lock();
        g.order.retain(|c| !keys.contains(&Self::digest(c)));
        g.seen.retain(|k| !keys.contains(k));
    }

    fn len(&self) -> usize {
        self.inner.lock().order.len()
    }
}
