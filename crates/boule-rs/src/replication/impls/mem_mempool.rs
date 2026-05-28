//! A bounded in-memory [`Mempool`] sufficient for unit tests and the
//! deterministic simulator.
//!
//! Ordering is strict FIFO (stronger than the trait's "FIFO-ish by
//! arrival" guarantee — simpler to reason about, and consensus never
//! relies on anything weaker). Dedup is keyed on SHA-256 of the raw
//! command bytes. Capacity is bounded; inserting past the cap returns
//! `Err` so callers surface backpressure rather than silently dropping.

use std::collections::{HashSet, VecDeque};

use bytes::Bytes;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};

use crate::replication::mempool::Mempool;

/// In-memory, bounded, deduplicating reference [`Mempool`].
pub struct InMemoryMempool {
    max_size: usize,
    inner: Mutex<Inner>,
}

struct Inner {
    order: VecDeque<Bytes>,
    seen: HashSet<[u8; 32]>,
}

impl InMemoryMempool {
    /// Create a mempool with a fixed maximum count.
    ///
    /// `max_size == 0` yields a mempool that rejects every `insert`;
    /// useful only as a sentinel.
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
            // Duplicate: no-op, not an error.
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn b(s: &[u8]) -> Bytes {
        Bytes::copy_from_slice(s)
    }

    #[test]
    fn insert_then_propose_returns_in_fifo_order() {
        let mp = InMemoryMempool::new(8);
        assert!(mp.insert(b(b"a")).unwrap());
        assert!(mp.insert(b(b"b")).unwrap());
        assert!(mp.insert(b(b"c")).unwrap());
        assert_eq!(mp.len(), 3);

        let proposed = mp.propose(10);
        assert_eq!(proposed, vec![b(b"a"), b(b"b"), b(b"c")]);
    }

    #[test]
    fn propose_respects_limit() {
        let mp = InMemoryMempool::new(8);
        for x in [b"a", b"b", b"c", b"d"] {
            mp.insert(b(x)).unwrap();
        }
        assert_eq!(mp.propose(2), vec![b(b"a"), b(b"b")]);
        assert_eq!(mp.propose(0), Vec::<Bytes>::new());
        assert_eq!(
            mp.propose(100),
            vec![b(b"a"), b(b"b"), b(b"c"), b(b"d")],
            "limit larger than size returns everything",
        );
    }

    #[test]
    fn propose_without_remove_still_returns_same_items() {
        // Per the trait contract, propose does NOT mutate — it's
        // remove_committed that evicts.
        let mp = InMemoryMempool::new(4);
        mp.insert(b(b"a")).unwrap();
        mp.insert(b(b"b")).unwrap();
        let first = mp.propose(10);
        let second = mp.propose(10);
        assert_eq!(first, second);
        assert_eq!(mp.len(), 2);
    }

    #[test]
    fn duplicate_insert_returns_false_and_does_not_grow() {
        let mp = InMemoryMempool::new(4);
        assert!(mp.insert(b(b"x")).unwrap());
        assert!(!mp.insert(b(b"x")).unwrap(), "dup returns Ok(false)");
        assert_eq!(mp.len(), 1);
        // And a duplicate never re-enters the FIFO tail.
        assert_eq!(mp.propose(10), vec![b(b"x")]);
    }

    #[test]
    fn capacity_full_surfaces_err_and_leaves_state_unchanged() {
        let mp = InMemoryMempool::new(2);
        mp.insert(b(b"a")).unwrap();
        mp.insert(b(b"b")).unwrap();
        let err = mp.insert(b(b"c")).unwrap_err();
        assert!(err.to_string().contains("mempool full"));
        assert_eq!(mp.len(), 2, "failed insert must not grow");
        assert_eq!(mp.propose(10), vec![b(b"a"), b(b"b")]);
    }

    #[test]
    fn zero_capacity_rejects_everything() {
        let mp = InMemoryMempool::new(0);
        assert!(mp.insert(b(b"x")).is_err());
        assert_eq!(mp.len(), 0);
    }

    #[test]
    fn key_invariant_propose_then_commit_never_repeats() {
        // From #21: propose → remove_committed, repeated, must never
        // return the same command twice across successive calls.
        let mp = InMemoryMempool::new(16);
        for x in [b"a", b"b", b"c", b"d", b"e"] {
            mp.insert(b(x)).unwrap();
        }

        let batch1 = mp.propose(2);
        assert_eq!(batch1, vec![b(b"a"), b(b"b")]);
        mp.remove_committed(&batch1);
        assert_eq!(mp.len(), 3);

        let batch2 = mp.propose(2);
        assert_eq!(batch2, vec![b(b"c"), b(b"d")]);
        // Neither element of batch2 appeared in batch1.
        for item in &batch2 {
            assert!(!batch1.contains(item));
        }
        mp.remove_committed(&batch2);

        let batch3 = mp.propose(10);
        assert_eq!(batch3, vec![b(b"e")]);
        mp.remove_committed(&batch3);
        assert!(mp.is_empty());
    }

    #[test]
    fn remove_committed_ignores_unknown_and_is_idempotent() {
        let mp = InMemoryMempool::new(4);
        mp.insert(b(b"a")).unwrap();
        mp.insert(b(b"b")).unwrap();

        // Remove a command we never inserted — no-op.
        mp.remove_committed(&[b(b"never")]);
        assert_eq!(mp.len(), 2);

        // Remove one we did insert — evicted.
        mp.remove_committed(&[b(b"a")]);
        assert_eq!(mp.propose(10), vec![b(b"b")]);

        // Remove again — still idempotent no-op.
        mp.remove_committed(&[b(b"a")]);
        assert_eq!(mp.propose(10), vec![b(b"b")]);

        // And re-inserting "a" works because the seen-set was also trimmed.
        assert!(mp.insert(b(b"a")).unwrap());
        assert_eq!(mp.propose(10), vec![b(b"b"), b(b"a")]);
    }

    #[test]
    fn remove_committed_empty_slice_is_noop() {
        let mp = InMemoryMempool::new(4);
        mp.insert(b(b"a")).unwrap();
        mp.remove_committed(&[]);
        assert_eq!(mp.len(), 1);
    }

    #[test]
    fn object_safe_via_arc_dyn() {
        // Consensus holds an `Arc<dyn Mempool>`, so the trait must be
        // object-safe. This test would fail to compile otherwise.
        let mp: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(4));
        mp.insert(b(b"a")).unwrap();
        assert_eq!(mp.len(), 1);
        assert_eq!(mp.propose(10), vec![b(b"a")]);
    }

    // ── Property tests ──────────────────────────────────────────────────

    use proptest::prelude::*;

    proptest! {
        // Apply a stream of unique commands; drain them in batches via
        // `propose → remove_committed`; assert the union equals the input
        // set and no batch repeats a command from an earlier batch.
        #[test]
        fn prop_propose_commit_cycle_drains_exactly_once(
            n in 0usize..64,
            batch_size in 1usize..8,
        ) {
            let mp = InMemoryMempool::new(128);
            let inputs: Vec<Bytes> = (0..n)
                .map(|i| Bytes::from(format!("cmd-{i:04}").into_bytes()))
                .collect();
            for cmd in &inputs {
                mp.insert(cmd.clone()).unwrap();
            }

            let mut seen_across_batches: HashSet<Bytes> = HashSet::new();
            while !mp.is_empty() {
                let batch = mp.propose(batch_size);
                prop_assert!(!batch.is_empty(), "non-empty pool must yield a non-empty propose");
                for item in &batch {
                    prop_assert!(
                        seen_across_batches.insert(item.clone()),
                        "command appeared twice across successive propose calls",
                    );
                }
                mp.remove_committed(&batch);
            }
            prop_assert_eq!(seen_across_batches.len(), n);
            let as_set: HashSet<Bytes> = inputs.into_iter().collect();
            prop_assert_eq!(seen_across_batches, as_set);
        }

        // Duplicate inserts never grow the pool and never change
        // propose's observable output.
        #[test]
        fn prop_duplicate_inserts_are_noops(
            cmds in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..32), 0..16),
        ) {
            let mp = InMemoryMempool::new(256);
            // First pass: insert each.
            for c in &cmds {
                let _ = mp.insert(Bytes::from(c.clone()));
            }
            let snapshot = mp.propose(1000);
            let len_before = mp.len();

            // Second pass: every item is now a duplicate.
            for c in &cmds {
                let res = mp.insert(Bytes::from(c.clone()));
                // Pool is bounded at 256 and we inserted at most 16
                // items in the first pass, so these MUST succeed as
                // dup no-ops (Ok(false)).
                prop_assert!(matches!(res, Ok(false)));
            }
            prop_assert_eq!(mp.len(), len_before);
            prop_assert_eq!(mp.propose(1000), snapshot);
        }
    }
}
