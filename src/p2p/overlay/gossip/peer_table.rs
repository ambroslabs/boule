//! Bounded `NodeId → PeerEntry` table fed by peer-list gossip.
//!
//! Every peer this node has ever heard about (directly via the manager,
//! or transitively via a peer-list push from a neighbour) lives here.
//! The partial-mesh maintenance loop (PR 3 in the #137 stack) consults
//! this table when it needs more direct connections; the
//! [`super::super::Discovery`] impl (PR 5) snapshots it for callers.
//!
//! # Capacity & eviction
//!
//! The table is bounded by `capacity` entries. When a fresh insertion
//! would exceed the cap, the entry with the **oldest `last_seen_unix_ms`**
//! is evicted first — i.e. an LRU-by-freshness policy. This matches the
//! threat model: an adversary trying to flood the table with garbage
//! `PeerList` entries will, by definition, not see those garbage peers
//! re-advertised by anyone honest, so their `last_seen` ages out and
//! they get evicted ahead of legitimate entries.
//!
//! # Merge semantics
//!
//! On receive, [`PeerTable::merge`] walks the incoming entries and
//! upserts each one, keeping the **larger `last_seen_unix_ms`** on
//! conflict. This is the "last-seen wins" rule from the breakdown
//! comment: a stale entry from one neighbour cannot overwrite a
//! fresher entry the receiver learned from another.
//!
//! Self-entries (where `node_id` matches the local id) are filtered
//! out — there is no point recording our own address in our own table,
//! and accepting it would let a peer reflect our address back at us.
//!
//! # Thread safety
//!
//! `PeerTable` wraps an internal `parking_lot::Mutex` so it can be
//! shared across the maintenance task, the publisher task, and the
//! [`super::super::Discovery`] reader on a single `Arc`. Lock hold
//! durations are O(n) on the few snapshot/merge call sites, which is
//! fine at validator-set scale (a few thousand entries).

use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::Mutex;

use super::super::super::tls::NodeId;
use super::wire::PeerEntry;

/// Bounded, last-seen-wins peer index.
///
/// Cheap to clone — internally it's an `Arc` over a single `Mutex`.
#[derive(Clone)]
pub struct PeerTable {
    inner: Arc<Mutex<Inner>>,
    capacity: usize,
    self_id: NodeId,
}

struct Inner {
    /// `node_id → (addr, last_seen_unix_ms)`.
    ///
    /// Stored as a `Vec` of (node_id, entry) pairs rather than a
    /// `HashMap` so the eviction-by-oldest-last-seen path can scan in
    /// place; with `capacity` typically O(thousands) the linear scan
    /// is well below memory-bandwidth-bound and avoids the
    /// constant-time-overhead of maintaining a separate ordering
    /// structure. A `HashMap`-plus-priority-queue can replace this if
    /// validator-set sizes ever justify it.
    entries: std::collections::HashMap<NodeId, EntryRecord>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EntryRecord {
    addr: SocketAddr,
    last_seen_unix_ms: u64,
    /// Whether the peer accepts inbound connections. Mirrors
    /// [`super::wire::PeerEntry::reachable`]; see issue #138.
    reachable: bool,
}

impl PeerTable {
    /// Build an empty table with the given upper bound.
    ///
    /// `self_id` filters self-references out of [`Self::merge`] so a
    /// peer reflecting our own entry back at us doesn't pollute the
    /// table or the [`super::super::Discovery::known_peers`]
    /// snapshot. Panics if `capacity` is zero — a zero-capacity table
    /// is almost certainly a configuration bug.
    pub fn new(self_id: NodeId, capacity: usize) -> Self {
        assert!(capacity > 0, "PeerTable capacity must be > 0");
        Self {
            inner: Arc::new(Mutex::new(Inner {
                entries: std::collections::HashMap::with_capacity(capacity.min(64)),
            })),
            capacity,
            self_id,
        }
    }

    /// Number of currently-tracked peers.
    pub fn len(&self) -> usize {
        self.inner.lock().entries.len()
    }

    /// True if no peers are tracked.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().entries.is_empty()
    }

    /// Whether `node_id` is in the table.
    pub fn contains(&self, node_id: &NodeId) -> bool {
        self.inner.lock().entries.contains_key(node_id)
    }

    /// Look up an entry by `node_id`, returning a copy.
    pub fn get(&self, node_id: &NodeId) -> Option<PeerEntry> {
        let inner = self.inner.lock();
        inner.entries.get(node_id).map(|rec| PeerEntry {
            node_id: *node_id,
            addr: rec.addr,
            last_seen_unix_ms: rec.last_seen_unix_ms,
            reachable: rec.reachable,
        })
    }

    /// Insert or refresh `(node_id, addr)` with the historical
    /// `reachable = true` default. Wraps [`Self::upsert_with_reachable`]
    /// for callers (and tests) that don't care about reachability.
    pub fn upsert(
        &self,
        node_id: NodeId,
        addr: SocketAddr,
        last_seen_unix_ms: u64,
    ) -> UpsertOutcome {
        self.upsert_with_reachable(node_id, addr, last_seen_unix_ms, true)
    }

    /// Insert or refresh `(node_id, addr, reachable)`.
    ///
    /// Refuses to insert the local node id (filtered against `self_id`).
    /// If the table is at capacity and `node_id` is not already
    /// present, the entry with the oldest `last_seen_unix_ms` is
    /// evicted to make room. If the existing entry has a newer
    /// `last_seen_unix_ms` than the proposed one, the existing entry
    /// wins and the upsert is a no-op (last-seen wins on tie-break).
    /// Reachability is overwritten on each successful refresh; the
    /// peer's own self-advertisement is the source of truth and a
    /// fresher record always reflects the latest claim.
    ///
    /// Returns [`UpsertOutcome`] describing what changed.
    pub fn upsert_with_reachable(
        &self,
        node_id: NodeId,
        addr: SocketAddr,
        last_seen_unix_ms: u64,
        reachable: bool,
    ) -> UpsertOutcome {
        if node_id == self.self_id {
            return UpsertOutcome::SkippedSelf;
        }
        let mut inner = self.inner.lock();

        if let Some(existing) = inner.entries.get_mut(&node_id) {
            if last_seen_unix_ms <= existing.last_seen_unix_ms {
                return UpsertOutcome::Stale;
            }
            let addr_changed = existing.addr != addr;
            existing.addr = addr;
            existing.last_seen_unix_ms = last_seen_unix_ms;
            existing.reachable = reachable;
            return if addr_changed {
                UpsertOutcome::AddrChanged
            } else {
                UpsertOutcome::Refreshed
            };
        }

        if inner.entries.len() >= self.capacity {
            // Evict the entry with the oldest `last_seen_unix_ms`. If
            // every entry is fresher than the proposed one, refuse the
            // insert rather than evicting a fresher entry to make room
            // for a staler newcomer.
            let (oldest_id, oldest_seen) = inner
                .entries
                .iter()
                .map(|(id, rec)| (*id, rec.last_seen_unix_ms))
                .min_by_key(|(_, seen)| *seen)
                .expect("entries is non-empty at capacity");
            if last_seen_unix_ms <= oldest_seen {
                return UpsertOutcome::AtCapacityNoEvict;
            }
            inner.entries.remove(&oldest_id);
        }

        inner.entries.insert(
            node_id,
            EntryRecord {
                addr,
                last_seen_unix_ms,
                reachable,
            },
        );
        UpsertOutcome::Inserted
    }

    /// Bulk-merge a [`PeerEntry`] list received over the wire. Entries
    /// matching `self_id` are silently dropped.
    ///
    /// Returns the set of `node_id`s whose record changed (newly
    /// inserted, address changed, or refreshed forward in time).
    pub fn merge<I>(&self, entries: I) -> Vec<NodeId>
    where
        I: IntoIterator<Item = PeerEntry>,
    {
        let mut changed = Vec::new();
        for entry in entries {
            match self.upsert_with_reachable(
                entry.node_id,
                entry.addr,
                entry.last_seen_unix_ms,
                entry.reachable,
            ) {
                UpsertOutcome::Inserted | UpsertOutcome::AddrChanged | UpsertOutcome::Refreshed => {
                    changed.push(entry.node_id);
                }
                UpsertOutcome::Stale
                | UpsertOutcome::SkippedSelf
                | UpsertOutcome::AtCapacityNoEvict => {}
            }
        }
        changed
    }

    /// Snapshot every tracked peer as an unordered [`PeerEntry`] vec.
    /// The returned vec is freshly allocated; the lock is released
    /// before this method returns.
    pub fn snapshot(&self) -> Vec<PeerEntry> {
        let inner = self.inner.lock();
        inner
            .entries
            .iter()
            .map(|(node_id, rec)| PeerEntry {
                node_id: *node_id,
                addr: rec.addr,
                last_seen_unix_ms: rec.last_seen_unix_ms,
                reachable: rec.reachable,
            })
            .collect()
    }

    /// Snapshot only the entries where `reachable == true`.
    ///
    /// Used by [`super::maintenance`] to filter dial candidates so the
    /// partial-mesh maintenance loop never picks an outbound-only
    /// peer (issue #138). Unreachable peers stay in the table — they
    /// are still propagated through peer-list gossip so other nodes
    /// can learn about them, and they may dial in to us themselves —
    /// but we never initiate connections to them.
    pub fn snapshot_reachable(&self) -> Vec<PeerEntry> {
        let inner = self.inner.lock();
        inner
            .entries
            .iter()
            .filter(|(_, rec)| rec.reachable)
            .map(|(node_id, rec)| PeerEntry {
                node_id: *node_id,
                addr: rec.addr,
                last_seen_unix_ms: rec.last_seen_unix_ms,
                reachable: rec.reachable,
            })
            .collect()
    }

    /// Snapshot of just the node ids, sorted for deterministic output.
    pub fn known_node_ids(&self) -> Vec<NodeId> {
        let inner = self.inner.lock();
        let mut ids: Vec<NodeId> = inner.entries.keys().copied().collect();
        ids.sort();
        ids
    }

    /// Drop a specific entry. Used by callers that learn an entry is
    /// definitively stale (e.g. a dial failed and we should forget the
    /// address rather than keep advertising it).
    pub fn remove(&self, node_id: &NodeId) -> Option<PeerEntry> {
        let mut inner = self.inner.lock();
        inner.entries.remove(node_id).map(|rec| PeerEntry {
            node_id: *node_id,
            addr: rec.addr,
            last_seen_unix_ms: rec.last_seen_unix_ms,
            reachable: rec.reachable,
        })
    }

    /// Drop entries whose `last_seen_unix_ms` is older than `cutoff`.
    /// Used by background sweeps in higher layers; the table itself
    /// does not run timers.
    pub fn evict_older_than(&self, cutoff_unix_ms: u64) -> usize {
        let mut inner = self.inner.lock();
        let before = inner.entries.len();
        inner
            .entries
            .retain(|_, rec| rec.last_seen_unix_ms >= cutoff_unix_ms);
        before - inner.entries.len()
    }
}

/// What [`PeerTable::upsert`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpsertOutcome {
    /// `node_id` was not in the table; a fresh entry was created.
    Inserted,
    /// An existing entry's address was replaced with a fresher one.
    AddrChanged,
    /// An existing entry's `last_seen_unix_ms` was advanced; the
    /// address was unchanged.
    Refreshed,
    /// The proposed `last_seen_unix_ms` was older than the existing
    /// entry's; the existing entry won the merge.
    Stale,
    /// The local `self_id` is filtered from the table; the upsert was
    /// dropped.
    SkippedSelf,
    /// The table was full and every existing entry was fresher than
    /// the proposed one. The proposed entry was rejected rather than
    /// evicting a fresher entry to make room.
    AtCapacityNoEvict,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(byte: u8) -> NodeId {
        let mut id = [0u8; 32];
        id[0] = byte;
        id
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn entry(byte: u8, port: u16, last_seen: u64) -> PeerEntry {
        PeerEntry {
            node_id: nid(byte),
            addr: addr(port),
            last_seen_unix_ms: last_seen,
            reachable: true,
        }
    }

    #[test]
    fn fresh_insert_returns_inserted() {
        let t = PeerTable::new(nid(0), 16);
        assert_eq!(t.upsert(nid(1), addr(7000), 100), UpsertOutcome::Inserted);
        assert_eq!(t.len(), 1);
        assert!(t.contains(&nid(1)));
    }

    #[test]
    fn refresh_keeps_addr_advances_seen() {
        let t = PeerTable::new(nid(0), 16);
        t.upsert(nid(1), addr(7000), 100);
        assert_eq!(t.upsert(nid(1), addr(7000), 200), UpsertOutcome::Refreshed);
        let got = t.get(&nid(1)).unwrap();
        assert_eq!(got.addr, addr(7000));
        assert_eq!(got.last_seen_unix_ms, 200);
    }

    #[test]
    fn fresher_addr_replaces_existing() {
        let t = PeerTable::new(nid(0), 16);
        t.upsert(nid(1), addr(7000), 100);
        assert_eq!(
            t.upsert(nid(1), addr(8000), 200),
            UpsertOutcome::AddrChanged
        );
        let got = t.get(&nid(1)).unwrap();
        assert_eq!(got.addr, addr(8000));
        assert_eq!(got.last_seen_unix_ms, 200);
    }

    #[test]
    fn stale_upsert_is_no_op() {
        let t = PeerTable::new(nid(0), 16);
        t.upsert(nid(1), addr(7000), 200);
        assert_eq!(t.upsert(nid(1), addr(8000), 100), UpsertOutcome::Stale);
        let got = t.get(&nid(1)).unwrap();
        assert_eq!(got.addr, addr(7000));
        assert_eq!(got.last_seen_unix_ms, 200);
    }

    #[test]
    fn equal_last_seen_is_treated_as_stale() {
        // Strictly-less-equal protects the "first writer wins on tie"
        // invariant: re-receiving an unchanged entry shouldn't
        // overwrite the existing record.
        let t = PeerTable::new(nid(0), 16);
        t.upsert(nid(1), addr(7000), 100);
        assert_eq!(t.upsert(nid(1), addr(8000), 100), UpsertOutcome::Stale);
    }

    #[test]
    fn self_id_is_filtered() {
        let t = PeerTable::new(nid(0), 16);
        assert_eq!(
            t.upsert(nid(0), addr(7000), 100),
            UpsertOutcome::SkippedSelf
        );
        assert!(t.is_empty());
    }

    #[test]
    fn capacity_evicts_oldest_last_seen() {
        let t = PeerTable::new(nid(0), 3);
        t.upsert(nid(1), addr(7001), 100);
        t.upsert(nid(2), addr(7002), 200);
        t.upsert(nid(3), addr(7003), 300);
        assert_eq!(t.len(), 3);

        // Inserting a fresher entry evicts nid(1) (oldest seen).
        assert_eq!(t.upsert(nid(4), addr(7004), 400), UpsertOutcome::Inserted);
        assert_eq!(t.len(), 3);
        assert!(!t.contains(&nid(1)));
        assert!(t.contains(&nid(2)));
        assert!(t.contains(&nid(3)));
        assert!(t.contains(&nid(4)));
    }

    #[test]
    fn capacity_refuses_staler_than_oldest() {
        let t = PeerTable::new(nid(0), 3);
        t.upsert(nid(1), addr(7001), 100);
        t.upsert(nid(2), addr(7002), 200);
        t.upsert(nid(3), addr(7003), 300);

        // Proposed entry is older than all three. Refuse rather than
        // evict a fresher one.
        assert_eq!(
            t.upsert(nid(9), addr(7009), 50),
            UpsertOutcome::AtCapacityNoEvict
        );
        assert!(!t.contains(&nid(9)));
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn merge_returns_changed_ids() {
        let t = PeerTable::new(nid(0), 16);
        t.upsert(nid(1), addr(7001), 100);
        t.upsert(nid(2), addr(7002), 200);

        let changed = t.merge(vec![
            entry(1, 7001, 150), // refresh
            entry(2, 7002, 50),  // stale -> dropped
            entry(3, 7003, 300), // new
            entry(4, 8004, 400), // new
            entry(0, 9999, 500), // self -> dropped
        ]);

        let mut sorted = changed;
        sorted.sort();
        assert_eq!(sorted, vec![nid(1), nid(3), nid(4)]);
        assert_eq!(t.len(), 4);
    }

    #[test]
    fn snapshot_round_trips_through_merge() {
        let a = PeerTable::new(nid(0), 16);
        a.upsert(nid(1), addr(7001), 100);
        a.upsert(nid(2), addr(7002), 200);
        a.upsert(nid(3), addr(7003), 300);

        let b = PeerTable::new(nid(99), 16);
        let changed = b.merge(a.snapshot());
        assert_eq!(changed.len(), 3);

        assert_eq!(b.get(&nid(1)).unwrap().last_seen_unix_ms, 100);
        assert_eq!(b.get(&nid(2)).unwrap().last_seen_unix_ms, 200);
        assert_eq!(b.get(&nid(3)).unwrap().last_seen_unix_ms, 300);
    }

    #[test]
    fn evict_older_than_drops_stale_entries() {
        let t = PeerTable::new(nid(0), 16);
        t.upsert(nid(1), addr(7001), 100);
        t.upsert(nid(2), addr(7002), 200);
        t.upsert(nid(3), addr(7003), 300);

        let dropped = t.evict_older_than(200);
        assert_eq!(dropped, 1);
        assert_eq!(t.len(), 2);
        assert!(!t.contains(&nid(1)));
        assert!(t.contains(&nid(2)));
        assert!(t.contains(&nid(3)));
    }

    #[test]
    fn remove_drops_entry() {
        let t = PeerTable::new(nid(0), 16);
        t.upsert(nid(1), addr(7001), 100);
        let got = t.remove(&nid(1)).expect("present");
        assert_eq!(got.addr, addr(7001));
        assert!(t.is_empty());
        assert!(t.remove(&nid(1)).is_none());
    }

    #[test]
    #[should_panic(expected = "capacity must be > 0")]
    fn zero_capacity_panics() {
        let _ = PeerTable::new(nid(0), 0);
    }

    #[test]
    fn upsert_default_marks_entry_reachable() {
        let t = PeerTable::new(nid(0), 16);
        assert_eq!(t.upsert(nid(1), addr(7000), 100), UpsertOutcome::Inserted);
        let got = t.get(&nid(1)).unwrap();
        assert!(
            got.reachable,
            "default upsert must mark entries reachable for backward compat"
        );
    }

    #[test]
    fn upsert_with_reachable_round_trips_flag() {
        let t = PeerTable::new(nid(0), 16);
        assert_eq!(
            t.upsert_with_reachable(nid(1), addr(7000), 100, false),
            UpsertOutcome::Inserted
        );
        let got = t.get(&nid(1)).unwrap();
        assert!(!got.reachable);
    }

    #[test]
    fn fresher_advertisement_overwrites_reachable_bit() {
        // Source of truth for `reachable` is the peer itself; a fresher
        // self-advertisement (or last-seen-wins refresh) replaces the
        // stored flag. This matches the merge contract documented on
        // PeerEntry.
        let t = PeerTable::new(nid(0), 16);
        t.upsert_with_reachable(nid(1), addr(7000), 100, true);
        t.upsert_with_reachable(nid(1), addr(7000), 200, false);
        assert!(!t.get(&nid(1)).unwrap().reachable);
        // And vice versa: a peer that comes back online marks itself
        // reachable again.
        t.upsert_with_reachable(nid(1), addr(7000), 300, true);
        assert!(t.get(&nid(1)).unwrap().reachable);
    }

    #[test]
    fn snapshot_reachable_excludes_inbound_disabled_peers() {
        let t = PeerTable::new(nid(0), 16);
        t.upsert_with_reachable(nid(1), addr(7001), 100, true);
        t.upsert_with_reachable(nid(2), addr(7002), 100, false);
        t.upsert_with_reachable(nid(3), addr(7003), 100, true);
        let mut ids: Vec<NodeId> = t
            .snapshot_reachable()
            .into_iter()
            .map(|e| e.node_id)
            .collect();
        ids.sort();
        assert_eq!(ids, vec![nid(1), nid(3)]);
        // Full snapshot still includes the unreachable entry.
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn merge_propagates_reachable_from_peer_entry() {
        let t = PeerTable::new(nid(0), 16);
        let _ = t.merge(vec![
            PeerEntry {
                node_id: nid(1),
                addr: addr(7001),
                last_seen_unix_ms: 100,
                reachable: false,
            },
            PeerEntry {
                node_id: nid(2),
                addr: addr(7002),
                last_seen_unix_ms: 100,
                reachable: true,
            },
        ]);
        assert!(!t.get(&nid(1)).unwrap().reachable);
        assert!(t.get(&nid(2)).unwrap().reachable);
    }

    #[test]
    fn known_node_ids_is_sorted() {
        let t = PeerTable::new(nid(0), 16);
        t.upsert(nid(3), addr(7003), 100);
        t.upsert(nid(1), addr(7001), 100);
        t.upsert(nid(2), addr(7002), 100);
        assert_eq!(t.known_node_ids(), vec![nid(1), nid(2), nid(3)]);
    }
}
