//! Bounded, TTL-based dedup set for [`super::wire::MsgId`].
//!
//! The gossip overlay re-broadcasts every payload it has not yet seen.
//! A naive implementation would loop forever as the message ricochets
//! through the partial mesh; the dedup set breaks that loop by holding
//! recently-seen `MsgId`s for a configurable TTL and reporting
//! "already seen" on duplicate insertions.
//!
//! # Sizing
//!
//! The set is bounded by `capacity` entries. When the cap is hit, the
//! oldest entry (by insertion order — FIFO) is evicted to make room.
//! `capacity` should comfortably exceed the number of distinct
//! broadcasts in flight within a TTL window. For HotStuff at 1 s view
//! durations and ~10 broadcasts per view across a 25-node cluster,
//! a few thousand entries with a TTL of a couple of minutes is
//! plenty.
//!
//! # TTL semantics
//!
//! Insertion stores `now + ttl` as the expiry instant. [`MsgIdRing::insert`]
//! treats an entry as expired (i.e. forgettable) once `now > expiry`.
//! Expired entries are lazily reclaimed on access — no background
//! sweep is needed. This matches the simpler-is-better posture of the
//! existing `gossip::cleanup` task.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use super::wire::MsgId;

/// Outcome of a dedup-set insertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    /// The id was not in the ring (or its prior entry had expired); it
    /// has now been recorded. Caller should treat the broadcast as new
    /// and re-fanout / surface to the application.
    New,
    /// The id was already present and live. Caller should drop the
    /// broadcast.
    AlreadySeen,
}

/// Fixed-capacity, TTL-bounded recently-seen-id set.
///
/// Not internally synchronized — wrap in a `parking_lot::Mutex` if
/// shared across tasks. The owner of the gossip overlay loop holds it
/// directly without a lock today, since all dedup access happens on
/// that single task.
pub struct MsgIdRing {
    /// Maximum number of live entries. Once reached, oldest entries
    /// are evicted FIFO-order until there is room.
    capacity: usize,
    /// How long a recently-inserted id is treated as "seen" before
    /// being lazily forgotten.
    ttl: Duration,
    /// Live entries. The `Instant` is the entry's expiry deadline.
    entries: HashMap<MsgId, Instant>,
    /// Insertion order. Used for FIFO eviction when at capacity. We
    /// keep this lazily — it may include entries that have already
    /// been removed by the expiry path; we skip those when popping.
    order: VecDeque<MsgId>,
}

impl MsgIdRing {
    /// Build a new ring with the given capacity and TTL.
    ///
    /// Panics if `capacity` is zero — a zero-capacity ring would never
    /// dedup anything, which is almost certainly a configuration bug.
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        assert!(capacity > 0, "MsgIdRing capacity must be > 0");
        Self {
            capacity,
            ttl,
            entries: HashMap::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
        }
    }

    /// Insert `id`, observing `now` as the current monotonic instant.
    ///
    /// Returns [`InsertOutcome::New`] if `id` was not present (or its
    /// prior entry had expired by `now`), [`InsertOutcome::AlreadySeen`]
    /// otherwise. In both cases the entry's expiry is refreshed to
    /// `now + ttl` — a re-seen broadcast extends the dedup window
    /// against further duplicates.
    pub fn insert(&mut self, id: MsgId, now: Instant) -> InsertOutcome {
        // Fast path for live duplicates.
        if let Some(expiry) = self.entries.get(&id).copied()
            && expiry > now
        {
            // Refresh: keep the dedup window alive against further
            // duplicates without bloating the order deque (we tolerate
            // a duplicate id in `order` — see eviction logic below).
            self.entries.insert(id, now + self.ttl);
            self.order.push_back(id);
            return InsertOutcome::AlreadySeen;
        }

        // Either absent, or present-but-expired. Treat as new and
        // make room if we're at capacity.
        while self.entries.len() >= self.capacity {
            if !self.evict_one(now) {
                break;
            }
        }

        self.entries.insert(id, now + self.ttl);
        self.order.push_back(id);
        InsertOutcome::New
    }

    /// Discard expired entries based on `now`. Useful for tests; the
    /// production path relies on lazy eviction in [`Self::insert`].
    pub fn purge_expired(&mut self, now: Instant) {
        self.entries.retain(|_, expiry| *expiry > now);
        // The order deque can stay; expired ids will simply be skipped
        // when they reach the front during eviction.
    }

    /// Number of currently-live entries (excludes expired ones lazily
    /// — a snapshot count after `purge_expired(now)`).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if the ring has no live entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Evict one stale-or-oldest entry from the front of `order`.
    /// Returns `true` if something was actually removed from
    /// `entries`, `false` if the deque is exhausted (only entries left
    /// are duplicates from the `AlreadySeen` refresh path that have
    /// already been evicted by an earlier pop).
    fn evict_one(&mut self, now: Instant) -> bool {
        while let Some(candidate) = self.order.pop_front() {
            // The deque may contain duplicates from refreshed entries
            // or stale references to ids that have already been
            // evicted. Only treat it as a real eviction if the id is
            // still live — and even then, only remove if the front
            // duplicate matches the canonical expiry.
            if let Some(expiry) = self.entries.get(&candidate).copied() {
                if expiry <= now {
                    // Expired: just drop it.
                    self.entries.remove(&candidate);
                    return true;
                }
                // The entry is live and the front of the deque points
                // at it, so this is the FIFO-oldest candidate. But
                // since refreshing pushes a new entry to the back,
                // the front may be an *outdated* deque entry for a
                // refreshed id; check whether there's a duplicate
                // further back.
                if self.order.contains(&candidate) {
                    // Refreshed: this front entry is stale. Discard
                    // it and continue scanning for the genuine FIFO
                    // oldest.
                    continue;
                }
                // Live and unique — this is the FIFO-oldest entry. Evict it.
                self.entries.remove(&candidate);
                return true;
            }
            // entries no longer contains this id — already evicted. Skip.
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> MsgId {
        [byte; 16]
    }

    #[test]
    fn first_insert_returns_new() {
        let mut ring = MsgIdRing::new(8, Duration::from_secs(60));
        let now = Instant::now();
        assert_eq!(ring.insert(id(1), now), InsertOutcome::New);
        assert_eq!(ring.len(), 1);
    }

    #[test]
    fn second_insert_within_ttl_is_already_seen() {
        let mut ring = MsgIdRing::new(8, Duration::from_secs(60));
        let now = Instant::now();
        assert_eq!(ring.insert(id(1), now), InsertOutcome::New);
        assert_eq!(ring.insert(id(1), now), InsertOutcome::AlreadySeen);
        // Refresh path bookkeeping should not change live count.
        assert_eq!(ring.len(), 1);
    }

    #[test]
    fn entry_after_ttl_is_treated_as_new_again() {
        let mut ring = MsgIdRing::new(8, Duration::from_millis(100));
        let t0 = Instant::now();
        assert_eq!(ring.insert(id(1), t0), InsertOutcome::New);

        let t1 = t0 + Duration::from_millis(101);
        // Past the TTL — the prior entry is "expired" from the ring's
        // perspective and the same id can be inserted again as new.
        assert_eq!(ring.insert(id(1), t1), InsertOutcome::New);
    }

    #[test]
    fn capacity_evicts_oldest_first() {
        let mut ring = MsgIdRing::new(3, Duration::from_secs(60));
        let now = Instant::now();
        ring.insert(id(1), now);
        ring.insert(id(2), now);
        ring.insert(id(3), now);
        // At capacity. Inserting a 4th should evict id(1).
        ring.insert(id(4), now);

        assert_eq!(ring.len(), 3);
        // id(1) should now be treated as never-seen.
        assert_eq!(ring.insert(id(1), now), InsertOutcome::New);
        // The eviction of id(1) (re-insert) bumped capacity again,
        // pushing out id(2). id(3) and id(4) remain live alongside the
        // freshly-inserted id(1).
        assert_eq!(ring.insert(id(3), now), InsertOutcome::AlreadySeen);
        assert_eq!(ring.insert(id(4), now), InsertOutcome::AlreadySeen);
    }

    #[test]
    fn purge_expired_drops_stale_entries() {
        let mut ring = MsgIdRing::new(8, Duration::from_millis(50));
        let t0 = Instant::now();
        ring.insert(id(1), t0);
        ring.insert(id(2), t0);
        assert_eq!(ring.len(), 2);

        ring.purge_expired(t0 + Duration::from_millis(51));
        assert_eq!(ring.len(), 0);
        assert!(ring.is_empty());
    }

    #[test]
    fn purge_keeps_unexpired_entries() {
        let mut ring = MsgIdRing::new(8, Duration::from_millis(100));
        let t0 = Instant::now();
        ring.insert(id(1), t0);
        ring.insert(id(2), t0 + Duration::from_millis(60));

        // At t = 70ms past t0, id(1) has expired (t0+100 > 70 false:
        // 100ms > 70ms means still alive). Use t = 110ms to expire #1
        // but not #2 (which expires at 60+100 = 160ms).
        ring.purge_expired(t0 + Duration::from_millis(110));
        assert_eq!(ring.len(), 1);
        // id(1) treated as new again now.
        assert_eq!(
            ring.insert(id(1), t0 + Duration::from_millis(110)),
            InsertOutcome::New
        );
    }

    #[test]
    #[should_panic(expected = "capacity must be > 0")]
    fn zero_capacity_panics() {
        let _ = MsgIdRing::new(0, Duration::from_secs(60));
    }

    #[test]
    fn refreshing_at_capacity_still_evicts_correctly() {
        // Regression: when an AlreadySeen path pushes a duplicate into
        // `order`, eviction must still find a real entry to drop and
        // not get stuck on the duplicate.
        let mut ring = MsgIdRing::new(2, Duration::from_secs(60));
        let now = Instant::now();
        ring.insert(id(1), now);
        ring.insert(id(2), now);

        // Refresh id(1). Now `order` has [1, 2, 1].
        ring.insert(id(1), now);
        assert_eq!(ring.len(), 2);

        // Insert id(3) — must evict id(2) (the genuine FIFO oldest
        // since id(1) was refreshed past it). id(1) survives.
        assert_eq!(ring.insert(id(3), now), InsertOutcome::New);
        assert_eq!(ring.len(), 2);
        assert_eq!(ring.insert(id(1), now), InsertOutcome::AlreadySeen);
        assert_eq!(ring.insert(id(3), now), InsertOutcome::AlreadySeen);
        assert_eq!(ring.insert(id(2), now), InsertOutcome::New);
    }

    #[test]
    fn distinct_ids_dont_collide() {
        let mut ring = MsgIdRing::new(1024, Duration::from_secs(60));
        let now = Instant::now();
        for i in 0u8..200 {
            assert_eq!(ring.insert(id(i), now), InsertOutcome::New);
        }
        assert_eq!(ring.len(), 200);
        for i in 0u8..200 {
            assert_eq!(ring.insert(id(i), now), InsertOutcome::AlreadySeen);
        }
    }
}
