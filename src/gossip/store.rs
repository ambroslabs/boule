use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use parking_lot::RwLock;

use super::{ContentHash, GossipMessage, InsertResult};

pub struct GossipStore {
    inner: RwLock<StoreInner>,
}

struct StoreInner {
    messages: HashMap<ContentHash, GossipMessage>,
    seen: HashSet<ContentHash>,
}

impl Default for GossipStore {
    fn default() -> Self {
        Self::new()
    }
}

impl GossipStore {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(StoreInner {
                messages: HashMap::new(),
                seen: HashSet::new(),
            }),
        }
    }

    pub fn try_insert(&self, msg: GossipMessage, now: DateTime<Utc>) -> InsertResult {
        // Check expiry before taking any lock.
        if msg.is_expired(now) {
            return InsertResult::Expired;
        }
        let hash = msg.content_hash();

        // Fast path: shared read lock to check seen set.
        // This is the common case for duplicate messages and does not block other readers.
        {
            let inner = self.inner.read();
            if inner.seen.contains(&hash) {
                return InsertResult::AlreadySeen;
            }
        }

        // Slow path: exclusive write lock with re-check (double-checked locking).
        let mut inner = self.inner.write();
        if msg.is_expired(now) {
            return InsertResult::Expired;
        }
        if inner.seen.contains(&hash) {
            return InsertResult::AlreadySeen;
        }
        inner.seen.insert(hash);
        inner.messages.insert(hash, msg);
        InsertResult::Inserted
    }

    pub fn list_live(&self, now: DateTime<Utc>) -> Vec<GossipMessage> {
        let inner = self.inner.read();
        inner
            .messages
            .values()
            .filter(|m| m.expiry > now)
            .cloned()
            .collect()
    }

    pub fn remove_expired(&self, now: DateTime<Utc>) -> usize {
        let mut inner = self.inner.write();
        let expired: Vec<ContentHash> = inner
            .messages
            .iter()
            .filter(|(_, m)| m.expiry <= now)
            .map(|(h, _)| *h)
            .collect();
        let count = expired.len();
        for hash in expired {
            inner.messages.remove(&hash);
            inner.seen.remove(&hash);
        }
        count
    }

    #[cfg(test)]
    fn panic_holding_write_lock(&self) -> ! {
        let _guard = self.inner.write();
        panic!("intentional panic while holding gossip store write lock");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use chrono::Duration;

    use super::*;

    fn msg(content: &str, ttl_ms: i64) -> GossipMessage {
        GossipMessage {
            content: content.to_string(),
            expiry: Utc::now() + Duration::milliseconds(ttl_ms),
        }
    }

    #[test]
    fn insert_fresh_message_stores_and_lists_it() {
        let store = GossipStore::new();
        let m = msg("hello", 60_000);

        assert!(matches!(
            store.try_insert(m.clone(), Utc::now()),
            InsertResult::Inserted
        ));

        let live = store.list_live(Utc::now());
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].content, "hello");
    }

    #[test]
    fn duplicate_insert_returns_already_seen() {
        let store = GossipStore::new();
        let m = msg("hello", 60_000);

        assert!(matches!(
            store.try_insert(m.clone(), Utc::now()),
            InsertResult::Inserted
        ));
        assert!(matches!(
            store.try_insert(m.clone(), Utc::now()),
            InsertResult::AlreadySeen
        ));
        assert_eq!(store.list_live(Utc::now()).len(), 1);
    }

    #[test]
    fn expired_message_is_rejected() {
        let store = GossipStore::new();
        let m = GossipMessage {
            content: "stale".into(),
            expiry: Utc::now() - Duration::seconds(1),
        };

        assert!(matches!(
            store.try_insert(m, Utc::now()),
            InsertResult::Expired
        ));
        assert!(store.list_live(Utc::now()).is_empty());
    }

    #[test]
    fn same_content_different_expiry_are_distinct() {
        // content_hash folds expiry in, so changing the expiry produces a new hash
        // and the second message is stored alongside the first.
        let store = GossipStore::new();
        let now = Utc::now();
        let a = GossipMessage {
            content: "x".into(),
            expiry: now + Duration::seconds(60),
        };
        let b = GossipMessage {
            content: "x".into(),
            expiry: now + Duration::seconds(120),
        };

        assert!(matches!(store.try_insert(a, now), InsertResult::Inserted));
        assert!(matches!(store.try_insert(b, now), InsertResult::Inserted));
        assert_eq!(store.list_live(now).len(), 2);
    }

    #[test]
    fn list_live_filters_out_expired_entries() {
        let store = GossipStore::new();
        let shortlived = msg("gone-soon", 50);
        let longlived = msg("still-here", 60_000);
        store.try_insert(shortlived, Utc::now());
        store.try_insert(longlived, Utc::now());

        thread::sleep(std::time::Duration::from_millis(150));

        let live = store.list_live(Utc::now());
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].content, "still-here");
    }

    #[test]
    fn remove_expired_drops_only_past_entries() {
        let store = GossipStore::new();
        store.try_insert(msg("gone-soon", 50), Utc::now());
        store.try_insert(msg("still-here", 60_000), Utc::now());

        thread::sleep(std::time::Duration::from_millis(150));

        assert_eq!(store.remove_expired(Utc::now()), 1);
        let live = store.list_live(Utc::now());
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].content, "still-here");
    }

    #[test]
    fn remove_expired_clears_seen_so_message_can_be_reinserted() {
        // Current behaviour: remove_expired drops the hash from the `seen` set,
        // so a later message with the same (content, expiry) would be inserted
        // as if fresh. Pin this so any future change is intentional.
        let store = GossipStore::new();
        let expiry = Utc::now() + Duration::milliseconds(50);
        let m = GossipMessage {
            content: "recycled".into(),
            expiry,
        };
        assert!(matches!(
            store.try_insert(m.clone(), Utc::now()),
            InsertResult::Inserted
        ));

        thread::sleep(std::time::Duration::from_millis(150));
        assert_eq!(store.remove_expired(Utc::now()), 1);

        let revived = GossipMessage {
            content: "recycled".into(),
            expiry: Utc::now() + Duration::seconds(60),
        };
        assert!(matches!(
            store.try_insert(revived, Utc::now()),
            InsertResult::Inserted
        ));
    }

    #[test]
    fn write_lock_is_not_poisoned_after_panic() {
        // Regression test for gossip-poisoning issue (#42): a task that panics
        // while holding the write lock must not prevent subsequent acquisition.
        // parking_lot::RwLock provides this by construction; this test pins it
        // so a future change back to std::sync::RwLock would fail loudly.
        let store = Arc::new(GossipStore::new());

        let s = Arc::clone(&store);
        let joined = thread::spawn(move || {
            s.panic_holding_write_lock();
        })
        .join();
        assert!(joined.is_err(), "panic thread should have unwound");

        let fresh = msg("post-panic", 60_000);
        assert!(matches!(
            store.try_insert(fresh, Utc::now()),
            InsertResult::Inserted
        ));
        assert_eq!(store.list_live(Utc::now()).len(), 1);
    }

    #[test]
    fn concurrent_insert_of_same_message_dedups_to_one() {
        // Validates the double-checked locking: under concurrent insertion of
        // the same message from many threads, exactly one should win.
        let store = Arc::new(GossipStore::new());
        let m = msg("contested", 60_000);

        let mut handles = Vec::new();
        for _ in 0..16 {
            let store = Arc::clone(&store);
            let m = m.clone();
            handles.push(thread::spawn(move || store.try_insert(m, Utc::now())));
        }

        let results: Vec<InsertResult> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let inserted = results
            .iter()
            .filter(|r| matches!(r, InsertResult::Inserted))
            .count();
        let seen = results
            .iter()
            .filter(|r| matches!(r, InsertResult::AlreadySeen))
            .count();

        assert_eq!(inserted, 1, "exactly one thread should insert");
        assert_eq!(seen, 15, "all others should see AlreadySeen");
        assert_eq!(store.list_live(Utc::now()).len(), 1);
    }
}
