use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use chrono::Utc;

use super::{ContentHash, GossipMessage, InsertResult};

pub struct GossipStore {
    inner: Mutex<StoreInner>,
}

struct StoreInner {
    messages: HashMap<ContentHash, GossipMessage>,
    seen: HashSet<ContentHash>,
}

impl GossipStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(StoreInner {
                messages: HashMap::new(),
                seen: HashSet::new(),
            }),
        }
    }

    pub fn try_insert(&self, msg: GossipMessage) -> InsertResult {
        let mut inner = self.inner.lock().unwrap();
        if msg.is_expired() {
            return InsertResult::Expired;
        }
        let hash = msg.content_hash();
        if inner.seen.contains(&hash) {
            return InsertResult::AlreadySeen;
        }
        inner.seen.insert(hash);
        inner.messages.insert(hash, msg);
        InsertResult::Inserted
    }

    pub fn list_live(&self) -> Vec<GossipMessage> {
        let inner = self.inner.lock().unwrap();
        let now = Utc::now();
        inner
            .messages
            .values()
            .filter(|m| m.expiry > now)
            .cloned()
            .collect()
    }

    pub fn remove_expired(&self) -> usize {
        let mut inner = self.inner.lock().unwrap();
        let now = Utc::now();
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
}
