pub mod api;
pub mod cleanup;
pub mod engine;
pub mod store;
pub mod wire;

pub const PROTOCOL_ID: u8 = 0x01;

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

pub type ContentHash = [u8; 32];

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GossipMessage {
    pub content: String,
    pub expiry: DateTime<Utc>,
}

impl GossipMessage {
    pub fn content_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(self.content.as_bytes());
        let nanos = self.expiry.timestamp_nanos_opt().unwrap_or(i64::MAX);
        hasher.update(nanos.to_be_bytes());
        hasher.finalize().into()
    }

    pub fn is_expired(&self) -> bool {
        self.expiry <= Utc::now()
    }
}

#[derive(Debug)]
pub enum InsertResult {
    Inserted,
    AlreadySeen,
    Expired,
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};

    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).unwrap()
    }

    #[test]
    fn content_hash_is_deterministic() {
        let m = GossipMessage {
            content: "hello".into(),
            expiry: at(1_700_000_000),
        };
        assert_eq!(m.content_hash(), m.content_hash());
    }

    #[test]
    fn content_hash_differs_when_content_differs() {
        let a = GossipMessage {
            content: "alpha".into(),
            expiry: at(1_700_000_000),
        };
        let b = GossipMessage {
            content: "beta".into(),
            expiry: at(1_700_000_000),
        };
        assert_ne!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn content_hash_differs_when_expiry_differs() {
        // Two messages with identical content but different expiries must hash
        // differently; otherwise the store would dedup a re-broadcast with an
        // extended lifetime.
        let a = GossipMessage {
            content: "same".into(),
            expiry: at(1_700_000_000),
        };
        let b = GossipMessage {
            content: "same".into(),
            expiry: at(1_700_000_001),
        };
        assert_ne!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn is_expired_respects_current_time() {
        let past = GossipMessage {
            content: "p".into(),
            expiry: Utc::now() - Duration::seconds(1),
        };
        let future = GossipMessage {
            content: "f".into(),
            expiry: Utc::now() + Duration::seconds(60),
        };
        assert!(past.is_expired());
        assert!(!future.is_expired());
    }
}
