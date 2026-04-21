pub mod cleanup;
pub mod engine;
pub mod store;

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
