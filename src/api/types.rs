use chrono::{DateTime, Utc};

#[derive(Debug, serde::Deserialize)]
pub struct PostMessageRequest {
    pub content: String,
    pub expiry: DateTime<Utc>,
}

#[derive(Debug, serde::Serialize)]
pub struct PostMessageResponse {
    pub hash: String,
}

#[derive(Debug, serde::Serialize)]
pub struct MessageItem {
    pub content: String,
    pub expiry: DateTime<Utc>,
}
