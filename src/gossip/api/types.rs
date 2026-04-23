//! Wire types for the gossip HTTP admin surface.
//!
//! These are only used at the HTTP boundary (JSON in / JSON out). The
//! on-the-wire gossip protocol uses [`wire::WireMessage`](crate::gossip::wire::WireMessage)
//! with its own encoding.

#![warn(missing_docs)]

use chrono::{DateTime, Utc};

/// Request body for `POST /messages`.
///
/// Callers submit a new message plus an absolute expiry. The gossip engine
/// stores the message locally, rebroadcasts it to every connected peer, and
/// evicts it once `expiry` passes.
///
/// # Example
///
/// ```text
/// POST /messages
/// Content-Type: application/json
///
/// { "content": "hello", "expiry": "2026-01-01T00:00:00Z" }
/// ```
///
/// Returns `201 Created` with a [`PostMessageResponse`] on success, or
/// `400 Bad Request` if `expiry` is in the past.
#[derive(Debug, serde::Deserialize)]
pub struct PostMessageRequest {
    /// UTF-8 message body. Size is bounded only by HTTP/serialization
    /// limits; the gossip store keeps messages in memory, so very large
    /// payloads will pressure memory and bandwidth.
    pub content: String,
    /// Absolute wall-clock time at which the gossip cleanup task evicts
    /// the message. Must be strictly in the future relative to the node's
    /// current wall clock; otherwise the request is rejected with
    /// `400 Bad Request`.
    pub expiry: DateTime<Utc>,
}

/// Response body for `POST /messages`.
///
/// Returned on both new inserts and idempotent re-inserts (already-seen
/// hashes); the caller cannot distinguish the two from the response.
#[derive(Debug, serde::Serialize)]
pub struct PostMessageResponse {
    /// Hex-encoded SHA-256 content hash of the stored message
    /// (see [`GossipMessage::content_hash`](crate::gossip::GossipMessage::content_hash)).
    /// Use this as a stable identifier if the caller needs to de-duplicate
    /// its own retries.
    pub hash: String,
}

/// One entry returned by `GET /messages`.
///
/// The list surfaces only currently live messages (expiry > now) at the
/// moment the request was served. Expired messages are swept out by
/// [`cleanup::run`](crate::gossip::cleanup::run).
#[derive(Debug, serde::Serialize)]
pub struct MessageItem {
    /// The message body, exactly as submitted by some peer.
    pub content: String,
    /// Absolute wall-clock expiry. Messages disappear from `/messages` and
    /// from the store once this passes.
    pub expiry: DateTime<Utc>,
}
