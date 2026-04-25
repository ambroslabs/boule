//! Partial-mesh gossip overlay (issue #137).
//!
//! Lands incrementally — this PR adds only the wire types and the dedup
//! ring. Subsequent PRs add the peer-list table, partial-mesh maintenance
//! loop, the [`super::Broadcaster`] / [`super::Discovery`] implementations,
//! and finally wire it into the binary.
//!
//! # Overview
//!
//! The gossip overlay sits at the same seam as [`super::mesh`] — it
//! implements the [`super::Broadcaster`] and [`super::Discovery`] traits
//! — but instead of relying on the peer manager's full N–1 connection
//! table, it:
//!
//! 1. Maintains direct TCP/TLS connections to ≤ `target_degree` peers
//!    (default 8).
//! 2. Learns about other peers through periodic peer-list gossip with
//!    those direct neighbours.
//! 3. On `broadcast`, fans the payload out to the direct neighbours,
//!    relying on receivers to forward on (with deduplication).
//!
//! See issue #137 for the full design and the [breakdown
//! comment](https://github.com/zrbecker/ambros-p2p/issues/137#issuecomment-4319359359)
//! for the per-PR plan.
//!
//! # Protocol ID
//!
//! Overlay control + forwarded application traffic share a single
//! protocol ID, [`PROTOCOL_ID`]. The
//! [`wire::OverlayFrame`](wire::OverlayFrame) enum disambiguates between
//! peer-list pushes and forwarded payloads inside that channel.

pub mod dedup;
pub mod wire;

/// Single-byte protocol identifier for the gossip overlay's control +
/// forwarded-payload channel. Reserved here so future PRs in the issue
/// #137 stack don't have to renumber.
///
/// Existing protocol IDs in the binary:
/// | ID | Owner |
/// |---:|---|
/// | `0x01` | [`crate::gossip`] (best-effort message overlay) |
/// | `0x02` | [`crate::ping`] |
/// | `0x03` | [`crate::consensus::node`] |
/// | `0x04` | this overlay |
pub const PROTOCOL_ID: u8 = 0x04;

/// Per-protocol frame-size cap. Sized to hold the largest forwarded
/// consensus frame (proposals carry batched mempool transactions) plus
/// a small wrapper margin for the [`wire::OverlayFrame`] envelope.
/// Matches consensus's [`crate::consensus::node::MAX_FRAME_BYTES`] of
/// 4 MiB today; grows in lockstep if a future consensus message gets
/// bigger.
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024 + 64 * 1024;
