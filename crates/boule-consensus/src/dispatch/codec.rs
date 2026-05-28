//! Postcard encode/decode for [`WireMessage`] frames.
//!
//! Single source of truth for "wire bytes ↔ `WireMessage`" so the
//! ingress and egress paths don't sprinkle `postcard::from_bytes` /
//! `postcard::to_stdvec` calls across each match arm. Wire encoding is
//! authoritatively framed by [`crate::wire::WireMessage`]'s
//! tag layout (see `wire_tag_layout_locked` in `p2p::limits`); this
//! module just owns the bytes.

use bytes::Bytes;

use crate::wire::WireMessage;

/// Decode a raw wire payload (with the protocol tag and length prefix
/// already stripped) into a [`WireMessage`].
pub(super) fn decode(bytes: &[u8]) -> Result<WireMessage, postcard::Error> {
    postcard::from_bytes(bytes)
}

/// Encode a [`WireMessage`] to a postcard byte buffer wrapped in
/// [`Bytes`] for the p2p layer.
pub(super) fn encode(msg: &WireMessage) -> Result<Bytes, postcard::Error> {
    postcard::to_stdvec(msg).map(Bytes::from)
}
