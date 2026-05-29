//! Wire types for the gossip overlay's control + forwarded-payload
//! protocol channel.
//!
//! Every byte sent on [`super::PROTOCOL_ID`] is a postcard-encoded
//! [`OverlayFrame`]. Two variants suffice for the v1 overlay:
//!
//! - [`OverlayFrame::Forward`] wraps an application payload (e.g. a
//!   consensus message) with a per-broadcast `msg_id` so receivers can
//!   dedup re-broadcasts using [`super::dedup::MsgIdRing`].
//! - [`OverlayFrame::PeerList`] carries a sender-side snapshot of
//!   directly-known peers so receivers can populate their own peer
//!   table for partial-mesh maintenance.
//!
//! The encoding is postcard rather than JSON because the consensus
//! payloads forwarded inside [`OverlayFrame::Forward`] are large
//! (kilobytes of batched mempool transactions per proposal); postcard
//! avoids the base64 / escaping overhead JSON would impose. The rest
//! of the codebase uses postcard for size-sensitive wire types
//! (`crate::consensus::hotstuff::qc`), so this is consistent.

use std::net::SocketAddr;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use super::super::super::tls::NodeId;

/// Opaque per-broadcast identifier. Used as the dedup key on receivers
/// so a forwarded payload that loops back through multiple paths is only
/// surfaced once.
///
/// 16 random bytes is enough that the birthday-paradox collision
/// probability is negligible across the dedup ring's TTL window — well
/// past 2^40 broadcasts before a 1% chance of collision, which is
/// orders of magnitude beyond anything a validator-set-sized cluster
/// will produce in a TTL.
pub type MsgId = [u8; 16];

/// Top-level wire envelope on the overlay protocol channel.
///
/// `Forward` carries application payloads with the dedup key
/// alongside; `PeerList` carries discovery information. Future variants
/// are reserved (e.g. a reactive PeerListRequest if we add pull-mode
/// gossip — see issue #137 design discussion).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OverlayFrame {
    /// An application-level payload being broadcast through the gossip
    /// overlay. The `msg_id` is the dedup key.
    ///
    /// Both [`boule::transport::overlay::Broadcaster::broadcast`] and
    /// [`boule::transport::overlay::Broadcaster::send_to`] produce this
    /// frame variant: in the gossip overlay, point-to-point sends are
    /// implemented as broadcasts (fanned out across the partial mesh,
    /// dedup-bounded, every receiver surfaces upstream). Issue #182
    /// settled on this design after a target-aware variant didn't
    /// reliably surface to the consensus dispatch on receivers in
    /// production. The bandwidth premium is small at validator-set
    /// scale, the wire path is the proven-healthy one consensus
    /// broadcasts already use, and the consensus dispatch is
    /// idempotent under duplicate `BlockRequest` / `BlockResponse`
    /// arrivals.
    Forward {
        /// Per-broadcast identifier. See [`MsgId`].
        msg_id: MsgId,
        /// The original sender — preserved across re-broadcasts so the
        /// receiving consumer (e.g. consensus's `dispatch::ingress`)
        /// sees the broadcast originator's NodeId rather than whichever
        /// neighbour happened to relay the frame on the last hop. See
        /// the gossip overlay module docs for the rationale.
        originator: NodeId,
        /// Opaque application payload. The overlay does not interpret
        /// these bytes; they are surfaced verbatim to the consensus /
        /// gossip consumer on the receiving side.
        payload: Bytes,
    },
    /// Sender's view of the network — every peer it currently has a
    /// direct or recently-heard-of address for. Receivers merge this
    /// into their own peer table.
    PeerList(Vec<PeerEntry>),
}

/// One row in a [`OverlayFrame::PeerList`] gossip message.
///
/// `last_seen_unix_ms` is a sender-side wall-clock timestamp used to
/// break ties when two senders disagree on a peer's address: receivers
/// keep the more recent entry. Wall-clock skew between senders is
/// bounded by the consensus pacemaker's timeout in practice, which is
/// well below the merge-window granularity, so a few hundred
/// milliseconds of skew is harmless.
///
/// # Wire compatibility
///
/// `reachable` was added in issue #138 (NAT-tolerant connectivity).
/// All in-cluster nodes must run a build that includes the field —
/// postcard's positional struct encoding does not tolerate adding
/// fields across versions. The pre-1.0 project policy is to roll
/// every node forward together.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerEntry {
    /// Long-term identity of the peer (Ed25519 pubkey == NodeId).
    pub node_id: NodeId,
    /// Address we (or an upstream gossip neighbour) last successfully
    /// reached this peer at.
    pub addr: SocketAddr,
    /// Wall-clock millis since the unix epoch at which this entry was
    /// last refreshed by the sender. Receivers use this for last-seen-
    /// wins merge.
    pub last_seen_unix_ms: u64,
    /// Whether the peer accepts inbound TCP/TLS connections.
    ///
    /// `true` is the default for normal validators: other nodes can
    /// dial them when the partial-mesh maintenance loop has a deficit.
    /// `false` is set by nodes running `[p2p] inbound_disabled = true`
    /// (issue #138) — typically operators behind a NAT or asymmetric
    /// firewall that can dial out but cannot accept new connections.
    /// The mesh-maintenance loop skips unreachable peers when picking
    /// dial candidates, so reachable nodes never waste TCP-connect
    /// attempts on hosts that would refuse them.
    ///
    /// The source of truth is the peer itself: every node injects its
    /// own self-entry into each peer-list push with the correct
    /// reachable bit, and the table's last-seen-wins merge propagates
    /// it. Third-party hops cannot fabricate reachability for someone
    /// else once that peer's own self-advertisement has been heard.
    pub reachable: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(byte: u8) -> NodeId {
        [byte; 32]
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[test]
    fn forward_roundtrips_via_postcard() {
        let original = OverlayFrame::Forward {
            msg_id: [7u8; 16],
            originator: nid(42),
            payload: Bytes::from_static(b"hello consensus"),
        };
        let bytes = postcard::to_stdvec(&original).expect("encode");
        let back: OverlayFrame = postcard::from_bytes(&bytes).expect("decode");
        assert_eq!(back, original);
    }

    #[test]
    fn peer_list_roundtrips_via_postcard() {
        let original = OverlayFrame::PeerList(vec![
            PeerEntry {
                node_id: nid(1),
                addr: addr(7000),
                last_seen_unix_ms: 1_700_000_000_000,
                reachable: true,
            },
            PeerEntry {
                node_id: nid(2),
                addr: addr(7001),
                last_seen_unix_ms: 1_700_000_001_000,
                reachable: false,
            },
        ]);
        let bytes = postcard::to_stdvec(&original).expect("encode");
        let back: OverlayFrame = postcard::from_bytes(&bytes).expect("decode");
        assert_eq!(back, original);
    }

    #[test]
    fn empty_peer_list_roundtrips() {
        let original = OverlayFrame::PeerList(Vec::new());
        let bytes = postcard::to_stdvec(&original).expect("encode");
        let back: OverlayFrame = postcard::from_bytes(&bytes).expect("decode");
        assert_eq!(back, original);
    }

    #[test]
    fn rejects_garbage_input() {
        let junk = [0xFFu8; 4];
        assert!(postcard::from_bytes::<OverlayFrame>(&junk).is_err());
    }

    #[test]
    fn variant_discriminant_is_stable() {
        // Capture the bytes that prefix each variant so a future
        // accidental variant-reorder breaks this test rather than
        // silently corrupting on-the-wire compatibility.
        //
        // postcard encodes enum discriminants as a varint; for the
        // first two variants that's a single zero/one byte.
        let forward = OverlayFrame::Forward {
            msg_id: [0; 16],
            originator: [0; 32],
            payload: Bytes::new(),
        };
        let peer_list = OverlayFrame::PeerList(Vec::new());

        let f_bytes = postcard::to_stdvec(&forward).unwrap();
        let p_bytes = postcard::to_stdvec(&peer_list).unwrap();

        assert_eq!(f_bytes[0], 0);
        assert_eq!(p_bytes[0], 1);
    }

    #[test]
    fn peer_entry_carries_reachable_flag() {
        // Issue #138: outbound-only nodes self-advertise with
        // `reachable = false` so the rest of the cluster knows not to
        // attempt to dial them. Round-trip both values to lock the
        // wire shape in.
        let entries = vec![
            PeerEntry {
                node_id: nid(1),
                addr: addr(7000),
                last_seen_unix_ms: 100,
                reachable: true,
            },
            PeerEntry {
                node_id: nid(2),
                addr: addr(7001),
                last_seen_unix_ms: 200,
                reachable: false,
            },
        ];
        let original = OverlayFrame::PeerList(entries);
        let bytes = postcard::to_stdvec(&original).expect("encode");
        let back: OverlayFrame = postcard::from_bytes(&bytes).expect("decode");
        assert_eq!(back, original);
    }
}
