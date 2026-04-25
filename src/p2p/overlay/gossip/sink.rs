//! Concrete [`OverlayUnicast`] backed by a per-protocol
//! `mpsc::Sender<ProtocolOutbound>`.
//!
//! The peer-list publisher and the gossip overlay's run loop both want
//! a synchronous, best-effort `send_to(node_id, bytes)`. The transport
//! exposes that via a [`crate::p2p::ProtocolOutbound::SendTo`] message
//! pushed onto the per-protocol outbound channel returned by
//! [`crate::p2p::PeerCommand::RegisterProtocol`]. This module is the
//! glue: it wraps a clone of that sender and turns the trait method
//! into a single non-blocking enqueue.
//!
//! # Backpressure: drop-on-full
//!
//! [`OverlayUnicast::send_to`] is sync (returns `()`), so it cannot
//! await capacity. We use [`tokio::sync::mpsc::Sender::try_send`] and
//! drop the payload on `Full` or `Closed`. That matches the trait's
//! contract — peer-list pushes are repeated each interval and overlay
//! `Forward` payloads are deduped+re-fanned-out across multiple
//! neighbours, so a single dropped enqueue is recoverable.
//!
//! Drops are logged at debug to keep the steady-state path quiet; if a
//! receiver task is permanently wedged you'll see a stream of
//! debug-level "outbound channel full" lines, which is the right
//! signal to investigate.
//!
//! # Why not `blocking_send`?
//!
//! `tokio::sync::mpsc::Sender::blocking_send` would let us back-pressure
//! synchronously, but blocking inside an async task wedges the runtime
//! worker. The peer-list publisher and the overlay loop are the only
//! callers and both run on the tokio runtime; `try_send` is the right
//! call.

use bytes::Bytes;
use tokio::sync::mpsc;
use tracing::warn;

use crate::p2p::ProtocolOutbound;
use crate::p2p::tls::NodeId;
use crate::p2p::tls::node_id_to_base58;

use super::peer_list_task::OverlayUnicast;

/// Wraps a per-protocol `Sender<ProtocolOutbound>` and exposes it as an
/// [`OverlayUnicast`] sink.
///
/// Cheap to clone (the underlying `Sender` is `Clone`).
#[derive(Clone)]
pub struct OverlaySink {
    send_tx: mpsc::Sender<ProtocolOutbound>,
}

impl OverlaySink {
    /// Wrap a clone of the per-protocol outbound sender returned by
    /// [`crate::p2p::PeerCommand::RegisterProtocol`].
    pub fn new(send_tx: mpsc::Sender<ProtocolOutbound>) -> Self {
        Self { send_tx }
    }
}

impl OverlayUnicast for OverlaySink {
    fn send_to(&self, target: NodeId, payload: Bytes) {
        let payload_bytes = payload.len();
        match self.send_tx.try_send(ProtocolOutbound::SendTo {
            node_id: target,
            payload,
        }) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                // The transport is back-pressured. Peer-list pushes
                // repeat at the next interval; overlay forwards take
                // multiple paths through the partial mesh — one
                // dropped enqueue is recoverable.
                //
                // Issue #178 follow-up: this drop is a leading suspect
                // for the gossip-layer request loss the reproducer
                // surfaced. Logging at warn with structured fields so
                // a single grep over a wedged node's log surfaces the
                // exact target whose outbound queue is overflowing.
                // Repeated bursts here mean either the per-peer
                // channel capacity is too small for the consensus
                // emit rate (#163 back-pressure) or one specific
                // peer's connection task has stalled.
                warn!(
                    target: "ambros_p2p::p2p::overlay::gossip",
                    target_peer = %node_id_to_base58(&target),
                    payload_bytes,
                    channel_capacity = self.send_tx.capacity(),
                    "overlay_sink_drop_full",
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // Manager has shut down. The overlay loop will exit
                // shortly after via its own shutdown path; nothing to
                // do here.
                warn!(
                    target: "ambros_p2p::p2p::overlay::gossip",
                    target_peer = %node_id_to_base58(&target),
                    "overlay_sink_drop_closed",
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(byte: u8) -> NodeId {
        let mut id = [0u8; 32];
        id[0] = byte;
        id
    }

    #[tokio::test]
    async fn send_to_enqueues_protocol_outbound_send_to() {
        let (tx, mut rx) = mpsc::channel::<ProtocolOutbound>(8);
        let sink = OverlaySink::new(tx);

        sink.send_to(nid(7), Bytes::from_static(b"hello"));

        match rx.recv().await.expect("channel closed") {
            ProtocolOutbound::SendTo { node_id, payload } => {
                assert_eq!(node_id, nid(7));
                assert_eq!(&payload[..], b"hello");
            }
            other => panic!("expected SendTo, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_to_drops_silently_when_channel_full() {
        // Capacity 1; fill it, then assert the next send_to is a no-op
        // (doesn't panic, doesn't block, doesn't enqueue a second
        // entry).
        let (tx, mut rx) = mpsc::channel::<ProtocolOutbound>(1);
        let sink = OverlaySink::new(tx);

        sink.send_to(nid(1), Bytes::from_static(b"first"));
        sink.send_to(nid(2), Bytes::from_static(b"dropped"));

        // First message survives; second was dropped on Full.
        match rx.recv().await.expect("channel closed") {
            ProtocolOutbound::SendTo { node_id, .. } => assert_eq!(node_id, nid(1)),
            other => panic!("expected SendTo, got {other:?}"),
        }
        // Channel must now be empty (no buffered second entry).
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn send_to_drops_silently_when_channel_closed() {
        let (tx, rx) = mpsc::channel::<ProtocolOutbound>(8);
        let sink = OverlaySink::new(tx);
        drop(rx);

        // Must not panic and must not block — the test completing is
        // the assertion.
        sink.send_to(nid(3), Bytes::from_static(b"into the void"));
    }

    #[tokio::test]
    async fn cloned_sink_shares_underlying_channel() {
        let (tx, mut rx) = mpsc::channel::<ProtocolOutbound>(8);
        let sink_a = OverlaySink::new(tx);
        let sink_b = sink_a.clone();

        sink_a.send_to(nid(1), Bytes::from_static(b"a"));
        sink_b.send_to(nid(2), Bytes::from_static(b"b"));

        let mut got = Vec::new();
        for _ in 0..2 {
            match rx.recv().await.expect("channel closed") {
                ProtocolOutbound::SendTo { node_id, .. } => got.push(node_id),
                other => panic!("expected SendTo, got {other:?}"),
            }
        }
        got.sort();
        assert_eq!(got, vec![nid(1), nid(2)]);
    }
}
