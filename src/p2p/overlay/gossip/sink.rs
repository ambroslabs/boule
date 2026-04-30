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

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

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
///
/// Carries an `Arc<AtomicU64>` overflow counter that increments every
/// time `send_to` returns `Full` from `try_send`. Cloned sinks share the
/// same counter so the rolled-up total reflects every drop on every
/// caller. Operators surface this through `ConsensusStatus` to spot
/// repeated drops without having to grep tracing logs (#163 / #486).
#[derive(Clone)]
pub struct OverlaySink {
    send_tx: mpsc::Sender<ProtocolOutbound>,
    overflows: Arc<AtomicU64>,
}

impl OverlaySink {
    /// Wrap a clone of the per-protocol outbound sender returned by
    /// [`crate::p2p::PeerCommand::RegisterProtocol`].
    pub fn new(send_tx: mpsc::Sender<ProtocolOutbound>) -> Self {
        Self {
            send_tx,
            overflows: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Shared handle to the overflow counter. Increments every time
    /// [`OverlayUnicast::send_to`] hits `try_send` `Full`. The closed
    /// case is intentionally not counted: those drops are a normal
    /// consequence of a manager shutting down and would mask real
    /// back-pressure events.
    pub fn overflow_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.overflows)
    }

    /// Read the current overflow count. Monotonic for the lifetime of
    /// the sink (and any clones); never decrements.
    pub fn overflow_count(&self) -> u64 {
        self.overflows.load(Ordering::Relaxed)
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
                self.overflows.fetch_add(1, Ordering::Relaxed);
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
        // entry) and the overflow counter increments.
        let (tx, mut rx) = mpsc::channel::<ProtocolOutbound>(1);
        let sink = OverlaySink::new(tx);

        sink.send_to(nid(1), Bytes::from_static(b"first"));
        assert_eq!(sink.overflow_count(), 0);
        sink.send_to(nid(2), Bytes::from_static(b"dropped"));
        assert_eq!(sink.overflow_count(), 1);

        // First message survives; second was dropped on Full.
        match rx.recv().await.expect("channel closed") {
            ProtocolOutbound::SendTo { node_id, .. } => assert_eq!(node_id, nid(1)),
            other => panic!("expected SendTo, got {other:?}"),
        }
        // Channel must now be empty (no buffered second entry).
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn overflow_counter_does_not_increment_on_closed() {
        // Closed receivers fire when the manager is shutting down;
        // counting those would mask real back-pressure events.
        let (tx, rx) = mpsc::channel::<ProtocolOutbound>(8);
        let sink = OverlaySink::new(tx);
        drop(rx);

        sink.send_to(nid(3), Bytes::from_static(b"into the void"));
        assert_eq!(sink.overflow_count(), 0);
    }

    #[tokio::test]
    async fn cloned_sinks_share_the_overflow_counter() {
        // Capacity 1; fill from sink_a, drop from sink_b — the
        // counter on either handle reflects the shared total.
        let (tx, _rx) = mpsc::channel::<ProtocolOutbound>(1);
        let sink_a = OverlaySink::new(tx);
        let sink_b = sink_a.clone();

        sink_a.send_to(nid(1), Bytes::from_static(b"first"));
        sink_b.send_to(nid(2), Bytes::from_static(b"dropped"));
        assert_eq!(sink_a.overflow_count(), 1);
        assert_eq!(sink_b.overflow_count(), 1);

        let counter = sink_a.overflow_counter();
        assert_eq!(counter.load(Ordering::Relaxed), 1);
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
