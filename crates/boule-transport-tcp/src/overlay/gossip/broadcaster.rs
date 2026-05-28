//! [`Broadcaster`] implementation for the gossip overlay.
//!
//! [`GossipBroadcaster`] is the consensus-facing handle: it implements
//! [`super::super::Broadcaster`] by enqueueing typed [`OverlayCmd`]
//! values onto an internal `mpsc::Sender`. The consumer is the
//! gossip overlay's run loop (added in a follow-up PR), which dedups
//! the originator's own broadcasts, wraps each payload in an
//! [`super::wire::OverlayFrame::Forward`], and fans it out across
//! the partial mesh.
//!
//! # Why a typed command channel?
//!
//! The run loop needs to multiplex three sources: control commands
//! from this broadcaster (`broadcast` / `send_to`), inbound frames
//! from the protocol receiver (`ProtocolEvent`), and shutdown.
//! Translating into [`OverlayCmd`] at the broadcaster boundary keeps
//! the run loop's `select!` arms clean — every cmd carries exactly
//! the bytes the loop needs, with no further match on the underlying
//! transport enum. Tests in this module drain the channel directly
//! so the broadcaster's behaviour is verifiable without spinning up
//! the loop.
//!
//! # Backpressure
//!
//! [`super::super::Broadcaster::broadcast`] / `send_to` return a
//! `BoxFuture` so callers can preserve `await`-on-send backpressure.
//! That maps directly to `mpsc::Sender::send().await`: the broadcaster
//! awaits capacity on the cmd channel, and a successful await means
//! the bytes have been handed to the run loop's queue. Same contract
//! as the legacy `MeshBroadcaster`.
//!
//! # Drop on shutdown
//!
//! If the run loop has exited (cmd channel closed), `send` returns
//! `Err`. We drop silently — the consumer-side has already torn
//! down and there is no recovery available at this seam. Mirrors
//! the `MeshBroadcaster` behaviour today.

use bytes::Bytes;
use tokio::sync::mpsc;

use boule::clock::BoxFuture;

use super::super::super::tls::NodeId;
use boule_transport::overlay::Broadcaster;

/// Typed command from a [`GossipBroadcaster`] to the gossip overlay's
/// run loop.
///
/// `pub(super)` so the run loop in a sibling module can match on the
/// variants directly while staying invisible to the rest of the
/// crate.
#[derive(Debug)]
pub enum OverlayCmd {
    /// Fan-out path: the run loop generates a fresh `MsgId`, records
    /// it in the dedup ring, and sends a `Forward` frame to every
    /// direct peer.
    Broadcast(Bytes),
    /// Unicast path: the run loop sends a `Forward` frame to
    /// `target` if it is in the direct-peer set; otherwise drops
    /// with a warning.
    SendTo {
        /// Intended recipient.
        target: NodeId,
        /// Application payload.
        payload: Bytes,
    },
}

/// [`Broadcaster`] backed by an `mpsc::Sender<OverlayCmd>` consumed
/// by the gossip overlay's run loop.
///
/// Cheap to clone (the underlying `Sender` is `Clone`); call sites
/// that need to broadcast from multiple tasks can share a single
/// instance via `Arc` or clone freely.
#[derive(Clone)]
pub struct GossipBroadcaster {
    cmd_tx: mpsc::Sender<OverlayCmd>,
}

impl GossipBroadcaster {
    /// Build a broadcaster that pushes onto `cmd_tx`. The consumer
    /// of the matching `cmd_rx` is the overlay's run loop.
    pub fn new(cmd_tx: mpsc::Sender<OverlayCmd>) -> Self {
        Self { cmd_tx }
    }
}

impl Broadcaster for GossipBroadcaster {
    fn broadcast(&self, payload: Bytes) -> BoxFuture<'_, ()> {
        let cmd_tx = self.cmd_tx.clone();
        Box::pin(async move {
            // Best-effort: drop on shutdown (cmd channel closed).
            // Identical posture to MeshBroadcaster's send_tx path.
            let _ = cmd_tx.send(OverlayCmd::Broadcast(payload)).await;
        })
    }

    fn send_to(&self, target: NodeId, payload: Bytes) -> BoxFuture<'_, ()> {
        let cmd_tx = self.cmd_tx.clone();
        Box::pin(async move {
            let _ = cmd_tx.send(OverlayCmd::SendTo { target, payload }).await;
        })
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
    async fn broadcast_enqueues_overlay_cmd_broadcast() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<OverlayCmd>(8);
        let bc = GossipBroadcaster::new(cmd_tx);

        bc.broadcast(Bytes::from_static(b"hello consensus")).await;

        match cmd_rx.recv().await.expect("cmd channel closed") {
            OverlayCmd::Broadcast(p) => assert_eq!(&p[..], b"hello consensus"),
            other => panic!("expected Broadcast, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_to_enqueues_overlay_cmd_send_to() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<OverlayCmd>(8);
        let bc = GossipBroadcaster::new(cmd_tx);

        bc.send_to(nid(7), Bytes::from_static(b"unicast")).await;

        match cmd_rx.recv().await.expect("cmd channel closed") {
            OverlayCmd::SendTo { target, payload } => {
                assert_eq!(target, nid(7));
                assert_eq!(&payload[..], b"unicast");
            }
            other => panic!("expected SendTo, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn broadcast_after_consumer_dropped_is_silent_no_op() {
        let (cmd_tx, cmd_rx) = mpsc::channel::<OverlayCmd>(8);
        let bc = GossipBroadcaster::new(cmd_tx);
        drop(cmd_rx);

        // Must not panic; the awaited future resolves successfully
        // (the inner `send` errored, but we discard the error).
        bc.broadcast(Bytes::from_static(b"into the void")).await;
        bc.send_to(nid(1), Bytes::from_static(b"into the void"))
            .await;
    }

    #[tokio::test]
    async fn cloned_broadcaster_shares_command_channel() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<OverlayCmd>(8);
        let bc_a = GossipBroadcaster::new(cmd_tx);
        let bc_b = bc_a.clone();

        bc_a.broadcast(Bytes::from_static(b"a")).await;
        bc_b.broadcast(Bytes::from_static(b"b")).await;

        let mut got: Vec<Bytes> = Vec::new();
        for _ in 0..2 {
            match cmd_rx.recv().await.expect("cmd channel closed") {
                OverlayCmd::Broadcast(p) => got.push(p),
                other => panic!("expected Broadcast, got {other:?}"),
            }
        }
        got.sort();
        assert_eq!(
            got,
            vec![Bytes::from_static(b"a"), Bytes::from_static(b"b")]
        );
    }

    #[tokio::test]
    async fn broadcast_awaits_consumer_capacity() {
        // Channel of capacity 1: first broadcast fills it, second
        // must await until the consumer drains. Verifies the
        // backpressure contract.
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<OverlayCmd>(1);
        let bc = GossipBroadcaster::new(cmd_tx);

        bc.broadcast(Bytes::from_static(b"first")).await;

        // Spawn the second send; it should block until we drain.
        let bc_clone = bc.clone();
        let blocked = tokio::spawn(async move {
            bc_clone.broadcast(Bytes::from_static(b"second")).await;
        });

        // Briefly yield so the spawned task gets a chance to run.
        tokio::task::yield_now().await;
        assert!(!blocked.is_finished(), "second broadcast should block");

        // Drain the first; the second send unblocks.
        match cmd_rx.recv().await.expect("closed") {
            OverlayCmd::Broadcast(p) => assert_eq!(&p[..], b"first"),
            other => panic!("expected Broadcast, got {other:?}"),
        }
        blocked.await.expect("send task panicked");

        match cmd_rx.recv().await.expect("closed") {
            OverlayCmd::Broadcast(p) => assert_eq!(&p[..], b"second"),
            other => panic!("expected Broadcast, got {other:?}"),
        }
    }
}
