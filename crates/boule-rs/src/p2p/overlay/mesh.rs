//! Full-mesh implementations of [`Broadcaster`] and [`Discovery`].
//!
//! These were the original implementations carved out when issue #131
//! introduced the overlay traits. They are still the default while the
//! gossip overlay (issue #137, see [`super::gossip`]) is under
//! construction.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use parking_lot::RwLock;
use tokio::sync::{broadcast, mpsc};
use tracing::debug;

use crate::clock::BoxFuture;

use super::super::ProtocolOutbound;
use super::super::tls::NodeId;
use super::traits::{Broadcaster, Discovery, DiscoveryEvent};

// ── MeshBroadcaster ──────────────────────────────────────────────────────────

/// [`Broadcaster`] backed by the full-mesh peer manager.
///
/// Wraps a clone of the per-protocol `mpsc::Sender<ProtocolOutbound>`
/// returned by [`super::super::PeerCommand::RegisterProtocol`]. Awaiting
/// a `broadcast` / `send_to` is exactly equivalent to the previous
/// `send_tx.send(ProtocolOutbound::Broadcast(...)).await` call site —
/// the manager fans it out across the peer table.
pub struct MeshBroadcaster {
    send_tx: mpsc::Sender<ProtocolOutbound>,
}

impl MeshBroadcaster {
    /// Wrap an outbound `send_tx` channel obtained from a
    /// [`super::super::ProtocolHandle`] into a [`Broadcaster`].
    pub fn new(send_tx: mpsc::Sender<ProtocolOutbound>) -> Self {
        Self { send_tx }
    }
}

impl Broadcaster for MeshBroadcaster {
    fn broadcast(&self, payload: Bytes) -> BoxFuture<'_, ()> {
        let send_tx = self.send_tx.clone();
        Box::pin(async move {
            // Best-effort: drop on shutdown (channel closed) just like
            // the previous direct `send_tx.send().await` call sites.
            let _ = send_tx.send(ProtocolOutbound::Broadcast(payload)).await;
        })
    }

    fn send_to(&self, target: NodeId, payload: Bytes) -> BoxFuture<'_, ()> {
        let send_tx = self.send_tx.clone();
        Box::pin(async move {
            let _ = send_tx
                .send(ProtocolOutbound::SendTo {
                    node_id: target,
                    payload,
                })
                .await;
        })
    }
}

// ── MeshDiscovery ────────────────────────────────────────────────────────────

/// [`Discovery`] backed by the full-mesh peer manager.
///
/// Maintains a local snapshot of the peer set, fed by a background task
/// that subscribes to the manager's [`DiscoveryEvent`] broadcast. The
/// snapshot is read-only for callers; updates flow exclusively from the
/// manager-spawned task.
pub struct MeshDiscovery {
    peers: Arc<RwLock<BTreeSet<NodeId>>>,
    events: broadcast::Sender<DiscoveryEvent>,
}

impl MeshDiscovery {
    /// Spawn the cache-maintenance task and return the resulting
    /// [`Discovery`] implementation.
    ///
    /// `source` is the broadcast receiver wired into the peer manager;
    /// the spawned task forwards every delta into a re-broadcast channel
    /// (so every subsequent `subscribe` call can independently lag) and
    /// updates the local cache used by [`Discovery::known_peers`].
    pub fn spawn(mut source: broadcast::Receiver<DiscoveryEvent>) -> Arc<Self> {
        let peers: Arc<RwLock<BTreeSet<NodeId>>> = Arc::new(RwLock::new(BTreeSet::new()));
        // `64` matches the depth of the peer-gone broadcast in `manager.rs`;
        // peer add/remove churn happens at the same rate, so the same
        // capacity is appropriate.
        let (events, _) = broadcast::channel::<DiscoveryEvent>(64);

        let peers_for_task = Arc::clone(&peers);
        let events_for_task = events.clone();
        tokio::spawn(async move {
            loop {
                match source.recv().await {
                    Ok(ev) => {
                        match &ev {
                            DiscoveryEvent::PeerAdded(p) => {
                                peers_for_task.write().insert(*p);
                            }
                            DiscoveryEvent::PeerRemoved(p) => {
                                peers_for_task.write().remove(p);
                            }
                        }
                        // Re-broadcast so downstream subscribers each get
                        // their own backpressure model. Drop the event if
                        // there are no subscribers — the cache has
                        // already been updated.
                        let _ = events_for_task.send(ev);
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // Lost some events; the cache is now stale. The
                        // manager is the only sender, so this is rare in
                        // practice; we log at debug and keep going. A
                        // future enhancement could trigger a `ListPeers`
                        // resync after lag.
                        debug!("MeshDiscovery: source channel lagged; cache may be stale");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        Arc::new(Self { peers, events })
    }
}

impl Discovery for MeshDiscovery {
    fn known_peers(&self) -> Vec<NodeId> {
        self.peers.read().iter().copied().collect()
    }

    fn add_bootstrap(&self, _addr: SocketAddr) {
        // Mesh today builds its dialer once at boot from the static
        // peer list (`src/p2p/dialer.rs` + `main.rs`'s wiring). Adding a
        // dial post-boot would require plumbing through the dialer
        // factory — explicitly out of scope for #131 (which calls out
        // dynamic membership as a non-goal). Logged at debug so future
        // callers can see they hit the no-op.
        debug!("MeshDiscovery::add_bootstrap is a no-op on the mesh implementation");
    }

    fn subscribe(&self) -> broadcast::Receiver<DiscoveryEvent> {
        self.events.subscribe()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn nid(byte: u8) -> NodeId {
        [byte; 32]
    }

    #[tokio::test]
    async fn mesh_broadcaster_forwards_broadcast_to_send_tx() {
        let (send_tx, mut send_rx) = mpsc::channel::<ProtocolOutbound>(8);
        let bc = MeshBroadcaster::new(send_tx);

        bc.broadcast(Bytes::from_static(b"hello")).await;

        match send_rx.recv().await.expect("send_tx closed") {
            ProtocolOutbound::Broadcast(p) => assert_eq!(&p[..], b"hello"),
            other => panic!("expected Broadcast, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn mesh_broadcaster_forwards_send_to_to_send_tx() {
        let (send_tx, mut send_rx) = mpsc::channel::<ProtocolOutbound>(8);
        let bc = MeshBroadcaster::new(send_tx);

        bc.send_to(nid(7), Bytes::from_static(b"hi")).await;

        match send_rx.recv().await.expect("send_tx closed") {
            ProtocolOutbound::SendTo { node_id, payload } => {
                assert_eq!(node_id, nid(7));
                assert_eq!(&payload[..], b"hi");
            }
            other => panic!("expected SendTo, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn mesh_discovery_tracks_add_and_remove() {
        let (source_tx, source_rx) = broadcast::channel::<DiscoveryEvent>(8);
        let disc = MeshDiscovery::spawn(source_rx);

        source_tx
            .send(DiscoveryEvent::PeerAdded(nid(1)))
            .expect("send");
        source_tx
            .send(DiscoveryEvent::PeerAdded(nid(2)))
            .expect("send");

        // Yield until the spawned task has drained both events. The
        // worst case here is a single scheduler turn; the loop just
        // bounds runaway under unexpected scheduler behaviour.
        for _ in 0..100 {
            tokio::task::yield_now().await;
            if disc.known_peers().len() == 2 {
                break;
            }
        }
        assert_eq!(disc.known_peers(), vec![nid(1), nid(2)]);

        source_tx
            .send(DiscoveryEvent::PeerRemoved(nid(1)))
            .expect("send");
        for _ in 0..100 {
            tokio::task::yield_now().await;
            if disc.known_peers() == vec![nid(2)] {
                break;
            }
        }
        assert_eq!(disc.known_peers(), vec![nid(2)]);
    }

    #[tokio::test]
    async fn mesh_discovery_subscribe_receives_subsequent_events() {
        let (source_tx, source_rx) = broadcast::channel::<DiscoveryEvent>(8);
        let disc = MeshDiscovery::spawn(source_rx);

        let mut sub = disc.subscribe();

        source_tx
            .send(DiscoveryEvent::PeerAdded(nid(3)))
            .expect("send");

        let received = tokio::time::timeout(Duration::from_millis(500), sub.recv())
            .await
            .expect("subscribe times out")
            .expect("subscribe channel closed");
        assert_eq!(received, DiscoveryEvent::PeerAdded(nid(3)));
    }

    #[tokio::test]
    async fn mesh_discovery_add_bootstrap_is_a_noop() {
        let (_source_tx, source_rx) = broadcast::channel::<DiscoveryEvent>(8);
        let disc = MeshDiscovery::spawn(source_rx);
        // Just exercises the no-op path; the assertion is that this
        // doesn't panic and known_peers stays empty.
        disc.add_bootstrap("127.0.0.1:9".parse().unwrap());
        assert!(disc.known_peers().is_empty());
    }
}
