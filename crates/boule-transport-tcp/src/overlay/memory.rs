//! In-memory [`Broadcaster`] and [`Discovery`] fakes for tests.
//!
//! These are **test doubles, not a transport.** Consensus is
//! transport-agnostic — [`boule_consensus`]'s `ConsensusNode::run` takes
//! `Arc<dyn Broadcaster>` + `Arc<dyn Discovery>` — so tests drive a node
//! by handing it these fakes instead of standing up TCP+TLS:
//!
//! - [`MemoryBroadcaster`] forwards every frame onto an `mpsc` channel
//!   the test (or the in-process `SimCluster` router) drains; there is
//!   no peer table and no fan-out.
//! - [`MemoryDiscovery`] tracks a peer set fed by a [`DiscoveryEvent`]
//!   broadcast the test publishes onto; [`Discovery::add_bootstrap`] is a
//!   no-op because there is nothing to dial.
//!
//! The real production overlay is [`super::gossip`].

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use parking_lot::RwLock;
use tokio::sync::{broadcast, mpsc};
use tracing::debug;

use boule_core::clock::BoxFuture;

use super::super::ProtocolOutbound;
use super::super::tls::NodeId;
use boule_core::transport::overlay::{Broadcaster, Discovery, DiscoveryEvent};

// ── MemoryBroadcaster ────────────────────────────────────────────────────────

/// In-memory [`Broadcaster`] fake: forwards each frame onto an
/// `mpsc::Sender<ProtocolOutbound>` that a test drains.
///
/// `broadcast` enqueues a [`ProtocolOutbound::Broadcast`] and `send_to`
/// a [`ProtocolOutbound::SendTo`]; the receiving end of the channel is
/// the test's in-process router (e.g. `SimCluster`), which decides who
/// actually "receives" the frame. There is no peer table, no transport,
/// and no fan-out here — that is the test harness's job.
pub struct MemoryBroadcaster {
    send_tx: mpsc::Sender<ProtocolOutbound>,
}

impl MemoryBroadcaster {
    /// Wrap an outbound `send_tx` channel whose receiver the test owns.
    pub fn new(send_tx: mpsc::Sender<ProtocolOutbound>) -> Self {
        Self { send_tx }
    }
}

impl Broadcaster for MemoryBroadcaster {
    fn broadcast(&self, payload: Bytes) -> BoxFuture<'_, ()> {
        let send_tx = self.send_tx.clone();
        Box::pin(async move {
            // Best-effort: drop on shutdown (channel closed), matching
            // the real overlays' send posture.
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

// ── MemoryDiscovery ──────────────────────────────────────────────────────────

/// In-memory [`Discovery`] fake: tracks a peer set fed by a
/// [`DiscoveryEvent`] broadcast the test publishes onto.
///
/// A background task drains the `source` receiver, applies each
/// add/remove to a local snapshot (read by [`Discovery::known_peers`]),
/// and re-broadcasts the delta so every [`Discovery::subscribe`] caller
/// gets its own independently-lagging stream. There is no dialer, so
/// [`Discovery::add_bootstrap`] is a no-op.
pub struct MemoryDiscovery {
    peers: Arc<RwLock<BTreeSet<NodeId>>>,
    events: broadcast::Sender<DiscoveryEvent>,
}

impl MemoryDiscovery {
    /// Spawn the cache-maintenance task and return the resulting
    /// [`Discovery`] fake.
    ///
    /// `source` is a [`DiscoveryEvent`] receiver the test publishes
    /// peer add/remove deltas onto; the spawned task folds each into the
    /// local cache and re-broadcasts it to downstream subscribers.
    pub fn spawn(mut source: broadcast::Receiver<DiscoveryEvent>) -> Arc<Self> {
        let peers: Arc<RwLock<BTreeSet<NodeId>>> = Arc::new(RwLock::new(BTreeSet::new()));
        // 64 is generous for the churn a test drives; matches the
        // depth the production overlays use for the same event stream.
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
                        debug!("MemoryDiscovery: source channel lagged; cache may be stale");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        Arc::new(Self { peers, events })
    }
}

impl Discovery for MemoryDiscovery {
    fn known_peers(&self) -> Vec<NodeId> {
        self.peers.read().iter().copied().collect()
    }

    fn add_bootstrap(&self, _addr: SocketAddr) {
        // No-op: the in-memory fake has no dialer; the peer set is
        // driven entirely by the `DiscoveryEvent` source the test feeds.
        debug!("MemoryDiscovery::add_bootstrap is a no-op on the in-memory fake");
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
    async fn memory_broadcaster_forwards_broadcast_to_send_tx() {
        let (send_tx, mut send_rx) = mpsc::channel::<ProtocolOutbound>(8);
        let bc = MemoryBroadcaster::new(send_tx);

        bc.broadcast(Bytes::from_static(b"hello")).await;

        match send_rx.recv().await.expect("send_tx closed") {
            ProtocolOutbound::Broadcast(p) => assert_eq!(&p[..], b"hello"),
            other => panic!("expected Broadcast, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn memory_broadcaster_forwards_send_to_to_send_tx() {
        let (send_tx, mut send_rx) = mpsc::channel::<ProtocolOutbound>(8);
        let bc = MemoryBroadcaster::new(send_tx);

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
    async fn memory_discovery_tracks_add_and_remove() {
        let (source_tx, source_rx) = broadcast::channel::<DiscoveryEvent>(8);
        let disc = MemoryDiscovery::spawn(source_rx);

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
    async fn memory_discovery_subscribe_receives_subsequent_events() {
        let (source_tx, source_rx) = broadcast::channel::<DiscoveryEvent>(8);
        let disc = MemoryDiscovery::spawn(source_rx);

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
    async fn memory_discovery_add_bootstrap_is_a_noop() {
        let (_source_tx, source_rx) = broadcast::channel::<DiscoveryEvent>(8);
        let disc = MemoryDiscovery::spawn(source_rx);
        // Just exercises the no-op path; the assertion is that this
        // doesn't panic and known_peers stays empty.
        disc.add_bootstrap("127.0.0.1:9".parse().unwrap());
        assert!(disc.known_peers().is_empty());
    }
}
