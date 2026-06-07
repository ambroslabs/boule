//! Object-safe [`Broadcaster`] / [`Discovery`] traits — the seam consensus
//! consumes. See the [parent module docs](super) for the delivery
//! contract.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use bytes::Bytes;
use tokio::sync::{broadcast, mpsc};
use tracing::debug;

use crate::clock::BoxFuture;

use crate::identity::NodeId;

// ── Broadcaster trait ────────────────────────────────────────────────────────

/// Outbound dispatch surface for an application protocol.
///
/// See the [parent module docs](super) for the delivery contract.
pub trait Broadcaster: Send + Sync {
    /// Send `payload` to every currently reachable peer.
    ///
    /// On the mesh implementation this fans out to every entry in the
    /// peer manager's connection table. On a future gossip
    /// implementation it would push to a small fanout subset and rely
    /// on receivers to forward.
    ///
    /// Awaiting the returned future blocks until the payload is queued
    /// in the underlying transport — the standard backpressure point.
    fn broadcast(&self, payload: Bytes) -> BoxFuture<'_, ()>;

    /// Send `payload` to the single peer `target`.
    ///
    /// If `target` is not currently reachable the implementation may
    /// silently drop the payload (the mesh today does so via the
    /// manager's `SendTo unknown peer …` warn-log path). Self-addressed
    /// sends are also dropped — see the parent module docs.
    fn send_to(&self, target: NodeId, payload: Bytes) -> BoxFuture<'_, ()>;
}

// ── Discovery trait ──────────────────────────────────────────────────────────

/// An add/remove delta in the peer set, published by [`Discovery::subscribe`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryEvent {
    /// A peer just became reachable.
    PeerAdded(NodeId),
    /// A peer is no longer reachable.
    PeerRemoved(NodeId),
}

/// Peer-membership and bootstrap surface.
///
/// Consensus consumes this for two purposes: a synchronous snapshot via
/// [`Discovery::known_peers`] when reporting status, and an event
/// stream via [`Discovery::subscribe`] to keep its own per-peer state
/// (e.g. consensus-layer connectivity tracking) in sync.
pub trait Discovery: Send + Sync {
    /// Snapshot the currently reachable peer set.
    ///
    /// The returned vector is freshly allocated and the underlying
    /// cache lock is released before this method returns; callers may
    /// hold the result across `.await` points without risking
    /// deadlocks.
    ///
    /// "Currently reachable" follows the implementation's own
    /// definition. For the mesh implementation this is "the peer
    /// manager has an open TLS connection". For a future gossip
    /// implementation this would be "we have a routing entry for this
    /// peer in the overlay".
    fn known_peers(&self) -> Vec<NodeId>;

    /// Hint that the implementation should attempt an outbound dial
    /// to `addr` if it doesn't already have one.
    ///
    /// The mesh implementation today is no-op (the static peer list in
    /// the config drives the dialer at boot — see #131 non-goals on
    /// dynamic membership). Future gossip / Kademlia implementations
    /// will use this for bootstrap-address ingestion.
    fn add_bootstrap(&self, addr: SocketAddr);

    /// Subscribe to the discovery event stream.
    ///
    /// Each subscriber receives every [`DiscoveryEvent`] published from
    /// the moment of subscription onward; events that fired before the
    /// subscriber existed are not replayed. Slow subscribers may lag
    /// (per `tokio::sync::broadcast` semantics) and miss events; for an
    /// always-current view of the peer set, combine `subscribe` with a
    /// follow-up `known_peers` snapshot.
    fn subscribe(&self) -> broadcast::Receiver<DiscoveryEvent>;
}

// ── ProtocolEvent ──────────────────────────────────────────────────────────────

/// Inbound seam an overlay implementation delivers to consensus.
///
/// Every overlay backend (the custom gossip overlay, the libp2p backend)
/// surfaces inbound activity to consensus as a stream of these events:
/// `PeerConnected` / `PeerDisconnected` membership deltas and `Message`
/// payloads. This lives in `boule-core` (not a specific transport crate) so
/// any backend can produce it without depending on another transport.
#[derive(Debug)]
pub enum ProtocolEvent {
    /// A peer just completed the handshake and is addressable.
    PeerConnected {
        /// The peer that just connected.
        node_id: NodeId,
        /// Remote address the peer is reachable at.
        ///
        /// On outbound connections this is the dial target; on inbound
        /// connections it is whatever the listener saw on `accept`. The
        /// custom gossip overlay (#137) uses this to seed its `PeerTable`;
        /// backends/protocols that don't care can ignore it.
        addr: SocketAddr,
    },
    /// A peer disconnected (network failure, explicit teardown, or
    /// peer-side close).
    PeerDisconnected {
        /// The peer that just disconnected.
        node_id: NodeId,
    },
    /// An application payload arrived from `from`.
    Message {
        /// The sender, already authenticated by the transport.
        from: NodeId,
        /// Opaque application payload (any transport framing stripped).
        payload: Bytes,
    },
}

// ── ProtocolOutbound ─────────────────────────────────────────────────────────

/// Outbound direction of a protocol: a frame the overlay should put on the
/// wire. The dual of [`ProtocolEvent`]. Lives in `boule-core` so test doubles
/// and any transport backend can produce it without depending on a specific
/// transport crate.
#[derive(Debug)]
pub enum ProtocolOutbound {
    /// Send this payload to every currently connected peer. Used for message
    /// fan-out.
    Broadcast(Bytes),
    /// Send this payload to a single peer (request/response, unicast).
    SendTo {
        /// Target peer.
        node_id: NodeId,
        /// Opaque application-level payload.
        payload: Bytes,
    },
}

// ── In-memory test doubles ───────────────────────────────────────────────────

/// In-memory [`Broadcaster`] fake: forwards each frame onto an
/// `mpsc::Sender<ProtocolOutbound>` that a test drains. There is no peer
/// table, no transport, and no fan-out — that is the test harness's job.
///
/// A **test double, not a transport.** Consensus is transport-agnostic, so
/// tests drive a node by handing it this fake instead of standing up a real
/// overlay.
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

/// In-memory [`Discovery`] fake: tracks a peer set fed by a [`DiscoveryEvent`]
/// broadcast the test publishes onto. A background task folds each add/remove
/// into a local snapshot and re-broadcasts the delta. There is no dialer, so
/// [`Discovery::add_bootstrap`] is a no-op. A **test double, not a transport.**
pub struct MemoryDiscovery {
    peers: Arc<RwLock<BTreeSet<NodeId>>>,
    events: broadcast::Sender<DiscoveryEvent>,
}

impl MemoryDiscovery {
    /// Spawn the cache-maintenance task and return the resulting [`Discovery`]
    /// fake. `source` is a [`DiscoveryEvent`] receiver the test publishes peer
    /// add/remove deltas onto.
    pub fn spawn(mut source: broadcast::Receiver<DiscoveryEvent>) -> Arc<Self> {
        let peers: Arc<RwLock<BTreeSet<NodeId>>> = Arc::new(RwLock::new(BTreeSet::new()));
        let (events, _) = broadcast::channel::<DiscoveryEvent>(64);

        let peers_for_task = Arc::clone(&peers);
        let events_for_task = events.clone();
        tokio::spawn(async move {
            loop {
                match source.recv().await {
                    Ok(ev) => {
                        match &ev {
                            DiscoveryEvent::PeerAdded(p) => {
                                peers_for_task.write().unwrap().insert(*p);
                            }
                            DiscoveryEvent::PeerRemoved(p) => {
                                peers_for_task.write().unwrap().remove(p);
                            }
                        }
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
        self.peers.read().unwrap().iter().copied().collect()
    }

    fn add_bootstrap(&self, _addr: SocketAddr) {
        debug!("MemoryDiscovery::add_bootstrap is a no-op on the in-memory fake");
    }

    fn subscribe(&self) -> broadcast::Receiver<DiscoveryEvent> {
        self.events.subscribe()
    }
}

#[cfg(test)]
mod memory_tests {
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
        disc.add_bootstrap("127.0.0.1:9".parse().unwrap());
        assert!(disc.known_peers().is_empty());
    }
}
