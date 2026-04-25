//! Object-safe [`Broadcaster`] / [`Discovery`] traits — the seam consensus
//! consumes. See the [parent module docs](super) for the delivery
//! contract.

use std::net::SocketAddr;

use bytes::Bytes;
use tokio::sync::broadcast;

use crate::clock::BoxFuture;

use super::super::tls::NodeId;

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
