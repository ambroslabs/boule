//! [`Discovery`] implementation for the gossip overlay.
//!
//! [`GossipDiscovery`] is the consensus-facing peer-membership handle.
//! It snapshots the live direct-peer set (the same `Arc<LockedVec>`
//! the peer-list publisher and mesh-maintenance loop already share)
//! and re-broadcasts add/remove deltas through a `tokio::sync::broadcast`
//! channel.
//!
//! Producer side — the channel sender plus the `LockedVec` — is owned
//! by the gossip overlay's run loop (added in a follow-up PR). The
//! run loop calls [`GossipDiscovery::publish`] when it observes a
//! [`crate::p2p::ProtocolEvent::PeerConnected`] /
//! `PeerDisconnected` so this module can stay decoupled from the
//! transport plumbing.
//!
//! # `known_peers` semantics
//!
//! Direct peers only — i.e. the same set the broadcaster fans out to.
//! That matches the [`super::super::Discovery::known_peers`] doc
//! ("currently reachable") for a partial-mesh implementation: a peer
//! we've only learned about transitively via peer-list gossip is in
//! the [`super::peer_table::PeerTable`] but is *not* "currently
//! reachable" until the maintenance loop dials it. Surfacing the
//! full peer table here would be misleading.
//!
//! # `add_bootstrap`
//!
//! Currently a debug-log no-op. The bootstrap-address ingestion path
//! requires plumbing a [`super::maintenance::Dialer`] through; that
//! happens in the binary-wiring PR (PR5b), where the overlay receives
//! a constructed dialer at boot. Logging at debug means future call
//! sites see they hit the placeholder.
//!
//! # Subscribe semantics
//!
//! Each subscriber receives every [`super::super::DiscoveryEvent`]
//! published from the moment of subscription onward; events that
//! fired before the subscriber existed are not replayed. Slow
//! subscribers may lag (per `tokio::sync::broadcast` semantics) and
//! miss events; combine `subscribe()` with a follow-up
//! `known_peers()` snapshot for an always-current view. Same
//! contract as the legacy [`super::super::MeshDiscovery`].

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::broadcast;
use tracing::debug;

use super::super::super::tls::NodeId;
use super::super::traits::{Discovery, DiscoveryEvent};
use super::peer_list_task::{DirectPeers, LockedVec};

/// Broadcast channel depth for re-published `DiscoveryEvent`s.
///
/// Matches the depth used by `MeshDiscovery::spawn` — peer churn
/// happens at the same rate regardless of overlay impl.
const DISCOVERY_CHANNEL_DEPTH: usize = 64;

/// [`Discovery`] implementation backed by the gossip overlay's
/// shared direct-peer set and a re-broadcast channel.
///
/// Cheap to clone (everything inside is `Arc` or `Clone`).
#[derive(Clone)]
pub struct GossipDiscovery {
    /// Shared direct-peer set; same `Arc<LockedVec>` the peer-list
    /// publisher and mesh-maintenance loop snapshot. Updates flow
    /// from the overlay run loop on `ProtocolEvent::PeerConnected`
    /// / `PeerDisconnected`.
    direct: Arc<LockedVec>,
    /// Re-broadcast channel for [`DiscoveryEvent`]s. The run loop
    /// holds a clone of the sender and calls [`Self::publish`] on
    /// observed peer add/remove transitions.
    events: broadcast::Sender<DiscoveryEvent>,
}

impl GossipDiscovery {
    /// Build a new discovery instance plus its companion event
    /// sender (for the run loop's use). The discovery shares
    /// ownership of `direct` with whoever else mutates the LockedVec
    /// (currently the run loop, exclusively).
    pub fn new(direct: Arc<LockedVec>) -> (Self, broadcast::Sender<DiscoveryEvent>) {
        let (events_tx, _) = broadcast::channel::<DiscoveryEvent>(DISCOVERY_CHANNEL_DEPTH);
        let me = Self {
            direct,
            events: events_tx.clone(),
        };
        (me, events_tx)
    }
}

impl Discovery for GossipDiscovery {
    fn known_peers(&self) -> Vec<NodeId> {
        // LockedVec releases its internal RwLock before returning the
        // snapshot; safe to hold the result across .await points
        // upstream.
        DirectPeers::snapshot(&*self.direct)
    }

    fn add_bootstrap(&self, _addr: SocketAddr) {
        // Real impl lands in PR5b alongside the binary wiring (the
        // dialer needs to be constructed there). Logging at debug so
        // call sites can see they hit the placeholder.
        debug!("GossipDiscovery::add_bootstrap is currently a no-op (wiring lands in PR5b)");
    }

    fn subscribe(&self) -> broadcast::Receiver<DiscoveryEvent> {
        self.events.subscribe()
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
    async fn known_peers_reflects_locked_vec_snapshot() {
        let direct = Arc::new(LockedVec::new());
        let (disc, _events_tx) = GossipDiscovery::new(direct.clone());

        assert!(disc.known_peers().is_empty());

        direct.set(vec![nid(1), nid(2), nid(3)]);
        let mut got = disc.known_peers();
        got.sort();
        assert_eq!(got, vec![nid(1), nid(2), nid(3)]);

        // Removing a peer flows through.
        direct.set(vec![nid(1), nid(3)]);
        let mut got = disc.known_peers();
        got.sort();
        assert_eq!(got, vec![nid(1), nid(3)]);
    }

    #[tokio::test]
    async fn subscribe_receives_subsequent_events_from_run_loop_sender() {
        let direct = Arc::new(LockedVec::new());
        let (disc, events_tx) = GossipDiscovery::new(direct);

        let mut sub = disc.subscribe();

        // Producer side (the run loop in production) publishes here.
        events_tx
            .send(DiscoveryEvent::PeerAdded(nid(1)))
            .expect("send");
        events_tx
            .send(DiscoveryEvent::PeerRemoved(nid(2)))
            .expect("send");

        let ev1 = sub.recv().await.expect("subscribe channel closed");
        let ev2 = sub.recv().await.expect("subscribe channel closed");
        assert_eq!(ev1, DiscoveryEvent::PeerAdded(nid(1)));
        assert_eq!(ev2, DiscoveryEvent::PeerRemoved(nid(2)));
    }

    #[tokio::test]
    async fn subscribe_does_not_replay_pre_subscription_events() {
        let direct = Arc::new(LockedVec::new());
        let (disc, events_tx) = GossipDiscovery::new(direct);

        // Pre-subscription event is dropped (no subscribers yet).
        let _ = events_tx.send(DiscoveryEvent::PeerAdded(nid(99)));

        let mut sub = disc.subscribe();

        events_tx
            .send(DiscoveryEvent::PeerAdded(nid(1)))
            .expect("send");

        let ev = sub.recv().await.expect("subscribe channel closed");
        assert_eq!(ev, DiscoveryEvent::PeerAdded(nid(1)));

        // No backlog from before subscription.
        assert!(matches!(
            sub.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn multiple_subscribers_each_receive_every_event() {
        let direct = Arc::new(LockedVec::new());
        let (disc, events_tx) = GossipDiscovery::new(direct);

        let mut sub_a = disc.subscribe();
        let mut sub_b = disc.subscribe();

        events_tx
            .send(DiscoveryEvent::PeerAdded(nid(7)))
            .expect("send");

        let ev_a = sub_a.recv().await.expect("sub_a closed");
        let ev_b = sub_b.recv().await.expect("sub_b closed");
        assert_eq!(ev_a, DiscoveryEvent::PeerAdded(nid(7)));
        assert_eq!(ev_b, DiscoveryEvent::PeerAdded(nid(7)));
    }

    #[tokio::test]
    async fn add_bootstrap_is_a_noop() {
        let direct = Arc::new(LockedVec::new());
        let (disc, _events_tx) = GossipDiscovery::new(direct);

        // Just exercises the placeholder path — must not panic and
        // must not affect known_peers.
        disc.add_bootstrap("127.0.0.1:9".parse().unwrap());
        assert!(disc.known_peers().is_empty());
    }

    #[tokio::test]
    async fn cloned_discovery_shares_underlying_state() {
        let direct = Arc::new(LockedVec::new());
        let (disc_a, events_tx) = GossipDiscovery::new(direct.clone());
        let disc_b = disc_a.clone();

        direct.set(vec![nid(1)]);
        let mut sub_b = disc_b.subscribe();

        events_tx
            .send(DiscoveryEvent::PeerAdded(nid(1)))
            .expect("send");

        // Both clones see the same direct-peer snapshot.
        assert_eq!(disc_a.known_peers(), vec![nid(1)]);
        assert_eq!(disc_b.known_peers(), vec![nid(1)]);

        // The b-side subscription receives the event.
        let ev = sub_b.recv().await.expect("closed");
        assert_eq!(ev, DiscoveryEvent::PeerAdded(nid(1)));
    }
}
