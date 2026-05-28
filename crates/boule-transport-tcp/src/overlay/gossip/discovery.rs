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
//! run loop calls `GossipDiscovery::publish` when it observes a
//! [`crate::ProtocolEvent::PeerConnected`] /
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
//! Triggers an outbound dial through the [`super::maintenance::Dialer`]
//! the constructor was given, with `expected = None` (TOFU — accept
//! whatever identity the peer presents on the handshake). The dial
//! is fire-and-forget: the dialer task retries on failure with
//! exponential backoff and the manager fans out a `PeerConnected`
//! event once the handshake completes, which the overlay
//! orchestrator then turns into a `DiscoveryEvent::PeerAdded`.
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

use super::super::super::tls::NodeId;
use super::maintenance::Dialer;
use super::peer_list_task::{DirectPeers, LockedVec};
use boule_transport::overlay::{Discovery, DiscoveryEvent};

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
    /// holds a clone of the sender and calls `publish` on
    /// observed peer add/remove transitions.
    events: broadcast::Sender<DiscoveryEvent>,
    /// Dialer used by [`Discovery::add_bootstrap`] to start an
    /// outbound dial loop targeting a fresh address. Shared with the
    /// partial-mesh maintenance loop.
    dialer: Arc<dyn Dialer>,
}

impl GossipDiscovery {
    /// Build a new discovery instance plus its companion event
    /// sender (for the run loop's use). The discovery shares
    /// ownership of `direct` with whoever else mutates the LockedVec
    /// (currently the run loop, exclusively); `dialer` is used by
    /// [`Discovery::add_bootstrap`] to start a TOFU dial against a
    /// freshly-learned address.
    pub fn new(
        direct: Arc<LockedVec>,
        dialer: Arc<dyn Dialer>,
    ) -> (Self, broadcast::Sender<DiscoveryEvent>) {
        let (events_tx, _) = broadcast::channel::<DiscoveryEvent>(DISCOVERY_CHANNEL_DEPTH);
        let me = Self {
            direct,
            events: events_tx.clone(),
            dialer,
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

    fn add_bootstrap(&self, addr: SocketAddr) {
        // TOFU dial — accept whatever identity the peer presents on
        // the handshake. The reconnect loop the dialer spawns retries
        // on failure with exponential backoff and the manager fans
        // out a `PeerConnected` event once handshake succeeds, which
        // the orchestrator translates into the
        // `DiscoveryEvent::PeerAdded` subscribers see.
        self.dialer.dial(addr, None);
    }

    fn subscribe(&self) -> broadcast::Receiver<DiscoveryEvent> {
        self.events.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use parking_lot::Mutex;

    use super::*;

    fn nid(byte: u8) -> NodeId {
        let mut id = [0u8; 32];
        id[0] = byte;
        id
    }

    /// No-op `Dialer` used by tests that don't care about the
    /// `add_bootstrap` plumbing.
    struct NullDialer;

    impl Dialer for NullDialer {
        fn dial(&self, _: SocketAddr, _: Option<NodeId>) {}
    }

    fn null_dialer() -> Arc<dyn Dialer> {
        Arc::new(NullDialer)
    }

    /// Recording `Dialer` used by the `add_bootstrap` test below to
    /// assert that `add_bootstrap(addr)` triggers a TOFU dial.
    #[derive(Default)]
    struct RecordingDialer {
        dialed: Mutex<Vec<(SocketAddr, Option<NodeId>)>>,
    }

    impl Dialer for RecordingDialer {
        fn dial(&self, addr: SocketAddr, expected: Option<NodeId>) {
            self.dialed.lock().push((addr, expected));
        }
    }

    #[tokio::test]
    async fn known_peers_reflects_locked_vec_snapshot() {
        let direct = Arc::new(LockedVec::new());
        let (disc, _events_tx) = GossipDiscovery::new(direct.clone(), null_dialer());

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
        let (disc, events_tx) = GossipDiscovery::new(direct, null_dialer());

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
        let (disc, events_tx) = GossipDiscovery::new(direct, null_dialer());

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
        let (disc, events_tx) = GossipDiscovery::new(direct, null_dialer());

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
    async fn add_bootstrap_triggers_tofu_dial() {
        let direct = Arc::new(LockedVec::new());
        let dialer = Arc::new(RecordingDialer::default());
        let (disc, _events_tx) =
            GossipDiscovery::new(direct.clone(), dialer.clone() as Arc<dyn Dialer>);

        let target: SocketAddr = "127.0.0.1:9".parse().unwrap();
        disc.add_bootstrap(target);

        // `Dialer::dial` is sync — recording mock captures the call
        // immediately even though the underlying dialer task is
        // fire-and-forget in production.
        let dialed = dialer.dialed.lock().clone();
        assert_eq!(dialed.len(), 1);
        assert_eq!(dialed[0].0, target);
        assert_eq!(dialed[0].1, None, "bootstrap dials use TOFU semantics");

        // Direct-peer set is unaffected until the manager reports a
        // PeerConnected event (out of scope for this unit test).
        assert!(disc.known_peers().is_empty());
    }

    #[tokio::test]
    async fn cloned_discovery_shares_underlying_state() {
        let direct = Arc::new(LockedVec::new());
        let (disc_a, events_tx) = GossipDiscovery::new(direct.clone(), null_dialer());
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
