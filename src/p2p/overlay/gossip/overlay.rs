//! `GossipOverlay` — the orchestrator that wires the gossip overlay's
//! standalone pieces (peer table, dedup ring, partial-mesh maintenance,
//! peer-list publisher, broadcaster, discovery) into a single tokio
//! task plus two helper tasks.
//!
//! # Why one task?
//!
//! The orchestrator owns the dedup ring (touched on broadcast and on
//! every inbound `Forward`), the live direct-peer set (mutated on
//! `ProtocolEvent::PeerConnected` / `PeerDisconnected`, snapshotted by
//! the broadcaster's fanout, the publisher, the maintenance loop, and
//! the discovery snapshot), and the inbound `ProtocolEvent` channel
//! from the peer manager. Putting these on one task keeps the dedup
//! ring lock-free and lets every command/event handler stay
//! non-blocking.
//!
//! # Sub-tasks
//!
//! [`spawn`](GossipOverlay::spawn) also starts:
//!
//! - [`super::peer_list_task::run_peer_list_publisher`] — pushes a
//!   peer-table snapshot to a randomized fanout subset of direct
//!   peers every [`super::peer_list_task::PeerListGossipConfig::interval`].
//! - [`super::maintenance::run_mesh_maintenance`] — dials extra peers
//!   from the table when the direct-peer count is below
//!   [`super::maintenance::MeshMaintenanceConfig::target_degree`].
//!
//! Both share the orchestrator's `PeerTable` and `Arc<LockedVec>` of
//! direct peers; both shut down when the orchestrator's shutdown is
//! signaled.
//!
//! # Upstream events
//!
//! The orchestrator owns the raw `ProtocolEvent` receiver from
//! `PeerCommand::RegisterProtocol` and exposes a fresh upstream
//! `mpsc::Receiver<ProtocolEvent>` via [`GossipOverlayHandles::event_rx`]
//! that the consensus loop consumes in place of the raw rx.
//!
//! Two filters apply:
//!
//! 1. `ProtocolEvent::Message` carrying an [`super::wire::OverlayFrame::PeerList`]
//!    is merged into the peer table and **not** surfaced upstream — it
//!    is overlay control traffic.
//! 2. `ProtocolEvent::PeerConnected` / `PeerDisconnected` are recorded
//!    in the direct-peer set and republished as
//!    [`super::super::traits::DiscoveryEvent`]s, but **not** surfaced
//!    upstream. The consensus layer reads peer membership through
//!    [`super::super::traits::Discovery::subscribe`]; routing the same
//!    deltas through the upstream `event_rx` would be a duplicate.
//!    (Today the consensus event loop in
//!    [`crate::consensus::node`] explicitly ignores
//!    `PeerConnected`/`PeerDisconnected` for the same reason.)
//!
//! Forwarded application payloads carried in
//! [`super::wire::OverlayFrame::Forward`] are dedup-checked, surfaced
//! upstream as `ProtocolEvent::Message { from: originator, payload }`
//! (so the consumer sees the broadcast originator's `NodeId` rather
//! than whichever neighbour relayed it on the last hop), and
//! re-broadcast to direct peers other than the relay sender.
//!
//! # `SendTo` fallback
//!
//! [`super::super::traits::Broadcaster::send_to`] for a `target` that
//! is not a current direct neighbour falls back to a broadcast — the
//! gossip overlay does not route point-to-point. Documented on
//! [`super::super::traits::Broadcaster::send_to`] too. See the
//! breakdown comment on issue #137 for the rationale.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, info};

use crate::clock::Clock;
use crate::p2p::ProtocolEvent;
use crate::p2p::dialer::DialerCtx;
use crate::p2p::tls::NodeId;

use super::super::traits::DiscoveryEvent;
use super::broadcaster::{GossipBroadcaster, OverlayCmd};
use super::dedup::{InsertOutcome, MsgIdRing};
use super::discovery::GossipDiscovery;
use super::maintenance::{Dialer, MeshMaintenanceConfig, run_mesh_maintenance};
use super::peer_list_task::{
    DirectPeers, FrameOutcome, LockedVec, OverlayUnicast, PeerListGossipConfig, SelfAdvertise,
    apply_overlay_frame, run_peer_list_publisher,
};
use super::peer_table::PeerTable;
use super::wire::{MsgId, OverlayFrame};

/// Knobs for [`GossipOverlay::spawn`].
///
/// Defaults are deliberately conservative — they match the breakdown
/// comment on issue #137 and the per-module defaults already shipped
/// in the previous stack PRs.
#[derive(Debug, Clone)]
pub struct GossipOverlayConfig {
    /// Peer-list publisher knobs (interval, fanout, max entries).
    pub peer_list: PeerListGossipConfig,
    /// Partial-mesh maintenance loop knobs (interval, target degree).
    pub maintenance: MeshMaintenanceConfig,
    /// Maximum live entries in the dedup ring. Should comfortably
    /// exceed the number of distinct broadcasts in flight within a
    /// `dedup_ttl` window.
    pub dedup_capacity: usize,
    /// How long an inserted msg_id is treated as "seen" before
    /// being lazily forgotten.
    pub dedup_ttl: Duration,
    /// Maximum entries the peer table holds. Excess merges evict the
    /// oldest-`last_seen` entry first.
    pub peer_table_capacity: usize,
    /// Bound on the `OverlayCmd` channel between the broadcaster and
    /// the orchestrator.
    pub cmd_channel_depth: usize,
    /// Bound on the upstream `ProtocolEvent` channel handed to the
    /// consensus loop.
    pub event_channel_depth: usize,
    /// Seed for deterministic RNG behaviour in sim tests. The
    /// orchestrator, peer-list publisher, and maintenance loop each
    /// derive their own sub-seed from this single value so a single
    /// config-level seed reproduces all RNG-driven behaviour.
    pub rng_seed: u64,
}

impl Default for GossipOverlayConfig {
    fn default() -> Self {
        Self {
            peer_list: PeerListGossipConfig::default(),
            maintenance: MeshMaintenanceConfig::default(),
            dedup_capacity: 4096,
            dedup_ttl: Duration::from_secs(120),
            peer_table_capacity: 1024,
            cmd_channel_depth: 256,
            event_channel_depth: 256,
            rng_seed: 0,
        }
    }
}

impl GossipOverlayConfig {
    /// Build a [`GossipOverlayConfig`] from the operator-facing
    /// [`crate::config::OverlayConfig`]. The two structs have separate
    /// vocabularies — config-side knobs are flat `_ms` durations for
    /// TOML readability; the runtime-side struct uses real
    /// `Duration`s and bundles per-task knobs into their owners
    /// (`PeerListGossipConfig`, `MeshMaintenanceConfig`).
    ///
    /// `rng_seed` is taken as a parameter so the binary can derive it
    /// from a per-node source (e.g. the node id) rather than baking
    /// it into `[overlay]`. Sim tests pass an explicit seed.
    pub fn from_config(cfg: &crate::config::OverlayConfig, rng_seed: u64) -> Self {
        Self {
            peer_list: PeerListGossipConfig {
                interval: Duration::from_millis(cfg.peer_gossip_interval_ms),
                fanout: cfg.peer_gossip_fanout,
                max_entries: None,
            },
            maintenance: MeshMaintenanceConfig {
                interval: Duration::from_millis(cfg.mesh_check_interval_ms),
                target_degree: cfg.target_degree,
            },
            dedup_capacity: cfg.dedup_capacity,
            dedup_ttl: Duration::from_millis(cfg.dedup_ttl_ms),
            peer_table_capacity: cfg.peer_table_capacity,
            cmd_channel_depth: 256,
            event_channel_depth: 256,
            rng_seed,
        }
    }
}

/// Inputs for [`GossipOverlay::spawn`].
pub struct SpawnArgs {
    /// Local NodeId. Used as `originator` on outbound `Forward`
    /// frames and as the self-filter on the peer table.
    pub self_id: NodeId,
    /// Local listening address. When `Some`, the publisher injects a
    /// `(self_id, listen_addr, now)` self-entry into every published
    /// peer-list frame so peers can learn our listening port even
    /// when they only ever saw us via an inbound connection (whose
    /// source port is ephemeral). `None` only in unit tests that
    /// don't exercise peer-list propagation.
    pub self_listen_addr: Option<std::net::SocketAddr>,
    /// Inbound `ProtocolEvent` stream from
    /// [`crate::p2p::PeerCommand::RegisterProtocol`].
    pub event_rx: mpsc::Receiver<ProtocolEvent>,
    /// Outbound unicast sink. In production an
    /// [`super::sink::OverlaySink`] wrapping the per-protocol
    /// `mpsc::Sender<ProtocolOutbound>` returned by
    /// [`crate::p2p::PeerCommand::RegisterProtocol`]; in tests a
    /// recording mock.
    pub sink: Arc<dyn OverlayUnicast>,
    /// Dialer used by the partial-mesh maintenance loop to fill the
    /// direct-peer deficit.
    pub dialer: Arc<dyn Dialer>,
    /// Clock for the publisher / maintenance interval timers.
    pub clock: Arc<dyn Clock>,
    /// Knobs.
    pub config: GossipOverlayConfig,
}

/// Handles returned by [`GossipOverlay::spawn`].
pub struct GossipOverlayHandles {
    /// Consensus-facing broadcaster. Wraps the orchestrator's
    /// `OverlayCmd` channel.
    pub broadcaster: GossipBroadcaster,
    /// Consensus-facing discovery handle. Snapshots direct peers and
    /// publishes membership deltas.
    pub discovery: Arc<GossipDiscovery>,
    /// Upstream `ProtocolEvent` receiver. Hand to the consensus loop's
    /// event consumer in place of the raw manager-side receiver.
    pub event_rx: mpsc::Receiver<ProtocolEvent>,
    /// Read-only handle on the shared peer table. Cheap to clone.
    /// Useful for status pages and tests.
    pub peer_table: PeerTable,
    /// Orchestrator task join.
    pub overlay_join: JoinHandle<()>,
    /// Peer-list publisher task join.
    pub publisher_join: JoinHandle<()>,
    /// Mesh-maintenance task join.
    pub maintenance_join: JoinHandle<()>,
    /// Orchestrator shutdown signal. Sending fans out to the
    /// publisher and maintenance tasks too — callers don't need to
    /// signal those separately.
    pub shutdown: oneshot::Sender<()>,
}

/// The gossip overlay's central task. Construct via [`Self::spawn`].
pub struct GossipOverlay {
    self_id: NodeId,
    peer_table: PeerTable,
    direct: Arc<LockedVec>,
    dedup: MsgIdRing,
    cmd_rx: mpsc::Receiver<OverlayCmd>,
    event_rx: mpsc::Receiver<ProtocolEvent>,
    upstream_event_tx: mpsc::Sender<ProtocolEvent>,
    sink: Arc<dyn OverlayUnicast>,
    discovery_tx: broadcast::Sender<DiscoveryEvent>,
    rng: ChaCha20Rng,
    shutdown: oneshot::Receiver<()>,
    publisher_shutdown: Option<oneshot::Sender<()>>,
    maintenance_shutdown: Option<oneshot::Sender<()>>,
}

impl GossipOverlay {
    /// Wire the gossip overlay's pieces together and spawn the
    /// orchestrator + helper tasks. See [`SpawnArgs`] /
    /// [`GossipOverlayHandles`] for the input/output shape.
    pub fn spawn(args: SpawnArgs) -> GossipOverlayHandles {
        let SpawnArgs {
            self_id,
            self_listen_addr,
            event_rx,
            sink,
            dialer,
            clock,
            config,
        } = args;

        let (cmd_tx, cmd_rx) = mpsc::channel::<OverlayCmd>(config.cmd_channel_depth);
        let (upstream_event_tx, upstream_event_rx) =
            mpsc::channel::<ProtocolEvent>(config.event_channel_depth);

        let direct = Arc::new(LockedVec::new());
        let peer_table = PeerTable::new(self_id, config.peer_table_capacity);
        let dedup = MsgIdRing::new(config.dedup_capacity, config.dedup_ttl);

        let broadcaster = GossipBroadcaster::new(cmd_tx);
        // Discovery shares the same `Dialer` the maintenance loop
        // uses so a `Discovery::add_bootstrap` call hits the same
        // `reconnect_loop` machinery the binary already trusts.
        let (discovery, discovery_tx) = GossipDiscovery::new(direct.clone(), dialer.clone());
        let discovery = Arc::new(discovery);

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let (publisher_sd_tx, publisher_sd_rx) = oneshot::channel::<()>();
        let (maintenance_sd_tx, maintenance_sd_rx) = oneshot::channel::<()>();

        // Sub-task seeds are deterministic offsets from the orchestrator's
        // `rng_seed` so a single config-level seed reproduces every
        // RNG-driven decision in the overlay.
        let publisher_seed = config.rng_seed.wrapping_add(1);
        let maintenance_seed = config.rng_seed.wrapping_add(2);

        let direct_dyn: Arc<dyn DirectPeers> = direct.clone();

        let self_advertise = self_listen_addr.map(|addr| SelfAdvertise {
            node_id: self_id,
            addr,
        });
        let publisher_join = tokio::spawn(run_peer_list_publisher(
            config.peer_list.clone(),
            peer_table.clone(),
            direct_dyn.clone(),
            sink.clone(),
            clock.clone(),
            publisher_seed,
            self_advertise,
            publisher_sd_rx,
        ));

        let maintenance_join = tokio::spawn(run_mesh_maintenance(
            config.maintenance.clone(),
            peer_table.clone(),
            direct_dyn,
            dialer,
            clock,
            maintenance_seed,
            maintenance_sd_rx,
        ));

        let peer_table_for_handles = peer_table.clone();

        let overlay = GossipOverlay {
            self_id,
            peer_table,
            direct,
            dedup,
            cmd_rx,
            event_rx,
            upstream_event_tx,
            sink,
            discovery_tx,
            rng: ChaCha20Rng::seed_from_u64(config.rng_seed),
            shutdown: shutdown_rx,
            publisher_shutdown: Some(publisher_sd_tx),
            maintenance_shutdown: Some(maintenance_sd_tx),
        };

        let overlay_join = tokio::spawn(overlay.run());

        GossipOverlayHandles {
            broadcaster,
            discovery,
            event_rx: upstream_event_rx,
            peer_table: peer_table_for_handles,
            overlay_join,
            publisher_join,
            maintenance_join,
            shutdown: shutdown_tx,
        }
    }

    async fn run(mut self) {
        loop {
            tokio::select! {
                biased;
                _ = &mut self.shutdown => break,
                Some(cmd) = self.cmd_rx.recv() => self.handle_cmd(cmd),
                Some(event) = self.event_rx.recv() => self.handle_event(event).await,
                else => break,
            }
        }

        // Fan-out shutdown to the helper tasks.
        if let Some(tx) = self.publisher_shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = self.maintenance_shutdown.take() {
            let _ = tx.send(());
        }
    }

    fn handle_cmd(&mut self, cmd: OverlayCmd) {
        match cmd {
            OverlayCmd::Broadcast(payload) => self.do_broadcast(payload),
            OverlayCmd::SendTo { target, payload } => self.do_send_to(target, payload),
        }
    }

    fn do_broadcast(&mut self, payload: Bytes) {
        let msg_id = self.fresh_msg_id();
        // Insert our own broadcast into the dedup ring so a peer
        // looping the frame back to us is silently dropped.
        let _ = self.dedup.insert(msg_id, Instant::now());
        let bytes = encode_forward(msg_id, self.self_id, payload);
        let targets = DirectPeers::snapshot(&*self.direct);
        let fanout = targets.len();
        for target in targets {
            self.sink.send_to(target, bytes.clone());
        }
        // Issue #178 follow-up: per-call counter so an operator can
        // compare `n2`'s emit rate (consensus side) against the actual
        // broadcast fanout. A low `fanout` here vs. a high
        // consensus-side emit count exposes a TLS-handshake or
        // peer-table issue that's invisible from consensus alone.
        // `cmd_channel_pending` lets us spot back-pressure on the
        // OverlayCmd queue (a saturated cmd channel makes
        // `Broadcaster::send_to` block, which the consensus event loop
        // experiences as a stall).
        debug!(
            target: "ambros_p2p::p2p::overlay::gossip",
            msg_id = ?msg_id,
            fanout,
            cmd_channel_pending = self.cmd_rx.len(),
            event_channel_pending = self.event_rx.len(),
            "gossip_broadcast_dispatched",
        );
    }

    fn do_send_to(&mut self, target: NodeId, payload: Bytes) {
        let direct = DirectPeers::snapshot(&*self.direct);
        if direct.contains(&target) {
            let msg_id = self.fresh_msg_id();
            let _ = self.dedup.insert(msg_id, Instant::now());
            let bytes = encode_forward(msg_id, self.self_id, payload);
            self.sink.send_to(target, bytes);
            // Issue #178 follow-up: pair with the consensus-side
            // `block_sync_request_emitted` event to confirm the unicast
            // actually reached the orchestrator's outbound sink. A
            // missing `gossip_send_to_direct_dispatched` for a given
            // emission means the OverlayCmd never landed on this side
            // of the cmd channel — back-pressure or shutdown is
            // swallowing it.
            debug!(
                target: "ambros_p2p::p2p::overlay::gossip",
                target_peer = %crate::p2p::tls::node_id_to_base58(&target),
                msg_id = ?msg_id,
                cmd_channel_pending = self.cmd_rx.len(),
                event_channel_pending = self.event_rx.len(),
                "gossip_send_to_direct_dispatched",
            );
        } else {
            // Per the breakdown comment on issue #137: the gossip
            // overlay does not route point-to-point, so a unicast to
            // a non-direct peer is a best-effort broadcast that may
            // reach the target through forwarding.
            //
            // Issue #178 surfaced this fallback at INFO level: a
            // `BlockRequest` aimed at the original proposer of an
            // unknown-parent proposal lands here whenever the proposer
            // isn't in our direct-peer set, which is the common case
            // under sparse-mesh + restart. Operators correlate this
            // with the matching `block_sync_request_emitted` line on
            // the consensus side to confirm the request actually went
            // out via a broadcast hop.
            info!(
                target: "ambros_p2p::p2p::overlay::gossip",
                target_peer = %crate::p2p::tls::node_id_to_base58(&target),
                direct_peer_count = direct.len(),
                "send_to_broadcast_fallback",
            );
            self.do_broadcast(payload);
        }
    }

    async fn handle_event(&mut self, event: ProtocolEvent) {
        match event {
            ProtocolEvent::Message { from, payload } => {
                self.handle_inbound_message(from, payload).await;
            }
            ProtocolEvent::PeerConnected { node_id, addr: _ } => {
                // Note: `addr` from `PeerConnected` is unreliable for
                // populating the peer table. On inbound connections
                // it's the peer's ephemeral source port, not their
                // listening port — advertising it via peer-list
                // gossip would teach downstream nodes a non-dialable
                // address. Instead, every peer self-advertises its
                // listening address through the peer-list publisher
                // (see `SelfAdvertise` plumbed into
                // `run_peer_list_publisher`); the receiver path
                // populates the table from those self-advertised
                // entries.
                self.add_direct_peer(node_id);
                let _ = self.discovery_tx.send(DiscoveryEvent::PeerAdded(node_id));
            }
            ProtocolEvent::PeerDisconnected { node_id } => {
                self.remove_direct_peer(node_id);
                let _ = self.discovery_tx.send(DiscoveryEvent::PeerRemoved(node_id));
            }
        }
    }

    async fn handle_inbound_message(&mut self, from: NodeId, payload: Bytes) {
        match apply_overlay_frame(&self.peer_table, &payload) {
            Ok(_changed) => {
                // PeerList: already merged into the peer table.
                // Nothing further to surface upstream.
            }
            Err(FrameOutcome::Malformed) => {
                // Already logged at warn by apply_overlay_frame.
            }
            Err(FrameOutcome::Forward {
                msg_id,
                originator,
                payload,
            }) => match self.dedup.insert(msg_id, Instant::now()) {
                InsertOutcome::AlreadySeen => {
                    // Loop break — drop without surfacing or re-fanning.
                    //
                    // Issue #178 follow-up: an emitter logs every
                    // outbound dispatch; comparing emitter counts
                    // against `gossip_inbound_dispatched` on direct
                    // neighbours pinpoints whether dropped requests
                    // are being silently absorbed by dedup (this arm)
                    // versus lost on the wire. `originator` lets the
                    // analyzer correlate to the original sender.
                    debug!(
                        target: "ambros_p2p::p2p::overlay::gossip",
                        from = %crate::p2p::tls::node_id_to_base58(&from),
                        originator = %crate::p2p::tls::node_id_to_base58(&originator),
                        msg_id = ?msg_id,
                        "gossip_dedup_dropped",
                    );
                }
                InsertOutcome::New => {
                    // Surface to consensus with `from = originator` so
                    // the consumer sees the broadcast originator
                    // regardless of how many hops the frame took.
                    //
                    // Issue #178 follow-up: this is the receive-side
                    // counterpart to `gossip_send_to_direct_dispatched` /
                    // `gossip_broadcast_dispatched`. A direct peer's
                    // emit count vs. our `gossip_inbound_dispatched`
                    // count exposes raw drop-on-the-wire (TLS reset,
                    // queue overflow on the read side, etc.) before
                    // any consensus-layer logic runs.
                    debug!(
                        target: "ambros_p2p::p2p::overlay::gossip",
                        from = %crate::p2p::tls::node_id_to_base58(&from),
                        originator = %crate::p2p::tls::node_id_to_base58(&originator),
                        msg_id = ?msg_id,
                        payload_bytes = payload.len(),
                        "gossip_inbound_dispatched",
                    );
                    let _ = self
                        .upstream_event_tx
                        .send(ProtocolEvent::Message {
                            from: originator,
                            payload: payload.clone(),
                        })
                        .await;

                    // Re-fanout to direct peers other than the relay
                    // sender.
                    let bytes = encode_forward(msg_id, originator, payload);
                    for target in DirectPeers::snapshot(&*self.direct) {
                        if target == from {
                            continue;
                        }
                        self.sink.send_to(target, bytes.clone());
                    }
                }
            },
        }
    }

    fn add_direct_peer(&self, node_id: NodeId) {
        let mut g = self.direct.0.write();
        if !g.contains(&node_id) {
            g.push(node_id);
        }
    }

    fn remove_direct_peer(&self, node_id: NodeId) {
        let mut g = self.direct.0.write();
        g.retain(|p| *p != node_id);
    }

    fn fresh_msg_id(&mut self) -> MsgId {
        let mut id = [0u8; 16];
        self.rng.fill_bytes(&mut id);
        id
    }
}

fn encode_forward(msg_id: MsgId, originator: NodeId, payload: Bytes) -> Bytes {
    let frame = OverlayFrame::Forward {
        msg_id,
        originator,
        payload,
    };
    Bytes::from(postcard::to_stdvec(&frame).expect("postcard encode of Forward cannot fail"))
}

/// Production [`Dialer`] impl that delegates to
/// [`DialerCtx::spawn`].
///
/// `DialerCtx` already encapsulates the TLS identity, the manager
/// channel, the peer-gone broadcast, and the clock — everything
/// `reconnect_loop` needs. This adapter just bridges the trait shape.
///
/// Cheap to clone (the underlying `DialerCtx` clones via `Arc`s and
/// `Sender`s).
#[derive(Clone)]
pub struct DialerCtxAdapter {
    ctx: DialerCtx,
}

impl DialerCtxAdapter {
    /// Wrap a constructed [`DialerCtx`].
    pub fn new(ctx: DialerCtx) -> Self {
        Self { ctx }
    }
}

impl Dialer for DialerCtxAdapter {
    fn dial(&self, addr: std::net::SocketAddr, expected: Option<NodeId>) {
        // `DialerCtx::spawn` returns a `JoinHandle`; we drop it
        // intentionally — the reconnect loop is fire-and-forget. The
        // task exits when the manager closes its `internal_tx` on
        // shutdown.
        std::mem::drop(self.ctx.spawn(addr, expected));
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use parking_lot::Mutex;

    use crate::clock::TokioClock;
    use crate::p2p::overlay::{Broadcaster, Discovery};

    use super::super::wire::PeerEntry;
    use super::*;

    fn nid(byte: u8) -> NodeId {
        let mut id = [0u8; 32];
        id[0] = byte;
        id
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[derive(Default)]
    struct RecordingSink {
        sent: Mutex<Vec<(NodeId, Bytes)>>,
    }

    impl RecordingSink {
        fn snapshot(&self) -> Vec<(NodeId, Bytes)> {
            self.sent.lock().clone()
        }

        fn clear(&self) {
            self.sent.lock().clear();
        }
    }

    impl OverlayUnicast for RecordingSink {
        fn send_to(&self, target: NodeId, payload: Bytes) {
            self.sent.lock().push((target, payload));
        }
    }

    struct NullDialer;

    impl Dialer for NullDialer {
        fn dial(&self, _: SocketAddr, _: Option<NodeId>) {}
    }

    struct Setup {
        event_tx: mpsc::Sender<ProtocolEvent>,
        sink: Arc<RecordingSink>,
        handles: GossipOverlayHandles,
    }

    fn setup(self_id: NodeId) -> Setup {
        let (event_tx, event_rx) = mpsc::channel::<ProtocolEvent>(32);
        let sink = Arc::new(RecordingSink::default());
        let dialer: Arc<dyn Dialer> = Arc::new(NullDialer);
        let clock: Arc<dyn Clock> = Arc::new(TokioClock::new());
        let handles = GossipOverlay::spawn(SpawnArgs {
            self_id,
            self_listen_addr: None,
            event_rx,
            sink: sink.clone() as Arc<dyn OverlayUnicast>,
            dialer,
            clock,
            config: GossipOverlayConfig::default(),
        });
        Setup {
            event_tx,
            sink,
            handles,
        }
    }

    /// Send an inbound Message and wait for the orchestrator to surface
    /// the matching upstream Message. Times out after 1 s.
    async fn await_upstream_message(rx: &mut mpsc::Receiver<ProtocolEvent>) -> ProtocolEvent {
        tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("upstream Message timed out")
            .expect("upstream channel closed")
    }

    fn make_forward_bytes(msg_id: MsgId, originator: NodeId, payload: &'static [u8]) -> Bytes {
        let frame = OverlayFrame::Forward {
            msg_id,
            originator,
            payload: Bytes::from_static(payload),
        };
        Bytes::from(postcard::to_stdvec(&frame).expect("encode"))
    }

    fn make_peer_list_bytes(entries: Vec<PeerEntry>) -> Bytes {
        let frame = OverlayFrame::PeerList(entries);
        Bytes::from(postcard::to_stdvec(&frame).expect("encode"))
    }

    /// Yield enough times that any pending tasks on the single-threaded
    /// runtime have run. Used after sending events that don't produce
    /// upstream traffic so the test can assert "nothing happened".
    async fn drain_runtime() {
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
    }

    // (a) dedup rejects a second copy of the same msg_id.
    #[tokio::test]
    async fn dedup_drops_duplicate_forward() {
        let mut s = setup(nid(1));

        // Connect a relay so events flow.
        s.event_tx
            .send(ProtocolEvent::PeerConnected {
                node_id: nid(2),
                addr: addr(7002),
            })
            .await
            .unwrap();

        let dup_id: MsgId = [7; 16];
        s.event_tx
            .send(ProtocolEvent::Message {
                from: nid(2),
                payload: make_forward_bytes(dup_id, nid(99), b"first"),
            })
            .await
            .unwrap();
        match await_upstream_message(&mut s.handles.event_rx).await {
            ProtocolEvent::Message { from, payload } => {
                assert_eq!(from, nid(99));
                assert_eq!(&payload[..], b"first");
            }
            other => panic!("expected Message, got {other:?}"),
        }

        // Same msg_id, different payload — should be deduped.
        s.event_tx
            .send(ProtocolEvent::Message {
                from: nid(2),
                payload: make_forward_bytes(dup_id, nid(99), b"second"),
            })
            .await
            .unwrap();

        // Distinct msg_id — should pass through. If it arrives before
        // any "second" payload, dedup is working.
        let fresh_id: MsgId = [8; 16];
        s.event_tx
            .send(ProtocolEvent::Message {
                from: nid(2),
                payload: make_forward_bytes(fresh_id, nid(99), b"third"),
            })
            .await
            .unwrap();
        match await_upstream_message(&mut s.handles.event_rx).await {
            ProtocolEvent::Message { payload, .. } => {
                assert_eq!(
                    &payload[..],
                    b"third",
                    "deduped duplicate must not be surfaced"
                );
            }
            other => panic!("expected Message, got {other:?}"),
        }

        // Nothing else should be queued upstream.
        assert!(s.handles.event_rx.try_recv().is_err());
    }

    // (b) Forward re-fanout excludes the relay sender.
    // (c) originator survives the round-trip.
    #[tokio::test]
    async fn refanout_excludes_relay_and_preserves_originator() {
        let mut s = setup(nid(1));

        for i in 2..=4u8 {
            s.event_tx
                .send(ProtocolEvent::PeerConnected {
                    node_id: nid(i),
                    addr: addr(7000 + i as u16),
                })
                .await
                .unwrap();
        }
        // Drain any prior sink traffic from connection setup (there
        // shouldn't be any, but be safe).
        drain_runtime().await;
        s.sink.clear();

        let msg_id: MsgId = [42; 16];
        s.event_tx
            .send(ProtocolEvent::Message {
                from: nid(2),
                payload: make_forward_bytes(msg_id, nid(99), b"x"),
            })
            .await
            .unwrap();
        match await_upstream_message(&mut s.handles.event_rx).await {
            ProtocolEvent::Message { from, payload } => {
                assert_eq!(from, nid(99));
                assert_eq!(&payload[..], b"x");
            }
            other => panic!("expected Message, got {other:?}"),
        }
        // Give the orchestrator a chance to do the re-fanout writes
        // after surfacing upstream.
        drain_runtime().await;

        let sent = s.sink.snapshot();
        let mut targets: Vec<NodeId> = sent.iter().map(|(t, _)| *t).collect();
        targets.sort();
        assert_eq!(
            targets,
            vec![nid(3), nid(4)],
            "re-fanout should hit direct peers other than the relay"
        );

        // Every re-fanouted frame preserves originator = nid(99) and
        // re-uses the same msg_id.
        for (_, payload) in &sent {
            match postcard::from_bytes::<OverlayFrame>(payload).unwrap() {
                OverlayFrame::Forward {
                    msg_id: m,
                    originator,
                    ..
                } => {
                    assert_eq!(m, msg_id);
                    assert_eq!(originator, nid(99));
                }
                other => panic!("expected Forward, got {other:?}"),
            }
        }
    }

    // (d) PeerList frames update the peer table.
    #[tokio::test]
    async fn peer_list_frames_update_peer_table() {
        let mut s = setup(nid(1));

        // Connect a relay so events flow.
        s.event_tx
            .send(ProtocolEvent::PeerConnected {
                node_id: nid(2),
                addr: addr(7002),
            })
            .await
            .unwrap();

        let entries = vec![
            PeerEntry {
                node_id: nid(5),
                addr: addr(7005),
                last_seen_unix_ms: 100,
            },
            PeerEntry {
                node_id: nid(6),
                addr: addr(7006),
                last_seen_unix_ms: 200,
            },
        ];
        s.event_tx
            .send(ProtocolEvent::Message {
                from: nid(2),
                payload: make_peer_list_bytes(entries),
            })
            .await
            .unwrap();

        // Wait for the orchestrator to process. The peer table is
        // shared with the handles so we can poll on it.
        for _ in 0..32 {
            tokio::task::yield_now().await;
            if s.handles.peer_table.contains(&nid(5)) && s.handles.peer_table.contains(&nid(6)) {
                break;
            }
        }
        assert!(s.handles.peer_table.contains(&nid(5)));
        assert!(s.handles.peer_table.contains(&nid(6)));

        // PeerList frames are not surfaced upstream.
        assert!(s.handles.event_rx.try_recv().is_err());
    }

    // (e) connect/disconnect transitions publish DiscoveryEvents.
    #[tokio::test]
    async fn connect_and_disconnect_publish_discovery_events() {
        let mut s = setup(nid(1));
        let mut sub = s.handles.discovery.subscribe();

        s.event_tx
            .send(ProtocolEvent::PeerConnected {
                node_id: nid(2),
                addr: addr(7002),
            })
            .await
            .unwrap();
        let ev = tokio::time::timeout(Duration::from_secs(1), sub.recv())
            .await
            .expect("PeerAdded timed out")
            .expect("subscription closed");
        assert_eq!(ev, DiscoveryEvent::PeerAdded(nid(2)));
        // Also reflected in the direct snapshot via discovery.
        assert_eq!(s.handles.discovery.known_peers(), vec![nid(2)]);

        s.event_tx
            .send(ProtocolEvent::PeerDisconnected { node_id: nid(2) })
            .await
            .unwrap();
        let ev = tokio::time::timeout(Duration::from_secs(1), sub.recv())
            .await
            .expect("PeerRemoved timed out")
            .expect("subscription closed");
        assert_eq!(ev, DiscoveryEvent::PeerRemoved(nid(2)));
        assert!(s.handles.discovery.known_peers().is_empty());

        // Connect/disconnect transitions are not forwarded upstream —
        // the discovery channel is the canonical signal.
        assert!(s.handles.event_rx.try_recv().is_err());
    }

    // (f) shutdown returns promptly.
    #[tokio::test]
    async fn shutdown_drains_all_tasks() {
        let s = setup(nid(1));
        let _ = s.handles.shutdown.send(());

        let GossipOverlayHandles {
            overlay_join,
            publisher_join,
            maintenance_join,
            ..
        } = s.handles;

        tokio::time::timeout(Duration::from_secs(2), async move {
            let _ = overlay_join.await;
            let _ = publisher_join.await;
            let _ = maintenance_join.await;
        })
        .await
        .expect("shutdown timed out");
    }

    // The local broadcaster's outbound msg_id is recorded in the
    // dedup ring, so a forwarded copy looped back through a relay is
    // silently dropped. This complements (a) which only exercises the
    // inbound dedup path.
    #[tokio::test]
    async fn self_originated_broadcast_is_self_deduped_on_loopback() {
        // Use a deterministic seed so we can reconstruct what msg_id
        // the broadcaster generated for a `broadcast` call.
        let (event_tx, event_rx) = mpsc::channel::<ProtocolEvent>(32);
        let sink = Arc::new(RecordingSink::default());
        let dialer: Arc<dyn Dialer> = Arc::new(NullDialer);
        let clock: Arc<dyn Clock> = Arc::new(TokioClock::new());
        let cfg = GossipOverlayConfig {
            rng_seed: 0x_de_ad_be_ef,
            ..Default::default()
        };
        let mut handles = GossipOverlay::spawn(SpawnArgs {
            self_id: nid(1),
            self_listen_addr: None,
            event_rx,
            sink: sink.clone() as Arc<dyn OverlayUnicast>,
            dialer,
            clock,
            config: cfg.clone(),
        });

        // Connect one peer and let the orchestrator pick up the
        // connect event before issuing the broadcast — the cmd and
        // event channels race otherwise (the `biased;` select! arm
        // prefers cmds, so a Broadcast queued before PeerConnected is
        // processed could fan out to zero peers).
        event_tx
            .send(ProtocolEvent::PeerConnected {
                node_id: nid(2),
                addr: addr(7002),
            })
            .await
            .unwrap();
        drain_runtime().await;
        handles
            .broadcaster
            .broadcast(Bytes::from_static(b"local"))
            .await;
        drain_runtime().await;

        // The sink received a Forward addressed to nid(2). Pull the
        // msg_id out so we can construct a loopback Message.
        let sent = sink.snapshot();
        assert_eq!(sent.len(), 1, "broadcast fanned out to one direct peer");
        let (_target, bytes) = sent.into_iter().next().unwrap();
        let (looped_msg_id, looped_originator) =
            match postcard::from_bytes::<OverlayFrame>(&bytes).unwrap() {
                OverlayFrame::Forward {
                    msg_id, originator, ..
                } => (msg_id, originator),
                other => panic!("expected Forward, got {other:?}"),
            };
        assert_eq!(looped_originator, nid(1));

        // Now feign that the same Forward bounced back from the relay.
        event_tx
            .send(ProtocolEvent::Message {
                from: nid(2),
                payload: make_forward_bytes(looped_msg_id, nid(1), b"local"),
            })
            .await
            .unwrap();
        drain_runtime().await;

        // Should not have surfaced upstream — we already saw it at
        // broadcast time and the dedup ring caught the loopback.
        assert!(handles.event_rx.try_recv().is_err());
    }
}
