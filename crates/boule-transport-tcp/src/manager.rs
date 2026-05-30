use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::{BufMut, Bytes, BytesMut};
use parking_lot::RwLock;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{broadcast, mpsc};
use tracing::{info, warn};

/// Capacity of each registered protocol's outbound `ProtocolOutbound`
/// channel (the per-protocol `send_tx`).
///
/// This channel is drained by a forwarding task that hands each message
/// to the single manager event loop via `internal_tx.send().await`. When
/// that loop is momentarily busy (an inbound burst, a connect/disconnect,
/// TLS work) the forwarder blocks and this channel backs up. The gossip
/// overlay enqueues here with `try_send` (drop-on-full), so a transient
/// loop stall under high commit throughput shows up as bounded bursts on
/// `gossip_sink_overflow_total` even though every per-peer write channel
/// is keeping up.
///
/// Sized against the measured worst-case transient backlog, not guessed.
/// Instrumenting the channel's high-water mark on a 7-node mesh running
/// flat-out at ~75 commits/s (≈5× the rate at which the overflow first
/// surfaced) showed the backlog peaking at ~410 deep before the drain
/// caught up — so 2048 leaves ~5× headroom over the worst case observed,
/// and overflow stays at zero. The peak grows with commit rate and with
/// fan-out (validator-set size); at large production sets this buffer is
/// not the right lever — decoupling the outbound drain from the inbound
/// event loop is — but for the meshes exercised today it holds with
/// margin. Drops here are recoverable (overlay re-fans-out, block-sync
/// re-fetches); keeping the steady-state count at zero is what makes the
/// metric a trustworthy signal for a *real* wedged peer, not benign noise.
pub const PROTOCOL_OUTBOUND_CAPACITY: usize = 2048;

/// Per-peer outbound `write_tx.try_send` `Full` count that trips a
/// slow-peer disconnect when accumulated within
/// [`SLOW_PEER_OVERFLOW_WINDOW`] (#490).
///
/// Default 64 — equal to the per-peer write_tx capacity; one full
/// channel-worth of consecutive drops over the window means the peer's
/// socket / connection task is almost certainly wedged. Hard-coded for
/// now; configurable knob can land later if production runs need it.
pub const SLOW_PEER_OVERFLOW_THRESHOLD: usize = 64;

/// Sliding window for [`SLOW_PEER_OVERFLOW_THRESHOLD`]. Drops older
/// than this age out of the count, so a peer that briefly stalled and
/// recovered isn't penalised forever.
pub const SLOW_PEER_OVERFLOW_WINDOW: Duration = Duration::from_secs(10);

/// Per-peer sliding-window record of `write_tx` overflow timestamps,
/// used by the slow-peer disconnect heuristic (#490).
struct SlowPeerTracker {
    overflows: VecDeque<Instant>,
    /// Set true after a disconnect has been triggered for this peer so
    /// the heuristic doesn't keep re-firing while the manager processes
    /// the disconnect cleanup; reset when the peer re-registers.
    disconnect_dispatched: bool,
}

impl SlowPeerTracker {
    fn new() -> Self {
        Self {
            overflows: VecDeque::new(),
            disconnect_dispatched: false,
        }
    }

    /// Record one overflow; return `true` iff this push pushed the
    /// in-window count past [`SLOW_PEER_OVERFLOW_THRESHOLD`] for the
    /// first time (so the caller fires exactly one disconnect per
    /// streak).
    fn record_overflow(&mut self, now: Instant) -> bool {
        let cutoff = now - SLOW_PEER_OVERFLOW_WINDOW;
        while self.overflows.front().is_some_and(|t| *t < cutoff) {
            self.overflows.pop_front();
        }
        if self.overflows.is_empty() {
            self.disconnect_dispatched = false;
        }
        self.overflows.push_back(now);
        if self.overflows.len() >= SLOW_PEER_OVERFLOW_THRESHOLD && !self.disconnect_dispatched {
            self.disconnect_dispatched = true;
            true
        } else {
            false
        }
    }
}

use super::connection;
use super::connection::ProtocolCaps;
use super::overlay::DiscoveryEvent;
use super::tls::{NodeId, node_id_to_base58};
use super::{PeerCommand, ProtocolEvent, ProtocolHandle, ProtocolOutbound};
use boule_core::transport::limits::{ConnectionLimiter, Direction};

/// Monotonic per-connection identity assigned by the manager. Used to
/// distinguish connections to the same peer so a tie-breaker replacement
/// does not look like a disconnect to the rest of the system (issue #114).
pub type ConnectionId = u64;

/// What the manager stores for each currently-connected peer: the id of the
/// specific connection that owns the peer slot plus the channel that writes
/// bytes onto it. `direction` and `addr` are kept on the slot so the
/// manager can release the matching [`ConnectionLimiter`] bucket on
/// [`ManagerMsg::PeerGone`] without re-asking the (closed) connection
/// task what direction it was.
struct PeerSlot {
    conn_id: ConnectionId,
    write_tx: mpsc::Sender<Bytes>,
    direction: Direction,
    addr: SocketAddr,
}

/// Combined async I/O trait used as a protocol-agnostic stream type.
/// Rust's trait-object rules only allow one non-auto trait per `dyn`, so we
/// need this supertrait to combine AsyncRead and AsyncWrite into one.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncReadWrite for T {}

pub type AnyStream = Box<dyn AsyncReadWrite>;

/// Internal messages that flow into the manager (from listener + connection tasks).
pub enum ManagerMsg {
    NewConnection {
        node_id: NodeId,
        addr: SocketAddr,
        /// Whether this connection arrived via the inbound listener or
        /// the outbound dialer. Charged against the matching
        /// [`ConnectionLimiter`] bucket.
        direction: Direction,
        stream: AnyStream,
    },
    /// Emitted by a connection task when its read/write loop exits. The
    /// `connection_id` disambiguates between the current connection for
    /// `node_id` and any prior connections that the tie-breaker has since
    /// replaced — the manager only treats this as a true disconnect if it
    /// matches the currently-registered connection (see #114).
    PeerGone {
        node_id: NodeId,
        connection_id: ConnectionId,
    },
    InboundMessage {
        node_id: NodeId,
        msg: Bytes,
    },
    ProtocolSend {
        protocol_id: u8,
        outbound: ProtocolOutbound,
    },
}

pub async fn run(
    our_node_id: NodeId,
    mut cmd_rx: mpsc::Receiver<PeerCommand>,
    mut internal_rx: mpsc::Receiver<ManagerMsg>,
    internal_tx: mpsc::Sender<ManagerMsg>,
    peer_gone_tx: broadcast::Sender<NodeId>,
    discovery_tx: broadcast::Sender<DiscoveryEvent>,
    connection_limiter: Option<Arc<ConnectionLimiter>>,
) {
    // `BTreeMap` so broadcast and event-fan-out iteration is deterministic;
    // the sim's byte-identical-trace determinism test relies on this, and
    // consistent broadcast ordering is also helpful for reproducing
    // production bugs.
    let mut peers: BTreeMap<NodeId, PeerSlot> = BTreeMap::new();
    let mut protocols: BTreeMap<u8, mpsc::Sender<ProtocolEvent>> = BTreeMap::new();
    // Shared with every spawned connection task; updated in place when a
    // protocol registers a tighter-than-global cap.
    let protocol_caps: ProtocolCaps = Arc::new(RwLock::new(HashMap::new()));
    // Monotonically increasing id for every connection the manager accepts.
    // Used to distinguish current vs. replaced connections when a PeerGone
    // arrives (see #114 / the tie-breaker path in `register_connection`).
    let mut next_conn_id: ConnectionId = 0;
    // Cumulative count of per-peer outbound `write_tx.try_send` failures
    // due to a full channel — both `SendTo` and `Broadcast` paths feed
    // it. Cloned into every [`ProtocolHandle`] returned by
    // [`PeerCommand::RegisterProtocol`] so a consumer (consensus) can
    // surface the running drop count via
    // `boule_consensus::status::BackpressureStatus`. `Closed`
    // failures are intentionally not counted: they fire when a peer
    // disconnects mid-send and would mask real back-pressure events.
    // (#163 / #486 follow-up.)
    let peer_outbound_overflows = Arc::new(AtomicU64::new(0));
    // Per-peer sliding window of overflow timestamps (#490). When a
    // peer accumulates [`SLOW_PEER_OVERFLOW_THRESHOLD`] overflows
    // within [`SLOW_PEER_OVERFLOW_WINDOW`], the manager kicks the
    // peer with the same cleanup path `PeerCommand::Disconnect`
    // takes — the back-pressure policy calls this the
    // "must-deliver-or-disconnect" escape valve.
    let mut slow_peer_trackers: HashMap<NodeId, SlowPeerTracker> = HashMap::new();

    loop {
        tokio::select! {
            // Bias branches in declared order so the select arm pick is
            // deterministic across runs (same rationale as above).
            biased;
            msg = internal_rx.recv() => {
                match msg {
                    Some(ManagerMsg::NewConnection { node_id, addr, direction, stream }) => {
                        // Check the connection cap *before* allocating a
                        // conn_id so a rejected attempt does not perturb
                        // the monotonic id sequence (which other tests
                        // rely on for tie-breaker replays).
                        if let Some(limiter) = connection_limiter.as_ref() {
                            if let Err(reason) = limiter.try_admit(direction, addr.ip()) {
                                warn!(
                                    peer = %node_id_to_base58(&node_id),
                                    addr = %addr,
                                    direction = ?direction,
                                    reason = reason.label(),
                                    "connection refused: cap reached",
                                );
                                // Drop `stream`. The TCP/TLS connection
                                // closes when the underlying socket is
                                // dropped — peer sees this as RST/EOF on
                                // their next read or write.
                                drop(stream);
                                continue;
                            }
                        }
                        next_conn_id += 1;
                        let outcome = register_connection(
                            our_node_id,
                            node_id,
                            addr,
                            direction,
                            stream,
                            next_conn_id,
                            &mut peers,
                            &protocols,
                            internal_tx.clone(),
                            Arc::clone(&protocol_caps),
                            &discovery_tx,
                        );
                        if let Some(limiter) = connection_limiter.as_ref() {
                            match outcome {
                                RegisterOutcome::Admitted => {}
                                RegisterOutcome::Rejected => {
                                    limiter.release(direction, addr.ip());
                                }
                                RegisterOutcome::Replaced { prev_direction, prev_addr } => {
                                    limiter.release(prev_direction, prev_addr.ip());
                                }
                            }
                        }
                    }
                    Some(ManagerMsg::PeerGone { node_id, connection_id }) => {
                        // Only treat this as a disconnect if the registered
                        // connection is the one that just exited. Otherwise
                        // this PeerGone is for a connection the tie-breaker
                        // replaced: the peer is still reachable via the new
                        // connection and no event fires (see #114).
                        let is_current = peers
                            .get(&node_id)
                            .is_some_and(|slot| slot.conn_id == connection_id);
                        if is_current {
                            let slot = peers.remove(&node_id).expect("just verified present");
                            if let Some(limiter) = connection_limiter.as_ref() {
                                limiter.release(slot.direction, slot.addr.ip());
                            }
                            slow_peer_trackers.remove(&node_id);
                            let _ = peer_gone_tx.send(node_id);
                            let _ = discovery_tx.send(DiscoveryEvent::PeerRemoved(node_id));
                            for event_tx in protocols.values() {
                                let _ = event_tx.try_send(ProtocolEvent::PeerDisconnected { node_id });
                            }
                        }
                    }
                    Some(ManagerMsg::InboundMessage { node_id, msg }) => {
                        if msg.is_empty() {
                            continue;
                        }
                        let protocol_id = msg[0];
                        let payload = msg.slice(1..);
                        if let Some(event_tx) = protocols.get(&protocol_id) {
                            let _ = event_tx.send(ProtocolEvent::Message { from: node_id, payload }).await;
                        } else {
                            warn!(
                                "unknown protocol_id {protocol_id:#04x} from {}",
                                node_id_to_base58(&node_id)
                            );
                        }
                    }
                    Some(ManagerMsg::ProtocolSend { protocol_id, outbound }) => {
                        match outbound {
                            ProtocolOutbound::Broadcast(payload) => {
                                let tagged = tag(protocol_id, payload);
                                let trip = broadcast_msg(
                                    &peers,
                                    tagged,
                                    &peer_outbound_overflows,
                                    &mut slow_peer_trackers,
                                );
                                for slow_peer in trip {
                                    disconnect_peer_for_overflow(
                                        slow_peer,
                                        &mut peers,
                                        &protocols,
                                        &peer_gone_tx,
                                        &discovery_tx,
                                        connection_limiter.as_ref(),
                                        &mut slow_peer_trackers,
                                    );
                                }
                            }
                            ProtocolOutbound::SendTo { node_id, payload } => {
                                let tagged = tag(protocol_id, payload);
                                let id = node_id_to_base58(&node_id);
                                let mut trip_disconnect = false;
                                if let Some(slot) = peers.get(&node_id) {
                                    match slot.write_tx.try_send(tagged) {
                                        Ok(()) => {}
                                        Err(mpsc::error::TrySendError::Full(_)) => {
                                            // Per-peer write channel is at capacity. Bump
                                            // the back-pressure counter (#486) so the drop
                                            // is visible in `ConsensusStatus.backpressure`,
                                            // record the timestamp in the per-peer
                                            // sliding window (#490) and kick the peer
                                            // if it crosses the threshold.
                                            peer_outbound_overflows.fetch_add(1, Ordering::Relaxed);
                                            warn!("SendTo {id}: channel full");
                                            let tracker = slow_peer_trackers
                                                .entry(node_id)
                                                .or_insert_with(SlowPeerTracker::new);
                                            if tracker.record_overflow(Instant::now()) {
                                                trip_disconnect = true;
                                            }
                                        }
                                        Err(mpsc::error::TrySendError::Closed(_)) => {
                                            // Closed channels are shutdown noise — counting
                                            // them would mask real back-pressure events.
                                            warn!("SendTo {id}: channel closed");
                                        }
                                    }
                                } else {
                                    warn!("SendTo unknown peer {id}");
                                }
                                if trip_disconnect {
                                    disconnect_peer_for_overflow(
                                        node_id,
                                        &mut peers,
                                        &protocols,
                                        &peer_gone_tx,
                                        &discovery_tx,
                                        connection_limiter.as_ref(),
                                        &mut slow_peer_trackers,
                                    );
                                }
                            }
                        }
                    }
                    None => break,
                }
            }

            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(PeerCommand::RegisterProtocol { id, max_frame_bytes, reply }) => {
                        let (event_tx, event_rx) = mpsc::channel::<ProtocolEvent>(256);
                        let (send_tx, mut send_rx) =
                            mpsc::channel::<ProtocolOutbound>(PROTOCOL_OUTBOUND_CAPACITY);
                        let itx = internal_tx.clone();
                        tokio::spawn(async move {
                            while let Some(outbound) = send_rx.recv().await {
                                if itx
                                    .send(ManagerMsg::ProtocolSend { protocol_id: id, outbound })
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        });
                        protocols.insert(id, event_tx);
                        // `None` falls back to the global cap in connection::run;
                        // `Some(n)` installs a tighter per-protocol limit
                        // enforced on every connection, present and future.
                        match max_frame_bytes {
                            Some(cap) => {
                                protocol_caps.write().insert(id, cap);
                            }
                            None => {
                                protocol_caps.write().remove(&id);
                            }
                        }
                        let _ = reply.send(ProtocolHandle {
                            send_tx,
                            event_rx,
                            peer_outbound_overflows: Arc::clone(&peer_outbound_overflows),
                        });
                    }
                    Some(PeerCommand::Disconnect { node_id }) => {
                        let id = node_id_to_base58(&node_id);
                        if let Some(slot) = peers.remove(&node_id) {
                            if let Some(limiter) = connection_limiter.as_ref() {
                                limiter.release(slot.direction, slot.addr.ip());
                            }
                            slow_peer_trackers.remove(&node_id);
                            // Broadcast the disconnect immediately instead
                            // of waiting for the connection task's PeerGone
                            // to land — that stale PeerGone will now see a
                            // missing slot and no-op (see #114). Dropping
                            // the slot's `write_tx` still closes the write
                            // channel and lets the connection task exit.
                            let _ = peer_gone_tx.send(node_id);
                            let _ = discovery_tx.send(DiscoveryEvent::PeerRemoved(node_id));
                            for event_tx in protocols.values() {
                                let _ = event_tx.try_send(ProtocolEvent::PeerDisconnected { node_id });
                            }
                        } else {
                            warn!("Disconnect unknown peer {id}");
                        }
                    }
                    Some(PeerCommand::ListPeers { reply }) => {
                        let list: Vec<NodeId> = peers.keys().copied().collect();
                        // Ignore send error: the requester cancelled before receiving the reply.
                        let _ = reply.send(list);
                    }
                    Some(PeerCommand::HasPeer { node_id, reply }) => {
                        let _ = reply.send(peers.contains_key(&node_id));
                    }
                    None => break,
                }
            }
        }
    }
}

/// Outcome of a [`register_connection`] call. The manager loop uses
/// this to release the right [`ConnectionLimiter`] slot when the
/// tie-breaker rejects or replaces a connection.
enum RegisterOutcome {
    /// Brand-new peer registered; nothing to release.
    Admitted,
    /// Tie-breaker preferred the existing connection; release the
    /// freshly-charged slot.
    Rejected,
    /// Tie-breaker replaced the existing connection; release the
    /// *prior* slot's charge so only the surviving connection counts.
    Replaced {
        prev_direction: Direction,
        prev_addr: SocketAddr,
    },
}

#[allow(clippy::too_many_arguments)]
fn register_connection(
    our_node_id: NodeId,
    peer_node_id: NodeId,
    addr: SocketAddr,
    direction: Direction,
    stream: AnyStream,
    conn_id: ConnectionId,
    peers: &mut BTreeMap<NodeId, PeerSlot>,
    protocols: &BTreeMap<u8, mpsc::Sender<ProtocolEvent>>,
    internal_tx: mpsc::Sender<ManagerMsg>,
    protocol_caps: ProtocolCaps,
    discovery_tx: &broadcast::Sender<DiscoveryEvent>,
) -> RegisterOutcome {
    let id = node_id_to_base58(&peer_node_id);

    let prior = peers
        .get(&peer_node_id)
        .map(|slot| (slot.direction, slot.addr));
    if let Some((prev_direction, prev_addr)) = prior {
        // Tie-breaker: the node with the lexicographically lower ID keeps the
        // existing connection; the higher-ID node accepts the new one instead.
        if our_node_id < peer_node_id {
            info!("tie-breaker: keeping existing connection to {id} (we have lower ID)");
            return RegisterOutcome::Rejected;
        }
        info!("tie-breaker: replacing existing connection to {id} (we have higher ID)");
        // Overwriting the slot below drops the old `write_tx`, closing the
        // old connection task's write channel so it exits. Because the slot
        // now has a new `conn_id`, the old task's PeerGone is recognised as
        // stale and no spurious peer-gone event fires (see #114).
        let (write_tx, write_rx) = mpsc::channel::<Bytes>(64);
        peers.insert(
            peer_node_id,
            PeerSlot {
                conn_id,
                write_tx,
                direction,
                addr,
            },
        );
        spawn_connection_task(
            peer_node_id,
            stream,
            write_rx,
            conn_id,
            internal_tx,
            protocol_caps,
        );
        return RegisterOutcome::Replaced {
            prev_direction,
            prev_addr,
        };
    }
    info!("registering new peer {id} at {addr}");

    let (write_tx, write_rx) = mpsc::channel::<Bytes>(64);
    peers.insert(
        peer_node_id,
        PeerSlot {
            conn_id,
            write_tx,
            direction,
            addr,
        },
    );

    // Notify protocols on this fresh connection. (The REPLACE branch
    // above intentionally suppresses these events: replacing the
    // underlying stream doesn't change the logical "is this peer
    // reachable" answer, so firing an extra PeerConnected without a
    // matching PeerDisconnected would confuse protocols that track
    // per-peer state.)
    let _ = discovery_tx.send(DiscoveryEvent::PeerAdded(peer_node_id));
    for event_tx in protocols.values() {
        let _ = event_tx.try_send(ProtocolEvent::PeerConnected {
            node_id: peer_node_id,
            addr,
        });
    }

    spawn_connection_task(
        peer_node_id,
        stream,
        write_rx,
        conn_id,
        internal_tx,
        protocol_caps,
    );
    RegisterOutcome::Admitted
}

/// Spawn the per-connection framing task, which reads/writes through
/// `stream` and notifies the manager with [`ManagerMsg::PeerGone`]
/// when it exits.
fn spawn_connection_task(
    peer_node_id: NodeId,
    stream: AnyStream,
    write_rx: mpsc::Receiver<Bytes>,
    conn_id: ConnectionId,
    internal_tx: mpsc::Sender<ManagerMsg>,
    protocol_caps: ProtocolCaps,
) {
    let conn_tx = internal_tx.clone();
    let id = node_id_to_base58(&peer_node_id);
    tokio::spawn(async move {
        connection::run(peer_node_id, stream, write_rx, conn_tx, protocol_caps).await;
        if internal_tx
            .send(ManagerMsg::PeerGone {
                node_id: peer_node_id,
                connection_id: conn_id,
            })
            .await
            .is_err()
        {
            // Expected during shutdown when the manager has already exited.
            warn!("could not notify manager of PeerGone for {id}");
        }
    });
}

fn tag(protocol_id: u8, payload: Bytes) -> Bytes {
    let mut buf = BytesMut::with_capacity(1 + payload.len());
    buf.put_u8(protocol_id);
    buf.extend_from_slice(&payload);
    buf.freeze()
}

/// Broadcast `msg` to every peer; on per-peer `Full` failures, bump
/// the global overflow counter and the per-peer slow-peer tracker.
/// Returns the [`NodeId`]s whose tracker tripped this call so the
/// caller can disconnect them outside the borrow on `peers`.
fn broadcast_msg(
    peers: &BTreeMap<NodeId, PeerSlot>,
    msg: Bytes,
    peer_outbound_overflows: &Arc<AtomicU64>,
    slow_peer_trackers: &mut HashMap<NodeId, SlowPeerTracker>,
) -> Vec<NodeId> {
    let mut to_disconnect = Vec::new();
    let now = Instant::now();
    for (node_id, slot) in peers {
        let id = node_id_to_base58(node_id);
        match slot.write_tx.try_send(msg.clone()) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                peer_outbound_overflows.fetch_add(1, Ordering::Relaxed);
                warn!("broadcast to {id}: channel full, skipping");
                let tracker = slow_peer_trackers
                    .entry(*node_id)
                    .or_insert_with(SlowPeerTracker::new);
                if tracker.record_overflow(now) {
                    to_disconnect.push(*node_id);
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                warn!("broadcast to {id}: channel closed, skipping");
            }
        }
    }
    to_disconnect
}

/// Tear down `node_id`'s peer slot and notify the rest of the system,
/// matching the cleanup `PeerCommand::Disconnect` performs. Used by
/// the slow-peer disconnect heuristic (#490) so the
/// must-deliver-or-disconnect contract has a real escape valve.
fn disconnect_peer_for_overflow(
    node_id: NodeId,
    peers: &mut BTreeMap<NodeId, PeerSlot>,
    protocols: &BTreeMap<u8, mpsc::Sender<ProtocolEvent>>,
    peer_gone_tx: &broadcast::Sender<NodeId>,
    discovery_tx: &broadcast::Sender<DiscoveryEvent>,
    connection_limiter: Option<&Arc<ConnectionLimiter>>,
    slow_peer_trackers: &mut HashMap<NodeId, SlowPeerTracker>,
) {
    let id = node_id_to_base58(&node_id);
    let Some(slot) = peers.remove(&node_id) else {
        return;
    };
    if let Some(limiter) = connection_limiter {
        limiter.release(slot.direction, slot.addr.ip());
    }
    let _ = peer_gone_tx.send(node_id);
    let _ = discovery_tx.send(DiscoveryEvent::PeerRemoved(node_id));
    for event_tx in protocols.values() {
        let _ = event_tx.try_send(ProtocolEvent::PeerDisconnected { node_id });
    }
    slow_peer_trackers.remove(&node_id);
    info!(
        "slow-peer disconnect: {id} hit {} write_tx overflows in {}s — kicking",
        SLOW_PEER_OVERFLOW_THRESHOLD,
        SLOW_PEER_OVERFLOW_WINDOW.as_secs(),
    );
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, DuplexStream, duplex};
    use tokio::sync::oneshot;

    use super::*;
    use crate::PeerCommand;
    use crate::tls::NodeId;

    fn nid(byte: u8) -> NodeId {
        [byte; 32]
    }

    fn addr() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    /// A running manager wired to freshly created channels. The returned
    /// handles are everything a test needs to drive it end-to-end without
    /// standing up real TLS or sockets.
    struct TestManager {
        cmd_tx: mpsc::Sender<PeerCommand>,
        internal_tx: mpsc::Sender<ManagerMsg>,
        peer_gone_rx: broadcast::Receiver<NodeId>,
        join: tokio::task::JoinHandle<()>,
    }

    impl TestManager {
        fn start(our_node_id: NodeId) -> Self {
            Self::start_with_limiter(our_node_id, None)
        }

        fn start_with_limiter(
            our_node_id: NodeId,
            connection_limiter: Option<Arc<ConnectionLimiter>>,
        ) -> Self {
            let (cmd_tx, cmd_rx) = mpsc::channel::<PeerCommand>(16);
            let (internal_tx, internal_rx) = mpsc::channel::<ManagerMsg>(64);
            let (peer_gone_tx, peer_gone_rx) = broadcast::channel::<NodeId>(16);
            let (discovery_tx, _) = broadcast::channel::<DiscoveryEvent>(16);
            let itx = internal_tx.clone();
            let join = tokio::spawn(async move {
                run(
                    our_node_id,
                    cmd_rx,
                    internal_rx,
                    itx,
                    peer_gone_tx,
                    discovery_tx,
                    connection_limiter,
                )
                .await;
            });
            Self {
                cmd_tx,
                internal_tx,
                peer_gone_rx,
                join,
            }
        }

        async fn register(&self, id: u8) -> ProtocolHandle {
            self.register_with_cap(id, None).await
        }

        async fn register_with_cap(
            &self,
            id: u8,
            max_frame_bytes: Option<usize>,
        ) -> ProtocolHandle {
            let (reply_tx, reply_rx) = oneshot::channel();
            self.cmd_tx
                .send(PeerCommand::RegisterProtocol {
                    id,
                    max_frame_bytes,
                    reply: reply_tx,
                })
                .await
                .unwrap();
            reply_rx.await.unwrap()
        }

        async fn list_peers(&self) -> Vec<NodeId> {
            let (reply_tx, reply_rx) = oneshot::channel();
            self.cmd_tx
                .send(PeerCommand::ListPeers { reply: reply_tx })
                .await
                .unwrap();
            reply_rx.await.unwrap()
        }

        async fn has_peer(&self, node_id: NodeId) -> bool {
            let (reply_tx, reply_rx) = oneshot::channel();
            self.cmd_tx
                .send(PeerCommand::HasPeer {
                    node_id,
                    reply: reply_tx,
                })
                .await
                .unwrap();
            reply_rx.await.unwrap()
        }
    }

    /// Inject a `NewConnection` with a duplex stream. Returns the "remote"
    /// end of the duplex for the test to drive. The connection's writer half
    /// will receive anything the manager sends to this peer; its reader half
    /// is where the test can push framed inbound messages.
    async fn add_peer(mgr: &TestManager, peer: NodeId) -> DuplexStream {
        add_peer_with(mgr, peer, addr(), Direction::Inbound).await
    }

    /// Variant of [`add_peer`] that lets a test pick the source address
    /// and direction (used by the [`ConnectionLimiter`] tests below to
    /// drive per-IP and per-direction caps).
    async fn add_peer_with(
        mgr: &TestManager,
        peer: NodeId,
        addr: SocketAddr,
        direction: Direction,
    ) -> DuplexStream {
        let (local, remote) = duplex(64 * 1024);
        mgr.internal_tx
            .send(ManagerMsg::NewConnection {
                node_id: peer,
                addr,
                direction,
                stream: Box::new(local),
            })
            .await
            .unwrap();
        // Give the register_connection + connection::run spawns a chance to
        // set up before the test interacts with the stream.
        tokio::time::sleep(Duration::from_millis(20)).await;
        remote
    }

    #[tokio::test]
    async fn register_protocol_returns_a_handle() {
        let mgr = TestManager::start(nid(1));
        let mut h = mgr.register(0x42).await;
        // No peers connected yet, so there should be no `PeerConnected`
        // event queued.
        tokio::select! {
            _ = h.event_rx.recv() => panic!("unexpected early event"),
            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
    }

    #[tokio::test]
    async fn register_protocol_outbound_channel_has_configured_capacity() {
        // Guards against silently shrinking the per-protocol outbound
        // buffer. The gossip overlay enqueues here with drop-on-full, so a
        // shallow buffer reintroduces the bounded-burst overflow this depth
        // is sized to absorb. Asserting the wired capacity keeps the
        // steady-state `gossip_sink_overflow_total: 0` invariant honest.
        let mgr = TestManager::start(nid(1));
        let h = mgr.register(0x42).await;
        assert_eq!(h.send_tx.max_capacity(), PROTOCOL_OUTBOUND_CAPACITY);
    }

    #[tokio::test]
    async fn double_register_replaces_old_protocol_mapping() {
        let mgr = TestManager::start(nid(1));
        let mut h1 = mgr.register(0x42).await;
        let mut h2 = mgr.register(0x42).await;

        // Attach a peer; only the second handle should see the
        // `PeerConnected` event (the first's event_tx has been replaced).
        let _remote = add_peer(&mgr, nid(2)).await;

        let saw_first = tokio::time::timeout(Duration::from_millis(50), h1.event_rx.recv())
            .await
            .ok()
            .flatten();
        assert!(
            saw_first.is_none(),
            "old protocol handle should no longer receive events"
        );

        let saw_second = tokio::time::timeout(Duration::from_millis(200), h2.event_rx.recv())
            .await
            .expect("second handle times out")
            .expect("second handle closed");
        match saw_second {
            ProtocolEvent::PeerConnected { node_id, .. } => assert_eq!(node_id, nid(2)),
            other => panic!("expected PeerConnected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_to_unknown_peer_does_not_crash() {
        let mgr = TestManager::start(nid(1));
        let h = mgr.register(0x01).await;

        // No peer registered for nid(99).
        h.send_tx
            .send(ProtocolOutbound::SendTo {
                node_id: nid(99),
                payload: Bytes::from_static(b"hi"),
            })
            .await
            .unwrap();

        // Manager must still be alive afterwards: ListPeers still answers.
        let peers = mgr.list_peers().await;
        assert!(peers.is_empty());
    }

    #[tokio::test]
    async fn broadcast_drops_slow_peer_frames_without_starving_others() {
        let mgr = TestManager::start(nid(1));
        let h = mgr.register(0x01).await;

        // Add a "fast" peer and a "slow" peer. The slow peer never reads
        // from its duplex half — once the connection::run write-task's
        // 64-byte per-peer channel fills, broadcasts to that peer must be
        // dropped, not block other peers.
        let mut fast = add_peer(&mgr, nid(10)).await;
        let _slow = add_peer(&mgr, nid(20)).await;

        // Fire many broadcasts; more than the per-peer channel depth so we
        // know the slow peer's channel overflows.
        for i in 0..200u32 {
            let mut buf = BytesMut::new();
            buf.extend_from_slice(&i.to_be_bytes());
            h.send_tx
                .send(ProtocolOutbound::Broadcast(buf.freeze()))
                .await
                .unwrap();
        }

        // The fast peer must still be receiving framed messages. Read one
        // and assert it decodes as the expected tagged payload.
        let mut read_buf = [0u8; 8];
        let read = tokio::time::timeout(Duration::from_millis(500), fast.read_exact(&mut read_buf))
            .await
            .expect("fast peer times out waiting for a broadcast");
        read.expect("read should succeed");
        // Length-delimited framing: 4 bytes length, then 1 byte protocol
        // tag, then 4 bytes payload. First frame is frame #0, so payload
        // bytes are 0x00000000.
        assert_eq!(&read_buf[..4], &[0, 0, 0, 5]); // frame length = 5
        assert_eq!(read_buf[4], 0x01); // protocol tag

        // Back-pressure metric (#486): the slow peer's duplex (64 KiB)
        // + write_tx (64 frames at any size) can absorb a few hundred
        // small frames. The test floods with 5-byte payloads which
        // never overflow the underlying duplex buffer. The counter is
        // exercised explicitly in
        // `send_to_full_channel_increments_overflow_counter` below
        // using larger payloads.
    }

    #[test]
    fn slow_peer_tracker_fires_once_per_streak() {
        // The first push past THRESHOLD returns true; subsequent
        // pushes within the window return false (so the manager
        // doesn't keep firing PeerGone events while the disconnect
        // cleanup is in flight).
        let mut t = SlowPeerTracker::new();
        let now = Instant::now();
        for i in 0..SLOW_PEER_OVERFLOW_THRESHOLD - 1 {
            assert!(!t.record_overflow(now + Duration::from_millis(i as u64)));
        }
        // The threshold-th push trips.
        assert!(
            t.record_overflow(now + Duration::from_millis(SLOW_PEER_OVERFLOW_THRESHOLD as u64))
        );
        // Subsequent pushes don't re-trip.
        assert!(
            !t.record_overflow(
                now + Duration::from_millis(SLOW_PEER_OVERFLOW_THRESHOLD as u64 + 1)
            )
        );
    }

    #[test]
    fn slow_peer_tracker_ages_out_old_overflows() {
        // Overflows older than the window are pruned, so a peer that
        // briefly stalled and recovered isn't penalised forever.
        let mut t = SlowPeerTracker::new();
        let now = Instant::now();
        // Push enough to be near threshold, all in the *past* window.
        for i in 0..SLOW_PEER_OVERFLOW_THRESHOLD - 1 {
            t.record_overflow(now + Duration::from_millis(i as u64));
        }
        // Jump forward past the window; the next push sees an empty
        // window and does not trip even though many pushes preceded it.
        let later = now + SLOW_PEER_OVERFLOW_WINDOW + Duration::from_secs(1);
        assert!(!t.record_overflow(later));
        assert_eq!(t.overflows.len(), 1);
    }

    #[tokio::test]
    async fn slow_peer_is_disconnected_after_threshold_overflows() {
        // The slow-peer disconnect heuristic (#490) kicks the peer
        // once SLOW_PEER_OVERFLOW_THRESHOLD writes hit `Full` within
        // SLOW_PEER_OVERFLOW_WINDOW. Flood a non-draining peer with
        // 4-KiB frames × 200 (well past the 64-frame threshold +
        // 64-KiB duplex buffer) and assert the peer is removed from
        // the manager's `peers` map and a PeerGone broadcast fires.
        let mut mgr = TestManager::start(nid(1));
        let h = mgr.register(0x01).await;
        let _slow = add_peer(&mgr, nid(20)).await;

        // Sanity: peer is registered before the flood.
        assert!(mgr.has_peer(nid(20)).await);

        let payload = Bytes::from(vec![0xAB; 4 * 1024]);
        for _ in 0..200 {
            h.send_tx
                .send(ProtocolOutbound::SendTo {
                    node_id: nid(20),
                    payload: payload.clone(),
                })
                .await
                .unwrap();
        }

        // Wait for PeerGone — that's the load-bearing observable. Emits
        // exactly once per disconnect via `peer_gone_tx`.
        let gone = tokio::time::timeout(Duration::from_secs(2), mgr.peer_gone_rx.recv())
            .await
            .expect("peer_gone broadcast times out — slow-peer disconnect did not fire")
            .expect("peer_gone channel closed");
        assert_eq!(gone, nid(20));

        // Peer is also removed from the manager's authoritative map.
        assert!(!mgr.has_peer(nid(20)).await);
    }

    #[tokio::test]
    async fn send_to_full_channel_increments_overflow_counter() {
        // To force a real overflow we have to flood enough bytes to
        // fill both the per-peer write_tx (64 frames) AND the
        // 64-KiB duplex buffer the test fixture wires up. Use 4-KiB
        // payloads × 200 frames = 800 KiB ≫ ~65 KiB capacity, so the
        // tail of the burst lands on a full write_tx and bumps the
        // counter.
        let mgr = TestManager::start(nid(1));
        let h = mgr.register(0x01).await;
        let _slow = add_peer(&mgr, nid(20)).await;

        let payload = Bytes::from(vec![0xAB; 4 * 1024]);
        let before = h.peer_outbound_overflows.load(Ordering::Relaxed);
        for _ in 0..200 {
            h.send_tx
                .send(ProtocolOutbound::SendTo {
                    node_id: nid(20),
                    payload: payload.clone(),
                })
                .await
                .unwrap();
        }
        // Let the manager drain the ProtocolSend queue into the slow
        // peer's write_tx so the try_send-Full failures actually fire.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let after = h.peer_outbound_overflows.load(Ordering::Relaxed);
        assert!(
            after > before,
            "send_to overflow counter must advance under flood (before={before} after={after})",
        );
    }

    #[tokio::test]
    async fn peer_gone_fans_out_to_all_protocols() {
        let mut mgr = TestManager::start(nid(1));
        let mut a = mgr.register(0x01).await;
        let mut b = mgr.register(0x02).await;

        let _remote = add_peer(&mgr, nid(7)).await;

        // Drain the two initial PeerConnected events.
        let _ = tokio::time::timeout(Duration::from_millis(200), a.event_rx.recv())
            .await
            .unwrap();
        let _ = tokio::time::timeout(Duration::from_millis(200), b.event_rx.recv())
            .await
            .unwrap();

        // Simulate peer departure via the public Disconnect command — the
        // manager broadcasts peer_gone and fans the event out to every
        // registered protocol. (Post-#114 we can no longer synthesise a
        // bare `ManagerMsg::PeerGone` from a test because it carries the
        // opaque, manager-assigned `connection_id`.)
        mgr.cmd_tx
            .send(PeerCommand::Disconnect { node_id: nid(7) })
            .await
            .unwrap();

        // Broadcast receiver fires. Use the receiver we created at startup,
        // not a resubscribe (which would only see messages published after
        // the resubscribe point).
        let got = tokio::time::timeout(Duration::from_millis(500), mgr.peer_gone_rx.recv())
            .await
            .expect("peer_gone broadcast times out")
            .expect("peer_gone closed");
        assert_eq!(got, nid(7));

        let ea = tokio::time::timeout(Duration::from_millis(200), a.event_rx.recv())
            .await
            .expect("protocol A times out")
            .expect("protocol A closed");
        let eb = tokio::time::timeout(Duration::from_millis(200), b.event_rx.recv())
            .await
            .expect("protocol B times out")
            .expect("protocol B closed");
        assert!(matches!(ea, ProtocolEvent::PeerDisconnected { node_id } if node_id == nid(7)));
        assert!(matches!(eb, ProtocolEvent::PeerDisconnected { node_id } if node_id == nid(7)));

        // After the event fan-out, the peer should be gone from the table.
        assert!(!mgr.has_peer(nid(7)).await);
    }

    #[tokio::test]
    async fn manager_exits_cleanly_when_command_channel_drops() {
        let mgr = TestManager::start(nid(1));
        let TestManager {
            cmd_tx,
            internal_tx,
            join,
            ..
        } = mgr;
        drop(cmd_tx);
        drop(internal_tx);
        // With both input channels closed, the manager's run-loop selects
        // against two None branches and breaks. Wait briefly for it.
        let result = tokio::time::timeout(Duration::from_millis(500), join)
            .await
            .expect("manager did not exit after channels dropped");
        result.expect("manager task panicked");
    }

    #[tokio::test]
    async fn inbound_message_with_unknown_protocol_is_dropped_not_panic() {
        let mgr = TestManager::start(nid(1));
        let _h = mgr.register(0x01).await;

        // Protocol 0xAA is not registered.
        let mut buf = BytesMut::new();
        buf.put_u8(0xAA);
        buf.extend_from_slice(b"payload");
        mgr.internal_tx
            .send(ManagerMsg::InboundMessage {
                node_id: nid(3),
                msg: buf.freeze(),
            })
            .await
            .unwrap();

        // Manager is still alive: commands still work.
        let peers = mgr.list_peers().await;
        assert!(peers.is_empty());
    }

    #[tokio::test]
    async fn empty_inbound_message_is_ignored() {
        let mgr = TestManager::start(nid(1));
        mgr.internal_tx
            .send(ManagerMsg::InboundMessage {
                node_id: nid(3),
                msg: Bytes::new(),
            })
            .await
            .unwrap();

        // Manager still responsive.
        assert!(mgr.list_peers().await.is_empty());
    }

    #[tokio::test]
    async fn tie_breaker_higher_id_rejects_new_connection() {
        // `our_node_id` is nid(1), peer is nid(9). 1 < 9, so by the
        // tie-breaker we keep the existing connection and reject a second:
        // the existing peer entry (and its underlying connection) survives
        // the duplicate NewConnection message.
        let mgr = TestManager::start(nid(1));
        let _h = mgr.register(0x01).await;

        let _first = add_peer(&mgr, nid(9)).await;
        let _second = add_peer(&mgr, nid(9)).await;

        // Still exactly one entry in the peer table.
        let peers = mgr.list_peers().await;
        assert_eq!(peers, vec![nid(9)]);
    }

    /// Regression test for #114: when the higher-ID side of the
    /// tie-breaker replaces an existing connection with a fresh one, the
    /// old connection's teardown must NOT surface as a peer_gone broadcast
    /// (or as a PeerDisconnected fan-out) — the peer is still reachable
    /// via the replacement, and a spurious peer_gone triggers a dialer
    /// reconnect loop.
    #[tokio::test]
    async fn tie_breaker_replace_does_not_emit_peer_gone() {
        // `our_node_id` is nid(9), peer is nid(1). 9 > 1, so the manager
        // takes the REPLACE branch on the second NewConnection.
        let mut mgr = TestManager::start(nid(9));
        let mut h = mgr.register(0x01).await;

        // First connection for nid(1). The protocol sees the initial
        // PeerConnected event.
        let _first = add_peer(&mgr, nid(1)).await;
        let connected = tokio::time::timeout(Duration::from_millis(200), h.event_rx.recv())
            .await
            .expect("initial PeerConnected times out")
            .expect("event channel closed");
        assert!(
            matches!(connected, ProtocolEvent::PeerConnected { node_id, .. } if node_id == nid(1))
        );

        // Second connection for the same peer triggers the REPLACE path.
        // The old `_first` connection's write channel is dropped and the
        // underlying task exits, which would previously have fired
        // peer_gone. Post-fix, it must stay silent.
        let _second = add_peer(&mgr, nid(1)).await;

        // Give the replaced connection task time to exit and push its
        // (stale) PeerGone through the manager.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Assertion 1: no peer_gone broadcast was emitted.
        match mgr.peer_gone_rx.try_recv() {
            Err(broadcast::error::TryRecvError::Empty) => {}
            Ok(n) => panic!(
                "tie-breaker REPLACE must not broadcast peer_gone, got {:?}",
                n
            ),
            Err(other) => panic!("unexpected peer_gone channel state: {other:?}"),
        }

        // Assertion 2: no extra PeerConnected or PeerDisconnected event
        // fanned out to protocols. (Replacing the stream doesn't change
        // whether the peer is reachable, so protocol state should stay
        // consistent.)
        match tokio::time::timeout(Duration::from_millis(50), h.event_rx.recv()).await {
            Err(_) => {}
            Ok(Some(ev)) => {
                panic!("replacement must not fan a protocol event out to handlers, got {ev:?}")
            }
            Ok(None) => panic!("event channel closed unexpectedly"),
        }

        // Assertion 3: the peer is still registered (via the replacement).
        assert!(mgr.has_peer(nid(1)).await);
        assert_eq!(mgr.list_peers().await, vec![nid(1)]);
    }

    #[tokio::test]
    async fn disconnect_unknown_peer_is_noop() {
        let mgr = TestManager::start(nid(1));
        mgr.cmd_tx
            .send(PeerCommand::Disconnect { node_id: nid(42) })
            .await
            .unwrap();
        // Manager survives and still answers.
        assert!(mgr.list_peers().await.is_empty());
    }

    #[tokio::test]
    async fn per_protocol_cap_admits_small_frames_and_drops_oversize() {
        use tokio::io::AsyncWriteExt;

        // Register protocol 0xAB with a 1000-byte cap. A 500-byte frame
        // should be delivered to the protocol handle; a 2000-byte frame
        // should close the connection and surface PeerGone.
        let mut mgr = TestManager::start(nid(1));
        let mut h = mgr.register_with_cap(0xAB, Some(1_000)).await;

        let mut remote = add_peer(&mgr, nid(5)).await;

        // Drain the PeerConnected event so the next recv() is guaranteed
        // to be either the inbound Message or the later PeerDisconnected.
        let connected = tokio::time::timeout(Duration::from_millis(200), h.event_rx.recv())
            .await
            .expect("peer-connected times out")
            .expect("event channel closed");
        assert!(
            matches!(connected, ProtocolEvent::PeerConnected { node_id, .. } if node_id == nid(5))
        );

        // Helper: pack a length-delimited frame whose body is
        // `[protocol_id][payload...]`.
        let frame = |protocol_id: u8, payload_len: usize| -> BytesMut {
            let body_len = 1 + payload_len;
            let mut buf = BytesMut::with_capacity(4 + body_len);
            buf.put_u32(body_len as u32);
            buf.put_u8(protocol_id);
            buf.extend_from_slice(&vec![0u8; payload_len]);
            buf
        };

        // Under-cap frame: body is 500 bytes (< 1000), delivered intact.
        remote.write_all(&frame(0xAB, 499)).await.unwrap();
        let msg = tokio::time::timeout(Duration::from_millis(500), h.event_rx.recv())
            .await
            .expect("inbound message times out")
            .expect("event channel closed");
        match msg {
            ProtocolEvent::Message { from, payload } => {
                assert_eq!(from, nid(5));
                assert_eq!(payload.len(), 499);
            }
            other => panic!("expected Message, got {other:?}"),
        }

        // Over-cap frame: body is 2000 bytes (> 1000). The connection
        // task must close; the manager emits PeerGone and fans out
        // PeerDisconnected to every registered protocol.
        remote.write_all(&frame(0xAB, 1_999)).await.unwrap();

        let gone = tokio::time::timeout(Duration::from_millis(500), mgr.peer_gone_rx.recv())
            .await
            .expect("peer-gone broadcast times out")
            .expect("peer-gone channel closed");
        assert_eq!(gone, nid(5));

        let disc = tokio::time::timeout(Duration::from_millis(500), h.event_rx.recv())
            .await
            .expect("peer-disconnected times out")
            .expect("event channel closed");
        assert!(matches!(disc, ProtocolEvent::PeerDisconnected { node_id } if node_id == nid(5)));

        // Peer table reflects the drop.
        assert!(!mgr.has_peer(nid(5)).await);
    }

    #[tokio::test]
    async fn register_protocol_without_cap_preserves_global_1mb_limit() {
        use tokio::io::AsyncWriteExt;

        // Registering with `max_frame_bytes: None` must keep the existing
        // behaviour: frames below the global 1 MB ceiling are accepted
        // regardless of body size.
        let mgr = TestManager::start(nid(1));
        let mut h = mgr.register_with_cap(0xAB, None).await;

        let mut remote = add_peer(&mgr, nid(5)).await;

        // Drain PeerConnected.
        let _ = tokio::time::timeout(Duration::from_millis(200), h.event_rx.recv())
            .await
            .expect("peer-connected times out");

        // 100 KB body — would have been rejected under a 1000-byte cap,
        // but the protocol registered no cap so this must be delivered.
        let body_len = 100 * 1024 + 1; // +1 for the protocol tag
        let mut buf = BytesMut::with_capacity(4 + body_len);
        buf.put_u32(body_len as u32);
        buf.put_u8(0xAB);
        buf.extend_from_slice(&vec![0u8; 100 * 1024]);
        remote.write_all(&buf).await.unwrap();

        let msg = tokio::time::timeout(Duration::from_millis(500), h.event_rx.recv())
            .await
            .expect("inbound message times out")
            .expect("event channel closed");
        match msg {
            ProtocolEvent::Message { payload, .. } => assert_eq!(payload.len(), 100 * 1024),
            other => panic!("expected Message, got {other:?}"),
        }
    }

    // ── ConnectionLimiter integration ──────────────────────────────────────

    use boule_core::transport::limits::ConnectionLimitsConfig;

    fn sa(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::from(([a, b, c, d], port))
    }

    /// Issue #134 acceptance: opening more than `max_inbound`
    /// connections is refused with a clear, observable error (the
    /// limiter's reject counter, mirrored in WARN logs).
    #[tokio::test]
    async fn excess_inbound_connections_are_refused() {
        let limiter = Arc::new(ConnectionLimiter::new(ConnectionLimitsConfig {
            max_inbound: 2,
            max_outbound: 99,
            max_per_ip: 99,
            max_total: usize::MAX,
        }));
        let mgr = TestManager::start_with_limiter(nid(1), Some(Arc::clone(&limiter)));
        let _h = mgr.register(0x01).await;

        // Two legitimate inbound connections from distinct peers + IPs
        // are admitted.
        let _a = add_peer_with(&mgr, nid(10), sa(10, 0, 0, 1, 7000), Direction::Inbound).await;
        let _b = add_peer_with(&mgr, nid(11), sa(10, 0, 0, 2, 7000), Direction::Inbound).await;
        assert_eq!(mgr.list_peers().await.len(), 2);

        // Third connection past the cap is rejected. The manager
        // logs WARN and increments the reject counter; the peer
        // table stays at 2.
        let _c = add_peer_with(&mgr, nid(12), sa(10, 0, 0, 3, 7000), Direction::Inbound).await;
        assert_eq!(
            mgr.list_peers().await.len(),
            2,
            "third connection must be refused"
        );
        assert!(limiter.rejects() >= 1);
    }

    /// Per-IP cap fires before the global cap: a single noisy peer can
    /// open at most `max_per_ip` connections regardless of overall
    /// inbound headroom.
    #[tokio::test]
    async fn per_ip_cap_blocks_a_single_noisy_source() {
        let limiter = Arc::new(ConnectionLimiter::new(ConnectionLimitsConfig {
            max_inbound: 99,
            max_outbound: 99,
            max_per_ip: 2,
            max_total: usize::MAX,
        }));
        let mgr = TestManager::start_with_limiter(nid(1), Some(Arc::clone(&limiter)));
        let _h = mgr.register(0x01).await;

        // Three connections from the same IP, distinct node IDs.
        // Only the first two should land in the peer table.
        let _a = add_peer_with(&mgr, nid(10), sa(10, 0, 0, 1, 7001), Direction::Inbound).await;
        let _b = add_peer_with(&mgr, nid(11), sa(10, 0, 0, 1, 7002), Direction::Inbound).await;
        let _c = add_peer_with(&mgr, nid(12), sa(10, 0, 0, 1, 7003), Direction::Inbound).await;
        assert_eq!(mgr.list_peers().await.len(), 2);
        assert!(limiter.rejects() >= 1);

        // A connection from a different IP is still admitted — the
        // per-IP cap is per-source, not a global side effect.
        let _d = add_peer_with(&mgr, nid(13), sa(10, 0, 0, 2, 7004), Direction::Inbound).await;
        assert_eq!(mgr.list_peers().await.len(), 3);
    }

    /// #187 / #511 acceptance: a 100-connection inbound flood at
    /// `inbound_max = 8` admits exactly 8 connections; the remaining
    /// 92 increment the limiter's reject counter and never land in
    /// the peer table. Drives the manager directly (rather than the
    /// listener) since the ConnectionLimiter is the layer that
    /// enforces the cap regardless of where the inbound originates.
    #[tokio::test(flavor = "current_thread")]
    async fn inbound_flood_stops_at_inbound_max() {
        // overlay.inbound_max = 8 in the limiter; max_per_ip is
        // bumped well past the flood size so the per-IP cap doesn't
        // fire first (we want this test to exercise the inbound cap
        // specifically — the per-IP cap has its own coverage above).
        let limiter = Arc::new(ConnectionLimiter::new(ConnectionLimitsConfig {
            max_inbound: 8,
            max_outbound: 99,
            max_per_ip: 200,
            max_total: usize::MAX,
        }));
        let mgr = TestManager::start_with_limiter(nid(1), Some(Arc::clone(&limiter)));
        let _h = mgr.register(0x01).await;

        // Send the 100 NewConnection messages back-to-back from
        // distinct NodeIds + IPs. Keep the duplex remote ends alive
        // for the duration of the test so the manager's per-peer
        // write task doesn't observe a dropped pipe and tear down.
        let mut remotes = Vec::with_capacity(100);
        for i in 0..100u32 {
            let (local, remote) = duplex(1024);
            remotes.push(remote);
            // Distinct NodeIds; the byte pattern doesn't matter so
            // long as it's unique. Use the index in the first two
            // bytes so up to 65k flood entries stay distinct.
            let mut id = [0u8; 32];
            id[0..2].copy_from_slice(&(i as u16).to_be_bytes());
            // Distinct IPs: 10.0.<hi>.<lo>.
            let ip_hi = (i >> 8) as u8;
            let ip_lo = i as u8;
            let src = sa(10, 0, ip_hi, ip_lo, 7000);
            mgr.internal_tx
                .send(ManagerMsg::NewConnection {
                    node_id: id,
                    addr: src,
                    direction: Direction::Inbound,
                    stream: Box::new(local),
                })
                .await
                .unwrap();
        }

        // Wait for the manager to process all 100 messages. Poll-with-
        // budget pattern from CLAUDE.md: stop as soon as the steady
        // state is observable, capped at well under the 15s ceiling.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let peers = mgr.list_peers().await.len();
            let rejects = limiter.rejects();
            if peers == 8 && rejects >= 92 {
                break;
            }
            if std::time::Instant::now() > deadline {
                panic!(
                    "did not converge within 5s: peers={peers}, rejects={rejects} \
                     (expected 8 / >=92)",
                );
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        assert_eq!(
            limiter.inbound(),
            8,
            "exactly inbound_max connections accepted",
        );
        assert!(
            limiter.rejects() >= 92,
            "remaining 92 attempts must register as rejects; got {}",
            limiter.rejects()
        );
    }

    /// `Disconnect` releases the connection-limiter slot so a fresh
    /// dial from the same IP can be admitted again.
    #[tokio::test]
    async fn disconnect_releases_connection_limiter_slot() {
        let limiter = Arc::new(ConnectionLimiter::new(ConnectionLimitsConfig {
            max_inbound: 1,
            max_outbound: 99,
            max_per_ip: 99,
            max_total: usize::MAX,
        }));
        let mgr = TestManager::start_with_limiter(nid(1), Some(Arc::clone(&limiter)));
        let _h = mgr.register(0x01).await;

        let _a = add_peer_with(&mgr, nid(10), sa(10, 0, 0, 1, 7000), Direction::Inbound).await;
        assert_eq!(limiter.inbound(), 1);

        mgr.cmd_tx
            .send(PeerCommand::Disconnect { node_id: nid(10) })
            .await
            .unwrap();
        // Wait for the manager to observe the disconnect and release.
        for _ in 0..50 {
            if limiter.inbound() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            limiter.inbound(),
            0,
            "disconnect must free the limiter slot"
        );

        // After release a fresh inbound from any IP fits within the
        // (now-empty) cap.
        let _b = add_peer_with(&mgr, nid(11), sa(10, 0, 0, 2, 7000), Direction::Inbound).await;
        assert!(mgr.has_peer(nid(11)).await);
    }
}
