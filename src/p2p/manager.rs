use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
use parking_lot::RwLock;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{broadcast, mpsc};
use tracing::{info, warn};

use super::connection;
use super::connection::ProtocolCaps;
use super::overlay::DiscoveryEvent;
use super::tls::{NodeId, node_id_to_base58};
use super::{PeerCommand, ProtocolEvent, ProtocolHandle, ProtocolOutbound};

/// Monotonic per-connection identity assigned by the manager. Used to
/// distinguish connections to the same peer so a tie-breaker replacement
/// does not look like a disconnect to the rest of the system (issue #114).
pub type ConnectionId = u64;

/// What the manager stores for each currently-connected peer: the id of the
/// specific connection that owns the peer slot plus the channel that writes
/// bytes onto it.
struct PeerSlot {
    conn_id: ConnectionId,
    write_tx: mpsc::Sender<Bytes>,
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

    loop {
        tokio::select! {
            // Bias branches in declared order so the select arm pick is
            // deterministic across runs (same rationale as above).
            biased;
            msg = internal_rx.recv() => {
                match msg {
                    Some(ManagerMsg::NewConnection { node_id, addr, stream }) => {
                        next_conn_id += 1;
                        register_connection(
                            our_node_id,
                            node_id,
                            addr,
                            stream,
                            next_conn_id,
                            &mut peers,
                            &protocols,
                            internal_tx.clone(),
                            Arc::clone(&protocol_caps),
                            &discovery_tx,
                        );
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
                            peers.remove(&node_id);
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
                                broadcast_msg(&peers, tagged);
                            }
                            ProtocolOutbound::SendTo { node_id, payload } => {
                                let tagged = tag(protocol_id, payload);
                                let id = node_id_to_base58(&node_id);
                                if let Some(slot) = peers.get(&node_id) {
                                    if slot.write_tx.try_send(tagged).is_err() {
                                        warn!("SendTo {id}: channel full or closed");
                                    }
                                } else {
                                    warn!("SendTo unknown peer {id}");
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
                        let (send_tx, mut send_rx) = mpsc::channel::<ProtocolOutbound>(256);
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
                        let _ = reply.send(ProtocolHandle { send_tx, event_rx });
                    }
                    Some(PeerCommand::Disconnect { node_id }) => {
                        let id = node_id_to_base58(&node_id);
                        if peers.remove(&node_id).is_some() {
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

#[allow(clippy::too_many_arguments)]
fn register_connection(
    our_node_id: NodeId,
    peer_node_id: NodeId,
    addr: SocketAddr,
    stream: AnyStream,
    conn_id: ConnectionId,
    peers: &mut BTreeMap<NodeId, PeerSlot>,
    protocols: &BTreeMap<u8, mpsc::Sender<ProtocolEvent>>,
    internal_tx: mpsc::Sender<ManagerMsg>,
    protocol_caps: ProtocolCaps,
    discovery_tx: &broadcast::Sender<DiscoveryEvent>,
) {
    let id = node_id_to_base58(&peer_node_id);

    let is_replacement = peers.contains_key(&peer_node_id);
    if is_replacement {
        // Tie-breaker: the node with the lexicographically lower ID keeps the
        // existing connection; the higher-ID node accepts the new one instead.
        if our_node_id < peer_node_id {
            info!("tie-breaker: keeping existing connection to {id} (we have lower ID)");
            return;
        }
        info!("tie-breaker: replacing existing connection to {id} (we have higher ID)");
        // Overwriting the slot below drops the old `write_tx`, closing the
        // old connection task's write channel so it exits. Because the slot
        // now has a new `conn_id`, the old task's PeerGone is recognised as
        // stale and no spurious peer-gone event fires (see #114).
    } else {
        info!("registering new peer {id} at {addr}");
    }

    let (write_tx, write_rx) = mpsc::channel::<Bytes>(64);
    peers.insert(peer_node_id, PeerSlot { conn_id, write_tx });

    // Only notify protocols on a fresh connection. Replacing the underlying
    // stream doesn't change the logical "is this peer reachable" answer, so
    // firing an extra PeerConnected (without a matching PeerDisconnected)
    // would confuse any protocol that tracks per-peer state.
    if !is_replacement {
        let _ = discovery_tx.send(DiscoveryEvent::PeerAdded(peer_node_id));
        for event_tx in protocols.values() {
            let _ = event_tx.try_send(ProtocolEvent::PeerConnected {
                node_id: peer_node_id,
                addr,
            });
        }
    }

    let conn_tx = internal_tx.clone();
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

fn broadcast_msg(peers: &BTreeMap<NodeId, PeerSlot>, msg: Bytes) {
    for (node_id, slot) in peers {
        let id = node_id_to_base58(node_id);
        if slot.write_tx.try_send(msg.clone()).is_err() {
            warn!("broadcast to {id}: channel full or closed, skipping");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, DuplexStream, duplex};
    use tokio::sync::oneshot;

    use super::*;
    use crate::p2p::PeerCommand;
    use crate::p2p::tls::NodeId;

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
        let (local, remote) = duplex(64 * 1024);
        mgr.internal_tx
            .send(ManagerMsg::NewConnection {
                node_id: peer,
                addr: addr(),
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
}
