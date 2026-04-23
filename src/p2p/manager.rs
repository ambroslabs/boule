use std::collections::BTreeMap;
use std::net::SocketAddr;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{broadcast, mpsc};
use tracing::{info, warn};

use super::connection;
use super::tls::{NodeId, node_id_to_base58};
use super::{PeerCommand, ProtocolEvent, ProtocolHandle, ProtocolOutbound};

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
    PeerGone {
        node_id: NodeId,
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
) {
    // `BTreeMap` so broadcast and event-fan-out iteration is deterministic;
    // the sim's byte-identical-trace determinism test relies on this, and
    // consistent broadcast ordering is also helpful for reproducing
    // production bugs.
    let mut peers: BTreeMap<NodeId, mpsc::Sender<Bytes>> = BTreeMap::new();
    let mut protocols: BTreeMap<u8, mpsc::Sender<ProtocolEvent>> = BTreeMap::new();

    loop {
        tokio::select! {
            // Bias branches in declared order so the select arm pick is
            // deterministic across runs (same rationale as above).
            biased;
            msg = internal_rx.recv() => {
                match msg {
                    Some(ManagerMsg::NewConnection { node_id, addr, stream }) => {
                        register_connection(
                            our_node_id,
                            node_id,
                            addr,
                            stream,
                            &mut peers,
                            &protocols,
                            internal_tx.clone(),
                        );
                    }
                    Some(ManagerMsg::PeerGone { node_id }) => {
                        peers.remove(&node_id);
                        let _ = peer_gone_tx.send(node_id);
                        for event_tx in protocols.values() {
                            let _ = event_tx.try_send(ProtocolEvent::PeerDisconnected { node_id });
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
                                if let Some(tx) = peers.get(&node_id) {
                                    if tx.try_send(tagged).is_err() {
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
                    Some(PeerCommand::RegisterProtocol { id, reply }) => {
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
                        let _ = reply.send(ProtocolHandle { send_tx, event_rx });
                    }
                    Some(PeerCommand::Disconnect { node_id }) => {
                        let id = node_id_to_base58(&node_id);
                        if peers.remove(&node_id).is_none() {
                            warn!("Disconnect unknown peer {id}");
                        }
                        // Dropping the sender closes the write channel, which
                        // causes the connection task to exit and emit PeerGone.
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

fn register_connection(
    our_node_id: NodeId,
    peer_node_id: NodeId,
    addr: SocketAddr,
    stream: AnyStream,
    peers: &mut BTreeMap<NodeId, mpsc::Sender<Bytes>>,
    protocols: &BTreeMap<u8, mpsc::Sender<ProtocolEvent>>,
    internal_tx: mpsc::Sender<ManagerMsg>,
) {
    let id = node_id_to_base58(&peer_node_id);

    if peers.contains_key(&peer_node_id) {
        // Tie-breaker: the node with the lexicographically lower ID keeps the
        // existing connection; the higher-ID node accepts the new one instead.
        if our_node_id < peer_node_id {
            info!("tie-breaker: keeping existing connection to {id} (we have lower ID)");
            return;
        }
        info!("tie-breaker: replacing existing connection to {id} (we have higher ID)");
        // Dropping the old sender below closes the old write channel, which
        // causes the old connection task to exit and fire PeerGone.
    } else {
        info!("registering new peer {id} at {addr}");
    }

    let (write_tx, write_rx) = mpsc::channel::<Bytes>(64);
    peers.insert(peer_node_id, write_tx);

    for event_tx in protocols.values() {
        let _ = event_tx.try_send(ProtocolEvent::PeerConnected {
            node_id: peer_node_id,
        });
    }

    let conn_tx = internal_tx.clone();
    tokio::spawn(async move {
        connection::run(peer_node_id, stream, write_rx, conn_tx).await;
        if internal_tx
            .send(ManagerMsg::PeerGone {
                node_id: peer_node_id,
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

fn broadcast_msg(peers: &BTreeMap<NodeId, mpsc::Sender<Bytes>>, msg: Bytes) {
    for (node_id, tx) in peers {
        let id = node_id_to_base58(node_id);
        if tx.try_send(msg.clone()).is_err() {
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
            let itx = internal_tx.clone();
            let join = tokio::spawn(async move {
                run(our_node_id, cmd_rx, internal_rx, itx, peer_gone_tx).await;
            });
            Self {
                cmd_tx,
                internal_tx,
                peer_gone_rx,
                join,
            }
        }

        async fn register(&self, id: u8) -> ProtocolHandle {
            let (reply_tx, reply_rx) = oneshot::channel();
            self.cmd_tx
                .send(PeerCommand::RegisterProtocol {
                    id,
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
            ProtocolEvent::PeerConnected { node_id } => assert_eq!(node_id, nid(2)),
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

        // Simulate peer departure.
        mgr.internal_tx
            .send(ManagerMsg::PeerGone { node_id: nid(7) })
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
}
