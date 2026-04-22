use std::collections::HashMap;
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
    let mut peers: HashMap<NodeId, mpsc::Sender<Bytes>> = HashMap::new();
    let mut protocols: HashMap<u8, mpsc::Sender<ProtocolEvent>> = HashMap::new();

    loop {
        tokio::select! {
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
    peers: &mut HashMap<NodeId, mpsc::Sender<Bytes>>,
    protocols: &HashMap<u8, mpsc::Sender<ProtocolEvent>>,
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

fn broadcast_msg(peers: &HashMap<NodeId, mpsc::Sender<Bytes>>, msg: Bytes) {
    for (node_id, tx) in peers {
        let id = node_id_to_base58(node_id);
        if tx.try_send(msg.clone()).is_err() {
            warn!("broadcast to {id}: channel full or closed, skipping");
        }
    }
}
