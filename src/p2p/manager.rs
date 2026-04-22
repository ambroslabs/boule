use std::collections::HashMap;
use std::net::SocketAddr;

use tokio::sync::{broadcast, mpsc};
use tracing::{info, warn};

use super::connection;
use super::tls::{node_id_to_base58, NodeId, TlsStream};
use super::{PeerCommand, PeerEvent};
use crate::wire::WireMessage;

/// Internal messages that flow into the manager (from listener + connection tasks).
pub enum ManagerMsg {
    NewConnection { node_id: NodeId, addr: SocketAddr, stream: TlsStream },
    PeerGone { node_id: NodeId },
}

pub async fn run(
    our_node_id: NodeId,
    mut cmd_rx: mpsc::Receiver<PeerCommand>,
    event_tx: mpsc::Sender<PeerEvent>,
    mut internal_rx: mpsc::Receiver<ManagerMsg>,
    internal_tx: mpsc::Sender<ManagerMsg>,
    peer_gone_tx: broadcast::Sender<NodeId>,
) {
    let mut peers: HashMap<NodeId, mpsc::Sender<WireMessage>> = HashMap::new();

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
                            event_tx.clone(),
                            internal_tx.clone(),
                        );
                    }
                    Some(ManagerMsg::PeerGone { node_id }) => {
                        peers.remove(&node_id);
                        let _ = peer_gone_tx.send(node_id);
                    }
                    None => break,
                }
            }

            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(PeerCommand::Broadcast { msg }) => {
                        broadcast_msg(&peers, msg);
                    }
                    Some(PeerCommand::SendTo { node_id, msg }) => {
                        let id = node_id_to_base58(&node_id);
                        if let Some(tx) = peers.get(&node_id) {
                            if tx.try_send(msg).is_err() {
                                warn!("SendTo {id}: channel full or closed");
                            }
                        } else {
                            warn!("SendTo unknown peer {id}");
                        }
                    }
                    Some(PeerCommand::Disconnect { node_id }) => {
                        let id = node_id_to_base58(&node_id);
                        if peers.remove(&node_id).is_none() {
                            warn!("Disconnect unknown peer {id}");
                        }
                        // Dropping the sender closes the write channel, which
                        // causes the connection task to exit and emit PeerDisconnected.
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
    stream: TlsStream,
    peers: &mut HashMap<NodeId, mpsc::Sender<WireMessage>>,
    event_tx: mpsc::Sender<PeerEvent>,
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

    let (write_tx, write_rx) = mpsc::channel::<WireMessage>(64);
    peers.insert(peer_node_id, write_tx);

    tokio::spawn(async move {
        connection::run(peer_node_id, stream, write_rx, event_tx).await;
        if internal_tx
            .send(ManagerMsg::PeerGone { node_id: peer_node_id })
            .await
            .is_err()
        {
            // Expected during shutdown when the manager has already exited.
            warn!("could not notify manager of PeerGone for {id}");
        }
    });
}

fn broadcast_msg(peers: &HashMap<NodeId, mpsc::Sender<WireMessage>>, msg: WireMessage) {
    for (node_id, tx) in peers {
        let id = node_id_to_base58(node_id);
        if tx.try_send(msg.clone()).is_err() {
            warn!("broadcast to {id}: channel full or closed, skipping");
        }
    }
}
