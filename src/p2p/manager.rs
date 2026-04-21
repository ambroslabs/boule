use std::collections::HashMap;
use std::net::SocketAddr;

use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{info, warn};

use super::connection;
use super::{P2pCommand, P2pEvent, PeerId};
use crate::wire::WireMessage;

/// Internal messages that flow into the manager (from listener + connection tasks).
pub enum ManagerMsg {
    NewConnection { stream: TcpStream, addr: SocketAddr },
    PeerGone { peer_id: PeerId },
}

pub async fn run(
    mut cmd_rx: mpsc::Receiver<P2pCommand>,
    event_tx: mpsc::Sender<P2pEvent>,
    mut internal_rx: mpsc::Receiver<ManagerMsg>,
    internal_tx: mpsc::Sender<ManagerMsg>,
) {
    // peer_id -> per-connection write sender
    let mut peers: HashMap<PeerId, mpsc::Sender<WireMessage>> = HashMap::new();

    loop {
        tokio::select! {
            msg = internal_rx.recv() => {
                match msg {
                    Some(ManagerMsg::NewConnection { stream, addr }) => {
                        register_connection(addr, stream, &mut peers, event_tx.clone(), internal_tx.clone());
                    }
                    Some(ManagerMsg::PeerGone { peer_id }) => {
                        peers.remove(&peer_id);
                        // The connection task already sent PeerDisconnected to event_tx.
                    }
                    None => break,
                }
            }

            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(P2pCommand::Broadcast { msg }) => {
                        broadcast(&peers, msg);
                    }
                    Some(P2pCommand::SendTo { peer_id, msg }) => {
                        if let Some(tx) = peers.get(&peer_id) {
                            let _ = tx.try_send(msg);
                        } else {
                            warn!("SendTo unknown peer {peer_id}");
                        }
                    }
                    Some(P2pCommand::Disconnect { peer_id }) => {
                        if peers.remove(&peer_id).is_none() {
                            warn!("Disconnect unknown peer {peer_id}");
                        }
                        // Dropping the sender closes the write channel, which
                        // causes the connection task to exit and emit PeerDisconnected.
                    }
                    Some(P2pCommand::ListPeers { reply }) => {
                        let list: Vec<PeerId> = peers.keys().copied().collect();
                        let _ = reply.send(list);
                    }
                    None => break,
                }
            }
        }
    }
}

fn register_connection(
    addr: SocketAddr,
    stream: TcpStream,
    peers: &mut HashMap<PeerId, mpsc::Sender<WireMessage>>,
    event_tx: mpsc::Sender<P2pEvent>,
    internal_tx: mpsc::Sender<ManagerMsg>,
) {
    let (write_tx, write_rx) = mpsc::channel::<WireMessage>(64);

    // If there's already a connection for this addr, the old sender is dropped,
    // which will close the old connection task's write channel.
    if peers.insert(addr, write_tx).is_some() {
        info!("replacing existing connection for {addr}");
    }

    tokio::spawn(async move {
        connection::run(addr, stream, write_rx, event_tx).await;
        let _ = internal_tx.send(ManagerMsg::PeerGone { peer_id: addr }).await;
    });
}

fn broadcast(peers: &HashMap<PeerId, mpsc::Sender<WireMessage>>, msg: WireMessage) {
    for (peer_id, tx) in peers {
        if tx.try_send(msg.clone()).is_err() {
            warn!("broadcast to {peer_id}: channel full or closed, skipping");
        }
    }
}
