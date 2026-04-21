pub mod connection;
pub mod listener;
pub mod manager;

use std::net::SocketAddr;

use tokio::sync::oneshot;

use crate::wire::WireMessage;

pub type PeerId = SocketAddr;

#[derive(Debug)]
#[allow(dead_code)]
pub enum P2pCommand {
    Broadcast { msg: WireMessage },
    SendTo { peer_id: PeerId, msg: WireMessage },
    Disconnect { peer_id: PeerId },
    ListPeers { reply: oneshot::Sender<Vec<PeerId>> },
}

#[derive(Debug)]
pub enum P2pEvent {
    PeerConnected { peer_id: PeerId },
    PeerDisconnected { peer_id: PeerId },
    MessageReceived { peer_id: PeerId, msg: WireMessage },
}
