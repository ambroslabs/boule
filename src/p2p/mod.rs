pub mod connection;
pub mod listener;
pub mod manager;
pub mod tls;

use tokio::sync::oneshot;

use crate::wire::WireMessage;

pub use tls::NodeId;

#[derive(Debug)]
#[allow(dead_code)] // TODO: remove once SendTo and Disconnect are wired up
pub enum PeerCommand {
    Broadcast { msg: WireMessage },
    SendTo { node_id: NodeId, msg: WireMessage },
    Disconnect { node_id: NodeId },
    ListPeers { reply: oneshot::Sender<Vec<NodeId>> },
    HasPeer { node_id: NodeId, reply: oneshot::Sender<bool> },
}

#[derive(Debug)]
pub enum PeerEvent {
    PeerConnected { node_id: NodeId },
    PeerDisconnected { node_id: NodeId },
    MessageReceived { node_id: NodeId, msg: WireMessage },
}
