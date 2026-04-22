pub mod api;
pub mod connection;
pub mod dialer;
pub mod listener;
pub mod manager;
pub mod tls;
pub mod tls_protocol;

use bytes::Bytes;
use tokio::sync::{broadcast, mpsc, oneshot};

pub use tls::NodeId;

pub trait ConnectionProtocol: Send + 'static {
    fn run(
        self,
        manager_tx: mpsc::Sender<manager::ManagerMsg>,
        peer_gone_tx: broadcast::Sender<NodeId>,
    ) -> impl std::future::Future<Output = ()> + Send;
}

#[derive(Debug)]
#[allow(dead_code)] // TODO: remove once SendTo and Disconnect are wired up
pub enum PeerCommand {
    Broadcast { msg: Bytes },
    SendTo { node_id: NodeId, msg: Bytes },
    Disconnect { node_id: NodeId },
    ListPeers { reply: oneshot::Sender<Vec<NodeId>> },
    HasPeer { node_id: NodeId, reply: oneshot::Sender<bool> },
}

#[derive(Debug)]
pub enum PeerEvent {
    PeerConnected { node_id: NodeId },
    PeerDisconnected { node_id: NodeId },
    MessageReceived { node_id: NodeId, msg: Bytes },
}
