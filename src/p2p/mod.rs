pub mod api;
pub mod connection;
pub mod dialer;
pub mod identity;
pub mod listener;
pub mod manager;
pub mod rpc;
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
#[allow(dead_code)]
pub enum PeerCommand {
    RegisterProtocol {
        id: u8,
        reply: oneshot::Sender<ProtocolHandle>,
    },
    Disconnect {
        node_id: NodeId,
    },
    ListPeers {
        reply: oneshot::Sender<Vec<NodeId>>,
    },
    HasPeer {
        node_id: NodeId,
        reply: oneshot::Sender<bool>,
    },
}

#[derive(Debug)]
#[allow(dead_code)] // SendTo will be used once multi-protocol routing is needed
pub enum ProtocolOutbound {
    Broadcast(Bytes),
    SendTo { node_id: NodeId, payload: Bytes },
}

#[derive(Debug)]
pub enum ProtocolEvent {
    PeerConnected { node_id: NodeId },
    PeerDisconnected { node_id: NodeId },
    Message { from: NodeId, payload: Bytes },
}

#[derive(Debug)]
pub struct ProtocolHandle {
    pub send_tx: mpsc::Sender<ProtocolOutbound>,
    pub event_rx: mpsc::Receiver<ProtocolEvent>,
}
