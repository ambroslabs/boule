use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc};

use super::dialer;
use super::listener;
use super::manager::ManagerMsg;
use super::tls::{TlsIdentity, base58_to_node_id};
use super::{ConnectionProtocol, NodeId};
use crate::clock::Clock;
use crate::config::PeerConfig;

pub struct TlsConnectionProtocol {
    pub identity: Arc<TlsIdentity>,
    pub peers: Vec<PeerConfig>,
    pub listener: TcpListener,
    pub clock: Arc<dyn Clock>,
}

impl ConnectionProtocol for TlsConnectionProtocol {
    async fn run(
        self,
        manager_tx: mpsc::Sender<ManagerMsg>,
        peer_gone_tx: broadcast::Sender<NodeId>,
    ) {
        tokio::spawn(listener::run(
            self.listener,
            self.identity.acceptor.clone(),
            manager_tx.clone(),
        ));

        for peer in self.peers {
            let expected = peer
                .node_id
                .as_deref()
                .map(base58_to_node_id)
                .transpose()
                .expect("invalid peer node_id in config");
            tokio::spawn(dialer::reconnect_loop(
                peer.addr,
                expected,
                Arc::clone(&self.identity),
                manager_tx.clone(),
                peer_gone_tx.clone(),
                Arc::clone(&self.clock),
            ));
        }
    }
}
