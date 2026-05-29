use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc};

use super::dialer::DialerCtx;
use super::listener;
use super::manager::ManagerMsg;
use super::tls::{TlsIdentity, base58_to_node_id};
use super::{ConnectionProtocol, NodeId, PeerCommand};
use boule_core::clock::Clock;
use boule_core::config::PeerConfig;

pub struct TlsConnectionProtocol {
    pub identity: Arc<TlsIdentity>,
    pub peers: Vec<PeerConfig>,
    /// `Some` for normal nodes that accept inbound connections; `None`
    /// when the node is in outbound-only mode (issue #138's
    /// `[p2p] inbound_disabled = true`). When `None`, no listener task
    /// is spawned and the node only ever participates as a dialer.
    pub listener: Option<TcpListener>,
    pub clock: Arc<dyn Clock>,
    /// Optional handle back into the peer manager's command channel so the
    /// dialer can ask whether a peer is already connected before redialing
    /// (see #114). `None` falls back to the old broadcast-only loop, which
    /// the sim transport is fine with because it never redials.
    pub peer_cmd_tx: Option<mpsc::Sender<PeerCommand>>,
}

impl ConnectionProtocol for TlsConnectionProtocol {
    async fn run(
        self,
        manager_tx: mpsc::Sender<ManagerMsg>,
        peer_gone_tx: broadcast::Sender<NodeId>,
    ) {
        if let Some(listener) = self.listener {
            tokio::spawn(listener::run(
                listener,
                self.identity.acceptor.clone(),
                self.identity.node_id,
                manager_tx.clone(),
            ));
        }

        let dialer_ctx = DialerCtx {
            identity: Arc::clone(&self.identity),
            internal_tx: manager_tx,
            peer_gone_tx,
            peer_cmd_tx: self.peer_cmd_tx,
            clock: Arc::clone(&self.clock),
        };

        for peer in self.peers {
            let expected = peer
                .node_id
                .as_deref()
                .map(base58_to_node_id)
                .transpose()
                .expect("invalid peer node_id in config");
            dialer_ctx.spawn(peer.addr, expected);
        }
    }
}
