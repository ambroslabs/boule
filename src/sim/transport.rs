//! In-memory [`crate::p2p::ConnectionProtocol`] for the simulator.
//!
//! On `run`, this fires `ManagerMsg::NewConnection` for each pre-wired peer
//! and then exits. The actual byte transport is a `tokio::io::DuplexStream`
//! pair that the [`SimDriver`] created when wiring nodes together; the
//! manager reads/writes through that stream identically to a TCP/TLS one,
//! so `connection::run` (the framing code) is exercised unchanged.

use std::net::SocketAddr;

use tokio::sync::{broadcast, mpsc};

use crate::p2p::manager::{AnyStream, ManagerMsg};
use crate::p2p::{ConnectionProtocol, NodeId};

pub struct SimConnectionProtocol {
    /// Pre-established connections to peers, handed in by the [`SimDriver`].
    pub peers: Vec<(NodeId, SocketAddr, AnyStream)>,
}

impl ConnectionProtocol for SimConnectionProtocol {
    async fn run(
        self,
        manager_tx: mpsc::Sender<ManagerMsg>,
        _peer_gone_tx: broadcast::Sender<NodeId>,
    ) {
        for (node_id, addr, stream) in self.peers {
            // If the manager has already shut down, nothing to do.
            if manager_tx
                .send(ManagerMsg::NewConnection {
                    node_id,
                    addr,
                    stream,
                })
                .await
                .is_err()
            {
                return;
            }
        }
    }
}
