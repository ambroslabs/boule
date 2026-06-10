use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use bytes::Bytes;
use tokio::sync::{broadcast, mpsc};
use tracing::debug;

use crate::clock::BoxFuture;

use crate::identity::NodeId;

pub trait Broadcaster: Send + Sync {
    fn broadcast(&self, payload: Bytes) -> BoxFuture<'_, ()>;

    fn send_to(&self, target: NodeId, payload: Bytes) -> BoxFuture<'_, ()>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryEvent {
    PeerAdded(NodeId),

    PeerRemoved(NodeId),
}

pub trait Discovery: Send + Sync {
    fn known_peers(&self) -> Vec<NodeId>;

    fn add_bootstrap(&self, addr: SocketAddr);

    fn disconnect(&self, _node_id: NodeId) {}

    fn subscribe(&self) -> broadcast::Receiver<DiscoveryEvent>;
}

#[derive(Debug)]
pub enum ProtocolEvent {
    PeerConnected { node_id: NodeId, addr: SocketAddr },

    PeerDisconnected { node_id: NodeId },

    Message { from: NodeId, payload: Bytes },
}

#[derive(Debug)]
pub enum ProtocolOutbound {
    Broadcast(Bytes),

    SendTo { node_id: NodeId, payload: Bytes },
}

pub struct MemoryBroadcaster {
    send_tx: mpsc::Sender<ProtocolOutbound>,
}

impl MemoryBroadcaster {
    pub fn new(send_tx: mpsc::Sender<ProtocolOutbound>) -> Self {
        Self { send_tx }
    }
}

impl Broadcaster for MemoryBroadcaster {
    fn broadcast(&self, payload: Bytes) -> BoxFuture<'_, ()> {
        let send_tx = self.send_tx.clone();
        Box::pin(async move {
            let _ = send_tx.send(ProtocolOutbound::Broadcast(payload)).await;
        })
    }

    fn send_to(&self, target: NodeId, payload: Bytes) -> BoxFuture<'_, ()> {
        let send_tx = self.send_tx.clone();
        Box::pin(async move {
            let _ = send_tx
                .send(ProtocolOutbound::SendTo {
                    node_id: target,
                    payload,
                })
                .await;
        })
    }
}

pub struct MemoryDiscovery {
    peers: Arc<RwLock<BTreeSet<NodeId>>>,
    events: broadcast::Sender<DiscoveryEvent>,
}

impl MemoryDiscovery {
    pub fn spawn(mut source: broadcast::Receiver<DiscoveryEvent>) -> Arc<Self> {
        let peers: Arc<RwLock<BTreeSet<NodeId>>> = Arc::new(RwLock::new(BTreeSet::new()));
        let (events, _) = broadcast::channel::<DiscoveryEvent>(64);

        let peers_for_task = Arc::clone(&peers);
        let events_for_task = events.clone();
        tokio::spawn(async move {
            loop {
                match source.recv().await {
                    Ok(ev) => {
                        match &ev {
                            DiscoveryEvent::PeerAdded(p) => {
                                peers_for_task.write().unwrap().insert(*p);
                            }
                            DiscoveryEvent::PeerRemoved(p) => {
                                peers_for_task.write().unwrap().remove(p);
                            }
                        }
                        let _ = events_for_task.send(ev);
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        debug!("MemoryDiscovery: source channel lagged; cache may be stale");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        Arc::new(Self { peers, events })
    }
}

impl Discovery for MemoryDiscovery {
    fn known_peers(&self) -> Vec<NodeId> {
        self.peers.read().unwrap().iter().copied().collect()
    }

    fn add_bootstrap(&self, _addr: SocketAddr) {
        debug!("MemoryDiscovery::add_bootstrap is a no-op on the in-memory fake");
    }

    fn subscribe(&self) -> broadcast::Receiver<DiscoveryEvent> {
        self.events.subscribe()
    }
}
