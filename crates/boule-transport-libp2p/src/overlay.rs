//! The libp2p overlay driver (#842): owns the `Swarm` in one tokio task and
//! implements the `boule_core::transport::overlay` `Broadcaster` /
//! `Discovery` seam over it.
//!
//! - [`Broadcaster::broadcast`] → gossipsub publish on the consensus topic.
//! - inbound gossipsub messages → [`ProtocolEvent::Message`] on the upstream
//!   channel consensus reads, with `from` = the signature-verified publisher.
//! - swarm connect/close → [`ProtocolEvent::PeerConnected`] /
//!   [`ProtocolEvent::PeerDisconnected`] + [`DiscoveryEvent`] deltas.
//!
//! `send_to` has no addressed unicast yet — Phase 2 mirrors the custom
//! overlay's broadcast-as-unicast (publish; the target acts, others ignore).
//! Phase 3 (#843) replaces it with a libp2p request-response stream.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use boule_core::clock::BoxFuture;
use boule_core::identity::NodeId;
use boule_core::transport::overlay::{Broadcaster, Discovery, DiscoveryEvent, ProtocolEvent};
use bytes::Bytes;
use futures::StreamExt as _;
use libp2p::core::ConnectedPoint;
use libp2p::gossipsub::TopicHash;
use libp2p::swarm::SwarmEvent;
use libp2p::{
    Multiaddr, PeerId, Swarm, gossipsub, identity::Keypair, multiaddr::Protocol, request_response,
};
use parking_lot::Mutex;
use tokio::sync::{broadcast, mpsc, oneshot};
use tracing::debug;

use crate::identity::{node_id_for, peer_id_for};
use crate::swarm::{Behaviour, BehaviourEvent, build_swarm, consensus_topic};

const TRACE: &str = "boule_transport_libp2p::overlay";

/// Outbound commands fed to the swarm-owning driver task.
enum Command {
    /// Publish a payload to the consensus topic.
    Broadcast(Bytes),
    /// Deliver a payload to a single peer (block-sync / unicast, #843).
    SendTo { target: NodeId, payload: Bytes },
    /// Dial a peer at the given address (bootstrap ingestion).
    Dial(Multiaddr),
}

/// Everything [`spawn`] hands back to the rest of the node.
pub struct Libp2pOverlayHandles {
    /// Outbound dispatch surface for consensus.
    pub broadcaster: Arc<Libp2pBroadcaster>,
    /// Peer-membership surface for consensus.
    pub discovery: Arc<Libp2pDiscovery>,
    /// Inbound events consensus consumes.
    pub event_rx: mpsc::Receiver<ProtocolEvent>,
    /// Drop or send to stop the driver task.
    pub shutdown: oneshot::Sender<()>,
    /// The driver task handle.
    pub join: tokio::task::JoinHandle<()>,
}

/// Inputs for [`spawn`].
pub struct SpawnConfig {
    /// The node's libp2p keypair (derived from its consensus Ed25519 key).
    pub keypair: Keypair,
    /// Address to listen on, or `None` for outbound-only (inbound disabled).
    pub listen_addr: Option<SocketAddr>,
    /// Addresses to dial at startup.
    pub bootstrap_addrs: Vec<SocketAddr>,
    /// Idle-connection timeout for the swarm.
    pub idle_connection_timeout: Duration,
    /// Connection-gating allow-list (#844/#836). `Some(non-empty)` =
    /// validator isolation (only these peers may connect); `None`/empty =
    /// open node (sentry).
    pub allowed_peers: Option<Vec<NodeId>>,
}

/// Build the swarm, start its driver task, and return the seam handles.
pub fn spawn(cfg: SpawnConfig) -> Result<Libp2pOverlayHandles> {
    let mut swarm = build_swarm(cfg.keypair, cfg.idle_connection_timeout, cfg.allowed_peers)?;
    if let Some(addr) = cfg.listen_addr {
        swarm
            .listen_on(socketaddr_to_multiaddr(addr))
            .context("libp2p listen_on")?;
    }
    for b in &cfg.bootstrap_addrs {
        let _ = swarm.dial(socketaddr_to_multiaddr(*b));
    }

    let (cmd_tx, cmd_rx) = mpsc::channel(256);
    let (event_tx, event_rx) = mpsc::channel(1024);
    let (disco_tx, _disco_rx) = broadcast::channel(256);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let peers = Arc::new(Mutex::new(HashSet::new()));

    let driver = Driver {
        swarm,
        cmd_rx,
        event_tx,
        disco_tx: disco_tx.clone(),
        peers: Arc::clone(&peers),
        topic: consensus_topic().hash(),
        shutdown_rx,
    };
    let join = tokio::spawn(driver.run());

    Ok(Libp2pOverlayHandles {
        broadcaster: Arc::new(Libp2pBroadcaster {
            cmd_tx: cmd_tx.clone(),
        }),
        discovery: Arc::new(Libp2pDiscovery {
            peers,
            events: disco_tx,
            cmd_tx,
        }),
        event_rx,
        shutdown: shutdown_tx,
        join,
    })
}

// ── Broadcaster ────────────────────────────────────────────────────────────────

/// [`Broadcaster`] backed by the libp2p driver's command channel.
pub struct Libp2pBroadcaster {
    cmd_tx: mpsc::Sender<Command>,
}

impl Broadcaster for Libp2pBroadcaster {
    fn broadcast(&self, payload: Bytes) -> BoxFuture<'_, ()> {
        let tx = self.cmd_tx.clone();
        Box::pin(async move {
            let _ = tx.send(Command::Broadcast(payload)).await;
        })
    }

    fn send_to(&self, target: NodeId, payload: Bytes) -> BoxFuture<'_, ()> {
        // Real addressed delivery via request-response (#843) — a direct
        // stream to `target`, no whole-mesh fan-out.
        let tx = self.cmd_tx.clone();
        Box::pin(async move {
            let _ = tx.send(Command::SendTo { target, payload }).await;
        })
    }
}

// ── Discovery ──────────────────────────────────────────────────────────────────

/// [`Discovery`] backed by the driver's live peer set + event stream.
pub struct Libp2pDiscovery {
    peers: Arc<Mutex<HashSet<NodeId>>>,
    events: broadcast::Sender<DiscoveryEvent>,
    cmd_tx: mpsc::Sender<Command>,
}

impl Discovery for Libp2pDiscovery {
    fn known_peers(&self) -> Vec<NodeId> {
        self.peers.lock().iter().copied().collect()
    }

    fn add_bootstrap(&self, addr: SocketAddr) {
        // Non-blocking; drop if the driver's command queue is full/closed.
        let _ = self
            .cmd_tx
            .try_send(Command::Dial(socketaddr_to_multiaddr(addr)));
    }

    fn subscribe(&self) -> broadcast::Receiver<DiscoveryEvent> {
        self.events.subscribe()
    }
}

// ── Driver ───────────────────────────────────────────────────────────────────

struct Driver {
    swarm: Swarm<Behaviour>,
    cmd_rx: mpsc::Receiver<Command>,
    event_tx: mpsc::Sender<ProtocolEvent>,
    disco_tx: broadcast::Sender<DiscoveryEvent>,
    peers: Arc<Mutex<HashSet<NodeId>>>,
    topic: TopicHash,
    shutdown_rx: oneshot::Receiver<()>,
}

impl Driver {
    async fn run(mut self) {
        loop {
            tokio::select! {
                _ = &mut self.shutdown_rx => break,
                cmd = self.cmd_rx.recv() => match cmd {
                    Some(Command::Broadcast(payload)) => {
                        if let Err(e) = self
                            .swarm
                            .behaviour_mut()
                            .gossipsub
                            .publish(self.topic.clone(), payload.to_vec())
                        {
                            // `InsufficientPeers` is expected before the mesh
                            // forms; nothing actionable, just trace it.
                            debug!(target: TRACE, error = %e, "gossipsub publish failed");
                        }
                    }
                    Some(Command::SendTo { target, payload }) => match peer_id_for(&target) {
                        Ok(peer) => {
                            // Direct stream to `target` (dials if an address is
                            // known, else fails — consensus retries another peer).
                            self.swarm
                                .behaviour_mut()
                                .block_sync
                                .send_request(&peer, payload.to_vec());
                        }
                        Err(e) => debug!(target: TRACE, error = %e, "send_to: bad target NodeId"),
                    },
                    Some(Command::Dial(addr)) => {
                        let _ = self.swarm.dial(addr);
                    }
                    None => break,
                },
                ev = self.swarm.select_next_some() => self.on_swarm_event(ev).await,
            }
        }
    }

    async fn on_swarm_event(&mut self, ev: SwarmEvent<BehaviourEvent>) {
        match ev {
            SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                message,
                ..
            })) => {
                // Strict validation guarantees `source` is present and
                // signature-verified; skip anything not attributable to a
                // boule (Ed25519) node.
                let Some(src) = message.source else { return };
                let Some(from) = node_id_for(&src) else {
                    return;
                };
                let _ = self
                    .event_tx
                    .send(ProtocolEvent::Message {
                        from,
                        payload: Bytes::from(message.data),
                    })
                    .await;
            }
            SwarmEvent::Behaviour(BehaviourEvent::BlockSync(
                request_response::Event::Message { peer, message, .. },
            )) => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    // `peer` is the direct sender (point-to-point, no relay).
                    if let Some(from) = node_id_for(&peer) {
                        let _ = self
                            .event_tx
                            .send(ProtocolEvent::Message {
                                from,
                                payload: Bytes::from(request),
                            })
                            .await;
                    }
                    // Ack so request-response considers the exchange complete;
                    // the real reply (e.g. a BlockResponse) comes back as its
                    // own `send_to`. Failure just means the peer went away.
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .block_sync
                        .send_response(channel, ());
                }
                request_response::Message::Response { .. } => {} // ack — ignored
            },
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => self.on_connected(peer_id, &endpoint).await,
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established: 0,
                ..
            } => self.on_disconnected(peer_id).await,
            _ => {}
        }
    }

    async fn on_connected(&mut self, peer_id: PeerId, endpoint: &ConnectedPoint) {
        let Some(node_id) = node_id_for(&peer_id) else {
            return;
        };
        // First connection to this peer only (a peer may open several).
        if !self.peers.lock().insert(node_id) {
            return;
        }
        // Add to the gossipsub mesh explicitly — important at validator-set
        // scale where the random mesh might not otherwise include a direct
        // peer.
        self.swarm
            .behaviour_mut()
            .gossipsub
            .add_explicit_peer(&peer_id);
        let addr =
            endpoint_socketaddr(endpoint).unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        let _ = self
            .event_tx
            .send(ProtocolEvent::PeerConnected { node_id, addr })
            .await;
        let _ = self.disco_tx.send(DiscoveryEvent::PeerAdded(node_id));
    }

    async fn on_disconnected(&mut self, peer_id: PeerId) {
        let Some(node_id) = node_id_for(&peer_id) else {
            return;
        };
        if !self.peers.lock().remove(&node_id) {
            return;
        }
        self.swarm
            .behaviour_mut()
            .gossipsub
            .remove_explicit_peer(&peer_id);
        let _ = self
            .event_tx
            .send(ProtocolEvent::PeerDisconnected { node_id })
            .await;
        let _ = self.disco_tx.send(DiscoveryEvent::PeerRemoved(node_id));
    }
}

// ── address helpers ────────────────────────────────────────────────────────────

fn socketaddr_to_multiaddr(addr: SocketAddr) -> Multiaddr {
    let ip = match addr.ip() {
        IpAddr::V4(a) => Protocol::Ip4(a),
        IpAddr::V6(a) => Protocol::Ip6(a),
    };
    Multiaddr::empty().with(ip).with(Protocol::Tcp(addr.port()))
}

fn multiaddr_to_socketaddr(ma: &Multiaddr) -> Option<SocketAddr> {
    let mut ip = None;
    let mut port = None;
    for p in ma.iter() {
        match p {
            Protocol::Ip4(a) => ip = Some(IpAddr::V4(a)),
            Protocol::Ip6(a) => ip = Some(IpAddr::V6(a)),
            Protocol::Tcp(p) => port = Some(p),
            _ => {}
        }
    }
    Some(SocketAddr::new(ip?, port?))
}

fn endpoint_socketaddr(endpoint: &ConnectedPoint) -> Option<SocketAddr> {
    let ma = match endpoint {
        ConnectedPoint::Dialer { address, .. } => address,
        ConnectedPoint::Listener { send_back_addr, .. } => send_back_addr,
    };
    multiaddr_to_socketaddr(ma)
}
