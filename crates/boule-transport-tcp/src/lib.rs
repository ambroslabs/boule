//! Peer-to-peer transport and protocol multiplexing.
//!
//! The `p2p` module owns everything below the application layer: the TLS
//! transport, node identity, the per-connection framing tasks, and the
//! **peer manager** that multiplexes multiple application protocols over one
//! physical link to each peer.
//!
//! # Mental model
//!
//! A *protocol* is an application-level channel (gossip, ping, consensus, …)
//! identified by a single-byte [`u8`] protocol ID on the wire. Each peer
//! connection carries frames from many protocols interleaved; the manager
//! demultiplexes by protocol ID on ingress and merges on egress.
//!
//! Concretely:
//!
//! - [`ConnectionProtocol`] is the transport driver (e.g. the TLS listener /
//!   dialer pair in [`tls_protocol::TlsConnectionProtocol`]). It hands
//!   authenticated streams up to the manager and reports `PeerGone`.
//! - [`manager::run`] owns the peer table and the protocol table. Submit a
//!   [`PeerCommand::RegisterProtocol`] and you get back a [`ProtocolHandle`]
//!   — a pair of channels for sending [`ProtocolOutbound`] messages and
//!   receiving [`ProtocolEvent`]s.
//! - The HTTP admin surface is in [`api`]; the optional matched
//!   request/response RPC layer is in [`rpc`].
//!
//! # Registering a new protocol
//!
//! Send a [`PeerCommand::RegisterProtocol`] over the manager's command
//! channel and wait for the reply oneshot to hand back a
//! [`ProtocolHandle`] you can drive a protocol task from:
//!
//! ```no_run
//! use boule_transport_tcp::{PeerCommand, ProtocolHandle};
//! use tokio::sync::{mpsc, oneshot};
//!
//! # async fn wiring(p2p_cmd_tx: mpsc::Sender<PeerCommand>) -> anyhow::Result<()> {
//! const MY_PROTOCOL_ID: u8 = 0x10;
//! let (reg_tx, reg_rx) = oneshot::channel();
//! p2p_cmd_tx
//!     .send(PeerCommand::RegisterProtocol {
//!         id: MY_PROTOCOL_ID,
//!         max_frame_bytes: Some(64 * 1024),
//!         reply: reg_tx,
//!     })
//!     .await?;
//! let _handle: ProtocolHandle = reg_rx.await?;
//!
//! // Spawn the protocol task with its handle; it owns `send_tx` / `event_rx`.
//! # Ok(())
//! # }
//! ```
//!
//! For matched request/response semantics, layer [`rpc::Rpc`] on top of a
//! raw handle — see [`rpc::RpcBuilder`] for the constructor.

#![warn(missing_docs)]

/// HTTP admin API for peer inspection (`GET /peers`, …).
pub mod api;
/// Per-connection framing task: reads length-delimited frames and forwards
/// them to the manager, writes outbound frames from a per-peer mpsc.
#[allow(missing_docs)]
pub mod connection;
/// Outbound dialer task. Retries with backoff and respects `peer_gone` so a
/// reconnect never races an in-flight connection.
#[allow(missing_docs)]
pub mod dialer;
/// Per-peer rate limiting and global connection caps (issue #134).
/// Inbound TLS listener task. Accepts mutually authenticated connections and
/// hands them to the manager.
#[allow(missing_docs)]
pub mod listener;
/// Peer manager: owns the peer table, the protocol table, and the
/// demultiplexer that routes framed messages to the right [`ProtocolHandle`].
#[allow(missing_docs)]
pub mod manager;
/// Object-safe traits ([`overlay::Broadcaster`] / [`overlay::Discovery`])
/// that abstract the full-mesh peer model so the consensus layer treats
/// the underlying topology as a black box. See the module docs for the
/// delivery contract.
pub mod overlay;
/// Matched request/response RPC built on top of [`ProtocolHandle`]. Opt-in
/// per protocol ID; see [`rpc`] for the frame layout and cancellation model.
pub mod rpc;
/// TLS identity primitives: loading certificates from a node identity,
/// node-ID encoding helpers.
#[allow(missing_docs)]
pub mod tls;
/// [`ConnectionProtocol`] implementation that uses mutually authenticated
/// TLS as the transport. Production builds use this; the sim uses an
/// in-memory alternative.
#[allow(missing_docs)]
pub mod tls_protocol;

use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use bytes::Bytes;
use tokio::sync::{broadcast, mpsc, oneshot};

pub use tls::NodeId;

/// A pluggable transport driver.
///
/// A `ConnectionProtocol` owns the underlying sockets and the dial/accept
/// logic. When it establishes an authenticated stream to a peer it hands the
/// stream up to the manager as a
/// [`ManagerMsg::NewConnection`](manager::ManagerMsg::NewConnection); when a
/// peer is lost it sends a [`ManagerMsg::PeerGone`](manager::ManagerMsg::PeerGone)
/// and also broadcasts on `peer_gone_tx` so background tasks (e.g. the
/// outbound dialer) can react without polling.
///
/// The trait is object-unfriendly on purpose: [`run`](Self::run) returns
/// `impl Future` so each implementation can keep its own future type without
/// boxing. Call it exactly once per instance — `run` consumes `self`.
///
/// # Implementations
///
/// - [`tls_protocol::TlsConnectionProtocol`] for production TLS.
/// - The simulator harness (`src/sim/`) provides an in-memory variant used
///   by integration tests.
///
/// # Example
///
/// Wiring the TLS protocol as `main.rs` does (every field in
/// `TlsConnectionProtocol` is the one the binary feeds in):
///
/// ```no_run
/// use std::sync::Arc;
///
/// use boule_core::clock::{Clock, TokioClock};
/// use boule_transport_tcp::{ConnectionProtocol, NodeId};
/// use boule_transport_tcp::manager::ManagerMsg;
/// use boule_transport_tcp::tls::TlsIdentity;
/// use boule_transport_tcp::tls_protocol::TlsConnectionProtocol;
/// use tokio::net::TcpListener;
/// use tokio::sync::{broadcast, mpsc};
///
/// # async fn wiring(
/// #     identity: Arc<TlsIdentity>,
/// #     listener: TcpListener,
/// #     internal_tx: mpsc::Sender<ManagerMsg>,
/// #     peer_gone_tx: broadcast::Sender<NodeId>,
/// # ) {
/// let clock: Arc<dyn Clock> = Arc::new(TokioClock::new());
/// let protocol = TlsConnectionProtocol {
///     identity,
///     peers: Vec::new(),
///     // `Some(listener)` for normal nodes; `None` skips the inbound
///     // listener task (issue #138's `[p2p] inbound_disabled = true`).
///     listener: Some(listener),
///     // `None` opts out of the pre-admission handshake bound + timeout
///     // (#805); production wiring passes
///     // `Some(Arc::new(HandshakeLimiter::new(..)))`.
///     handshake_limiter: None,
///     clock,
///     peer_cmd_tx: None,
/// };
/// tokio::spawn(protocol.run(internal_tx, peer_gone_tx));
/// # }
/// ```
pub trait ConnectionProtocol: Send + 'static {
    /// Drive the transport forever. Sends
    /// [`ManagerMsg`](manager::ManagerMsg) for every new/dropped connection
    /// and broadcasts on `peer_gone_tx` when a peer disconnects.
    fn run(
        self,
        manager_tx: mpsc::Sender<manager::ManagerMsg>,
        peer_gone_tx: broadcast::Sender<NodeId>,
    ) -> impl std::future::Future<Output = ()> + Send;
}

/// Commands submitted to the peer manager from outside tasks (admin HTTP
/// handlers, the main binary's wiring code, tests, …).
///
/// Each variant carries a `reply` `oneshot::Sender` where the manager
/// returns the result. Dropping the receiver without awaiting the reply is
/// safe — the manager sends best-effort and continues.
#[derive(Debug)]
#[allow(dead_code)]
pub enum PeerCommand {
    /// Register a new application protocol on ID `id` and return the
    /// [`ProtocolHandle`] the caller should use to send/receive.
    ///
    /// Register **before** the transport starts accepting connections so no
    /// [`ProtocolEvent::PeerConnected`] is missed. See `main.rs` for the
    /// canonical ordering: register gossip/ping, then spawn
    /// [`tls_protocol::TlsConnectionProtocol::run`].
    ///
    /// Registering the same `id` twice overwrites the previous handle;
    /// events from that point forward go to the new receiver. The new
    /// registration's `max_frame_bytes` also replaces the previous cap.
    ///
    /// # Frame-size enforcement
    ///
    /// `max_frame_bytes` bounds the length-delimited frame body (the 1-byte
    /// protocol tag plus the application payload). A peer that sends a
    /// frame exceeding this cap has its connection closed immediately; the
    /// manager emits the usual `PeerGone` event. `None` keeps only the
    /// transport-wide [`connection::DEFAULT_MAX_FRAME_LEN`] ceiling, while
    /// `Some(n)` installs a per-protocol cap enforced against every
    /// connection. Pick a cap tight enough to rule out obvious abuse
    /// (e.g. votes should not fit 1 MB) without rejecting legitimate
    /// traffic.
    RegisterProtocol {
        /// Single-byte protocol identifier. Must be unique across the node.
        id: u8,
        /// Optional per-protocol frame-size cap. `None` falls back to the
        /// global transport cap.
        max_frame_bytes: Option<usize>,
        /// Channel for the manager to return the newly created handle on.
        reply: oneshot::Sender<ProtocolHandle>,
    },
    /// Ask the manager to drop a specific peer's connection. Delivers a
    /// [`ProtocolEvent::PeerDisconnected`] to every registered protocol.
    Disconnect {
        /// Peer whose connection should be torn down.
        node_id: NodeId,
    },
    /// Snapshot the current set of connected peers.
    ListPeers {
        /// Channel for the manager to return the peer list on.
        reply: oneshot::Sender<Vec<NodeId>>,
    },
    /// Query whether a specific peer is currently connected. Useful for
    /// tests and admin endpoints.
    HasPeer {
        /// Peer to check.
        node_id: NodeId,
        /// Channel for the manager to return the answer on.
        reply: oneshot::Sender<bool>,
    },
}

/// Outbound direction of a protocol: one frame the application wants sent
/// to peer(s).
///
/// The manager is responsible for translating `Broadcast` to per-peer sends
/// and for routing `SendTo` to the right connection task.
#[derive(Debug)]
#[allow(dead_code)] // SendTo will be used once multi-protocol routing is needed
pub enum ProtocolOutbound {
    /// Send this payload to every currently connected peer. Used by gossip
    /// for message fan-out.
    Broadcast(Bytes),
    /// Send this payload to a single peer. Used by request/response RPC and
    /// future unicast protocols.
    SendTo {
        /// Target peer.
        node_id: NodeId,
        /// Opaque application-level payload. The manager wraps it with the
        /// protocol ID and length-delimits it on the wire.
        payload: Bytes,
    },
}

/// Inbound direction of a protocol: events from the manager.
///
/// Every registered protocol sees `PeerConnected` / `PeerDisconnected` for
/// every peer (the manager fans these out to all protocol event channels),
/// and `Message` for frames tagged with its own protocol ID.
///
/// The definition lives in `boule-core` (the transport-agnostic seam) so the
/// libp2p backend can produce it too; it is re-exported here unchanged.
pub use boule_core::transport::overlay::ProtocolEvent;

/// The application-facing endpoint for a single protocol ID.
///
/// Obtain one by submitting a [`PeerCommand::RegisterProtocol`] before the
/// transport starts. Move it into the protocol's task (it contains a
/// receiver, so it isn't `Clone`); clone `send_tx` freely if multiple
/// senders are needed.
///
/// # Example
///
/// See `gossip::engine::run` and `ping::echo` in the tree for real usage.
/// The typical shape is:
///
/// ```no_run
/// use boule_transport_tcp::{ProtocolEvent, ProtocolHandle, ProtocolOutbound};
/// use bytes::Bytes;
///
/// # async fn wiring(handle: ProtocolHandle) {
/// let ProtocolHandle { send_tx, mut event_rx, peer_outbound_overflows: _ } = handle;
///
/// while let Some(event) = event_rx.recv().await {
///     match event {
///         ProtocolEvent::PeerConnected { .. } => { /* greet */ }
///         ProtocolEvent::PeerDisconnected { .. } => { /* clean up */ }
///         ProtocolEvent::Message { from: _, payload: _ } => {
///             let reply = Bytes::from_static(b"ack");
///             send_tx
///                 .send(ProtocolOutbound::Broadcast(reply))
///                 .await
///                 .ok();
///         }
///     }
/// }
/// # }
/// ```
#[derive(Debug)]
pub struct ProtocolHandle {
    /// Outbound side: frames queued here are sent on the matching protocol
    /// channel. Backpressure is bounded — `send` will await capacity.
    pub send_tx: mpsc::Sender<ProtocolOutbound>,
    /// Inbound side: every connect / disconnect plus every inbound frame for
    /// this protocol ID arrives here. Dropping the receiver implicitly
    /// unregisters the protocol for future events.
    pub event_rx: mpsc::Receiver<ProtocolEvent>,
    /// Shared with the peer manager. Increments every time the
    /// per-peer outbound `write_tx.try_send` returns `Full` — i.e. the
    /// transport-level back-pressure event the
    /// `boule_consensus::status::BackpressureStatus::peer_outbound_overflow_total`
    /// metric counts. Wired through to consensus so a single counter
    /// covers `SendTo` + `Broadcast` outbound drops on every protocol.
    /// Closed-channel failures are intentionally not counted.
    pub peer_outbound_overflows: Arc<AtomicU64>,
}
