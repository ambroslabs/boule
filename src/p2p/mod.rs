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
//! The canonical example is gossip's registration in `main.rs`:
//!
//! ```ignore
//! let (reg_tx, reg_rx) = tokio::sync::oneshot::channel();
//! p2p_cmd_tx
//!     .send(p2p::PeerCommand::RegisterProtocol {
//!         id: gossip::PROTOCOL_ID,
//!         reply: reg_tx,
//!     })
//!     .await?;
//! let handle: p2p::ProtocolHandle = reg_rx.await?;
//!
//! // Spawn the protocol task with its handle; it owns `send_tx`/`event_rx`.
//! tokio::spawn(gossip::engine::run(handle, store, clock));
//! ```
//!
//! Ping's registration in `src/ping.rs` shows how to layer `rpc::Rpc` on
//! top of a raw handle to get matched request/response semantics.

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
/// Pluggable long-term identity (Ed25519) storage backends.
pub mod identity;
/// Inbound TLS listener task. Accepts mutually authenticated connections and
/// hands them to the manager.
#[allow(missing_docs)]
pub mod listener;
/// Peer manager: owns the peer table, the protocol table, and the
/// demultiplexer that routes framed messages to the right [`ProtocolHandle`].
#[allow(missing_docs)]
pub mod manager;
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
/// Wiring the TLS protocol in `main.rs`:
///
/// ```ignore
/// let protocol = TlsConnectionProtocol { identity, peers, listener, clock };
/// tokio::spawn(protocol.run(internal_tx.clone(), peer_gone_tx.clone()));
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
    /// events from that point forward go to the new receiver.
    RegisterProtocol {
        /// Single-byte protocol identifier. Must be unique across the node.
        id: u8,
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
#[derive(Debug)]
pub enum ProtocolEvent {
    /// A peer just completed the handshake and is addressable. Delivered to
    /// every registered protocol.
    PeerConnected {
        /// The peer that just connected.
        node_id: NodeId,
    },
    /// A peer disconnected (network failure, explicit `Disconnect`, or
    /// peer-side teardown). Delivered to every registered protocol.
    PeerDisconnected {
        /// The peer that just disconnected.
        node_id: NodeId,
    },
    /// A frame tagged with this protocol's ID arrived from `from`.
    Message {
        /// The sender; already authenticated by the transport.
        from: NodeId,
        /// Opaque application payload (protocol ID and length prefix have
        /// been stripped).
        payload: Bytes,
    },
}

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
/// ```ignore
/// let handle: ProtocolHandle = /* from RegisterProtocol */;
/// let ProtocolHandle { send_tx, mut event_rx } = handle;
///
/// while let Some(event) = event_rx.recv().await {
///     match event {
///         ProtocolEvent::PeerConnected { .. } => { /* … */ }
///         ProtocolEvent::PeerDisconnected { .. } => { /* … */ }
///         ProtocolEvent::Message { from, payload } => {
///             // handle inbound frame …
///             send_tx
///                 .send(ProtocolOutbound::Broadcast(reply))
///                 .await
///                 .ok();
///         }
///     }
/// }
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
}
