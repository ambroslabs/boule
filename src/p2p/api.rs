//! HTTP admin surface for the peer manager.
//!
//! Exposes read-only endpoints that are mounted into the node's main
//! [`axum::Router`] in `main.rs`:
//!
//! ```ignore
//! let app = axum::Router::new()
//!     .merge(p2p::api::router(p2p_cmd_tx.clone()))
//!     .merge(gossip::api::router(store, gossip_send_tx, clock))
//!     .merge(ping::router(ping_rpc));
//! ```
//!
//! Endpoints:
//!
//! - `GET /peers` — list currently connected peers, encoded as base58 node
//!   IDs.

#![warn(missing_docs)]

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use tokio::sync::{mpsc, oneshot};

use super::tls::node_id_to_base58;
use super::{NodeId, PeerCommand};

/// Build the peer-admin router.
///
/// `cmd_tx` is the sender half of the channel the peer manager listens on
/// (see [`manager::run`](super::manager::run)). The router submits
/// [`PeerCommand`]s through this sender to answer requests; the typical
/// wiring lives in `main.rs`:
///
/// ```ignore
/// let (p2p_cmd_tx, p2p_cmd_rx) = mpsc::channel::<p2p::PeerCommand>(256);
/// // … spawn manager with p2p_cmd_rx …
/// let app = axum::Router::new().merge(p2p::api::router(p2p_cmd_tx.clone()));
/// ```
///
/// # Invariants
///
/// - The manager must already be running (or about to run) when the router
///   handles requests. If `cmd_tx` is closed, handlers degrade gracefully
///   — `/peers` returns an empty array rather than an error.
pub fn router(cmd_tx: mpsc::Sender<PeerCommand>) -> Router {
    Router::new()
        .route("/peers", get(list_peers))
        .with_state(cmd_tx)
}

async fn list_peers(State(cmd_tx): State<mpsc::Sender<PeerCommand>>) -> Json<Vec<String>> {
    let (tx, rx) = oneshot::channel::<Vec<NodeId>>();
    let _ = cmd_tx.send(PeerCommand::ListPeers { reply: tx }).await;
    let peers = rx.await.unwrap_or_default();
    Json(peers.iter().map(node_id_to_base58).collect())
}
