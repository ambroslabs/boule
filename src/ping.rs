//! Tiny ping RPC used as the integration-test consumer of the RPC layer.
//!
//! Runs on its own protocol ID so it doesn't interfere with gossip. The
//! handler simply echoes the request payload.

use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use bytes::Bytes;
use tokio_util::sync::CancellationToken;

use crate::p2p::NodeId;
use crate::p2p::rpc::{Rpc, RpcError};
use crate::p2p::tls::base58_to_node_id;

pub const PROTOCOL_ID: u8 = 0x02;
pub const METHOD_PING: u16 = 0x0001;

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

/// Handler registered server-side: echo the request body.
///
/// `_cancel` is unused here because echoing is synchronous-ish — there's
/// nothing to abort. Real handlers (block assembly, signature verification,
/// long storage scans) should honor the token; see [`RpcHandler`] for the
/// cancellation contract.
///
/// [`RpcHandler`]: crate::p2p::rpc::RpcHandler
pub async fn echo(_peer: NodeId, body: Bytes, _cancel: CancellationToken) -> Result<Bytes, Bytes> {
    Ok(body)
}

#[derive(serde::Deserialize)]
struct PingRequest {
    payload: String,
}

#[derive(serde::Serialize)]
struct PingResponse {
    payload: String,
}

pub fn router(rpc: Rpc) -> Router {
    Router::new()
        .route("/rpc/ping/{peer}", post(ping_handler))
        .with_state(rpc)
}

async fn ping_handler(
    State(rpc): State<Rpc>,
    Path(peer): Path<String>,
    Json(req): Json<PingRequest>,
) -> impl IntoResponse {
    let node_id = match base58_to_node_id(&peer) {
        Ok(n) => n,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid peer node id").into_response(),
    };

    match rpc
        .call(
            node_id,
            METHOD_PING,
            Bytes::from(req.payload.into_bytes()),
            DEFAULT_TIMEOUT,
        )
        .await
    {
        Ok(body) => {
            let payload = String::from_utf8_lossy(&body).into_owned();
            (StatusCode::OK, Json(PingResponse { payload })).into_response()
        }
        Err(RpcError::Timeout) => (StatusCode::GATEWAY_TIMEOUT, "rpc timeout").into_response(),
        Err(RpcError::PeerGone) => (StatusCode::BAD_GATEWAY, "peer disconnected").into_response(),
        Err(RpcError::Busy) => (StatusCode::TOO_MANY_REQUESTS, "rpc busy").into_response(),
        Err(RpcError::Shutdown) => {
            (StatusCode::SERVICE_UNAVAILABLE, "rpc shutting down").into_response()
        }
        Err(RpcError::Remote(b)) => (StatusCode::BAD_GATEWAY, b.to_vec()).into_response(),
    }
}
