//! Public eth-facing HTTP services for full nodes (#806): the **testnet
//! faucet** and the **public eth JSON-RPC proxy**.
//!
//! Both are reth/EVM-specific, so this module is gated on the `reth` cargo
//! feature. The reusable, network-free logic — tx building, rate limiting,
//! JSON-RPC method allow-listing — lives in [`boule_reth::faucet`] /
//! [`boule_reth::rpc_proxy`]; this module only wraps it in axum routers and
//! plugs the HTTP edge into the wall clock + client IP.
//!
//! These run as **standalone services** alongside a full node (see the
//! `faucet` and `eth-rpc-proxy` bins), following the public/admin split of
//! #807/#813: they are public-internet-facing, carry their own abuse
//! protection, and never share a listener with the privileged admin surface.
//!
//! # Client IP for rate limiting
//!
//! The limiter keys on the peer socket address from
//! [`axum::extract::ConnectInfo`]. Behind a reverse proxy / load balancer the
//! peer IP is the proxy's, so the operator should either run this as the edge
//! or have the proxy enforce per-client limits too — documented in the bin
//! help. We deliberately do **not** trust `X-Forwarded-For` (trivially spoofed
//! when the service is directly reachable), which would defeat the per-IP cap.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::Json;
use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Router, body::Bytes};
use serde_json::{Value, json};
use tracing::{info, warn};

/// Max accepted body for `POST /faucet`. The request is a single
/// `{ "address": "0x…" }` object — a few dozen bytes — so a small fixed cap
/// rejects oversized bodies at the layer before any buffering (#823).
const FAUCET_MAX_BODY_BYTES: usize = 4 * 1024;

use boule_reth::faucet::{Admission, DripRequest, DripResponse, FaucetState};
use boule_reth::rpc_proxy::{
    PublicRpcState, Rejection, first_denied_method, rejection_to_jsonrpc, validate_payload,
};

// ───────────────────────────── faucet ──────────────────────────────────────

/// Build the faucet router: `POST /faucet { "address": "0x…" }`.
///
/// A [`DefaultBodyLimit`] layer caps the request body up front, so an oversized
/// body is rejected (`413`) before axum buffers it for the `Json` extractor —
/// not after (#823).
pub fn faucet_router(state: Arc<FaucetState>) -> Router {
    Router::new()
        .route("/faucet", post(faucet_handler))
        .layer(DefaultBodyLimit::max(FAUCET_MAX_BODY_BYTES))
        .with_state(state)
}

async fn faucet_handler(
    State(state): State<Arc<FaucetState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<DripRequest>,
) -> Response {
    let ip = peer.ip();
    // Parse + normalize the recipient address.
    let (to, to_norm) = match boule_reth::faucet::parse_address(&req.address) {
        Some(pair) => pair,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid `address` (expected 0x-prefixed 20-byte hex)" })),
            )
                .into_response();
        }
    };

    let now = Instant::now();
    // Admission check under the lock; submit outside it.
    {
        let mut rl = state.limiter.lock();
        rl.gc(now);
        match rl.check(ip, to, now) {
            Admission::Allowed => {}
            Admission::AddressCooldown(retry) => {
                return rate_limited(
                    "address on cooldown (one drip per address per window)",
                    retry.as_secs(),
                );
            }
            Admission::IpRateLimited(retry) => {
                return rate_limited("per-IP request rate exceeded", retry.as_secs());
            }
        }
    }

    match state.service.drip(to).await {
        Ok(tx_hash) => {
            // Only burn the address cooldown once the drip actually submitted.
            state.limiter.lock().record_drip(to, Instant::now());
            info!(target: "boule::faucet", %ip, address = %to, %tx_hash, "faucet drip submitted");
            (
                StatusCode::OK,
                Json(DripResponse {
                    tx_hash,
                    amount_wei: state.service.drip_wei().to_string(),
                    address: to_norm,
                }),
            )
                .into_response()
        }
        Err(e) => {
            warn!(target: "boule::faucet", %ip, address = %to, error = %e, "faucet drip failed");
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": format!("drip failed: {e:#}") })),
            )
                .into_response()
        }
    }
}

fn rate_limited(msg: &str, retry_after_secs: u64) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [("retry-after", retry_after_secs.to_string())],
        Json(json!({ "error": msg, "retry_after_secs": retry_after_secs })),
    )
        .into_response()
}

// ─────────────────────── public eth JSON-RPC proxy ─────────────────────────

/// Build the public eth-RPC proxy router: a single `POST /` that forwards
/// allow-listed JSON-RPC to reth, with batch/body caps + per-IP rate limiting.
///
/// The configured `max_body_bytes` is enforced as a [`DefaultBodyLimit`] layer
/// so an oversized body is rejected (`413`) *before* axum buffers it into the
/// `Bytes` extractor, rather than after (#823). The handler keeps an explicit
/// post-buffer check too, as defense in depth and to emit the JSON-RPC
/// `BodyTooLarge` envelope for bodies that slip under the layer's granularity.
pub fn rpc_proxy_router(state: Arc<PublicRpcState>) -> Router {
    let max_body = state.cfg.max_body_bytes;
    Router::new()
        .route("/", post(rpc_proxy_handler))
        .layer(DefaultBodyLimit::max(max_body))
        .with_state(state)
}

async fn rpc_proxy_handler(
    State(state): State<Arc<PublicRpcState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    body: Bytes,
) -> Response {
    let ip = peer.ip();
    let now = Instant::now();

    // 1. Per-IP rate limit (cheapest first).
    {
        let mut rl = state.limiter.lock();
        rl.gc(now);
        if !rl.admit(ip, now) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(rejection_to_jsonrpc(Rejection::BatchTooLarge, Value::Null)),
            )
                .into_response();
        }
    }

    // 2. Body-size cap.
    if body.len() > state.cfg.max_body_bytes {
        return jsonrpc_error(Rejection::BodyTooLarge, Value::Null);
    }

    // 3. Parse + policy-check (batch size + method allow-list).
    let payload: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return jsonrpc_error(Rejection::Malformed, Value::Null),
    };
    let echo_id = single_request_id(&payload);
    if let Err(rej) = validate_payload(&payload, state.cfg.max_batch) {
        if rej == Rejection::MethodNotAllowed {
            if let Some(m) = first_denied_method(&payload) {
                warn!(target: "boule::ethrpc", %ip, method = %m, "denied non-allow-listed RPC method");
            }
        }
        return jsonrpc_error(rej, echo_id);
    }

    // 4. Forward verbatim to reth's public RPC and relay the response.
    match state.transport.eth_raw(payload).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(e) => {
            warn!(target: "boule::ethrpc", %ip, error = %e, "upstream reth RPC error");
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": echo_id,
                    "error": { "code": -32603, "message": "upstream RPC error" }
                })),
            )
                .into_response()
        }
    }
}

/// JSON-RPC `id` of a single (non-batch) request, for echoing in error
/// envelopes. Batches echo `null`.
fn single_request_id(payload: &Value) -> Value {
    payload.get("id").cloned().unwrap_or(Value::Null)
}

fn jsonrpc_error(rej: Rejection, id: Value) -> Response {
    (StatusCode::OK, Json(rejection_to_jsonrpc(rej, id))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::connect_info::MockConnectInfo;
    use axum::http::Request;
    use boule_reth::faucet::FaucetConfig;
    use boule_reth::rpc_proxy::PublicRpcConfig;
    use tower::ServiceExt;

    /// A fixed client address injected into requests so `ConnectInfo` resolves
    /// without an actual TCP accept.
    fn mock_peer() -> MockConnectInfo<SocketAddr> {
        MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 5555)))
    }

    fn faucet_state() -> Arc<FaucetState> {
        let signer = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .unwrap();
        let mut cfg = FaucetConfig::new("http://127.0.0.1:1".into(), signer);
        cfg.ip_max_per_window = 1;
        FaucetState::new(cfg)
    }

    /// The faucet router rejects a malformed address with 400 before any
    /// network call — so it works without a live reth.
    #[tokio::test]
    async fn faucet_rejects_bad_address() {
        let router = faucet_router(faucet_state()).layer(mock_peer());
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/faucet")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"address":"not-an-address"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    fn rpc_state() -> Arc<PublicRpcState> {
        let mut cfg = PublicRpcConfig::new("http://127.0.0.1:1".into());
        cfg.ip_max_per_window = 100;
        cfg.max_batch = 3;
        PublicRpcState::new(cfg)
    }

    async fn post_rpc(state: Arc<PublicRpcState>, body: &str) -> (StatusCode, Value) {
        let app = rpc_proxy_router(state).layer(mock_peer());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, v)
    }

    /// A denied method is rejected with a JSON-RPC error (no upstream call,
    /// so no live reth needed).
    #[tokio::test]
    async fn rpc_proxy_denies_admin_method() {
        let (status, v) = post_rpc(
            rpc_state(),
            r#"{"jsonrpc":"2.0","id":9,"method":"admin_addPeer","params":[]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["id"], json!(9));
        assert_eq!(v["error"]["code"], json!(-32601));
    }

    /// An oversized batch is rejected before any upstream call.
    #[tokio::test]
    async fn rpc_proxy_rejects_oversized_batch() {
        let item = r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}"#;
        let batch = format!("[{item},{item},{item},{item}]"); // 4 > max_batch=3
        let (_status, v) = post_rpc(rpc_state(), &batch).await;
        assert_eq!(v["error"]["code"], json!(-32600));
    }

    /// Malformed JSON gets a parse-error envelope.
    #[tokio::test]
    async fn rpc_proxy_rejects_malformed_json() {
        let (_status, v) = post_rpc(rpc_state(), "{not json").await;
        assert_eq!(v["error"]["code"], json!(-32700));
    }

    /// #823: an oversized body is rejected by the `DefaultBodyLimit` layer
    /// (HTTP 413) *before* the handler buffers it — the body never reaches the
    /// `Bytes` extractor or the rate limiter.
    #[tokio::test]
    async fn rpc_proxy_rejects_oversized_body_at_layer() {
        let mut cfg = PublicRpcConfig::new("http://127.0.0.1:1".into());
        cfg.max_body_bytes = 64; // tiny cap for the test
        let state = PublicRpcState::new(cfg);
        let app = rpc_proxy_router(state).layer(mock_peer());

        let big = "x".repeat(4096);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header("content-type", "application/json")
                    .body(Body::from(big))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// #823: the faucet router likewise rejects an oversized body at the layer
    /// (413) before the `Json` extractor buffers it.
    #[tokio::test]
    async fn faucet_rejects_oversized_body_at_layer() {
        let app = faucet_router(faucet_state()).layer(mock_peer());
        let big = format!(r#"{{"address":"0x{}"}}"#, "0".repeat(8192));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/faucet")
                    .header("content-type", "application/json")
                    .body(Body::from(big))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}
