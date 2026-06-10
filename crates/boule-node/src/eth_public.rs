use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use axum::Json;
use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Router, body::Bytes};
use serde_json::{Value, json};
use tracing::{info, warn};

use boule_reth::faucet::FaucetConfig;
use boule_reth::rpc_proxy::{ALLOWED_METHODS, PublicRpcConfig};

const FAUCET_MAX_BODY_BYTES: usize = 4 * 1024;

use boule_reth::faucet::{Admission, DripRequest, DripResponse, FaucetState};
use boule_reth::rpc_proxy::{
    PublicRpcState, Rejection, first_denied_method, rejection_to_jsonrpc, validate_payload,
};

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

    if body.len() > state.cfg.max_body_bytes {
        return jsonrpc_error(Rejection::BodyTooLarge, Value::Null);
    }

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

fn single_request_id(payload: &Value) -> Value {
    payload.get("id").cloned().unwrap_or(Value::Null)
}

fn jsonrpc_error(rej: Rejection, id: Value) -> Response {
    (StatusCode::OK, Json(rejection_to_jsonrpc(rej, id))).into_response()
}

#[derive(Debug, Clone)]
pub struct FaucetOptions {
    pub listen: SocketAddr,

    pub eth_url: String,

    pub private_key: String,

    pub drip_wei: Option<u128>,

    pub address_cooldown_secs: Option<u64>,

    pub ip_window_secs: Option<u64>,

    pub ip_max_per_window: Option<u32>,

    pub max_fee_per_gas: Option<u128>,

    pub max_priority_fee_per_gas: Option<u128>,
}

pub async fn serve_faucet(opts: FaucetOptions) -> anyhow::Result<()> {
    let signer = opts
        .private_key
        .trim()
        .parse()
        .context("faucet private key is not a valid 0x-hex private key")?;
    let mut cfg = FaucetConfig::new(opts.eth_url.clone(), signer);
    if let Some(v) = opts.drip_wei {
        cfg.drip_wei = v;
    }
    if let Some(v) = opts.address_cooldown_secs {
        cfg.address_cooldown = std::time::Duration::from_secs(v);
    }
    if let Some(v) = opts.ip_window_secs {
        cfg.ip_window = std::time::Duration::from_secs(v);
    }
    if let Some(v) = opts.ip_max_per_window {
        cfg.ip_max_per_window = v;
    }
    if let Some(v) = opts.max_fee_per_gas {
        cfg.max_fee_per_gas = v;
    }
    if let Some(v) = opts.max_priority_fee_per_gas {
        cfg.max_priority_fee_per_gas = v;
    }

    let listen = opts.listen;
    let eth_url = cfg.eth_url.clone();
    let state = FaucetState::new(cfg);
    info!(
        target: "boule::faucet",
        %listen, %eth_url,
        faucet_address = %format!("0x{}", hex::encode(state.service.faucet_address())),
        drip_wei = state.service.drip_wei(),
        "faucet starting (ensure the faucet address is prefunded in genesis — #804)"
    );

    let app = faucet_router(state).into_make_service_with_connect_info::<SocketAddr>();
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .context("bind faucet listener")?;
    info!(target: "boule::faucet", addr = %listener.local_addr()?, "faucet listening");
    axum::serve(listener, app).await.context("faucet server")?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct RpcProxyOptions {
    pub listen: SocketAddr,

    pub eth_url: String,

    pub max_batch: Option<usize>,

    pub max_body_bytes: Option<usize>,

    pub ip_window_secs: Option<u64>,

    pub ip_max_per_window: Option<u32>,
}

pub async fn serve_rpc_proxy(opts: RpcProxyOptions) -> anyhow::Result<()> {
    let mut cfg = PublicRpcConfig::new(opts.eth_url.clone());
    if let Some(v) = opts.max_batch {
        cfg.max_batch = v;
    }
    if let Some(v) = opts.max_body_bytes {
        cfg.max_body_bytes = v;
    }
    if let Some(v) = opts.ip_window_secs {
        cfg.ip_window = std::time::Duration::from_secs(v);
    }
    if let Some(v) = opts.ip_max_per_window {
        cfg.ip_max_per_window = v;
    }

    let listen = opts.listen;
    let backend = cfg.eth_url.clone();
    info!(
        target: "boule::ethrpc",
        %listen, %backend,
        max_batch = cfg.max_batch,
        max_body_bytes = cfg.max_body_bytes,
        allowed_methods = ALLOWED_METHODS.len(),
        "public eth-RPC proxy starting (forwarding only the allow-listed surface)"
    );
    let state = PublicRpcState::new(cfg);
    let app = rpc_proxy_router(state).into_make_service_with_connect_info::<SocketAddr>();
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .context("bind proxy listener")?;
    info!(target: "boule::ethrpc", addr = %listener.local_addr()?, "eth-rpc-proxy listening");
    axum::serve(listener, app)
        .await
        .context("eth-rpc-proxy server")?;
    Ok(())
}
