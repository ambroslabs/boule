//! Public eth JSON-RPC proxy (#806).
//!
//! Sits in front of a reth full node's public `eth_*` RPC and forwards only the
//! allow-listed, read-only-plus-`eth_sendRawTransaction` surface, with batch /
//! body caps and per-IP rate limiting suitable for the open internet (see
//! [`boule_reth::rpc_proxy`]). Lets the operator keep reth's own RPC bound to
//! loopback while this is the single public ingress.
//!
//! # Configuration (env)
//!
//! - `ETH_RPC_PROXY_LISTEN_ADDR` — bind address (default `0.0.0.0:8547`).
//! - `ETH_RPC_PROXY_BACKEND_URL` — reth public RPC to forward to
//!   (default `http://127.0.0.1:8545`; keep this loopback-only on the host).
//! - `ETH_RPC_PROXY_MAX_BATCH`   — max JSON-RPC batch length (default 20).
//! - `ETH_RPC_PROXY_MAX_BODY_BYTES` — max request body (default 262144).
//! - `ETH_RPC_PROXY_IP_WINDOW_SECS` — per-IP window (default 1).
//! - `ETH_RPC_PROXY_IP_MAX_PER_WINDOW` — per-IP cap (default 20).
//!
//! Per-IP limits key on the direct peer IP — run as the public edge; behind a
//! reverse proxy, enforce limits there too. `POST /` takes a JSON-RPC request
//! (single or batch).

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use boule_node::eth_public::rpc_proxy_router;
use boule_reth::rpc_proxy::{ALLOWED_METHODS, PublicRpcConfig, PublicRpcState};
use tracing::info;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let listen: SocketAddr = env_or("ETH_RPC_PROXY_LISTEN_ADDR", "0.0.0.0:8547")
        .parse()
        .context("ETH_RPC_PROXY_LISTEN_ADDR")?;
    let backend = env_or("ETH_RPC_PROXY_BACKEND_URL", "http://127.0.0.1:8545");

    let mut cfg = PublicRpcConfig::new(backend.clone());
    if let Ok(v) = std::env::var("ETH_RPC_PROXY_MAX_BATCH") {
        cfg.max_batch = v.parse().context("ETH_RPC_PROXY_MAX_BATCH")?;
    }
    if let Ok(v) = std::env::var("ETH_RPC_PROXY_MAX_BODY_BYTES") {
        cfg.max_body_bytes = v.parse().context("ETH_RPC_PROXY_MAX_BODY_BYTES")?;
    }
    if let Ok(v) = std::env::var("ETH_RPC_PROXY_IP_WINDOW_SECS") {
        cfg.ip_window = Duration::from_secs(v.parse().context("ETH_RPC_PROXY_IP_WINDOW_SECS")?);
    }
    if let Ok(v) = std::env::var("ETH_RPC_PROXY_IP_MAX_PER_WINDOW") {
        cfg.ip_max_per_window = v.parse().context("ETH_RPC_PROXY_IP_MAX_PER_WINDOW")?;
    }

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
