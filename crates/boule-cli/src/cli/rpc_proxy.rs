//! `boule rpc-proxy` — run the public eth JSON-RPC proxy (#806, folded from the
//! former `eth-rpc-proxy` bin in #890).
//!
//! Sits in front of a reth full node's public `eth_*` RPC and forwards only the
//! allow-listed, read-only-plus-`eth_sendRawTransaction` surface, with batch /
//! body caps and per-IP rate limiting suitable for the open internet. Lets the
//! operator keep reth's own RPC bound to loopback while this is the single
//! public ingress.
//!
//! Flags default to the same values the old bin's env knobs did; each flag also
//! reads its former env var as a fallback so existing deployment tooling keeps
//! working. Reth-only: built into `boule` under the `reth` feature.

use std::net::SocketAddr;

use clap::Args;

use boule_node::eth_public::{RpcProxyOptions, serve_rpc_proxy};

#[derive(Args)]
pub(crate) struct RpcProxyArgs {
    /// Bind address (env: ETH_RPC_PROXY_LISTEN_ADDR).
    #[arg(
        long,
        env = "ETH_RPC_PROXY_LISTEN_ADDR",
        default_value = "0.0.0.0:8547"
    )]
    listen: SocketAddr,
    /// reth public RPC to forward to; keep loopback-only on the host (env:
    /// ETH_RPC_PROXY_BACKEND_URL).
    #[arg(
        long,
        env = "ETH_RPC_PROXY_BACKEND_URL",
        default_value = "http://127.0.0.1:8545"
    )]
    backend_url: String,
    /// Max JSON-RPC batch length (env: ETH_RPC_PROXY_MAX_BATCH).
    #[arg(long, env = "ETH_RPC_PROXY_MAX_BATCH")]
    max_batch: Option<usize>,
    /// Max request body in bytes (env: ETH_RPC_PROXY_MAX_BODY_BYTES).
    #[arg(long, env = "ETH_RPC_PROXY_MAX_BODY_BYTES")]
    max_body_bytes: Option<usize>,
    /// Per-IP window in seconds (env: ETH_RPC_PROXY_IP_WINDOW_SECS).
    #[arg(long, env = "ETH_RPC_PROXY_IP_WINDOW_SECS")]
    ip_window_secs: Option<u64>,
    /// Per-IP request cap within the window (env:
    /// ETH_RPC_PROXY_IP_MAX_PER_WINDOW).
    #[arg(long, env = "ETH_RPC_PROXY_IP_MAX_PER_WINDOW")]
    ip_max_per_window: Option<u32>,
}

pub(crate) async fn handle(args: RpcProxyArgs) -> anyhow::Result<()> {
    serve_rpc_proxy(RpcProxyOptions {
        listen: args.listen,
        eth_url: args.backend_url,
        max_batch: args.max_batch,
        max_body_bytes: args.max_body_bytes,
        ip_window_secs: args.ip_window_secs,
        ip_max_per_window: args.ip_max_per_window,
    })
    .await
}
