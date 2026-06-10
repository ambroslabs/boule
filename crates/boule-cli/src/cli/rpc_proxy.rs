use std::net::SocketAddr;

use clap::Args;

use boule_node::eth_public::{RpcProxyOptions, serve_rpc_proxy};

#[derive(Args)]
pub struct RpcProxyArgs {
    #[arg(
        long,
        env = "ETH_RPC_PROXY_LISTEN_ADDR",
        default_value = "0.0.0.0:8547"
    )]
    listen: SocketAddr,

    #[arg(
        long,
        env = "ETH_RPC_PROXY_BACKEND_URL",
        default_value = "http://127.0.0.1:8545"
    )]
    backend_url: String,

    #[arg(long, env = "ETH_RPC_PROXY_MAX_BATCH")]
    max_batch: Option<usize>,

    #[arg(long, env = "ETH_RPC_PROXY_MAX_BODY_BYTES")]
    max_body_bytes: Option<usize>,

    #[arg(long, env = "ETH_RPC_PROXY_IP_WINDOW_SECS")]
    ip_window_secs: Option<u64>,

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
