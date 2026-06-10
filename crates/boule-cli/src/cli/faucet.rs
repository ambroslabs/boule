use std::net::SocketAddr;

use clap::Args;

use boule_node::eth_public::{FaucetOptions, serve_faucet};

#[derive(Args)]
pub struct FaucetArgs {
    #[arg(long, env = "FAUCET_LISTEN_ADDR", default_value = "0.0.0.0:8546")]
    listen: SocketAddr,

    #[arg(long, env = "FAUCET_ETH_URL", default_value = "http://127.0.0.1:8545")]
    eth_url: String,

    #[arg(long, env = "FAUCET_PRIVATE_KEY", hide_env_values = true)]
    private_key: String,

    #[arg(long, env = "FAUCET_DRIP_WEI")]
    drip_wei: Option<u128>,

    #[arg(long, env = "FAUCET_ADDRESS_COOLDOWN_SECS")]
    address_cooldown_secs: Option<u64>,

    #[arg(long, env = "FAUCET_IP_WINDOW_SECS")]
    ip_window_secs: Option<u64>,

    #[arg(long, env = "FAUCET_IP_MAX_PER_WINDOW")]
    ip_max_per_window: Option<u32>,

    #[arg(long, env = "FAUCET_MAX_FEE_PER_GAS")]
    max_fee_per_gas: Option<u128>,

    #[arg(long, env = "FAUCET_MAX_PRIORITY_FEE_PER_GAS")]
    max_priority_fee_per_gas: Option<u128>,
}

pub(crate) async fn handle(args: FaucetArgs) -> anyhow::Result<()> {
    serve_faucet(FaucetOptions {
        listen: args.listen,
        eth_url: args.eth_url,
        private_key: args.private_key,
        drip_wei: args.drip_wei,
        address_cooldown_secs: args.address_cooldown_secs,
        ip_window_secs: args.ip_window_secs,
        ip_max_per_window: args.ip_max_per_window,
        max_fee_per_gas: args.max_fee_per_gas,
        max_priority_fee_per_gas: args.max_priority_fee_per_gas,
    })
    .await
}
