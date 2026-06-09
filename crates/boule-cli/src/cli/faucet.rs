//! `boule faucet` — run the dev/testnet faucet service (#806, folded from the
//! former `faucet` bin in #890).
//!
//! Dispenses a fixed drip of gas tokens to a requested address, signing +
//! submitting an EIP-1559 funding tx through a reth full node's public eth
//! JSON-RPC, with per-address cooldown + per-IP rate limiting. The faucet's
//! funding key (`--private-key`) must be prefunded in genesis (see #804).
//!
//! Flags default to the same values the old bin's env knobs did; each flag also
//! reads its former env var as a fallback so existing deployment tooling keeps
//! working. Reth-only: built into `boule` under the `reth` feature.

use std::net::SocketAddr;

use clap::Args;

use boule_node::eth_public::{FaucetOptions, serve_faucet};

#[derive(Args)]
pub(crate) struct FaucetArgs {
    /// Bind address (env: FAUCET_LISTEN_ADDR).
    #[arg(long, env = "FAUCET_LISTEN_ADDR", default_value = "0.0.0.0:8546")]
    listen: SocketAddr,
    /// reth public RPC to submit through (env: FAUCET_ETH_URL).
    #[arg(long, env = "FAUCET_ETH_URL", default_value = "http://127.0.0.1:8545")]
    eth_url: String,
    /// The faucet's funding key, `0x`-prefixed 32-byte hex (env:
    /// FAUCET_PRIVATE_KEY). Its address MUST be prefunded in genesis (#804).
    #[arg(long, env = "FAUCET_PRIVATE_KEY", hide_env_values = true)]
    private_key: String,
    /// Amount per drip in wei (env: FAUCET_DRIP_WEI).
    #[arg(long, env = "FAUCET_DRIP_WEI")]
    drip_wei: Option<u128>,
    /// Per-address cooldown in seconds (env: FAUCET_ADDRESS_COOLDOWN_SECS).
    #[arg(long, env = "FAUCET_ADDRESS_COOLDOWN_SECS")]
    address_cooldown_secs: Option<u64>,
    /// Per-IP window in seconds (env: FAUCET_IP_WINDOW_SECS).
    #[arg(long, env = "FAUCET_IP_WINDOW_SECS")]
    ip_window_secs: Option<u64>,
    /// Per-IP request cap within the window (env: FAUCET_IP_MAX_PER_WINDOW).
    #[arg(long, env = "FAUCET_IP_MAX_PER_WINDOW")]
    ip_max_per_window: Option<u32>,
    /// EIP-1559 max_fee_per_gas in wei (env: FAUCET_MAX_FEE_PER_GAS).
    #[arg(long, env = "FAUCET_MAX_FEE_PER_GAS")]
    max_fee_per_gas: Option<u128>,
    /// EIP-1559 max_priority_fee_per_gas in wei (env:
    /// FAUCET_MAX_PRIORITY_FEE_PER_GAS).
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
