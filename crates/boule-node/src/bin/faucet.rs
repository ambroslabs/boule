//! Testnet faucet service (#806).
//!
//! Dispenses a fixed drip of gas tokens to a requested address, signing +
//! submitting an EIP-1559 funding tx through a reth full node's public eth
//! JSON-RPC. Per-address cooldown + per-IP rate limiting guard against
//! draining / flooding (see [`boule_reth::faucet`]).
//!
//! # Configuration (env)
//!
//! - `FAUCET_LISTEN_ADDR`   — bind address (default `0.0.0.0:8546`).
//! - `FAUCET_ETH_URL`       — reth public RPC to submit through
//!   (default `http://127.0.0.1:8545`).
//! - `FAUCET_PRIVATE_KEY`   — **required**: the faucet's funding key
//!   (`0x`-prefixed 32-byte hex). Its address MUST be prefunded in genesis
//!   (cross-reference #804's `prefund` allocations); the faucet never touches
//!   genesis structure, it only reads this key.
//! - `FAUCET_DRIP_WEI`      — amount per drip (default 1e18 = 1 token).
//! - `FAUCET_ADDRESS_COOLDOWN_SECS` — per-address cooldown (default 86400).
//! - `FAUCET_IP_WINDOW_SECS`        — per-IP window (default 3600).
//! - `FAUCET_IP_MAX_PER_WINDOW`     — per-IP cap (default 5).
//! - `FAUCET_MAX_FEE_PER_GAS` / `FAUCET_MAX_PRIORITY_FEE_PER_GAS` — EIP-1559
//!   fee params in wei (defaults 2 gwei / 1 gwei); raise if the base fee
//!   climbs.
//!
//! Per-IP limits key on the direct peer IP, so run the faucet as the public
//! edge (don't trust `X-Forwarded-For`); behind a proxy, enforce limits there
//! too. `POST /faucet { "address": "0x…" }` → `{ "tx_hash", "amount_wei",
//! "address" }`.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use boule_node::eth_public::faucet_router;
use boule_reth::faucet::{FaucetConfig, FaucetState};
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

    let listen: SocketAddr = env_or("FAUCET_LISTEN_ADDR", "0.0.0.0:8546")
        .parse()
        .context("FAUCET_LISTEN_ADDR")?;
    let eth_url = env_or("FAUCET_ETH_URL", "http://127.0.0.1:8545");
    let pk = std::env::var("FAUCET_PRIVATE_KEY").context(
        "FAUCET_PRIVATE_KEY is required (the faucet's prefunded funding key, 0x-hex); its \
         address must be prefunded in genesis (see #804)",
    )?;
    let signer = pk
        .trim()
        .parse()
        .context("FAUCET_PRIVATE_KEY not a valid private key")?;

    let mut cfg = FaucetConfig::new(eth_url.clone(), signer);
    if let Ok(v) = std::env::var("FAUCET_DRIP_WEI") {
        cfg.drip_wei = v.parse().context("FAUCET_DRIP_WEI")?;
    }
    if let Ok(v) = std::env::var("FAUCET_ADDRESS_COOLDOWN_SECS") {
        cfg.address_cooldown =
            Duration::from_secs(v.parse().context("FAUCET_ADDRESS_COOLDOWN_SECS")?);
    }
    if let Ok(v) = std::env::var("FAUCET_IP_WINDOW_SECS") {
        cfg.ip_window = Duration::from_secs(v.parse().context("FAUCET_IP_WINDOW_SECS")?);
    }
    if let Ok(v) = std::env::var("FAUCET_IP_MAX_PER_WINDOW") {
        cfg.ip_max_per_window = v.parse().context("FAUCET_IP_MAX_PER_WINDOW")?;
    }
    if let Ok(v) = std::env::var("FAUCET_MAX_FEE_PER_GAS") {
        cfg.max_fee_per_gas = v.parse().context("FAUCET_MAX_FEE_PER_GAS")?;
    }
    if let Ok(v) = std::env::var("FAUCET_MAX_PRIORITY_FEE_PER_GAS") {
        cfg.max_priority_fee_per_gas = v.parse().context("FAUCET_MAX_PRIORITY_FEE_PER_GAS")?;
    }

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
