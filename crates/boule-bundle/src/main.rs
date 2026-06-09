//! `boule` — the single-binary bundled node (milestone #7, #886).
//!
//! `boule node -c <config> --chain <genesis.json> --datadir <dir>` boots the
//! custom reth EL (`BouleNode`) **in-process** and runs boule consensus against
//! it in the same process — no second process, no HTTP Engine API, no JWT.
//!
//! This binary links the reth SDK (via `boule-reth-node` / `reth-ethereum`); it
//! lives in the reth-side workspace so `boule-cli` (the standalone two-process
//! `boule start` / `init` / `rotation` CLI) stays reth-SDK-free.

mod runtime;
mod transport;

use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::EnvFilter;

use boule_core::config;

use crate::runtime::{BundleRethConfig, RethPorts, run_bundled};

#[derive(Parser)]
#[command(
    name = "boule",
    about = "Single-binary boule node: consensus + the custom reth EL in one process"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Boot reth in-process + consensus in one process (the canonical run command).
    Node(NodeArgs),
}

#[derive(Parser)]
struct NodeArgs {
    /// Config file path (default: platform-specific location).
    #[arg(short = 'c', long = "config")]
    config_path: Option<PathBuf>,
    /// Fail closed on insecure defaults (also set by BOULE_ENV=production).
    #[arg(long)]
    production: bool,
    /// Permit a key file with group/other-readable permissions.
    #[arg(long = "allow-insecure-key-perms")]
    allow_insecure_perms: bool,
    /// Path to the seeded genesis JSON (the `gen-genesis` output / build.rs
    /// `genesis.json` seeded with validator weights). Parsed into reth's
    /// chainspec.
    #[arg(long = "chain")]
    chain: PathBuf,
    /// reth data directory (mdbx + static files).
    #[arg(long = "datadir")]
    datadir: PathBuf,
    /// Public eth `eth_*` HTTP RPC port.
    #[arg(long = "http.port", default_value_t = 8545)]
    http_port: u16,
    /// Authenticated Engine API TCP port (the bundle talks to it over IPC, but
    /// reth still binds this).
    #[arg(long = "authrpc.port", default_value_t = 8551)]
    auth_port: u16,
    /// devp2p listener port (`0` lets the OS pick).
    #[arg(long = "port", default_value_t = 0)]
    p2p_port: u16,
    /// Auth-server IPC endpoint path the in-process engine client connects to.
    #[arg(long = "authrpc.ipcpath", default_value = "/tmp/boule_engine_api.ipc")]
    auth_ipc_path: PathBuf,
    /// Public eth RPC module selection.
    #[arg(long = "http.api", default_value = "eth,net,web3,txpool,admin")]
    http_api: String,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building the tokio runtime")?;
    runtime.block_on(async {
        match cli.command {
            Command::Node(args) => handle_node(args).await,
        }
    })
}

/// `boule node`: mirrors `boule-cli`'s `start::handle` (config load + identity
/// resolution), then launches the bundled reth-in-process runtime.
async fn handle_node(args: NodeArgs) -> anyhow::Result<()> {
    let config_path = crate::resolve_config_path(args.config_path)?;
    let config = config::load(&config_path)?;
    info!("loaded config from {}", config_path.display());

    let production = crate::is_production(args.production);
    let identity_cfg =
        config::resolve_and_validate_identity(&config.node, production, args.allow_insecure_perms)?;
    info!("network identity backend: {}", identity_cfg.backend_name());

    let provider = config::build_provider(&identity_cfg)?;
    let network_identity = provider.try_load()?.ok_or_else(|| {
        anyhow::anyhow!(
            "no node key found via the `{}` backend. Run `boule-cli init --config {}` first \
             (or provision the key out-of-band for read-only backends).",
            identity_cfg.backend_name(),
            config_path.display(),
        )
    })?;

    // Optional separate validator (consensus signing) identity.
    let validator_identity = if let Some(val_cfg) = config::resolve_validator_identity(&config.node)
    {
        info!("validator identity backend: {}", val_cfg.backend_name());
        let val_provider = config::build_provider(&val_cfg)?;
        let val_id = val_provider.try_load()?.ok_or_else(|| {
            anyhow::anyhow!(
                "no validator key found via the `{}` backend. Run `boule-cli init --config {}` \
                 first.",
                val_cfg.backend_name(),
                config_path.display(),
            )
        })?;
        Some(val_id)
    } else {
        None
    };

    // The reth chainspec is read from the genesis file (a path); pass it through
    // verbatim — `EthereumChainSpecParser` accepts a path or JSON string.
    let chain_json = std::fs::read_to_string(&args.chain)
        .with_context(|| format!("reading chainspec genesis {}", args.chain.display()))?;

    let reth_cfg = BundleRethConfig {
        chain_json,
        datadir: args.datadir,
        ports: RethPorts {
            http_port: args.http_port,
            auth_port: args.auth_port,
            p2p_port: args.p2p_port,
            auth_ipc_path: args.auth_ipc_path,
        },
        http_api: args.http_api,
    };

    run_bundled(config, network_identity, validator_identity, reth_cfg).await
}

/// The explicit `--config` value, or the platform-specific default (mirrors
/// `boule-cli`'s shared helper; duplicated to keep `boule-cli` reth-SDK-free).
fn resolve_config_path(explicit: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    boule_core::paths::default_config_path().ok_or_else(|| {
        anyhow::anyhow!(
            "no --config given and the platform default could not be resolved. Pass \
             --config <path> explicitly."
        )
    })
}

/// Fail-closed production semantics: the `--production` flag or `BOULE_ENV=production`.
fn is_production(cli_flag: bool) -> bool {
    if cli_flag {
        return true;
    }
    std::env::var("BOULE_ENV")
        .map(|v| v.eq_ignore_ascii_case("production"))
        .unwrap_or(false)
}
