mod dev;
mod runtime;
mod transport;

use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use tracing::info;

use boule_cli::cli;
use boule_core::config;

use crate::runtime::{BundleRethConfig, RethPorts, run_bundled};

#[derive(Parser)]
#[command(
    name = "boule",
    version,
    about = "Single-binary boule node: consensus + the custom reth EL in one process, \
             plus the full provisioning/ops CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {

    Node(NodeArgs),

    #[command(flatten)]
    Cli(cli::Command),
}

#[derive(Parser)]
struct NodeArgs {

    #[arg(long)]
    dev: bool,

    #[arg(short = 'c', long = "config")]
    config_path: Option<PathBuf>,

    #[arg(long)]
    production: bool,

    #[arg(long = "allow-insecure-key-perms")]
    allow_insecure_perms: bool,

    #[arg(long = "chain", required_unless_present = "dev")]
    chain: Option<PathBuf>,

    #[arg(long = "datadir")]
    datadir: Option<PathBuf>,

    #[arg(long = "http.port", default_value_t = 8545)]
    http_port: u16,

    #[arg(long = "authrpc.port", default_value_t = 8551)]
    auth_port: u16,

    #[arg(long = "port", default_value_t = 0)]
    p2p_port: u16,

    #[arg(long = "authrpc.ipcpath", default_value = "/tmp/boule_engine_api.ipc")]
    auth_ipc_path: PathBuf,

    #[arg(long = "http.api", default_value = "eth,net,web3,txpool,admin")]
    http_api: String,
}

fn main() -> anyhow::Result<()> {
    boule_cli::init_tracing();

    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building the tokio runtime")?;
    runtime.block_on(async {
        match cli.command {
            Command::Node(args) => handle_node(args).await,
            Command::Cli(cmd) => cli::dispatch_command(cmd).await,
        }
    })
}

async fn handle_node(args: NodeArgs) -> anyhow::Result<()> {
    if args.dev {
        return dev::run_dev(dev::DevArgs {
            datadir: args.datadir,
            http_port: args.http_port,
            auth_port: args.auth_port,
            p2p_port: args.p2p_port,
            http_api: args.http_api,
            fee_recipient: dev::DEV_FEE_RECIPIENT.to_string(),
        })
        .await;
    }

    let chain = args.chain.context("--chain is required without --dev")?;
    let datadir = args
        .datadir
        .context("--datadir is required without --dev")?;

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
            "no node key found via the `{}` backend. Run `boule init --config {}` first \
             (or provision the key out-of-band for read-only backends).",
            identity_cfg.backend_name(),
            config_path.display(),
        )
    })?;

    let validator_identity = if let Some(val_cfg) = config::resolve_validator_identity(&config.node)
    {
        info!("validator identity backend: {}", val_cfg.backend_name());
        let val_provider = config::build_provider(&val_cfg)?;
        let val_id = val_provider.try_load()?.ok_or_else(|| {
            anyhow::anyhow!(
                "no validator key found via the `{}` backend. Run `boule init --config {}` \
                 first.",
                val_cfg.backend_name(),
                config_path.display(),
            )
        })?;
        Some(val_id)
    } else {
        None
    };

    let chain_json = std::fs::read_to_string(&chain)
        .with_context(|| format!("reading chainspec genesis {}", chain.display()))?;

    let reth_cfg = BundleRethConfig {
        chain_json,
        datadir,
        ports: RethPorts {

            http_port: args.http_port,
            auth_port: args.auth_port,
            p2p_port: args.p2p_port,
            auth_ipc_path: args.auth_ipc_path,
            ..RethPorts::default()
        },
        http_api: args.http_api,
    };

    run_bundled(config, network_identity, validator_identity, reth_cfg).await
}

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

fn is_production(cli_flag: bool) -> bool {
    if cli_flag {
        return true;
    }
    std::env::var("BOULE_ENV")
        .map(|v| v.eq_ignore_ascii_case("production"))
        .unwrap_or(false)
}
