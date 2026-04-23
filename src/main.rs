use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tracing::{info, warn};

use ambros_p2p::clock::{Clock, TokioClock};
use ambros_p2p::config::{self, IdentityConfig, NodeConfig};
use ambros_p2p::gossip;
use ambros_p2p::p2p::{self, ConnectionProtocol};
use ambros_p2p::p2p::manager::ManagerMsg;
use ambros_p2p::p2p::tls::{TlsIdentity, node_id_to_base58};
use ambros_p2p::p2p::tls_protocol::TlsConnectionProtocol;
use ambros_p2p::ping;

const ENV_PRODUCTION: &str = "AMBROS_ENV";
const DEFAULT_KEY_FILE: &str = "node.key";

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ambros_p2p=info".into()),
        )
        .init();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(first) = args.first() {
        if first == "key" {
            return handle_key_subcommand(&args[1..]);
        }
        if first == "--help" || first == "-h" {
            print_help();
            return Ok(());
        }
    }

    let cli = CliArgs::parse(&args)?;
    run_node(cli).await
}

fn print_help() {
    println!("Usage: ambros-p2p [--config <path>] [--production] [--allow-insecure-key-perms]");
    println!("       ambros-p2p key migrate --to <backend> [backend flags]");
    println!();
    println!("Options:");
    println!("  -c, --config <path>          Path to TOML config file [default: config.toml]");
    println!(
        "      --production             Fail closed if no identity backend is explicitly configured"
    );
    println!("      --allow-insecure-key-perms");
    println!(
        "                               Skip the 0o077 permission check on the node key file (dev only)"
    );
    println!();
    println!("Subcommands:");
    println!("  key migrate --to file             --path <path>");
    println!("  key migrate --to encrypted-file   --path <path> [--passphrase-env <var>]");
    println!("  key migrate --to keyring          [--service <name>] [--account <name>]");
    println!("     (reads the current [node.identity] from --config; use --delete-source to");
    println!("      zeroize and remove a file-backed source after a successful migration)");
}

#[derive(Debug)]
struct CliArgs {
    config_path: PathBuf,
    production: bool,
    allow_insecure_perms: bool,
}

impl CliArgs {
    fn parse(args: &[String]) -> anyhow::Result<Self> {
        let mut config_path = PathBuf::from("config.toml");
        let mut production = false;
        let mut allow_insecure_perms = false;
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--config" | "-c" => {
                    i += 1;
                    let p = args
                        .get(i)
                        .ok_or_else(|| anyhow::anyhow!("--config requires a path argument"))?;
                    config_path = PathBuf::from(p);
                }
                "--production" => production = true,
                "--allow-insecure-key-perms" => allow_insecure_perms = true,
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                other => {
                    anyhow::bail!("unknown argument '{other}'; run with --help");
                }
            }
            i += 1;
        }
        Ok(Self {
            config_path,
            production,
            allow_insecure_perms,
        })
    }
}

fn is_production(cli_flag: bool) -> bool {
    if cli_flag {
        return true;
    }
    std::env::var(ENV_PRODUCTION)
        .map(|v| v.eq_ignore_ascii_case("production"))
        .unwrap_or(false)
}

/// Pick the identity config, applying CLI overrides and fail-closed prod semantics.
fn resolve_and_validate_identity(
    node: &NodeConfig,
    production: bool,
    allow_insecure_perms: bool,
) -> anyhow::Result<IdentityConfig> {
    match config::resolve_identity(node) {
        Some(mut cfg) => {
            // Propagate the CLI flag into the file backend variant.
            if let IdentityConfig::File {
                allow_insecure_perms: ref mut a,
                ..
            } = cfg
            {
                if allow_insecure_perms {
                    *a = true;
                }
            }
            Ok(cfg)
        }
        None => {
            if production {
                anyhow::bail!(
                    "refusing to start in production without an explicit [node.identity] backend. \
                     Configure one of: file, env, keyring, encrypted-file, exec. See --help."
                );
            }
            Ok(IdentityConfig::File {
                path: PathBuf::from(DEFAULT_KEY_FILE),
                allow_insecure_perms,
            })
        }
    }
}

async fn run_node(cli: CliArgs) -> anyhow::Result<()> {
    let config = config::load(&cli.config_path)?;
    info!("loaded config from {}", cli.config_path.display());

    let production = is_production(cli.production);
    let identity_cfg =
        resolve_and_validate_identity(&config.node, production, cli.allow_insecure_perms)?;
    info!("identity backend: {}", identity_cfg.backend_name());

    let provider = config::build_provider(&identity_cfg)?;
    let node_identity = provider.load_or_init()?;
    let identity = Arc::new(TlsIdentity::from_identity(&node_identity)?);
    // Drop the raw key material from this scope; TlsIdentity now owns what it needs.
    drop(node_identity);

    info!("node ID: {}", node_id_to_base58(&identity.node_id));

    let clock: Arc<dyn Clock> = Arc::new(TokioClock::new());
    let store = Arc::new(gossip::store::GossipStore::new());

    let (p2p_cmd_tx, p2p_cmd_rx) = mpsc::channel::<p2p::PeerCommand>(256);
    let (internal_tx, internal_rx) = mpsc::channel::<ManagerMsg>(256);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (peer_gone_tx, _) = broadcast::channel::<p2p::NodeId>(64);

    let manager_handle = {
        let itx = internal_tx.clone();
        let pgt = peer_gone_tx.clone();
        let our_id = identity.node_id;
        tokio::spawn(p2p::manager::run(our_id, p2p_cmd_rx, internal_rx, itx, pgt))
    };

    // Register the gossip protocol before spawning TlsConnectionProtocol so
    // PeerConnected events are never missed.
    let (reg_tx, reg_rx) = oneshot::channel();
    p2p_cmd_tx
        .send(p2p::PeerCommand::RegisterProtocol {
            id: gossip::PROTOCOL_ID,
            reply: reg_tx,
        })
        .await?;
    let gossip_handle = reg_rx.await?;
    let gossip_send_tx = gossip_handle.send_tx.clone();

    let engine_handle = {
        let store = Arc::clone(&store);
        let clock = Arc::clone(&clock);
        tokio::spawn(gossip::engine::run(gossip_handle, store, clock))
    };

    // Register the ping RPC protocol on its own ID and build an Rpc client
    // with the echo handler registered for incoming calls.
    let (ping_reg_tx, ping_reg_rx) = oneshot::channel();
    p2p_cmd_tx
        .send(p2p::PeerCommand::RegisterProtocol {
            id: ping::PROTOCOL_ID,
            reply: ping_reg_tx,
        })
        .await?;
    let ping_handle = ping_reg_rx.await?;
    let ping_rpc = p2p::rpc::RpcBuilder::new()
        .handler(ping::METHOD_PING, ping::echo)
        .spawn(ping_handle, Arc::clone(&clock));

    let cleanup_handle = {
        let store = Arc::clone(&store);
        let interval = config.api.cleanup_interval_secs;
        let srx = shutdown_rx.clone();
        let clock = Arc::clone(&clock);
        tokio::spawn(gossip::cleanup::run(store, interval, srx, clock))
    };

    // Bind the API listener here so we know the actual port before writing addr_file.
    let api_listener = TcpListener::bind(config.api.listen_addr).await?;
    let api_actual_addr = api_listener.local_addr()?;
    let api_handle = {
        let app = axum::Router::new()
            .merge(p2p::api::router(p2p_cmd_tx.clone()))
            .merge(gossip::api::router(
                Arc::clone(&store),
                gossip_send_tx,
                Arc::clone(&clock),
            ))
            .merge(ping::router(ping_rpc));
        tokio::spawn(async move {
            info!("HTTP API listening on {api_actual_addr}");
            axum::serve(api_listener, app).await.unwrap();
        })
    };

    // Bind the P2P listener before spawning the protocol so the actual port is
    // known before we write addr_file.
    let p2p_listener = TcpListener::bind(config.node.listen_addr).await?;
    let p2p_actual_addr = p2p_listener.local_addr()?;
    info!("P2P listening on {p2p_actual_addr}");

    // Write bound addresses + node ID to addr_file if configured.
    // Tests use this to discover actual ports when listen_addr uses port 0.
    if let Some(ref path) = config.node.addr_file {
        let content = serde_json::json!({
            "p2p_addr": p2p_actual_addr.to_string(),
            "api_addr": api_actual_addr.to_string(),
            "node_id": node_id_to_base58(&identity.node_id),
        });
        std::fs::write(path, content.to_string())?;
    }

    let protocol = TlsConnectionProtocol {
        identity: Arc::clone(&identity),
        peers: config.peers.clone(),
        listener: p2p_listener,
        clock: Arc::clone(&clock),
    };
    let protocol_handle = tokio::spawn(protocol.run(internal_tx.clone(), peer_gone_tx.clone()));

    tokio::signal::ctrl_c().await?;
    info!("shutting down...");
    let _ = shutdown_tx.send(true);
    drop(p2p_cmd_tx);

    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        let _ = manager_handle.await;
        let _ = engine_handle.await;
        let _ = cleanup_handle.await;
        let _ = api_handle.await;
        let _ = protocol_handle.await;
    })
    .await;

    Ok(())
}

// ── `key` subcommand ────────────────────────────────────────────────────────

fn handle_key_subcommand(args: &[String]) -> anyhow::Result<()> {
    let sub = args
        .first()
        .ok_or_else(|| anyhow::anyhow!("missing key subcommand (try: migrate)"))?;
    match sub.as_str() {
        "migrate" => handle_key_migrate(&args[1..]),
        other => anyhow::bail!("unknown `key` subcommand: {other}"),
    }
}

#[derive(Debug, Default)]
struct MigrateArgs {
    config_path: PathBuf,
    to: Option<String>,
    path: Option<PathBuf>,
    passphrase_env: Option<String>,
    service: Option<String>,
    account: Option<String>,
    delete_source: bool,
}

fn parse_migrate_args(args: &[String]) -> anyhow::Result<MigrateArgs> {
    let mut out = MigrateArgs {
        config_path: PathBuf::from("config.toml"),
        ..Default::default()
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" => {
                i += 1;
                out.config_path = args
                    .get(i)
                    .ok_or_else(|| anyhow::anyhow!("--config needs a value"))?
                    .into();
            }
            "--to" => {
                i += 1;
                out.to = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--to needs a value"))?
                        .clone(),
                );
            }
            "--path" => {
                i += 1;
                out.path = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--path needs a value"))?
                        .into(),
                );
            }
            "--passphrase-env" => {
                i += 1;
                out.passphrase_env = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--passphrase-env needs a value"))?
                        .clone(),
                );
            }
            "--service" => {
                i += 1;
                out.service = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--service needs a value"))?
                        .clone(),
                );
            }
            "--account" => {
                i += 1;
                out.account = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--account needs a value"))?
                        .clone(),
                );
            }
            "--delete-source" => out.delete_source = true,
            other => anyhow::bail!("unknown migrate flag: {other}"),
        }
        i += 1;
    }
    Ok(out)
}

fn handle_key_migrate(args: &[String]) -> anyhow::Result<()> {
    let args = parse_migrate_args(args)?;
    let to = args
        .to
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("key migrate requires --to <backend>"))?;

    let config = config::load(&args.config_path)?;
    let source_cfg = config::resolve_identity(&config.node).ok_or_else(|| {
        anyhow::anyhow!(
            "config {} has no [node.identity] or key_file; nothing to migrate from",
            args.config_path.display()
        )
    })?;
    info!("migrating from {} to {}", source_cfg.backend_name(), to);

    let source_provider = config::build_provider(&source_cfg)?;
    let node_identity = source_provider.load_or_init()?;

    let dest_cfg = match to {
        "file" => IdentityConfig::File {
            path: args
                .path
                .clone()
                .ok_or_else(|| anyhow::anyhow!("--to file requires --path"))?,
            allow_insecure_perms: false,
        },
        "encrypted-file" => IdentityConfig::EncryptedFile {
            path: args
                .path
                .clone()
                .ok_or_else(|| anyhow::anyhow!("--to encrypted-file requires --path"))?,
            passphrase_env: args.passphrase_env.clone(),
        },
        "keyring" => IdentityConfig::Keyring {
            service: args
                .service
                .clone()
                .unwrap_or_else(|| "ambros-p2p".to_string()),
            account: args.account.clone(),
        },
        other => anyhow::bail!("unsupported --to backend: {other}"),
    };

    let dest_provider = config::build_provider(&dest_cfg)?;
    dest_provider.provision(&node_identity)?;

    if args.delete_source {
        if let IdentityConfig::File { path, .. } = &source_cfg {
            use std::io::Write as _;
            if path.exists() {
                // Best-effort shred: overwrite with zeros before unlink.
                if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
                    let len = std::fs::metadata(path)
                        .map(|m| m.len() as usize)
                        .unwrap_or(0);
                    let zeros = vec![0u8; len];
                    let _ = f.write_all(&zeros);
                    let _ = f.sync_all();
                }
                std::fs::remove_file(path).ok();
                warn!("deleted source key file at {}", path.display());
            }
        } else {
            warn!("--delete-source is only supported for file source backends; skipping");
        }
    }

    info!("migration complete");
    Ok(())
}
