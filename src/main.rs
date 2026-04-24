use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tracing::{info, warn};

use ambros_p2p::clock::{Clock, TokioClock};
use ambros_p2p::config::{self, ConsensusConfig, IdentityConfig, NodeConfig};
use ambros_p2p::consensus::node::{ConsensusNode, NodeConfigForConsensus};
use ambros_p2p::consensus::validator_set::ValidatorSet;
use ambros_p2p::crypto::signed::NodeSigner;
use ambros_p2p::gossip;
use ambros_p2p::p2p::manager::ManagerMsg;
use ambros_p2p::p2p::tls::{NodeId, TlsIdentity, base58_to_node_id, node_id_to_base58};
use ambros_p2p::p2p::tls_protocol::TlsConnectionProtocol;
use ambros_p2p::p2p::{self, ConnectionProtocol};
use ambros_p2p::ping;
use ambros_p2p::replication::block::Block;
use ambros_p2p::replication::impls::{CounterStateMachine, InMemoryMempool};
use ambros_p2p::replication::state_machine::StateMachine;
use ambros_p2p::storage::{DiskStorage, DiskWal, MemoryStorage, MemoryWal, Storage, Wal};

const ENV_PRODUCTION: &str = "AMBROS_ENV";
const DEFAULT_KEY_FILE: &str = "node.key";

/// Initialize the tracing subscriber.
///
/// Honors two environment variables:
///
/// - `RUST_LOG`: standard `tracing-subscriber` env filter. Defaults to
///   `ambros_p2p=info`. Set to `info,ambros_p2p::consensus=debug` to get
///   the structured event-boundary logs the consensus layer emits.
/// - `RUST_LOG_FORMAT`: `pretty` (default) or `json`. JSON emits one
///   structured event per line, which operators can pipe through `jq` to
///   filter across nodes.
fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "ambros_p2p=info".into());

    let json = std::env::var("RUST_LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);

    if json {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
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
    // Build the consensus signer here as well so we can drop the raw
    // key material from this scope; both `TlsIdentity` and `NodeSigner`
    // now hold their own internal copies of the parsed key.
    let consensus_signer = Arc::new(NodeSigner::from_identity(&node_identity)?);
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
            max_frame_bytes: Some(gossip::MAX_FRAME_BYTES),
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
            max_frame_bytes: Some(ping::MAX_FRAME_BYTES),
            reply: ping_reg_tx,
        })
        .await?;
    let ping_handle = ping_reg_rx.await?;
    let ping_rpc = p2p::rpc::RpcBuilder::new()
        .handler(ping::METHOD_PING, ping::echo)
        .spawn(ping_handle, Arc::clone(&clock));

    // Optionally start consensus. The protocol is registered, the
    // ConsensusNode is constructed (with disk storage if configured,
    // otherwise in-memory) and its `run` loop is spawned. A oneshot
    // shutdown sender is kept so we can stop the loop gracefully on
    // ctrl-c.
    let consensus_runtime = if let Some(cons_cfg) = config.consensus.as_ref() {
        Some(start_consensus(cons_cfg, &p2p_cmd_tx, &identity.node_id, &consensus_signer).await?)
    } else {
        info!("consensus: disabled (no [consensus] section in config)");
        None
    };

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
        peer_cmd_tx: Some(p2p_cmd_tx.clone()),
    };
    let protocol_handle = tokio::spawn(protocol.run(internal_tx.clone(), peer_gone_tx.clone()));

    tokio::signal::ctrl_c().await?;
    info!("shutting down...");
    let _ = shutdown_tx.send(true);
    drop(p2p_cmd_tx);

    // Signal the consensus loop to exit before awaiting joins below.
    let consensus_join = consensus_runtime.map(|(handle, sd)| {
        let _ = sd.send(());
        handle
    });

    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        let _ = manager_handle.await;
        let _ = engine_handle.await;
        let _ = cleanup_handle.await;
        let _ = api_handle.await;
        let _ = protocol_handle.await;
        if let Some(h) = consensus_join {
            let _ = h.await;
        }
    })
    .await;

    Ok(())
}

// ── Consensus wiring ────────────────────────────────────────────────────────

/// Start the HotStuff consensus protocol alongside gossip + ping.
///
/// Returns the run-loop join handle and the oneshot shutdown sender; the
/// caller fires the sender on ctrl-c and awaits the handle for graceful
/// exit.
async fn start_consensus(
    cons_cfg: &ConsensusConfig,
    p2p_cmd_tx: &mpsc::Sender<p2p::PeerCommand>,
    self_id: &NodeId,
    signer: &Arc<NodeSigner>,
) -> anyhow::Result<(
    tokio::task::JoinHandle<anyhow::Result<()>>,
    oneshot::Sender<()>,
)> {
    let validator_set = build_validator_set(cons_cfg, self_id)?;
    info!(
        "consensus: validator_set has {} members",
        validator_set.len()
    );

    let genesis = build_genesis(cons_cfg)?;
    info!("consensus: genesis hash = {:?}", genesis.hash());

    let (storage, wal): (Arc<dyn Storage>, Arc<dyn Wal>) = match &cons_cfg.storage_dir {
        Some(dir) => {
            std::fs::create_dir_all(dir).map_err(|e| {
                anyhow::anyhow!("creating consensus storage_dir {}: {e}", dir.display())
            })?;
            let storage = Arc::new(DiskStorage::open(dir.join("kv.redb"))?);
            let wal = Arc::new(DiskWal::open(dir.join("wal.redb"))?);
            info!("consensus: durable storage at {}", dir.display());
            (storage, wal)
        }
        None => {
            warn!("consensus: storage_dir unset — using in-memory storage (no crash recovery)");
            (Arc::new(MemoryStorage::new()), Arc::new(MemoryWal::new()))
        }
    };

    let node_cfg = NodeConfigForConsensus {
        validator_set,
        genesis,
        propose_limit: cons_cfg.propose_limit,
        timeout_base: Duration::from_millis(cons_cfg.timeout_base_ms),
        timeout_max: Duration::from_millis(cons_cfg.timeout_max_ms),
    };

    let state_machine: Arc<Mutex<Box<dyn StateMachine>>> =
        Arc::new(Mutex::new(Box::new(CounterStateMachine::new())));
    let mempool = Arc::new(InMemoryMempool::new(1024));

    // Register the consensus protocol with the multiplexer and obtain the
    // ProtocolHandle that the ConsensusNode reads/writes through.
    let (reg_tx, reg_rx) = oneshot::channel();
    p2p_cmd_tx
        .send(p2p::PeerCommand::RegisterProtocol {
            id: ambros_p2p::consensus::node::PROTOCOL_ID,
            max_frame_bytes: Some(ambros_p2p::consensus::node::MAX_FRAME_BYTES),
            reply: reg_tx,
        })
        .await?;
    let consensus_handle = reg_rx.await?;

    let node = ConsensusNode::recover(*self_id, node_cfg, state_machine, mempool, storage, wal)?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let signer = Arc::clone(signer) as Arc<dyn ambros_p2p::crypto::signed::Signer>;
    let join = tokio::spawn(async move { node.run(consensus_handle, signer, shutdown_rx).await });
    info!("consensus: event loop spawned");
    Ok((join, shutdown_tx))
}

/// Build a [`ValidatorSet`] from base58-encoded NodeIds in the config,
/// validating that this node's own ID is present.
fn build_validator_set(cfg: &ConsensusConfig, self_id: &NodeId) -> anyhow::Result<ValidatorSet> {
    if cfg.validators.is_empty() {
        anyhow::bail!("[consensus.validators] must list at least one node");
    }
    let mut ids: Vec<NodeId> = Vec::with_capacity(cfg.validators.len());
    for raw in &cfg.validators {
        let id = base58_to_node_id(raw)
            .map_err(|e| anyhow::anyhow!("decoding validator NodeId {raw:?}: {e}"))?;
        ids.push(id);
    }
    if !ids.iter().any(|id| id == self_id) {
        anyhow::bail!(
            "[consensus.validators] does not include this node's own ID {}",
            node_id_to_base58(self_id),
        );
    }
    Ok(ValidatorSet::new(ids))
}

/// Build the genesis block from the optional `genesis_seed_hex` config
/// field. Defaults to all-zeros when unset.
fn build_genesis(cfg: &ConsensusConfig) -> anyhow::Result<Block> {
    let mut seed = [0u8; 32];
    if let Some(hex) = &cfg.genesis_seed_hex {
        let bytes = decode_hex32(hex)
            .ok_or_else(|| anyhow::anyhow!("genesis_seed_hex must be 64 hex chars (32 bytes)"))?;
        seed = bytes;
    }
    Ok(Block::genesis(seed))
}

/// Decode 64 hex chars into 32 bytes; returns `None` on any error.
fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_nibble(s.as_bytes()[2 * i])?;
        let lo = hex_nibble(s.as_bytes()[2 * i + 1])?;
        *byte = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
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
