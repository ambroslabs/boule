use std::path::{Path, PathBuf};
use std::sync::Arc;

use tracing::{info, warn};

use ambros_p2p::config::{self, Config, IdentityConfig, NodeConfig};
use ambros_p2p::node;
use ambros_p2p::p2p::identity::KeyProvider;
use ambros_p2p::p2p::tls::node_id_to_base58;
use ambros_p2p::paths;

const ENV_PRODUCTION: &str = "AMBROS_ENV";

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
    match dispatch(&args).await {
        Ok(()) => Ok(()),
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::exit(1);
        }
    }
}

async fn dispatch(args: &[String]) -> anyhow::Result<()> {
    let first = match args.first().map(String::as_str) {
        Some(s) => s,
        None => {
            print_usage();
            anyhow::bail!("missing subcommand");
        }
    };
    match first {
        "init" => handle_init(&args[1..]),
        "start" => handle_start(&args[1..]).await,
        "key" => handle_key_subcommand(&args[1..]),
        "--help" | "-h" | "help" => {
            print_usage();
            Ok(())
        }
        other => {
            print_usage();
            anyhow::bail!("unknown subcommand '{other}'");
        }
    }
}

fn print_usage() {
    println!("Usage: ambros-p2p <subcommand> [options]");
    println!();
    println!("Subcommands:");
    println!("  init [--config <path>]");
    println!("      Bootstrap a node: write a starter config if missing,");
    println!("      provision the node key (file/encrypted-file backends),");
    println!("      ensure storage_dir exists, and print the resulting NodeId.");
    println!();
    println!("  start [--config <path>] [--production] [--allow-insecure-key-perms]");
    println!("      Run the node. Refuses to start if no key has been provisioned.");
    println!();
    println!("  key migrate --to <backend> [backend flags]");
    println!("      Migrate the node key between identity backends. Backends:");
    println!("        --to file             --path <path>");
    println!("        --to encrypted-file   --path <path> [--passphrase-env <var>]");
    println!("        --to keyring          [--service <name>] [--account <name>]");
    println!("      Reads the current [node.identity] from --config; pass");
    println!("      --delete-source to zeroize and remove a file-backed source.");
    println!();
    println!("If --config is omitted, the platform-specific default is used:");
    if let Some(p) = paths::default_config_path() {
        println!("  default: {}", p.display());
    } else {
        println!("  default: <unavailable on this host; pass --config explicitly>");
    }
}

// ── Shared CLI parsing ──────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct InitArgs {
    config_path: Option<PathBuf>,
}

fn parse_init_args(args: &[String]) -> anyhow::Result<InitArgs> {
    let mut out = InitArgs::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" => {
                i += 1;
                let p = args
                    .get(i)
                    .ok_or_else(|| anyhow::anyhow!("--config requires a path"))?;
                out.config_path = Some(PathBuf::from(p));
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown init flag: {other}"),
        }
        i += 1;
    }
    Ok(out)
}

#[derive(Debug, Default)]
struct StartArgs {
    config_path: Option<PathBuf>,
    production: bool,
    allow_insecure_perms: bool,
}

fn parse_start_args(args: &[String]) -> anyhow::Result<StartArgs> {
    let mut out = StartArgs::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" => {
                i += 1;
                let p = args
                    .get(i)
                    .ok_or_else(|| anyhow::anyhow!("--config requires a path"))?;
                out.config_path = Some(PathBuf::from(p));
            }
            "--production" => out.production = true,
            "--allow-insecure-key-perms" => out.allow_insecure_perms = true,
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown start flag: {other}"),
        }
        i += 1;
    }
    Ok(out)
}

fn resolve_config_path(explicit: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    paths::default_config_path().ok_or_else(|| {
        anyhow::anyhow!(
            "no --config given and the platform default could not be resolved \
             (HOME / APPDATA unset?). Pass --config <path> explicitly."
        )
    })
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
                     Configure one of: file, env, keyring, encrypted-file, exec."
                );
            }
            // The starter config written by `init` always sets
            // [node.identity], so the only way to land here is an
            // operator-edited config that dropped the table. Default to
            // a file backend in the platform-specific data dir so
            // operators don't end up with `./node.key` polluting cwd.
            let path = paths::default_data_dir()
                .map(|d| d.join("node.key"))
                .unwrap_or_else(|| PathBuf::from("node.key"));
            warn!(
                "no [node.identity] in config; defaulting to file backend at {}",
                path.display()
            );
            Ok(IdentityConfig::File {
                path,
                allow_insecure_perms,
            })
        }
    }
}

// ── `init` subcommand ───────────────────────────────────────────────────────

fn handle_init(args: &[String]) -> anyhow::Result<()> {
    let args = parse_init_args(args)?;
    let config_path = resolve_config_path(args.config_path)?;

    // Step 1: write the starter template if the config doesn't exist.
    if !config_path.exists() {
        write_starter_config(&config_path)?;
        println!("wrote starter config to {}", config_path.display());
    } else {
        println!("config already exists at {}", config_path.display());
    }

    // Step 2: load + validate.
    let config = config::load(&config_path)?;
    info!("loaded config from {}", config_path.display());

    // Step 3: resolve the identity backend. `init` does not need
    // production semantics — operators run it interactively to bootstrap.
    let identity_cfg = resolve_and_validate_identity(&config.node, false, false)?;
    println!("network identity backend: {}", identity_cfg.backend_name());

    // Step 4: provision the network key (or report externally-managed).
    let provider = config::build_provider(&identity_cfg)?;
    provision_or_report(&*provider, identity_cfg.backend_name(), "network")?;

    // Step 4a: cross-validate `[[peers]]` against the local NodeId now
    // that the network key has been loaded. Catches a self-id in the
    // static peers list at `init` time so operators don't ship a config
    // that only fails at `start`.
    if let Some(net_id) = provider.try_load()? {
        let tls = ambros_p2p::p2p::tls::TlsIdentity::from_identity(&net_id)?;
        config.validate(&tls.node_id)?;
    }

    // Step 4b: same flow for `[node.validator_identity]` if configured.
    // When the table is absent, the network key is reused for consensus
    // signing at start time (with a deprecation warning), so `init` has
    // nothing extra to do here.
    if let Some(val_cfg) = config::resolve_validator_identity(&config.node) {
        println!("validator identity backend: {}", val_cfg.backend_name());
        let val_provider = config::build_provider(&val_cfg)?;
        provision_or_report(&*val_provider, val_cfg.backend_name(), "validator")?;
    }

    // Step 5: ensure consensus storage_dir exists. Doing this in init
    // (rather than lazily on first start) lets operators verify the
    // path is writable before going live.
    if let Some(cons) = config.consensus.as_ref() {
        if let Some(dir) = cons.storage_dir.as_ref() {
            std::fs::create_dir_all(dir).map_err(|e| {
                anyhow::anyhow!("creating consensus storage_dir {}: {e}", dir.display())
            })?;
            println!("consensus storage_dir ready at {}", dir.display());
        }
    }

    // Step 6: pre-flight validation of the rest of the config so init
    // is the natural moment to surface typos in peer addresses or
    // validator IDs.
    preflight_validate(&config)?;

    println!(
        "init complete. Run `ambros-p2p start --config {}` to launch.",
        config_path.display()
    );
    Ok(())
}

/// Bootstrap a single key slot: report idempotently if a key already
/// exists, otherwise mint one for backends that can self-provision and
/// print an externally-managed notice for the rest. `slot` distinguishes
/// `network` vs `validator` in the printed messages.
fn provision_or_report(
    provider: &dyn KeyProvider,
    backend_name: &str,
    slot: &str,
) -> anyhow::Result<()> {
    match provider.try_load()? {
        Some(id) => {
            let tls = ambros_p2p::p2p::tls::TlsIdentity::from_identity(&id)?;
            println!(
                "{slot} key already provisioned: NodeId = {}",
                node_id_to_base58(&tls.node_id)
            );
        }
        None => {
            if provider.is_provisioning_capable() {
                let new_id = provider.load_or_init()?;
                let tls = ambros_p2p::p2p::tls::TlsIdentity::from_identity(&new_id)?;
                println!(
                    "provisioned new {slot} key: NodeId = {}",
                    node_id_to_base58(&tls.node_id)
                );
            } else {
                println!(
                    "{slot} key backend `{backend_name}` is externally managed; \
                     provision the key out-of-band, then re-run `init` to print the resulting NodeId."
                );
            }
        }
    }
    Ok(())
}

fn write_starter_config(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                anyhow::anyhow!("creating config directory {}: {e}", parent.display())
            })?;
        }
    }

    let data_dir = paths::default_data_dir().unwrap_or_else(|| PathBuf::from("./ambros-p2p"));
    let key_path = data_dir.join("node.key");
    let storage_dir = data_dir.join("consensus");

    // The starter ships gossip-only so a fresh `init` followed by
    // `start` works out of the box for single-node smoke tests.
    // Uncomment the [consensus] block (and fill in `validators` with
    // the node IDs your `init` prints across the cluster) to turn on
    // HotStuff. See docs/testnet-local.md.
    let template = format!(
        "# ambros-p2p starter config — generated by `ambros-p2p init`.\n\
         # See docs/testnet-local.md for a fuller walkthrough.\n\n\
         [node]\n\
         listen_addr = \"127.0.0.1:7000\"\n\n\
         [node.identity]\n\
         backend = \"file\"\n\
         path    = \"{key_path}\"\n\n\
         [api]\n\
         listen_addr = \"127.0.0.1:8000\"\n\
         cleanup_interval_secs = 60\n\n\
         # [[peers]]\n\
         # addr    = \"127.0.0.1:7001\"\n\
         # node_id = \"<peer NodeId from their `init` output>\"\n\n\
         # [consensus]\n\
         # validators       = [\"<node1-id>\", \"<node2-id>\", \"<node3-id>\", \"<node4-id>\"]\n\
         # storage_dir      = \"{storage_dir}\"\n\
         # timeout_base_ms  = 500\n\
         # timeout_max_ms   = 5000\n",
        key_path = key_path.display(),
        storage_dir = storage_dir.display(),
    );

    std::fs::write(path, template)
        .map_err(|e| anyhow::anyhow!("writing starter config to {}: {e}", path.display()))?;
    Ok(())
}

fn preflight_validate(config: &Config) -> anyhow::Result<()> {
    // Peer addresses are SocketAddr-typed at parse time; nothing more
    // to do there. Validate consensus inputs if present.
    if let Some(cons) = config.consensus.as_ref() {
        if !cons.validators.is_empty() {
            for raw in &cons.validators {
                ambros_p2p::p2p::tls::base58_to_node_id(raw).map_err(|e| {
                    anyhow::anyhow!(
                        "[consensus.validators] entry {raw:?} is not a valid NodeId: {e}"
                    )
                })?;
            }
        }
        if let Some(seed) = cons.genesis_seed_hex.as_ref() {
            if seed.len() != 64 || !seed.chars().all(|c| c.is_ascii_hexdigit()) {
                anyhow::bail!("[consensus].genesis_seed_hex must be 64 hex chars");
            }
        }
    }
    Ok(())
}

// ── `start` subcommand ──────────────────────────────────────────────────────

async fn handle_start(args: &[String]) -> anyhow::Result<()> {
    let args = parse_start_args(args)?;
    let config_path = resolve_config_path(args.config_path)?;

    let config = config::load(&config_path)?;
    info!("loaded config from {}", config_path.display());

    let production = is_production(args.production);
    let identity_cfg =
        resolve_and_validate_identity(&config.node, production, args.allow_insecure_perms)?;
    info!("network identity backend: {}", identity_cfg.backend_name());

    let provider = config::build_provider(&identity_cfg)?;
    let network_identity = provider.try_load()?.ok_or_else(|| {
        anyhow::anyhow!(
            "no node key found via the `{}` backend. Run `ambros-p2p init --config {}` \
             first (or provision the key out-of-band for read-only backends).",
            identity_cfg.backend_name(),
            config_path.display(),
        )
    })?;

    // Optional separate validator (consensus signing) identity. If the
    // table is present, it must already hold a key — `start` never
    // mints one (that's `init`'s job).
    let validator_identity = if let Some(val_cfg) = config::resolve_validator_identity(&config.node)
    {
        info!("validator identity backend: {}", val_cfg.backend_name());
        let val_provider = config::build_provider(&val_cfg)?;
        let val_id = val_provider.try_load()?.ok_or_else(|| {
            anyhow::anyhow!(
                "no validator key found via the `{}` backend. Run `ambros-p2p init --config {}` \
                 first (or provision the key out-of-band for read-only backends).",
                val_cfg.backend_name(),
                config_path.display(),
            )
        })?;
        Some(val_id)
    } else {
        None
    };

    node::run(config, network_identity, validator_identity).await
}

// ── `key` subcommand (existing migrate flow) ────────────────────────────────

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
    config_path: Option<PathBuf>,
    to: Option<String>,
    path: Option<PathBuf>,
    passphrase_env: Option<String>,
    service: Option<String>,
    account: Option<String>,
    delete_source: bool,
}

fn parse_migrate_args(args: &[String]) -> anyhow::Result<MigrateArgs> {
    let mut out = MigrateArgs::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" => {
                i += 1;
                out.config_path = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--config needs a value"))?
                        .into(),
                );
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
    let config_path = resolve_config_path(args.config_path.clone())?;

    let config = config::load(&config_path)?;
    let source_cfg = config::resolve_identity(&config.node).ok_or_else(|| {
        anyhow::anyhow!(
            "config {} has no [node.identity] or key_file; nothing to migrate from",
            config_path.display()
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

    let dest_provider: Arc<dyn KeyProvider> = config::build_provider(&dest_cfg)?;
    dest_provider.provision(&node_identity)?;

    if args.delete_source {
        if let IdentityConfig::File { path, .. } = &source_cfg {
            use std::io::Write as _;
            if path.exists() {
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
