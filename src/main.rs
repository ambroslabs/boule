use std::path::{Path, PathBuf};
use std::sync::Arc;

use tracing::{info, warn};

use ambros_p2p::cli::{self, OutputFormat};
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
        "config" => handle_config(&args[1..]),
        "snapshot" => handle_snapshot_subcommand(&args[1..]),
        "reconfig" => handle_reconfig_subcommand(&args[1..]),
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
    println!("  snapshot export [--config <path>] [--height <H>] --out <dir>");
    println!("      Dump a snapshot from the consensus storage_dir into a");
    println!("      portable directory layout (manifest.bin + chunk-N.bin).");
    println!("      `--height` selects an exact snapshot; omit for the latest.");
    println!();
    println!("  snapshot import [--config <path>] --in <dir>");
    println!("      Read a directory layout produced by `snapshot export` and");
    println!("      write it back into the local consensus storage_dir's");
    println!("      snapshot store. Verifies chunk hashes against the manifest.");
    println!();
    println!("  reconfig add-validator --pubkey <base58> --addr <socketaddr> --v-eff <view>");
    println!("      Build a tagged ReconfigCommand payload that adds a validator");
    println!("      to the active committee at view `v_eff` and print it as hex");
    println!("      on stdout. Operators inject the resulting bytes into a");
    println!("      cluster member's mempool to propose the reconfig. The");
    println!(
        "      consensus floor is {} validators after applying;",
        ambros_p2p::consensus::reconfig::MIN_VALIDATOR_FLOOR,
    );
    println!(
        "      `v_eff` must be at least `current_view + {}`.",
        ambros_p2p::consensus::reconfig::MIN_V_EFF_DELAY,
    );
    println!();
    println!("  reconfig remove-validator --pubkey <base58> --v-eff <view>");
    println!("      Build a tagged ReconfigCommand payload that removes a");
    println!("      validator at view `v_eff` and print it as hex on stdout.");
    println!("      Same rules as add-validator (floor, v_eff delay).");
    println!();
    println!("  config [--config <path>] [--format human|json|toml] [--raw|--edit|--path]");
    println!("      Print or edit the node's effective configuration. Default");
    println!("      prints the fully-resolved config (file contents + filled-in");
    println!("      defaults). `--format` overrides the per-config default set by");
    println!("      `[ui] output_format`; for `config`, both `human` (the global");
    println!("      default) and `toml` render TOML, while `json` emits JSON");
    println!(
        "      suitable for piping (e.g. `ambros-p2p config --format json | jq '.consensus.timeout_base_ms'`)."
    );
    println!("      `--raw` prints the file as-written. `--edit` opens the file");
    println!("      in $EDITOR / $VISUAL and validates the result. `--path` prints");
    println!("      the resolved config file path and exits.");
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

// ── `config` subcommand ─────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct ConfigArgs {
    config_path: Option<PathBuf>,
    format: Option<OutputFormat>,
    raw: bool,
    edit: bool,
    print_path: bool,
}

fn parse_config_args(args: &[String]) -> anyhow::Result<ConfigArgs> {
    let mut out = ConfigArgs::default();
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
            "--format" | "-f" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| anyhow::anyhow!("--format requires a value"))?;
                out.format = Some(OutputFormat::parse(v)?);
            }
            "--raw" => out.raw = true,
            "--edit" => out.edit = true,
            "--path" => out.print_path = true,
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown config flag: {other}"),
        }
        i += 1;
    }
    Ok(out)
}

fn handle_config(args: &[String]) -> anyhow::Result<()> {
    let args = parse_config_args(args)?;

    // Mode flags are mutually exclusive — pick exactly one of
    // print/raw/edit/path. Default (no mode flag) is "print resolved".
    let mode_count = [args.print_path, args.edit, args.raw]
        .iter()
        .filter(|b| **b)
        .count();
    if mode_count > 1 {
        anyhow::bail!("--path, --edit, and --raw are mutually exclusive");
    }
    if args.format.is_some() && (args.print_path || args.edit || args.raw) {
        anyhow::bail!("--format only applies to the default (resolved-output) mode");
    }

    let config_path = resolve_config_path(args.config_path)?;

    if args.print_path {
        println!("{}", config_path.display());
        return Ok(());
    }

    if args.edit {
        return edit_config(&config_path);
    }

    if args.raw {
        let text = std::fs::read_to_string(&config_path)
            .map_err(|e| anyhow::anyhow!("reading config {}: {e}", config_path.display()))?;
        // Use print! (not println!) so we don't tack on a trailing newline
        // beyond what the file itself contains.
        print!("{text}");
        return Ok(());
    }

    let config = config::load(&config_path)?;
    // The `config` subcommand has no natural human-readable rendering
    // (the underlying data IS the TOML config file), so we fall back
    // to TOML when the resolved format is `human`. The CLI override
    // wins; otherwise [`UiConfig::output_format`] from the loaded
    // config is the default — see issue #149.
    let format =
        cli::resolve_structured_format(args.format, config.ui.output_format, OutputFormat::Toml);
    let rendered = cli::render_structured(&config, format)?;
    print!("{rendered}");
    if !rendered.ends_with('\n') {
        println!();
    }
    Ok(())
}

/// Open the config file in `$EDITOR` (or `$VISUAL`, or a platform
/// default) and validate the saved result. The original file is left
/// untouched on a non-zero editor exit, since most editors honour
/// abort semantics (`vim :cq`, etc.) by exiting non-zero without
/// writing.
fn edit_config(config_path: &Path) -> anyhow::Result<()> {
    if !config_path.exists() {
        anyhow::bail!(
            "no config at {} to edit; run `ambros-p2p init --config {}` first",
            config_path.display(),
            config_path.display(),
        );
    }
    let editor = pick_editor();
    let (program, mut argv) = split_editor_command(&editor);
    argv.push(config_path.as_os_str().to_owned());
    let status = std::process::Command::new(&program)
        .args(&argv)
        .status()
        .map_err(|e| anyhow::anyhow!("spawning editor `{}`: {e}", editor))?;
    if !status.success() {
        anyhow::bail!(
            "editor `{}` exited {}; not validating, config left untouched",
            editor,
            status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "via signal".to_string()),
        );
    }
    // Re-parse the (possibly modified) file so operators learn about
    // typos before they restart the node.
    config::load(config_path).map_err(|e| {
        anyhow::anyhow!(
            "config at {} is no longer valid after edit: {e}",
            config_path.display(),
        )
    })?;
    println!("config validated: {}", config_path.display());
    Ok(())
}

fn pick_editor() -> String {
    if let Ok(v) = std::env::var("EDITOR") {
        if !v.trim().is_empty() {
            return v;
        }
    }
    if let Ok(v) = std::env::var("VISUAL") {
        if !v.trim().is_empty() {
            return v;
        }
    }
    if cfg!(windows) {
        "notepad".to_string()
    } else {
        "nano".to_string()
    }
}

/// Split a command string like `"vim -u NONE"` into `(program, argv)`
/// using whitespace. Quoting / shell metacharacters are not
/// interpreted; operators with exotic editor invocations can wrap
/// their command in a script.
fn split_editor_command(cmd: &str) -> (std::ffi::OsString, Vec<std::ffi::OsString>) {
    let mut parts = cmd.split_whitespace();
    let program = parts.next().unwrap_or("nano").into();
    let argv = parts.map(std::ffi::OsString::from).collect();
    (program, argv)
}

// ── `snapshot` subcommand ───────────────────────────────────────────────────

fn handle_snapshot_subcommand(args: &[String]) -> anyhow::Result<()> {
    let sub = args
        .first()
        .ok_or_else(|| anyhow::anyhow!("missing snapshot subcommand (try: export, import)"))?;
    match sub.as_str() {
        "export" => handle_snapshot_export(&args[1..]),
        "import" => handle_snapshot_import(&args[1..]),
        other => anyhow::bail!("unknown `snapshot` subcommand: {other}"),
    }
}

#[derive(Debug, Default)]
struct SnapshotExportArgs {
    config_path: Option<PathBuf>,
    height: Option<u64>,
    out: Option<PathBuf>,
}

fn parse_snapshot_export_args(args: &[String]) -> anyhow::Result<SnapshotExportArgs> {
    let mut out = SnapshotExportArgs::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" => {
                i += 1;
                out.config_path = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--config requires a path"))?
                        .into(),
                );
            }
            "--height" => {
                i += 1;
                let raw = args
                    .get(i)
                    .ok_or_else(|| anyhow::anyhow!("--height requires a value"))?;
                out.height = Some(
                    raw.parse::<u64>()
                        .map_err(|e| anyhow::anyhow!("invalid --height {raw:?}: {e}"))?,
                );
            }
            "--out" | "-o" => {
                i += 1;
                out.out = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--out requires a path"))?
                        .into(),
                );
            }
            other => anyhow::bail!("unknown snapshot export flag: {other}"),
        }
        i += 1;
    }
    Ok(out)
}

fn handle_snapshot_export(args: &[String]) -> anyhow::Result<()> {
    let args = parse_snapshot_export_args(args)?;
    let out_dir = args
        .out
        .clone()
        .ok_or_else(|| anyhow::anyhow!("snapshot export requires --out <dir>"))?;
    let config_path = resolve_config_path(args.config_path)?;
    let config = config::load(&config_path)?;
    let store = open_snapshot_store_for_cli(&config)?;

    let height = match args.height {
        Some(h) => h,
        None => store.latest_height()?.ok_or_else(|| {
            anyhow::anyhow!("no snapshots found in consensus storage_dir; nothing to export")
        })?,
    };
    let manifest = store.load_manifest(height)?.ok_or_else(|| {
        anyhow::anyhow!(
            "no snapshot at height {height}; available: {:?}",
            store.list_heights().unwrap_or_default(),
        )
    })?;

    let mut chunks: Vec<bytes::Bytes> = Vec::with_capacity(manifest.chunk_count as usize);
    for idx in 0..manifest.chunk_count {
        let chunk = store
            .load_chunk(height, idx)?
            .ok_or_else(|| anyhow::anyhow!("snapshot at height {height} is missing chunk {idx}"))?;
        chunks.push(chunk);
    }
    ambros_p2p::replication::snapshot::export_to_directory(&manifest, &chunks, &out_dir)?;
    println!(
        "exported snapshot height={} view={} chunks={} into {}",
        manifest.height,
        manifest.view,
        manifest.chunk_count,
        out_dir.display(),
    );
    Ok(())
}

#[derive(Debug, Default)]
struct SnapshotImportArgs {
    config_path: Option<PathBuf>,
    in_dir: Option<PathBuf>,
}

fn parse_snapshot_import_args(args: &[String]) -> anyhow::Result<SnapshotImportArgs> {
    let mut out = SnapshotImportArgs::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" => {
                i += 1;
                out.config_path = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--config requires a path"))?
                        .into(),
                );
            }
            "--in" | "-i" => {
                i += 1;
                out.in_dir = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--in requires a path"))?
                        .into(),
                );
            }
            other => anyhow::bail!("unknown snapshot import flag: {other}"),
        }
        i += 1;
    }
    Ok(out)
}

fn handle_snapshot_import(args: &[String]) -> anyhow::Result<()> {
    let args = parse_snapshot_import_args(args)?;
    let in_dir = args
        .in_dir
        .clone()
        .ok_or_else(|| anyhow::anyhow!("snapshot import requires --in <dir>"))?;
    let config_path = resolve_config_path(args.config_path)?;
    let config = config::load(&config_path)?;
    let store = open_snapshot_store_for_cli(&config)?;

    let (manifest, chunks) = ambros_p2p::replication::snapshot::import_from_directory(&in_dir)?;
    store.save(&manifest, &chunks)?;
    println!(
        "imported snapshot height={} view={} chunks={} into consensus storage",
        manifest.height, manifest.view, manifest.chunk_count,
    );
    Ok(())
}

// ── `reconfig` subcommand (#251) ───────────────────────────────────────────

fn handle_reconfig_subcommand(args: &[String]) -> anyhow::Result<()> {
    let sub = args.first().ok_or_else(|| {
        anyhow::anyhow!("missing reconfig subcommand (try: add-validator, remove-validator)")
    })?;
    match sub.as_str() {
        "add-validator" => handle_reconfig_add(&args[1..]),
        "remove-validator" => handle_reconfig_remove(&args[1..]),
        other => anyhow::bail!("unknown `reconfig` subcommand: {other}"),
    }
}

#[derive(Debug, Default)]
struct ReconfigArgs {
    pubkey: Option<String>,
    addr: Option<String>,
    v_eff: Option<u64>,
}

fn parse_reconfig_args(args: &[String]) -> anyhow::Result<ReconfigArgs> {
    let mut out = ReconfigArgs::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--pubkey" => {
                i += 1;
                out.pubkey = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--pubkey requires a base58 NodeId"))?
                        .clone(),
                );
            }
            "--addr" => {
                i += 1;
                out.addr = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--addr requires a socket address"))?
                        .clone(),
                );
            }
            "--v-eff" => {
                i += 1;
                let raw = args
                    .get(i)
                    .ok_or_else(|| anyhow::anyhow!("--v-eff requires a view number"))?;
                out.v_eff = Some(
                    raw.parse::<u64>()
                        .map_err(|e| anyhow::anyhow!("invalid --v-eff {raw:?}: {e}"))?,
                );
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown reconfig flag: {other}"),
        }
        i += 1;
    }
    Ok(out)
}

fn handle_reconfig_add(args: &[String]) -> anyhow::Result<()> {
    use ambros_p2p::consensus::reconfig::ReconfigCommand;
    use ambros_p2p::p2p::tls::base58_to_node_id;

    let a = parse_reconfig_args(args)?;
    let pubkey_b58 = a
        .pubkey
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("reconfig add-validator requires --pubkey <base58>"))?;
    let addr_str = a
        .addr
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("reconfig add-validator requires --addr <socketaddr>"))?;
    let v_eff = a
        .v_eff
        .ok_or_else(|| anyhow::anyhow!("reconfig add-validator requires --v-eff <view>"))?;

    let node_id = base58_to_node_id(pubkey_b58)
        .map_err(|e| anyhow::anyhow!("--pubkey {pubkey_b58:?} is not a valid NodeId: {e}"))?;
    let addr: std::net::SocketAddr = addr_str
        .parse()
        .map_err(|e| anyhow::anyhow!("--addr {addr_str:?} is not a valid socket address: {e}"))?;

    let payload = ReconfigCommand::build_add_validator_payload(node_id, addr, v_eff);
    println!("{}", hex::encode(&payload));
    Ok(())
}

fn handle_reconfig_remove(args: &[String]) -> anyhow::Result<()> {
    use ambros_p2p::consensus::reconfig::ReconfigCommand;
    use ambros_p2p::p2p::tls::base58_to_node_id;

    let a = parse_reconfig_args(args)?;
    let pubkey_b58 = a
        .pubkey
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("reconfig remove-validator requires --pubkey <base58>"))?;
    let v_eff = a
        .v_eff
        .ok_or_else(|| anyhow::anyhow!("reconfig remove-validator requires --v-eff <view>"))?;
    if a.addr.is_some() {
        anyhow::bail!("reconfig remove-validator does not take --addr");
    }

    let node_id = base58_to_node_id(pubkey_b58)
        .map_err(|e| anyhow::anyhow!("--pubkey {pubkey_b58:?} is not a valid NodeId: {e}"))?;

    let payload = ReconfigCommand::build_remove_validator_payload(node_id, v_eff);
    println!("{}", hex::encode(&payload));
    Ok(())
}

/// Open the [`crate::replication::SnapshotStore`] backed by the
/// configured consensus `storage_dir`. Errors if `[consensus]` or
/// `storage_dir` is missing — there is no meaningful place to put
/// snapshots otherwise.
fn open_snapshot_store_for_cli(
    config: &Config,
) -> anyhow::Result<ambros_p2p::replication::snapshot::SnapshotStore> {
    let cons_cfg = config
        .consensus
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("snapshot subcommands require [consensus] in the config"))?;
    let dir = cons_cfg.storage_dir.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "snapshot subcommands require [consensus] storage_dir to be set; \
             in-memory storage has nothing to export from / import into"
        )
    })?;
    std::fs::create_dir_all(dir)
        .map_err(|e| anyhow::anyhow!("creating consensus storage_dir {}: {e}", dir.display()))?;
    let storage: Arc<dyn ambros_p2p::storage::Storage> =
        Arc::new(ambros_p2p::storage::DiskStorage::open(dir.join("kv.redb"))?);
    Ok(ambros_p2p::replication::snapshot::SnapshotStore::new(
        storage,
    ))
}
