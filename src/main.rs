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
        "rotation" => handle_rotation_subcommand(&args[1..]),
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
    println!("                         [--bls-pop-file <path> | --bls-key-file <path>]");
    println!("                         [--config <path>]");
    println!("      Build a tagged ReconfigCommand payload that adds a validator");
    println!("      to the active committee at view `v_eff` and print it as hex");
    println!("      on stdout. Operators inject the resulting bytes into a");
    println!("      cluster member's mempool to propose the reconfig.");
    println!("      On BLS chains pass --bls-pop-file (hex `<pubkey>:<sig>`) or");
    println!("      --bls-key-file (a BlsKeyFile to derive PoP from). When --config");
    println!("      is supplied, the chain's signature_scheme is cross-checked.");
    println!(
        "      The consensus floor is {} validators after applying;",
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
    println!("  rotation propose --new-key-backend <file|encrypted-file>");
    println!("                   --new-key-path <path> [--new-key-passphrase-env <var>]");
    println!("                   [--new-bls-key-backend file --new-bls-key-path <path>]");
    println!("                   --v-eff <view> [--config <path>]");
    println!("      Build a tagged DualSignedRotation payload that rotates the");
    println!("      validator's consensus signing key at view `v_eff` and print");
    println!("      it as hex on stdout. The current signer is read from");
    println!("      `[node.validator_identity]` (or, when absent, the network");
    println!("      identity). The new key is minted under the chosen backend if");
    println!("      the path doesn't already exist. On `bls_aggregated` chains,");
    println!("      the BLS half is also minted (or reloaded) and bundled into the");
    println!("      payload along with a chain-bound proof-of-possession.");
    println!(
        "      `v_eff` must be at least `current_view + {}`.",
        ambros_p2p::consensus::validator_rotation::V_EFF_MIN_DELAY,
    );
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
         listen_addr = \"127.0.0.1:8000\"\n\n\
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
        anyhow::anyhow!(
            "missing reconfig subcommand (try: add-validator, remove-validator, change-weight)"
        )
    })?;
    match sub.as_str() {
        "add-validator" => handle_reconfig_add(&args[1..]),
        "remove-validator" => handle_reconfig_remove(&args[1..]),
        "change-weight" => handle_reconfig_change_weight(&args[1..]),
        other => anyhow::bail!("unknown `reconfig` subcommand: {other}"),
    }
}

#[derive(Debug, Default)]
struct ReconfigArgs {
    pubkey: Option<String>,
    addr: Option<String>,
    v_eff: Option<u64>,
    /// Voting weight for the validator at and after `v_eff` (#462).
    /// Required for `add-validator`; optional and ignored for
    /// `remove-validator`. Required for `change-weight`. Must be `>= 1`.
    weight: Option<u64>,
    /// Path to a hex-encoded `<pubkey_hex>:<pop_hex>` file (48-byte
    /// BLS pubkey + 96-byte PoP signature) for the new validator.
    /// Mutually exclusive with `--bls-key-file`.
    bls_pop_file: Option<PathBuf>,
    /// Path to a `BlsKeyFile` (33-byte format-versioned secret key) on
    /// disk. The CLI derives the pubkey + PoP locally before printing
    /// the payload. Mutually exclusive with `--bls-pop-file`.
    bls_key_file: Option<PathBuf>,
    /// Optional config path; when set the CLI cross-checks the chain's
    /// `signature_scheme` against the BLS-flag presence and refuses to
    /// build a payload that would be rejected at commit time (#334).
    config_path: Option<PathBuf>,
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
            "--weight" => {
                i += 1;
                let raw = args
                    .get(i)
                    .ok_or_else(|| anyhow::anyhow!("--weight requires a u64 weight"))?;
                let w = raw
                    .parse::<u64>()
                    .map_err(|e| anyhow::anyhow!("invalid --weight {raw:?}: {e}"))?;
                if w == 0 {
                    anyhow::bail!(
                        "--weight 0 is reserved; use `remove-validator` to drop a validator."
                    );
                }
                out.weight = Some(w);
            }
            "--bls-pop-file" => {
                i += 1;
                out.bls_pop_file =
                    Some(PathBuf::from(args.get(i).ok_or_else(|| {
                        anyhow::anyhow!("--bls-pop-file requires a path")
                    })?));
            }
            "--bls-key-file" => {
                i += 1;
                out.bls_key_file =
                    Some(PathBuf::from(args.get(i).ok_or_else(|| {
                        anyhow::anyhow!("--bls-key-file requires a path")
                    })?));
            }
            "--config" | "-c" => {
                i += 1;
                out.config_path =
                    Some(PathBuf::from(args.get(i).ok_or_else(|| {
                        anyhow::anyhow!("--config requires a path")
                    })?));
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
    use ambros_p2p::consensus::reconfig::{ReconfigCommand, ValidatorEntry};
    use ambros_p2p::crypto::sig_scheme::{BlsAggregated, SignatureSchemeChoice};
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
    let v_eff = ambros_p2p::consensus::View(
        a.v_eff
            .ok_or_else(|| anyhow::anyhow!("reconfig add-validator requires --v-eff <view>"))?,
    );
    if a.bls_pop_file.is_some() && a.bls_key_file.is_some() {
        anyhow::bail!(
            "--bls-pop-file and --bls-key-file are mutually exclusive — pass one or the other.",
        );
    }

    let node_id = base58_to_node_id(pubkey_b58)
        .map_err(|e| anyhow::anyhow!("--pubkey {pubkey_b58:?} is not a valid NodeId: {e}"))?;
    let addr: std::net::SocketAddr = addr_str
        .parse()
        .map_err(|e| anyhow::anyhow!("--addr {addr_str:?} is not a valid socket address: {e}"))?;

    // BLS PoPs are now bound to the chain_id (#410). To produce or
    // verify one, the CLI needs the chain_id, which means an operator
    // who wants to attach a PoP must point at the chain's config.
    if (a.bls_pop_file.is_some() || a.bls_key_file.is_some()) && a.config_path.is_none() {
        anyhow::bail!(
            "--bls-pop-file / --bls-key-file requires --config so the chain_id can be derived \
             from the genesis. BLS proof-of-possession pre-images bind to chain_id (#410); \
             without --config the CLI cannot mint or verify the PoP.",
        );
    }

    // Resolve the chain_id (when --config is supplied) once, up front
    // — used by the CLI's local PoP verify and threaded into
    // `derive_bls_pop_from_key_file` for fresh-mint workflows.
    let cfg_chain_id: Option<ambros_p2p::crypto::signed::ChainId> =
        if let Some(cfg_path) = &a.config_path {
            let cfg = config::load(cfg_path)?;
            let cons = cfg.consensus.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "--config {} has no [consensus] section — cannot infer scheme or chain_id",
                    cfg_path.display(),
                )
            })?;
            // Scheme cross-check (predates #410): refuse to build a
            // payload that would be rejected at commit time by #334's
            // scheme-driven enforcement.
            match (cons.signature_scheme, &a.bls_pop_file, &a.bls_key_file) {
                (SignatureSchemeChoice::BlsAggregated, None, None) => {
                    anyhow::bail!(
                        "--config declares signature_scheme = \"bls_aggregated\" but no \
                     --bls-pop-file or --bls-key-file was supplied. Every BLS-chain `adds` \
                     entry must carry a proof-of-possession.",
                    );
                }
                (SignatureSchemeChoice::Ed25519Collected, Some(_), _)
                | (SignatureSchemeChoice::Ed25519Collected, _, Some(_)) => {
                    anyhow::bail!(
                        "--config declares signature_scheme = \"ed25519_collected\" but a \
                     --bls-pop-file or --bls-key-file was supplied. Ed25519 chains have no \
                     use for BLS keys; remove the BLS flag.",
                    );
                }
                _ => {}
            }
            Some(ambros_p2p::node::derive_chain_id(cons)?)
        } else {
            None
        };

    // Resolve the BLS proof-of-possession from whichever flag the
    // operator passed (or none, for an Ed25519 chain).
    let bls_pop = if let Some(path) = &a.bls_pop_file {
        Some(read_bls_pop_file(path)?)
    } else if let Some(path) = &a.bls_key_file {
        let chain_id = cfg_chain_id
            .as_ref()
            .expect("--config presence enforced above when --bls-key-file is set");
        Some(derive_bls_pop_from_key_file(path, chain_id)?)
    } else {
        None
    };

    // Local cryptographic check: a malformed PoP would be rejected at
    // commit time anyway, but operators want a fast-fail before they
    // distribute the payload bytes to other operators. Now scoped to
    // the deployment's chain_id (#410).
    if let Some(pop) = &bls_pop {
        let chain_id = cfg_chain_id
            .as_ref()
            .expect("--config presence enforced above when bls_pop is built");
        BlsAggregated::verify_pop(pop, &pop.pubkey, chain_id).map_err(|e| {
            anyhow::anyhow!(
                "BLS PoP failed verification under its embedded pubkey + the chain's chain_id: \
                 {e:?}. Re-mint the PoP for this deployment via --bls-key-file (PoP pre-images \
                 are now chain-bound, #410).",
            )
        })?;
    }

    let weight = a.weight.ok_or_else(|| {
        anyhow::anyhow!(
            "reconfig add-validator requires --weight <u64>; use 1 for an unweighted committee."
        )
    })?;
    let cmd = ReconfigCommand {
        adds: vec![ValidatorEntry {
            node_id,
            addr,
            bls_pop,
            weight,
        }],
        removes: vec![],
        changes: vec![],
        v_eff,
    };
    let payload = cmd.encode();
    println!("{}", hex::encode(&payload));
    Ok(())
}

/// Read a `<pubkey_hex>:<pop_hex>` file (48-byte BLS pubkey + 96-byte
/// PoP signature). Whitespace at either end is ignored.
fn read_bls_pop_file(path: &Path) -> anyhow::Result<ambros_p2p::crypto::sig_scheme::BlsPop> {
    use ambros_p2p::crypto::sig_scheme::BlsPop;
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("reading --bls-pop-file {}: {e}", path.display()))?;
    let trimmed = raw.trim();
    let (pk_hex, sig_hex) = trimmed.split_once(':').ok_or_else(|| {
        anyhow::anyhow!(
            "{} is not in the expected `<pubkey_hex>:<pop_hex>` format",
            path.display(),
        )
    })?;
    let pk_bytes = hex::decode(pk_hex.trim())
        .map_err(|e| anyhow::anyhow!("--bls-pop-file pubkey is not valid hex: {e}"))?;
    let sig_bytes = hex::decode(sig_hex.trim())
        .map_err(|e| anyhow::anyhow!("--bls-pop-file pop signature is not valid hex: {e}"))?;
    if pk_bytes.len() != 48 {
        anyhow::bail!(
            "--bls-pop-file pubkey is {} bytes, expected 48",
            pk_bytes.len(),
        );
    }
    if sig_bytes.len() != 96 {
        anyhow::bail!(
            "--bls-pop-file pop signature is {} bytes, expected 96",
            sig_bytes.len(),
        );
    }
    let mut pubkey = [0u8; 48];
    pubkey.copy_from_slice(&pk_bytes);
    let mut sig = [0u8; 96];
    sig.copy_from_slice(&sig_bytes);
    Ok(BlsPop { pubkey, sig })
}

/// Load a [`BlsKeyFile`] from disk and derive a chain-id-bound PoP
/// (#410) on the fly. The CLI uses this to let an operator generate
/// an add-validator payload from a freshly-provisioned BLS key file
/// in one step. The PoP pre-image binds to `chain_id` so the same key
/// produces a different PoP per deployment, blocking cross-chain
/// replay.
fn derive_bls_pop_from_key_file(
    path: &Path,
    chain_id: &ambros_p2p::crypto::signed::ChainId,
) -> anyhow::Result<ambros_p2p::crypto::sig_scheme::BlsPop> {
    use ambros_p2p::crypto::bls_key::{BlsKeyFile, BlsKeyProvider as _};
    use ambros_p2p::crypto::sig_scheme::BlsAggregated;
    let provider = BlsKeyFile::new(path.to_path_buf());
    let id = provider
        .load_or_init()
        .map_err(|e| anyhow::anyhow!("loading BLS key from {}: {e}", path.display()))?;
    BlsAggregated::sign_pop(&id.secret, chain_id)
        .map_err(|e| anyhow::anyhow!("signing BLS PoP for {}: {e:?}", path.display()))
}

fn handle_reconfig_remove(args: &[String]) -> anyhow::Result<()> {
    use ambros_p2p::consensus::reconfig::ReconfigCommand;
    use ambros_p2p::p2p::tls::base58_to_node_id;

    let a = parse_reconfig_args(args)?;
    let pubkey_b58 = a
        .pubkey
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("reconfig remove-validator requires --pubkey <base58>"))?;
    let v_eff = ambros_p2p::consensus::View(
        a.v_eff
            .ok_or_else(|| anyhow::anyhow!("reconfig remove-validator requires --v-eff <view>"))?,
    );
    if a.addr.is_some() {
        anyhow::bail!("reconfig remove-validator does not take --addr");
    }

    let node_id = base58_to_node_id(pubkey_b58)
        .map_err(|e| anyhow::anyhow!("--pubkey {pubkey_b58:?} is not a valid NodeId: {e}"))?;

    let payload = ReconfigCommand::build_remove_validator_payload(node_id, v_eff);
    println!("{}", hex::encode(&payload));
    Ok(())
}

/// `reconfig change-weight` (#462): change a currently-seated
/// validator's voting weight at and after `v_eff`. Membership is
/// unchanged.
fn handle_reconfig_change_weight(args: &[String]) -> anyhow::Result<()> {
    use ambros_p2p::consensus::reconfig::ReconfigCommand;
    use ambros_p2p::p2p::tls::base58_to_node_id;

    let a = parse_reconfig_args(args)?;
    let pubkey_b58 = a
        .pubkey
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("reconfig change-weight requires --pubkey <base58>"))?;
    let v_eff = ambros_p2p::consensus::View(
        a.v_eff
            .ok_or_else(|| anyhow::anyhow!("reconfig change-weight requires --v-eff <view>"))?,
    );
    let weight = a
        .weight
        .ok_or_else(|| anyhow::anyhow!("reconfig change-weight requires --weight <u64>"))?;
    if a.addr.is_some() {
        anyhow::bail!("reconfig change-weight does not take --addr");
    }

    let node_id = base58_to_node_id(pubkey_b58)
        .map_err(|e| anyhow::anyhow!("--pubkey {pubkey_b58:?} is not a valid NodeId: {e}"))?;

    let payload = ReconfigCommand::build_change_weight_payload(node_id, weight, v_eff);
    println!("{}", hex::encode(&payload));
    Ok(())
}

// ── `rotation` subcommand (#313) ───────────────────────────────────────────

fn handle_rotation_subcommand(args: &[String]) -> anyhow::Result<()> {
    let sub = args
        .first()
        .ok_or_else(|| anyhow::anyhow!("missing rotation subcommand (try: propose)"))?;
    match sub.as_str() {
        "propose" => handle_rotation_propose(&args[1..]),
        other => anyhow::bail!("unknown `rotation` subcommand: {other}"),
    }
}

#[derive(Debug, Default)]
struct RotationProposeArgs {
    config_path: Option<PathBuf>,
    new_key_backend: Option<String>,
    new_key_path: Option<PathBuf>,
    new_key_passphrase_env: Option<String>,
    new_bls_key_backend: Option<String>,
    new_bls_key_path: Option<PathBuf>,
    v_eff: Option<u64>,
}

fn parse_rotation_propose_args(args: &[String]) -> anyhow::Result<RotationProposeArgs> {
    let mut out = RotationProposeArgs::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" => {
                i += 1;
                out.config_path =
                    Some(PathBuf::from(args.get(i).ok_or_else(|| {
                        anyhow::anyhow!("--config requires a path")
                    })?));
            }
            "--new-key-backend" => {
                i += 1;
                out.new_key_backend = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--new-key-backend requires a value"))?
                        .clone(),
                );
            }
            "--new-key-path" => {
                i += 1;
                out.new_key_path =
                    Some(PathBuf::from(args.get(i).ok_or_else(|| {
                        anyhow::anyhow!("--new-key-path requires a path")
                    })?));
            }
            "--new-key-passphrase-env" => {
                i += 1;
                out.new_key_passphrase_env = Some(
                    args.get(i)
                        .ok_or_else(|| {
                            anyhow::anyhow!("--new-key-passphrase-env requires a variable name")
                        })?
                        .clone(),
                );
            }
            "--new-bls-key-backend" => {
                i += 1;
                out.new_bls_key_backend = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--new-bls-key-backend requires a value"))?
                        .clone(),
                );
            }
            "--new-bls-key-path" => {
                i += 1;
                out.new_bls_key_path =
                    Some(PathBuf::from(args.get(i).ok_or_else(|| {
                        anyhow::anyhow!("--new-bls-key-path requires a path")
                    })?));
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
            other => anyhow::bail!("unknown rotation propose flag: {other}"),
        }
        i += 1;
    }
    Ok(out)
}

/// Translate the `--new-key-backend` + path/passphrase flags into an
/// [`IdentityConfig`]. The CLI deliberately accepts only the two
/// path-bearing backends — `file` and `encrypted-file` — because they
/// can self-provision a fresh key when the path doesn't yet exist
/// (which is the common rotation path: "mint a new key, sign with it,
/// submit"). Read-only backends (env, exec, keyring) need bespoke flags
/// and an out-of-band provisioning step; operators using those should
/// rotate by hand against the `DualSignedRotation::sign` API for now.
fn build_new_identity_config_for_rotation(
    backend: &str,
    path: Option<PathBuf>,
    passphrase_env: Option<String>,
) -> anyhow::Result<IdentityConfig> {
    match backend {
        "file" => Ok(IdentityConfig::File {
            path: path
                .ok_or_else(|| anyhow::anyhow!("--new-key-backend file requires --new-key-path"))?,
            allow_insecure_perms: false,
        }),
        "encrypted-file" => Ok(IdentityConfig::EncryptedFile {
            path: path.ok_or_else(|| {
                anyhow::anyhow!("--new-key-backend encrypted-file requires --new-key-path")
            })?,
            passphrase_env,
        }),
        "env" | "exec" | "keyring" => anyhow::bail!(
            "--new-key-backend `{backend}` is not supported by `rotation propose` yet \
             (read-only backends need separate provisioning); use `file` or `encrypted-file`",
        ),
        other => anyhow::bail!(
            "--new-key-backend `{other}` is not a valid backend (try: file, encrypted-file)",
        ),
    }
}

/// Outcome of building a rotation envelope from CLI inputs. Captured as
/// a struct so tests can assert on the resolved fields without re-doing
/// the whole orchestration.
#[derive(Debug)]
struct RotationProposeOutcome {
    envelope: ambros_p2p::consensus::validator_rotation::DualSignedRotation,
    /// True iff the chain's `signature_scheme` is `bls_aggregated` and
    /// the rotation therefore carries a BLS pubkey + PoP.
    bls_chain: bool,
}

/// Orchestration core of `rotation propose` — resolves the current
/// validator key from config, mints (or reloads) the new Ed25519 key,
/// mints (or reloads) the new BLS key on BLS chains, builds a
/// chain-bound [`DualSignedRotation`], and returns it. Lives as a free
/// function so unit tests can drive the same flow without spawning a
/// process.
fn build_rotation_envelope(args: &RotationProposeArgs) -> anyhow::Result<RotationProposeOutcome> {
    use ambros_p2p::consensus::validator_rotation::{DualSignedRotation, ValidatorKeyRotation};
    use ambros_p2p::crypto::bls_key::{BlsKeyFile, BlsKeyProvider as _};
    use ambros_p2p::crypto::sig_scheme::{BlsAggregated, SignatureSchemeChoice};
    use ambros_p2p::crypto::signed::{NodeSigner, Signer as _};

    let v_eff = ambros_p2p::consensus::View(
        args.v_eff
            .ok_or_else(|| anyhow::anyhow!("rotation propose requires --v-eff <view>"))?,
    );
    let new_backend = args.new_key_backend.as_deref().ok_or_else(|| {
        anyhow::anyhow!("rotation propose requires --new-key-backend <file|encrypted-file>")
    })?;
    let config_path = resolve_config_path(args.config_path.clone())?;
    let config = config::load(&config_path)?;
    let cons = config.consensus.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "--config {} has no [consensus] section; rotation requires the \
             chain's signature_scheme + chain_id to bundle a chain-bound payload",
            config_path.display(),
        )
    })?;
    let chain_id = ambros_p2p::node::derive_chain_id(cons)?;

    // Reject scheme/flag mismatches *before* minting any new keys so a
    // misconfigured invocation leaves no half-provisioned files behind.
    // Operators expect dry-fail semantics here — the same property the
    // `add-validator` reconfig CLI provides on a BLS/Ed25519 mismatch.
    match cons.signature_scheme {
        SignatureSchemeChoice::BlsAggregated => {
            if args.new_bls_key_backend.is_none() {
                anyhow::bail!(
                    "[consensus].signature_scheme = \"bls_aggregated\" but no \
                     --new-bls-key-backend was supplied; BLS chains rotate both halves \
                     atomically (#358)",
                );
            }
        }
        SignatureSchemeChoice::Ed25519Collected => {
            if args.new_bls_key_backend.is_some() || args.new_bls_key_path.is_some() {
                anyhow::bail!(
                    "[consensus].signature_scheme = \"ed25519_collected\" but a \
                     --new-bls-key-* flag was supplied; Ed25519 chains have no use for \
                     BLS keys (remove the flag)",
                );
            }
        }
    }

    // Resolve the *current* validator signer. Mirrors the precedence
    // `start` uses: prefer `[node.validator_identity]` if present;
    // otherwise fall back to the network identity (the legacy single-
    // key setup). Either way, the signer must already exist on disk —
    // rotation never mints the *current* key, only the new one.
    let (current_id_cfg, current_slot) = match config::resolve_validator_identity(&config.node) {
        Some(cfg) => (cfg, "validator"),
        None => match config::resolve_identity(&config.node) {
            Some(cfg) => (cfg, "network (legacy single-key)"),
            None => anyhow::bail!(
                "--config {} has no [node.validator_identity] or [node.identity]; \
                 rotation needs an existing consensus signing key to produce sig_old",
                config_path.display(),
            ),
        },
    };
    let current_provider = config::build_provider(&current_id_cfg)?;
    let current_identity = current_provider.try_load()?.ok_or_else(|| {
        anyhow::anyhow!(
            "no current consensus key found via the {} `{}` backend; provision it via \
             `ambros-p2p init` (or out-of-band) before rotating",
            current_slot,
            current_id_cfg.backend_name(),
        )
    })?;
    let current_signer = NodeSigner::from_identity(&current_identity)?;

    // Resolve / provision the *new* Ed25519 key.
    let new_id_cfg = build_new_identity_config_for_rotation(
        new_backend,
        args.new_key_path.clone(),
        args.new_key_passphrase_env.clone(),
    )?;
    let new_provider = config::build_provider(&new_id_cfg)?;
    let new_identity = if new_provider.is_provisioning_capable() {
        new_provider.load_or_init()?
    } else {
        new_provider.try_load()?.ok_or_else(|| {
            anyhow::anyhow!(
                "new key backend `{}` is read-only and no key is yet provisioned; \
                 mint the key out-of-band first",
                new_id_cfg.backend_name(),
            )
        })?
    };
    let new_signer = NodeSigner::from_identity(&new_identity)?;

    // BLS half. Scheme/flag-presence consistency was already enforced
    // up front; this block now only runs the actual provisioning on
    // BLS chains.
    let bls_chain = matches!(cons.signature_scheme, SignatureSchemeChoice::BlsAggregated);
    let (new_bls_pubkey, new_bls_pop) = if bls_chain {
        let backend = args
            .new_bls_key_backend
            .as_deref()
            .expect("BLS-flag presence verified above");
        if backend != "file" {
            anyhow::bail!("--new-bls-key-backend `{backend}` is not supported (only `file` today)",);
        }
        let bls_path = args.new_bls_key_path.clone().ok_or_else(|| {
            anyhow::anyhow!("--new-bls-key-backend file requires --new-bls-key-path")
        })?;
        let bls_provider = BlsKeyFile::new(bls_path);
        let bls_id = bls_provider.load_or_init()?;
        let pop = BlsAggregated::sign_pop(&bls_id.secret, &chain_id)
            .map_err(|e| anyhow::anyhow!("signing BLS PoP: {e:?}"))?;
        (Some(bls_id.public), Some(pop))
    } else {
        (None, None)
    };

    let payload = ValidatorKeyRotation {
        validator: current_signer.node_id(),
        new_pubkey: new_signer.node_id(),
        v_eff,
        new_bls_pubkey,
        new_bls_pop,
    };

    // Surface a no-op rotation as a CLI-level error — the engine would
    // reject it via `validate_structural` at commit time anyway, but
    // catching it here saves the operator a round-trip and a confusing
    // "NewKeyEqualsValidator" log line on every replica.
    if payload.new_pubkey == payload.validator {
        anyhow::bail!(
            "new_pubkey equals current validator key; the --new-key-path is already \
             pointing at the active consensus key — pick a different path",
        );
    }
    payload
        .validate_scheme_consistency(cons.signature_scheme, &chain_id)
        .map_err(|e| anyhow::anyhow!("rotation payload failed scheme-consistency check: {e}"))?;

    let envelope = DualSignedRotation::sign(payload, &current_signer, &new_signer, &chain_id)?;
    Ok(RotationProposeOutcome {
        envelope,
        bls_chain,
    })
}

fn handle_rotation_propose(args: &[String]) -> anyhow::Result<()> {
    use ambros_p2p::p2p::tls::node_id_to_base58;

    let parsed = parse_rotation_propose_args(args)?;
    let outcome = build_rotation_envelope(&parsed)?;
    let bytes = outcome.envelope.encode_command();
    println!("{}", hex::encode(&bytes));
    eprintln!(
        "rotation built: validator={} new_pubkey={} v_eff={} bls_chain={}",
        node_id_to_base58(&outcome.envelope.payload.validator),
        node_id_to_base58(&outcome.envelope.payload.new_pubkey),
        outcome.envelope.payload.v_eff.0,
        outcome.bls_chain,
    );
    eprintln!(
        "submit the hex above into a validator's mempool to propose the rotation \
         (no admin RPC yet; route is operator-specific)"
    );
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

#[cfg(test)]
mod tests {
    use super::*;
    use ambros_p2p::crypto::bls_key::{BlsKeyFile, BlsKeyProvider as _};
    use ambros_p2p::crypto::sig_scheme::BlsAggregated;
    use ambros_p2p::crypto::signed::ChainId;
    use tempfile::TempDir;

    #[test]
    fn read_bls_pop_file_round_trips_with_valid_pop() {
        // Write a valid `<pubkey_hex>:<pop_hex>` file and confirm the
        // helper reads back a structurally-identical PoP that verifies.
        let mut ikm = [0u8; 32];
        ikm[0] = 0x42;
        let (sk, pk) = BlsAggregated::keygen(&ikm).unwrap();
        let pop = BlsAggregated::sign_pop(&sk, &ChainId([0u8; 32])).unwrap();

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("pop.txt");
        std::fs::write(
            &path,
            format!("{}:{}\n", hex::encode(pk), hex::encode(pop.sig)),
        )
        .unwrap();

        let parsed = read_bls_pop_file(&path).expect("must parse");
        assert_eq!(parsed.pubkey, pop.pubkey);
        assert_eq!(parsed.sig, pop.sig);
        BlsAggregated::verify_pop(&parsed, &pk, &ChainId([0u8; 32]))
            .expect("must still verify after round-trip");
    }

    #[test]
    fn read_bls_pop_file_rejects_wrong_lengths() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bad.txt");
        // Pubkey of wrong length (only 32 bytes).
        std::fs::write(
            &path,
            format!("{}:{}", hex::encode([0u8; 32]), hex::encode([0u8; 96])),
        )
        .unwrap();
        let err = read_bls_pop_file(&path).unwrap_err();
        assert!(err.to_string().contains("48"), "{err}");

        // Sig of wrong length (only 32 bytes).
        std::fs::write(
            &path,
            format!("{}:{}", hex::encode([0u8; 48]), hex::encode([0u8; 32])),
        )
        .unwrap();
        let err = read_bls_pop_file(&path).unwrap_err();
        assert!(err.to_string().contains("96"), "{err}");
    }

    #[test]
    fn read_bls_pop_file_rejects_missing_separator() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nosep.txt");
        std::fs::write(&path, "deadbeef").unwrap();
        let err = read_bls_pop_file(&path).unwrap_err();
        assert!(err.to_string().contains("expected"), "{err}");
    }

    #[test]
    fn derive_bls_pop_from_key_file_produces_verifiable_pop() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bls.key");
        // Provision the key file via the standard provider.
        let provider = BlsKeyFile::new(path.clone());
        let id = provider.load_or_init().unwrap();

        let chain_id = ChainId([0x55; 32]);
        let derived = derive_bls_pop_from_key_file(&path, &chain_id).expect("must succeed");
        assert_eq!(derived.pubkey, id.public);
        BlsAggregated::verify_pop(&derived, &id.public, &chain_id)
            .expect("derived PoP must verify under the same chain_id");
        // #410: the same key derives a different (and incompatible)
        // PoP under a different chain_id.
        let other = ChainId([0xCC; 32]);
        assert!(BlsAggregated::verify_pop(&derived, &id.public, &other).is_err());
    }

    // ── `rotation propose` (#313) ───────────────────────────────────────

    /// Mint a fresh Ed25519 file-backed validator key and return its
    /// path together with the base58-encoded NodeId. Both halves are
    /// what the rotation tests need to write a usable config TOML.
    fn mint_validator_key(path: &Path) -> String {
        use ambros_p2p::crypto::signed::{NodeSigner, Signer as _};
        let cfg = ambros_p2p::config::IdentityConfig::File {
            path: path.to_path_buf(),
            allow_insecure_perms: false,
        };
        let provider = ambros_p2p::config::build_provider(&cfg).unwrap();
        let id = provider.load_or_init().unwrap();
        let signer = NodeSigner::from_identity(&id).unwrap();
        ambros_p2p::p2p::tls::node_id_to_base58(&signer.node_id())
    }

    fn write_ed25519_chain_config(
        config_path: &Path,
        current_key_path: &Path,
        validator_b58: &str,
    ) {
        let text = format!(
            "[node]\n\
             listen_addr = \"127.0.0.1:7000\"\n\n\
             [node.identity]\n\
             backend = \"file\"\n\
             path = \"{key}\"\n\n\
             [node.validator_identity]\n\
             backend = \"file\"\n\
             path = \"{key}\"\n\n\
             [api]\n\
             listen_addr = \"127.0.0.1:8000\"\n\n\
             [consensus]\n\
             validators = [\"{val}\"]\n\
             signature_scheme = \"ed25519_collected\"\n",
            key = current_key_path.display(),
            val = validator_b58,
        );
        std::fs::write(config_path, text).unwrap();
    }

    fn write_bls_chain_config(
        config_path: &Path,
        current_key_path: &Path,
        validator_b58: &str,
        validator_bls_pubkey_hex: &str,
        validator_bls_pop_hex: &str,
    ) {
        let text = format!(
            "[node]\n\
             listen_addr = \"127.0.0.1:7000\"\n\n\
             [node.identity]\n\
             backend = \"file\"\n\
             path = \"{key}\"\n\n\
             [node.validator_identity]\n\
             backend = \"file\"\n\
             path = \"{key}\"\n\n\
             [api]\n\
             listen_addr = \"127.0.0.1:8000\"\n\n\
             [consensus]\n\
             validators = [\"{val}\"]\n\
             signature_scheme = \"bls_aggregated\"\n\n\
             [[consensus.validators_bls]]\n\
             node_id = \"{val}\"\n\
             bls_pubkey = \"{pk}\"\n\
             bls_pop = \"{pop}\"\n",
            key = current_key_path.display(),
            val = validator_b58,
            pk = validator_bls_pubkey_hex,
            pop = validator_bls_pop_hex,
        );
        std::fs::write(config_path, text).unwrap();
    }

    #[test]
    fn rotation_propose_ed25519_chain_builds_verifiable_envelope() {
        // End-to-end: real config + real existing validator key on
        // disk → minted new key → signed envelope that verifies under
        // the validator's current pubkey and the chain's chain_id.
        // This is the CLI-level integration test called for in the
        // issue's acceptance criteria.
        use ambros_p2p::crypto::signed::{NodeSigner, Signer as _};

        let dir = TempDir::new().unwrap();
        let current_key = dir.path().join("current.key");
        let validator_b58 = mint_validator_key(&current_key);
        let config_path = dir.path().join("config.toml");
        write_ed25519_chain_config(&config_path, &current_key, &validator_b58);

        let new_key = dir.path().join("new.key");
        assert!(!new_key.exists(), "new key must not pre-exist");
        let args = RotationProposeArgs {
            config_path: Some(config_path.clone()),
            new_key_backend: Some("file".into()),
            new_key_path: Some(new_key.clone()),
            new_key_passphrase_env: None,
            new_bls_key_backend: None,
            new_bls_key_path: None,
            v_eff: Some(500),
        };
        let outcome = build_rotation_envelope(&args).expect("rotation propose must succeed");

        // The new key must have been minted on the spot.
        assert!(
            new_key.exists(),
            "new key file must be created by load_or_init"
        );
        assert!(!outcome.bls_chain);
        assert!(outcome.envelope.payload.new_bls_pubkey.is_none());
        assert!(outcome.envelope.payload.new_bls_pop.is_none());
        assert_eq!(outcome.envelope.payload.v_eff.0, 500);

        // Recover the current and new signers independently and confirm
        // they match the envelope.
        let current_id =
            ambros_p2p::config::build_provider(&ambros_p2p::config::IdentityConfig::File {
                path: current_key.clone(),
                allow_insecure_perms: false,
            })
            .unwrap()
            .try_load()
            .unwrap()
            .unwrap();
        let current_signer = NodeSigner::from_identity(&current_id).unwrap();
        let new_id =
            ambros_p2p::config::build_provider(&ambros_p2p::config::IdentityConfig::File {
                path: new_key.clone(),
                allow_insecure_perms: false,
            })
            .unwrap()
            .try_load()
            .unwrap()
            .unwrap();
        let new_signer = NodeSigner::from_identity(&new_id).unwrap();
        assert_eq!(outcome.envelope.payload.validator, current_signer.node_id());
        assert_eq!(outcome.envelope.payload.new_pubkey, new_signer.node_id());

        // Cryptographic round-trip: the envelope must verify under the
        // chain's chain_id and the current pubkey, exactly the path
        // `apply_committed_rotations` exercises at commit time.
        let cfg = ambros_p2p::config::load(&config_path).unwrap();
        let chain_id = ambros_p2p::node::derive_chain_id(cfg.consensus.as_ref().unwrap()).unwrap();
        outcome
            .envelope
            .verify(&current_signer.node_id(), &chain_id)
            .expect("envelope must verify");

        // And the encoded bytes carry the rotation tag, so an operator
        // can drop them straight into a `Block.commands` slot.
        let bytes = outcome.envelope.encode_command();
        assert!(
            ambros_p2p::consensus::validator_rotation::DualSignedRotation::is_rotation_payload(
                &bytes,
            ),
        );
    }

    #[test]
    fn rotation_propose_idempotent_when_new_key_already_exists() {
        // Re-running with a pre-minted `new_key_path` must reload it
        // (not overwrite) and produce a payload pointing at the same
        // pubkey. Operators retry rotations after fixing a mistyped
        // `--v-eff`; the new key should not flip on every retry.
        use ambros_p2p::crypto::signed::{NodeSigner, Signer as _};

        let dir = TempDir::new().unwrap();
        let current_key = dir.path().join("current.key");
        let validator_b58 = mint_validator_key(&current_key);
        let config_path = dir.path().join("config.toml");
        write_ed25519_chain_config(&config_path, &current_key, &validator_b58);

        let new_key = dir.path().join("new.key");
        let args = RotationProposeArgs {
            config_path: Some(config_path.clone()),
            new_key_backend: Some("file".into()),
            new_key_path: Some(new_key.clone()),
            new_key_passphrase_env: None,
            new_bls_key_backend: None,
            new_bls_key_path: None,
            v_eff: Some(500),
        };
        let first = build_rotation_envelope(&args).unwrap();
        let second = build_rotation_envelope(&args).unwrap();

        let new_id =
            ambros_p2p::config::build_provider(&ambros_p2p::config::IdentityConfig::File {
                path: new_key.clone(),
                allow_insecure_perms: false,
            })
            .unwrap()
            .try_load()
            .unwrap()
            .unwrap();
        let new_signer = NodeSigner::from_identity(&new_id).unwrap();
        assert_eq!(first.envelope.payload.new_pubkey, new_signer.node_id());
        assert_eq!(second.envelope.payload.new_pubkey, new_signer.node_id());
    }

    #[test]
    fn rotation_propose_rejects_bls_flags_on_ed25519_chain() {
        // Ed25519-chain config + BLS flag must error before any key is
        // minted, mirroring `add-validator`'s ergonomics.
        let dir = TempDir::new().unwrap();
        let current_key = dir.path().join("current.key");
        let validator_b58 = mint_validator_key(&current_key);
        let config_path = dir.path().join("config.toml");
        write_ed25519_chain_config(&config_path, &current_key, &validator_b58);

        let new_key = dir.path().join("new.key");
        let new_bls = dir.path().join("new-bls.key");
        let args = RotationProposeArgs {
            config_path: Some(config_path.clone()),
            new_key_backend: Some("file".into()),
            new_key_path: Some(new_key.clone()),
            new_key_passphrase_env: None,
            new_bls_key_backend: Some("file".into()),
            new_bls_key_path: Some(new_bls.clone()),
            v_eff: Some(500),
        };
        let err = build_rotation_envelope(&args).unwrap_err();
        assert!(
            err.to_string().contains("ed25519_collected"),
            "unexpected error: {err}",
        );
        // The Ed25519 path must reject BLS flags before any key is
        // touched on disk — operators expect dry-fail semantics here.
        assert!(!new_bls.exists());
    }

    #[test]
    fn rotation_propose_bls_chain_bundles_bls_key_and_pop() {
        // BLS-chain happy path: both halves are minted, the envelope
        // carries a chain-bound PoP, and the payload passes
        // `validate_scheme_consistency` (which is what the engine runs
        // at commit time).
        use ambros_p2p::crypto::signed::{NodeSigner, Signer as _};

        let dir = TempDir::new().unwrap();
        let current_key = dir.path().join("current.key");
        let validator_b58 = mint_validator_key(&current_key);

        // Generate a BLS keypair for the genesis validator entry.
        // The PoP is bogus (its pre-image is chain_id-bound but
        // chain_id depends on the entry itself); that's OK because the
        // rotation path never verifies the *genesis* PoP — only its
        // own freshly-derived one.
        let mut ikm = [0u8; 32];
        ikm[0] = 0xAA;
        let (_genesis_sk, genesis_pk) = BlsAggregated::keygen(&ikm).unwrap();
        let genesis_pk_hex = hex::encode(genesis_pk);
        let genesis_pop_hex = hex::encode([0u8; 96]);

        let config_path = dir.path().join("config.toml");
        write_bls_chain_config(
            &config_path,
            &current_key,
            &validator_b58,
            &genesis_pk_hex,
            &genesis_pop_hex,
        );

        let new_key = dir.path().join("new.key");
        let new_bls = dir.path().join("new-bls.key");
        let args = RotationProposeArgs {
            config_path: Some(config_path.clone()),
            new_key_backend: Some("file".into()),
            new_key_path: Some(new_key.clone()),
            new_key_passphrase_env: None,
            new_bls_key_backend: Some("file".into()),
            new_bls_key_path: Some(new_bls.clone()),
            v_eff: Some(500),
        };
        let outcome = build_rotation_envelope(&args).expect("BLS rotation must succeed");

        assert!(outcome.bls_chain);
        assert!(new_bls.exists(), "BLS key file must be minted");
        let env_pk = outcome
            .envelope
            .payload
            .new_bls_pubkey
            .expect("must carry BLS pubkey");
        let env_pop = outcome
            .envelope
            .payload
            .new_bls_pop
            .as_ref()
            .expect("must carry PoP");

        // The envelope's BLS pubkey must match the file we just minted.
        let bls_id = BlsKeyFile::new(new_bls.clone()).load_or_init().unwrap();
        assert_eq!(env_pk, bls_id.public);

        // The PoP must verify under the chain's chain_id (the same
        // check `apply_committed_rotations` runs through
        // `validate_scheme_consistency`).
        let cfg = ambros_p2p::config::load(&config_path).unwrap();
        let chain_id = ambros_p2p::node::derive_chain_id(cfg.consensus.as_ref().unwrap()).unwrap();
        BlsAggregated::verify_pop(env_pop, &env_pk, &chain_id)
            .expect("BLS PoP must verify under the chain's chain_id");

        // Scheme-consistency check passes — same surface the engine
        // hits at commit time.
        outcome
            .envelope
            .payload
            .validate_scheme_consistency(
                ambros_p2p::crypto::sig_scheme::SignatureSchemeChoice::BlsAggregated,
                &chain_id,
            )
            .expect("must pass scheme-consistency under the BLS scheme");

        // And the dual-Ed25519 signatures still verify.
        let current_id =
            ambros_p2p::config::build_provider(&ambros_p2p::config::IdentityConfig::File {
                path: current_key.clone(),
                allow_insecure_perms: false,
            })
            .unwrap()
            .try_load()
            .unwrap()
            .unwrap();
        let current_signer = NodeSigner::from_identity(&current_id).unwrap();
        outcome
            .envelope
            .verify(&current_signer.node_id(), &chain_id)
            .expect("Ed25519 dual-signature must verify on BLS chains too");
    }

    #[test]
    fn rotation_propose_bls_chain_requires_bls_key_flags() {
        let dir = TempDir::new().unwrap();
        let current_key = dir.path().join("current.key");
        let validator_b58 = mint_validator_key(&current_key);
        let mut ikm = [0u8; 32];
        ikm[0] = 0xAB;
        let (_sk, pk) = BlsAggregated::keygen(&ikm).unwrap();
        let config_path = dir.path().join("config.toml");
        write_bls_chain_config(
            &config_path,
            &current_key,
            &validator_b58,
            &hex::encode(pk),
            &hex::encode([0u8; 96]),
        );

        let new_key = dir.path().join("new.key");
        let args = RotationProposeArgs {
            config_path: Some(config_path),
            new_key_backend: Some("file".into()),
            new_key_path: Some(new_key.clone()),
            new_key_passphrase_env: None,
            new_bls_key_backend: None,
            new_bls_key_path: None,
            v_eff: Some(500),
        };
        let err = build_rotation_envelope(&args).unwrap_err();
        assert!(
            err.to_string().contains("--new-bls-key-backend"),
            "unexpected error: {err}",
        );
        // No Ed25519 key gets minted either: we fail before touching disk.
        assert!(!new_key.exists());
    }

    #[test]
    fn rotation_propose_rejects_v_eff_too_close_when_validated_at_current_view() {
        // build_rotation_envelope itself doesn't know "current_view"
        // (that lives on the running node), but the engine enforces
        // V_EFF_MIN_DELAY at commit time. We exercise the constant
        // here so a future change to the floor surfaces in a CLI test
        // rather than only in the consensus layer.
        let payload = ambros_p2p::consensus::validator_rotation::ValidatorKeyRotation {
            validator: [1u8; 32],
            new_pubkey: [2u8; 32],
            v_eff: ambros_p2p::consensus::View(11),
            new_bls_pubkey: None,
            new_bls_pop: None,
        };
        // current_view=10, v_eff=11 → < current+2; must be rejected.
        assert!(payload.validate_structural(10).is_err());
    }

    #[test]
    fn parse_rotation_propose_args_round_trips() {
        let args: Vec<String> = [
            "--config",
            "/tmp/c.toml",
            "--new-key-backend",
            "file",
            "--new-key-path",
            "/tmp/n.key",
            "--v-eff",
            "100",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let parsed = parse_rotation_propose_args(&args).unwrap();
        assert_eq!(parsed.config_path.unwrap(), PathBuf::from("/tmp/c.toml"));
        assert_eq!(parsed.new_key_backend.as_deref(), Some("file"));
        assert_eq!(parsed.new_key_path.unwrap(), PathBuf::from("/tmp/n.key"));
        assert_eq!(parsed.v_eff, Some(100));
        assert!(parsed.new_bls_key_backend.is_none());
    }

    #[test]
    fn parse_rotation_propose_args_rejects_unknown_flag() {
        let args = ["--no-such-flag"]
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        let err = parse_rotation_propose_args(&args).unwrap_err();
        assert!(err.to_string().contains("--no-such-flag"));
    }

    #[test]
    fn parse_rotation_propose_args_rejects_invalid_v_eff() {
        let args = ["--v-eff", "not-a-number"]
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        let err = parse_rotation_propose_args(&args).unwrap_err();
        assert!(err.to_string().contains("--v-eff"));
    }

    #[test]
    fn build_new_identity_config_for_rotation_supports_path_backends() {
        let cfg =
            build_new_identity_config_for_rotation("file", Some(PathBuf::from("/tmp/k")), None)
                .unwrap();
        assert!(matches!(
            cfg,
            ambros_p2p::config::IdentityConfig::File { .. }
        ));
        assert_eq!(cfg.backend_name(), "file");

        let cfg = build_new_identity_config_for_rotation(
            "encrypted-file",
            Some(PathBuf::from("/tmp/k")),
            Some("PASS".into()),
        )
        .unwrap();
        assert_eq!(cfg.backend_name(), "encrypted-file");
    }

    #[test]
    fn build_new_identity_config_for_rotation_rejects_read_only_backends() {
        for backend in ["env", "exec", "keyring"] {
            let err = build_new_identity_config_for_rotation(backend, None, None).unwrap_err();
            assert!(
                err.to_string().contains("not supported"),
                "{backend}: {err}",
            );
        }
    }

    #[test]
    fn build_new_identity_config_for_rotation_rejects_unknown_backend() {
        let err = build_new_identity_config_for_rotation("hsm", None, None).unwrap_err();
        assert!(err.to_string().contains("not a valid backend"));
    }
}
