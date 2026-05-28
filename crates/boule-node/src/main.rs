use std::path::{Path, PathBuf};

use tracing::info;

use boule::cli::{self, OutputFormat};
use boule::config;
use boule::consensus::validator_rotation::RotationProposeRequest;
use boule::node;
use boule::p2p::identity::KeyProvider;
use boule::p2p::tls::node_id_to_base58;
use boule::paths;

const ENV_PRODUCTION: &str = "BOULE_ENV";

/// Initialize the tracing subscriber.
///
/// Honors two environment variables:
///
/// - `RUST_LOG`: standard `tracing-subscriber` env filter. Defaults to
///   `boule=info`. Set to `info,boule::consensus=debug` to get
///   the structured event-boundary logs the consensus layer emits.
/// - `RUST_LOG_FORMAT`: `pretty` (default) or `json`. JSON emits one
///   structured event per line, which operators can pipe through `jq` to
///   filter across nodes.
fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "boule=info".into());

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
    println!("Usage: boule <subcommand> [options]");
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
        boule::consensus::reconfig::MIN_VALIDATOR_FLOOR,
    );
    println!(
        "      `v_eff` must be at least `current_view + {}`.",
        boule::consensus::reconfig::MIN_V_EFF_DELAY,
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
        boule::consensus::validator_rotation::V_EFF_MIN_DELAY,
    );
    println!();
    println!("  config [--config <path>] [--format human|json|toml] [--raw|--edit|--path]");
    println!("      Print or edit the node's effective configuration. Default");
    println!("      prints the fully-resolved config (file contents + filled-in");
    println!("      defaults). `--format` overrides the per-config default set by");
    println!("      `[ui] output_format`; for `config`, both `human` (the global");
    println!("      default) and `toml` render TOML, while `json` emits JSON");
    println!(
        "      suitable for piping (e.g. `boule config --format json | jq '.consensus.timeout_base_ms'`)."
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

// ── `init` subcommand ───────────────────────────────────────────────────────

fn handle_init(args: &[String]) -> anyhow::Result<()> {
    let args = parse_init_args(args)?;
    let config_path = resolve_config_path(args.config_path)?;

    // Step 1: write the starter template if the config doesn't exist.
    if !config_path.exists() {
        config::write_starter_config(&config_path)?;
        println!("wrote starter config to {}", config_path.display());
    } else {
        println!("config already exists at {}", config_path.display());
    }

    // Step 2: load + validate.
    let config = config::load(&config_path)?;
    info!("loaded config from {}", config_path.display());

    // Step 3: resolve the identity backend. `init` does not need
    // production semantics — operators run it interactively to bootstrap.
    let identity_cfg = config::resolve_and_validate_identity(&config.node, false, false)?;
    println!("network identity backend: {}", identity_cfg.backend_name());

    // Step 4: provision the network key (or report externally-managed).
    let provider = config::build_provider(&identity_cfg)?;
    provision_or_report(&*provider, identity_cfg.backend_name(), "network")?;

    // Step 4a: cross-validate `[[peers]]` against the local NodeId now
    // that the network key has been loaded. Catches a self-id in the
    // static peers list at `init` time so operators don't ship a config
    // that only fails at `start`.
    if let Some(net_id) = provider.try_load()? {
        let tls = boule::p2p::tls::TlsIdentity::from_identity(&net_id)?;
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
    config.preflight_validate()?;

    println!(
        "init complete. Run `boule start --config {}` to launch.",
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
            let tls = boule::p2p::tls::TlsIdentity::from_identity(&id)?;
            println!(
                "{slot} key already provisioned: NodeId = {}",
                node_id_to_base58(&tls.node_id)
            );
        }
        None => {
            if provider.is_provisioning_capable() {
                let new_id = provider.load_or_init()?;
                let tls = boule::p2p::tls::TlsIdentity::from_identity(&new_id)?;
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

// ── `start` subcommand ──────────────────────────────────────────────────────

async fn handle_start(args: &[String]) -> anyhow::Result<()> {
    let args = parse_start_args(args)?;
    let config_path = resolve_config_path(args.config_path)?;

    let config = config::load(&config_path)?;
    info!("loaded config from {}", config_path.display());

    let production = is_production(args.production);
    let identity_cfg =
        config::resolve_and_validate_identity(&config.node, production, args.allow_insecure_perms)?;
    info!("network identity backend: {}", identity_cfg.backend_name());

    let provider = config::build_provider(&identity_cfg)?;
    let network_identity = provider.try_load()?.ok_or_else(|| {
        anyhow::anyhow!(
            "no node key found via the `{}` backend. Run `boule init --config {}` \
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
                "no validator key found via the `{}` backend. Run `boule init --config {}` \
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
    config::migrate_key(
        &config_path,
        to,
        args.path,
        args.passphrase_env,
        args.service,
        args.account,
        args.delete_source,
    )
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
            "no config at {} to edit; run `boule init --config {}` first",
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
    let store = boule::replication::snapshot::open_snapshot_store(&config)?;
    let manifest = boule::replication::snapshot::export_snapshot(&store, args.height, &out_dir)?;
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
    let store = boule::replication::snapshot::open_snapshot_store(&config)?;
    let manifest = boule::replication::snapshot::import_snapshot(&store, &in_dir)?;
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
    use boule::consensus::reconfig;
    use boule::p2p::tls::base58_to_node_id;

    let a = parse_reconfig_args(args)?;
    let pubkey_b58 = a
        .pubkey
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("reconfig add-validator requires --pubkey <base58>"))?;
    let addr_str = a
        .addr
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("reconfig add-validator requires --addr <socketaddr>"))?;
    let v_eff = boule::consensus::View(
        a.v_eff
            .ok_or_else(|| anyhow::anyhow!("reconfig add-validator requires --v-eff <view>"))?,
    );
    let weight = a.weight.ok_or_else(|| {
        anyhow::anyhow!(
            "reconfig add-validator requires --weight <u64>; use 1 for an unweighted committee."
        )
    })?;
    let node_id = base58_to_node_id(pubkey_b58)
        .map_err(|e| anyhow::anyhow!("--pubkey {pubkey_b58:?} is not a valid NodeId: {e}"))?;
    let addr: std::net::SocketAddr = addr_str
        .parse()
        .map_err(|e| anyhow::anyhow!("--addr {addr_str:?} is not a valid socket address: {e}"))?;

    let config = a
        .config_path
        .as_ref()
        .map(|p| config::load(p))
        .transpose()?;
    let payload = reconfig::build_add_validator_payload(
        config.as_ref(),
        node_id,
        addr,
        v_eff,
        weight,
        a.bls_pop_file.as_deref(),
        a.bls_key_file.as_deref(),
    )?;
    println!("{}", hex::encode(&payload));
    Ok(())
}

fn handle_reconfig_remove(args: &[String]) -> anyhow::Result<()> {
    use boule::consensus::reconfig::ReconfigCommand;
    use boule::p2p::tls::base58_to_node_id;

    let a = parse_reconfig_args(args)?;
    let pubkey_b58 = a
        .pubkey
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("reconfig remove-validator requires --pubkey <base58>"))?;
    let v_eff = boule::consensus::View(
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
    use boule::consensus::reconfig::ReconfigCommand;
    use boule::p2p::tls::base58_to_node_id;

    let a = parse_reconfig_args(args)?;
    let pubkey_b58 = a
        .pubkey
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("reconfig change-weight requires --pubkey <base58>"))?;
    let v_eff = boule::consensus::View(
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

fn parse_rotation_propose_args(args: &[String]) -> anyhow::Result<RotationProposeRequest> {
    let mut out = RotationProposeRequest::default();
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

fn handle_rotation_propose(args: &[String]) -> anyhow::Result<()> {
    use boule::consensus::validator_rotation::build_rotation_envelope;
    use boule::p2p::tls::node_id_to_base58;

    let mut req = parse_rotation_propose_args(args)?;
    // Resolve the default config path here (a binary concern) so the lib
    // can load it directly.
    req.config_path = Some(resolve_config_path(req.config_path.take())?);
    let outcome = build_rotation_envelope(&req)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use boule::consensus::validator_rotation::{
        build_new_identity_config_for_rotation, build_rotation_envelope,
    };
    use boule::crypto::bls_key::{BlsKeyFile, BlsKeyProvider as _};
    use boule::crypto::sig_scheme::BlsAggregated;
    use tempfile::TempDir;

    // ── `rotation propose` (#313) ───────────────────────────────────────

    /// Mint a fresh Ed25519 file-backed validator key and return its
    /// path together with the base58-encoded NodeId. Both halves are
    /// what the rotation tests need to write a usable config TOML.
    fn mint_validator_key(path: &Path) -> String {
        use boule::crypto::signed::{NodeSigner, Signer as _};
        let cfg = boule::config::IdentityConfig::File {
            path: path.to_path_buf(),
            allow_insecure_perms: false,
        };
        let provider = boule::config::build_provider(&cfg).unwrap();
        let id = provider.load_or_init().unwrap();
        let signer = NodeSigner::from_identity(&id).unwrap();
        boule::p2p::tls::node_id_to_base58(&signer.node_id())
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
        use boule::crypto::signed::{NodeSigner, Signer as _};

        let dir = TempDir::new().unwrap();
        let current_key = dir.path().join("current.key");
        let validator_b58 = mint_validator_key(&current_key);
        let config_path = dir.path().join("config.toml");
        write_ed25519_chain_config(&config_path, &current_key, &validator_b58);

        let new_key = dir.path().join("new.key");
        assert!(!new_key.exists(), "new key must not pre-exist");
        let args = RotationProposeRequest {
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
        let current_id = boule::config::build_provider(&boule::config::IdentityConfig::File {
            path: current_key.clone(),
            allow_insecure_perms: false,
        })
        .unwrap()
        .try_load()
        .unwrap()
        .unwrap();
        let current_signer = NodeSigner::from_identity(&current_id).unwrap();
        let new_id = boule::config::build_provider(&boule::config::IdentityConfig::File {
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
        let cfg = boule::config::load(&config_path).unwrap();
        let chain_id = boule::node::derive_chain_id(cfg.consensus.as_ref().unwrap()).unwrap();
        outcome
            .envelope
            .verify(&current_signer.node_id(), &chain_id)
            .expect("envelope must verify");

        // And the encoded bytes carry the rotation tag, so an operator
        // can drop them straight into a `Block.commands` slot.
        let bytes = outcome.envelope.encode_command();
        assert!(
            boule::consensus::validator_rotation::DualSignedRotation::is_rotation_payload(&bytes,),
        );
    }

    #[test]
    fn rotation_propose_idempotent_when_new_key_already_exists() {
        // Re-running with a pre-minted `new_key_path` must reload it
        // (not overwrite) and produce a payload pointing at the same
        // pubkey. Operators retry rotations after fixing a mistyped
        // `--v-eff`; the new key should not flip on every retry.
        use boule::crypto::signed::{NodeSigner, Signer as _};

        let dir = TempDir::new().unwrap();
        let current_key = dir.path().join("current.key");
        let validator_b58 = mint_validator_key(&current_key);
        let config_path = dir.path().join("config.toml");
        write_ed25519_chain_config(&config_path, &current_key, &validator_b58);

        let new_key = dir.path().join("new.key");
        let args = RotationProposeRequest {
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

        let new_id = boule::config::build_provider(&boule::config::IdentityConfig::File {
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
        let args = RotationProposeRequest {
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
        use boule::crypto::signed::{NodeSigner, Signer as _};

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
        let args = RotationProposeRequest {
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
        let cfg = boule::config::load(&config_path).unwrap();
        let chain_id = boule::node::derive_chain_id(cfg.consensus.as_ref().unwrap()).unwrap();
        BlsAggregated::verify_pop(env_pop, &env_pk, &chain_id)
            .expect("BLS PoP must verify under the chain's chain_id");

        // Scheme-consistency check passes — same surface the engine
        // hits at commit time.
        outcome
            .envelope
            .payload
            .validate_scheme_consistency(
                boule::crypto::sig_scheme::SignatureSchemeChoice::BlsAggregated,
                &chain_id,
            )
            .expect("must pass scheme-consistency under the BLS scheme");

        // And the dual-Ed25519 signatures still verify.
        let current_id = boule::config::build_provider(&boule::config::IdentityConfig::File {
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
        let args = RotationProposeRequest {
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
        let payload = boule::consensus::validator_rotation::ValidatorKeyRotation {
            validator: [1u8; 32],
            new_pubkey: [2u8; 32],
            v_eff: boule::consensus::View(11),
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
        assert!(matches!(cfg, boule::config::IdentityConfig::File { .. }));
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
