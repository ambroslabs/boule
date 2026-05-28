use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand};
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
async fn main() {
    init_tracing();
    if let Err(e) = dispatch(Cli::parse()).await {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

async fn dispatch(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Init(a) => handle_init(a),
        Command::Start(a) => handle_start(a).await,
        Command::Key(KeyCmd::Migrate(a)) => handle_key_migrate(a),
        Command::Config(a) => handle_config(a),
        Command::Snapshot(SnapshotCmd::Export(a)) => handle_snapshot_export(a),
        Command::Snapshot(SnapshotCmd::Import(a)) => handle_snapshot_import(a),
        Command::Reconfig(ReconfigCmd::AddValidator(a)) => handle_reconfig_add(a),
        Command::Reconfig(ReconfigCmd::RemoveValidator(a)) => handle_reconfig_remove(a),
        Command::Reconfig(ReconfigCmd::ChangeWeight(a)) => handle_reconfig_change_weight(a),
        Command::Rotation(RotationCmd::Propose(a)) => handle_rotation_propose(a),
    }
}

/// A peer-to-peer runtime hosting a HotStuff-style BFT consensus node.
#[derive(Parser)]
#[command(name = "boule", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Bootstrap a node: write a starter config if missing, provision the
    /// node key, ensure storage_dir exists, and print the resulting NodeId.
    Init(InitArgs),
    /// Run the node. Refuses to start if no key has been provisioned.
    Start(StartArgs),
    /// Manage the node's identity key.
    #[command(subcommand)]
    Key(KeyCmd),
    /// Print or edit the node's effective configuration.
    Config(ConfigArgs),
    /// Export or import consensus snapshots.
    #[command(subcommand)]
    Snapshot(SnapshotCmd),
    /// Build validator-set reconfiguration payloads (printed as hex).
    #[command(subcommand)]
    Reconfig(ReconfigCmd),
    /// Build validator key-rotation payloads (printed as hex).
    #[command(subcommand)]
    Rotation(RotationCmd),
}

/// Shared `--config/-c` flag: path to the node config, defaulting to the
/// platform-specific location when omitted.
#[derive(Args)]
struct InitArgs {
    /// Config file path (default: platform-specific location).
    #[arg(short = 'c', long = "config")]
    config_path: Option<PathBuf>,
}

#[derive(Args)]
struct StartArgs {
    /// Config file path (default: platform-specific location).
    #[arg(short = 'c', long = "config")]
    config_path: Option<PathBuf>,
    /// Fail closed on insecure defaults (also set by BOULE_ENV=production).
    #[arg(long)]
    production: bool,
    /// Permit a key file with group/other-readable permissions.
    #[arg(long = "allow-insecure-key-perms")]
    allow_insecure_perms: bool,
}

#[derive(Subcommand)]
enum KeyCmd {
    /// Migrate the node key between identity backends. Reads the current
    /// `[node.identity]` from the config and provisions the destination.
    Migrate(MigrateArgs),
}

#[derive(Args)]
struct MigrateArgs {
    /// Config file path (default: platform-specific location).
    #[arg(short = 'c', long = "config")]
    config_path: Option<PathBuf>,
    /// Destination backend: file, encrypted-file, or keyring.
    #[arg(long)]
    to: String,
    /// Destination path (file / encrypted-file backends).
    #[arg(long)]
    path: Option<PathBuf>,
    /// Env var holding the passphrase (encrypted-file backend).
    #[arg(long)]
    passphrase_env: Option<String>,
    /// Keyring service name (keyring backend; default "boule").
    #[arg(long)]
    service: Option<String>,
    /// Keyring account name (keyring backend).
    #[arg(long)]
    account: Option<String>,
    /// Zeroize and remove a file-backed source key after migrating.
    #[arg(long)]
    delete_source: bool,
}

#[derive(Args)]
struct ConfigArgs {
    /// Config file path (default: platform-specific location).
    #[arg(short = 'c', long = "config")]
    config_path: Option<PathBuf>,
    /// Output format: human, json, or toml. Overrides `[ui] output_format`.
    #[arg(
        short = 'f',
        long,
        value_parser = parse_output_format,
        conflicts_with_all = ["raw", "edit", "print_path"],
    )]
    format: Option<OutputFormat>,
    /// Print the config file as-written, without filling in defaults.
    #[arg(long, group = "config_mode")]
    raw: bool,
    /// Open the config in $EDITOR / $VISUAL and validate the result.
    #[arg(long, group = "config_mode")]
    edit: bool,
    /// Print the resolved config file path and exit.
    #[arg(long = "path", group = "config_mode")]
    print_path: bool,
}

#[derive(Subcommand)]
enum SnapshotCmd {
    /// Dump a snapshot into a portable directory (manifest.bin + chunks).
    Export(SnapshotExportArgs),
    /// Load a directory produced by `snapshot export` into local storage.
    Import(SnapshotImportArgs),
}

#[derive(Args)]
struct SnapshotExportArgs {
    /// Config file path (default: platform-specific location).
    #[arg(short = 'c', long = "config")]
    config_path: Option<PathBuf>,
    /// Snapshot height to export (default: the latest).
    #[arg(long)]
    height: Option<u64>,
    /// Output directory.
    #[arg(short = 'o', long)]
    out: PathBuf,
}

#[derive(Args)]
struct SnapshotImportArgs {
    /// Config file path (default: platform-specific location).
    #[arg(short = 'c', long = "config")]
    config_path: Option<PathBuf>,
    /// Input directory, as produced by `snapshot export`.
    #[arg(short = 'i', long = "in")]
    in_dir: PathBuf,
}

#[derive(Subcommand)]
enum ReconfigCmd {
    /// Add a validator to the committee at view `v_eff`.
    AddValidator(ReconfigAddArgs),
    /// Remove a validator from the committee at view `v_eff`.
    RemoveValidator(ReconfigRemoveArgs),
    /// Change a seated validator's voting weight at view `v_eff`.
    ChangeWeight(ReconfigChangeWeightArgs),
}

#[derive(Args)]
struct ReconfigAddArgs {
    /// New validator NodeId (base58).
    #[arg(long)]
    pubkey: String,
    /// New validator socket address.
    #[arg(long)]
    addr: String,
    /// View at and after which the change takes effect.
    #[arg(long = "v-eff")]
    v_eff: u64,
    /// Voting weight (>= 1; use 1 for an unweighted committee).
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    weight: u64,
    /// Hex `<pubkey>:<pop>` proof-of-possession file (BLS chains).
    #[arg(long, conflicts_with = "bls_key_file")]
    bls_pop_file: Option<PathBuf>,
    /// BlsKeyFile to derive the PoP from locally (BLS chains).
    #[arg(long)]
    bls_key_file: Option<PathBuf>,
    /// Config path; enables the chain `signature_scheme` cross-check.
    #[arg(short = 'c', long = "config")]
    config_path: Option<PathBuf>,
}

#[derive(Args)]
struct ReconfigRemoveArgs {
    /// Validator NodeId to remove (base58).
    #[arg(long)]
    pubkey: String,
    /// View at and after which the removal takes effect.
    #[arg(long = "v-eff")]
    v_eff: u64,
}

#[derive(Args)]
struct ReconfigChangeWeightArgs {
    /// Validator NodeId to reweight (base58).
    #[arg(long)]
    pubkey: String,
    /// New voting weight (>= 1).
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    weight: u64,
    /// View at and after which the new weight takes effect.
    #[arg(long = "v-eff")]
    v_eff: u64,
}

#[derive(Subcommand)]
enum RotationCmd {
    /// Build a validator key-rotation payload, minting the new key(s).
    Propose(RotationProposeArgs),
}

#[derive(Args)]
struct RotationProposeArgs {
    /// Config file path (default: platform-specific location).
    #[arg(short = 'c', long = "config")]
    config_path: Option<PathBuf>,
    /// New consensus key backend: file or encrypted-file.
    #[arg(long)]
    new_key_backend: String,
    /// Path for the new consensus key.
    #[arg(long)]
    new_key_path: Option<PathBuf>,
    /// Env var holding the new key's passphrase (encrypted-file).
    #[arg(long)]
    new_key_passphrase_env: Option<String>,
    /// New BLS key backend (BLS chains; only `file` today).
    #[arg(long)]
    new_bls_key_backend: Option<String>,
    /// Path for the new BLS key (BLS chains).
    #[arg(long)]
    new_bls_key_path: Option<PathBuf>,
    /// View at and after which the rotation takes effect.
    #[arg(long = "v-eff")]
    v_eff: u64,
}

/// Parse a `--format` value into the shared [`OutputFormat`].
fn parse_output_format(s: &str) -> anyhow::Result<OutputFormat> {
    OutputFormat::parse(s)
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

fn handle_init(args: InitArgs) -> anyhow::Result<()> {
    let config_path = resolve_config_path(args.config_path)?;

    if !config_path.exists() {
        config::write_starter_config(&config_path)?;
        println!("wrote starter config to {}", config_path.display());
    } else {
        println!("config already exists at {}", config_path.display());
    }

    let config = config::load(&config_path)?;
    info!("loaded config from {}", config_path.display());

    // `init` runs interactively to bootstrap, so production semantics are off.
    let identity_cfg = config::resolve_and_validate_identity(&config.node, false, false)?;
    println!("network identity backend: {}", identity_cfg.backend_name());

    let provider = config::build_provider(&identity_cfg)?;
    provision_or_report(&*provider, identity_cfg.backend_name(), "network")?;

    // Cross-validate `[[peers]]` against the local NodeId now so a self-id is
    // caught at `init` rather than only surfacing at `start`.
    if let Some(net_id) = provider.try_load()? {
        let tls = boule::p2p::tls::TlsIdentity::from_identity(&net_id)?;
        config.validate(&tls.node_id)?;
    }

    if let Some(val_cfg) = config::resolve_validator_identity(&config.node) {
        println!("validator identity backend: {}", val_cfg.backend_name());
        let val_provider = config::build_provider(&val_cfg)?;
        provision_or_report(&*val_provider, val_cfg.backend_name(), "validator")?;
    }

    // Create storage_dir during `init` so operators learn it's writable
    // before going live, rather than lazily on first `start`.
    if let Some(cons) = config.consensus.as_ref() {
        if let Some(dir) = cons.storage_dir.as_ref() {
            std::fs::create_dir_all(dir).map_err(|e| {
                anyhow::anyhow!("creating consensus storage_dir {}: {e}", dir.display())
            })?;
            println!("consensus storage_dir ready at {}", dir.display());
        }
    }

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

async fn handle_start(args: StartArgs) -> anyhow::Result<()> {
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

fn handle_key_migrate(args: MigrateArgs) -> anyhow::Result<()> {
    let config_path = resolve_config_path(args.config_path)?;
    config::migrate_key(
        &config_path,
        &args.to,
        args.path,
        args.passphrase_env,
        args.service,
        args.account,
        args.delete_source,
    )
}

fn handle_config(args: ConfigArgs) -> anyhow::Result<()> {
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

fn handle_snapshot_export(args: SnapshotExportArgs) -> anyhow::Result<()> {
    let out_dir = args.out;
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

fn handle_snapshot_import(args: SnapshotImportArgs) -> anyhow::Result<()> {
    let in_dir = args.in_dir;
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

fn handle_reconfig_add(args: ReconfigAddArgs) -> anyhow::Result<()> {
    use boule::consensus::reconfig;
    use boule::p2p::tls::base58_to_node_id;

    let node_id = base58_to_node_id(&args.pubkey)
        .map_err(|e| anyhow::anyhow!("--pubkey {:?} is not a valid NodeId: {e}", args.pubkey))?;
    let addr: std::net::SocketAddr = args.addr.parse().map_err(|e| {
        anyhow::anyhow!("--addr {:?} is not a valid socket address: {e}", args.addr)
    })?;
    let v_eff = boule::consensus::View(args.v_eff);

    let config = args
        .config_path
        .as_ref()
        .map(|p| config::load(p))
        .transpose()?;
    let payload = reconfig::build_add_validator_payload(
        config.as_ref(),
        node_id,
        addr,
        v_eff,
        args.weight,
        args.bls_pop_file.as_deref(),
        args.bls_key_file.as_deref(),
    )?;
    println!("{}", hex::encode(&payload));
    Ok(())
}

fn handle_reconfig_remove(args: ReconfigRemoveArgs) -> anyhow::Result<()> {
    use boule::consensus::reconfig::ReconfigCommand;
    use boule::p2p::tls::base58_to_node_id;

    let node_id = base58_to_node_id(&args.pubkey)
        .map_err(|e| anyhow::anyhow!("--pubkey {:?} is not a valid NodeId: {e}", args.pubkey))?;
    let v_eff = boule::consensus::View(args.v_eff);
    let payload = ReconfigCommand::build_remove_validator_payload(node_id, v_eff);
    println!("{}", hex::encode(&payload));
    Ok(())
}

fn handle_reconfig_change_weight(args: ReconfigChangeWeightArgs) -> anyhow::Result<()> {
    use boule::consensus::reconfig::ReconfigCommand;
    use boule::p2p::tls::base58_to_node_id;

    let node_id = base58_to_node_id(&args.pubkey)
        .map_err(|e| anyhow::anyhow!("--pubkey {:?} is not a valid NodeId: {e}", args.pubkey))?;
    let v_eff = boule::consensus::View(args.v_eff);
    let payload = ReconfigCommand::build_change_weight_payload(node_id, args.weight, v_eff);
    println!("{}", hex::encode(&payload));
    Ok(())
}

fn handle_rotation_propose(args: RotationProposeArgs) -> anyhow::Result<()> {
    use boule::consensus::validator_rotation::build_rotation_envelope;
    use boule::p2p::tls::node_id_to_base58;

    let req = RotationProposeRequest {
        config_path: Some(resolve_config_path(args.config_path)?),
        new_key_backend: Some(args.new_key_backend),
        new_key_path: args.new_key_path,
        new_key_passphrase_env: args.new_key_passphrase_env,
        new_bls_key_backend: args.new_bls_key_backend,
        new_bls_key_path: args.new_bls_key_path,
        v_eff: Some(args.v_eff),
    };
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
