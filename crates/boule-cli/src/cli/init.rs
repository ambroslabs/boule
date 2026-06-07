//! `boule init` — bootstrap a node.

use std::path::PathBuf;

use clap::Args;
use tracing::info;

use boule_core::config;
use boule_core::identity::KeyProvider;
use boule_core::identity::node_id_to_base58;

use super::shared::resolve_config_path;

#[derive(Args)]
pub(crate) struct InitArgs {
    /// Config file path (default: platform-specific location).
    #[arg(short = 'c', long = "config")]
    config_path: Option<PathBuf>,
}

pub(crate) fn handle(args: InitArgs) -> anyhow::Result<()> {
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
        config.validate(&net_id.node_id()?)?;
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
            println!(
                "{slot} key already provisioned: NodeId = {}",
                node_id_to_base58(&id.node_id()?)
            );
        }
        None => {
            if provider.is_provisioning_capable() {
                let new_id = provider.load_or_init()?;
                println!(
                    "provisioned new {slot} key: NodeId = {}",
                    node_id_to_base58(&new_id.node_id()?)
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
