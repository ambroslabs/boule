//! `boule key` — identity-key management.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use boule::config;

use super::shared::resolve_config_path;

#[derive(Subcommand)]
pub(crate) enum KeyCmd {
    /// Migrate the node key between identity backends. Reads the current
    /// `[node.identity]` from the config and provisions the destination.
    Migrate(MigrateArgs),
}

#[derive(Args)]
pub(crate) struct MigrateArgs {
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

pub(crate) fn handle_migrate(args: MigrateArgs) -> anyhow::Result<()> {
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
