use std::path::PathBuf;

use clap::{Args, Subcommand};

use boule_core::config;

use super::shared::resolve_config_path;

#[derive(Subcommand)]
pub enum KeyCmd {
    Migrate(MigrateArgs),
}

#[derive(Args)]
pub struct MigrateArgs {
    #[arg(short = 'c', long = "config")]
    config_path: Option<PathBuf>,

    #[arg(long)]
    to: String,

    #[arg(long)]
    path: Option<PathBuf>,

    #[arg(long)]
    passphrase_env: Option<String>,

    #[arg(long)]
    service: Option<String>,

    #[arg(long)]
    account: Option<String>,

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
