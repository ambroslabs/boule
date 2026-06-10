use std::path::PathBuf;

use clap::{Args, Subcommand};

use boule_consensus::replication::snapshot;
use boule_core::config;

use super::shared::resolve_config_path;

#[derive(Subcommand)]
pub enum SnapshotCmd {
    Export(SnapshotExportArgs),

    Import(SnapshotImportArgs),
}

#[derive(Args)]
pub struct SnapshotExportArgs {
    #[arg(short = 'c', long = "config")]
    config_path: Option<PathBuf>,

    #[arg(long)]
    height: Option<u64>,

    #[arg(short = 'o', long)]
    out: PathBuf,
}

#[derive(Args)]
pub struct SnapshotImportArgs {
    #[arg(short = 'c', long = "config")]
    config_path: Option<PathBuf>,

    #[arg(short = 'i', long = "in")]
    in_dir: PathBuf,
}

pub(crate) fn handle_export(args: SnapshotExportArgs) -> anyhow::Result<()> {
    let out_dir = args.out;
    let config_path = resolve_config_path(args.config_path)?;
    let config = config::load(&config_path)?;
    let store = snapshot::open_snapshot_store(&config)?;
    let manifest = snapshot::export_snapshot(&store, args.height, &out_dir)?;
    println!(
        "exported snapshot height={} view={} chunks={} into {}",
        manifest.height,
        manifest.view,
        manifest.chunk_count,
        out_dir.display(),
    );
    Ok(())
}

pub(crate) fn handle_import(args: SnapshotImportArgs) -> anyhow::Result<()> {
    let in_dir = args.in_dir;
    let config_path = resolve_config_path(args.config_path)?;
    let config = config::load(&config_path)?;
    let store = snapshot::open_snapshot_store(&config)?;
    let manifest = snapshot::import_snapshot(&store, &in_dir)?;
    println!(
        "imported snapshot height={} view={} chunks={} into consensus storage",
        manifest.height, manifest.view, manifest.chunk_count,
    );
    Ok(())
}
