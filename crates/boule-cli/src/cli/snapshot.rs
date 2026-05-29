//! `boule snapshot` — export/import consensus snapshots.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use boule_consensus::replication::snapshot;
use boule_core::config;

use super::shared::resolve_config_path;

#[derive(Subcommand)]
pub(crate) enum SnapshotCmd {
    /// Dump a snapshot into a portable directory (manifest.bin + chunks).
    Export(SnapshotExportArgs),
    /// Load a directory produced by `snapshot export` into local storage.
    Import(SnapshotImportArgs),
}

#[derive(Args)]
pub(crate) struct SnapshotExportArgs {
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
pub(crate) struct SnapshotImportArgs {
    /// Config file path (default: platform-specific location).
    #[arg(short = 'c', long = "config")]
    config_path: Option<PathBuf>,
    /// Input directory, as produced by `snapshot export`.
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
