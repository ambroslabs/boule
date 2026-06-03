//! The `boule` command-line interface: a clap-derived command tree with
//! one module per subcommand group, plus a `shared` helper module.

use clap::{Parser, Subcommand};

mod config;
mod init;
mod key;
mod reconfig;
mod rotation;
mod shared;
mod snapshot;
mod start;

/// A peer-to-peer runtime hosting a HotStuff-style BFT consensus node.
#[derive(Parser)]
#[command(name = "boule", version, about, long_about = None)]
pub(crate) struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Bootstrap a node: write a starter config if missing, provision the
    /// node key, ensure storage_dir exists, and print the resulting NodeId.
    Init(init::InitArgs),
    /// Run the node. Refuses to start if no key has been provisioned.
    Start(start::StartArgs),
    /// Manage the node's identity key.
    #[command(subcommand)]
    Key(key::KeyCmd),
    /// Print or edit the node's effective configuration.
    Config(config::ConfigArgs),
    /// Export or import consensus snapshots.
    #[command(subcommand)]
    Snapshot(snapshot::SnapshotCmd),
    /// Build validator-set reconfiguration payloads (printed as hex).
    #[command(subcommand)]
    Reconfig(reconfig::ReconfigCmd),
    /// Build validator key-rotation payloads (printed as hex).
    #[command(subcommand)]
    Rotation(rotation::RotationCmd),
}

pub(crate) async fn dispatch(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Init(a) => init::handle(a),
        Command::Start(a) => start::handle(a).await,
        Command::Key(key::KeyCmd::Migrate(a)) => key::handle_migrate(a),
        Command::Config(a) => config::handle(a),
        Command::Snapshot(snapshot::SnapshotCmd::Export(a)) => snapshot::handle_export(a),
        Command::Snapshot(snapshot::SnapshotCmd::Import(a)) => snapshot::handle_import(a),
        Command::Reconfig(reconfig::ReconfigCmd::AddValidator(a)) => reconfig::handle_add(a),
        Command::Reconfig(reconfig::ReconfigCmd::RemoveValidator(a)) => reconfig::handle_remove(a),
        Command::Reconfig(reconfig::ReconfigCmd::ChangeWeight(a)) => {
            reconfig::handle_change_weight(a)
        }
        Command::Rotation(rotation::RotationCmd::Propose(a)) => rotation::handle_propose(a),
        Command::Rotation(rotation::RotationCmd::ProposeOperatorRecovery(a)) => {
            rotation::handle_propose_operator_recovery(a)
        }
    }
}
