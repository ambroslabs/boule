//! The `boule` command-line interface: a clap-derived command tree with
//! one module per subcommand group, plus a `shared` helper module.

use clap::{Parser, Subcommand};

mod config;
mod endpoint;
#[cfg(feature = "reth")]
mod faucet;
#[cfg(feature = "reth")]
mod genesis;
mod init;
mod key;
mod reconfig;
mod rotation;
#[cfg(feature = "reth")]
mod rpc_proxy;
mod shared;
mod snapshot;
mod start;

/// A peer-to-peer runtime hosting a HotStuff-style BFT consensus node.
#[derive(Parser)]
#[command(name = "boule", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// The reth-free `boule` subcommand tree. The unified `boule` binary
/// (`boule-bundle`) flattens this into its own command enum alongside `node`,
/// so every subcommand here is reachable from the single binary.
#[derive(Subcommand)]
pub enum Command {
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
    /// Build validator endpoint-advertisement payloads (printed as hex).
    #[command(subcommand)]
    Endpoint(endpoint::EndpointCmd),
    /// Generate the reth EL genesis + chain-bound BLS proofs-of-possession.
    #[cfg(feature = "reth")]
    #[command(subcommand)]
    Genesis(genesis::GenesisCmd),
    /// Run the dev/testnet faucet service (reth EL).
    #[cfg(feature = "reth")]
    Faucet(faucet::FaucetArgs),
    /// Run the public eth JSON-RPC proxy in front of a reth node.
    #[cfg(feature = "reth")]
    RpcProxy(rpc_proxy::RpcProxyArgs),
}

/// Parse-and-run entry point for a standalone `boule` invocation.
pub async fn dispatch(cli: Cli) -> anyhow::Result<()> {
    dispatch_command(cli.command).await
}

/// Dispatch a single [`Command`]. Exposed so the unified `boule` binary
/// (`boule-bundle`) can flatten this enum into its own top-level command and
/// route the reth-free subcommands through here.
pub async fn dispatch_command(command: Command) -> anyhow::Result<()> {
    match command {
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
        Command::Reconfig(reconfig::ReconfigCmd::ConsentSign(a)) => {
            reconfig::handle_consent_sign(a)
        }
        Command::Rotation(rotation::RotationCmd::Propose(a)) => rotation::handle_propose(a),
        Command::Rotation(rotation::RotationCmd::ProposeOperatorRecovery(a)) => {
            rotation::handle_propose_operator_recovery(a)
        }
        Command::Rotation(rotation::RotationCmd::ProposeOperatorKeyRotation(a)) => {
            rotation::handle_propose_operator_key_rotation(a)
        }
        Command::Rotation(rotation::RotationCmd::HotRotate(a)) => {
            rotation::handle_hot_rotate(a).await
        }
        Command::Endpoint(endpoint::EndpointCmd::Set(a)) => endpoint::handle_set(a),
        Command::Endpoint(endpoint::EndpointCmd::Add(a)) => endpoint::handle_add(a),
        Command::Endpoint(endpoint::EndpointCmd::Remove(a)) => endpoint::handle_remove(a),
        #[cfg(feature = "reth")]
        Command::Genesis(genesis::GenesisCmd::Dev(a)) => genesis::handle_dev(a),
        #[cfg(feature = "reth")]
        Command::Genesis(genesis::GenesisCmd::BlsPop(a)) => genesis::handle_bls_pop(a),
        #[cfg(feature = "reth")]
        Command::Faucet(a) => faucet::handle(a).await,
        #[cfg(feature = "reth")]
        Command::RpcProxy(a) => rpc_proxy::handle(a).await,
    }
}
