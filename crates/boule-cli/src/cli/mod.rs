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

#[derive(Parser)]
#[command(name = "boule", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    Init(init::InitArgs),

    Start(start::StartArgs),

    #[command(subcommand)]
    Key(key::KeyCmd),

    Config(config::ConfigArgs),

    #[command(subcommand)]
    Snapshot(snapshot::SnapshotCmd),

    #[command(subcommand)]
    Reconfig(reconfig::ReconfigCmd),

    #[command(subcommand)]
    Rotation(rotation::RotationCmd),

    #[command(subcommand)]
    Endpoint(endpoint::EndpointCmd),

    #[cfg(feature = "reth")]
    #[command(subcommand)]
    Genesis(genesis::GenesisCmd),

    #[cfg(feature = "reth")]
    Faucet(faucet::FaucetArgs),

    #[cfg(feature = "reth")]
    RpcProxy(rpc_proxy::RpcProxyArgs),
}

pub async fn dispatch(cli: Cli) -> anyhow::Result<()> {
    dispatch_command(cli.command).await
}

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
