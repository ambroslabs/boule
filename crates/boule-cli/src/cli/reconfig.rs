//! `boule reconfig` — build validator-set reconfiguration payloads.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use boule_consensus::View;
use boule_consensus::reconfig::{self, ReconfigCommand};
use boule_core::config;
use boule_core::identity::base58_to_node_id;

#[derive(Subcommand)]
pub(crate) enum ReconfigCmd {
    /// Add a validator to the committee at view `v_eff`.
    AddValidator(ReconfigAddArgs),
    /// Remove a validator from the committee at view `v_eff`.
    RemoveValidator(ReconfigRemoveArgs),
    /// Change a seated validator's voting weight at view `v_eff`.
    ChangeWeight(ReconfigChangeWeightArgs),
}

#[derive(Args)]
pub(crate) struct ReconfigAddArgs {
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
pub(crate) struct ReconfigRemoveArgs {
    /// Validator NodeId to remove (base58).
    #[arg(long)]
    pubkey: String,
    /// View at and after which the removal takes effect.
    #[arg(long = "v-eff")]
    v_eff: u64,
}

#[derive(Args)]
pub(crate) struct ReconfigChangeWeightArgs {
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

pub(crate) fn handle_add(args: ReconfigAddArgs) -> anyhow::Result<()> {
    let node_id = base58_to_node_id(&args.pubkey)
        .map_err(|e| anyhow::anyhow!("--pubkey {:?} is not a valid NodeId: {e}", args.pubkey))?;
    let addr: std::net::SocketAddr = args.addr.parse().map_err(|e| {
        anyhow::anyhow!("--addr {:?} is not a valid socket address: {e}", args.addr)
    })?;
    let v_eff = View(args.v_eff);

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

pub(crate) fn handle_remove(args: ReconfigRemoveArgs) -> anyhow::Result<()> {
    let node_id = base58_to_node_id(&args.pubkey)
        .map_err(|e| anyhow::anyhow!("--pubkey {:?} is not a valid NodeId: {e}", args.pubkey))?;
    let v_eff = View(args.v_eff);
    let payload = ReconfigCommand::build_remove_validator_payload(node_id, v_eff);
    println!("{}", hex::encode(&payload));
    Ok(())
}

pub(crate) fn handle_change_weight(args: ReconfigChangeWeightArgs) -> anyhow::Result<()> {
    let node_id = base58_to_node_id(&args.pubkey)
        .map_err(|e| anyhow::anyhow!("--pubkey {:?} is not a valid NodeId: {e}", args.pubkey))?;
    let v_eff = View(args.v_eff);
    let payload = ReconfigCommand::build_change_weight_payload(node_id, args.weight, v_eff);
    println!("{}", hex::encode(&payload));
    Ok(())
}
