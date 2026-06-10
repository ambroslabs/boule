use std::path::PathBuf;

use clap::{Args, Subcommand};

use boule_consensus::endpoint_registry::{
    EndpointEntry, EndpointOp, EndpointPublishRequest, build_endpoint_command,
};
use boule_core::identity::{base58_to_node_id, node_id_to_base58};

use super::shared::resolve_config_path;

#[derive(Subcommand)]
pub enum EndpointCmd {
    Set(EndpointEntriesArgs),

    Add(EndpointEntriesArgs),

    Remove(EndpointRemoveArgs),
}

#[derive(Args)]
pub struct EndpointEntriesArgs {
    #[arg(short = 'c', long = "config")]
    config_path: Option<PathBuf>,

    #[arg(long)]
    seq: u64,

    #[arg(long = "entry", required = true)]
    entries: Vec<String>,
}

#[derive(Args)]
pub struct EndpointRemoveArgs {
    #[arg(short = 'c', long = "config")]
    config_path: Option<PathBuf>,

    #[arg(long)]
    seq: u64,

    #[arg(long = "network-id", required = true)]
    network_ids: Vec<String>,
}

fn parse_entry(s: &str) -> anyhow::Result<EndpointEntry> {
    let (id, addr) = s
        .split_once('@')
        .ok_or_else(|| anyhow::anyhow!("--entry {s:?} must be <network_id_base58>@<host:port>"))?;
    let network_id = base58_to_node_id(id)
        .map_err(|e| anyhow::anyhow!("--entry network_id {id:?} is not a valid NodeId: {e}"))?;
    let network_address = addr
        .parse()
        .map_err(|e| anyhow::anyhow!("--entry address {addr:?} is not a socket address: {e}"))?;
    Ok(EndpointEntry {
        network_id,
        network_address,
    })
}

fn emit(config_path: Option<PathBuf>, seq: u64, op: EndpointOp) -> anyhow::Result<()> {
    let req = EndpointPublishRequest {
        config_path: resolve_config_path(config_path)?,
        seq,
        op,
    };
    let signed = build_endpoint_command(&req)?;
    println!("{}", hex::encode(signed.encode_command()));
    eprintln!(
        "endpoint command built: validator={} seq={}",
        node_id_to_base58(&signed.payload.validator),
        signed.payload.seq,
    );
    eprintln!(
        "submit the hex above into a validator's mempool to publish the change \
         (no admin RPC yet; route is operator-specific)"
    );
    Ok(())
}

pub(crate) fn handle_set(args: EndpointEntriesArgs) -> anyhow::Result<()> {
    let entries = args
        .entries
        .iter()
        .map(|s| parse_entry(s))
        .collect::<anyhow::Result<Vec<_>>>()?;
    emit(args.config_path, args.seq, EndpointOp::Set(entries))
}

pub(crate) fn handle_add(args: EndpointEntriesArgs) -> anyhow::Result<()> {
    let entries = args
        .entries
        .iter()
        .map(|s| parse_entry(s))
        .collect::<anyhow::Result<Vec<_>>>()?;
    emit(args.config_path, args.seq, EndpointOp::Add(entries))
}

pub(crate) fn handle_remove(args: EndpointRemoveArgs) -> anyhow::Result<()> {
    let ids = args
        .network_ids
        .iter()
        .map(|s| {
            base58_to_node_id(s)
                .map_err(|e| anyhow::anyhow!("--network-id {s:?} is not a valid NodeId: {e}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    emit(args.config_path, args.seq, EndpointOp::Remove(ids))
}
