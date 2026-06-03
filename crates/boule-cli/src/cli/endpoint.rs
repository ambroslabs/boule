//! `boule endpoint` — build validator endpoint-advertisement payloads (#546),
//! printed as hex to pipe into a validator's mempool (same route as
//! `reconfig` / `rotation` payloads; no admin RPC yet).

use std::path::PathBuf;

use clap::{Args, Subcommand};

use boule_consensus::endpoint_registry::{
    EndpointEntry, EndpointOp, EndpointPublishRequest, build_endpoint_command,
};
use boule_core::identity::{base58_to_node_id, node_id_to_base58};

use super::shared::resolve_config_path;

#[derive(Subcommand)]
pub(crate) enum EndpointCmd {
    /// Replace the validator's published endpoint list.
    Set(EndpointEntriesArgs),
    /// Append entries to the validator's published list.
    Add(EndpointEntriesArgs),
    /// Drop entries (by `network_id`) from the validator's list.
    Remove(EndpointRemoveArgs),
}

#[derive(Args)]
pub(crate) struct EndpointEntriesArgs {
    /// Config file path (default: platform-specific location). The
    /// validator's consensus key is loaded from it to sign the command.
    #[arg(short = 'c', long = "config")]
    config_path: Option<PathBuf>,
    /// Per-validator sequence number. Must strictly exceed the validator's
    /// last-applied endpoint `seq`, or the chain drops the command at commit.
    #[arg(long)]
    seq: u64,
    /// An entry as `<network_id_base58>@<host:port>`. Repeatable.
    #[arg(long = "entry", required = true)]
    entries: Vec<String>,
}

#[derive(Args)]
pub(crate) struct EndpointRemoveArgs {
    /// Config file path (default: platform-specific location).
    #[arg(short = 'c', long = "config")]
    config_path: Option<PathBuf>,
    /// Per-validator sequence number (must strictly increase).
    #[arg(long)]
    seq: u64,
    /// A `network_id` (base58) to drop. Repeatable.
    #[arg(long = "network-id", required = true)]
    network_ids: Vec<String>,
}

/// Parse `<network_id_base58>@<host:port>` into an [`EndpointEntry`].
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_entry_round_trips() {
        let id = node_id_to_base58(&[7u8; 32]);
        let e = parse_entry(&format!("{id}@10.0.0.1:9000")).unwrap();
        assert_eq!(e.network_id, [7u8; 32]);
        assert_eq!(e.network_address, "10.0.0.1:9000".parse().unwrap());
    }

    #[test]
    fn parse_entry_rejects_missing_at() {
        assert!(parse_entry("deadbeef-no-at").is_err());
    }

    #[test]
    fn parse_entry_rejects_bad_address() {
        let id = node_id_to_base58(&[7u8; 32]);
        assert!(parse_entry(&format!("{id}@not-an-addr")).is_err());
    }
}
