use std::path::PathBuf;

use clap::{Args, Subcommand};

use boule_consensus::View;
use boule_consensus::endpoint_registry::EndpointEntry;
use boule_consensus::reconfig::{self, ReconfigCommand};
use boule_core::config;
use boule_core::identity::base58_to_node_id;

fn parse_endpoint(s: &str) -> anyhow::Result<EndpointEntry> {
    let (id, addr) = s.split_once('@').ok_or_else(|| {
        anyhow::anyhow!("--endpoint {s:?} must be <network_id_base58>@<host:port>")
    })?;
    let network_id = base58_to_node_id(id)
        .map_err(|e| anyhow::anyhow!("--endpoint network_id {id:?} is not a valid NodeId: {e}"))?;
    let network_address = addr
        .parse()
        .map_err(|e| anyhow::anyhow!("--endpoint address {addr:?} is not a socket address: {e}"))?;
    Ok(EndpointEntry {
        network_id,
        network_address,
    })
}

#[derive(Subcommand)]
pub enum ReconfigCmd {
    AddValidator(ReconfigAddArgs),

    RemoveValidator(ReconfigRemoveArgs),

    ChangeWeight(ReconfigChangeWeightArgs),

    ConsentSign(ReconfigConsentSignArgs),
}

#[derive(Args)]
pub struct ReconfigAddArgs {
    #[arg(long)]
    pubkey: String,

    #[arg(long)]
    addr: String,

    #[arg(long = "v-eff")]
    v_eff: u64,

    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    weight: u64,

    #[arg(long, conflicts_with = "bls_key_file")]
    bls_pop_file: Option<PathBuf>,

    #[arg(long)]
    bls_key_file: Option<PathBuf>,

    #[arg(long)]
    operator_pubkey: Option<String>,

    #[arg(long)]
    consent_sig: Option<String>,

    #[arg(long = "endpoint")]
    endpoints: Vec<String>,

    #[arg(short = 'c', long = "config")]
    config_path: Option<PathBuf>,
}

#[derive(Args)]
pub struct ReconfigConsentSignArgs {
    #[arg(long)]
    pubkey: String,

    #[arg(long)]
    addr: String,

    #[arg(long = "v-eff")]
    v_eff: u64,

    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    weight: u64,

    #[arg(long, conflicts_with = "bls_key_file")]
    bls_pop_file: Option<PathBuf>,

    #[arg(long)]
    bls_key_file: Option<PathBuf>,

    #[arg(long)]
    operator_key_backend: String,

    #[arg(long)]
    operator_key_path: Option<PathBuf>,

    #[arg(long)]
    operator_key_passphrase_env: Option<String>,

    #[arg(long = "endpoint")]
    endpoints: Vec<String>,

    #[arg(short = 'c', long = "config")]
    config_path: Option<PathBuf>,
}

#[derive(Args)]
pub struct ReconfigRemoveArgs {
    #[arg(long)]
    pubkey: String,

    #[arg(long = "v-eff")]
    v_eff: u64,
}

#[derive(Args)]
pub struct ReconfigChangeWeightArgs {
    #[arg(long)]
    pubkey: String,

    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    weight: u64,

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
    let operator_pubkey = args
        .operator_pubkey
        .as_deref()
        .map(|s| {
            base58_to_node_id(s)
                .map_err(|e| anyhow::anyhow!("--operator-pubkey {s:?} is not a valid NodeId: {e}"))
        })
        .transpose()?;

    let consent_sig = decode_consent_sig(args.consent_sig.as_deref())?;
    if operator_pubkey.is_some() && consent_sig.is_none() {
        anyhow::bail!(
            "--operator-pubkey is set but --consent-sig is missing: an operator-keyed add is \
             rejected at commit without the inbound operator's consent. Produce it with \
             `reconfig consent-sign` (matching --pubkey/--addr/--v-eff/--weight) and pass the \
             hex via --consent-sig.",
        );
    }
    if operator_pubkey.is_none() && consent_sig.is_some() {
        anyhow::bail!(
            "--consent-sig was supplied without --operator-pubkey; consent is only meaningful \
             for an add that names an operator key.",
        );
    }

    let initial_endpoints = args
        .endpoints
        .iter()
        .map(|s| parse_endpoint(s))
        .collect::<anyhow::Result<Vec<_>>>()?;

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
        operator_pubkey,
        consent_sig,
        initial_endpoints,
    )?;
    println!("{}", hex::encode(&payload));
    Ok(())
}

fn decode_consent_sig(hex_sig: Option<&str>) -> anyhow::Result<Option<[u8; 64]>> {
    let Some(s) = hex_sig else { return Ok(None) };
    let bytes = hex::decode(s.trim())
        .map_err(|e| anyhow::anyhow!("--consent-sig is not valid hex: {e}"))?;
    let arr: [u8; 64] = bytes.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "--consent-sig must be a 64-byte Ed25519 signature (128 hex chars); got {} bytes",
            bytes.len(),
        )
    })?;
    Ok(Some(arr))
}

pub(crate) fn handle_consent_sign(args: ReconfigConsentSignArgs) -> anyhow::Result<()> {
    use boule_core::identity::node_id_to_base58;

    let node_id = base58_to_node_id(&args.pubkey)
        .map_err(|e| anyhow::anyhow!("--pubkey {:?} is not a valid NodeId: {e}", args.pubkey))?;
    let addr: std::net::SocketAddr = args.addr.parse().map_err(|e| {
        anyhow::anyhow!("--addr {:?} is not a valid socket address: {e}", args.addr)
    })?;

    let initial_endpoints = args
        .endpoints
        .iter()
        .map(|s| parse_endpoint(s))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let req = reconfig::ReconfigConsentSignRequest {
        config_path: Some(super::shared::resolve_config_path(args.config_path)?),
        node_id,
        addr: Some(addr),
        weight: args.weight,
        v_eff: args.v_eff,
        bls_pop_file: args.bls_pop_file,
        bls_key_file: args.bls_key_file,
        operator_key_backend: Some(args.operator_key_backend),
        operator_key_path: args.operator_key_path,
        operator_key_passphrase_env: args.operator_key_passphrase_env,
        initial_endpoints,
    };
    let (sig, operator_pubkey) = reconfig::build_add_consent_signature(&req)?;
    println!("{}", hex::encode(sig));
    eprintln!(
        "inbound consent signed by operator {} for validator {} (addr {}, weight {}, v_eff {})",
        node_id_to_base58(&operator_pubkey),
        node_id_to_base58(&node_id),
        addr,
        args.weight,
        args.v_eff,
    );
    eprintln!(
        "pass the hex above to `reconfig add-validator --consent-sig <hex>` with matching \
         --pubkey/--addr/--v-eff/--weight and --operator-pubkey {}",
        node_id_to_base58(&operator_pubkey),
    );
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
