//! `boule reconfig` — build validator-set reconfiguration payloads.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use boule_consensus::View;
use boule_consensus::endpoint_registry::EndpointEntry;
use boule_consensus::reconfig::{self, ReconfigCommand};
use boule_core::config;
use boule_core::identity::base58_to_node_id;

/// Parse `<network_id_base58>@<host:port>` into an [`EndpointEntry`] (#547).
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
pub(crate) enum ReconfigCmd {
    /// Add a validator to the committee at view `v_eff`.
    AddValidator(ReconfigAddArgs),
    /// Remove a validator from the committee at view `v_eff`.
    RemoveValidator(ReconfigRemoveArgs),
    /// Change a seated validator's voting weight at view `v_eff`.
    ChangeWeight(ReconfigChangeWeightArgs),
    /// Sign inbound consent for an add (#548), as the inbound operator.
    /// Prints the hex consent signature to feed into `add-validator
    /// --consent-sig`. An add naming an operator key is rejected at commit
    /// without it.
    ConsentSign(ReconfigConsentSignArgs),
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
    /// Optional operator key (base58, #549): the cold-storage administrative
    /// key that can later rotate this validator's signing key without the old
    /// key (recovery) or rotate itself. Omit to seat with no operator key.
    #[arg(long)]
    operator_pubkey: Option<String>,
    /// Inbound-consent signature (hex, #548), produced by the inbound
    /// operator via `reconfig consent-sign`. Required when `--operator-pubkey`
    /// is set: the add is rejected at commit without a valid consent.
    #[arg(long)]
    consent_sig: Option<String>,
    /// Initial endpoint hint (#547) as `<network_id_base58>@<host:port>`,
    /// repeatable. Seeds the validator's published endpoint list at
    /// registration. When `--operator-pubkey` is set these must match the
    /// `--endpoint`s the consent was signed over, or the add is rejected.
    #[arg(long = "endpoint")]
    endpoints: Vec<String>,
    /// Config path; enables the chain `signature_scheme` cross-check.
    #[arg(short = 'c', long = "config")]
    config_path: Option<PathBuf>,
}

#[derive(Args)]
pub(crate) struct ReconfigConsentSignArgs {
    /// NodeId (base58) of the validator being admitted — the same `--pubkey`
    /// the add will carry.
    #[arg(long)]
    pubkey: String,
    /// Validator socket address (must match the add's `--addr`).
    #[arg(long)]
    addr: String,
    /// Effective view (must match the add's `--v-eff`).
    #[arg(long = "v-eff")]
    v_eff: u64,
    /// Voting weight (must match the add's `--weight`).
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    weight: u64,
    /// Hex `<pubkey>:<pop>` proof-of-possession file (BLS chains; must match
    /// the add's BLS identity).
    #[arg(long, conflicts_with = "bls_key_file")]
    bls_pop_file: Option<PathBuf>,
    /// BlsKeyFile to derive the PoP from locally (BLS chains).
    #[arg(long)]
    bls_key_file: Option<PathBuf>,
    /// Operator key backend holding the signing authority: file or
    /// encrypted-file. Must already exist.
    #[arg(long)]
    operator_key_backend: String,
    /// Path to the operator key.
    #[arg(long)]
    operator_key_path: Option<PathBuf>,
    /// Env var holding the operator key's passphrase (encrypted-file).
    #[arg(long)]
    operator_key_passphrase_env: Option<String>,
    /// Initial endpoint hint (#547) as `<network_id_base58>@<host:port>`,
    /// repeatable. Must match the `--endpoint`s the `add-validator` will
    /// carry — the consent signature binds them.
    #[arg(long = "endpoint")]
    endpoints: Vec<String>,
    /// Config path — required: the consent pre-image binds the chain_id.
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
    let operator_pubkey = args
        .operator_pubkey
        .as_deref()
        .map(|s| {
            base58_to_node_id(s)
                .map_err(|e| anyhow::anyhow!("--operator-pubkey {s:?} is not a valid NodeId: {e}"))
        })
        .transpose()?;

    // #548: an add naming an operator key must carry that operator's
    // inbound-consent signature, or the chain rejects it at commit. Decode
    // the hex `--consent-sig` (produced by `reconfig consent-sign`) and
    // fail fast on the obvious mismatch rather than emitting a payload the
    // chain will silently drop.
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

/// Decode an optional hex inbound-consent signature into a fixed 64-byte
/// array, with clear errors on bad hex or wrong length.
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
