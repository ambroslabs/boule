use std::path::PathBuf;

use clap::{Args, Subcommand};

use boule_consensus::validator_rotation::{
    OperatorKeyRotationRequest, OperatorRecoveryRequest, RotationProposeRequest,
    build_operator_key_rotation_envelope, build_operator_recovery_envelope,
    build_rotation_envelope,
};
use boule_core::identity::node_id_to_base58;

use super::shared::resolve_config_path;

#[derive(Subcommand)]
pub enum RotationCmd {
    Propose(RotationProposeArgs),

    ProposeOperatorRecovery(OperatorRecoveryArgs),

    ProposeOperatorKeyRotation(OperatorKeyRotationArgs),

    HotRotate(HotRotateArgs),
}

#[derive(Args)]
pub struct HotRotateArgs {
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    api_url: String,

    #[arg(long, default_value = "file")]
    new_key_backend: String,

    #[arg(long)]
    new_key_path: Option<PathBuf>,

    #[arg(long)]
    new_key_passphrase_env: Option<String>,

    #[arg(long = "v-eff")]
    v_eff: Option<u64>,
}

pub(crate) async fn handle_hot_rotate(args: HotRotateArgs) -> anyhow::Result<()> {
    use boule_node::admin_api::{RotateKeyRequest, RotateKeyResponse};

    let req = RotateKeyRequest {
        new_key_backend: args.new_key_backend,
        new_key_path: args.new_key_path,
        new_key_passphrase_env: args.new_key_passphrase_env,
        v_eff: args.v_eff,
    };
    let url = format!("{}/admin/rotate-key", args.api_url.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .post(&url)
        .json(&req)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("POST {url} failed: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("rotate-key request rejected ({status}): {body}");
    }
    let receipt: RotateKeyResponse = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("decoding rotate-key response failed: {e}"))?;
    println!("{}", serde_json::to_string_pretty(&receipt)?);
    eprintln!(
        "hot rotation scheduled: validator {} will sign under {} at v_eff {} (node view {})",
        receipt.validator, receipt.new_pubkey, receipt.v_eff, receipt.current_view,
    );
    eprintln!(
        "the rotation tx has been admitted to the node's mempool; it takes effect once committed \
         and the boundary at v_eff {} is reached",
        receipt.v_eff,
    );
    Ok(())
}

#[derive(Args)]
pub struct RotationProposeArgs {
    #[arg(short = 'c', long = "config")]
    config_path: Option<PathBuf>,

    #[arg(long)]
    new_key_backend: String,

    #[arg(long)]
    new_key_path: Option<PathBuf>,

    #[arg(long)]
    new_key_passphrase_env: Option<String>,

    #[arg(long)]
    new_bls_key_backend: Option<String>,

    #[arg(long)]
    new_bls_key_path: Option<PathBuf>,

    #[arg(long = "v-eff")]
    v_eff: u64,
}

pub(crate) fn handle_propose(args: RotationProposeArgs) -> anyhow::Result<()> {
    let req = RotationProposeRequest {
        config_path: Some(resolve_config_path(args.config_path)?),
        new_key_backend: Some(args.new_key_backend),
        new_key_path: args.new_key_path,
        new_key_passphrase_env: args.new_key_passphrase_env,
        new_bls_key_backend: args.new_bls_key_backend,
        new_bls_key_path: args.new_bls_key_path,
        v_eff: Some(args.v_eff),
    };
    let outcome = build_rotation_envelope(&req)?;
    let bytes = outcome.envelope.encode_command();
    println!("{}", hex::encode(&bytes));
    eprintln!(
        "rotation built: validator={} new_pubkey={} v_eff={} bls_chain={}",
        node_id_to_base58(&outcome.envelope.payload.validator),
        node_id_to_base58(&outcome.envelope.payload.new_pubkey),
        outcome.envelope.payload.v_eff.0,
        outcome.bls_chain,
    );
    eprintln!(
        "submit the hex above into a validator's mempool to propose the rotation \
         (no admin RPC yet; route is operator-specific)"
    );
    Ok(())
}

#[derive(Args)]
pub struct OperatorRecoveryArgs {
    #[arg(short = 'c', long = "config")]
    config_path: Option<PathBuf>,

    #[arg(long)]
    validator: String,

    #[arg(long)]
    operator_key_backend: String,

    #[arg(long)]
    operator_key_path: Option<PathBuf>,

    #[arg(long)]
    operator_key_passphrase_env: Option<String>,

    #[arg(long)]
    new_key_backend: String,

    #[arg(long)]
    new_key_path: Option<PathBuf>,

    #[arg(long)]
    new_key_passphrase_env: Option<String>,

    #[arg(long)]
    new_bls_key_backend: Option<String>,

    #[arg(long)]
    new_bls_key_path: Option<PathBuf>,

    #[arg(long = "v-eff")]
    v_eff: u64,
}

pub(crate) fn handle_propose_operator_recovery(args: OperatorRecoveryArgs) -> anyhow::Result<()> {
    let req = OperatorRecoveryRequest {
        config_path: Some(resolve_config_path(args.config_path)?),
        validator: Some(args.validator),
        operator_key_backend: Some(args.operator_key_backend),
        operator_key_path: args.operator_key_path,
        operator_key_passphrase_env: args.operator_key_passphrase_env,
        new_key_backend: Some(args.new_key_backend),
        new_key_path: args.new_key_path,
        new_key_passphrase_env: args.new_key_passphrase_env,
        new_bls_key_backend: args.new_bls_key_backend,
        new_bls_key_path: args.new_bls_key_path,
        v_eff: Some(args.v_eff),
    };
    let outcome = build_operator_recovery_envelope(&req)?;
    let bytes = outcome.envelope.encode_command();
    println!("{}", hex::encode(&bytes));
    eprintln!(
        "operator-recovery built: validator={} new_pubkey={} v_eff={} bls_chain={}",
        node_id_to_base58(&outcome.envelope.payload.validator),
        node_id_to_base58(&outcome.envelope.payload.new_pubkey),
        outcome.envelope.payload.v_eff.0,
        outcome.bls_chain,
    );
    eprintln!(
        "submit the hex above into a validator's mempool; it is authorised by the operator \
         key and needs no old signing key (no admin RPC yet; route is operator-specific)"
    );
    Ok(())
}

#[derive(Args)]
pub struct OperatorKeyRotationArgs {
    #[arg(short = 'c', long = "config")]
    config_path: Option<PathBuf>,

    #[arg(long)]
    validator: String,

    #[arg(long)]
    old_operator_key_backend: String,

    #[arg(long)]
    old_operator_key_path: Option<PathBuf>,

    #[arg(long)]
    old_operator_key_passphrase_env: Option<String>,

    #[arg(long)]
    new_operator_key_backend: String,

    #[arg(long)]
    new_operator_key_path: Option<PathBuf>,

    #[arg(long)]
    new_operator_key_passphrase_env: Option<String>,

    #[arg(long = "v-eff")]
    v_eff: u64,
}

pub(crate) fn handle_propose_operator_key_rotation(
    args: OperatorKeyRotationArgs,
) -> anyhow::Result<()> {
    let req = OperatorKeyRotationRequest {
        config_path: Some(resolve_config_path(args.config_path)?),
        validator: Some(args.validator),
        old_operator_key_backend: Some(args.old_operator_key_backend),
        old_operator_key_path: args.old_operator_key_path,
        old_operator_key_passphrase_env: args.old_operator_key_passphrase_env,
        new_operator_key_backend: Some(args.new_operator_key_backend),
        new_operator_key_path: args.new_operator_key_path,
        new_operator_key_passphrase_env: args.new_operator_key_passphrase_env,
        v_eff: Some(args.v_eff),
    };
    let outcome = build_operator_key_rotation_envelope(&req)?;
    let bytes = outcome.envelope.encode_command();
    println!("{}", hex::encode(&bytes));
    eprintln!(
        "operator-key rotation built: validator={} new_operator_pubkey={} v_eff={}",
        node_id_to_base58(&outcome.envelope.payload.validator),
        node_id_to_base58(&outcome.envelope.payload.new_operator_pubkey),
        outcome.envelope.payload.v_eff.0,
    );
    eprintln!(
        "submit the hex above into a validator's mempool to rotate the operator key \
         (no admin RPC yet; route is operator-specific)"
    );
    Ok(())
}
