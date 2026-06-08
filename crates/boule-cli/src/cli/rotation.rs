//! `boule rotation` — build validator key-rotation payloads.

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
pub(crate) enum RotationCmd {
    /// Build a validator key-rotation payload, minting the new key(s).
    Propose(RotationProposeArgs),
    /// Build an operator-signed signing-key recovery payload (#549): rotate a
    /// validator's signing key authorised by its operator key, without the old
    /// signing key — the recovery-from-loss path for a destroyed signing key.
    ProposeOperatorRecovery(OperatorRecoveryArgs),
    /// Build an operator-key self-rotation payload (#549): rotate a validator's
    /// own operator key, dual-signed by the old and new operator keys.
    ProposeOperatorKeyRotation(OperatorKeyRotationArgs),
    /// Hot-rotate a *running* node's consensus signing key with no restart
    /// (#707): POSTs to the node's `/admin/rotate-key` admin endpoint, which
    /// mints/loads the new key, admits the dual-signed rotation tx, and
    /// schedules the live swap at `v_eff`.
    HotRotate(HotRotateArgs),
}

#[derive(Args)]
pub(crate) struct HotRotateArgs {
    /// Base URL of the running node's HTTP API (where `/admin/rotate-key`
    /// is served). Bind the API to a trusted interface — the endpoint is
    /// unauthenticated.
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    api_url: String,
    /// New consensus key backend: file or encrypted-file. The node mints
    /// the key if absent.
    #[arg(long, default_value = "file")]
    new_key_backend: String,
    /// Path (on the NODE's filesystem) for the new consensus key.
    #[arg(long)]
    new_key_path: Option<PathBuf>,
    /// Env var (on the node) holding the new key's passphrase (encrypted-file).
    #[arg(long)]
    new_key_passphrase_env: Option<String>,
    /// Effective view for the swap. Omit for a safe default; a too-close
    /// value is rejected by the node.
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
pub(crate) struct RotationProposeArgs {
    /// Config file path (default: platform-specific location).
    #[arg(short = 'c', long = "config")]
    config_path: Option<PathBuf>,
    /// New consensus key backend: file or encrypted-file.
    #[arg(long)]
    new_key_backend: String,
    /// Path for the new consensus key.
    #[arg(long)]
    new_key_path: Option<PathBuf>,
    /// Env var holding the new key's passphrase (encrypted-file).
    #[arg(long)]
    new_key_passphrase_env: Option<String>,
    /// New BLS key backend (BLS chains; only `file` today).
    #[arg(long)]
    new_bls_key_backend: Option<String>,
    /// Path for the new BLS key (BLS chains).
    #[arg(long)]
    new_bls_key_path: Option<PathBuf>,
    /// View at and after which the rotation takes effect.
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
pub(crate) struct OperatorRecoveryArgs {
    /// Config file path (default: platform-specific location).
    #[arg(short = 'c', long = "config")]
    config_path: Option<PathBuf>,
    /// Base58 stable id of the validator being recovered (the signing key is
    /// presumed lost, so it can't identify the validator itself).
    #[arg(long)]
    validator: String,
    /// Operator key backend: file or encrypted-file. Must already exist.
    #[arg(long)]
    operator_key_backend: String,
    /// Path to the operator key.
    #[arg(long)]
    operator_key_path: Option<PathBuf>,
    /// Env var holding the operator key's passphrase (encrypted-file).
    #[arg(long)]
    operator_key_passphrase_env: Option<String>,
    /// New consensus signing key backend: file or encrypted-file (minted).
    #[arg(long)]
    new_key_backend: String,
    /// Path for the new consensus signing key.
    #[arg(long)]
    new_key_path: Option<PathBuf>,
    /// Env var holding the new key's passphrase (encrypted-file).
    #[arg(long)]
    new_key_passphrase_env: Option<String>,
    /// New BLS key backend (BLS chains; only `file` today).
    #[arg(long)]
    new_bls_key_backend: Option<String>,
    /// Path for the new BLS key (BLS chains).
    #[arg(long)]
    new_bls_key_path: Option<PathBuf>,
    /// View at and after which the recovery rotation takes effect.
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
pub(crate) struct OperatorKeyRotationArgs {
    /// Config file path (default: platform-specific location).
    #[arg(short = 'c', long = "config")]
    config_path: Option<PathBuf>,
    /// Base58 stable id of the validator whose operator key is rotating.
    #[arg(long)]
    validator: String,
    /// Current operator key backend: file or encrypted-file. Must already exist.
    #[arg(long)]
    old_operator_key_backend: String,
    /// Path to the current operator key.
    #[arg(long)]
    old_operator_key_path: Option<PathBuf>,
    /// Env var holding the current operator key's passphrase (encrypted-file).
    #[arg(long)]
    old_operator_key_passphrase_env: Option<String>,
    /// New operator key backend: file or encrypted-file (minted if absent).
    #[arg(long)]
    new_operator_key_backend: String,
    /// Path for the new operator key.
    #[arg(long)]
    new_operator_key_path: Option<PathBuf>,
    /// Env var holding the new operator key's passphrase (encrypted-file).
    #[arg(long)]
    new_operator_key_passphrase_env: Option<String>,
    /// View at and after which the operator-key rotation takes effect.
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

#[cfg(test)]
mod tests {
    use boule_consensus::validator_rotation::{
        RotationProposeRequest, build_new_identity_config_for_rotation, build_rotation_envelope,
    };
    use boule_core::crypto::bls_key::{BlsKeyFile, BlsKeyProvider as _};
    use boule_core::crypto::sig_scheme::BlsAggregated;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    /// Mint a fresh Ed25519 file-backed validator key and return its
    /// base58-encoded NodeId. Both halves are what the rotation tests
    /// need to write a usable config TOML.
    fn mint_validator_key(path: &Path) -> String {
        use boule_core::crypto::signed::{NodeSigner, Signer as _};
        let cfg = boule_core::config::IdentityConfig::File {
            path: path.to_path_buf(),
            allow_insecure_perms: false,
        };
        let provider = boule_core::config::build_provider(&cfg).unwrap();
        let id = provider.load_or_init().unwrap();
        let signer = NodeSigner::from_identity(&id).unwrap();
        boule_core::identity::node_id_to_base58(&signer.node_id())
    }

    /// Mint a fresh BLS validator pubkey and return `(pubkey_hex, pop_hex)`
    /// suitable for a `[[consensus.validators_bls]]` table entry. The PoP is a
    /// 96-byte placeholder: the rotation tool under test never verifies the
    /// genesis PoP (it derives and verifies its own), only the pubkey feeds the
    /// chain_id, so a bogus PoP is sufficient for these scheme-agnostic tests.
    fn bls_validator_entry(seed: u8) -> (String, String) {
        let mut ikm = [0u8; 32];
        ikm[0] = seed;
        let (_sk, pk) = BlsAggregated::keygen(&ikm).unwrap();
        (hex::encode(pk), hex::encode([0u8; 96]))
    }

    fn write_bls_chain_config(
        config_path: &Path,
        current_key_path: &Path,
        validator_b58: &str,
        validator_bls_pubkey_hex: &str,
        validator_bls_pop_hex: &str,
    ) {
        let text = format!(
            "[node]\n\
             listen_addr = \"127.0.0.1:7000\"\n\n\
             [node.identity]\n\
             backend = \"file\"\n\
             path = \"{key}\"\n\n\
             [node.validator_identity]\n\
             backend = \"file\"\n\
             path = \"{key}\"\n\n\
             [api]\n\
             listen_addr = \"127.0.0.1:8000\"\n\n\
             [consensus]\n\
             validators = [\"{val}\"]\n\
             signature_scheme = \"bls_aggregated\"\n\n\
             [[consensus.validators_bls]]\n\
             node_id = \"{val}\"\n\
             bls_pubkey = \"{pk}\"\n\
             bls_pop = \"{pop}\"\n",
            key = current_key_path.display(),
            val = validator_b58,
            pk = validator_bls_pubkey_hex,
            pop = validator_bls_pop_hex,
        );
        std::fs::write(config_path, text).unwrap();
    }

    /// #549: end-to-end operator-recovery — a validator whose signing key is
    /// "lost" recovers via its operator key. The minted envelope verifies
    /// under the operator pubkey (not the old signing key) and the chain_id.
    #[test]
    fn operator_recovery_ed25519_builds_envelope_verifiable_under_operator_key() {
        use boule_consensus::validator_rotation::{
            OperatorRecoveryRequest, OperatorSignedRotation, build_operator_recovery_envelope,
        };
        use boule_core::crypto::signed::{NodeSigner, Signer as _};
        use boule_core::identity::base58_to_node_id;

        let dir = TempDir::new().unwrap();
        // The validator's signing key (its base58 == stable id) and the
        // operator key are both minted to disk.
        let validator_key = dir.path().join("validator.key");
        let validator_b58 = mint_validator_key(&validator_key);
        let operator_key = dir.path().join("operator.key");
        let operator_b58 = mint_validator_key(&operator_key);
        let (bls_pk_hex, bls_pop_hex) = bls_validator_entry(0x11);

        // Config declares the operator key for the validator (BLS chain).
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            format!(
                "[node]\n\
                 listen_addr = \"127.0.0.1:7000\"\n\n\
                 [node.identity]\n\
                 backend = \"file\"\n\
                 path = \"{vk}\"\n\n\
                 [api]\n\
                 listen_addr = \"127.0.0.1:8000\"\n\n\
                 [consensus]\n\
                 validators = [\"{val}\"]\n\
                 signature_scheme = \"bls_aggregated\"\n\n\
                 [[consensus.validators_bls]]\n\
                 node_id = \"{val}\"\n\
                 bls_pubkey = \"{pk}\"\n\
                 bls_pop = \"{pop}\"\n\n\
                 [[consensus.validators_operator_keys]]\n\
                 node_id = \"{val}\"\n\
                 operator_pubkey = \"{op}\"\n",
                vk = validator_key.display(),
                val = validator_b58,
                pk = bls_pk_hex,
                pop = bls_pop_hex,
                op = operator_b58,
            ),
        )
        .unwrap();

        let new_key = dir.path().join("new.key");
        let new_bls = dir.path().join("new-bls.key");
        let req = OperatorRecoveryRequest {
            config_path: Some(config_path.clone()),
            validator: Some(validator_b58.clone()),
            operator_key_backend: Some("file".into()),
            operator_key_path: Some(operator_key.clone()),
            operator_key_passphrase_env: None,
            new_key_backend: Some("file".into()),
            new_key_path: Some(new_key.clone()),
            new_key_passphrase_env: None,
            new_bls_key_backend: Some("file".into()),
            new_bls_key_path: Some(new_bls.clone()),
            v_eff: Some(500),
        };
        let outcome = build_operator_recovery_envelope(&req).expect("recovery must succeed");
        assert!(outcome.bls_chain);
        assert!(new_key.exists(), "new signing key must be minted");
        assert!(new_bls.exists(), "new BLS key must be minted");

        let new_id =
            boule_core::config::build_provider(&boule_core::config::IdentityConfig::File {
                path: new_key.clone(),
                allow_insecure_perms: false,
            })
            .unwrap()
            .try_load()
            .unwrap()
            .unwrap();
        let new_signer = NodeSigner::from_identity(&new_id).unwrap();
        let validator_nid = base58_to_node_id(&validator_b58).unwrap();
        let operator_nid = base58_to_node_id(&operator_b58).unwrap();
        assert_eq!(outcome.envelope.payload.validator, validator_nid);
        assert_eq!(outcome.envelope.payload.new_pubkey, new_signer.node_id());
        assert_eq!(outcome.envelope.payload.v_eff.0, 500);

        let cfg = boule_core::config::load(&config_path).unwrap();
        let chain_id =
            boule_consensus::genesis::derive_chain_id(cfg.consensus.as_ref().unwrap()).unwrap();
        // Verifies under the OPERATOR key — the authority — not the old key.
        outcome
            .envelope
            .verify(&operator_nid, &chain_id)
            .expect("envelope must verify under the operator key");

        let bytes = outcome.envelope.encode_command();
        assert!(OperatorSignedRotation::is_operator_rotation_payload(&bytes));
    }

    /// #549: recovery requires the operator key to actually exist — it is the
    /// authority, never minted by the command. A missing operator key errors
    /// (and does not mint the new key behind it).
    #[test]
    fn operator_recovery_errors_when_operator_key_missing() {
        use boule_consensus::validator_rotation::{
            OperatorRecoveryRequest, build_operator_recovery_envelope,
        };

        let dir = TempDir::new().unwrap();
        let validator_key = dir.path().join("validator.key");
        let validator_b58 = mint_validator_key(&validator_key);
        let (bls_pk_hex, bls_pop_hex) = bls_validator_entry(0x22);
        let config_path = dir.path().join("config.toml");
        write_bls_chain_config(
            &config_path,
            &validator_key,
            &validator_b58,
            &bls_pk_hex,
            &bls_pop_hex,
        );

        let missing_operator = dir.path().join("nope-operator.key");
        let new_key = dir.path().join("new.key");
        let new_bls = dir.path().join("new-bls.key");
        let req = OperatorRecoveryRequest {
            config_path: Some(config_path),
            validator: Some(validator_b58),
            operator_key_backend: Some("file".into()),
            operator_key_path: Some(missing_operator),
            operator_key_passphrase_env: None,
            new_key_backend: Some("file".into()),
            new_key_path: Some(new_key.clone()),
            new_key_passphrase_env: None,
            new_bls_key_backend: Some("file".into()),
            new_bls_key_path: Some(new_bls),
            v_eff: Some(500),
        };
        let err = build_operator_recovery_envelope(&req).unwrap_err();
        assert!(
            err.to_string().contains("operator key"),
            "unexpected error: {err}",
        );
    }

    /// #549: end-to-end operator-key self-rotation — the minted envelope is
    /// dual-signed (old + new operator keys) and verifies under the CURRENT
    /// operator key + chain_id.
    #[test]
    fn operator_key_rotation_builds_envelope_verifiable_under_current_operator_key() {
        use boule_consensus::validator_rotation::{
            DualSignedOperatorRotation, OperatorKeyRotationRequest,
            build_operator_key_rotation_envelope,
        };
        use boule_core::crypto::signed::{NodeSigner, Signer as _};
        use boule_core::identity::base58_to_node_id;

        let dir = TempDir::new().unwrap();
        let validator_key = dir.path().join("validator.key");
        let validator_b58 = mint_validator_key(&validator_key);
        let old_operator = dir.path().join("old-operator.key");
        let old_op_b58 = mint_validator_key(&old_operator);
        let (bls_pk_hex, bls_pop_hex) = bls_validator_entry(0x33);

        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            format!(
                "[node]\n\
                 listen_addr = \"127.0.0.1:7000\"\n\n\
                 [node.identity]\n\
                 backend = \"file\"\n\
                 path = \"{vk}\"\n\n\
                 [api]\n\
                 listen_addr = \"127.0.0.1:8000\"\n\n\
                 [consensus]\n\
                 validators = [\"{val}\"]\n\
                 signature_scheme = \"bls_aggregated\"\n\n\
                 [[consensus.validators_bls]]\n\
                 node_id = \"{val}\"\n\
                 bls_pubkey = \"{pk}\"\n\
                 bls_pop = \"{pop}\"\n\n\
                 [[consensus.validators_operator_keys]]\n\
                 node_id = \"{val}\"\n\
                 operator_pubkey = \"{op}\"\n",
                vk = validator_key.display(),
                val = validator_b58,
                pk = bls_pk_hex,
                pop = bls_pop_hex,
                op = old_op_b58,
            ),
        )
        .unwrap();

        let new_operator = dir.path().join("new-operator.key");
        let req = OperatorKeyRotationRequest {
            config_path: Some(config_path.clone()),
            validator: Some(validator_b58.clone()),
            old_operator_key_backend: Some("file".into()),
            old_operator_key_path: Some(old_operator.clone()),
            old_operator_key_passphrase_env: None,
            new_operator_key_backend: Some("file".into()),
            new_operator_key_path: Some(new_operator.clone()),
            new_operator_key_passphrase_env: None,
            v_eff: Some(500),
        };
        let outcome = build_operator_key_rotation_envelope(&req).expect("must succeed");
        assert!(new_operator.exists(), "new operator key must be minted");

        let new_id =
            boule_core::config::build_provider(&boule_core::config::IdentityConfig::File {
                path: new_operator.clone(),
                allow_insecure_perms: false,
            })
            .unwrap()
            .try_load()
            .unwrap()
            .unwrap();
        let new_signer = NodeSigner::from_identity(&new_id).unwrap();
        let validator_nid = base58_to_node_id(&validator_b58).unwrap();
        let old_op_nid = base58_to_node_id(&old_op_b58).unwrap();
        assert_eq!(outcome.envelope.payload.validator, validator_nid);
        assert_eq!(
            outcome.envelope.payload.new_operator_pubkey,
            new_signer.node_id()
        );
        assert_eq!(outcome.envelope.payload.v_eff.0, 500);

        let cfg = boule_core::config::load(&config_path).unwrap();
        let chain_id =
            boule_consensus::genesis::derive_chain_id(cfg.consensus.as_ref().unwrap()).unwrap();
        // Verifies under the CURRENT operator key (the authorising key).
        outcome
            .envelope
            .verify(&old_op_nid, &chain_id)
            .expect("envelope must verify under the current operator key");

        let bytes = outcome.envelope.encode_command();
        assert!(DualSignedOperatorRotation::is_operator_key_rotation_payload(&bytes));
    }

    /// #549: operator-key rotation requires the *current* operator key to exist
    /// (it authorises). A missing current key errors.
    #[test]
    fn operator_key_rotation_errors_when_current_operator_key_missing() {
        use boule_consensus::validator_rotation::{
            OperatorKeyRotationRequest, build_operator_key_rotation_envelope,
        };

        let dir = TempDir::new().unwrap();
        let validator_key = dir.path().join("validator.key");
        let validator_b58 = mint_validator_key(&validator_key);
        let (bls_pk_hex, bls_pop_hex) = bls_validator_entry(0x44);
        let config_path = dir.path().join("config.toml");
        write_bls_chain_config(
            &config_path,
            &validator_key,
            &validator_b58,
            &bls_pk_hex,
            &bls_pop_hex,
        );

        let missing_old = dir.path().join("nope-old.key");
        let new_op = dir.path().join("new-operator.key");
        let req = OperatorKeyRotationRequest {
            config_path: Some(config_path),
            validator: Some(validator_b58),
            old_operator_key_backend: Some("file".into()),
            old_operator_key_path: Some(missing_old),
            old_operator_key_passphrase_env: None,
            new_operator_key_backend: Some("file".into()),
            new_operator_key_path: Some(new_op),
            new_operator_key_passphrase_env: None,
            v_eff: Some(500),
        };
        let err = build_operator_key_rotation_envelope(&req).unwrap_err();
        assert!(
            err.to_string().contains("current operator key"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn rotation_propose_idempotent_when_new_key_already_exists() {
        // Re-running with a pre-minted `new_key_path` must reload it (not
        // overwrite) and produce a payload pointing at the same pubkey.
        use boule_core::crypto::signed::{NodeSigner, Signer as _};

        let dir = TempDir::new().unwrap();
        let current_key = dir.path().join("current.key");
        let validator_b58 = mint_validator_key(&current_key);
        let (bls_pk_hex, bls_pop_hex) = bls_validator_entry(0x55);
        let config_path = dir.path().join("config.toml");
        write_bls_chain_config(
            &config_path,
            &current_key,
            &validator_b58,
            &bls_pk_hex,
            &bls_pop_hex,
        );

        let new_key = dir.path().join("new.key");
        let new_bls = dir.path().join("new-bls.key");
        let args = RotationProposeRequest {
            config_path: Some(config_path.clone()),
            new_key_backend: Some("file".into()),
            new_key_path: Some(new_key.clone()),
            new_key_passphrase_env: None,
            new_bls_key_backend: Some("file".into()),
            new_bls_key_path: Some(new_bls.clone()),
            v_eff: Some(500),
        };
        let first = build_rotation_envelope(&args).unwrap();
        let second = build_rotation_envelope(&args).unwrap();

        let new_id =
            boule_core::config::build_provider(&boule_core::config::IdentityConfig::File {
                path: new_key.clone(),
                allow_insecure_perms: false,
            })
            .unwrap()
            .try_load()
            .unwrap()
            .unwrap();
        let new_signer = NodeSigner::from_identity(&new_id).unwrap();
        assert_eq!(first.envelope.payload.new_pubkey, new_signer.node_id());
        assert_eq!(second.envelope.payload.new_pubkey, new_signer.node_id());
    }

    #[test]
    fn rotation_propose_bls_chain_bundles_bls_key_and_pop() {
        // BLS-chain happy path: both halves minted, the envelope carries a
        // chain-bound PoP, and the payload passes scheme-consistency.
        use boule_core::crypto::signed::{NodeSigner, Signer as _};

        let dir = TempDir::new().unwrap();
        let current_key = dir.path().join("current.key");
        let validator_b58 = mint_validator_key(&current_key);

        // The genesis PoP is bogus; OK because rotation never verifies the
        // genesis PoP, only its own freshly-derived one.
        let mut ikm = [0u8; 32];
        ikm[0] = 0xAA;
        let (_genesis_sk, genesis_pk) = BlsAggregated::keygen(&ikm).unwrap();
        let genesis_pk_hex = hex::encode(genesis_pk);
        let genesis_pop_hex = hex::encode([0u8; 96]);

        let config_path = dir.path().join("config.toml");
        write_bls_chain_config(
            &config_path,
            &current_key,
            &validator_b58,
            &genesis_pk_hex,
            &genesis_pop_hex,
        );

        let new_key = dir.path().join("new.key");
        let new_bls = dir.path().join("new-bls.key");
        let args = RotationProposeRequest {
            config_path: Some(config_path.clone()),
            new_key_backend: Some("file".into()),
            new_key_path: Some(new_key.clone()),
            new_key_passphrase_env: None,
            new_bls_key_backend: Some("file".into()),
            new_bls_key_path: Some(new_bls.clone()),
            v_eff: Some(500),
        };
        let outcome = build_rotation_envelope(&args).expect("BLS rotation must succeed");

        assert!(outcome.bls_chain);
        assert!(new_bls.exists(), "BLS key file must be minted");
        let env_pk = outcome
            .envelope
            .payload
            .new_bls_pubkey
            .expect("must carry BLS pubkey");
        let env_pop = outcome
            .envelope
            .payload
            .new_bls_pop
            .as_ref()
            .expect("must carry PoP");

        let bls_id = BlsKeyFile::new(new_bls.clone()).load_or_init().unwrap();
        assert_eq!(env_pk, bls_id.public);

        let cfg = boule_core::config::load(&config_path).unwrap();
        let chain_id =
            boule_consensus::genesis::derive_chain_id(cfg.consensus.as_ref().unwrap()).unwrap();
        BlsAggregated::verify_pop(env_pop, &env_pk, &chain_id)
            .expect("BLS PoP must verify under the chain's chain_id");

        outcome
            .envelope
            .payload
            .validate_scheme_consistency(
                boule_core::crypto::sig_scheme::SignatureSchemeChoice::BlsAggregated,
                &chain_id,
            )
            .expect("must pass scheme-consistency under the BLS scheme");

        let current_id =
            boule_core::config::build_provider(&boule_core::config::IdentityConfig::File {
                path: current_key.clone(),
                allow_insecure_perms: false,
            })
            .unwrap()
            .try_load()
            .unwrap()
            .unwrap();
        let current_signer = NodeSigner::from_identity(&current_id).unwrap();
        outcome
            .envelope
            .verify(&current_signer.node_id(), &chain_id)
            .expect("Ed25519 dual-signature must verify on BLS chains too");
    }

    #[test]
    fn rotation_propose_bls_chain_requires_bls_key_flags() {
        let dir = TempDir::new().unwrap();
        let current_key = dir.path().join("current.key");
        let validator_b58 = mint_validator_key(&current_key);
        let mut ikm = [0u8; 32];
        ikm[0] = 0xAB;
        let (_sk, pk) = BlsAggregated::keygen(&ikm).unwrap();
        let config_path = dir.path().join("config.toml");
        write_bls_chain_config(
            &config_path,
            &current_key,
            &validator_b58,
            &hex::encode(pk),
            &hex::encode([0u8; 96]),
        );

        let new_key = dir.path().join("new.key");
        let args = RotationProposeRequest {
            config_path: Some(config_path),
            new_key_backend: Some("file".into()),
            new_key_path: Some(new_key.clone()),
            new_key_passphrase_env: None,
            new_bls_key_backend: None,
            new_bls_key_path: None,
            v_eff: Some(500),
        };
        let err = build_rotation_envelope(&args).unwrap_err();
        assert!(
            err.to_string().contains("--new-bls-key-backend"),
            "unexpected error: {err}",
        );
        assert!(!new_key.exists());
    }

    #[test]
    fn rotation_propose_rejects_v_eff_too_close_when_validated_at_current_view() {
        // build_rotation_envelope doesn't know "current_view"; the engine
        // enforces V_EFF_MIN_DELAY at commit time. Exercise the constant
        // here so a floor change surfaces in a CLI test too.
        let payload = boule_consensus::validator_rotation::ValidatorKeyRotation {
            validator: [1u8; 32],
            new_pubkey: [2u8; 32],
            v_eff: boule_consensus::View(11),
            new_bls_pubkey: None,
            new_bls_pop: None,
        };
        // current_view=10, v_eff=11 → < current+2; must be rejected.
        assert!(payload.validate_structural(10).is_err());
    }

    #[test]
    fn build_new_identity_config_for_rotation_supports_path_backends() {
        let cfg =
            build_new_identity_config_for_rotation("file", Some(PathBuf::from("/tmp/k")), None)
                .unwrap();
        assert!(matches!(
            cfg,
            boule_core::config::IdentityConfig::File { .. }
        ));
        assert_eq!(cfg.backend_name(), "file");

        let cfg = build_new_identity_config_for_rotation(
            "encrypted-file",
            Some(PathBuf::from("/tmp/k")),
            Some("PASS".into()),
        )
        .unwrap();
        assert_eq!(cfg.backend_name(), "encrypted-file");
    }

    #[test]
    fn build_new_identity_config_for_rotation_rejects_read_only_backends() {
        for backend in ["env", "exec", "keyring"] {
            let err = build_new_identity_config_for_rotation(backend, None, None).unwrap_err();
            assert!(
                err.to_string().contains("not supported"),
                "{backend}: {err}",
            );
        }
    }

    #[test]
    fn build_new_identity_config_for_rotation_rejects_unknown_backend() {
        let err = build_new_identity_config_for_rotation("hsm", None, None).unwrap_err();
        assert!(err.to_string().contains("not a valid backend"));
    }
}
