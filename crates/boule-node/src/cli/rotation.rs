//! `boule rotation` — build validator key-rotation payloads.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use boule::consensus::validator_rotation::{RotationProposeRequest, build_rotation_envelope};
use boule::p2p::tls::node_id_to_base58;

use super::shared::resolve_config_path;

#[derive(Subcommand)]
pub(crate) enum RotationCmd {
    /// Build a validator key-rotation payload, minting the new key(s).
    Propose(RotationProposeArgs),
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

#[cfg(test)]
mod tests {
    use boule::consensus::validator_rotation::{
        RotationProposeRequest, build_new_identity_config_for_rotation, build_rotation_envelope,
    };
    use boule::crypto::bls_key::{BlsKeyFile, BlsKeyProvider as _};
    use boule::crypto::sig_scheme::BlsAggregated;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    /// Mint a fresh Ed25519 file-backed validator key and return its
    /// base58-encoded NodeId. Both halves are what the rotation tests
    /// need to write a usable config TOML.
    fn mint_validator_key(path: &Path) -> String {
        use boule::crypto::signed::{NodeSigner, Signer as _};
        let cfg = boule::config::IdentityConfig::File {
            path: path.to_path_buf(),
            allow_insecure_perms: false,
        };
        let provider = boule::config::build_provider(&cfg).unwrap();
        let id = provider.load_or_init().unwrap();
        let signer = NodeSigner::from_identity(&id).unwrap();
        boule::p2p::tls::node_id_to_base58(&signer.node_id())
    }

    fn write_ed25519_chain_config(
        config_path: &Path,
        current_key_path: &Path,
        validator_b58: &str,
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
             signature_scheme = \"ed25519_collected\"\n",
            key = current_key_path.display(),
            val = validator_b58,
        );
        std::fs::write(config_path, text).unwrap();
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

    #[test]
    fn rotation_propose_ed25519_chain_builds_verifiable_envelope() {
        // End-to-end: real config + existing validator key on disk → minted
        // new key → signed envelope that verifies under the validator's
        // current pubkey and the chain's chain_id.
        use boule::crypto::signed::{NodeSigner, Signer as _};

        let dir = TempDir::new().unwrap();
        let current_key = dir.path().join("current.key");
        let validator_b58 = mint_validator_key(&current_key);
        let config_path = dir.path().join("config.toml");
        write_ed25519_chain_config(&config_path, &current_key, &validator_b58);

        let new_key = dir.path().join("new.key");
        assert!(!new_key.exists(), "new key must not pre-exist");
        let args = RotationProposeRequest {
            config_path: Some(config_path.clone()),
            new_key_backend: Some("file".into()),
            new_key_path: Some(new_key.clone()),
            new_key_passphrase_env: None,
            new_bls_key_backend: None,
            new_bls_key_path: None,
            v_eff: Some(500),
        };
        let outcome = build_rotation_envelope(&args).expect("rotation propose must succeed");

        assert!(
            new_key.exists(),
            "new key file must be created by load_or_init"
        );
        assert!(!outcome.bls_chain);
        assert!(outcome.envelope.payload.new_bls_pubkey.is_none());
        assert!(outcome.envelope.payload.new_bls_pop.is_none());
        assert_eq!(outcome.envelope.payload.v_eff.0, 500);

        let current_id = boule::config::build_provider(&boule::config::IdentityConfig::File {
            path: current_key.clone(),
            allow_insecure_perms: false,
        })
        .unwrap()
        .try_load()
        .unwrap()
        .unwrap();
        let current_signer = NodeSigner::from_identity(&current_id).unwrap();
        let new_id = boule::config::build_provider(&boule::config::IdentityConfig::File {
            path: new_key.clone(),
            allow_insecure_perms: false,
        })
        .unwrap()
        .try_load()
        .unwrap()
        .unwrap();
        let new_signer = NodeSigner::from_identity(&new_id).unwrap();
        assert_eq!(outcome.envelope.payload.validator, current_signer.node_id());
        assert_eq!(outcome.envelope.payload.new_pubkey, new_signer.node_id());

        let cfg = boule::config::load(&config_path).unwrap();
        let chain_id = boule::node::derive_chain_id(cfg.consensus.as_ref().unwrap()).unwrap();
        outcome
            .envelope
            .verify(&current_signer.node_id(), &chain_id)
            .expect("envelope must verify");

        let bytes = outcome.envelope.encode_command();
        assert!(
            boule::consensus::validator_rotation::DualSignedRotation::is_rotation_payload(&bytes,),
        );
    }

    #[test]
    fn rotation_propose_idempotent_when_new_key_already_exists() {
        // Re-running with a pre-minted `new_key_path` must reload it (not
        // overwrite) and produce a payload pointing at the same pubkey.
        use boule::crypto::signed::{NodeSigner, Signer as _};

        let dir = TempDir::new().unwrap();
        let current_key = dir.path().join("current.key");
        let validator_b58 = mint_validator_key(&current_key);
        let config_path = dir.path().join("config.toml");
        write_ed25519_chain_config(&config_path, &current_key, &validator_b58);

        let new_key = dir.path().join("new.key");
        let args = RotationProposeRequest {
            config_path: Some(config_path.clone()),
            new_key_backend: Some("file".into()),
            new_key_path: Some(new_key.clone()),
            new_key_passphrase_env: None,
            new_bls_key_backend: None,
            new_bls_key_path: None,
            v_eff: Some(500),
        };
        let first = build_rotation_envelope(&args).unwrap();
        let second = build_rotation_envelope(&args).unwrap();

        let new_id = boule::config::build_provider(&boule::config::IdentityConfig::File {
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
    fn rotation_propose_rejects_bls_flags_on_ed25519_chain() {
        let dir = TempDir::new().unwrap();
        let current_key = dir.path().join("current.key");
        let validator_b58 = mint_validator_key(&current_key);
        let config_path = dir.path().join("config.toml");
        write_ed25519_chain_config(&config_path, &current_key, &validator_b58);

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
        let err = build_rotation_envelope(&args).unwrap_err();
        assert!(
            err.to_string().contains("ed25519_collected"),
            "unexpected error: {err}",
        );
        // Ed25519 path must reject BLS flags before touching disk.
        assert!(!new_bls.exists());
    }

    #[test]
    fn rotation_propose_bls_chain_bundles_bls_key_and_pop() {
        // BLS-chain happy path: both halves minted, the envelope carries a
        // chain-bound PoP, and the payload passes scheme-consistency.
        use boule::crypto::signed::{NodeSigner, Signer as _};

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

        let cfg = boule::config::load(&config_path).unwrap();
        let chain_id = boule::node::derive_chain_id(cfg.consensus.as_ref().unwrap()).unwrap();
        BlsAggregated::verify_pop(env_pop, &env_pk, &chain_id)
            .expect("BLS PoP must verify under the chain's chain_id");

        outcome
            .envelope
            .payload
            .validate_scheme_consistency(
                boule::crypto::sig_scheme::SignatureSchemeChoice::BlsAggregated,
                &chain_id,
            )
            .expect("must pass scheme-consistency under the BLS scheme");

        let current_id = boule::config::build_provider(&boule::config::IdentityConfig::File {
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
        let payload = boule::consensus::validator_rotation::ValidatorKeyRotation {
            validator: [1u8; 32],
            new_pubkey: [2u8; 32],
            v_eff: boule::consensus::View(11),
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
        assert!(matches!(cfg, boule::config::IdentityConfig::File { .. }));
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
