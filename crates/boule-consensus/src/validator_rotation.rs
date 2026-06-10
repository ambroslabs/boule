use std::path::PathBuf;

use anyhow::Result;
use bytes::Bytes;
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

use crate::View;
use boule_core::crypto::sig_scheme::{BlsAggregated, BlsPop, BlsPublicKey};
use boule_core::crypto::signed::{ChainId, SignedMessage, Signer, preimage};
use boule_core::identity::NodeId;

pub const ROTATION_TAG: &[u8; 6] = b"VKROT\0";

pub const ROTATION_CANCEL_TAG: &[u8; 6] = b"VKCAN\0";

pub const OPERATOR_ROTATION_TAG: &[u8; 6] = b"VKOPR\0";

pub const OPERATOR_KEY_ROTATION_TAG: &[u8; 6] = b"OKROT\0";

pub const V_EFF_MIN_DELAY: View = View::new(2);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorKeyRotation {
    pub validator: NodeId,
    pub new_pubkey: NodeId,
    pub v_eff: View,

    #[serde(default, with = "serde_optional_bls_pubkey")]
    pub new_bls_pubkey: Option<BlsPublicKey>,

    #[serde(default)]
    pub new_bls_pop: Option<BlsPop>,
}

impl SignedMessage for ValidatorKeyRotation {
    const DOMAIN: &'static str = "boule.consensus.validator_rotation.v1";
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DualSignedRotation {
    pub payload: ValidatorKeyRotation,
    #[serde(with = "serde_sig")]
    pub sig_old: [u8; 64],
    #[serde(with = "serde_sig")]
    pub sig_new: [u8; 64],
}

#[derive(Debug, PartialEq, Eq)]
pub enum RotationStructuralError {
    EffectiveViewTooSoon {
        current_view: View,
        v_eff: View,
    },
    NewKeyEqualsValidator,

    BlsFieldsInconsistentWithScheme {
        bls_pubkey_present: bool,
        bls_pop_present: bool,
    },

    BlsPopVerificationFailed,
}

impl std::fmt::Display for RotationStructuralError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EffectiveViewTooSoon {
                current_view,
                v_eff,
            } => write!(
                f,
                "rotation v_eff={v_eff} is not at least {V_EFF_MIN_DELAY} views ahead of \
                 current_view={current_view}",
            ),
            Self::NewKeyEqualsValidator => {
                write!(
                    f,
                    "rotation new_pubkey equals current validator key (no-op rotation)"
                )
            }
            Self::BlsFieldsInconsistentWithScheme {
                bls_pubkey_present,
                bls_pop_present,
            } => write!(
                f,
                "rotation BLS fields inconsistent: \
                 new_bls_pubkey={bls_pubkey_present}, new_bls_pop={bls_pop_present}; \
                 a rotation requires both",
            ),
            Self::BlsPopVerificationFailed => f.write_str(
                "rotation new_bls_pop does not verify under new_bls_pubkey \
                 (rogue-key-attack defense)",
            ),
        }
    }
}

impl std::error::Error for RotationStructuralError {}

impl ValidatorKeyRotation {
    pub fn validate_structural(
        &self,
        current_view: impl Into<View>,
    ) -> Result<(), RotationStructuralError> {
        let current_view = current_view.into();
        if self.v_eff < current_view.saturating_add(V_EFF_MIN_DELAY) {
            return Err(RotationStructuralError::EffectiveViewTooSoon {
                current_view,
                v_eff: self.v_eff,
            });
        }
        if self.new_pubkey == self.validator {
            return Err(RotationStructuralError::NewKeyEqualsValidator);
        }
        Ok(())
    }

    pub fn validate_scheme_consistency(
        &self,
        chain_id: &ChainId,
    ) -> Result<(), RotationStructuralError> {
        let (Some(pk), Some(pop)) = (&self.new_bls_pubkey, &self.new_bls_pop) else {
            return Err(RotationStructuralError::BlsFieldsInconsistentWithScheme {
                bls_pubkey_present: self.new_bls_pubkey.is_some(),
                bls_pop_present: self.new_bls_pop.is_some(),
            });
        };
        BlsAggregated::verify_pop(pop, pk, chain_id)
            .map_err(|_| RotationStructuralError::BlsPopVerificationFailed)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RotationVerifyError {
    InvalidOldSignature,

    InvalidNewSignature,

    Preimage(String),

    InvalidOperatorSignature,
}

impl std::fmt::Display for RotationVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidOldSignature => f.write_str(
                "rotation sig_old does not verify under the validator's current consensus key",
            ),
            Self::InvalidNewSignature => {
                f.write_str("rotation sig_new does not verify under payload.new_pubkey")
            }
            Self::Preimage(e) => write!(f, "computing rotation pre-image failed: {e}"),
            Self::InvalidOperatorSignature => f.write_str(
                "rotation sig_operator does not verify under the validator's active operator key",
            ),
        }
    }
}

impl std::error::Error for RotationVerifyError {}

impl DualSignedRotation {
    pub fn encode_command(&self) -> Bytes {
        let body =
            postcard::to_stdvec(self).expect("postcard encoding of DualSignedRotation cannot fail");
        let mut out = Vec::with_capacity(ROTATION_TAG.len() + body.len());
        out.extend_from_slice(ROTATION_TAG);
        out.extend_from_slice(&body);
        Bytes::from(out)
    }

    pub fn is_rotation_payload(bytes: &[u8]) -> bool {
        bytes.starts_with(ROTATION_TAG)
    }

    pub fn decode_command(bytes: &[u8]) -> Result<Self> {
        let body = bytes
            .strip_prefix(ROTATION_TAG.as_slice())
            .ok_or_else(|| anyhow::anyhow!("missing rotation tag prefix"))?;
        postcard::from_bytes(body).map_err(|e| anyhow::anyhow!("malformed DualSignedRotation: {e}"))
    }

    pub fn sign(
        payload: ValidatorKeyRotation,
        current: &dyn Signer,
        new: &dyn Signer,
        chain_id: &ChainId,
    ) -> Result<Self> {
        if new.node_id() != payload.new_pubkey {
            anyhow::bail!(
                "new signer's node_id does not match payload.new_pubkey; the resulting \
                 sig_new would never verify"
            );
        }
        let bytes = preimage::<ValidatorKeyRotation>(&payload, chain_id)?;
        let sig_old = current.sign(&bytes);
        let sig_new = new.sign(&bytes);
        Ok(Self {
            payload,
            sig_old,
            sig_new,
        })
    }

    pub fn verify(
        &self,
        current_pubkey: &NodeId,
        chain_id: &ChainId,
    ) -> Result<(), RotationVerifyError> {
        let bytes = preimage::<ValidatorKeyRotation>(&self.payload, chain_id)
            .map_err(|e| RotationVerifyError::Preimage(e.to_string()))?;

        UnparsedPublicKey::new(&ED25519, current_pubkey as &[u8])
            .verify(&bytes, &self.sig_old)
            .map_err(|_| RotationVerifyError::InvalidOldSignature)?;

        UnparsedPublicKey::new(&ED25519, &self.payload.new_pubkey as &[u8])
            .verify(&bytes, &self.sig_new)
            .map_err(|_| RotationVerifyError::InvalidNewSignature)?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorSignedRotation {
    pub payload: ValidatorKeyRotation,
    #[serde(with = "serde_sig")]
    pub sig_operator: [u8; 64],
    #[serde(with = "serde_sig")]
    pub sig_new: [u8; 64],
}

impl OperatorSignedRotation {
    pub fn encode_command(&self) -> Bytes {
        let body = postcard::to_stdvec(self)
            .expect("postcard encoding of OperatorSignedRotation cannot fail");
        let mut out = Vec::with_capacity(OPERATOR_ROTATION_TAG.len() + body.len());
        out.extend_from_slice(OPERATOR_ROTATION_TAG);
        out.extend_from_slice(&body);
        Bytes::from(out)
    }

    pub fn is_operator_rotation_payload(bytes: &[u8]) -> bool {
        bytes.starts_with(OPERATOR_ROTATION_TAG)
    }

    pub fn decode_command(bytes: &[u8]) -> Result<Self> {
        let body = bytes
            .strip_prefix(OPERATOR_ROTATION_TAG.as_slice())
            .ok_or_else(|| anyhow::anyhow!("missing operator-rotation tag prefix"))?;
        postcard::from_bytes(body)
            .map_err(|e| anyhow::anyhow!("malformed OperatorSignedRotation: {e}"))
    }

    pub fn sign(
        payload: ValidatorKeyRotation,
        operator: &dyn Signer,
        new: &dyn Signer,
        chain_id: &ChainId,
    ) -> Result<Self> {
        if new.node_id() != payload.new_pubkey {
            anyhow::bail!(
                "new signer's node_id does not match payload.new_pubkey; the resulting \
                 sig_new would never verify"
            );
        }
        let bytes = preimage::<ValidatorKeyRotation>(&payload, chain_id)?;
        let sig_operator = operator.sign(&bytes);
        let sig_new = new.sign(&bytes);
        Ok(Self {
            payload,
            sig_operator,
            sig_new,
        })
    }

    pub fn verify(
        &self,
        operator_pubkey: &NodeId,
        chain_id: &ChainId,
    ) -> Result<(), RotationVerifyError> {
        let bytes = preimage::<ValidatorKeyRotation>(&self.payload, chain_id)
            .map_err(|e| RotationVerifyError::Preimage(e.to_string()))?;

        UnparsedPublicKey::new(&ED25519, operator_pubkey as &[u8])
            .verify(&bytes, &self.sig_operator)
            .map_err(|_| RotationVerifyError::InvalidOperatorSignature)?;

        UnparsedPublicKey::new(&ED25519, &self.payload.new_pubkey as &[u8])
            .verify(&bytes, &self.sig_new)
            .map_err(|_| RotationVerifyError::InvalidNewSignature)?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorKeyRotation {
    pub validator: NodeId,

    pub new_operator_pubkey: NodeId,

    pub v_eff: View,
}

impl SignedMessage for OperatorKeyRotation {
    const DOMAIN: &'static str = "boule.consensus.operator_key_rotation.v1";
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DualSignedOperatorRotation {
    pub payload: OperatorKeyRotation,

    #[serde(with = "serde_sig")]
    pub sig_old: [u8; 64],

    #[serde(with = "serde_sig")]
    pub sig_new: [u8; 64],
}

impl DualSignedOperatorRotation {
    pub fn encode_command(&self) -> Bytes {
        let body = postcard::to_stdvec(self)
            .expect("postcard encoding of DualSignedOperatorRotation cannot fail");
        let mut out = Vec::with_capacity(OPERATOR_KEY_ROTATION_TAG.len() + body.len());
        out.extend_from_slice(OPERATOR_KEY_ROTATION_TAG);
        out.extend_from_slice(&body);
        Bytes::from(out)
    }

    pub fn is_operator_key_rotation_payload(bytes: &[u8]) -> bool {
        bytes.starts_with(OPERATOR_KEY_ROTATION_TAG)
    }

    pub fn decode_command(bytes: &[u8]) -> Result<Self> {
        let body = bytes
            .strip_prefix(OPERATOR_KEY_ROTATION_TAG.as_slice())
            .ok_or_else(|| anyhow::anyhow!("missing operator-key-rotation tag prefix"))?;
        postcard::from_bytes(body)
            .map_err(|e| anyhow::anyhow!("malformed DualSignedOperatorRotation: {e}"))
    }

    pub fn sign(
        payload: OperatorKeyRotation,
        old: &dyn Signer,
        new: &dyn Signer,
        chain_id: &ChainId,
    ) -> Result<Self> {
        if new.node_id() != payload.new_operator_pubkey {
            anyhow::bail!(
                "new signer's node_id does not match payload.new_operator_pubkey; the \
                 resulting sig_new would never verify"
            );
        }
        let bytes = preimage::<OperatorKeyRotation>(&payload, chain_id)?;
        let sig_old = old.sign(&bytes);
        let sig_new = new.sign(&bytes);
        Ok(Self {
            payload,
            sig_old,
            sig_new,
        })
    }

    pub fn verify(
        &self,
        current_operator_pubkey: &NodeId,
        chain_id: &ChainId,
    ) -> Result<(), RotationVerifyError> {
        let bytes = preimage::<OperatorKeyRotation>(&self.payload, chain_id)
            .map_err(|e| RotationVerifyError::Preimage(e.to_string()))?;

        UnparsedPublicKey::new(&ED25519, current_operator_pubkey as &[u8])
            .verify(&bytes, &self.sig_old)
            .map_err(|_| RotationVerifyError::InvalidOldSignature)?;

        UnparsedPublicKey::new(&ED25519, &self.payload.new_operator_pubkey as &[u8])
            .verify(&bytes, &self.sig_new)
            .map_err(|_| RotationVerifyError::InvalidNewSignature)?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorRotationCancel {
    pub validator: NodeId,
    pub cancelling_v_eff: View,
}

impl SignedMessage for ValidatorRotationCancel {
    const DOMAIN: &'static str = "boule.consensus.validator_rotation_cancel.v1";
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DualSignedRotationCancel {
    pub payload: ValidatorRotationCancel,
    #[serde(with = "serde_sig")]
    pub sig_old: [u8; 64],
    #[serde(with = "serde_sig")]
    pub sig_new: [u8; 64],
}

impl DualSignedRotationCancel {
    pub fn encode_command(&self) -> Bytes {
        let body = postcard::to_stdvec(self)
            .expect("postcard encoding of DualSignedRotationCancel cannot fail");
        let mut out = Vec::with_capacity(ROTATION_CANCEL_TAG.len() + body.len());
        out.extend_from_slice(ROTATION_CANCEL_TAG);
        out.extend_from_slice(&body);
        Bytes::from(out)
    }

    pub fn is_cancel_payload(bytes: &[u8]) -> bool {
        bytes.starts_with(ROTATION_CANCEL_TAG)
    }

    pub fn decode_command(bytes: &[u8]) -> Result<Self> {
        let body = bytes
            .strip_prefix(ROTATION_CANCEL_TAG.as_slice())
            .ok_or_else(|| anyhow::anyhow!("missing rotation-cancel tag prefix"))?;
        postcard::from_bytes(body)
            .map_err(|e| anyhow::anyhow!("malformed DualSignedRotationCancel: {e}"))
    }

    pub fn sign(
        payload: ValidatorRotationCancel,
        current: &dyn Signer,
        new: &dyn Signer,
        chain_id: &ChainId,
    ) -> Result<Self> {
        let bytes = preimage::<ValidatorRotationCancel>(&payload, chain_id)?;
        let sig_old = current.sign(&bytes);
        let sig_new = new.sign(&bytes);
        Ok(Self {
            payload,
            sig_old,
            sig_new,
        })
    }

    pub fn verify(
        &self,
        current_pubkey: &NodeId,
        pending_new_pubkey: &NodeId,
        chain_id: &ChainId,
    ) -> Result<(), RotationVerifyError> {
        let bytes = preimage::<ValidatorRotationCancel>(&self.payload, chain_id)
            .map_err(|e| RotationVerifyError::Preimage(e.to_string()))?;

        UnparsedPublicKey::new(&ED25519, current_pubkey as &[u8])
            .verify(&bytes, &self.sig_old)
            .map_err(|_| RotationVerifyError::InvalidOldSignature)?;

        UnparsedPublicKey::new(&ED25519, pending_new_pubkey as &[u8])
            .verify(&bytes, &self.sig_new)
            .map_err(|_| RotationVerifyError::InvalidNewSignature)?;

        Ok(())
    }
}

mod serde_optional_bls_pubkey {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    use boule_core::crypto::sig_scheme::BlsPublicKey;

    pub fn serialize<S: Serializer>(opt: &Option<BlsPublicKey>, s: S) -> Result<S::Ok, S::Error> {
        match opt {
            Some(pk) => s.serialize_some(&pk[..]),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<BlsPublicKey>, D::Error> {
        let opt: Option<Vec<u8>> = Option::deserialize(d)?;
        match opt {
            Some(v) => v
                .as_slice()
                .try_into()
                .map(Some)
                .map_err(|_| D::Error::custom("BLS pubkey must be exactly 48 bytes")),
            None => Ok(None),
        }
    }
}

mod serde_sig {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(sig: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&sig[..], s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Vec::<u8>::deserialize(d)?;
        v.as_slice()
            .try_into()
            .map_err(|_| D::Error::custom("signature must be exactly 64 bytes"))
    }
}

#[derive(Debug, Default)]
pub struct RotationProposeRequest {
    pub config_path: Option<PathBuf>,
    pub new_key_backend: Option<String>,
    pub new_key_path: Option<PathBuf>,
    pub new_key_passphrase_env: Option<String>,
    pub new_bls_key_backend: Option<String>,
    pub new_bls_key_path: Option<PathBuf>,
    pub v_eff: Option<u64>,
}

#[derive(Debug)]
pub struct RotationProposeOutcome {
    pub envelope: DualSignedRotation,

    pub bls_chain: bool,
}

pub fn build_new_identity_config_for_rotation(
    backend: &str,
    path: Option<PathBuf>,
    passphrase_env: Option<String>,
) -> anyhow::Result<boule_core::config::IdentityConfig> {
    use boule_core::config::IdentityConfig;
    match backend {
        "file" => Ok(IdentityConfig::File {
            path: path
                .ok_or_else(|| anyhow::anyhow!("--new-key-backend file requires --new-key-path"))?,
            allow_insecure_perms: false,
        }),
        "encrypted-file" => Ok(IdentityConfig::EncryptedFile {
            path: path.ok_or_else(|| {
                anyhow::anyhow!("--new-key-backend encrypted-file requires --new-key-path")
            })?,
            passphrase_env,
        }),
        "env" | "exec" | "keyring" => anyhow::bail!(
            "--new-key-backend `{backend}` is not supported by `rotation propose` yet \
             (read-only backends need separate provisioning); use `file` or `encrypted-file`",
        ),
        other => anyhow::bail!(
            "--new-key-backend `{other}` is not a valid backend (try: file, encrypted-file)",
        ),
    }
}

pub fn build_rotation_envelope(
    req: &RotationProposeRequest,
) -> anyhow::Result<RotationProposeOutcome> {
    use boule_core::crypto::bls_key::{BlsKeyFile, BlsKeyProvider as _};
    use boule_core::crypto::signed::NodeSigner;

    let v_eff = View(
        req.v_eff
            .ok_or_else(|| anyhow::anyhow!("rotation propose requires --v-eff <view>"))?,
    );
    let new_backend = req.new_key_backend.as_deref().ok_or_else(|| {
        anyhow::anyhow!("rotation propose requires --new-key-backend <file|encrypted-file>")
    })?;
    let config_path = req
        .config_path
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("rotation propose requires --config"))?;
    let config = boule_core::config::load(config_path)?;
    let cons = config.consensus.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "--config {} has no [consensus] section; rotation requires the \
             chain's chain_id to bundle a chain-bound payload",
            config_path.display(),
        )
    })?;
    let chain_id = crate::genesis::derive_chain_id(cons)?;

    if req.new_bls_key_backend.is_none() {
        anyhow::bail!(
            "no --new-bls-key-backend was supplied; rotations carry both the Ed25519 \
             and BLS halves atomically (#358)",
        );
    }

    let (current_id_cfg, current_slot) =
        match boule_core::config::resolve_validator_identity(&config.node) {
            Some(cfg) => (cfg, "validator"),
            None => match boule_core::config::resolve_identity(&config.node) {
                Some(cfg) => (cfg, "network (legacy single-key)"),
                None => anyhow::bail!(
                    "--config {} has no [node.validator_identity] or [node.identity]; \
                 rotation needs an existing consensus signing key to produce sig_old",
                    config_path.display(),
                ),
            },
        };
    let current_provider = boule_core::config::build_provider(&current_id_cfg)?;
    let current_identity = current_provider.try_load()?.ok_or_else(|| {
        anyhow::anyhow!(
            "no current consensus key found via the {} `{}` backend; provision it via \
             `boule init` (or out-of-band) before rotating",
            current_slot,
            current_id_cfg.backend_name(),
        )
    })?;
    let current_signer = NodeSigner::from_identity(&current_identity)?;

    let new_id_cfg = build_new_identity_config_for_rotation(
        new_backend,
        req.new_key_path.clone(),
        req.new_key_passphrase_env.clone(),
    )?;
    let new_provider = boule_core::config::build_provider(&new_id_cfg)?;
    let new_identity = if new_provider.is_provisioning_capable() {
        new_provider.load_or_init()?
    } else {
        new_provider.try_load()?.ok_or_else(|| {
            anyhow::anyhow!(
                "new key backend `{}` is read-only and no key is yet provisioned; \
                 mint the key out-of-band first",
                new_id_cfg.backend_name(),
            )
        })?
    };
    let new_signer = NodeSigner::from_identity(&new_identity)?;

    let (new_bls_pubkey, new_bls_pop) = {
        let backend = req
            .new_bls_key_backend
            .as_deref()
            .expect("BLS-flag presence verified above");
        if backend != "file" {
            anyhow::bail!("--new-bls-key-backend `{backend}` is not supported (only `file` today)",);
        }
        let bls_path = req.new_bls_key_path.clone().ok_or_else(|| {
            anyhow::anyhow!("--new-bls-key-backend file requires --new-bls-key-path")
        })?;
        let bls_provider = BlsKeyFile::new(bls_path);
        let bls_id = bls_provider.load_or_init()?;
        let pop = BlsAggregated::sign_pop(&bls_id.secret, &chain_id)
            .map_err(|e| anyhow::anyhow!("signing BLS PoP: {e:?}"))?;
        (Some(bls_id.public), Some(pop))
    };

    let payload = ValidatorKeyRotation {
        validator: current_signer.node_id(),
        new_pubkey: new_signer.node_id(),
        v_eff,
        new_bls_pubkey,
        new_bls_pop,
    };

    if payload.new_pubkey == payload.validator {
        anyhow::bail!(
            "new_pubkey equals current validator key; the --new-key-path is already \
             pointing at the active consensus key — pick a different path",
        );
    }
    payload
        .validate_scheme_consistency(&chain_id)
        .map_err(|e| anyhow::anyhow!("rotation payload failed scheme-consistency check: {e}"))?;

    let envelope = DualSignedRotation::sign(payload, &current_signer, &new_signer, &chain_id)?;
    Ok(RotationProposeOutcome {
        envelope,
        bls_chain: true,
    })
}

#[derive(Debug, Default)]
pub struct OperatorRecoveryRequest {
    pub config_path: Option<PathBuf>,

    pub validator: Option<String>,

    pub operator_key_backend: Option<String>,
    pub operator_key_path: Option<PathBuf>,
    pub operator_key_passphrase_env: Option<String>,

    pub new_key_backend: Option<String>,
    pub new_key_path: Option<PathBuf>,
    pub new_key_passphrase_env: Option<String>,
    pub new_bls_key_backend: Option<String>,
    pub new_bls_key_path: Option<PathBuf>,
    pub v_eff: Option<u64>,
}

#[derive(Debug)]
pub struct OperatorRecoveryOutcome {
    pub envelope: OperatorSignedRotation,
    pub bls_chain: bool,
}

pub fn build_operator_recovery_envelope(
    req: &OperatorRecoveryRequest,
) -> anyhow::Result<OperatorRecoveryOutcome> {
    use boule_core::crypto::bls_key::{BlsKeyFile, BlsKeyProvider as _};
    use boule_core::crypto::signed::NodeSigner;

    let v_eff = View(req.v_eff.ok_or_else(|| {
        anyhow::anyhow!("rotation propose-operator-recovery requires --v-eff <view>")
    })?);
    let new_backend = req.new_key_backend.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "rotation propose-operator-recovery requires --new-key-backend <file|encrypted-file>"
        )
    })?;
    let operator_backend = req.operator_key_backend.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "rotation propose-operator-recovery requires --operator-key-backend \
             <file|encrypted-file>"
        )
    })?;
    let validator_b58 = req.validator.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "rotation propose-operator-recovery requires --validator <base58 stable id> \
             (the signing key is presumed lost, so the validator can't be identified from it)"
        )
    })?;
    let validator = boule_core::identity::base58_to_node_id(validator_b58).map_err(|e| {
        anyhow::anyhow!("--validator {validator_b58:?} is not a base58 NodeId: {e}")
    })?;

    let config_path = req
        .config_path
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("rotation propose-operator-recovery requires --config"))?;
    let config = boule_core::config::load(config_path)?;
    let cons = config.consensus.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "--config {} has no [consensus] section; recovery requires the chain's \
             chain_id to bundle a chain-bound payload",
            config_path.display(),
        )
    })?;
    let chain_id = crate::genesis::derive_chain_id(cons)?;

    if req.new_bls_key_backend.is_none() {
        anyhow::bail!(
            "no --new-bls-key-backend was supplied; rotations carry both the Ed25519 \
             and BLS halves atomically (#358)",
        );
    }

    let operator_cfg = build_new_identity_config_for_rotation(
        operator_backend,
        req.operator_key_path.clone(),
        req.operator_key_passphrase_env.clone(),
    )?;
    let operator_identity = boule_core::config::build_provider(&operator_cfg)?
        .try_load()?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no operator key found via the `{}` backend; the operator key must already \
                 exist (it is the recovery authority, not minted here)",
                operator_cfg.backend_name(),
            )
        })?;
    let operator_signer = NodeSigner::from_identity(&operator_identity)?;

    let new_id_cfg = build_new_identity_config_for_rotation(
        new_backend,
        req.new_key_path.clone(),
        req.new_key_passphrase_env.clone(),
    )?;
    let new_provider = boule_core::config::build_provider(&new_id_cfg)?;
    let new_identity = if new_provider.is_provisioning_capable() {
        new_provider.load_or_init()?
    } else {
        new_provider.try_load()?.ok_or_else(|| {
            anyhow::anyhow!(
                "new key backend `{}` is read-only and no key is yet provisioned; \
                 mint the key out-of-band first",
                new_id_cfg.backend_name(),
            )
        })?
    };
    let new_signer = NodeSigner::from_identity(&new_identity)?;

    let (new_bls_pubkey, new_bls_pop) = {
        let backend = req
            .new_bls_key_backend
            .as_deref()
            .expect("BLS-flag presence verified above");
        if backend != "file" {
            anyhow::bail!("--new-bls-key-backend `{backend}` is not supported (only `file` today)",);
        }
        let bls_path = req.new_bls_key_path.clone().ok_or_else(|| {
            anyhow::anyhow!("--new-bls-key-backend file requires --new-bls-key-path")
        })?;
        let bls_id = BlsKeyFile::new(bls_path).load_or_init()?;
        let pop = BlsAggregated::sign_pop(&bls_id.secret, &chain_id)
            .map_err(|e| anyhow::anyhow!("signing BLS PoP: {e:?}"))?;
        (Some(bls_id.public), Some(pop))
    };

    let payload = ValidatorKeyRotation {
        validator,
        new_pubkey: new_signer.node_id(),
        v_eff,
        new_bls_pubkey,
        new_bls_pop,
    };
    if payload.new_pubkey == payload.validator {
        anyhow::bail!(
            "new_pubkey equals the validator's stable id; pick a --new-key-path that is not \
             the genesis key",
        );
    }
    payload
        .validate_scheme_consistency(&chain_id)
        .map_err(|e| anyhow::anyhow!("recovery payload failed scheme-consistency check: {e}"))?;

    let envelope = OperatorSignedRotation::sign(payload, &operator_signer, &new_signer, &chain_id)?;
    Ok(OperatorRecoveryOutcome {
        envelope,
        bls_chain: true,
    })
}

#[derive(Debug, Default)]
pub struct OperatorKeyRotationRequest {
    pub config_path: Option<PathBuf>,

    pub validator: Option<String>,

    pub old_operator_key_backend: Option<String>,
    pub old_operator_key_path: Option<PathBuf>,
    pub old_operator_key_passphrase_env: Option<String>,

    pub new_operator_key_backend: Option<String>,
    pub new_operator_key_path: Option<PathBuf>,
    pub new_operator_key_passphrase_env: Option<String>,
    pub v_eff: Option<u64>,
}

#[derive(Debug)]
pub struct OperatorKeyRotationOutcome {
    pub envelope: DualSignedOperatorRotation,
}

pub fn build_operator_key_rotation_envelope(
    req: &OperatorKeyRotationRequest,
) -> anyhow::Result<OperatorKeyRotationOutcome> {
    use boule_core::crypto::signed::NodeSigner;

    let v_eff = View(req.v_eff.ok_or_else(|| {
        anyhow::anyhow!("rotation propose-operator-key-rotation requires --v-eff <view>")
    })?);
    let old_backend = req.old_operator_key_backend.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "rotation propose-operator-key-rotation requires --old-operator-key-backend \
             <file|encrypted-file>"
        )
    })?;
    let new_backend = req.new_operator_key_backend.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "rotation propose-operator-key-rotation requires --new-operator-key-backend \
             <file|encrypted-file>"
        )
    })?;
    let validator_b58 = req.validator.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "rotation propose-operator-key-rotation requires --validator <base58 stable id>"
        )
    })?;
    let validator = boule_core::identity::base58_to_node_id(validator_b58).map_err(|e| {
        anyhow::anyhow!("--validator {validator_b58:?} is not a base58 NodeId: {e}")
    })?;

    let config_path = req.config_path.as_ref().ok_or_else(|| {
        anyhow::anyhow!("rotation propose-operator-key-rotation requires --config")
    })?;
    let config = boule_core::config::load(config_path)?;
    let cons = config.consensus.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "--config {} has no [consensus] section; operator-key rotation requires the \
             chain's chain_id to bundle a chain-bound payload",
            config_path.display(),
        )
    })?;
    let chain_id = crate::genesis::derive_chain_id(cons)?;

    let old_cfg = build_new_identity_config_for_rotation(
        old_backend,
        req.old_operator_key_path.clone(),
        req.old_operator_key_passphrase_env.clone(),
    )?;
    let old_identity = boule_core::config::build_provider(&old_cfg)?
        .try_load()?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no current operator key found via the `{}` backend; the current operator key \
                 must already exist (it authorises the rotation)",
                old_cfg.backend_name(),
            )
        })?;
    let old_signer = NodeSigner::from_identity(&old_identity)?;

    let new_cfg = build_new_identity_config_for_rotation(
        new_backend,
        req.new_operator_key_path.clone(),
        req.new_operator_key_passphrase_env.clone(),
    )?;
    let new_provider = boule_core::config::build_provider(&new_cfg)?;
    let new_identity = if new_provider.is_provisioning_capable() {
        new_provider.load_or_init()?
    } else {
        new_provider.try_load()?.ok_or_else(|| {
            anyhow::anyhow!(
                "new operator key backend `{}` is read-only and no key is yet provisioned; \
                 mint the key out-of-band first",
                new_cfg.backend_name(),
            )
        })?
    };
    let new_signer = NodeSigner::from_identity(&new_identity)?;

    if new_signer.node_id() == old_signer.node_id() {
        anyhow::bail!(
            "new operator key equals the current operator key; pick a --new-operator-key-path \
             that is not the current key",
        );
    }

    let payload = OperatorKeyRotation {
        validator,
        new_operator_pubkey: new_signer.node_id(),
        v_eff,
    };
    let envelope = DualSignedOperatorRotation::sign(payload, &old_signer, &new_signer, &chain_id)?;
    Ok(OperatorKeyRotationOutcome { envelope })
}
