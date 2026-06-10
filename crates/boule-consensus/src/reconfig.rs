use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::View;
use crate::endpoint_registry::EndpointEntry;
use crate::validator_set::{ValidatorId, ValidatorSet};
use boule_core::crypto::sig_scheme::{BlsAggregated, BlsKeyError, BlsPop};
use boule_core::crypto::signed::ChainId;
use boule_core::identity::NodeId;

pub const RECONFIG_TAG: &[u8; 6] = b"RECFG\0";

pub const MIN_VALIDATOR_FLOOR: usize = 4;

pub const MIN_V_EFF_DELAY: View = View::new(4);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorEntry {
    pub node_id: NodeId,
    pub addr: SocketAddr,

    pub bls_pop: Option<BlsPop>,

    pub weight: u64,

    pub operator_pubkey: Option<NodeId>,

    #[serde(with = "serde_optional_sig")]
    pub consent_sig: Option<[u8; 64]>,

    #[serde(default)]
    pub initial_endpoints: Vec<EndpointEntry>,
}

mod serde_optional_sig {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(sig: &Option<[u8; 64]>, s: S) -> Result<S::Ok, S::Error> {
        let as_slice: Option<&[u8]> = sig.as_ref().map(|b| &b[..]);
        serde::Serialize::serialize(&as_slice, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 64]>, D::Error> {
        let v: Option<Vec<u8>> = Option::<Vec<u8>>::deserialize(d)?;
        match v {
            None => Ok(None),
            Some(bytes) => bytes
                .as_slice()
                .try_into()
                .map(Some)
                .map_err(|_| D::Error::custom("consent signature must be exactly 64 bytes")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WeightChange {
    pub node_id: NodeId,
    pub weight: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconfigCommand {
    pub adds: Vec<ValidatorEntry>,
    pub removes: Vec<NodeId>,

    pub changes: Vec<WeightChange>,
    pub v_eff: View,
}

impl ReconfigCommand {
    pub fn encode(&self) -> Bytes {
        let body =
            postcard::to_stdvec(self).expect("postcard encoding of ReconfigCommand cannot fail");
        let mut out = Vec::with_capacity(RECONFIG_TAG.len() + body.len());
        out.extend_from_slice(RECONFIG_TAG);
        out.extend_from_slice(&body);
        Bytes::from(out)
    }

    pub fn is_reconfig_payload(bytes: &[u8]) -> bool {
        bytes.starts_with(RECONFIG_TAG)
    }

    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let body = bytes
            .strip_prefix(RECONFIG_TAG.as_slice())
            .ok_or_else(|| anyhow::anyhow!("missing reconfig tag prefix"))?;
        postcard::from_bytes(body).map_err(|e| anyhow::anyhow!("malformed ReconfigCommand: {e}"))
    }

    pub fn build_add_validator_payload(
        node_id: NodeId,
        addr: SocketAddr,
        weight: u64,
        v_eff: View,
    ) -> Bytes {
        Self {
            adds: vec![ValidatorEntry {
                node_id,
                addr,
                bls_pop: None,
                weight,
                operator_pubkey: None,
                consent_sig: None,
                initial_endpoints: vec![],
            }],
            removes: vec![],
            changes: vec![],
            v_eff,
        }
        .encode()
    }

    pub fn build_remove_validator_payload(node_id: NodeId, v_eff: View) -> Bytes {
        Self {
            adds: vec![],
            removes: vec![node_id],
            changes: vec![],
            v_eff,
        }
        .encode()
    }

    pub fn build_change_weight_payload(node_id: NodeId, weight: u64, v_eff: View) -> Bytes {
        Self {
            adds: vec![],
            removes: vec![],
            changes: vec![WeightChange { node_id, weight }],
            v_eff,
        }
        .encode()
    }

    pub fn validate_against_with_delay_and_chain(
        &self,
        current_set: &ValidatorSet,
        current_view: impl Into<View>,
        min_v_eff_delay: View,
        chain_id: &ChainId,
    ) -> anyhow::Result<Vec<(NodeId, u64)>> {
        let current_view = current_view.into();
        let effective_delay = std::cmp::max(min_v_eff_delay, MIN_V_EFF_DELAY);
        let min_v_eff = current_view.checked_add(effective_delay).ok_or_else(|| {
            anyhow::anyhow!("current_view {current_view} + delay {effective_delay} overflows",)
        })?;
        if self.v_eff < min_v_eff {
            anyhow::bail!(
                "v_eff {} must be >= current_view {} + delay {}",
                self.v_eff,
                current_view,
                effective_delay
            );
        }

        for entry in &self.adds {
            if entry.weight == 0 {
                anyhow::bail!(
                    "validator {} has weight 0; weight 0 is reserved — \
                     remove the validator via `removes` instead.",
                    hex::encode(entry.node_id),
                );
            }
        }
        for change in &self.changes {
            if change.weight == 0 {
                anyhow::bail!(
                    "weight change for {} carries weight 0; weight 0 is reserved — \
                     remove the validator via `removes` instead.",
                    hex::encode(change.node_id),
                );
            }
        }

        let mut adds_seen: BTreeSet<NodeId> = BTreeSet::new();
        for entry in &self.adds {
            if !adds_seen.insert(entry.node_id) {
                anyhow::bail!("duplicate node_id in adds: {}", hex::encode(entry.node_id));
            }
        }

        let mut removes_seen: BTreeSet<NodeId> = BTreeSet::new();
        for n in &self.removes {
            if !removes_seen.insert(*n) {
                anyhow::bail!("duplicate node_id in removes: {}", hex::encode(n));
            }
        }

        let mut changes_seen: BTreeSet<NodeId> = BTreeSet::new();
        for change in &self.changes {
            if !changes_seen.insert(change.node_id) {
                anyhow::bail!(
                    "duplicate node_id in changes: {}",
                    hex::encode(change.node_id)
                );
            }
        }

        if let Some(n) = adds_seen.intersection(&removes_seen).next() {
            anyhow::bail!(
                "node_id appears in both adds and removes: {}",
                hex::encode(n)
            );
        }
        if let Some(n) = adds_seen.intersection(&changes_seen).next() {
            anyhow::bail!(
                "node_id appears in both adds and changes: {}",
                hex::encode(n)
            );
        }
        if let Some(n) = removes_seen.intersection(&changes_seen).next() {
            anyhow::bail!(
                "node_id appears in both removes and changes: {}",
                hex::encode(n)
            );
        }

        for n in &removes_seen {
            let vid = ValidatorId::from_genesis_pubkey(*n);
            if !current_set.contains(&vid) {
                anyhow::bail!("remove targets non-member: {}", hex::encode(n));
            }
        }

        for n in &adds_seen {
            let vid = ValidatorId::from_genesis_pubkey(*n);
            if current_set.contains(&vid) {
                anyhow::bail!("add targets existing member: {}", hex::encode(n));
            }
        }

        for n in &changes_seen {
            let vid = ValidatorId::from_genesis_pubkey(*n);
            if !current_set.contains(&vid) {
                anyhow::bail!("change targets non-member: {}", hex::encode(n));
            }
        }

        for entry in &self.adds {
            match &entry.bls_pop {
                Some(pop) => {
                    BlsAggregated::verify_pop(pop, &pop.pubkey, chain_id).map_err(|e| match e {
                        BlsKeyError::PopPubkeyMismatch => anyhow::anyhow!(
                            "BLS PoP for validator {} has mismatched embedded pubkey",
                            hex::encode(entry.node_id),
                        ),
                        BlsKeyError::Blst(err) => anyhow::anyhow!(
                            "BLS PoP for validator {} failed to verify: {err:?}",
                            hex::encode(entry.node_id),
                        ),
                    })?;
                }
                None => {
                    anyhow::bail!(
                        "validator {} has no bls_pop — every `adds` entry must declare a \
                         proof-of-possession.",
                        hex::encode(entry.node_id),
                    );
                }
            }
        }

        for entry in &self.adds {
            if entry.operator_pubkey.is_none() {
                continue;
            }
            let consent = crate::reconfig_consent::ReconfigAddConsent::for_entry(entry, self.v_eff)
                .expect("operator_pubkey is Some, so for_entry returns Some");
            let sig = entry.consent_sig.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "validator {} declares an operator key but carries no inbound-consent \
                     signature (#548)",
                    hex::encode(entry.node_id),
                )
            })?;
            consent.verify(sig, chain_id).map_err(|e| {
                anyhow::anyhow!(
                    "inbound-consent signature for validator {} is invalid: {e}",
                    hex::encode(entry.node_id),
                )
            })?;
        }

        let mut next: Vec<(NodeId, u64)> = current_set
            .iter_weighted()
            .map(|(v, w)| (v.into_node_id(), w))
            .filter(|(n, _)| !removes_seen.contains(n))
            .collect();

        for change in &self.changes {
            if let Some((_, w)) = next.iter_mut().find(|(n, _)| *n == change.node_id) {
                *w = change.weight;
            }
        }

        for entry in &self.adds {
            next.push((entry.node_id, entry.weight));
        }
        next.sort_by_key(|(n, _)| *n);
        next.dedup_by_key(|(n, _)| *n);

        if next.len() < MIN_VALIDATOR_FLOOR {
            anyhow::bail!(
                "resulting set size {} below floor {}",
                next.len(),
                MIN_VALIDATOR_FLOOR
            );
        }

        Ok(next)
    }
}

pub fn read_bls_pop_file(path: &Path) -> anyhow::Result<BlsPop> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("reading --bls-pop-file {}: {e}", path.display()))?;
    let trimmed = raw.trim();
    let (pk_hex, sig_hex) = trimmed.split_once(':').ok_or_else(|| {
        anyhow::anyhow!(
            "{} is not in the expected `<pubkey_hex>:<pop_hex>` format",
            path.display(),
        )
    })?;
    let pk_bytes = hex::decode(pk_hex.trim())
        .map_err(|e| anyhow::anyhow!("--bls-pop-file pubkey is not valid hex: {e}"))?;
    let sig_bytes = hex::decode(sig_hex.trim())
        .map_err(|e| anyhow::anyhow!("--bls-pop-file pop signature is not valid hex: {e}"))?;
    if pk_bytes.len() != 48 {
        anyhow::bail!(
            "--bls-pop-file pubkey is {} bytes, expected 48",
            pk_bytes.len(),
        );
    }
    if sig_bytes.len() != 96 {
        anyhow::bail!(
            "--bls-pop-file pop signature is {} bytes, expected 96",
            sig_bytes.len(),
        );
    }
    let mut pubkey = [0u8; 48];
    pubkey.copy_from_slice(&pk_bytes);
    let mut sig = [0u8; 96];
    sig.copy_from_slice(&sig_bytes);
    Ok(BlsPop { pubkey, sig })
}

pub fn derive_bls_pop_from_key_file(path: &Path, chain_id: &ChainId) -> anyhow::Result<BlsPop> {
    use boule_core::crypto::bls_key::{BlsKeyFile, BlsKeyProvider as _};
    let provider = BlsKeyFile::new(path.to_path_buf());
    let id = provider
        .load_or_init()
        .map_err(|e| anyhow::anyhow!("loading BLS key from {}: {e}", path.display()))?;
    BlsAggregated::sign_pop(&id.secret, chain_id)
        .map_err(|e| anyhow::anyhow!("signing BLS PoP for {}: {e:?}", path.display()))
}

#[allow(clippy::too_many_arguments)]
pub fn build_add_validator_payload(
    config: Option<&boule_core::config::Config>,
    node_id: NodeId,
    addr: SocketAddr,
    v_eff: View,
    weight: u64,
    bls_pop_file: Option<&Path>,
    bls_key_file: Option<&Path>,
    operator_pubkey: Option<NodeId>,
    consent_sig: Option<[u8; 64]>,
    initial_endpoints: Vec<EndpointEntry>,
) -> anyhow::Result<Bytes> {
    let (entry, _chain_id) = resolve_add_entry(
        config,
        node_id,
        addr,
        weight,
        bls_pop_file,
        bls_key_file,
        operator_pubkey,
        consent_sig,
        initial_endpoints,
    )?;
    let cmd = ReconfigCommand {
        adds: vec![entry],
        removes: vec![],
        changes: vec![],
        v_eff,
    };
    Ok(cmd.encode())
}

#[allow(clippy::too_many_arguments)]
fn resolve_add_entry(
    config: Option<&boule_core::config::Config>,
    node_id: NodeId,
    addr: SocketAddr,
    weight: u64,
    bls_pop_file: Option<&Path>,
    bls_key_file: Option<&Path>,
    operator_pubkey: Option<NodeId>,
    consent_sig: Option<[u8; 64]>,
    initial_endpoints: Vec<EndpointEntry>,
) -> anyhow::Result<(ValidatorEntry, Option<ChainId>)> {
    if bls_pop_file.is_some() && bls_key_file.is_some() {
        anyhow::bail!(
            "--bls-pop-file and --bls-key-file are mutually exclusive — pass one or the other.",
        );
    }
    if (bls_pop_file.is_some() || bls_key_file.is_some()) && config.is_none() {
        anyhow::bail!(
            "--bls-pop-file / --bls-key-file requires --config so the chain_id can be derived \
             from the genesis. BLS proof-of-possession pre-images bind to chain_id (#410); \
             without --config the CLI cannot mint or verify the PoP.",
        );
    }

    let cfg_chain_id: Option<ChainId> = if let Some(cfg) = config {
        let cons = cfg.consensus.as_ref().ok_or_else(|| {
            anyhow::anyhow!("--config has no [consensus] section — cannot infer chain_id")
        })?;

        if bls_pop_file.is_none() && bls_key_file.is_none() {
            anyhow::bail!(
                "no --bls-pop-file or --bls-key-file was supplied. Every `adds` entry must \
                 carry a proof-of-possession.",
            );
        }
        Some(crate::genesis::derive_chain_id(cons)?)
    } else {
        None
    };

    let bls_pop = if let Some(path) = bls_pop_file {
        Some(read_bls_pop_file(path)?)
    } else if let Some(path) = bls_key_file {
        let chain_id = cfg_chain_id
            .as_ref()
            .expect("--config presence enforced above when --bls-key-file is set");
        Some(derive_bls_pop_from_key_file(path, chain_id)?)
    } else {
        None
    };

    if let Some(pop) = &bls_pop {
        let chain_id = cfg_chain_id
            .as_ref()
            .expect("--config presence enforced above when bls_pop is built");
        BlsAggregated::verify_pop(pop, &pop.pubkey, chain_id).map_err(|e| {
            anyhow::anyhow!(
                "BLS PoP failed verification under its embedded pubkey + the chain's chain_id: \
                 {e:?}. Re-mint the PoP for this deployment via --bls-key-file (PoP pre-images \
                 are now chain-bound, #410).",
            )
        })?;
    }

    let entry = ValidatorEntry {
        node_id,
        addr,
        bls_pop,
        weight,
        operator_pubkey,
        consent_sig,
        initial_endpoints,
    };
    Ok((entry, cfg_chain_id))
}

#[derive(Debug, Default)]
pub struct ReconfigConsentSignRequest {
    pub config_path: Option<PathBuf>,
    pub node_id: NodeId,
    pub addr: Option<SocketAddr>,
    pub weight: u64,
    pub v_eff: u64,
    pub bls_pop_file: Option<PathBuf>,
    pub bls_key_file: Option<PathBuf>,
    pub operator_key_backend: Option<String>,
    pub operator_key_path: Option<PathBuf>,
    pub operator_key_passphrase_env: Option<String>,

    pub initial_endpoints: Vec<EndpointEntry>,
}

pub fn build_add_consent_signature(
    req: &ReconfigConsentSignRequest,
) -> anyhow::Result<([u8; 64], NodeId)> {
    use boule_core::crypto::signed::{NodeSigner, Signer as _};

    let config_path = req.config_path.as_ref().ok_or_else(|| {
        anyhow::anyhow!("reconfig consent-sign requires --config (chain_id binds the consent)")
    })?;
    let addr = req
        .addr
        .ok_or_else(|| anyhow::anyhow!("reconfig consent-sign requires --addr"))?;
    let operator_backend = req.operator_key_backend.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "reconfig consent-sign requires --operator-key-backend <file|encrypted-file>"
        )
    })?;
    let v_eff = View(req.v_eff);

    let operator_cfg = crate::validator_rotation::build_new_identity_config_for_rotation(
        operator_backend,
        req.operator_key_path.clone(),
        req.operator_key_passphrase_env.clone(),
    )?;
    let operator_identity = boule_core::config::build_provider(&operator_cfg)?
        .try_load()?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no operator key found via the `{}` backend; consent is signed by the inbound \
                 validator's operator key, which must already exist",
                operator_cfg.backend_name(),
            )
        })?;
    let operator_signer = NodeSigner::from_identity(&operator_identity)?;
    let operator_pubkey = operator_signer.node_id();

    let config = boule_core::config::load(config_path)?;
    let (entry, chain_id) = resolve_add_entry(
        Some(&config),
        req.node_id,
        addr,
        req.weight,
        req.bls_pop_file.as_deref(),
        req.bls_key_file.as_deref(),
        Some(operator_pubkey),
        None,
        req.initial_endpoints.clone(),
    )?;
    let chain_id =
        chain_id.expect("config supplied above, so resolve_add_entry returns the chain_id");

    let consent = crate::reconfig_consent::ReconfigAddConsent::for_entry(&entry, v_eff)
        .expect("operator_pubkey is Some, so for_entry returns Some");
    let sig = consent.sign(&operator_signer, &chain_id)?;
    Ok((sig, operator_pubkey))
}
