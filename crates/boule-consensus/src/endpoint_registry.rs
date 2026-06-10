use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

use boule_core::crypto::signed::{ChainId, SignedMessage, Signer, preimage};
use boule_core::identity::NodeId;

pub const ENDPOINT_TAG: &[u8; 6] = b"ENDPT\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointEntry {
    pub network_id: NodeId,
    pub network_address: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EndpointOp {
    Set(Vec<EndpointEntry>),

    Add(Vec<EndpointEntry>),

    Remove(Vec<NodeId>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointCommand {
    pub validator: NodeId,

    pub seq: u64,
    pub op: EndpointOp,
}

impl SignedMessage for EndpointCommand {
    const DOMAIN: &'static str = "boule.consensus.endpoint_command.v1";
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedEndpointCommand {
    pub payload: EndpointCommand,
    #[serde(with = "serde_sig")]
    pub sig: [u8; 64],
}

impl SignedEndpointCommand {
    pub fn sign(payload: EndpointCommand, signer: &dyn Signer, chain_id: &ChainId) -> Self {
        let bytes = preimage::<EndpointCommand>(&payload, chain_id)
            .expect("serializing EndpointCommand pre-image cannot fail");
        let sig = signer.sign(&bytes);
        Self { payload, sig }
    }

    pub fn verify(
        &self,
        signing_pubkey: &NodeId,
        chain_id: &ChainId,
    ) -> Result<(), EndpointVerifyError> {
        let bytes = preimage::<EndpointCommand>(&self.payload, chain_id)
            .map_err(|e| EndpointVerifyError::Preimage(e.to_string()))?;
        UnparsedPublicKey::new(&ED25519, signing_pubkey as &[u8])
            .verify(&bytes, &self.sig)
            .map_err(|_| EndpointVerifyError::InvalidSignature)?;
        Ok(())
    }

    pub fn encode_command(&self) -> bytes::Bytes {
        let body = postcard::to_stdvec(self)
            .expect("postcard encoding of SignedEndpointCommand cannot fail");
        let mut out = Vec::with_capacity(ENDPOINT_TAG.len() + body.len());
        out.extend_from_slice(ENDPOINT_TAG);
        out.extend_from_slice(&body);
        bytes::Bytes::from(out)
    }

    pub fn is_endpoint_payload(bytes: &[u8]) -> bool {
        bytes.starts_with(ENDPOINT_TAG)
    }

    pub fn decode_command(bytes: &[u8]) -> anyhow::Result<Self> {
        let body = bytes
            .strip_prefix(ENDPOINT_TAG.as_slice())
            .ok_or_else(|| anyhow::anyhow!("missing endpoint tag prefix"))?;
        postcard::from_bytes(body)
            .map_err(|e| anyhow::anyhow!("malformed SignedEndpointCommand: {e}"))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum EndpointVerifyError {
    InvalidSignature,

    Preimage(String),
}

impl std::fmt::Display for EndpointVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignature => {
                f.write_str("endpoint command signature does not verify under the signing key")
            }
            Self::Preimage(e) => write!(f, "computing endpoint-command pre-image failed: {e}"),
        }
    }
}

impl std::error::Error for EndpointVerifyError {}

#[derive(Debug, PartialEq, Eq)]
pub enum EndpointApplyError {
    NonMonotonicSeq { last_seq: u64, seq: u64 },

    DuplicateNetworkId(NodeId),

    TooLong { max: usize, got: usize },
}

impl std::fmt::Display for EndpointApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonMonotonicSeq { last_seq, seq } => write!(
                f,
                "endpoint command seq {seq} is not greater than last-applied {last_seq}"
            ),
            Self::DuplicateNetworkId(id) => {
                write!(
                    f,
                    "duplicate network_id in endpoint list: {}",
                    hex::encode(id)
                )
            }
            Self::TooLong { max, got } => {
                write!(f, "endpoint list length {got} exceeds max {max}")
            }
        }
    }
}

impl std::error::Error for EndpointApplyError {}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct ValidatorEndpoints {
    last_seq: u64,
    entries: Vec<EndpointEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointRegistry {
    by_validator: BTreeMap<NodeId, ValidatorEndpoints>,

    max_len: usize,
}

impl EndpointRegistry {
    pub fn new(max_len: usize) -> Self {
        Self {
            by_validator: BTreeMap::new(),
            max_len,
        }
    }

    pub fn set_max_len(&mut self, max_len: usize) {
        self.max_len = max_len;
    }

    pub fn endpoints_of(&self, validator: &NodeId) -> &[EndpointEntry] {
        self.by_validator
            .get(validator)
            .map(|v| v.entries.as_slice())
            .unwrap_or(&[])
    }

    pub fn last_seq(&self, validator: &NodeId) -> u64 {
        self.by_validator
            .get(validator)
            .map(|v| v.last_seq)
            .unwrap_or(0)
    }

    pub fn forget(&mut self, validator: &NodeId) -> bool {
        self.by_validator.remove(validator).is_some()
    }

    pub fn seed(
        &mut self,
        validator: NodeId,
        entries: Vec<EndpointEntry>,
    ) -> Result<(), EndpointApplyError> {
        if entries.is_empty() {
            return Ok(());
        }
        dedup_check(entries.iter().map(|e| &e.network_id))?;
        if entries.len() > self.max_len {
            return Err(EndpointApplyError::TooLong {
                max: self.max_len,
                got: entries.len(),
            });
        }
        self.by_validator.insert(
            validator,
            ValidatorEndpoints {
                last_seq: 0,
                entries,
            },
        );
        Ok(())
    }

    pub fn apply(&mut self, cmd: &EndpointCommand) -> Result<(), EndpointApplyError> {
        let cur = self.by_validator.entry(cmd.validator).or_default();
        if cmd.seq <= cur.last_seq {
            return Err(EndpointApplyError::NonMonotonicSeq {
                last_seq: cur.last_seq,
                seq: cmd.seq,
            });
        }

        let proposed = match &cmd.op {
            EndpointOp::Set(entries) => {
                dedup_check(entries.iter().map(|e| &e.network_id))?;
                entries.clone()
            }
            EndpointOp::Add(entries) => {
                dedup_check(entries.iter().map(|e| &e.network_id))?;
                let mut next = cur.entries.clone();
                for e in entries {
                    if next.iter().any(|x| x.network_id == e.network_id) {
                        return Err(EndpointApplyError::DuplicateNetworkId(e.network_id));
                    }
                    next.push(e.clone());
                }
                next
            }
            EndpointOp::Remove(ids) => cur
                .entries
                .iter()
                .filter(|e| !ids.contains(&e.network_id))
                .cloned()
                .collect(),
        };

        if proposed.len() > self.max_len {
            return Err(EndpointApplyError::TooLong {
                max: self.max_len,
                got: proposed.len(),
            });
        }

        cur.entries = proposed;
        cur.last_seq = cmd.seq;
        Ok(())
    }
}

fn dedup_check<'a>(ids: impl Iterator<Item = &'a NodeId>) -> Result<(), EndpointApplyError> {
    let mut seen = std::collections::BTreeSet::new();
    for id in ids {
        if !seen.insert(*id) {
            return Err(EndpointApplyError::DuplicateNetworkId(*id));
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct EndpointPublishRequest {
    pub config_path: PathBuf,
    pub seq: u64,
    pub op: EndpointOp,
}

pub fn build_endpoint_command(
    req: &EndpointPublishRequest,
) -> anyhow::Result<SignedEndpointCommand> {
    let config = boule_core::config::load(&req.config_path)?;
    let cons = config.consensus.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "--config {} has no [consensus] section; an endpoint command binds to the \
             chain's chain_id",
            req.config_path.display(),
        )
    })?;
    let chain_id = crate::genesis::derive_chain_id(cons)?;

    let (id_cfg, slot) = match boule_core::config::resolve_validator_identity(&config.node) {
        Some(cfg) => (cfg, "validator"),
        None => match boule_core::config::resolve_identity(&config.node) {
            Some(cfg) => (cfg, "network (legacy single-key)"),
            None => anyhow::bail!(
                "--config {} has no [node.validator_identity] or [node.identity]; publishing \
                 endpoints needs the validator's consensus signing key",
                req.config_path.display(),
            ),
        },
    };
    let identity = boule_core::config::build_provider(&id_cfg)?
        .try_load()?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no consensus key found via the {slot} `{}` backend; provision it via \
                 `boule init` (or out-of-band) before publishing endpoints",
                id_cfg.backend_name(),
            )
        })?;
    let signer = boule_core::crypto::signed::NodeSigner::from_identity(&identity)?;

    let payload = EndpointCommand {
        validator: signer.node_id(),
        seq: req.seq,
        op: req.op.clone(),
    };
    Ok(SignedEndpointCommand::sign(payload, &signer, &chain_id))
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
