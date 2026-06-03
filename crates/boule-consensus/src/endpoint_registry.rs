//! On-chain validator endpoint advertisement (#546) — the state machine
//! that lets a validator publish where peers can reach its consensus
//! traffic.
//!
//! A validator maps to a list of [`EndpointEntry`] = `(network_id,
//! network_address)` pairs: the TLS pubkey peers authenticate against and
//! the address that speaks under it (typically a sentry node the validator
//! runs, not the validator's own key). Peers treat the list as a
//! **discovery hint** — connect to a published address, authenticate
//! against the published `network_id`, fall back to the gossip overlay on
//! mismatch. The list never *constrains* the validator; an empty list just
//! means "reach me via gossip."
//!
//! # Commands
//!
//! A validator mutates its own list with a [`SignedEndpointCommand`] — an
//! [`EndpointCommand`] (`set` / `add` / `remove`) signed by the validator's
//! consensus signing key (the same key class that signs rotations, #258),
//! bound to the deployment `chain_id` (#324). Replay is prevented by a
//! per-validator strictly-monotone `seq` carried in the payload and tracked
//! in the registry — self-contained, no dependency on the general replay
//! framework (#541).
//!
//! # Scope of this module
//!
//! Type definitions, the postcard/tagged wire form, signature
//! sign/verify, and the [`EndpointRegistry`] apply logic (monotone `seq`,
//! the `max_endpoint_list_length` cap, the no-duplicate-`network_id`
//! invariant, and `set`/`add`/`remove` semantics). The commit-time
//! application path, persistence, recovery re-derivation, and the
//! consensus-param wiring are follow-ups (mirroring how
//! [`crate::validator_rotation`] splits the pure verifier from the
//! commit-path application in the node's `reconfig_apply`-style code).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

use boule_core::crypto::signed::{ChainId, SignedMessage, Signer, preimage};
use boule_core::identity::NodeId;

/// Magic prefix tagging a `Block.commands` entry as a [`SignedEndpointCommand`]
/// (#546). Mirrors the 6-byte tag convention from [`crate::reconfig`] /
/// [`crate::validator_rotation`] so the commit scanner can route it without
/// attempting `postcard::from_bytes` on every opaque command slot.
pub const ENDPOINT_TAG: &[u8; 6] = b"ENDPT\0";

/// One advertised entry point for a validator's consensus traffic.
///
/// `network_id` is the network-layer (TLS) pubkey peers authenticate the
/// connection against — typically a sentry node's key, not the validator's
/// own consensus key. `network_address` is where a node speaking under that
/// `network_id` can be reached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointEntry {
    pub network_id: NodeId,
    pub network_address: SocketAddr,
}

/// The mutation an [`EndpointCommand`] applies to a validator's list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EndpointOp {
    /// Replace the validator's entire list with these entries.
    Set(Vec<EndpointEntry>),
    /// Append these entries (none may collide with an existing `network_id`).
    Add(Vec<EndpointEntry>),
    /// Drop entries whose `network_id` is in this list (absent ids are no-ops).
    Remove(Vec<NodeId>),
}

/// The signed payload: which validator, a strictly-monotone per-validator
/// `seq` (replay guard), and the operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointCommand {
    /// The validator publishing — its stable id (#328), independent of the
    /// active signing key, so a signing-key rotation does not orphan the
    /// list.
    pub validator: NodeId,
    /// Per-validator strictly-increasing sequence number. The registry
    /// rejects any command whose `seq` is not greater than the
    /// last-applied one for this validator, so a replayed command is a
    /// no-op.
    pub seq: u64,
    pub op: EndpointOp,
}

impl SignedMessage for EndpointCommand {
    const DOMAIN: &'static str = "boule.consensus.endpoint_command.v1";
}

/// An [`EndpointCommand`] plus the validator's signature over its
/// canonical, chain-bound pre-image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedEndpointCommand {
    pub payload: EndpointCommand,
    #[serde(with = "serde_sig")]
    pub sig: [u8; 64],
}

impl SignedEndpointCommand {
    /// Sign `payload` with the validator's consensus signing key.
    pub fn sign(payload: EndpointCommand, signer: &dyn Signer, chain_id: &ChainId) -> Self {
        // preimage is infallible for this fixed-shape payload; if
        // serialization ever regressed, signing a corrupt pre-image is no
        // worse than the panic, and verify would reject anyway.
        let bytes = preimage::<EndpointCommand>(&payload, chain_id)
            .expect("serializing EndpointCommand pre-image cannot fail");
        let sig = signer.sign(&bytes);
        Self { payload, sig }
    }

    /// Verify the signature under `signing_pubkey` — the key the validator
    /// was signing under at the command's view (the caller resolves this
    /// from the key history, same trusted-source discipline as rotation's
    /// `sig_old`). `chain_id` scopes the command to the deployment.
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

    /// Encode as a tagged byte sequence suitable for `Block.commands`.
    pub fn encode_command(&self) -> bytes::Bytes {
        let body = postcard::to_stdvec(self)
            .expect("postcard encoding of SignedEndpointCommand cannot fail");
        let mut out = Vec::with_capacity(ENDPOINT_TAG.len() + body.len());
        out.extend_from_slice(ENDPOINT_TAG);
        out.extend_from_slice(&body);
        bytes::Bytes::from(out)
    }

    /// True iff `bytes` carries the endpoint-command tag prefix.
    pub fn is_endpoint_payload(bytes: &[u8]) -> bool {
        bytes.starts_with(ENDPOINT_TAG)
    }

    /// Decode a tagged endpoint command. Errors if the tag is absent or the
    /// body is malformed.
    pub fn decode_command(bytes: &[u8]) -> anyhow::Result<Self> {
        let body = bytes
            .strip_prefix(ENDPOINT_TAG.as_slice())
            .ok_or_else(|| anyhow::anyhow!("missing endpoint tag prefix"))?;
        postcard::from_bytes(body)
            .map_err(|e| anyhow::anyhow!("malformed SignedEndpointCommand: {e}"))
    }
}

/// Why a [`SignedEndpointCommand`] signature was rejected.
#[derive(Debug, PartialEq, Eq)]
pub enum EndpointVerifyError {
    /// The signature does not verify under the provided signing pubkey over
    /// the canonical pre-image. Covers a forged/tampered signature, a wrong
    /// key, an altered payload, and a wrong-chain replay.
    InvalidSignature,
    /// Recovering the canonical pre-image failed (a serialization
    /// regression). Surfaced distinctly so it is not masked as a bad
    /// signature.
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

/// Why applying an [`EndpointCommand`] to the registry was rejected. The
/// command is dropped (no-op) on any of these — it never rolls back the
/// block that carried it.
#[derive(Debug, PartialEq, Eq)]
pub enum EndpointApplyError {
    /// `seq` was not strictly greater than the validator's last-applied
    /// `seq` — a stale or replayed command.
    NonMonotonicSeq { last_seq: u64, seq: u64 },
    /// A `set`/`add` carried two entries with the same `network_id`, or an
    /// `add` collided with an existing one — the list must hold each
    /// `network_id` at most once.
    DuplicateNetworkId(NodeId),
    /// The resulting list would exceed `max_endpoint_list_length`.
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

/// Per-validator endpoint state: the last-applied `seq` (replay guard) and
/// the current list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct ValidatorEndpoints {
    last_seq: u64,
    entries: Vec<EndpointEntry>,
}

/// The validator → endpoint-list map (#546). Deterministic: every replica
/// applies the same committed commands in order and reaches the same state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointRegistry {
    by_validator: BTreeMap<NodeId, ValidatorEndpoints>,
    /// Cap on a single validator's published list
    /// (`max_endpoint_list_length`).
    max_len: usize,
}

impl EndpointRegistry {
    /// An empty registry capping each validator's list at `max_len`.
    pub fn new(max_len: usize) -> Self {
        Self {
            by_validator: BTreeMap::new(),
            max_len,
        }
    }

    /// The validator's currently-published entries (empty if none).
    pub fn endpoints_of(&self, validator: &NodeId) -> &[EndpointEntry] {
        self.by_validator
            .get(validator)
            .map(|v| v.entries.as_slice())
            .unwrap_or(&[])
    }

    /// The last-applied `seq` for `validator` (0 if it has never published).
    pub fn last_seq(&self, validator: &NodeId) -> u64 {
        self.by_validator
            .get(validator)
            .map(|v| v.last_seq)
            .unwrap_or(0)
    }

    /// Drop a validator's entire endpoint state — used when a validator is
    /// removed from the set (GC at `v_eff + k`, #546 lifecycle). A no-op if
    /// absent.
    pub fn forget(&mut self, validator: &NodeId) {
        self.by_validator.remove(validator);
    }

    /// Apply a (already signature-verified) command. Enforces the monotone
    /// `seq` replay guard, the no-duplicate-`network_id` invariant, and the
    /// `max_len` cap; mutates the validator's list per the op. On any error
    /// the registry is left unchanged (the caller log-and-drops, like every
    /// other system-tx apply path).
    pub fn apply(&mut self, cmd: &EndpointCommand) -> Result<(), EndpointApplyError> {
        let cur = self.by_validator.entry(cmd.validator).or_default();
        if cmd.seq <= cur.last_seq {
            return Err(EndpointApplyError::NonMonotonicSeq {
                last_seq: cur.last_seq,
                seq: cmd.seq,
            });
        }

        // Compute the proposed list without mutating until it is fully
        // validated, so a rejected command leaves no partial state.
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

/// Reject an iterator of `network_id`s containing a duplicate.
fn dedup_check<'a>(ids: impl Iterator<Item = &'a NodeId>) -> Result<(), EndpointApplyError> {
    let mut seen = std::collections::BTreeSet::new();
    for id in ids {
        if !seen.insert(*id) {
            return Err(EndpointApplyError::DuplicateNetworkId(*id));
        }
    }
    Ok(())
}

/// CLI inputs for `boule endpoint {set,add,remove}` (#546): build a signed
/// endpoint command from the node's config + an operator-supplied
/// sequence number and operation.
#[derive(Debug)]
pub struct EndpointPublishRequest {
    pub config_path: PathBuf,
    pub seq: u64,
    pub op: EndpointOp,
}

/// Build a [`SignedEndpointCommand`] for this node's validator, signed by
/// its consensus key resolved from `--config` and bound to the chain_id —
/// the payload-builder backing `boule endpoint {set,add,remove}` (mirrors
/// [`crate::validator_rotation`]'s `build_rotation_envelope`). The operator
/// pipes the printed hex into a validator's mempool, the same route as a
/// reconfig / rotation tx.
///
/// `seq` must strictly exceed the validator's last-applied endpoint `seq`
/// (the registry rejects a stale one at commit); the operator tracks it.
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

    // Resolve the validator signing key, mirroring `start` / rotation
    // precedence: prefer `[node.validator_identity]`, else the network
    // identity. It must already exist on disk.
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

/// Compact `Option`-free 64-byte signature codec (serde has no built-in
/// array impl past length 32). Mirrors the helper in
/// [`crate::validator_rotation`].
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

#[cfg(test)]
mod tests {
    use super::*;
    use boule_core::crypto::signed::NodeSigner;
    use boule_core::identity::NodeIdentity;
    use rcgen::{KeyPair as RcgenKeyPair, PKCS_ED25519};
    use zeroize::Zeroizing;

    fn fresh_signer() -> NodeSigner {
        let kp = RcgenKeyPair::generate_for(&PKCS_ED25519).unwrap();
        let id = NodeIdentity {
            pkcs8_der: Zeroizing::new(kp.serialize_der()),
        };
        NodeSigner::from_identity(&id).unwrap()
    }

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn entry(net: u8, port: u16) -> EndpointEntry {
        EndpointEntry {
            network_id: nid(net),
            network_address: format!("10.0.0.{net}:{port}").parse().unwrap(),
        }
    }

    fn cmd(validator: NodeId, seq: u64, op: EndpointOp) -> EndpointCommand {
        EndpointCommand { validator, seq, op }
    }

    // ── signing / verification ──────────────────────────────────────────

    #[test]
    fn sign_verify_round_trips() {
        let signer = fresh_signer();
        let payload = cmd(signer.node_id(), 1, EndpointOp::Set(vec![entry(1, 9001)]));
        let signed = SignedEndpointCommand::sign(payload, &signer, &ChainId::TEST);
        assert_eq!(signed.verify(&signer.node_id(), &ChainId::TEST), Ok(()));
    }

    #[test]
    fn wrong_key_is_rejected() {
        let signer = fresh_signer();
        let other = fresh_signer();
        let payload = cmd(signer.node_id(), 1, EndpointOp::Set(vec![entry(1, 9001)]));
        let signed = SignedEndpointCommand::sign(payload, &signer, &ChainId::TEST);
        assert_eq!(
            signed.verify(&other.node_id(), &ChainId::TEST),
            Err(EndpointVerifyError::InvalidSignature),
        );
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let signer = fresh_signer();
        let payload = cmd(signer.node_id(), 1, EndpointOp::Set(vec![entry(1, 9001)]));
        let mut signed = SignedEndpointCommand::sign(payload, &signer, &ChainId::TEST);
        signed.payload.seq = 2;
        assert_eq!(
            signed.verify(&signer.node_id(), &ChainId::TEST),
            Err(EndpointVerifyError::InvalidSignature),
        );
    }

    #[test]
    fn does_not_cross_chains() {
        let signer = fresh_signer();
        let payload = cmd(signer.node_id(), 1, EndpointOp::Set(vec![entry(1, 9001)]));
        let signed = SignedEndpointCommand::sign(payload, &signer, &ChainId::TEST);
        assert_eq!(
            signed.verify(&signer.node_id(), &ChainId([9; 32])),
            Err(EndpointVerifyError::InvalidSignature),
        );
    }

    #[test]
    fn tagged_codec_round_trips() {
        let signer = fresh_signer();
        let payload = cmd(signer.node_id(), 3, EndpointOp::Add(vec![entry(2, 9002)]));
        let signed = SignedEndpointCommand::sign(payload, &signer, &ChainId::TEST);
        let bytes = signed.encode_command();
        assert!(SignedEndpointCommand::is_endpoint_payload(&bytes));
        assert_eq!(
            SignedEndpointCommand::decode_command(&bytes).unwrap(),
            signed
        );
    }

    // ── registry apply ──────────────────────────────────────────────────

    #[test]
    fn set_then_add_then_remove() {
        let v = nid(0xAA);
        let mut reg = EndpointRegistry::new(8);
        assert!(reg.endpoints_of(&v).is_empty());

        reg.apply(&cmd(v, 1, EndpointOp::Set(vec![entry(1, 9001)])))
            .unwrap();
        assert_eq!(reg.endpoints_of(&v), &[entry(1, 9001)]);

        reg.apply(&cmd(v, 2, EndpointOp::Add(vec![entry(2, 9002)])))
            .unwrap();
        assert_eq!(reg.endpoints_of(&v), &[entry(1, 9001), entry(2, 9002)]);

        reg.apply(&cmd(v, 3, EndpointOp::Remove(vec![nid(1)])))
            .unwrap();
        assert_eq!(reg.endpoints_of(&v), &[entry(2, 9002)]);
        assert_eq!(reg.last_seq(&v), 3);
    }

    #[test]
    fn replayed_or_stale_seq_is_rejected() {
        let v = nid(0xAA);
        let mut reg = EndpointRegistry::new(8);
        reg.apply(&cmd(v, 5, EndpointOp::Set(vec![entry(1, 9001)])))
            .unwrap();
        // Equal seq: replay.
        assert_eq!(
            reg.apply(&cmd(v, 5, EndpointOp::Set(vec![entry(2, 9002)]))),
            Err(EndpointApplyError::NonMonotonicSeq {
                last_seq: 5,
                seq: 5
            }),
        );
        // Earlier seq: stale.
        assert!(matches!(
            reg.apply(&cmd(v, 4, EndpointOp::Set(vec![]))),
            Err(EndpointApplyError::NonMonotonicSeq { .. })
        ));
        // The list is unchanged by the rejected commands.
        assert_eq!(reg.endpoints_of(&v), &[entry(1, 9001)]);
    }

    #[test]
    fn set_with_internal_duplicate_is_rejected() {
        let v = nid(0xAA);
        let mut reg = EndpointRegistry::new(8);
        assert_eq!(
            reg.apply(&cmd(
                v,
                1,
                EndpointOp::Set(vec![entry(1, 9001), entry(1, 9999)])
            )),
            Err(EndpointApplyError::DuplicateNetworkId(nid(1))),
        );
        assert!(reg.endpoints_of(&v).is_empty());
        // ...and the rejected command did not advance seq.
        assert_eq!(reg.last_seq(&v), 0);
    }

    #[test]
    fn add_colliding_with_existing_network_id_is_rejected() {
        let v = nid(0xAA);
        let mut reg = EndpointRegistry::new(8);
        reg.apply(&cmd(v, 1, EndpointOp::Set(vec![entry(1, 9001)])))
            .unwrap();
        assert_eq!(
            reg.apply(&cmd(v, 2, EndpointOp::Add(vec![entry(1, 9999)]))),
            Err(EndpointApplyError::DuplicateNetworkId(nid(1))),
        );
        assert_eq!(reg.endpoints_of(&v), &[entry(1, 9001)]);
    }

    #[test]
    fn exceeding_max_len_is_rejected() {
        let v = nid(0xAA);
        let mut reg = EndpointRegistry::new(2);
        assert_eq!(
            reg.apply(&cmd(
                v,
                1,
                EndpointOp::Set(vec![entry(1, 9001), entry(2, 9002), entry(3, 9003)])
            )),
            Err(EndpointApplyError::TooLong { max: 2, got: 3 }),
        );
        assert!(reg.endpoints_of(&v).is_empty());
    }

    #[test]
    fn remove_of_absent_id_is_a_noop_but_advances_seq() {
        let v = nid(0xAA);
        let mut reg = EndpointRegistry::new(8);
        reg.apply(&cmd(v, 1, EndpointOp::Set(vec![entry(1, 9001)])))
            .unwrap();
        reg.apply(&cmd(v, 2, EndpointOp::Remove(vec![nid(0xEE)])))
            .unwrap();
        assert_eq!(reg.endpoints_of(&v), &[entry(1, 9001)]);
        assert_eq!(reg.last_seq(&v), 2);
    }

    #[test]
    fn forget_drops_a_validators_state() {
        let v = nid(0xAA);
        let mut reg = EndpointRegistry::new(8);
        reg.apply(&cmd(v, 1, EndpointOp::Set(vec![entry(1, 9001)])))
            .unwrap();
        reg.forget(&v);
        assert!(reg.endpoints_of(&v).is_empty());
        // After GC, seq resets — a re-added validator starts fresh.
        assert_eq!(reg.last_seq(&v), 0);
    }

    #[test]
    fn validators_are_independent() {
        let (a, b) = (nid(1), nid(2));
        let mut reg = EndpointRegistry::new(8);
        reg.apply(&cmd(a, 1, EndpointOp::Set(vec![entry(10, 9001)])))
            .unwrap();
        reg.apply(&cmd(b, 1, EndpointOp::Set(vec![entry(20, 9002)])))
            .unwrap();
        assert_eq!(reg.endpoints_of(&a), &[entry(10, 9001)]);
        assert_eq!(reg.endpoints_of(&b), &[entry(20, 9002)]);
    }

    /// End-to-end CLI builder: mint a validator key + minimal config, build a
    /// `Set` command, and confirm it is signed by that validator's key under
    /// the config's derived chain_id.
    #[test]
    fn build_endpoint_command_signs_under_the_validator_key() {
        use boule_core::crypto::signed::Signer as _;
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let key_path = dir.path().join("validator.key");
        let provider =
            boule_core::config::build_provider(&boule_core::config::IdentityConfig::File {
                path: key_path.clone(),
                allow_insecure_perms: false,
            })
            .unwrap();
        let identity = provider.load_or_init().unwrap();
        let validator = boule_core::crypto::signed::NodeSigner::from_identity(&identity)
            .unwrap()
            .node_id();
        let validator_b58 = boule_core::identity::node_id_to_base58(&validator);

        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            format!(
                "[node]\n\
                 listen_addr = \"127.0.0.1:7000\"\n\n\
                 [node.identity]\n\
                 backend = \"file\"\n\
                 path = \"{key}\"\n\n\
                 [api]\n\
                 listen_addr = \"127.0.0.1:8000\"\n\n\
                 [consensus]\n\
                 validators = [\"{val}\"]\n\
                 signature_scheme = \"ed25519_collected\"\n",
                key = key_path.display(),
                val = validator_b58,
            ),
        )
        .unwrap();

        let req = EndpointPublishRequest {
            config_path: config_path.clone(),
            seq: 1,
            op: EndpointOp::Set(vec![entry(9, 9001)]),
        };
        let signed = build_endpoint_command(&req).expect("build must succeed");
        assert_eq!(signed.payload.validator, validator);
        assert_eq!(signed.payload.seq, 1);

        let cfg = boule_core::config::load(&config_path).unwrap();
        let chain_id = crate::genesis::derive_chain_id(cfg.consensus.as_ref().unwrap()).unwrap();
        assert_eq!(signed.verify(&validator, &chain_id), Ok(()));
    }
}
