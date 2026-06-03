use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tracing::{info, warn};

use crate::cli::OutputFormat;
use crate::crypto::sig_scheme::{BlsAggregated, BlsPop, BlsPublicKey, SignatureSchemeChoice};
use crate::crypto::signed::ChainId;
use crate::identity::KeyProvider;
use crate::identity::encrypted_file::EncryptedFileKeyProvider;
use crate::identity::env::EnvKeyProvider;
use crate::identity::exec::ExecKeyProvider;
use crate::identity::file::FileKeyProvider;
use crate::identity::{NodeId, base58_to_node_id, node_id_to_base58};

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct Config {
    pub node: NodeConfig,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<PeerConfig>,
    pub api: ApiConfig,
    /// Optional HotStuff consensus configuration. When absent the node
    /// runs gossip-only; when present a `boule_node::consensus_node::ConsensusNode`
    /// is started alongside the gossip and ping protocols.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consensus: Option<ConsensusConfig>,
    /// Topology overlay configuration for the partial-mesh gossip
    /// overlay (issue #137). When absent, the gossip defaults apply.
    #[serde(default)]
    pub overlay: OverlayConfig,
    /// Per-peer rate limiting and global connection caps (issue #134).
    /// Defaults apply when the section is omitted.
    #[serde(default)]
    pub p2p: P2pConfig,
    /// Operator-facing UI knobs — currently just the global default for
    /// CLI structured-output formatting (issue #149). Per-invocation
    /// `--format` flags on individual subcommands override this.
    #[serde(default)]
    pub ui: UiConfig,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct NodeConfig {
    pub listen_addr: SocketAddr,
    /// Network (TLS) identity backend. The Ed25519 public key loaded here
    /// becomes the node's overlay [`crate::identity::NodeId`] and the
    /// certificate the TLS handshake presents. If absent, falls back to
    /// the deprecated `key_file` field or, failing that, a file backend
    /// at `./node.key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityConfig>,
    /// Optional validator (consensus signing) identity backend. When set,
    /// the consensus layer signs proposals/votes/timeouts with this key
    /// instead of the network identity. When unset, the network identity
    /// is reused for consensus signing — the historical single-key
    /// behavior — with a deprecation warning at startup if consensus is
    /// enabled. Both slots accept any of the same backends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validator_identity: Option<IdentityConfig>,
    /// BLS validator-signing identity backend. Required when the chain's
    /// `signature_scheme = "bls_aggregated"` (#288); rejected when the
    /// chain is `ed25519_collected` so a misconfigured node refuses to
    /// start rather than booting in an inconsistent state. Today only a
    /// `file` backend is supported. See [`BlsIdentityConfig`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bls_validator_identity: Option<BlsIdentityConfig>,
    /// Deprecated alias for `[node.identity] backend = "file" path = ...`.
    /// Retained for backward compatibility; emits a warning at startup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_file: Option<PathBuf>,
    /// If set, the node writes its actual bound addresses and node ID to this file
    /// as JSON once both listeners are ready. Used by tests to discover dynamic ports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addr_file: Option<PathBuf>,
}

/// Where the node's long-term Ed25519 identity lives.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(tag = "backend", rename_all = "kebab-case")]
pub enum IdentityConfig {
    /// PKCS#8 PEM on disk, mode 0600. Default for development.
    File {
        #[serde(default = "default_key_file")]
        path: PathBuf,
        /// Skip the 0o077 permission check on read (dev escape hatch).
        #[serde(default)]
        allow_insecure_perms: bool,
    },
    /// Read PKCS#8 (PEM or base64 DER) from an environment variable.
    /// Suitable for K8s secret volumes projected to env.
    Env { env_var: String },
    /// OS keyring (Secret Service / Keychain / Credential Manager).
    /// Requires the `keyring-backend` cargo feature.
    Keyring {
        #[cfg_attr(not(feature = "keyring-backend"), allow(dead_code))]
        #[serde(default = "default_keyring_service")]
        service: String,
        #[cfg_attr(not(feature = "keyring-backend"), allow(dead_code))]
        #[serde(default, skip_serializing_if = "Option::is_none")]
        account: Option<String>,
    },
    /// Passphrase-encrypted file (XChaCha20-Poly1305 + Argon2id).
    EncryptedFile {
        path: PathBuf,
        /// Env var to read the passphrase from. If omitted, prompts the TTY.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase_env: Option<String>,
    },
    /// Run an operator-provided command; read PKCS#8 from its stdout.
    /// Escape hatch for Vault / KMS / custom signers before first-class
    /// backends ship.
    Exec { command: Vec<String> },
}

impl IdentityConfig {
    pub fn backend_name(&self) -> &'static str {
        match self {
            Self::File { .. } => "file",
            Self::Env { .. } => "env",
            Self::Keyring { .. } => "keyring",
            Self::EncryptedFile { .. } => "encrypted-file",
            Self::Exec { .. } => "exec",
        }
    }
}

/// Where the node's BLS validator-signing key lives. Distinct from
/// [`IdentityConfig`] because BLS keys aren't an X.509 algorithm —
/// they're 32 raw secret-key bytes with a 1-byte format-version
/// header (see [`crate::crypto::bls_key::BlsKeyFile`]). PEM/PKCS#8
/// framing would only obscure the wire-format invariants.
///
/// Only `file` is implemented today; `env` and `exec` would mirror
/// their [`IdentityConfig`] counterparts when the need arises.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(tag = "backend", rename_all = "kebab-case")]
pub enum BlsIdentityConfig {
    /// Raw 33-byte secret-key file on disk, mode 0600.
    File {
        path: PathBuf,
        /// Skip the 0o077 permission check on read (dev escape hatch).
        #[serde(default)]
        allow_insecure_perms: bool,
    },
}

impl BlsIdentityConfig {
    pub fn backend_name(&self) -> &'static str {
        match self {
            Self::File { .. } => "file",
        }
    }
}

fn default_key_file() -> PathBuf {
    PathBuf::from("node.key")
}

fn default_keyring_service() -> String {
    "boule".to_string()
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct PeerConfig {
    pub addr: SocketAddr,
    /// Expected base58-encoded Ed25519 node ID of this peer.
    /// If set, the connection is rejected when the peer presents a different identity.
    /// Omit for trust-on-first-use (e.g. in development).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct ApiConfig {
    pub listen_addr: SocketAddr,
}

/// `[consensus.application]` — which execution backend processes the
/// blocks consensus orders. Absent means the built-in counter state
/// machine. `backend = "reth"` drives an external reth execution layer
/// over the Engine API (one block = one EVM payload); it requires the
/// node binary to be built with the `reth` cargo feature, otherwise
/// startup fails with a clear error.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(tag = "backend", rename_all = "kebab-case")]
pub enum ApplicationConfig {
    /// The built-in in-process counter state machine (the default).
    Counter,
    /// An external reth EL driven over the Engine API.
    Reth {
        /// Authenticated Engine API endpoint (reth `--authrpc`, e.g.
        /// `http://127.0.0.1:8551`).
        engine_url: String,
        /// Public `eth_*` JSON-RPC endpoint (e.g. `http://127.0.0.1:8545`),
        /// used to read reth's genesis for the consensus↔EL genesis bridge.
        eth_url: String,
        /// Path to reth's `--authrpc.jwtsecret` (32-byte hex).
        jwt_secret_path: PathBuf,
        /// EVM `suggestedFeeRecipient` for built payloads.
        fee_recipient: String,
        /// Pause between `forkchoiceUpdatedV3(attrs)` and `getPayloadV3`
        /// so reth's async build can pull pool transactions in.
        #[serde(default = "default_reth_build_wait_ms")]
        build_wait_ms: u64,
        /// Other validators' reth `enode://…` URLs. At startup the node
        /// connects its local reth to each via `admin_addPeer` (reth's
        /// `admin` RPC namespace must be enabled). Peering the validator
        /// reths enables EVM tx-pool gossip (a tx submitted to any node is
        /// seen by every leader) and lets a behind/fresh reth self-sync
        /// (snap/full) from its peers. Empty = isolated reths.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        reth_peers: Vec<String>,
    },
}

fn default_reth_build_wait_ms() -> u64 {
    200
}

/// HotStuff consensus configuration. Opt-in via the top-level
/// `[consensus]` table; absent means the binary runs gossip-only.
///
/// The `validators` list must contain this node's own base58 NodeId
/// and must be byte-identical across every replica in the cluster
/// (validator-set ordering determines round-robin leader rotation).
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ConsensusConfig {
    /// Base58-encoded NodeIds of every validator in the committee.
    /// Must include this node's own ID.
    pub validators: Vec<String>,
    /// 32-byte hex string used as the genesis block's `state_commitment`.
    /// Must match across all replicas. Defaults to all zeros. For the
    /// reth backend this must equal reth's genesis state root (the node
    /// verifies that bridge at startup).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genesis_seed_hex: Option<String>,
    /// Optional weak-subjectivity checkpoint (#642): a recent, operator-trusted
    /// finalized block. When set, the node refuses to commit or recover a chain
    /// whose block at `height` does not hash to `hash` — an anchor a fresh
    /// joiner trusts instead of re-verifying the whole history from genesis, and
    /// the snap-sync pivot anchor for the reth backend. Unset (the default) is
    /// genesis-anchored, today's behaviour. See `[consensus.weak_subjectivity_checkpoint]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weak_subjectivity_checkpoint: Option<WeakSubjectivityCheckpoint>,
    /// Execution backend (`[consensus.application]`). Absent = the
    /// built-in counter state machine. See [`ApplicationConfig`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<ApplicationConfig>,
    /// Maximum commands the leader pulls from the mempool per proposal.
    #[serde(default = "default_propose_limit")]
    pub propose_limit: usize,
    /// Maximum entries the bundled in-memory mempool will accept.
    /// Inserts past the cap surface as `Err` to the caller (see
    /// `boule_consensus::replication::impls::mem_mempool::InMemoryMempool`),
    /// rather than silently dropping. The application layer that will
    /// eventually replace this implementation is free to ignore the
    /// field; consensus only consults it when constructing the default
    /// `InMemoryMempool` at startup. Lives here beside [`Self::propose_limit`]
    /// (the other mempool-facing knob) rather than under
    /// `[consensus.limits]`, which holds only the safety-core cache caps
    /// that project into `boule_consensus::limits::CacheLimits`.
    #[serde(default = "default_mempool_capacity")]
    pub mempool_capacity: usize,
    /// Cap on the number of entries a single validator may publish in its
    /// on-chain endpoint list (#546). A consensus parameter — identical
    /// across replicas — bounding the cluster-amplified-flood attack
    /// surface (a Byzantine validator publishing many bogus
    /// `(network_id, address)` pairs). Live updates are tracked by #542.
    #[serde(default = "default_max_endpoint_list_length")]
    pub max_endpoint_list_length: usize,
    /// View-timer base duration in milliseconds.
    #[serde(default = "default_timeout_base_ms")]
    pub timeout_base_ms: u64,
    /// View-timer ceiling (exponential backoff saturates here) in ms.
    #[serde(default = "default_timeout_max_ms")]
    pub timeout_max_ms: u64,
    /// Directory holding the consensus KV store and WAL on disk.
    /// If unset, in-memory storage is used (no crash recovery).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_dir: Option<PathBuf>,
    /// Bounded-cache caps for the safety core and the integration
    /// layer's timeout-vote handler. See [`ConsensusLimits`] for the
    /// per-cache documentation; defaults match
    /// `boule_consensus::limits::CacheLimits::production_defaults`.
    #[serde(default)]
    pub limits: ConsensusLimits,
    /// Take a state-machine snapshot every `snapshot_interval_blocks`
    /// committed blocks. `0` disables snapshot creation entirely. See
    /// `boule_consensus::replication::snapshot` for the on-disk layout.
    #[serde(default = "default_snapshot_interval_blocks")]
    pub snapshot_interval_blocks: u64,
    /// Number of most-recent snapshots to keep on disk. Older snapshots
    /// are pruned atomically when a new one commits. `0` disables
    /// pruning (snapshots accumulate without bound — useful for tests).
    #[serde(default = "default_snapshot_retention_count")]
    pub snapshot_retention_count: usize,
    /// Bytes per snapshot chunk. Must be `> 0` and leave headroom under
    /// the consensus protocol's `MAX_FRAME_BYTES` once postcard envelope
    /// overhead is added; [`ConsensusConfig::validate_snapshot_policy`]
    /// enforces the bound.
    #[serde(default = "default_snapshot_chunk_size_bytes")]
    pub snapshot_chunk_size_bytes: u32,
    /// Signature scheme used by this chain's QCs. Selected at genesis
    /// and **fixed** for the lifetime of the chain — switching requires
    /// a coordinated restart from new genesis. Defaults to
    /// `"ed25519_collected"`. Unknown values are rejected at parse time
    /// so an operator who fat-fingers the field learns at startup
    /// rather than mid-cluster. See [`SignatureSchemeChoice`].
    #[serde(default)]
    pub signature_scheme: SignatureSchemeChoice,
    /// Per-validator BLS pubkey + proof-of-possession declarations.
    ///
    /// Required when `signature_scheme = "bls_aggregated"`: every
    /// validator listed in `validators` must appear here exactly once
    /// with a hex-encoded BLS pubkey and PoP, both verified at startup.
    /// Forbidden when `signature_scheme = "ed25519_collected"`: an
    /// Ed25519 chain has no use for BLS keys, and silently accepting
    /// them would mask a misconfigured genesis. See
    /// [`ConsensusConfig::resolve_genesis_bls_keys`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub validators_bls: Vec<ValidatorBlsEntry>,
    /// Per-validator **operator-key** declarations (#549).
    ///
    /// The operator key is the cold-storage / multi-sig administrative key
    /// that can rotate a validator's consensus *signing* key without the old
    /// signing key — the recovery-from-loss path. Optional: a validator that
    /// declares no operator key here simply cannot use operator-authorised
    /// actions (it relies on dual-signed signing-key rotation, which needs
    /// the old key). Each entry's `node_id` must reference a declared
    /// validator; declared at most once. See
    /// [`ConsensusConfig::resolve_genesis_operator_keys`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub validators_operator_keys: Vec<ValidatorOperatorKeyEntry>,
    /// Number of committed blocks to retain in `kv.redb` below
    /// `last_committed`. Older committed blocks are deleted in the
    /// same atomic batch as each commit. `0` disables pruning entirely
    /// (archive mode — every committed block is kept). The block-sync
    /// responder serves `BlockResponse(None)` for any pruned hash, so
    /// the window is "how stale is the laggiest peer we want to
    /// serve?" — not a safety knob.
    #[serde(default = "default_block_retention_window")]
    pub block_retention_window: u64,
    /// Minimum wall-clock spacing, in milliseconds, between proposals this
    /// node produces as leader. `0` (the default) disables pacing. At
    /// `n >= 4` the network already paces block production, so this only
    /// bites a local leader that would otherwise outrun it — most usefully a
    /// single-validator dev chain, where it sets a steady block time instead
    /// of producing blocks as fast as the loop spins.
    #[serde(default)]
    pub min_block_interval_ms: u64,
}

/// A weak-subjectivity checkpoint: a recent, operator-trusted finalized block,
/// surfaced as the `[consensus.weak_subjectivity_checkpoint]` TOML table.
///
/// It is the trust anchor a fresh joiner uses instead of re-verifying the whole
/// chain from genesis: the node refuses to commit or recover any chain whose
/// block at `height` does not hash to `hash`. Operators source it out of band
/// (a block hash from a trusted node / explorer at a recent finalized height).
/// Trade-off: a stale checkpoint still anchors safety but lets the node accept a
/// longer prefix unverified-against-recent-state; genesis-only (unset) verifies
/// everything but cannot rule out a long-range fork a fresh joiner is fed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct WeakSubjectivityCheckpoint {
    /// Committed height the checkpoint pins. Must be `> 0` (genesis is already
    /// agreed via `genesis_seed_hex`).
    pub height: u64,
    /// 32-byte block content hash at `height`, lower-case hex (64 chars).
    pub hash: String,
}

/// One row of [`ConsensusConfig::validators_bls`]: the BLS half of a
/// genesis validator's identity. Cross-referenced with
/// [`ConsensusConfig::validators`] by `node_id`; the count and set of
/// `node_id`s must match.
///
/// Hex-encoded on disk so the file is human-diffable; parsed and
/// PoP-verified by [`ConsensusConfig::resolve_genesis_bls_keys`].
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ValidatorBlsEntry {
    /// Base58-encoded Ed25519 NodeId of the validator. Must appear in
    /// [`ConsensusConfig::validators`].
    pub node_id: String,
    /// 48-byte BLS12-381 G1 (min-pk) pubkey, lower-case hex.
    pub bls_pubkey: String,
    /// 96-byte BLS12-381 PoP signature over `bls_pubkey`, lower-case hex.
    pub bls_pop: String,
}

/// One row of [`ConsensusConfig::validators_operator_keys`]: a genesis
/// validator's operator key (#549). Cross-referenced with
/// [`ConsensusConfig::validators`] by `node_id`.
///
/// Both fields are base58-encoded Ed25519 pubkeys (the operator key is an
/// Ed25519 key like the validator's own NodeId — at high stake it SHOULD be
/// a multi-sig / threshold key, but the protocol just verifies whatever
/// Ed25519 signature the operator presents; the multi-sig scheme is an
/// operator-side choice, #549). Parsed by
/// [`ConsensusConfig::resolve_genesis_operator_keys`].
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ValidatorOperatorKeyEntry {
    /// Base58-encoded NodeId of the validator. Must appear in
    /// [`ConsensusConfig::validators`].
    pub node_id: String,
    /// Base58-encoded Ed25519 operator pubkey authorised to administer this
    /// validator (rotate its signing key, etc.).
    pub operator_pubkey: String,
}

impl ConsensusConfig {
    /// Parse and structurally validate the `validators_bls` table
    /// against `signature_scheme` and `validators`. Returns the
    /// ordered list of `(node_id, bls_pubkey, bls_pop)` triples ready
    /// for two consumers:
    ///
    /// 1. A `(NodeId, BlsPublicKey)` projection seeds the genesis
    ///    `boule_consensus::bls_key_history::BlsKeyHistory` and
    ///    feeds the genesis-block `validator_history_commitment`.
    /// 2. The `BlsPop` is verified cryptographically by
    ///    [`Self::verify_genesis_bls_pops`] *after* the genesis hash
    ///    (and therefore the chain_id) is known, since the PoP
    ///    pre-image binds to chain_id (#410).
    ///
    /// Errors:
    /// - On a BLS chain: `validators_bls` missing, mismatched length,
    ///   duplicate or unknown `node_id`s, or malformed hex. PoP
    ///   cryptographic verification is deferred to
    ///   [`Self::verify_genesis_bls_pops`] because the chain_id isn't
    ///   known until the genesis block is built from this triple.
    /// - On an Ed25519 chain: any `validators_bls` entry present at all.
    ///
    /// On a BLS chain, the returned `Vec` is the per-validator BLS
    /// timeline at view 0 plus the operator-supplied PoPs. On an
    /// Ed25519 chain, returns an empty `Vec`.
    pub fn resolve_genesis_bls_keys(&self) -> anyhow::Result<Vec<(NodeId, BlsPublicKey, BlsPop)>> {
        match self.signature_scheme {
            SignatureSchemeChoice::Ed25519Collected => {
                if !self.validators_bls.is_empty() {
                    anyhow::bail!(
                        "consensus.validators_bls is set but signature_scheme = \
                         \"ed25519_collected\" — Ed25519 chains have no use for BLS keys. \
                         Remove the validators_bls table or switch to \
                         signature_scheme = \"bls_aggregated\"."
                    );
                }
                Ok(Vec::new())
            }
            SignatureSchemeChoice::BlsAggregated => {
                if self.validators_bls.is_empty() {
                    anyhow::bail!(
                        "consensus.validators_bls is required when signature_scheme = \
                         \"bls_aggregated\" but the table is empty or missing. \
                         Each entry in `validators` must declare a matching `node_id`, \
                         `bls_pubkey`, and `bls_pop`."
                    );
                }
                if self.validators_bls.len() != self.validators.len() {
                    anyhow::bail!(
                        "consensus.validators_bls has {} entries but consensus.validators has {} \
                         — each validator must declare exactly one BLS entry.",
                        self.validators_bls.len(),
                        self.validators.len(),
                    );
                }
                // Resolve each validator NodeId once so we can detect
                // duplicates and unknown NodeIds in a single pass.
                let mut declared: std::collections::BTreeSet<NodeId> =
                    std::collections::BTreeSet::new();
                for (idx, raw) in self.validators.iter().enumerate() {
                    let nid = base58_to_node_id(raw).map_err(|e| {
                        anyhow::anyhow!(
                            "consensus.validators[{idx}] {raw:?} is not valid base58 NodeId: {e}",
                        )
                    })?;
                    if !declared.insert(nid) {
                        anyhow::bail!(
                            "consensus.validators[{idx}] {raw:?} is a duplicate; \
                             every validator must appear exactly once.",
                        );
                    }
                }

                let mut out = Vec::with_capacity(self.validators_bls.len());
                let mut seen: std::collections::BTreeSet<NodeId> =
                    std::collections::BTreeSet::new();
                for (idx, entry) in self.validators_bls.iter().enumerate() {
                    let nid = base58_to_node_id(&entry.node_id).map_err(|e| {
                        anyhow::anyhow!(
                            "consensus.validators_bls[{idx}].node_id {:?} is not valid base58 \
                             NodeId: {e}",
                            entry.node_id,
                        )
                    })?;
                    if !declared.contains(&nid) {
                        anyhow::bail!(
                            "consensus.validators_bls[{idx}].node_id {:?} is not in \
                             consensus.validators — every BLS entry must reference a declared \
                             validator.",
                            entry.node_id,
                        );
                    }
                    if !seen.insert(nid) {
                        anyhow::bail!(
                            "consensus.validators_bls[{idx}].node_id {:?} appears more than \
                             once; declare each validator's BLS pubkey exactly once.",
                            entry.node_id,
                        );
                    }
                    let pubkey: BlsPublicKey = decode_hex_array(&entry.bls_pubkey).map_err(|e| {
                        anyhow::anyhow!(
                            "consensus.validators_bls[{idx}].bls_pubkey is not 48-byte hex: {e}",
                        )
                    })?;
                    let sig_bytes: [u8; 96] = decode_hex_array(&entry.bls_pop).map_err(|e| {
                        anyhow::anyhow!(
                            "consensus.validators_bls[{idx}].bls_pop is not 96-byte hex: {e}",
                        )
                    })?;
                    let pop = BlsPop {
                        pubkey,
                        sig: sig_bytes,
                    };
                    out.push((nid, pubkey, pop));
                }
                Ok(out)
            }
        }
    }

    /// Parse and structurally validate the `validators_operator_keys` table
    /// (#549), returning the `(validator_id, operator_pubkey)` pairs ready to
    /// seed the genesis `OperatorKeyHistory` (in `boule-consensus`).
    ///
    /// The table is **optional and scheme-independent** (unlike
    /// `validators_bls`): a validator may declare no operator key, in which
    /// case it has no operator-recovery path. Each declared entry must
    /// reference a validator in `validators` and appear at most once; both
    /// fields must be valid base58 NodeIds. No cryptographic verification is
    /// needed at genesis — the operator key is a plain pubkey, only used to
    /// verify *later* operator-signed actions.
    pub fn resolve_genesis_operator_keys(&self) -> anyhow::Result<Vec<(NodeId, NodeId)>> {
        if self.validators_operator_keys.is_empty() {
            return Ok(Vec::new());
        }
        // Resolve the declared validator set once for membership + dup checks.
        let mut declared: std::collections::BTreeSet<NodeId> = std::collections::BTreeSet::new();
        for (idx, raw) in self.validators.iter().enumerate() {
            let nid = base58_to_node_id(raw).map_err(|e| {
                anyhow::anyhow!(
                    "consensus.validators[{idx}] {raw:?} is not valid base58 NodeId: {e}",
                )
            })?;
            declared.insert(nid);
        }

        let mut out = Vec::with_capacity(self.validators_operator_keys.len());
        let mut seen: std::collections::BTreeSet<NodeId> = std::collections::BTreeSet::new();
        for (idx, entry) in self.validators_operator_keys.iter().enumerate() {
            let nid = base58_to_node_id(&entry.node_id).map_err(|e| {
                anyhow::anyhow!(
                    "consensus.validators_operator_keys[{idx}].node_id {:?} is not valid \
                     base58 NodeId: {e}",
                    entry.node_id,
                )
            })?;
            if !declared.contains(&nid) {
                anyhow::bail!(
                    "consensus.validators_operator_keys[{idx}].node_id {:?} is not in \
                     consensus.validators — every operator-key entry must reference a \
                     declared validator.",
                    entry.node_id,
                );
            }
            if !seen.insert(nid) {
                anyhow::bail!(
                    "consensus.validators_operator_keys[{idx}].node_id {:?} appears more \
                     than once; declare each validator's operator key at most once.",
                    entry.node_id,
                );
            }
            let operator_pubkey = base58_to_node_id(&entry.operator_pubkey).map_err(|e| {
                anyhow::anyhow!(
                    "consensus.validators_operator_keys[{idx}].operator_pubkey {:?} is not \
                     valid base58 Ed25519 pubkey: {e}",
                    entry.operator_pubkey,
                )
            })?;
            out.push((nid, operator_pubkey));
        }
        Ok(out)
    }

    /// Cryptographically verify the genesis `validators_bls` PoPs
    /// against `chain_id`. Run after the genesis block is built so the
    /// chain_id is known (#410): the PoP pre-image is
    /// `chain_id || pubkey`, so an operator-supplied PoP that does
    /// not bind to the deployment's chain_id is rejected here.
    ///
    /// On Ed25519 chains this is a no-op; the `entries` slice will be
    /// empty.
    pub fn verify_genesis_bls_pops(
        &self,
        entries: &[(NodeId, BlsPublicKey, BlsPop)],
        chain_id: &ChainId,
    ) -> anyhow::Result<()> {
        for (idx, (_nid, pubkey, pop)) in entries.iter().enumerate() {
            BlsAggregated::verify_pop(pop, pubkey, chain_id).map_err(|e| {
                anyhow::anyhow!(
                    "consensus.validators_bls[{idx}] PoP failed verification under its declared \
                     pubkey and the chain's chain_id: {e}. Re-mint the PoP against this \
                     deployment's genesis (the PoP pre-image now binds to chain_id, #410).",
                )
            })?;
        }
        Ok(())
    }

    /// Validate that the snapshot-policy fields are internally
    /// consistent. Surfaced as `Err` from [`Config::validate`] so an
    /// operator who picks a chunk size larger than the wire-frame cap
    /// learns at startup rather than on the first snapshot.
    pub fn validate_snapshot_policy(&self) -> anyhow::Result<()> {
        if self.snapshot_interval_blocks > 0 && self.snapshot_chunk_size_bytes == 0 {
            anyhow::bail!(
                "consensus.snapshot_chunk_size_bytes must be > 0 when \
                 snapshot_interval_blocks is non-zero"
            );
        }
        // `MAX_FRAME_BYTES` (4 MiB) caps a single postcard frame on the
        // consensus protocol. Reserve 64 KiB of headroom for the chunk-
        // response envelope (`SnapshotChunkResponse` carries `height`,
        // `chunk_idx`, and a postcard `Option<Bytes>` framing on top of
        // the raw payload). 64 KiB is comfortably above the actual
        // overhead (a few dozen bytes) but small enough that operators
        // who deliberately push the chunk size to the wire-frame
        // ceiling still leave room for protocol evolution.
        const FRAME_OVERHEAD_RESERVED: usize = 64 * 1024;
        let max_chunk_size = crate::config::MAX_FRAME_BYTES.saturating_sub(FRAME_OVERHEAD_RESERVED);
        if (self.snapshot_chunk_size_bytes as usize) > max_chunk_size {
            anyhow::bail!(
                "consensus.snapshot_chunk_size_bytes={} exceeds wire-frame budget {} \
                 (MAX_FRAME_BYTES {} − {} reserved for envelope)",
                self.snapshot_chunk_size_bytes,
                max_chunk_size,
                crate::config::MAX_FRAME_BYTES,
                FRAME_OVERHEAD_RESERVED,
            );
        }
        Ok(())
    }
}

/// Per-cache capacity caps for the safety core and integration layer.
/// Parsed from the `[consensus.limits]` TOML sub-table; defaults apply
/// when the table — or any individual field — is omitted. Every field
/// here projects 1:1 into `boule_consensus::limits::CacheLimits`; the
/// mempool cap is *not* here — it lives on [`ConsensusConfig`] beside
/// `propose_limit`, since it is consumed by node wiring, not the
/// safety core.
///
/// Eviction policy and rationale are documented on
/// `boule_consensus::limits::CacheLimits`; this struct is the
/// configuration shape, the runtime shape lives in that module so the
/// safety core can stay free of `serde` dependencies.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ConsensusLimits {
    /// Cap on the safety core's `vote_bucket` map. Defaults to
    /// [`crate::config::DEFAULT_VOTE_BUCKET_CAPACITY`].
    #[serde(default = "default_vote_bucket_capacity")]
    pub vote_bucket_capacity: usize,
    /// Cap on the safety core's `parked_proposals` map. Defaults to
    /// [`crate::config::DEFAULT_PARKED_PROPOSALS_CAPACITY`].
    #[serde(default = "default_parked_proposals_capacity")]
    pub parked_proposals_capacity: usize,
    /// Cap on the safety core's `pending_blocks` map. Defaults to
    /// [`crate::config::DEFAULT_PENDING_BLOCKS_CAPACITY`].
    #[serde(default = "default_pending_blocks_capacity")]
    pub pending_blocks_capacity: usize,
    /// Cap on the integration layer's `timeout_buckets` map. Defaults
    /// to [`crate::config::DEFAULT_TIMEOUT_BUCKETS_CAPACITY`].
    #[serde(default = "default_timeout_buckets_capacity")]
    pub timeout_buckets_capacity: usize,
    /// Initial views to wait between successive `RequestBlock` retries
    /// for the same parent hash. See
    /// `boule_consensus::limits::CacheLimits::block_sync_initial_backoff_views`.
    #[serde(default = "default_block_sync_initial_backoff_views")]
    pub block_sync_initial_backoff_views: u64,
    /// Cap on the per-parent-hash retry gap. See
    /// `boule_consensus::limits::CacheLimits::block_sync_max_backoff_views`.
    #[serde(default = "default_block_sync_max_backoff_views")]
    pub block_sync_max_backoff_views: u64,
    /// Same-peer attempts before the safety core rotates to the next
    /// validator on `RequestBlock` retries. See
    /// `boule_consensus::limits::CacheLimits::block_sync_per_peer_attempts`.
    #[serde(default = "default_block_sync_per_peer_attempts")]
    pub block_sync_per_peer_attempts: u32,
    /// Total `RequestBlock` budget per parent hash before parked
    /// proposals are dropped. See
    /// `boule_consensus::limits::CacheLimits::block_sync_max_attempts`.
    #[serde(default = "default_block_sync_max_attempts")]
    pub block_sync_max_attempts: u32,
}

impl Default for ConsensusLimits {
    fn default() -> Self {
        Self {
            vote_bucket_capacity: default_vote_bucket_capacity(),
            parked_proposals_capacity: default_parked_proposals_capacity(),
            pending_blocks_capacity: default_pending_blocks_capacity(),
            timeout_buckets_capacity: default_timeout_buckets_capacity(),
            block_sync_initial_backoff_views: default_block_sync_initial_backoff_views(),
            block_sync_max_backoff_views: default_block_sync_max_backoff_views(),
            block_sync_per_peer_attempts: default_block_sync_per_peer_attempts(),
            block_sync_max_attempts: default_block_sync_max_attempts(),
        }
    }
}

fn default_propose_limit() -> usize {
    64
}

fn default_timeout_base_ms() -> u64 {
    200
}

fn default_timeout_max_ms() -> u64 {
    10_000
}

fn default_vote_bucket_capacity() -> usize {
    crate::config::DEFAULT_VOTE_BUCKET_CAPACITY
}

fn default_parked_proposals_capacity() -> usize {
    crate::config::DEFAULT_PARKED_PROPOSALS_CAPACITY
}

fn default_pending_blocks_capacity() -> usize {
    crate::config::DEFAULT_PENDING_BLOCKS_CAPACITY
}

fn default_timeout_buckets_capacity() -> usize {
    crate::config::DEFAULT_TIMEOUT_BUCKETS_CAPACITY
}

fn default_block_sync_initial_backoff_views() -> u64 {
    crate::config::DEFAULT_BLOCK_SYNC_INITIAL_BACKOFF_VIEWS
}

fn default_block_sync_max_backoff_views() -> u64 {
    crate::config::DEFAULT_BLOCK_SYNC_MAX_BACKOFF_VIEWS
}

fn default_block_sync_per_peer_attempts() -> u32 {
    crate::config::DEFAULT_BLOCK_SYNC_PER_PEER_ATTEMPTS
}

fn default_block_sync_max_attempts() -> u32 {
    crate::config::DEFAULT_BLOCK_SYNC_MAX_ATTEMPTS
}

fn default_mempool_capacity() -> usize {
    1024
}

fn default_max_endpoint_list_length() -> usize {
    8
}

/// Caps a single postcard frame on the consensus wire protocol (4 MiB).
/// The runtime wire codec (`consensus::node::wire`) enforces it; config
/// validation uses it to bound `snapshot_chunk_size_bytes`.
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Default cap on the `vote_bucket` map. Sized for four to a few dozen
/// validators across a Byzantine-flood window of a few hundred views.
pub const DEFAULT_VOTE_BUCKET_CAPACITY: usize = 1024;
/// Default cap on `parked_proposals`. Each parked proposal is at most
/// one in-flight `RequestBlock` retry per pacemaker tick, so this also
/// caps the per-tick block-sync request rate.
pub const DEFAULT_PARKED_PROPOSALS_CAPACITY: usize = 256;
/// Default cap on `pending_blocks`. Generous for a steady-state node
/// (which only needs a handful of blocks above the commit frontier),
/// tight enough that a flood of distinct future-height blocks gets
/// pruned before consuming meaningful memory.
pub const DEFAULT_PENDING_BLOCKS_CAPACITY: usize = 1024;
/// Default cap on the integration layer's timeout-vote buckets.
pub const DEFAULT_TIMEOUT_BUCKETS_CAPACITY: usize = 1024;
/// Default initial views between successive `RequestBlock` retries on
/// the same parent hash. The first retry is eligible after one
/// `PacemakerAdvance`; subsequent retries double the gap up to
/// [`DEFAULT_BLOCK_SYNC_MAX_BACKOFF_VIEWS`].
pub const DEFAULT_BLOCK_SYNC_INITIAL_BACKOFF_VIEWS: u64 = 1;
/// Default ceiling on the per-parent-hash retry gap in views. With the
/// default initial of `1` and the doubling schedule, the gap saturates
/// here after roughly four attempts.
pub const DEFAULT_BLOCK_SYNC_MAX_BACKOFF_VIEWS: u64 = 8;
/// Default attempts at the same peer before rotating to the next
/// validator in the ring. Two gives the original sender a brief retry
/// window (one redelivery in case the first probe was lost in flight)
/// before fanning out.
pub const DEFAULT_BLOCK_SYNC_PER_PEER_ATTEMPTS: u32 = 2;
/// Default total `RequestBlock` budget per parent hash. With the
/// default `per_peer = 2`, eight attempts cover the original sender
/// plus three rotation rounds, which exhausts the four-validator
/// ring twice. After this, the parked proposals depending on the
/// missing parent are dropped and the cache-eviction counter ticks.
pub const DEFAULT_BLOCK_SYNC_MAX_ATTEMPTS: u32 = 8;

fn default_snapshot_interval_blocks() -> u64 {
    10_000
}

fn default_snapshot_retention_count() -> usize {
    3
}

fn default_snapshot_chunk_size_bytes() -> u32 {
    1024 * 1024
}

/// Default committed-block retention window (#194). Sized to comfortably
/// exceed any plausibly-laggy peer in normal operation: at the
/// `timeout_base_ms = 200` testnet rate, 10k blocks is roughly 30
/// minutes of wall-clock; at production block times of a few seconds,
/// it's hours. Operators with archive nodes or slower-catch-up
/// requirements can override either way (`0` disables pruning).
fn default_block_retention_window() -> u64 {
    10_000
}

/// Configuration for the p2p layer that is independent of the overlay
/// mode and consensus wiring.
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct P2pConfig {
    /// `[p2p.limits]` sub-table. Optional: when absent, no rate
    /// limiting or connection caps are installed (matches the pre-#134
    /// behaviour, suitable for closed-network test deployments). When
    /// present, sub-fields default to
    /// [`P2pLimitsConfig::production_defaults`].
    #[serde(default)]
    pub limits: Option<P2pLimitsConfig>,
    /// Outbound-only mode (issue #138). When `true` the node skips
    /// binding the TCP listener and never accepts new inbound
    /// connections, but still dials peers over outbound TCP/TLS and
    /// uses each established session bidirectionally. Suitable for
    /// validators behind a NAT or asymmetric firewall.
    ///
    /// A node running in this mode MUST configure either
    /// `[overlay] bootstrap_addrs = [...]` or `[[peers]]` so it has
    /// somewhere to dial out to; the gossip overlay also publishes
    /// `reachable = false` in its peer-list gossip so the rest of the
    /// cluster knows not to attempt to dial back.
    #[serde(default)]
    pub inbound_disabled: bool,
    /// `[p2p.keepalive]` sub-table. Application-layer dead-peer
    /// detection on every connection. Absent disables it — the default
    /// until the mechanism is validated in the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive: Option<P2pKeepaliveConfig>,
}

/// `[p2p.keepalive]` — application-layer keepalive / dead-peer
/// detection.
///
/// Each connection sends a keepalive probe once it has been silent (no
/// inbound frame of any protocol) for `interval_ms`, and is dropped
/// once it has been silent for `timeout_ms`. This catches a peer that
/// has gone silent *without* closing its socket — a failed NIC, a hung
/// kernel, a network blackhole — within `timeout_ms`, even when this
/// node has no traffic of its own to send that peer and so would never
/// otherwise notice. Application traffic counts as liveness, so a busy
/// link never spends a probe.
#[derive(Debug, Clone, Copy, serde::Deserialize, serde::Serialize)]
pub struct P2pKeepaliveConfig {
    /// Idle time before a keepalive probe is sent.
    #[serde(default = "default_keepalive_interval_ms")]
    pub interval_ms: u64,
    /// Idle time before the connection is dropped. Must exceed
    /// `interval_ms` so at least one probe goes out before the deadline.
    #[serde(default = "default_keepalive_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for P2pKeepaliveConfig {
    fn default() -> Self {
        Self {
            interval_ms: default_keepalive_interval_ms(),
            timeout_ms: default_keepalive_timeout_ms(),
        }
    }
}

impl P2pKeepaliveConfig {
    /// Reject a config whose deadline would fire before the first probe
    /// (or a zero interval that would busy-spin).
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.interval_ms == 0 {
            anyhow::bail!("[p2p.keepalive] interval_ms must be greater than 0");
        }
        if self.timeout_ms <= self.interval_ms {
            anyhow::bail!(
                "[p2p.keepalive] timeout_ms ({}) must exceed interval_ms ({}) so at least \
                 one keepalive probe is sent before the connection is dropped",
                self.timeout_ms,
                self.interval_ms,
            );
        }
        Ok(())
    }
}

fn default_keepalive_interval_ms() -> u64 {
    10_000
}

fn default_keepalive_timeout_ms() -> u64 {
    30_000
}

/// Per-peer rate limits + connection caps. Surfaced as the
/// `[p2p.limits]` TOML table. Sub-fields fall back to
/// [`P2pLimitsConfig::production_defaults`] when omitted, so an
/// operator can override one knob (e.g. tighter `max_per_ip`) without
/// re-spelling the rest.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct P2pLimitsConfig {
    /// Maximum concurrent inbound connections.
    #[serde(default = "default_max_inbound_connections")]
    pub max_inbound_connections: usize,
    /// Maximum concurrent outbound connections.
    #[serde(default = "default_max_outbound_connections")]
    pub max_outbound_connections: usize,
    /// Maximum concurrent connections from a single source IP.
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: usize,
    /// Per-message-type and bytes/sec rate buckets.
    #[serde(default)]
    pub rate: P2pRateLimitsConfig,
    /// Violation-window / max-violations parameters that drive the
    /// per-peer disconnect decision.
    #[serde(default)]
    pub violations: P2pViolationsConfig,
}

impl Default for P2pLimitsConfig {
    fn default() -> Self {
        Self::production_defaults()
    }
}

impl P2pLimitsConfig {
    /// Defaults sized for a healthy 4-validator cluster with 1× RTT
    /// margin; the rate buckets sit well above honest steady-state
    /// (see issue #134 for the calculation).
    pub fn production_defaults() -> Self {
        Self {
            max_inbound_connections: default_max_inbound_connections(),
            max_outbound_connections: default_max_outbound_connections(),
            max_connections_per_ip: default_max_connections_per_ip(),
            rate: P2pRateLimitsConfig::default(),
            violations: P2pViolationsConfig::default(),
        }
    }
}

/// Per-message-type token-bucket rates and the wire-bytes/sec ceiling.
/// All rates are units-per-second.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct P2pRateLimitsConfig {
    #[serde(default = "default_proposal_per_sec")]
    pub proposal_per_sec: f64,
    #[serde(default = "default_vote_per_sec")]
    pub vote_per_sec: f64,
    #[serde(default = "default_timeout_vote_per_sec")]
    pub timeout_vote_per_sec: f64,
    #[serde(default = "default_new_view_per_sec")]
    pub new_view_per_sec: f64,
    #[serde(default = "default_request_block_per_sec")]
    pub request_block_per_sec: f64,
    #[serde(default = "default_receive_block_per_sec")]
    pub receive_block_per_sec: f64,
    /// Steady-state inbound rate of `SnapshotManifestRequest` frames.
    /// See `crate::transport::limits::RateLimitsConfig::snapshot_manifest_request_per_sec`.
    #[serde(default = "default_snapshot_manifest_request_per_sec")]
    pub snapshot_manifest_request_per_sec: f64,
    /// Steady-state inbound rate of `SnapshotManifestResponse` frames.
    #[serde(default = "default_snapshot_manifest_response_per_sec")]
    pub snapshot_manifest_response_per_sec: f64,
    /// Steady-state inbound rate of `SnapshotChunkRequest` frames.
    #[serde(default = "default_snapshot_chunk_request_per_sec")]
    pub snapshot_chunk_request_per_sec: f64,
    /// Steady-state inbound rate of `SnapshotChunkResponse` frames.
    #[serde(default = "default_snapshot_chunk_response_per_sec")]
    pub snapshot_chunk_response_per_sec: f64,
    /// Steady-state inbound rate of `BlockRangeRequest` frames (#514).
    #[serde(default = "default_block_range_request_per_sec")]
    pub block_range_request_per_sec: f64,
    /// Steady-state inbound rate of `BlockRangeResponse` frames (#514).
    #[serde(default = "default_block_range_response_per_sec")]
    pub block_range_response_per_sec: f64,
    /// Steady-state inbound rate of `EquivocationEvidence` gossip frames
    /// (#657b). Evidence is rare (one proof per equivocator), so a low
    /// ceiling both fits honest traffic and blunts a flood of bogus
    /// proofs — each costs the receiver a verification.
    #[serde(default = "default_equivocation_evidence_per_sec")]
    pub equivocation_evidence_per_sec: f64,
    #[serde(default = "default_bytes_per_sec")]
    pub bytes_per_sec: f64,
    /// Per-peer outbound wire-bytes/sec ceiling (#553). Symmetric to
    /// `bytes_per_sec` but charged on egress: caps how much a single
    /// peer can pull out of this responder per second, regardless of
    /// how cheap their inbound requests were. Defends against the
    /// `BlockRangeRequest`/`BlockRangeResponse` amplification vector.
    #[serde(default = "default_outbound_bytes_per_sec")]
    pub outbound_bytes_per_sec: f64,
    /// Burst capacity = `rate × burst_seconds`. A 1.0s burst window is
    /// large enough that a leader's view-change recovery flurry stays
    /// within budget without admitting sustained over-rate.
    #[serde(default = "default_burst_seconds")]
    pub burst_seconds: f64,
}

impl Default for P2pRateLimitsConfig {
    fn default() -> Self {
        Self {
            proposal_per_sec: default_proposal_per_sec(),
            vote_per_sec: default_vote_per_sec(),
            timeout_vote_per_sec: default_timeout_vote_per_sec(),
            new_view_per_sec: default_new_view_per_sec(),
            request_block_per_sec: default_request_block_per_sec(),
            receive_block_per_sec: default_receive_block_per_sec(),
            snapshot_manifest_request_per_sec: default_snapshot_manifest_request_per_sec(),
            snapshot_manifest_response_per_sec: default_snapshot_manifest_response_per_sec(),
            snapshot_chunk_request_per_sec: default_snapshot_chunk_request_per_sec(),
            snapshot_chunk_response_per_sec: default_snapshot_chunk_response_per_sec(),
            block_range_request_per_sec: default_block_range_request_per_sec(),
            block_range_response_per_sec: default_block_range_response_per_sec(),
            equivocation_evidence_per_sec: default_equivocation_evidence_per_sec(),
            bytes_per_sec: default_bytes_per_sec(),
            outbound_bytes_per_sec: default_outbound_bytes_per_sec(),
            burst_seconds: default_burst_seconds(),
        }
    }
}

/// Sliding-window parameters for the per-peer disconnect decision.
/// After `max_violations` rate-limit drops within `window_secs`, the
/// limiter returns `Decision::Disconnect` once and the consensus layer
/// tears down the connection.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct P2pViolationsConfig {
    #[serde(default = "default_violation_window_secs")]
    pub window_secs: u64,
    #[serde(default = "default_max_violations")]
    pub max_violations: u32,
}

impl Default for P2pViolationsConfig {
    fn default() -> Self {
        Self {
            window_secs: default_violation_window_secs(),
            max_violations: default_max_violations(),
        }
    }
}

fn default_max_inbound_connections() -> usize {
    64
}
fn default_max_outbound_connections() -> usize {
    64
}
fn default_max_connections_per_ip() -> usize {
    4
}
fn default_proposal_per_sec() -> f64 {
    16.0
}
fn default_vote_per_sec() -> f64 {
    256.0
}
fn default_timeout_vote_per_sec() -> f64 {
    64.0
}
fn default_new_view_per_sec() -> f64 {
    64.0
}
fn default_request_block_per_sec() -> f64 {
    8.0
}
fn default_receive_block_per_sec() -> f64 {
    8.0
}
fn default_snapshot_manifest_request_per_sec() -> f64 {
    4.0
}
fn default_snapshot_manifest_response_per_sec() -> f64 {
    4.0
}
fn default_snapshot_chunk_request_per_sec() -> f64 {
    32.0
}
fn default_snapshot_chunk_response_per_sec() -> f64 {
    32.0
}
fn default_block_range_request_per_sec() -> f64 {
    8.0
}
fn default_block_range_response_per_sec() -> f64 {
    8.0
}
fn default_equivocation_evidence_per_sec() -> f64 {
    8.0
}
fn default_bytes_per_sec() -> f64 {
    1024.0 * 1024.0
}
fn default_outbound_bytes_per_sec() -> f64 {
    1024.0 * 1024.0
}
fn default_burst_seconds() -> f64 {
    1.0
}
fn default_violation_window_secs() -> u64 {
    10
}
fn default_max_violations() -> u32 {
    100
}

/// Topology-overlay configuration for the partial-mesh gossip overlay
/// (`mode = "gossip"`, the only overlay).
///
/// Defaults are tuned to match the per-module `Default` impls in the
/// gossip building blocks (`boule_transport_tcp::overlay::gossip::peer_list_task::PeerListGossipConfig`,
/// `boule_transport_tcp::overlay::gossip::maintenance::MeshMaintenanceConfig`,
/// `boule_transport_tcp::overlay::gossip::overlay::GossipOverlayConfig`), so a
/// node that omits `[overlay]` entirely gets the breakdown-comment
/// defaults from issue #137.
///
/// # Direct-peer budgets (#187)
///
/// `outbound_target` is a soft floor that the maintenance loop dials
/// toward; `inbound_max` is a hard cap on accepted inbound connections;
/// `total_max` is a hard ceiling on registered direct peers regardless
/// of direction. Splitting the single `target_degree` knob into these
/// three numbers lets operators run generous outbound (peers we chose,
/// sized for partition resilience) alongside conservative inbound
/// (anyone can dial us, including a Byzantine flood).
///
/// `target_degree` is retained as a deprecated alias: when present it
/// sets `outbound_target = inbound_max = total_max = N` and emits a
/// warning at config load.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct OverlayConfig {
    /// Which overlay implementation to use. Only `gossip` exists today
    /// (the legacy full-mesh overlay was retired in #137); the field is
    /// kept so a future overlay can be selected without reshaping the
    /// config.
    #[serde(default)]
    pub mode: OverlayMode,
    /// Soft floor on the outbound direct-peer count maintained by the
    /// partial-mesh maintenance loop (#187). Used in `mode = "gossip"`
    /// only.
    #[serde(default = "default_outbound_target")]
    pub outbound_target: usize,
    /// Hard cap on inbound direct connections (#187). A fresh inbound
    /// TLS handshake past this cap is closed cleanly. Used in
    /// `mode = "gossip"` only.
    #[serde(default = "default_inbound_max")]
    pub inbound_max: usize,
    /// Hard ceiling on total registered direct peers regardless of
    /// direction (#187). Acts as a safety net above
    /// `outbound_target + inbound_max`. Used in `mode = "gossip"`
    /// only.
    #[serde(default = "default_total_max")]
    pub total_max: usize,
    /// Deprecated alias for the three direct-peer budget knobs. When
    /// present, sets `outbound_target = inbound_max = total_max = N`
    /// and emits a warning at config load. Prefer the explicit knobs
    /// for new configs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_degree: Option<usize>,
    /// Peer-list publisher tick interval, milliseconds. Used in
    /// `mode = "gossip"` only.
    #[serde(default = "default_peer_gossip_interval_ms")]
    pub peer_gossip_interval_ms: u64,
    /// Maximum number of direct neighbours to push our peer-table
    /// snapshot to per tick. Used in `mode = "gossip"` only.
    #[serde(default = "default_peer_gossip_fanout")]
    pub peer_gossip_fanout: usize,
    /// Mesh-maintenance loop tick interval, milliseconds. Used in
    /// `mode = "gossip"` only.
    #[serde(default = "default_mesh_check_interval_ms")]
    pub mesh_check_interval_ms: u64,
    /// Maximum live entries in the dedup ring.
    #[serde(default = "default_dedup_capacity")]
    pub dedup_capacity: usize,
    /// How long an inserted msg_id is treated as "seen" before being
    /// lazily forgotten, milliseconds.
    #[serde(default = "default_dedup_ttl_ms")]
    pub dedup_ttl_ms: u64,
    /// Maximum entries the peer table holds.
    #[serde(default = "default_peer_table_capacity")]
    pub peer_table_capacity: usize,
    /// Bootstrap addresses dialed at startup. Each is a TOFU dial — the
    /// peer's TLS identity is whatever it presents on the handshake.
    /// Used in `mode = "gossip"` only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bootstrap_addrs: Vec<SocketAddr>,
}

impl Default for OverlayConfig {
    fn default() -> Self {
        Self {
            mode: OverlayMode::default(),
            outbound_target: default_outbound_target(),
            inbound_max: default_inbound_max(),
            total_max: default_total_max(),
            target_degree: None,
            peer_gossip_interval_ms: default_peer_gossip_interval_ms(),
            peer_gossip_fanout: default_peer_gossip_fanout(),
            mesh_check_interval_ms: default_mesh_check_interval_ms(),
            dedup_capacity: default_dedup_capacity(),
            dedup_ttl_ms: default_dedup_ttl_ms(),
            peer_table_capacity: default_peer_table_capacity(),
            bootstrap_addrs: Vec::new(),
        }
    }
}

impl OverlayConfig {
    /// Resolve the deprecated `target_degree` alias into the split
    /// `outbound_target` / `inbound_max` / `total_max` knobs (#187).
    ///
    /// When `target_degree = N` is present in the parsed config this
    /// overwrites all three new knobs with `N` and clears the alias —
    /// matching the breakdown comment on #187 — and emits a warning so
    /// operators see the rename in their logs. When the alias is
    /// absent this is a no-op.
    ///
    /// Called automatically from [`load`]; tests that bypass `load`
    /// (using `toml::from_str` directly) should call this if they
    /// want to observe alias-resolved values.
    pub fn resolve_deprecated_aliases(&mut self) {
        if let Some(n) = self.target_degree.take() {
            warn!(
                "`[overlay] target_degree` is deprecated (#187); use \
                 `outbound_target`, `inbound_max`, and `total_max` \
                 instead. Setting all three to {n} for compatibility."
            );
            self.outbound_target = n;
            self.inbound_max = n;
            self.total_max = n;
        }
    }
}

/// Which topology overlay implementation to drive consensus with.
///
/// Single-variant today — the legacy full-mesh overlay was retired once
/// gossip became the production default (#137). The enum is retained so
/// a future overlay can be added without reshaping the config surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OverlayMode {
    /// Partial-mesh gossip overlay (issue #137). Operators get a
    /// bounded direct-peer count (`outbound_target`, default 8, plus
    /// the inbound caps from #187) without coordinated config rollouts
    /// when the validator set grows.
    #[default]
    Gossip,
}

/// Operator-facing UI defaults. Currently a single knob: the default
/// output format for CLI subcommands that emit structured payloads
/// (e.g. `config`). Per-invocation `--format` flags override this.
///
/// Subcommands with inherently free-form output (`init`'s status
/// messages, `start`'s logs) ignore this — see [`crate::cli`].
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct UiConfig {
    /// Default for `--format` on subcommands with structured output.
    /// `human` (the default) means "let each subcommand pick a sensible
    /// representation for terminal reading" — for `config`, that's
    /// TOML; future subcommands may pick differently. `toml` and `json`
    /// are for piping / scripting (e.g. `... | jq`).
    #[serde(default)]
    pub output_format: OutputFormat,
}

fn default_outbound_target() -> usize {
    8
}

/// Hard cap on inbound connections (#187). Sized so a healthy
/// outbound_target=8 deployment has 2× headroom for inbound peers,
/// which limits the consequences of a Byzantine inbound flood without
/// starving honest peers that legitimately want to dial us.
fn default_inbound_max() -> usize {
    16
}

/// Hard ceiling on total registered direct peers (#187), regardless
/// of direction. `outbound_target + inbound_max` for the defaults so
/// it acts as a safety net rather than the binding limit in steady
/// state.
fn default_total_max() -> usize {
    24
}

fn default_peer_gossip_interval_ms() -> u64 {
    5_000
}

fn default_peer_gossip_fanout() -> usize {
    3
}

fn default_mesh_check_interval_ms() -> u64 {
    5_000
}

fn default_dedup_capacity() -> usize {
    4_096
}

fn default_dedup_ttl_ms() -> u64 {
    120_000
}

fn default_peer_table_capacity() -> usize {
    1_024
}

pub fn load(path: &Path) -> anyhow::Result<Config> {
    let text = std::fs::read_to_string(path)?;
    let mut config: Config = toml::from_str(&text)?;
    // Migrate `[overlay] target_degree = N` → split knobs (#187).
    // Doing this once at load keeps the rest of the binary on the
    // post-#187 names without per-call branching.
    config.overlay.resolve_deprecated_aliases();
    Ok(config)
}

/// The starter `config.toml` contents written by `boule init`: a
/// gossip-only single-node setup that runs out of the box, with the
/// `[consensus]` block commented out. Returned as a `String` so callers
/// (and tests) can render it without touching the filesystem.
pub fn starter_toml() -> String {
    let data_dir = crate::paths::default_data_dir().unwrap_or_else(|| PathBuf::from("./boule"));
    let key_path = data_dir.join("node.key");
    let storage_dir = data_dir.join("consensus");
    format!(
        "# boule starter config — generated by `boule init`.\n\n\
         [node]\n\
         listen_addr = \"127.0.0.1:7000\"\n\n\
         [node.identity]\n\
         backend = \"file\"\n\
         path    = \"{key_path}\"\n\n\
         [api]\n\
         listen_addr = \"127.0.0.1:8000\"\n\n\
         # [[peers]]\n\
         # addr    = \"127.0.0.1:7001\"\n\
         # node_id = \"<peer NodeId from their `init` output>\"\n\n\
         # [consensus]\n\
         # validators       = [\"<node1-id>\", \"<node2-id>\", \"<node3-id>\", \"<node4-id>\"]\n\
         # storage_dir      = \"{storage_dir}\"\n\
         # timeout_base_ms  = 500\n\
         # timeout_max_ms   = 5000\n",
        key_path = key_path.display(),
        storage_dir = storage_dir.display(),
    )
}

/// Write the [`starter_toml`] template to `path`, creating the parent
/// directory if needed.
pub fn write_starter_config(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                anyhow::anyhow!("creating config directory {}: {e}", parent.display())
            })?;
        }
    }
    std::fs::write(path, starter_toml())
        .map_err(|e| anyhow::anyhow!("writing starter config to {}: {e}", path.display()))?;
    Ok(())
}

impl Config {
    /// Cross-validate the parsed config against the local TLS identity.
    ///
    /// Rejects any static `[[peers]]` entry whose `node_id` matches the
    /// local node — a self-dial would loop back to our own listener,
    /// count against `outbound_target`, and surface as a real peer in
    /// `/peers`. TOFU `bootstrap_addrs` carry no `node_id`, so the
    /// equivalent check there is deferred to the dialer / listener
    /// handshake guards (see `src/p2p/dialer.rs` and
    /// `src/p2p/listener.rs`).
    ///
    /// Also surfaces malformed `node_id` strings here so operators see
    /// a clean error before `start` panics on the same string deeper
    /// in the stack.
    pub fn validate(&self, self_id: &NodeId) -> anyhow::Result<()> {
        for (idx, peer) in self.peers.iter().enumerate() {
            let Some(raw) = peer.node_id.as_deref() else {
                continue;
            };
            let pid = base58_to_node_id(raw).map_err(|e| {
                anyhow::anyhow!(
                    "[[peers]][{idx}] (addr = {}) has malformed node_id {raw:?}: {e}",
                    peer.addr,
                )
            })?;
            if &pid == self_id {
                anyhow::bail!(
                    "[[peers]][{idx}] (addr = {}) lists this node's own NodeId {} — \
                     a self-dial would loop back to our own listener; remove this \
                     entry from the static peers list.",
                    peer.addr,
                    node_id_to_base58(self_id),
                );
            }
        }
        if let Some(cons) = self.consensus.as_ref() {
            cons.validate_snapshot_policy()?;
            cons.resolve_genesis_bls_keys()?;
        }
        if let Some(keepalive) = self.p2p.keepalive.as_ref() {
            keepalive.validate()?;
        }
        Ok(())
    }

    /// Pre-flight validation of consensus inputs: validator `NodeId`
    /// strings and the genesis seed. Run at `init` so operators catch
    /// typos in validator IDs or the seed before `start`.
    pub fn preflight_validate(&self) -> anyhow::Result<()> {
        // Peer addresses are SocketAddr-typed at parse time; nothing more
        // to do there. Validate consensus inputs if present.
        if let Some(cons) = self.consensus.as_ref() {
            if !cons.validators.is_empty() {
                for raw in &cons.validators {
                    base58_to_node_id(raw).map_err(|e| {
                        anyhow::anyhow!(
                            "[consensus.validators] entry {raw:?} is not a valid NodeId: {e}"
                        )
                    })?;
                }
            }
            if let Some(seed) = cons.genesis_seed_hex.as_ref() {
                if seed.len() != 64 || !seed.chars().all(|c| c.is_ascii_hexdigit()) {
                    anyhow::bail!("[consensus].genesis_seed_hex must be 64 hex chars");
                }
            }
            if let Some(cp) = cons.weak_subjectivity_checkpoint.as_ref() {
                if cp.height == 0 {
                    anyhow::bail!(
                        "[consensus.weak_subjectivity_checkpoint].height must be > 0 \
                         (genesis is anchored by genesis_seed_hex)"
                    );
                }
                let h = cp.hash.strip_prefix("0x").unwrap_or(&cp.hash);
                if h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
                    anyhow::bail!(
                        "[consensus.weak_subjectivity_checkpoint].hash must be a 32-byte hex \
                         block hash (64 hex chars)"
                    );
                }
            }
        }
        Ok(())
    }
}

/// Decode a lower-case hex string into a fixed-size byte array. Helper
/// used by [`ConsensusConfig::resolve_genesis_bls_keys`] for `bls_pubkey`
/// (N=48) and `bls_pop` (N=96).
fn decode_hex_array<const N: usize>(s: &str) -> anyhow::Result<[u8; N]> {
    let bytes = hex::decode(s).map_err(|e| anyhow::anyhow!("hex decode: {e}"))?;
    if bytes.len() != N {
        anyhow::bail!("expected {N} bytes, got {}", bytes.len());
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Resolve the effective identity configuration, honoring the deprecated
/// `key_file` alias. Returns `None` if the caller should apply the
/// environment-aware default (dev → file; prod → fail).
pub fn resolve_identity(node: &NodeConfig) -> Option<IdentityConfig> {
    if let Some(cfg) = &node.identity {
        return Some(cfg.clone());
    }
    if let Some(path) = &node.key_file {
        warn!(
            "`node.key_file` is deprecated; prefer `[node.identity] backend = \"file\" path = ...`"
        );
        return Some(IdentityConfig::File {
            path: path.clone(),
            allow_insecure_perms: false,
        });
    }
    None
}

/// Resolve the validator-signing identity. Returns `None` when the
/// `[node.validator_identity]` table is absent; callers should then fall
/// back to the network identity for consensus signing (with a deprecation
/// warning), preserving the historical single-key behavior.
pub fn resolve_validator_identity(node: &NodeConfig) -> Option<IdentityConfig> {
    node.validator_identity.clone()
}

/// Pick the network identity config, applying the `--allow-insecure-perms`
/// override and fail-closed production semantics. Returns the resolved
/// [`IdentityConfig`], defaulting to a file backend in the platform data
/// dir when `[node.identity]` is absent (non-production only; production
/// fails closed).
pub fn resolve_and_validate_identity(
    node: &NodeConfig,
    production: bool,
    allow_insecure_perms: bool,
) -> anyhow::Result<IdentityConfig> {
    match resolve_identity(node) {
        Some(mut cfg) => {
            if let IdentityConfig::File {
                allow_insecure_perms: ref mut a,
                ..
            } = cfg
            {
                if allow_insecure_perms {
                    *a = true;
                }
            }
            Ok(cfg)
        }
        None => {
            if production {
                anyhow::bail!(
                    "refusing to start in production without an explicit [node.identity] backend. \
                     Configure one of: file, env, keyring, encrypted-file, exec."
                );
            }
            // The starter config written by `init` always sets
            // [node.identity], so the only way to land here is an
            // operator-edited config that dropped the table. Default to
            // a file backend in the platform-specific data dir so
            // operators don't end up with `./node.key` polluting cwd.
            let path = crate::paths::default_data_dir()
                .map(|d| d.join("node.key"))
                .unwrap_or_else(|| PathBuf::from("node.key"));
            warn!(
                "no [node.identity] in config; defaulting to file backend at {}",
                path.display()
            );
            Ok(IdentityConfig::File {
                path,
                allow_insecure_perms,
            })
        }
    }
}

/// Migrate the network key from the source backend named in `config_path`'s
/// `[node.identity]` to the `to` backend, provisioning the destination and
/// optionally shredding the source file. Backs `boule key migrate`.
pub fn migrate_key(
    config_path: &Path,
    to: &str,
    dest_path: Option<PathBuf>,
    passphrase_env: Option<String>,
    service: Option<String>,
    account: Option<String>,
    delete_source: bool,
) -> anyhow::Result<()> {
    let config = load(config_path)?;
    let source_cfg = resolve_identity(&config.node).ok_or_else(|| {
        anyhow::anyhow!(
            "config {} has no [node.identity] or key_file; nothing to migrate from",
            config_path.display()
        )
    })?;
    info!("migrating from {} to {}", source_cfg.backend_name(), to);

    let source_provider = build_provider(&source_cfg)?;
    let node_identity = source_provider.load_or_init()?;

    let dest_cfg = match to {
        "file" => IdentityConfig::File {
            path: dest_path.ok_or_else(|| anyhow::anyhow!("--to file requires --path"))?,
            allow_insecure_perms: false,
        },
        "encrypted-file" => IdentityConfig::EncryptedFile {
            path: dest_path
                .ok_or_else(|| anyhow::anyhow!("--to encrypted-file requires --path"))?,
            passphrase_env,
        },
        "keyring" => IdentityConfig::Keyring {
            service: service.unwrap_or_else(|| "boule".to_string()),
            account,
        },
        other => anyhow::bail!("unsupported --to backend: {other}"),
    };

    let dest_provider: Arc<dyn KeyProvider> = build_provider(&dest_cfg)?;
    dest_provider.provision(&node_identity)?;

    if delete_source {
        if let IdentityConfig::File { path, .. } = &source_cfg {
            use std::io::Write as _;
            if path.exists() {
                if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
                    let len = std::fs::metadata(path)
                        .map(|m| m.len() as usize)
                        .unwrap_or(0);
                    let zeros = vec![0u8; len];
                    let _ = f.write_all(&zeros);
                    let _ = f.sync_all();
                }
                std::fs::remove_file(path).ok();
                warn!("deleted source key file at {}", path.display());
            }
        } else {
            warn!("--delete-source is only supported for file source backends; skipping");
        }
    }

    info!("migration complete");
    Ok(())
}

/// Resolve the BLS validator-signing identity. Returns `None` when the
/// `[node.bls_validator_identity]` table is absent.
pub fn resolve_bls_validator_identity(node: &NodeConfig) -> Option<BlsIdentityConfig> {
    node.bls_validator_identity.clone()
}

/// Build a [`crate::crypto::bls_key::BlsKeyProvider`] from a config.
pub fn build_bls_provider(
    cfg: &BlsIdentityConfig,
) -> anyhow::Result<Arc<dyn crate::crypto::bls_key::BlsKeyProvider>> {
    match cfg {
        BlsIdentityConfig::File {
            path,
            allow_insecure_perms,
        } => Ok(Arc::new(
            crate::crypto::bls_key::BlsKeyFile::new(path.clone())
                .with_allow_insecure_perms(*allow_insecure_perms),
        )),
    }
}

/// Build a `KeyProvider` for the given identity config.
pub fn build_provider(cfg: &IdentityConfig) -> anyhow::Result<Arc<dyn KeyProvider>> {
    match cfg {
        IdentityConfig::File {
            path,
            allow_insecure_perms,
        } => Ok(Arc::new(
            FileKeyProvider::new(path.clone()).with_allow_insecure_perms(*allow_insecure_perms),
        )),
        IdentityConfig::Env { env_var } => Ok(Arc::new(EnvKeyProvider::new(env_var.clone()))),
        IdentityConfig::EncryptedFile {
            path,
            passphrase_env,
        } => Ok(Arc::new(EncryptedFileKeyProvider::new(
            path.clone(),
            passphrase_env.clone(),
        ))),
        IdentityConfig::Exec { command } => Ok(Arc::new(ExecKeyProvider::new(command.clone())?)),
        #[cfg(feature = "keyring-backend")]
        IdentityConfig::Keyring { service, account } => {
            let acct = account.clone().unwrap_or_else(default_keyring_account);
            Ok(Arc::new(crate::identity::keyring::KeyringKeyProvider::new(
                service.clone(),
                acct,
            )))
        }
        #[cfg(not(feature = "keyring-backend"))]
        IdentityConfig::Keyring { .. } => {
            anyhow::bail!(
                "keyring backend is not compiled in; rebuild with `--features keyring-backend`"
            )
        }
    }
}

#[cfg(feature = "keyring-backend")]
fn default_keyring_account() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "default".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Config {
        toml::from_str(s).unwrap()
    }

    #[test]
    fn legacy_key_file_still_parses() {
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"
key_file = "/tmp/x.key"

[api]
listen_addr = "127.0.0.1:8080"
"#,
        );
        let id = resolve_identity(&c.node).unwrap();
        match id {
            IdentityConfig::File { path, .. } => assert_eq!(path, PathBuf::from("/tmp/x.key")),
            _ => panic!("expected file backend"),
        }
    }

    #[test]
    fn explicit_identity_wins_over_key_file() {
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"
key_file = "/tmp/legacy.key"

[node.identity]
backend = "file"
path    = "/tmp/new.key"

[api]
listen_addr = "127.0.0.1:8080"
"#,
        );
        let id = resolve_identity(&c.node).unwrap();
        match id {
            IdentityConfig::File { path, .. } => assert_eq!(path, PathBuf::from("/tmp/new.key")),
            _ => panic!("expected file backend"),
        }
    }

    #[test]
    fn no_identity_returns_none() {
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"
"#,
        );
        assert!(resolve_identity(&c.node).is_none());
    }

    #[test]
    fn env_backend_parses() {
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[node.identity]
backend = "env"
env_var = "BOULE_NODE_KEY"

[api]
listen_addr = "127.0.0.1:8080"
"#,
        );
        match resolve_identity(&c.node).unwrap() {
            IdentityConfig::Env { env_var } => assert_eq!(env_var, "BOULE_NODE_KEY"),
            _ => panic!("expected env backend"),
        }
    }

    #[test]
    fn encrypted_file_backend_parses() {
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[node.identity]
backend = "encrypted-file"
path = "/tmp/n.enc"
passphrase_env = "PW"

[api]
listen_addr = "127.0.0.1:8080"
"#,
        );
        match resolve_identity(&c.node).unwrap() {
            IdentityConfig::EncryptedFile {
                path,
                passphrase_env,
            } => {
                assert_eq!(path, PathBuf::from("/tmp/n.enc"));
                assert_eq!(passphrase_env.as_deref(), Some("PW"));
            }
            _ => panic!("expected encrypted-file backend"),
        }
    }

    #[test]
    fn exec_backend_parses() {
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[node.identity]
backend = "exec"
command = ["/usr/bin/vault-key", "--arg"]

[api]
listen_addr = "127.0.0.1:8080"
"#,
        );
        match resolve_identity(&c.node).unwrap() {
            IdentityConfig::Exec { command } => {
                assert_eq!(command, vec!["/usr/bin/vault-key", "--arg"]);
            }
            _ => panic!("expected exec backend"),
        }
    }

    #[test]
    fn consensus_section_parses() {
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[consensus]
validators = ["abc", "def", "ghi", "jkl"]
genesis_seed_hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
propose_limit = 32
timeout_base_ms = 100
timeout_max_ms = 5000
storage_dir = "/tmp/cons"
"#,
        );
        let cons = c.consensus.expect("consensus section");
        assert_eq!(cons.validators.len(), 4);
        assert_eq!(cons.propose_limit, 32);
        assert_eq!(cons.timeout_base_ms, 100);
        assert_eq!(cons.timeout_max_ms, 5000);
        assert_eq!(cons.storage_dir, Some(PathBuf::from("/tmp/cons")));
    }

    const VALID_HASH64: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    #[test]
    fn weak_subjectivity_checkpoint_parses_and_validates() {
        let c = parse(&format!(
            "[node]\nlisten_addr = \"127.0.0.1:7000\"\n[api]\nlisten_addr = \"127.0.0.1:8080\"\n[consensus]\nvalidators = []\n\
             [consensus.weak_subjectivity_checkpoint]\nheight = 1000\nhash = \"{VALID_HASH64}\"\n",
        ));
        let cp = c
            .consensus
            .as_ref()
            .unwrap()
            .weak_subjectivity_checkpoint
            .as_ref()
            .expect("checkpoint present");
        assert_eq!(cp.height, 1000);
        c.preflight_validate()
            .expect("a valid checkpoint passes preflight");
    }

    #[test]
    fn weak_subjectivity_checkpoint_unset_by_default() {
        let c = parse(
            "[node]\nlisten_addr = \"127.0.0.1:7000\"\n[api]\nlisten_addr = \"127.0.0.1:8080\"\n[consensus]\nvalidators = []\n",
        );
        assert!(c.consensus.unwrap().weak_subjectivity_checkpoint.is_none());
    }

    #[test]
    fn weak_subjectivity_checkpoint_rejects_bad_hash() {
        let c = parse(
            "[node]\nlisten_addr = \"127.0.0.1:7000\"\n[api]\nlisten_addr = \"127.0.0.1:8080\"\n[consensus]\nvalidators = []\n\
             [consensus.weak_subjectivity_checkpoint]\nheight = 5\nhash = \"not-hex\"\n",
        );
        assert!(c.preflight_validate().is_err());
    }

    #[test]
    fn weak_subjectivity_checkpoint_rejects_zero_height() {
        let c = parse(&format!(
            "[node]\nlisten_addr = \"127.0.0.1:7000\"\n[api]\nlisten_addr = \"127.0.0.1:8080\"\n[consensus]\nvalidators = []\n\
             [consensus.weak_subjectivity_checkpoint]\nheight = 0\nhash = \"{VALID_HASH64}\"\n",
        ));
        assert!(c.preflight_validate().is_err());
    }

    #[test]
    fn consensus_defaults_apply_when_omitted() {
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[consensus]
validators = ["a"]
"#,
        );
        let cons = c.consensus.expect("consensus section");
        assert_eq!(cons.propose_limit, 64);
        assert_eq!(cons.timeout_base_ms, 200);
        assert_eq!(cons.timeout_max_ms, 10_000);
        assert!(cons.storage_dir.is_none());
        assert!(cons.genesis_seed_hex.is_none());
        // Limits sub-table default — see ConsensusLimits::default().
        assert_eq!(
            cons.limits.vote_bucket_capacity,
            crate::config::DEFAULT_VOTE_BUCKET_CAPACITY,
        );
        assert_eq!(
            cons.limits.parked_proposals_capacity,
            crate::config::DEFAULT_PARKED_PROPOSALS_CAPACITY,
        );
        assert_eq!(
            cons.limits.pending_blocks_capacity,
            crate::config::DEFAULT_PENDING_BLOCKS_CAPACITY,
        );
        assert_eq!(
            cons.limits.timeout_buckets_capacity,
            crate::config::DEFAULT_TIMEOUT_BUCKETS_CAPACITY,
        );
        assert_eq!(
            cons.limits.block_sync_initial_backoff_views,
            crate::config::DEFAULT_BLOCK_SYNC_INITIAL_BACKOFF_VIEWS,
        );
        assert_eq!(
            cons.limits.block_sync_max_backoff_views,
            crate::config::DEFAULT_BLOCK_SYNC_MAX_BACKOFF_VIEWS,
        );
        assert_eq!(
            cons.limits.block_sync_per_peer_attempts,
            crate::config::DEFAULT_BLOCK_SYNC_PER_PEER_ATTEMPTS,
        );
        assert_eq!(
            cons.limits.block_sync_max_attempts,
            crate::config::DEFAULT_BLOCK_SYNC_MAX_ATTEMPTS,
        );
        assert_eq!(cons.mempool_capacity, 1024);
        // Default scheme: collected Ed25519. BLS lands at #289.
        assert_eq!(
            cons.signature_scheme,
            SignatureSchemeChoice::Ed25519Collected,
        );
    }

    #[test]
    fn consensus_signature_scheme_explicit_ed25519_collected_parses() {
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[consensus]
validators = ["a"]
signature_scheme = "ed25519_collected"
"#,
        );
        let cons = c.consensus.expect("consensus section");
        assert_eq!(
            cons.signature_scheme,
            SignatureSchemeChoice::Ed25519Collected,
        );
    }

    #[test]
    fn consensus_signature_scheme_unknown_value_fails_to_parse() {
        // Catch operator typos at startup, not on the first QC.
        let s = r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[consensus]
validators = ["a"]
signature_scheme = "ed25519_aggregated"
"#;
        let err = toml::from_str::<Config>(s).expect_err("unknown scheme must not parse");
        let msg = err.to_string();
        assert!(
            msg.contains("signature_scheme") || msg.contains("ed25519_aggregated"),
            "error must point at the offending field/value, got: {msg}",
        );
    }

    #[test]
    fn consensus_limits_subtable_overrides_defaults() {
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[consensus]
validators = ["a"]
mempool_capacity = 2048

[consensus.limits]
vote_bucket_capacity = 32
parked_proposals_capacity = 16
pending_blocks_capacity = 64
timeout_buckets_capacity = 8
block_sync_initial_backoff_views = 4
block_sync_max_backoff_views = 32
block_sync_per_peer_attempts = 5
block_sync_max_attempts = 25
"#,
        );
        let cons = c.consensus.expect("consensus section");
        assert_eq!(cons.limits.vote_bucket_capacity, 32);
        assert_eq!(cons.limits.parked_proposals_capacity, 16);
        assert_eq!(cons.limits.pending_blocks_capacity, 64);
        assert_eq!(cons.limits.timeout_buckets_capacity, 8);
        assert_eq!(cons.limits.block_sync_initial_backoff_views, 4);
        assert_eq!(cons.limits.block_sync_max_backoff_views, 32);
        assert_eq!(cons.limits.block_sync_per_peer_attempts, 5);
        assert_eq!(cons.limits.block_sync_max_attempts, 25);
        assert_eq!(cons.mempool_capacity, 2048);
    }

    #[test]
    fn consensus_snapshot_policy_defaults_when_omitted() {
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[consensus]
validators = ["a"]
"#,
        );
        let cons = c.consensus.expect("consensus section");
        assert_eq!(cons.snapshot_interval_blocks, 10_000);
        assert_eq!(cons.snapshot_retention_count, 3);
        assert_eq!(cons.snapshot_chunk_size_bytes, 1024 * 1024);
        cons.validate_snapshot_policy().unwrap();
    }

    #[test]
    fn consensus_snapshot_policy_overrides_apply() {
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[consensus]
validators = ["a"]
snapshot_interval_blocks = 250
snapshot_retention_count = 1
snapshot_chunk_size_bytes = 524288
"#,
        );
        let cons = c.consensus.expect("consensus section");
        assert_eq!(cons.snapshot_interval_blocks, 250);
        assert_eq!(cons.snapshot_retention_count, 1);
        assert_eq!(cons.snapshot_chunk_size_bytes, 524288);
        cons.validate_snapshot_policy().unwrap();
    }

    #[test]
    fn consensus_snapshot_chunk_size_bound_rejects_oversized() {
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[consensus]
validators = ["a"]
snapshot_interval_blocks = 100
snapshot_chunk_size_bytes = 4194304
"#,
        );
        // 4 MiB == MAX_FRAME_BYTES; the policy reserves headroom and
        // must reject this value.
        let cons = c.consensus.expect("consensus section");
        let err = cons
            .validate_snapshot_policy()
            .expect_err("4 MiB chunks leave no room for envelope");
        assert!(err.to_string().contains("snapshot_chunk_size_bytes"));
    }

    #[test]
    fn consensus_snapshot_zero_interval_disables() {
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[consensus]
validators = ["a"]
snapshot_interval_blocks = 0
snapshot_chunk_size_bytes = 0
"#,
        );
        // chunk_size_bytes=0 is fine when snapshots are disabled — the
        // validator only enforces the bound when the interval is
        // non-zero.
        let cons = c.consensus.expect("consensus section");
        cons.validate_snapshot_policy().unwrap();
    }

    #[test]
    fn consensus_limits_partial_override_keeps_other_defaults() {
        // Operators commonly override one knob (a tighter vote bucket
        // for a memory-constrained host, say) and expect the rest to
        // fall back to safe defaults.
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[consensus]
validators = ["a"]

[consensus.limits]
vote_bucket_capacity = 64
"#,
        );
        let cons = c.consensus.expect("consensus section");
        assert_eq!(cons.limits.vote_bucket_capacity, 64);
        assert_eq!(
            cons.limits.parked_proposals_capacity,
            crate::config::DEFAULT_PARKED_PROPOSALS_CAPACITY,
        );
        assert_eq!(
            cons.limits.timeout_buckets_capacity,
            crate::config::DEFAULT_TIMEOUT_BUCKETS_CAPACITY,
        );
    }

    #[test]
    fn missing_consensus_section_is_none() {
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"
"#,
        );
        assert!(c.consensus.is_none());
    }

    #[test]
    fn validator_identity_absent_returns_none() {
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[node.identity]
backend = "file"
path = "/tmp/net.key"

[api]
listen_addr = "127.0.0.1:8080"
"#,
        );
        assert!(resolve_validator_identity(&c.node).is_none());
    }

    #[test]
    fn validator_identity_parses_independently() {
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[node.identity]
backend = "file"
path = "/tmp/net.key"

[node.validator_identity]
backend = "file"
path = "/tmp/val.key"

[api]
listen_addr = "127.0.0.1:8080"
"#,
        );
        let net = resolve_identity(&c.node).expect("network identity");
        let val = resolve_validator_identity(&c.node).expect("validator identity");
        match net {
            IdentityConfig::File { path, .. } => assert_eq!(path, PathBuf::from("/tmp/net.key")),
            _ => panic!("expected file backend"),
        }
        match val {
            IdentityConfig::File { path, .. } => assert_eq!(path, PathBuf::from("/tmp/val.key")),
            _ => panic!("expected file backend"),
        }
    }

    #[test]
    fn validator_identity_can_use_distinct_backend() {
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[node.identity]
backend = "file"
path = "/tmp/net.key"

[node.validator_identity]
backend = "encrypted-file"
path = "/tmp/val.enc"
passphrase_env = "VAL_PW"

[api]
listen_addr = "127.0.0.1:8080"
"#,
        );
        match resolve_validator_identity(&c.node).unwrap() {
            IdentityConfig::EncryptedFile {
                path,
                passphrase_env,
            } => {
                assert_eq!(path, PathBuf::from("/tmp/val.enc"));
                assert_eq!(passphrase_env.as_deref(), Some("VAL_PW"));
            }
            other => panic!("expected encrypted-file backend, got {other:?}"),
        }
    }

    #[test]
    fn overlay_section_absent_applies_defaults() {
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"
"#,
        );
        // Defaults match the breakdown-comment values on #137,
        // including `mode = "gossip"` after the stack-9 cutover, and
        // the split direct-peer budgets from #187.
        assert_eq!(c.overlay.mode, OverlayMode::Gossip);
        assert_eq!(c.overlay.outbound_target, 8);
        assert_eq!(c.overlay.inbound_max, 16);
        assert_eq!(c.overlay.total_max, 24);
        assert_eq!(c.overlay.target_degree, None);
        assert_eq!(c.overlay.peer_gossip_interval_ms, 5_000);
        assert_eq!(c.overlay.peer_gossip_fanout, 3);
        assert_eq!(c.overlay.mesh_check_interval_ms, 5_000);
        assert_eq!(c.overlay.dedup_capacity, 4_096);
        assert_eq!(c.overlay.dedup_ttl_ms, 120_000);
        assert_eq!(c.overlay.peer_table_capacity, 1_024);
        assert!(c.overlay.bootstrap_addrs.is_empty());
    }

    #[test]
    fn overlay_mode_gossip_parses() {
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[overlay]
mode = "gossip"
"#,
        );
        assert_eq!(c.overlay.mode, OverlayMode::Gossip);
        // Section-present, knob-absent: defaults still apply.
        assert_eq!(c.overlay.outbound_target, 8);
        assert_eq!(c.overlay.inbound_max, 16);
        assert_eq!(c.overlay.total_max, 24);
    }

    /// #187 backwards-compat: a config with the deprecated
    /// `target_degree = N` knob still parses, and after
    /// `resolve_deprecated_aliases` runs it's projected onto all three
    /// new direct-peer-budget knobs.
    #[test]
    fn overlay_target_degree_alias_sets_all_three_split_knobs() {
        let mut c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[overlay]
mode = "gossip"
target_degree = 11
"#,
        );
        // Before resolution: alias visible, split knobs at defaults.
        assert_eq!(c.overlay.target_degree, Some(11));
        assert_eq!(c.overlay.outbound_target, 8);
        // After resolution: alias cleared, split knobs all set to N.
        c.overlay.resolve_deprecated_aliases();
        assert_eq!(c.overlay.target_degree, None);
        assert_eq!(c.overlay.outbound_target, 11);
        assert_eq!(c.overlay.inbound_max, 11);
        assert_eq!(c.overlay.total_max, 11);
    }

    #[test]
    fn overlay_individual_knob_overrides_take_effect() {
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[overlay]
mode = "gossip"
outbound_target = 12
inbound_max = 20
total_max = 32
peer_gossip_interval_ms = 2500
peer_gossip_fanout = 5
mesh_check_interval_ms = 7500
dedup_capacity = 16384
dedup_ttl_ms = 30000
peer_table_capacity = 4096
bootstrap_addrs = ["127.0.0.1:7100", "127.0.0.1:7200"]
"#,
        );
        assert_eq!(c.overlay.mode, OverlayMode::Gossip);
        assert_eq!(c.overlay.outbound_target, 12);
        assert_eq!(c.overlay.inbound_max, 20);
        assert_eq!(c.overlay.total_max, 32);
        assert_eq!(c.overlay.peer_gossip_interval_ms, 2_500);
        assert_eq!(c.overlay.peer_gossip_fanout, 5);
        assert_eq!(c.overlay.mesh_check_interval_ms, 7_500);
        assert_eq!(c.overlay.dedup_capacity, 16_384);
        assert_eq!(c.overlay.dedup_ttl_ms, 30_000);
        assert_eq!(c.overlay.peer_table_capacity, 4_096);
        assert_eq!(c.overlay.bootstrap_addrs.len(), 2);
        assert_eq!(c.overlay.bootstrap_addrs[0].port(), 7_100);
        assert_eq!(c.overlay.bootstrap_addrs[1].port(), 7_200);
    }

    #[test]
    fn overlay_malformed_mode_is_rejected() {
        let raw = r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[overlay]
mode = "not-a-real-mode"
"#;
        let err = toml::from_str::<Config>(raw).expect_err("malformed mode must fail to parse");
        let msg = err.to_string();
        assert!(
            msg.contains("not-a-real-mode") || msg.contains("variant"),
            "expected variant-rejection diagnostic, got: {msg}",
        );
    }

    #[test]
    fn overlay_bootstrap_addrs_round_trip() {
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[overlay]
mode = "gossip"
bootstrap_addrs = ["10.0.0.1:7000", "[::1]:7000"]
"#,
        );
        assert_eq!(c.overlay.bootstrap_addrs.len(), 2);
        assert_eq!(c.overlay.bootstrap_addrs[0].port(), 7000);
        assert!(c.overlay.bootstrap_addrs[1].is_ipv6());
    }

    #[test]
    fn p2p_inbound_disabled_defaults_to_false() {
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"
"#,
        );
        assert!(!c.p2p.inbound_disabled);
    }

    #[test]
    fn p2p_inbound_disabled_parses_when_set() {
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[p2p]
inbound_disabled = true
"#,
        );
        assert!(c.p2p.inbound_disabled);
    }

    #[test]
    fn p2p_keepalive_absent_means_disabled() {
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[p2p]
inbound_disabled = false
"#,
        );
        assert!(c.p2p.keepalive.is_none());
    }

    #[test]
    fn p2p_keepalive_empty_table_uses_defaults() {
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[p2p.keepalive]
"#,
        );
        let ka = c.p2p.keepalive.expect("keepalive table present");
        assert_eq!(ka.interval_ms, 10_000);
        assert_eq!(ka.timeout_ms, 30_000);
        ka.validate().expect("defaults must validate");
    }

    #[test]
    fn p2p_keepalive_partial_override_keeps_other_default() {
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[p2p.keepalive]
timeout_ms = 45000
"#,
        );
        let ka = c.p2p.keepalive.expect("keepalive table present");
        assert_eq!(ka.interval_ms, 10_000);
        assert_eq!(ka.timeout_ms, 45_000);
    }

    #[test]
    fn p2p_keepalive_validate_rejects_timeout_not_above_interval() {
        // Equal is rejected (no ping fits before the deadline)…
        let equal = P2pKeepaliveConfig {
            interval_ms: 10_000,
            timeout_ms: 10_000,
        };
        assert!(equal.validate().is_err());

        // …as is a zero interval that would busy-spin.
        let zero = P2pKeepaliveConfig {
            interval_ms: 0,
            timeout_ms: 30_000,
        };
        assert!(zero.validate().is_err());

        // A sane pair passes.
        let ok = P2pKeepaliveConfig {
            interval_ms: 10_000,
            timeout_ms: 30_000,
        };
        ok.validate().expect("interval < timeout must validate");
    }

    #[test]
    fn p2p_section_absent_means_no_limits() {
        // Pre-#134 behaviour preserved: a config that omits the
        // `[p2p]` table entirely runs without any rate limiting or
        // connection caps. (The runtime treats `limits = None` as
        // "do not install a limiter".)
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"
"#,
        );
        assert!(c.p2p.limits.is_none());
    }

    #[test]
    fn p2p_limits_subtable_uses_production_defaults_when_partial() {
        // Section present but every field omitted: production defaults
        // apply.
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[p2p.limits]
"#,
        );
        let limits = c.p2p.limits.expect("limits section");
        assert_eq!(limits.max_inbound_connections, 64);
        assert_eq!(limits.max_outbound_connections, 64);
        assert_eq!(limits.max_connections_per_ip, 4);
        assert_eq!(limits.rate.proposal_per_sec, 16.0);
        assert_eq!(limits.violations.window_secs, 10);
        assert_eq!(limits.violations.max_violations, 100);
    }

    #[test]
    fn p2p_limits_partial_override_keeps_other_defaults() {
        // Operators commonly want to tighten one knob (e.g.
        // `max_per_ip` for an exposed deployment) and expect the
        // rest to fall back to production defaults.
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[p2p.limits]
max_connections_per_ip = 1

[p2p.limits.rate]
vote_per_sec = 1024.0
"#,
        );
        let limits = c.p2p.limits.expect("limits section");
        assert_eq!(limits.max_connections_per_ip, 1);
        assert_eq!(limits.max_inbound_connections, 64); // default kept
        assert_eq!(limits.rate.vote_per_sec, 1024.0);
        assert_eq!(limits.rate.proposal_per_sec, 16.0); // default kept
        // Violation window/count defaults are preserved. The projection
        // into the runtime RateLimitsConfig is covered in p2p::limits.
        assert_eq!(limits.violations.window_secs, 10);
        assert_eq!(limits.violations.max_violations, 100);
    }

    #[test]
    fn p2p_limits_violations_override_takes_effect() {
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[p2p.limits.violations]
window_secs = 5
max_violations = 20
"#,
        );
        let limits = c.p2p.limits.expect("limits section");
        assert_eq!(limits.violations.window_secs, 5);
        assert_eq!(limits.violations.max_violations, 20);
    }

    #[test]
    fn validate_rejects_self_id_in_peers_list() {
        // A static [[peers]] entry whose node_id matches the local TLS
        // identity is a configuration footgun: the dialer would TLS-
        // handshake against its own listener (we hold both keys),
        // count the loopback against outbound_target, and surface it
        // in /peers. validate() rejects it at boot with a clear
        // pointer to the offending entry.
        let self_id: NodeId = [7u8; 32];
        let raw = node_id_to_base58(&self_id);
        let toml_str = format!(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[[peers]]
addr = "127.0.0.1:7001"
node_id = "{raw}"
"#,
        );
        let cfg: Config = toml::from_str(&toml_str).unwrap();
        let err = cfg.validate(&self_id).expect_err("self-id must reject");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("self-dial") || msg.contains("own NodeId"),
            "diagnostic must explain the self-dial reason; got: {msg}",
        );
        assert!(
            msg.contains("127.0.0.1:7001"),
            "diagnostic must point at the offending addr; got: {msg}",
        );
    }

    #[test]
    fn validate_accepts_distinct_peer_ids() {
        let self_id: NodeId = [1u8; 32];
        let other_id: NodeId = [2u8; 32];
        let toml_str = format!(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[[peers]]
addr = "127.0.0.1:7001"
node_id = "{}"
"#,
            node_id_to_base58(&other_id),
        );
        let cfg: Config = toml::from_str(&toml_str).unwrap();
        cfg.validate(&self_id).expect("distinct id must pass");
    }

    #[test]
    fn validate_accepts_tofu_peer_without_node_id() {
        // TOFU entries (no `node_id`) cannot be checked at config
        // validation time — the peer's identity is whatever it
        // presents on the handshake. validate() lets these through;
        // the dialer and listener handshake guards catch the self
        // case at cons.limits.
        let self_id: NodeId = [3u8; 32];
        let cfg: Config = toml::from_str(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[[peers]]
addr = "127.0.0.1:7001"
"#,
        )
        .unwrap();
        cfg.validate(&self_id).expect("TOFU entry must pass");
    }

    #[test]
    fn validate_rejects_malformed_peer_node_id() {
        // Surfacing malformed base58 here means operators see a clean
        // diagnostic at config-validation time, instead of the
        // `expect("invalid peer node_id in config")` panic that the
        // dialer wiring in `tls_protocol.rs` would otherwise hit.
        let self_id: NodeId = [4u8; 32];
        let cfg: Config = toml::from_str(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[[peers]]
addr = "127.0.0.1:7001"
node_id = "0OIl"
"#,
        )
        .unwrap();
        let err = cfg
            .validate(&self_id)
            .expect_err("malformed base58 must reject");
        assert!(
            format!("{err:#}").contains("malformed node_id"),
            "got: {err:#}",
        );
    }

    #[test]
    fn keyring_backend_parses_even_without_feature() {
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[node.identity]
backend = "keyring"

[api]
listen_addr = "127.0.0.1:8080"
"#,
        );
        match resolve_identity(&c.node).unwrap() {
            IdentityConfig::Keyring { service, account } => {
                assert_eq!(service, "boule");
                assert!(account.is_none());
            }
            _ => panic!("expected keyring backend"),
        }
    }

    // ── BLS genesis validators (#333) ────────────────────────────

    /// One generated genesis validator: base58 NodeId + hex BLS pubkey
    /// + hex BLS PoP. Used to drive the table-validation tests.
    struct BlsTestEntry {
        nid_b58: String,
        pubkey_hex: String,
        pop_hex: String,
    }

    fn make_bls_validator(seed: u8) -> BlsTestEntry {
        // Tests bind PoPs to the test sentinel chain_id; the
        // corresponding `verify_genesis_bls_pops` calls below pass
        // `&ChainId::TEST`. A real deployment would mint PoPs against
        // the deployment's actual `ChainId::from_genesis_hash(...)`.
        let nid: NodeId = [seed; 32];
        let mut ikm = [0u8; 32];
        ikm[0] = seed;
        ikm[1] = 0xAA;
        let (sk, pk) = BlsAggregated::keygen(&ikm).unwrap();
        let pop = BlsAggregated::sign_pop(&sk, &ChainId::TEST).unwrap();
        BlsTestEntry {
            nid_b58: node_id_to_base58(&nid),
            pubkey_hex: hex::encode(pk),
            pop_hex: hex::encode(pop.sig),
        }
    }

    fn render_bls_table(entries: &[BlsTestEntry]) -> String {
        let mut out = String::new();
        for e in entries {
            out.push_str(&format!(
                "[[consensus.validators_bls]]\n\
                 node_id = \"{}\"\n\
                 bls_pubkey = \"{}\"\n\
                 bls_pop = \"{}\"\n\n",
                e.nid_b58, e.pubkey_hex, e.pop_hex,
            ));
        }
        out
    }

    fn render_validators(entries: &[BlsTestEntry]) -> String {
        let names: Vec<String> = entries
            .iter()
            .map(|e| format!("\"{}\"", e.nid_b58))
            .collect();
        format!("validators = [{}]\n", names.join(", "))
    }

    #[test]
    fn bls_chain_with_complete_genesis_table_resolves() {
        let v = (1..=4u8).map(make_bls_validator).collect::<Vec<_>>();
        let s = format!(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[consensus]
{validators}signature_scheme = "bls_aggregated"

{bls_table}"#,
            validators = render_validators(&v),
            bls_table = render_bls_table(&v),
        );
        let cons = parse(&s).consensus.expect("consensus");
        let resolved = cons
            .resolve_genesis_bls_keys()
            .expect("structural validation must pass");
        assert_eq!(resolved.len(), 4);
        // Each NodeId in the resolved list must appear in the validators list.
        for (nid, _pk, _pop) in &resolved {
            let b58 = node_id_to_base58(nid);
            assert!(v.iter().any(|e| e.nid_b58 == b58));
        }
        // PoPs were minted under `ChainId::TEST`; verification under
        // the same chain_id must succeed (#410).
        cons.verify_genesis_bls_pops(&resolved, &ChainId::TEST)
            .expect("PoPs minted under ChainId::TEST must verify under ChainId::TEST");
    }

    /// #549: a `validators_operator_keys` table resolves to
    /// `(validator_id, operator_pubkey)` pairs. It is optional and a *subset*
    /// of validators may declare one.
    #[test]
    fn operator_keys_resolve_for_a_subset_of_validators() {
        let v1 = node_id_to_base58(&[1u8; 32]);
        let v2 = node_id_to_base58(&[2u8; 32]);
        let op1 = node_id_to_base58(&[0x11u8; 32]);
        let op2 = node_id_to_base58(&[0x22u8; 32]);
        let s = format!(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[consensus]
validators = ["{v1}", "{v2}", "{v3}", "{v4}"]

[[consensus.validators_operator_keys]]
node_id = "{v1}"
operator_pubkey = "{op1}"

[[consensus.validators_operator_keys]]
node_id = "{v2}"
operator_pubkey = "{op2}"
"#,
            v3 = node_id_to_base58(&[3u8; 32]),
            v4 = node_id_to_base58(&[4u8; 32]),
        );
        let cons = parse(&s).consensus.expect("consensus");
        let resolved = cons.resolve_genesis_operator_keys().expect("resolve");
        assert_eq!(
            resolved,
            vec![([1u8; 32], [0x11u8; 32]), ([2u8; 32], [0x22u8; 32])]
        );
    }

    /// #549: an absent table resolves to empty (operator keys are optional).
    #[test]
    fn operator_keys_absent_resolves_empty() {
        let v1 = node_id_to_base58(&[1u8; 32]);
        let s = format!(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[consensus]
validators = ["{v1}"]
"#,
        );
        let cons = parse(&s).consensus.expect("consensus");
        assert!(cons.resolve_genesis_operator_keys().unwrap().is_empty());
    }

    /// #549: an operator-key entry referencing a non-validator is rejected,
    /// and so is a duplicate validator entry.
    #[test]
    fn operator_keys_reject_unknown_validator_and_duplicates() {
        let v1 = node_id_to_base58(&[1u8; 32]);
        let stranger = node_id_to_base58(&[9u8; 32]);
        let op = node_id_to_base58(&[0x11u8; 32]);

        // Unknown validator.
        let unknown = format!(
            "[node]\nlisten_addr = \"127.0.0.1:7000\"\n[api]\nlisten_addr = \"127.0.0.1:8080\"\n\
             [consensus]\nvalidators = [\"{v1}\"]\n\
             [[consensus.validators_operator_keys]]\nnode_id = \"{stranger}\"\n\
             operator_pubkey = \"{op}\"\n",
        );
        let err = parse(&unknown)
            .consensus
            .unwrap()
            .resolve_genesis_operator_keys()
            .unwrap_err();
        assert!(err.to_string().contains("not in consensus.validators"));

        // Duplicate validator entry.
        let dup = format!(
            "[node]\nlisten_addr = \"127.0.0.1:7000\"\n[api]\nlisten_addr = \"127.0.0.1:8080\"\n\
             [consensus]\nvalidators = [\"{v1}\"]\n\
             [[consensus.validators_operator_keys]]\nnode_id = \"{v1}\"\n\
             operator_pubkey = \"{op}\"\n\
             [[consensus.validators_operator_keys]]\nnode_id = \"{v1}\"\n\
             operator_pubkey = \"{op}\"\n",
        );
        let err = parse(&dup)
            .consensus
            .unwrap()
            .resolve_genesis_operator_keys()
            .unwrap_err();
        assert!(err.to_string().contains("more than once"));
    }

    /// Audit finding 7-2 (#410): a `validators_bls` table whose PoPs
    /// were minted against chain_id A is rejected when verified
    /// against chain_id B. This is the genesis-config dual of the
    /// reconfig-add cross-chain replay defense.
    #[test]
    fn bls_chain_pop_verification_rejects_cross_chain_replay() {
        let v = (1..=4u8).map(make_bls_validator).collect::<Vec<_>>();
        let s = format!(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[consensus]
{validators}signature_scheme = "bls_aggregated"

{bls_table}"#,
            validators = render_validators(&v),
            bls_table = render_bls_table(&v),
        );
        let cons = parse(&s).consensus.expect("consensus");
        let resolved = cons.resolve_genesis_bls_keys().unwrap();
        // PoPs were minted under `ChainId::TEST`; verifying them
        // against a different chain_id must fail.
        let other = ChainId([0xCC; 32]);
        let err = cons.verify_genesis_bls_pops(&resolved, &other).unwrap_err();
        assert!(
            err.to_string().contains("PoP failed verification"),
            "got: {err}",
        );
    }

    #[test]
    fn bls_chain_without_table_is_rejected() {
        let v = (1..=4u8).map(make_bls_validator).collect::<Vec<_>>();
        let s = format!(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[consensus]
{validators}signature_scheme = "bls_aggregated"
"#,
            validators = render_validators(&v),
        );
        let cons = parse(&s).consensus.expect("consensus");
        let err = cons.resolve_genesis_bls_keys().unwrap_err();
        assert!(
            err.to_string().contains("validators_bls is required"),
            "got: {err}",
        );
    }

    #[test]
    fn ed25519_chain_with_validators_bls_is_rejected() {
        let v = (1..=4u8).map(make_bls_validator).collect::<Vec<_>>();
        let s = format!(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[consensus]
{validators}signature_scheme = "ed25519_collected"

{bls_table}"#,
            validators = render_validators(&v),
            bls_table = render_bls_table(&v),
        );
        let cons = parse(&s).consensus.expect("consensus");
        let err = cons.resolve_genesis_bls_keys().unwrap_err();
        assert!(err.to_string().contains("ed25519_collected"), "got: {err}",);
    }

    #[test]
    fn bls_chain_with_bad_pop_is_rejected() {
        let mut v = (1..=4u8).map(make_bls_validator).collect::<Vec<_>>();
        // Tamper one entry's PoP — flip a bit.
        let bytes = hex::decode(&v[2].pop_hex).unwrap();
        let mut tampered = bytes.clone();
        tampered[10] ^= 0x01;
        v[2].pop_hex = hex::encode(&tampered);

        let s = format!(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[consensus]
{validators}signature_scheme = "bls_aggregated"

{bls_table}"#,
            validators = render_validators(&v),
            bls_table = render_bls_table(&v),
        );
        let cons = parse(&s).consensus.expect("consensus");
        // Structural decode succeeds — the tamper is a cryptographic
        // failure, surfaced by `verify_genesis_bls_pops`.
        let resolved = cons.resolve_genesis_bls_keys().unwrap();
        let err = cons
            .verify_genesis_bls_pops(&resolved, &ChainId::TEST)
            .unwrap_err();
        assert!(
            err.to_string().contains("PoP failed verification"),
            "got: {err}",
        );
    }

    #[test]
    fn bls_chain_with_unknown_node_id_in_table_is_rejected() {
        let v = (1..=4u8).map(make_bls_validator).collect::<Vec<_>>();
        let stray = make_bls_validator(99);
        // Replace one of the table entries' node_id with a stray.
        let mut bls_v = v.clone_into_bls();
        bls_v[1].nid_b58 = stray.nid_b58.clone();

        let s = format!(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[consensus]
{validators}signature_scheme = "bls_aggregated"

{bls_table}"#,
            validators = render_validators(&v),
            bls_table = render_bls_table(&bls_v),
        );
        let cons = parse(&s).consensus.expect("consensus");
        let err = cons.resolve_genesis_bls_keys().unwrap_err();
        assert!(
            err.to_string().contains("not in consensus.validators"),
            "got: {err}",
        );
    }

    #[test]
    fn bls_chain_with_length_mismatch_is_rejected() {
        let v = (1..=4u8).map(make_bls_validator).collect::<Vec<_>>();
        // Drop one entry from the BLS table.
        let mut short = v.clone_into_bls();
        short.pop();

        let s = format!(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[consensus]
{validators}signature_scheme = "bls_aggregated"

{bls_table}"#,
            validators = render_validators(&v),
            bls_table = render_bls_table(&short),
        );
        let cons = parse(&s).consensus.expect("consensus");
        let err = cons.resolve_genesis_bls_keys().unwrap_err();
        assert!(
            err.to_string()
                .contains("entries but consensus.validators has"),
            "got: {err}",
        );
    }

    /// Lightweight clone trait for `Vec<BlsTestEntry>` (the struct
    /// itself doesn't derive `Clone` because the strings own data we'd
    /// rather not copy in the happy-path tests). Used by the negative
    /// tests above to mutate one entry without disturbing the others.
    trait CloneIntoBls {
        fn clone_into_bls(&self) -> Vec<BlsTestEntry>;
    }
    impl CloneIntoBls for Vec<BlsTestEntry> {
        fn clone_into_bls(&self) -> Vec<BlsTestEntry> {
            self.iter()
                .map(|e| BlsTestEntry {
                    nid_b58: e.nid_b58.clone(),
                    pubkey_hex: e.pubkey_hex.clone(),
                    pop_hex: e.pop_hex.clone(),
                })
                .collect()
        }
    }
}
