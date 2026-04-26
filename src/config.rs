use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tracing::warn;

use crate::p2p::identity::KeyProvider;
use crate::p2p::identity::encrypted_file::EncryptedFileKeyProvider;
use crate::p2p::identity::env::EnvKeyProvider;
use crate::p2p::identity::exec::ExecKeyProvider;
use crate::p2p::identity::file::FileKeyProvider;
use crate::p2p::tls::{NodeId, base58_to_node_id, node_id_to_base58};

#[derive(Debug, serde::Deserialize)]
pub struct Config {
    pub node: NodeConfig,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
    pub api: ApiConfig,
    /// Optional HotStuff consensus configuration. When absent the node
    /// runs gossip-only; when present a [`crate::consensus::node::ConsensusNode`]
    /// is started alongside the gossip and ping protocols.
    #[serde(default)]
    pub consensus: Option<ConsensusConfig>,
    /// Topology overlay configuration. Selects between the legacy
    /// full-mesh implementation and the partial-mesh gossip overlay
    /// (issue #137). When absent, defaults — including
    /// `mode = "mesh"` — apply.
    #[serde(default)]
    pub overlay: OverlayConfig,
}

#[derive(Debug, serde::Deserialize)]
pub struct NodeConfig {
    pub listen_addr: SocketAddr,
    /// Network (TLS) identity backend. The Ed25519 public key loaded here
    /// becomes the node's overlay [`crate::p2p::tls::NodeId`] and the
    /// certificate the TLS handshake presents. If absent, falls back to
    /// the deprecated `key_file` field or, failing that, a file backend
    /// at `./node.key`.
    #[serde(default)]
    pub identity: Option<IdentityConfig>,
    /// Optional validator (consensus signing) identity backend. When set,
    /// the consensus layer signs proposals/votes/timeouts with this key
    /// instead of the network identity. When unset, the network identity
    /// is reused for consensus signing — the historical single-key
    /// behavior — with a deprecation warning at startup if consensus is
    /// enabled. Both slots accept any of the same backends.
    #[serde(default)]
    pub validator_identity: Option<IdentityConfig>,
    /// Deprecated alias for `[node.identity] backend = "file" path = ...`.
    /// Retained for backward compatibility; emits a warning at startup.
    #[serde(default)]
    pub key_file: Option<PathBuf>,
    /// If set, the node writes its actual bound addresses and node ID to this file
    /// as JSON once both listeners are ready. Used by tests to discover dynamic ports.
    #[serde(default)]
    pub addr_file: Option<PathBuf>,
}

/// Where the node's long-term Ed25519 identity lives.
#[derive(Debug, Clone, serde::Deserialize)]
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
        #[serde(default)]
        account: Option<String>,
    },
    /// Passphrase-encrypted file (XChaCha20-Poly1305 + Argon2id).
    EncryptedFile {
        path: PathBuf,
        /// Env var to read the passphrase from. If omitted, prompts the TTY.
        #[serde(default)]
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

fn default_key_file() -> PathBuf {
    PathBuf::from("node.key")
}

fn default_keyring_service() -> String {
    "ambros-p2p".to_string()
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct PeerConfig {
    pub addr: SocketAddr,
    /// Expected base58-encoded Ed25519 node ID of this peer.
    /// If set, the connection is rejected when the peer presents a different identity.
    /// Omit for trust-on-first-use (e.g. in development).
    #[serde(default)]
    pub node_id: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ApiConfig {
    pub listen_addr: SocketAddr,
    #[serde(default = "default_cleanup_interval")]
    pub cleanup_interval_secs: u64,
}

fn default_cleanup_interval() -> u64 {
    60
}

/// HotStuff consensus configuration. Opt-in via the top-level
/// `[consensus]` table; absent means the binary runs gossip-only.
///
/// The `validators` list must contain this node's own base58 NodeId
/// and must be byte-identical across every replica in the cluster
/// (validator-set ordering determines round-robin leader rotation).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ConsensusConfig {
    /// Base58-encoded NodeIds of every validator in the committee.
    /// Must include this node's own ID.
    pub validators: Vec<String>,
    /// 32-byte hex string used as the genesis block's `state_commitment`.
    /// Must match across all replicas. Defaults to all zeros.
    #[serde(default)]
    pub genesis_seed_hex: Option<String>,
    /// Maximum commands the leader pulls from the mempool per proposal.
    #[serde(default = "default_propose_limit")]
    pub propose_limit: usize,
    /// View-timer base duration in milliseconds.
    #[serde(default = "default_timeout_base_ms")]
    pub timeout_base_ms: u64,
    /// View-timer ceiling (exponential backoff saturates here) in ms.
    #[serde(default = "default_timeout_max_ms")]
    pub timeout_max_ms: u64,
    /// Directory holding the consensus KV store and WAL on disk.
    /// If unset, in-memory storage is used (no crash recovery).
    #[serde(default)]
    pub storage_dir: Option<PathBuf>,
    /// Bounded-cache caps for the safety core and the integration
    /// layer's timeout-vote handler. See [`ConsensusLimits`] for the
    /// per-cache documentation; defaults match
    /// [`crate::consensus::limits::CacheLimits::production_defaults`].
    #[serde(default)]
    pub limits: ConsensusLimits,
}

/// Per-cache capacity caps and an in-memory mempool cap. Parsed from
/// the `[consensus.limits]` TOML sub-table; defaults apply when the
/// table — or any individual field — is omitted.
///
/// Eviction policy and rationale are documented on
/// [`crate::consensus::limits::CacheLimits`]; this struct is the
/// configuration shape, the runtime shape lives in that module so the
/// safety core can stay free of `serde` dependencies.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ConsensusLimits {
    /// Cap on the safety core's `vote_bucket` map. Defaults to
    /// [`crate::consensus::limits::DEFAULT_VOTE_BUCKET_CAPACITY`].
    #[serde(default = "default_vote_bucket_capacity")]
    pub vote_bucket_capacity: usize,
    /// Cap on the safety core's `parked_proposals` map. Defaults to
    /// [`crate::consensus::limits::DEFAULT_PARKED_PROPOSALS_CAPACITY`].
    #[serde(default = "default_parked_proposals_capacity")]
    pub parked_proposals_capacity: usize,
    /// Cap on the safety core's `pending_blocks` map. Defaults to
    /// [`crate::consensus::limits::DEFAULT_PENDING_BLOCKS_CAPACITY`].
    #[serde(default = "default_pending_blocks_capacity")]
    pub pending_blocks_capacity: usize,
    /// Cap on the integration layer's `timeout_buckets` map. Defaults
    /// to [`crate::consensus::limits::DEFAULT_TIMEOUT_BUCKETS_CAPACITY`].
    #[serde(default = "default_timeout_buckets_capacity")]
    pub timeout_buckets_capacity: usize,
    /// Maximum entries the bundled in-memory mempool will accept.
    /// Inserts past the cap surface as `Err` to the caller (see
    /// [`crate::replication::impls::mem_mempool::InMemoryMempool`]),
    /// rather than silently dropping. The application layer that
    /// will eventually replace this implementation is free to ignore
    /// the field; consensus only consults it when constructing the
    /// default `InMemoryMempool` at startup.
    #[serde(default = "default_mempool_capacity")]
    pub mempool_capacity: usize,
}

impl Default for ConsensusLimits {
    fn default() -> Self {
        Self {
            vote_bucket_capacity: default_vote_bucket_capacity(),
            parked_proposals_capacity: default_parked_proposals_capacity(),
            pending_blocks_capacity: default_pending_blocks_capacity(),
            timeout_buckets_capacity: default_timeout_buckets_capacity(),
            mempool_capacity: default_mempool_capacity(),
        }
    }
}

impl ConsensusLimits {
    /// Project the safety-core / integration-layer caps into the
    /// runtime [`crate::consensus::limits::CacheLimits`] shape. The
    /// `mempool_capacity` field is consumed independently by the
    /// startup wiring in `src/node.rs` and does not appear in
    /// `CacheLimits`.
    pub fn to_cache_limits(&self) -> crate::consensus::limits::CacheLimits {
        crate::consensus::limits::CacheLimits {
            vote_bucket_capacity: self.vote_bucket_capacity,
            parked_proposals_capacity: self.parked_proposals_capacity,
            pending_blocks_capacity: self.pending_blocks_capacity,
            timeout_buckets_capacity: self.timeout_buckets_capacity,
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
    crate::consensus::limits::DEFAULT_VOTE_BUCKET_CAPACITY
}

fn default_parked_proposals_capacity() -> usize {
    crate::consensus::limits::DEFAULT_PARKED_PROPOSALS_CAPACITY
}

fn default_pending_blocks_capacity() -> usize {
    crate::consensus::limits::DEFAULT_PENDING_BLOCKS_CAPACITY
}

fn default_timeout_buckets_capacity() -> usize {
    crate::consensus::limits::DEFAULT_TIMEOUT_BUCKETS_CAPACITY
}

fn default_mempool_capacity() -> usize {
    1024
}

/// Topology-overlay configuration. Selects between the partial-mesh
/// gossip overlay (`mode = "gossip"`, the default) and the legacy
/// full-mesh implementation (`mode = "mesh"`, retained for fallback
/// and for tests that want N–1 connectivity guarantees).
///
/// Defaults are tuned to match the per-module `Default` impls in the
/// gossip building blocks ([`crate::p2p::overlay::gossip::peer_list_task::PeerListGossipConfig`],
/// [`crate::p2p::overlay::gossip::maintenance::MeshMaintenanceConfig`],
/// [`crate::p2p::overlay::gossip::overlay::GossipOverlayConfig`]), so a
/// node that omits `[overlay]` entirely gets the breakdown-comment
/// defaults from issue #137.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct OverlayConfig {
    /// Which overlay implementation to use. Defaults to `gossip`
    /// after the 25-node sim convergence test landed in stack 8 of
    /// issue #137. Operators who need the legacy full-mesh behaviour
    /// (every node holds N–1 direct connections) can set
    /// `mode = "mesh"`.
    #[serde(default)]
    pub mode: OverlayMode,
    /// Upper bound on direct peer count for the partial-mesh
    /// maintenance loop. Used in `mode = "gossip"` only.
    #[serde(default = "default_target_degree")]
    pub target_degree: usize,
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
    #[serde(default)]
    pub bootstrap_addrs: Vec<SocketAddr>,
}

impl Default for OverlayConfig {
    fn default() -> Self {
        Self {
            mode: OverlayMode::default(),
            target_degree: default_target_degree(),
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

/// Which topology overlay implementation to drive consensus with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OverlayMode {
    /// Legacy full-mesh implementation. Retained as an opt-in for
    /// operators who need N–1 direct connectivity guarantees; the
    /// gossip overlay is the default.
    Mesh,
    /// Partial-mesh gossip overlay (issue #137). Default since
    /// stack 9 of #137 — operators get bounded direct-peer count
    /// (`target_degree`, default 8) without coordinated config
    /// rollouts when the validator set grows.
    #[default]
    Gossip,
}

fn default_target_degree() -> usize {
    8
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
    let config: Config = toml::from_str(&text)?;
    Ok(config)
}

impl Config {
    /// Cross-validate the parsed config against the local TLS identity.
    ///
    /// Rejects any static `[[peers]]` entry whose `node_id` matches the
    /// local node — a self-dial would loop back to our own listener,
    /// count against `target_degree`, and surface as a real peer in
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
        Ok(())
    }
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
            Ok(Arc::new(
                crate::p2p::identity::keyring::KeyringKeyProvider::new(service.clone(), acct),
            ))
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
env_var = "AMBROS_NODE_KEY"

[api]
listen_addr = "127.0.0.1:8080"
"#,
        );
        match resolve_identity(&c.node).unwrap() {
            IdentityConfig::Env { env_var } => assert_eq!(env_var, "AMBROS_NODE_KEY"),
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
        let runtime = cons.limits.to_cache_limits();
        assert_eq!(
            runtime.vote_bucket_capacity,
            crate::consensus::limits::DEFAULT_VOTE_BUCKET_CAPACITY,
        );
        assert_eq!(
            runtime.parked_proposals_capacity,
            crate::consensus::limits::DEFAULT_PARKED_PROPOSALS_CAPACITY,
        );
        assert_eq!(
            runtime.pending_blocks_capacity,
            crate::consensus::limits::DEFAULT_PENDING_BLOCKS_CAPACITY,
        );
        assert_eq!(
            runtime.timeout_buckets_capacity,
            crate::consensus::limits::DEFAULT_TIMEOUT_BUCKETS_CAPACITY,
        );
        assert_eq!(cons.limits.mempool_capacity, 1024);
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

[consensus.limits]
vote_bucket_capacity = 32
parked_proposals_capacity = 16
pending_blocks_capacity = 64
timeout_buckets_capacity = 8
mempool_capacity = 2048
"#,
        );
        let cons = c.consensus.expect("consensus section");
        let runtime = cons.limits.to_cache_limits();
        assert_eq!(runtime.vote_bucket_capacity, 32);
        assert_eq!(runtime.parked_proposals_capacity, 16);
        assert_eq!(runtime.pending_blocks_capacity, 64);
        assert_eq!(runtime.timeout_buckets_capacity, 8);
        assert_eq!(cons.limits.mempool_capacity, 2048);
    }

    #[test]
    fn consensus_limits_partial_override_keeps_other_defaults() {
        // Operators commonly override one knob (a tighter mempool
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
mempool_capacity = 64
"#,
        );
        let cons = c.consensus.expect("consensus section");
        let runtime = cons.limits.to_cache_limits();
        assert_eq!(cons.limits.mempool_capacity, 64);
        assert_eq!(
            runtime.vote_bucket_capacity,
            crate::consensus::limits::DEFAULT_VOTE_BUCKET_CAPACITY,
        );
        assert_eq!(
            runtime.timeout_buckets_capacity,
            crate::consensus::limits::DEFAULT_TIMEOUT_BUCKETS_CAPACITY,
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
        // including `mode = "gossip"` after the stack-9 cutover.
        assert_eq!(c.overlay.mode, OverlayMode::Gossip);
        assert_eq!(c.overlay.target_degree, 8);
        assert_eq!(c.overlay.peer_gossip_interval_ms, 5_000);
        assert_eq!(c.overlay.peer_gossip_fanout, 3);
        assert_eq!(c.overlay.mesh_check_interval_ms, 5_000);
        assert_eq!(c.overlay.dedup_capacity, 4_096);
        assert_eq!(c.overlay.dedup_ttl_ms, 120_000);
        assert_eq!(c.overlay.peer_table_capacity, 1_024);
        assert!(c.overlay.bootstrap_addrs.is_empty());
    }

    #[test]
    fn overlay_mode_mesh_parses_explicitly() {
        // After the stack-9 cutover, `mode = "gossip"` is the default,
        // so operators who want the legacy full-mesh behaviour must
        // opt in explicitly.
        let c = parse(
            r#"
[node]
listen_addr = "127.0.0.1:7000"

[api]
listen_addr = "127.0.0.1:8080"

[overlay]
mode = "mesh"
"#,
        );
        assert_eq!(c.overlay.mode, OverlayMode::Mesh);
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
        assert_eq!(c.overlay.target_degree, 8);
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
target_degree = 12
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
        assert_eq!(c.overlay.target_degree, 12);
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
    fn validate_rejects_self_id_in_peers_list() {
        // A static [[peers]] entry whose node_id matches the local TLS
        // identity is a configuration footgun: the dialer would TLS-
        // handshake against its own listener (we hold both keys),
        // count the loopback against target_degree, and surface it in
        // /peers. validate() rejects it at boot with a clear pointer
        // to the offending entry.
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
        // case at runtime.
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
                assert_eq!(service, "ambros-p2p");
                assert!(account.is_none());
            }
            _ => panic!("expected keyring backend"),
        }
    }
}
