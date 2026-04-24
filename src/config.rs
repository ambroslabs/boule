use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tracing::warn;

use crate::p2p::identity::KeyProvider;
use crate::p2p::identity::encrypted_file::EncryptedFileKeyProvider;
use crate::p2p::identity::env::EnvKeyProvider;
use crate::p2p::identity::exec::ExecKeyProvider;
use crate::p2p::identity::file::FileKeyProvider;

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
}

#[derive(Debug, serde::Deserialize)]
pub struct NodeConfig {
    pub listen_addr: SocketAddr,
    /// Optional identity backend. If absent, falls back to the deprecated
    /// `key_file` field or, failing that, a file backend at `./node.key`.
    #[serde(default)]
    pub identity: Option<IdentityConfig>,
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

pub fn load(path: &Path) -> anyhow::Result<Config> {
    let text = std::fs::read_to_string(path)?;
    let config: Config = toml::from_str(&text)?;
    Ok(config)
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
