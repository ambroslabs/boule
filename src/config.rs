use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, serde::Deserialize)]
pub struct Config {
    pub node: NodeConfig,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
    pub api: ApiConfig,
}

#[derive(Debug, serde::Deserialize)]
pub struct NodeConfig {
    pub listen_addr: SocketAddr,
    /// Path to the Ed25519 private key file (PEM). Generated on first run if absent.
    #[serde(default = "default_key_file")]
    pub key_file: PathBuf,
    /// If set, the node writes its actual bound addresses and node ID to this file
    /// as JSON once both listeners are ready. Used by tests to discover dynamic ports.
    #[serde(default)]
    pub addr_file: Option<PathBuf>,
}

fn default_key_file() -> PathBuf {
    PathBuf::from("node.key")
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

pub fn load(path: &Path) -> anyhow::Result<Config> {
    let text = std::fs::read_to_string(path)?;
    let config: Config = toml::from_str(&text)?;
    Ok(config)
}
