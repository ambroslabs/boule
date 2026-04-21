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
    /// If set, the node writes its actual bound addresses (P2P + API) to this file
    /// as JSON once both listeners are ready. Used by tests to discover dynamic ports.
    #[serde(default)]
    pub addr_file: Option<PathBuf>,
}

#[derive(Debug, serde::Deserialize)]
pub struct PeerConfig {
    pub addr: SocketAddr,
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
