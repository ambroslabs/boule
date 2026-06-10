use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::topology::TopologySpec;

pub const STATE_FILE: &str = "state.json";

pub const EVENTS_FILE: &str = "events.jsonl";

pub fn node_dir_name(index: usize) -> String {
    format!("node{}", index + 1)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeLayout {
    pub index: usize,
    pub config_path: PathBuf,
    pub key_path: PathBuf,
    pub log_path: PathBuf,
    pub pid_path: PathBuf,
    pub addr_path: PathBuf,
    pub consensus_dir: PathBuf,

    pub bootstrap_peers: Vec<usize>,

    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default)]
    pub p2p_addr: Option<SocketAddr>,
    #[serde(default)]
    pub api_addr: Option<SocketAddr>,

    #[serde(default)]
    pub admin_addr: Option<SocketAddr>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bls_key_path: Option<PathBuf>,
}

impl NodeLayout {
    pub fn display_name(&self) -> String {
        node_dir_name(self.index)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub spec: PersistedSpec,
    pub nodes: Vec<NodeLayout>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedSpec {
    pub nodes: usize,
    pub seed_extra: usize,
    pub target_degree: usize,
    pub seed: u64,
}

impl From<TopologySpec> for PersistedSpec {
    fn from(s: TopologySpec) -> Self {
        Self {
            nodes: s.nodes,
            seed_extra: s.seed_extra,
            target_degree: s.target_degree,
            seed: s.seed,
        }
    }
}

impl From<PersistedSpec> for TopologySpec {
    fn from(s: PersistedSpec) -> Self {
        Self {
            nodes: s.nodes,
            seed_extra: s.seed_extra,
            target_degree: s.target_degree,
            seed: s.seed,
        }
    }
}

impl State {
    pub fn load(workdir: &Path) -> anyhow::Result<Self> {
        let path = workdir.join(STATE_FILE);
        let bytes = std::fs::read(&path)
            .map_err(|e| anyhow::anyhow!("reading state file {}: {e}", path.display()))?;
        let state: State = serde_json::from_slice(&bytes)
            .map_err(|e| anyhow::anyhow!("parsing state file {}: {e}", path.display()))?;
        Ok(state)
    }

    pub fn save(&self, workdir: &Path) -> anyhow::Result<()> {
        let path = workdir.join(STATE_FILE);
        let bytes = serde_json::to_vec_pretty(self)?;
        std::fs::write(&path, bytes)
            .map_err(|e| anyhow::anyhow!("writing state file {}: {e}", path.display()))?;
        Ok(())
    }

    pub fn node(&self, name_or_idx: &str) -> anyhow::Result<&NodeLayout> {
        let idx = parse_node_id(name_or_idx, self.nodes.len())?;
        Ok(&self.nodes[idx])
    }
}

pub fn parse_node_id(name: &str, count: usize) -> anyhow::Result<usize> {
    let trimmed = name.strip_prefix("node").unwrap_or(name);
    let one_based: usize = trimmed
        .parse()
        .map_err(|_| anyhow::anyhow!("expected 'nodeN' or 'N', got {name:?}"))?;
    if one_based == 0 || one_based > count {
        anyhow::bail!("node {name:?} is out of range 1..={count}");
    }
    Ok(one_based - 1)
}

#[derive(Debug, Deserialize)]
pub struct NodeAddrFile {
    pub p2p_addr: String,
    pub api_addr: String,
    pub node_id: String,

    #[serde(default)]
    pub admin_addr: Option<String>,
}

pub fn read_addr_file(path: &Path) -> anyhow::Result<NodeAddrFile> {
    let bytes = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("reading addr file {}: {e}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("parsing addr file {}: {e}", path.display()))
}
