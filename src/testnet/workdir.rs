//! Workdir layout + the persistent state file the driver maintains.
//!
//! Layout, all under `<workdir>/`:
//!
//! ```text
//! state.json              # cluster topology + per-node static info
//! events.jsonl            # append-only event log
//! node{N}/config.toml     # per-node ambros-p2p config
//! node{N}/node.key        # provisioned by `ambros-p2p init`
//! node{N}/consensus/      # consensus storage_dir
//! node{N}/log             # combined stdout+stderr capture
//! node{N}/addr.json       # written by the node binary on listener bind
//! node{N}/pid             # current PID when the node is up; absent when down
//! ```
//!
//! `state.json` is the source of truth for "what nodes exist" and is
//! written exactly once by `testnet new`. The per-node `pid` file is
//! the source of truth for "is this node up right now"; using a file
//! rather than only relying on `state.json` lets a re-invoked driver
//! recover after its own process was killed mid-scenario.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::topology::TopologySpec;

/// Filename of the cluster-level state file under the workdir.
pub const STATE_FILE: &str = "state.json";
/// Filename of the events log under the workdir.
pub const EVENTS_FILE: &str = "events.jsonl";

/// Name of the per-node directory within the workdir.
pub fn node_dir_name(index: usize) -> String {
    format!("node{}", index + 1)
}

/// Per-node static layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeLayout {
    /// Zero-based topology index. The display name is `node{index+1}`.
    pub index: usize,
    pub config_path: PathBuf,
    pub key_path: PathBuf,
    pub log_path: PathBuf,
    pub pid_path: PathBuf,
    pub addr_path: PathBuf,
    pub consensus_dir: PathBuf,
    /// Bootstrap peer indices (ring neighbours + random extras).
    pub bootstrap_peers: Vec<usize>,
    /// `node_id` (base58) + bound P2P / API addrs, populated by `init`
    /// (which spins the node briefly via the addr_file mechanism). May
    /// be absent for very fresh workdirs that haven't completed `new`.
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default)]
    pub p2p_addr: Option<SocketAddr>,
    #[serde(default)]
    pub api_addr: Option<SocketAddr>,
    /// Path to this node's BLS validator key file. Populated only on
    /// `bls_aggregated` chains (#360); otherwise absent. Read by the
    /// node binary via `[node.bls_validator_identity] backend = "file"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bls_key_path: Option<PathBuf>,
}

impl NodeLayout {
    pub fn display_name(&self) -> String {
        node_dir_name(self.index)
    }
}

/// Cluster-wide state file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub spec: PersistedSpec,
    pub nodes: Vec<NodeLayout>,
}

/// Mirror of `TopologySpec` with `serde` derives. The spec module is
/// kept dependency-free so test code can construct one without the
/// serialization stack.
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

/// Accept either a 1-based `nodeN` name or a bare 1-based number, and
/// return the zero-based index. Mirrors the per-node directory naming.
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

/// JSON shape the `ambros-p2p` binary writes to `addr_file` on listener
/// bind. Local copy — keeps the testnet driver decoupled from internal
/// `node` types.
#[derive(Debug, Deserialize)]
pub struct NodeAddrFile {
    pub p2p_addr: String,
    pub api_addr: String,
    pub node_id: String,
}

/// Read and parse the addr_file emitted by a started `ambros-p2p`.
pub fn read_addr_file(path: &Path) -> anyhow::Result<NodeAddrFile> {
    let bytes = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("reading addr file {}: {e}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("parsing addr file {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_node_id_accepts_both_forms() {
        assert_eq!(parse_node_id("node1", 5).unwrap(), 0);
        assert_eq!(parse_node_id("3", 5).unwrap(), 2);
        assert_eq!(parse_node_id("node5", 5).unwrap(), 4);
    }

    #[test]
    fn parse_node_id_rejects_zero_and_overflow() {
        assert!(parse_node_id("node0", 5).is_err());
        assert!(parse_node_id("node6", 5).is_err());
        assert!(parse_node_id("six", 5).is_err());
    }

    #[test]
    fn state_roundtrips_through_json() {
        let n = NodeLayout {
            index: 0,
            config_path: PathBuf::from("/w/node1/config.toml"),
            key_path: PathBuf::from("/w/node1/node.key"),
            log_path: PathBuf::from("/w/node1/log"),
            pid_path: PathBuf::from("/w/node1/pid"),
            addr_path: PathBuf::from("/w/node1/addr.json"),
            consensus_dir: PathBuf::from("/w/node1/consensus"),
            bootstrap_peers: vec![1, 2],
            node_id: Some("foo".to_string()),
            p2p_addr: "127.0.0.1:7000".parse().ok(),
            api_addr: "127.0.0.1:8000".parse().ok(),
            bls_key_path: None,
        };
        let state = State {
            spec: PersistedSpec {
                nodes: 4,
                seed_extra: 1,
                target_degree: 4,
                seed: 7,
            },
            nodes: vec![n],
        };
        let bytes = serde_json::to_vec(&state).unwrap();
        let back: State = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(state, back);
    }
}
