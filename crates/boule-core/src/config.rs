use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tracing::{info, warn};

use crate::cli::OutputFormat;
use crate::crypto::sig_scheme::{BlsAggregated, BlsPop, BlsPublicKey};
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

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consensus: Option<ConsensusConfig>,

    #[serde(default)]
    pub overlay: OverlayConfig,

    #[serde(default)]
    pub p2p: P2pConfig,

    #[serde(default)]
    pub ui: UiConfig,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct NodeConfig {
    pub listen_addr: SocketAddr,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validator_identity: Option<IdentityConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bls_validator_identity: Option<BlsIdentityConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_file: Option<PathBuf>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addr_file: Option<PathBuf>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(tag = "backend", rename_all = "kebab-case")]
pub enum IdentityConfig {
    File {
        #[serde(default = "default_key_file")]
        path: PathBuf,

        #[serde(default)]
        allow_insecure_perms: bool,
    },

    Env {
        env_var: String,
    },

    Keyring {
        #[cfg_attr(not(feature = "keyring-backend"), allow(dead_code))]
        #[serde(default = "default_keyring_service")]
        service: String,
        #[cfg_attr(not(feature = "keyring-backend"), allow(dead_code))]
        #[serde(default, skip_serializing_if = "Option::is_none")]
        account: Option<String>,
    },

    EncryptedFile {
        path: PathBuf,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase_env: Option<String>,
    },

    Exec {
        command: Vec<String>,
    },
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

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(tag = "backend", rename_all = "kebab-case")]
pub enum BlsIdentityConfig {
    File {
        path: PathBuf,

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

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,

    #[serde(default)]
    pub private: bool,

    #[serde(default)]
    pub persistent: bool,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct ApiConfig {
    pub listen_addr: SocketAddr,

    #[serde(default)]
    pub admin: AdminApiConfig,
}

#[derive(Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct AdminApiConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_addr: Option<SocketAddr>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token_env: Option<String>,
}

impl AdminApiConfig {
    pub fn resolve_auth_token(&self) -> anyhow::Result<Option<String>> {
        if let Some(var) = self.auth_token_env.as_ref() {
            let val = std::env::var(var).map_err(|_| {
                anyhow::anyhow!(
                    "[api.admin].auth_token_env points at ${var}, which is unset or not \
                     valid UTF-8; refusing to start an admin listener without the token \
                     the operator asked to require"
                )
            })?;
            if val.is_empty() {
                anyhow::bail!("[api.admin].auth_token_env (${var}) is empty");
            }
            return Ok(Some(val));
        }
        Ok(self.auth_token.clone().filter(|t| !t.is_empty()))
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(tag = "backend", rename_all = "kebab-case")]
pub enum ApplicationConfig {
    Reth {
        engine_url: String,

        eth_url: String,

        jwt_secret_path: PathBuf,

        fee_recipient: String,

        #[serde(default = "default_reth_build_wait_ms")]
        build_wait_ms: u64,

        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        reth_peers: Vec<String>,
    },

    #[serde(rename = "reth-inprocess")]
    RethInProcess {
        fee_recipient: String,

        #[serde(default = "default_reth_build_wait_ms")]
        build_wait_ms: u64,
    },
}

fn default_reth_build_wait_ms() -> u64 {
    200
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ConsensusConfig {
    pub validators: Vec<String>,

    #[serde(default)]
    pub full_node: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genesis_seed_hex: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weak_subjectivity_checkpoint: Option<WeakSubjectivityCheckpoint>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<ApplicationConfig>,

    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_counter_state_machine: bool,

    #[serde(default = "default_propose_limit")]
    pub propose_limit: usize,

    #[serde(default = "default_mempool_capacity")]
    pub mempool_capacity: usize,

    #[serde(default = "default_max_endpoint_list_length")]
    pub max_endpoint_list_length: usize,

    #[serde(default = "default_timeout_base_ms")]
    pub timeout_base_ms: u64,

    #[serde(default = "default_timeout_max_ms")]
    pub timeout_max_ms: u64,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_dir: Option<PathBuf>,

    #[serde(default)]
    pub limits: ConsensusLimits,

    #[serde(default = "default_snapshot_interval_blocks")]
    pub snapshot_interval_blocks: u64,

    #[serde(default = "default_snapshot_retention_count")]
    pub snapshot_retention_count: usize,

    #[serde(default = "default_snapshot_chunk_size_bytes")]
    pub snapshot_chunk_size_bytes: u32,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub validators_bls: Vec<ValidatorBlsEntry>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub validators_operator_keys: Vec<ValidatorOperatorKeyEntry>,

    #[serde(default = "default_block_retention_window")]
    pub block_retention_window: u64,

    #[serde(default)]
    pub min_block_interval_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct WeakSubjectivityCheckpoint {
    pub height: u64,

    pub hash: String,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ValidatorBlsEntry {
    pub node_id: String,

    pub bls_pubkey: String,

    pub bls_pop: String,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ValidatorOperatorKeyEntry {
    pub node_id: String,

    pub operator_pubkey: String,
}

impl ConsensusConfig {
    pub fn resolve_genesis_bls_keys(&self) -> anyhow::Result<Vec<(NodeId, BlsPublicKey, BlsPop)>> {
        if self.validators_bls.is_empty() {
            anyhow::bail!(
                "consensus.validators_bls is required but the table is empty or missing. \
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

        let mut declared: std::collections::BTreeSet<NodeId> = std::collections::BTreeSet::new();
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
        let mut seen: std::collections::BTreeSet<NodeId> = std::collections::BTreeSet::new();
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
                anyhow::anyhow!("consensus.validators_bls[{idx}].bls_pop is not 96-byte hex: {e}",)
            })?;
            let pop = BlsPop {
                pubkey,
                sig: sig_bytes,
            };
            out.push((nid, pubkey, pop));
        }
        Ok(out)
    }

    pub fn resolve_genesis_operator_keys(&self) -> anyhow::Result<Vec<(NodeId, NodeId)>> {
        if self.validators_operator_keys.is_empty() {
            return Ok(Vec::new());
        }

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

    pub fn validate_snapshot_policy(&self) -> anyhow::Result<()> {
        if self.snapshot_interval_blocks > 0 && self.snapshot_chunk_size_bytes == 0 {
            anyhow::bail!(
                "consensus.snapshot_chunk_size_bytes must be > 0 when \
                 snapshot_interval_blocks is non-zero"
            );
        }

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

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ConsensusLimits {
    #[serde(default = "default_vote_bucket_capacity")]
    pub vote_bucket_capacity: usize,

    #[serde(default = "default_parked_proposals_capacity")]
    pub parked_proposals_capacity: usize,

    #[serde(default = "default_pending_blocks_capacity")]
    pub pending_blocks_capacity: usize,

    #[serde(default = "default_timeout_buckets_capacity")]
    pub timeout_buckets_capacity: usize,

    #[serde(default = "default_block_sync_initial_backoff_views")]
    pub block_sync_initial_backoff_views: u64,

    #[serde(default = "default_block_sync_max_backoff_views")]
    pub block_sync_max_backoff_views: u64,

    #[serde(default = "default_block_sync_per_peer_attempts")]
    pub block_sync_per_peer_attempts: u32,

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

pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

pub const DEFAULT_VOTE_BUCKET_CAPACITY: usize = 1024;

pub const DEFAULT_PARKED_PROPOSALS_CAPACITY: usize = 256;

pub const DEFAULT_PENDING_BLOCKS_CAPACITY: usize = 1024;

pub const DEFAULT_TIMEOUT_BUCKETS_CAPACITY: usize = 1024;

pub const DEFAULT_BLOCK_SYNC_INITIAL_BACKOFF_VIEWS: u64 = 1;

pub const DEFAULT_BLOCK_SYNC_MAX_BACKOFF_VIEWS: u64 = 8;

pub const DEFAULT_BLOCK_SYNC_PER_PEER_ATTEMPTS: u32 = 2;

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

fn default_block_retention_window() -> u64 {
    0
}

#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct P2pConfig {
    #[serde(default)]
    pub limits: Option<P2pLimitsConfig>,

    #[serde(default)]
    pub inbound_disabled: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive: Option<P2pKeepaliveConfig>,
}

#[derive(Debug, Clone, Copy, serde::Deserialize, serde::Serialize)]
pub struct P2pKeepaliveConfig {
    #[serde(default = "default_keepalive_interval_ms")]
    pub interval_ms: u64,

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

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct P2pLimitsConfig {
    #[serde(default = "default_max_inbound_connections")]
    pub max_inbound_connections: usize,

    #[serde(default = "default_max_outbound_connections")]
    pub max_outbound_connections: usize,

    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: usize,

    #[serde(default = "default_handshake_timeout_ms")]
    pub handshake_timeout_ms: u64,

    #[serde(default = "default_max_inflight_handshakes")]
    pub max_inflight_handshakes: usize,

    #[serde(default = "default_max_inflight_handshakes_per_ip")]
    pub max_inflight_handshakes_per_ip: usize,

    #[serde(default)]
    pub rate: P2pRateLimitsConfig,

    #[serde(default)]
    pub violations: P2pViolationsConfig,
}

impl Default for P2pLimitsConfig {
    fn default() -> Self {
        Self::production_defaults()
    }
}

impl P2pLimitsConfig {
    pub fn production_defaults() -> Self {
        Self {
            max_inbound_connections: default_max_inbound_connections(),
            max_outbound_connections: default_max_outbound_connections(),
            max_connections_per_ip: default_max_connections_per_ip(),
            handshake_timeout_ms: default_handshake_timeout_ms(),
            max_inflight_handshakes: default_max_inflight_handshakes(),
            max_inflight_handshakes_per_ip: default_max_inflight_handshakes_per_ip(),
            rate: P2pRateLimitsConfig::default(),
            violations: P2pViolationsConfig::default(),
        }
    }

    pub fn handshake_limits(&self) -> crate::transport::limits::HandshakeLimitsConfig {
        crate::transport::limits::HandshakeLimitsConfig {
            max_inflight: self.max_inflight_handshakes,
            max_inflight_per_ip: self.max_inflight_handshakes_per_ip,
            timeout: std::time::Duration::from_millis(self.handshake_timeout_ms),
        }
    }
}

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

    #[serde(default = "default_snapshot_manifest_request_per_sec")]
    pub snapshot_manifest_request_per_sec: f64,

    #[serde(default = "default_snapshot_manifest_response_per_sec")]
    pub snapshot_manifest_response_per_sec: f64,

    #[serde(default = "default_snapshot_chunk_request_per_sec")]
    pub snapshot_chunk_request_per_sec: f64,

    #[serde(default = "default_snapshot_chunk_response_per_sec")]
    pub snapshot_chunk_response_per_sec: f64,

    #[serde(default = "default_block_range_request_per_sec")]
    pub block_range_request_per_sec: f64,

    #[serde(default = "default_block_range_response_per_sec")]
    pub block_range_response_per_sec: f64,

    #[serde(default = "default_equivocation_evidence_per_sec")]
    pub equivocation_evidence_per_sec: f64,
    #[serde(default = "default_bytes_per_sec")]
    pub bytes_per_sec: f64,

    #[serde(default = "default_outbound_bytes_per_sec")]
    pub outbound_bytes_per_sec: f64,

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
    512
}
fn default_max_outbound_connections() -> usize {
    64
}
fn default_max_connections_per_ip() -> usize {
    8
}

fn default_handshake_timeout_ms() -> u64 {
    10_000
}
fn default_max_inflight_handshakes() -> usize {
    256
}
fn default_max_inflight_handshakes_per_ip() -> usize {
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

#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct OverlayConfig {
    #[serde(default)]
    pub mode: OverlayMode,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bootstrap_addrs: Vec<SocketAddr>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_peers: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OverlayMode {
    #[default]
    Libp2p,
}

#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct UiConfig {
    #[serde(default)]
    pub output_format: OutputFormat,
}

pub fn load(path: &Path) -> anyhow::Result<Config> {
    let text = std::fs::read_to_string(path)?;
    let config: Config = toml::from_str(&text)?;
    Ok(config)
}

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
    pub fn validate(&self, self_id: &NodeId) -> anyhow::Result<()> {
        for (idx, peer) in self.peers.iter().enumerate() {
            let Some(raw) = peer.node_id.as_deref() else {
                if peer.private || peer.persistent {
                    let flag = if peer.private {
                        "private"
                    } else {
                        "persistent"
                    };
                    anyhow::bail!(
                        "[[peers]][{idx}] (addr = {}) sets `{flag} = true` but has no \
                         `node_id` — private/persistent peers are identified by their \
                         NodeId in gossip and connection admission; add a `node_id`.",
                        peer.addr,
                    );
                }
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

        if let Some(admin_addr) = self.api.admin.listen_addr {
            let token = self.api.admin.resolve_auth_token()?;
            if !admin_addr.ip().is_loopback() && token.is_none() {
                warn!(
                    "[api.admin].listen_addr = {admin_addr} is not loopback and no \
                     auth_token/auth_token_env is set — the privileged admin + mempool \
                     API would be reachable off-box without authentication. Bind it to a \
                     trusted interface or set an auth token."
                );
            }
        }
        Ok(())
    }

    pub fn preflight_validate(&self) -> anyhow::Result<()> {
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

fn decode_hex_array<const N: usize>(s: &str) -> anyhow::Result<[u8; N]> {
    let bytes = hex::decode(s).map_err(|e| anyhow::anyhow!("hex decode: {e}"))?;
    if bytes.len() != N {
        anyhow::bail!("expected {N} bytes, got {}", bytes.len());
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

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

pub fn resolve_validator_identity(node: &NodeConfig) -> Option<IdentityConfig> {
    node.validator_identity.clone()
}

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

pub fn resolve_bls_validator_identity(node: &NodeConfig) -> Option<BlsIdentityConfig> {
    node.bls_validator_identity.clone()
}

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
