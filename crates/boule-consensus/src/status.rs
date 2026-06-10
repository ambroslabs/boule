use serde::{Deserialize, Serialize};

use super::{Height, View};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedStatus {
    pub view: View,
    pub height: Height,

    pub block_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QcStatus {
    pub view: View,
    pub height: Option<Height>,

    pub block_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoteBucketStatus {
    pub view: View,

    pub block_hash: String,
    pub signers: usize,
    pub quorum: usize,

    #[serde(default)]
    pub signer_weight: u128,

    #[serde(default)]
    pub quorum_weight: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeoutBucketStatus {
    pub view: View,
    pub signers: usize,
    pub quorum: usize,

    #[serde(default)]
    pub signer_weight: u128,

    #[serde(default)]
    pub quorum_weight: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParkedProposalStatus {
    pub block_hash: String,

    pub parent_hash: String,
    pub view: View,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CacheEvictionStatus {
    pub vote_buckets: u64,

    pub parked_proposals: u64,

    pub pending_blocks: u64,

    pub timeout_buckets: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BackpressureStatus {
    pub gossip_sink_overflow_total: u64,

    #[serde(default)]
    pub peer_outbound_overflow_total: u64,

    #[serde(default)]
    pub block_sync_serve_drops_total: u64,

    #[serde(default)]
    pub p2p_egress_byte_drops_total: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationEntry {
    pub v_eff: View,

    pub pubkey: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorKeyStatus {
    pub stable_id: String,

    pub active_pubkey: String,

    pub entries: Vec<RotationEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusStatus {
    pub node_id: String,

    pub self_role: String,
    pub current_view: View,
    pub last_voted_view: View,
    pub last_committed_height: Height,
    pub last_committed_view: View,
    pub locked: Option<LockedStatus>,
    pub high_qc: Option<QcStatus>,

    pub vote_buckets: Vec<VoteBucketStatus>,

    pub timeout_buckets: Vec<TimeoutBucketStatus>,
    pub parked_proposals: Vec<ParkedProposalStatus>,
    pub pending_blocks_count: usize,

    pub peers_connected: Vec<String>,

    pub validator_set: Vec<String>,

    #[serde(default)]
    pub validator_keys: Vec<ValidatorKeyStatus>,
    pub mempool_size: usize,

    #[serde(default)]
    pub cache_evictions: CacheEvictionStatus,

    #[serde(default)]
    pub dropped_commands: u64,

    #[serde(default)]
    pub equivocations_detected: u64,

    #[serde(default)]
    pub proposal_equivocations_detected: u64,

    #[serde(default)]
    pub equivocation_proofs_built: u64,

    #[serde(default)]
    pub equivocation_evidence_committed: u64,

    #[serde(default)]
    pub state_divergence_detected: u64,

    #[serde(default)]
    pub proposal_command_rejections: u64,

    #[serde(default)]
    pub backpressure: BackpressureStatus,

    #[serde(default)]
    pub delinquent_validators: Vec<String>,

    #[serde(default)]
    pub cluster_participation_permille: Option<u64>,

    #[serde(default)]
    pub el_behind: bool,

    #[serde(default)]
    pub el_behind_height_gap: u64,
}

pub const BUCKET_VIEW_WINDOW: u64 = 4;
