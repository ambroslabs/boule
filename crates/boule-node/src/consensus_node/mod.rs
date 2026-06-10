use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use tokio::sync::{broadcast, mpsc, oneshot, watch};

use std::time::Duration;

use boule_consensus::api::CommitNotifier;
use boule_consensus::block_sync_retry_timer::{
    BlockSyncRetryTimer, DEFAULT_INITIAL_DELAY as BLOCK_SYNC_RETRY_INITIAL_DELAY,
    DEFAULT_MAX_DELAY as BLOCK_SYNC_RETRY_MAX_DELAY, next_delay as next_retry_delay,
};
use boule_consensus::dispatch::{self, Outbound};
use boule_consensus::endpoint_registry::EndpointRegistry;
use boule_consensus::hotstuff::qc::{ConsensusMsg, VerifiedQc, genesis_qc_bls};
use boule_consensus::hotstuff::step::{HotStuffCore, StateUpdate};
use boule_consensus::hotstuff::{HotStuffState, QuorumCertificate};
use boule_consensus::limits::CacheEvictionCounters;
use boule_consensus::liveness_tracker::LivenessTracker;
use boule_consensus::node_role::NodeRole;
use boule_consensus::operator_key_history::OperatorKeyHistory;
use boule_consensus::pacemaker::Event as PacemakerEvent;
use boule_consensus::pacemaker::Pacemaker;
use boule_consensus::pacemaker::leader::WeightedAccumulatorSelector;
use boule_consensus::pacemaker::timeout::ExponentialBackoff;
use boule_consensus::rate_limit::MessageRateLimiter as RateLimiter;
use boule_consensus::replication::application::{Application, ValidatorEffect, ValidatorUpdate};
use boule_consensus::replication::block::BlockHash;
use boule_consensus::replication::mempool::Mempool;
use boule_consensus::status::ConsensusStatus;
use boule_consensus::validator_history::ValidatorSetHistory;
use boule_consensus::validator_key_history::ValidatorKeyHistory;
use boule_consensus::validator_set::{ValidatorId, ValidatorSet};
use boule_consensus::view_timer::ViewTimer;
use boule_consensus::{Height, View};
use boule_core::crypto::signed::{ChainId, Signer};
use boule_core::identity::NodeId;
use boule_core::identity::node_id_to_base58;
use boule_core::storage::{Storage, Wal};
use boule_core::transport::overlay::ProtocolEvent;
use boule_core::transport::overlay::{Broadcaster, Discovery, DiscoveryEvent};

mod action_interpreter;
mod app_context;
mod app_reconfig;
mod block_sync;
mod commit;
mod config;
mod endpoint_apply;
mod equivocation;
mod evidence_apply;
mod param_apply;
mod persistence;
mod reconfig_apply;
mod rotation_apply;
mod snapshot_io;
mod status;
mod timeout_bucket;

mod uninitialized_app;

pub use boule_consensus::wire::{
    BLOCK_RANGE_RESPONSE_MAX_BLOCKS, BlockRangeResponsePayload, BlockResponsePayload,
    MAX_FRAME_BYTES, PROTOCOL_ID, WireMessage,
};
pub use config::NodeConfigForConsensus;
pub use persistence::{
    LastCommitted, RECENT_QC_CACHE_CAPACITY, STORAGE_KEY_BLOCK_PREFIX, STORAGE_KEY_BLS_KEY_HISTORY,
    STORAGE_KEY_COMMITTED_EVIDENCE, STORAGE_KEY_ENDPOINT_REGISTRY, STORAGE_KEY_HEIGHT_PREFIX,
    STORAGE_KEY_HIGH_QC, STORAGE_KEY_LAST_COMMITTED, STORAGE_KEY_LAST_TIMEOUT_VOTE,
    STORAGE_KEY_LAST_VOTED_VIEW, STORAGE_KEY_LOCKED, STORAGE_KEY_OPERATOR_KEY_HISTORY,
    STORAGE_KEY_PARAM_HISTORY, STORAGE_KEY_PROPOSED_IN_VIEW, STORAGE_KEY_VALIDATOR_HISTORY,
    STORAGE_KEY_VALIDATOR_KEY_HISTORY, block_storage_key, decode_block, decode_height_storage_key,
    decode_high_qc, decode_last_committed, decode_last_timeout_vote, decode_locked,
    decode_proposed_in_view, decode_voted_view, encode_block, encode_high_qc,
    encode_last_committed, encode_last_timeout_vote, encode_locked, encode_proposed_in_view,
    encode_voted_view, height_storage_key, load_block_from_storage, load_block_range_from_storage,
    recover_state,
};

use persistence::RecentQcCache;
use timeout_bucket::TimeoutBucket;

pub const TRACE_TARGET: &str = "boule_core::consensus";

const EL_CATCHUP_LIVE_GAP_THRESHOLD: u64 = 16;

const EL_CATCHUP_TICK: Duration = Duration::from_secs(2);

const EL_BEHIND_READY_THRESHOLD: u64 = 32;

const EL_BEHIND_SUSTAIN: u32 = 3;

fn el_behind_next(prev_degraded: bool, prev_sustain: u32, gap: u64) -> (bool, u32) {
    let over = gap >= EL_BEHIND_READY_THRESHOLD;
    if over == prev_degraded {
        (prev_degraded, 0)
    } else {
        let sustain = prev_sustain + 1;
        if sustain >= EL_BEHIND_SUSTAIN {
            (over, 0)
        } else {
            (prev_degraded, sustain)
        }
    }
}

pub(super) fn msg_kind(msg: &ConsensusMsg) -> &'static str {
    match msg {
        ConsensusMsg::Proposal(_) => "Proposal",
        ConsensusMsg::Vote(_) => "Vote",
        ConsensusMsg::NewView(_) => "NewView",
    }
}

pub(super) fn update_kind(u: &StateUpdate) -> &'static str {
    match u {
        StateUpdate::VotedInView { .. } => "VotedInView",
        StateUpdate::Locked(_) => "Locked",
        StateUpdate::HighQc(_) => "HighQc",
        StateUpdate::ProposedInView { .. } => "ProposedInView",
    }
}

pub(super) fn pacemaker_event_kind(ev: &PacemakerEvent) -> &'static str {
    match ev {
        PacemakerEvent::OnQc(_) => "OnQc",
        PacemakerEvent::OnTimeoutCert(_) => "OnTimeoutCert",
        PacemakerEvent::OnTimeout(_) => "OnTimeout",
        PacemakerEvent::OnProposalReceived(_) => "OnProposalReceived",
        PacemakerEvent::OnRoundSync { .. } => "OnRoundSync",
    }
}

pub(super) async fn send_outbound(
    broadcaster: &dyn Broadcaster,
    rate_limiter: Option<&RateLimiter>,
    _peers_connected: &HashSet<NodeId>,
    out: Outbound,
) {
    match out {
        Outbound::Broadcast(payload) => broadcaster.broadcast(payload).await,
        Outbound::SendTo { to, payload } => {
            if let Some(limiter) = rate_limiter
                && matches!(
                    limiter.admit_outbound(to, payload.len()),
                    boule_core::transport::limits::Decision::Drop
                )
            {
                tracing::warn!(
                    target: TRACE_TARGET,
                    peer = %node_id_to_base58(&to),
                    bytes = payload.len(),
                    "p2p_egress_byte_drop",
                );
                return;
            }
            broadcaster.send_to(to, payload).await
        }
    }
}

pub struct ConsensusNode {
    pub self_id: NodeId,

    signing_view: Arc<AtomicU64>,

    pub core: HotStuffCore,

    pub pacemaker: Pacemaker,

    pub mempool: Arc<dyn Mempool>,

    pub storage: Arc<dyn Storage>,

    pub wal: Arc<dyn Wal>,

    pub validator_set: ValidatorSet,

    pub role: NodeRole,

    pub validator_history: ValidatorSetHistory,

    pub validator_key_history: ValidatorKeyHistory,

    pub operator_key_history: OperatorKeyHistory,

    pub bls_key_history: Option<boule_consensus::bls_key_history::BlsKeyHistory>,

    pub bls_signer: Option<
        Arc<
            dyn boule_core::crypto::signed::PartialSigner<
                    boule_core::crypto::sig_scheme::BlsAggregated,
                >,
        >,
    >,

    pub timeout_policy: Arc<ExponentialBackoff>,

    timeout_buckets: HashMap<View, TimeoutBucket>,

    timeout_buckets_capacity: usize,

    eviction_counters: CacheEvictionCounters,

    commit_notifier: Option<Arc<dyn CommitNotifier>>,

    gossip_sink_overflows: Option<Arc<AtomicU64>>,

    peer_outbound_overflows: Option<Arc<AtomicU64>>,

    pub(super) block_sync_credit: Arc<block_sync::BlockSyncCreditWindow>,

    block_sync_range_inflight: HashMap<(Height, Height), BlockSyncRangeInflight>,

    peers_connected: HashSet<NodeId>,

    block_sync_neighbour_rr: u64,

    peer_heights: HashMap<NodeId, Height>,

    last_committed_height: Arc<AtomicU64>,

    app: Arc<dyn Application>,

    loopback_stack: Vec<boule_consensus::dispatch::Dispatch>,

    draining_loopback: bool,

    min_block_interval: Duration,

    param_history: boule_consensus::consensus_params::ConsensusParamHistory,

    weak_subjectivity_checkpoint: Option<(Height, BlockHash)>,

    staged_validator_updates: Vec<ValidatorUpdate>,

    staged_effects: Vec<ValidatorEffect>,

    staged_governance_reconfig: Option<boule_consensus::reconfig::ReconfigCommand>,

    last_proposal_at: Option<tokio::time::Instant>,

    stashed_proposal: Option<ConsensusMsg>,

    dropped_commands: Arc<AtomicU64>,

    equivocations_detected: Arc<AtomicU64>,

    proposal_equivocations_detected: Arc<AtomicU64>,

    seen_votes: equivocation::SeenVotes,

    seen_proposals: equivocation::SeenProposals,

    equivocation_proofs_built: u64,

    committed_evidence: std::collections::BTreeMap<ValidatorId, View>,

    endpoint_registry: EndpointRegistry,

    liveness_tracker: LivenessTracker,

    evidence_minted: std::collections::HashSet<ValidatorId>,

    state_divergence_detected: Arc<AtomicU64>,

    vote_divergence_check_enabled: bool,

    proposal_command_rejections: Arc<AtomicU64>,

    last_committed_view: View,

    status_tx: Option<watch::Sender<Arc<ConsensusStatus>>>,

    rate_limiter: Option<Arc<RateLimiter>>,

    disconnect_via: Option<Arc<dyn Discovery>>,

    snapshot_policy: boule_consensus::replication::snapshot::SnapshotPolicy,

    min_v_eff_delay: View,

    recent_qcs: Mutex<RecentQcCache>,

    pub(super) block_retention_window: u64,

    snapshot_sync: boule_consensus::snapshot_sync::SnapshotSync,

    chain_id: ChainId,

    el_behind: bool,

    el_behind_height_gap: u64,

    el_behind_sustain: u32,
}

#[derive(Debug, Clone)]
pub(super) struct BlockSyncRangeInflight {
    pub(super) peer: NodeId,

    pub(super) attempts: u32,

    pub(super) last_asked_at: tokio::time::Instant,
}

pub(super) fn weak_subjectivity_violation(
    checkpoint: Option<(Height, BlockHash)>,
    height: Height,
    block_hash: BlockHash,
) -> Option<String> {
    let (cp_height, cp_hash) = checkpoint?;
    if height != cp_height || block_hash == cp_hash {
        return None;
    }
    Some(format!(
        "block at the weak-subjectivity checkpoint height {} hashes to {} but the configured \
         checkpoint is {}; this node is on a chain that disagrees with the operator-trusted \
         anchor",
        cp_height.0,
        hex::encode(block_hash),
        hex::encode(cp_hash),
    ))
}

fn role_for(self_id: NodeId, validator_set: &ValidatorSet) -> NodeRole {
    let self_as_validator = ValidatorId::from_genesis_pubkey(self_id);
    if validator_set.contains(&self_as_validator) {
        NodeRole::Validator
    } else {
        NodeRole::Full
    }
}

impl ConsensusNode {
    pub fn new(
        self_id: NodeId,
        config: NodeConfigForConsensus,
        mempool: Arc<dyn Mempool>,
        storage: Arc<dyn Storage>,
        wal: Arc<dyn Wal>,
    ) -> Self {
        let validator_set = Arc::new(config.validator_set.clone());

        let timeout_policy = Arc::new(ExponentialBackoff::new(
            config.timeout_base,
            config.timeout_max,
        ));

        let selector = Arc::new(WeightedAccumulatorSelector::from_genesis_set(Arc::clone(
            &validator_set,
        )));

        let pacemaker = Pacemaker::new(
            self_id,
            Arc::clone(&selector) as _,
            Arc::clone(&timeout_policy) as _,
        );

        let last_committed_height = Arc::new(AtomicU64::new(0));
        let dropped_commands = Arc::new(AtomicU64::new(0));

        let app: Arc<dyn Application> = Arc::new(uninitialized_app::UninitializedApplication);

        let validator_set_len = config.validator_set.len();

        let chain_id = ChainId::from_genesis_hash(config.genesis.hash());

        let boot_qc = genesis_qc_bls(&config.genesis, validator_set_len);
        let mut hs_state = HotStuffState::new(config.validator_set.clone(), config.genesis);

        hs_state.high_qc = Some(VerifiedQc::unchecked(boot_qc));
        let eviction_counters = CacheEvictionCounters::default();
        let core =
            HotStuffCore::with_limits(self_id, hs_state, config.limits, eviction_counters.clone());

        let validator_history = ValidatorSetHistory::from_genesis(config.validator_set.clone());
        let validator_key_history = ValidatorKeyHistory::new(config.validator_set.iter().copied());

        let operator_key_history = OperatorKeyHistory::with_genesis(
            config
                .operator_keys
                .iter()
                .map(|(v, op)| (ValidatorId::from_genesis_pubkey(*v), *op)),
        );
        let role = role_for(self_id, &config.validator_set);
        Self {
            self_id,
            core,
            pacemaker,
            mempool,
            storage,
            wal,
            validator_set: config.validator_set,
            role,
            validator_history,
            signing_view: Arc::new(AtomicU64::new(0)),
            validator_key_history,
            operator_key_history,
            bls_key_history: None,
            bls_signer: None,
            timeout_policy,
            timeout_buckets: HashMap::new(),
            timeout_buckets_capacity: config.limits.timeout_buckets_capacity,
            eviction_counters,
            commit_notifier: None,
            gossip_sink_overflows: None,
            peer_outbound_overflows: None,
            block_sync_credit: Arc::new(block_sync::BlockSyncCreditWindow::new()),
            block_sync_range_inflight: HashMap::new(),
            peers_connected: HashSet::new(),
            block_sync_neighbour_rr: 0,
            peer_heights: HashMap::new(),
            last_committed_height,
            app,
            loopback_stack: Vec::new(),
            draining_loopback: false,
            min_block_interval: config.min_block_interval,
            param_history: boule_consensus::consensus_params::ConsensusParamHistory::new(
                boule_consensus::consensus_params::ConsensusParams {
                    min_block_interval_ms: config.min_block_interval.as_millis() as u64,
                },
            ),
            weak_subjectivity_checkpoint: config.weak_subjectivity_checkpoint,
            staged_validator_updates: Vec::new(),
            staged_effects: Vec::new(),
            staged_governance_reconfig: None,
            last_proposal_at: None,
            stashed_proposal: None,
            dropped_commands,
            equivocations_detected: Arc::new(AtomicU64::new(0)),
            proposal_equivocations_detected: Arc::new(AtomicU64::new(0)),
            seen_votes: equivocation::SeenVotes::new(),
            seen_proposals: equivocation::SeenProposals::new(),
            equivocation_proofs_built: 0,
            committed_evidence: std::collections::BTreeMap::new(),
            endpoint_registry: EndpointRegistry::new(config.max_endpoint_list_length),
            liveness_tracker: LivenessTracker::default(),
            evidence_minted: std::collections::HashSet::new(),
            state_divergence_detected: Arc::new(AtomicU64::new(0)),
            vote_divergence_check_enabled: true,
            proposal_command_rejections: Arc::new(AtomicU64::new(0)),
            last_committed_view: View::ZERO,
            status_tx: None,
            rate_limiter: None,
            disconnect_via: None,
            snapshot_policy: config.snapshot_policy,
            min_v_eff_delay: config.min_v_eff_delay,
            recent_qcs: Mutex::new(RecentQcCache::default()),
            block_retention_window: config.block_retention_window,
            snapshot_sync: boule_consensus::snapshot_sync::SnapshotSync::new(
                config.snapshot_policy,
            ),
            chain_id,
            el_behind: false,
            el_behind_height_gap: 0,
            el_behind_sustain: 0,
        }
    }

    pub fn with_bls_key_history(
        mut self,
        bls_key_history: boule_consensus::bls_key_history::BlsKeyHistory,
    ) -> Self {
        self.bls_key_history = Some(bls_key_history);
        self
    }

    pub fn with_bls_signer(
        mut self,
        bls_signer: Arc<
            dyn boule_core::crypto::signed::PartialSigner<
                    boule_core::crypto::sig_scheme::BlsAggregated,
                >,
        >,
    ) -> Self {
        self.bls_signer = Some(bls_signer);
        self
    }

    pub fn with_commit_notifier(mut self, notifier: Arc<dyn CommitNotifier>) -> Self {
        self.commit_notifier = Some(notifier);
        self
    }

    pub fn with_application(mut self, app: Arc<dyn Application>) -> Self {
        let caps = app.capabilities();
        tracing::info!(
            target: TRACE_TARGET,
            capabilities = ?caps,
            "application_wired",
        );
        self.app = app;
        self
    }

    pub fn with_gossip_sink_overflow_counter(mut self, counter: Arc<AtomicU64>) -> Self {
        self.gossip_sink_overflows = Some(counter);
        self
    }

    pub fn with_peer_outbound_overflow_counter(mut self, counter: Arc<AtomicU64>) -> Self {
        self.peer_outbound_overflows = Some(counter);
        self
    }

    pub fn with_genesis_qc(mut self, qc: QuorumCertificate) -> Self {
        self.core.set_high_qc(VerifiedQc::unchecked(qc));
        self
    }

    pub fn with_rate_limiter(mut self, limiter: Arc<RateLimiter>) -> Self {
        self.rate_limiter = Some(limiter);
        self
    }

    pub fn with_status_publisher(mut self, tx: watch::Sender<Arc<ConsensusStatus>>) -> Self {
        self.status_tx = Some(tx);
        self
    }

    pub fn equivocations_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.equivocations_detected)
    }

    pub fn proposal_equivocations_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.proposal_equivocations_detected)
    }

    pub fn state_divergence_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.state_divergence_detected)
    }

    pub fn proposal_command_rejections_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.proposal_command_rejections)
    }

    pub fn eviction_counters(&self) -> &CacheEvictionCounters {
        &self.eviction_counters
    }

    fn publish_status(&self) {
        if let Some(tx) = &self.status_tx {
            let _ = tx.send_replace(Arc::new(self.build_status()));
        }
    }

    pub fn recover(
        self_id: NodeId,
        config: NodeConfigForConsensus,
        mempool: Arc<dyn Mempool>,
        storage: Arc<dyn Storage>,
        wal: Arc<dyn Wal>,
    ) -> anyhow::Result<Self> {
        use anyhow::Context;

        let hs_state = recover_state(
            storage.as_ref(),
            config.validator_set.clone(),
            config.genesis.clone(),
        )?;

        let last_committed = match storage
            .get(STORAGE_KEY_LAST_COMMITTED)
            .context("read last_committed from storage")?
        {
            Some(raw) => decode_last_committed(&raw)?,
            None => LastCommitted {
                height: Height::ZERO,
                view: View::ZERO,
                last_committed_hash: [0u8; 32],
            },
        };

        let validator_history = match storage
            .get(STORAGE_KEY_VALIDATOR_HISTORY)
            .context("read validator_history from storage")?
        {
            Some(raw) => {
                let persisted: boule_consensus::validator_history::PersistedValidatorHistory =
                    postcard::from_bytes(&raw).context("decode persisted validator_history")?;
                ValidatorSetHistory::from_persisted(persisted)
                    .context("rebuild ValidatorSetHistory from persisted form")?
            }
            None => ValidatorSetHistory::from_genesis(config.validator_set.clone()),
        };

        let active_set = (*validator_history.current_set()).clone();
        let timeout_policy = Arc::new(ExponentialBackoff::new(
            config.timeout_base,
            config.timeout_max,
        ));

        let selector = Arc::new(WeightedAccumulatorSelector::new(Arc::new(
            validator_history.clone(),
        )));
        let pacemaker = Pacemaker::new(
            self_id,
            Arc::clone(&selector) as _,
            Arc::clone(&timeout_policy) as _,
        );

        let last_committed_height = Arc::new(AtomicU64::new(last_committed.height.0));
        let dropped_commands = Arc::new(AtomicU64::new(0));

        let app: Arc<dyn Application> = Arc::new(uninitialized_app::UninitializedApplication);

        let proposed_in_view = match storage
            .get(STORAGE_KEY_PROPOSED_IN_VIEW)
            .context("read proposed_in_view from storage")?
        {
            Some(raw) => decode_proposed_in_view(&raw)?,
            None => View::ZERO,
        };
        let eviction_counters = CacheEvictionCounters::default();
        let mut core =
            HotStuffCore::with_limits(self_id, hs_state, config.limits, eviction_counters.clone())
                .with_proposed_in_view(proposed_in_view);

        for (v_eff, set) in validator_history.iter() {
            if v_eff == View::ZERO {
                continue;
            }
            core.insert_validator_boundary(v_eff, (**set).clone())
                .with_context(|| format!("replay validator boundary at v_eff = {v_eff}"))?;
        }

        let validator_key_history = match storage
            .get(STORAGE_KEY_VALIDATOR_KEY_HISTORY)
            .context("read validator_key_history from storage")?
        {
            Some(raw) => {
                let persisted: boule_consensus::validator_key_history::PersistedValidatorKeyHistory =
                    postcard::from_bytes(&raw)
                        .context("decode persisted validator_key_history")?;
                ValidatorKeyHistory::from_persisted(persisted)
                    .context("rebuild ValidatorKeyHistory from persisted form")?
            }
            None => ValidatorKeyHistory::from_set_history(&validator_history),
        };

        let operator_key_history = match storage
            .get(STORAGE_KEY_OPERATOR_KEY_HISTORY)
            .context("read operator_key_history from storage")?
        {
            Some(raw) => {
                let persisted: boule_consensus::operator_key_history::PersistedOperatorKeyHistory =
                    postcard::from_bytes(&raw).context("decode persisted operator_key_history")?;
                OperatorKeyHistory::from_persisted(persisted)
                    .context("rebuild OperatorKeyHistory from persisted form")?
            }
            None => OperatorKeyHistory::with_genesis(
                config
                    .operator_keys
                    .iter()
                    .map(|(v, op)| (ValidatorId::from_genesis_pubkey(*v), *op)),
            ),
        };

        let chain_id = ChainId::from_genesis_hash(config.genesis.hash());

        let committed_evidence = Self::load_committed_evidence(storage.as_ref());

        let endpoint_registry =
            Self::load_endpoint_registry(storage.as_ref(), config.max_endpoint_list_length);

        let genesis_params = boule_consensus::consensus_params::ConsensusParams {
            min_block_interval_ms: config.min_block_interval.as_millis() as u64,
        };
        let param_history = match storage
            .get(STORAGE_KEY_PARAM_HISTORY)
            .context("read param_history from storage")?
        {
            Some(raw) => {
                match postcard::from_bytes::<
                    boule_consensus::consensus_params::PersistedConsensusParamHistory,
                >(&raw)
                .map_err(anyhow::Error::from)
                .and_then(|p| {
                    boule_consensus::consensus_params::ConsensusParamHistory::from_persisted(p)
                }) {
                    Ok(h) => h,

                    Err(e) => {
                        tracing::warn!(
                            target: TRACE_TARGET,
                            error = %e,
                            "param_history_decode_failed_falling_back_to_genesis",
                        );
                        boule_consensus::consensus_params::ConsensusParamHistory::new(
                            genesis_params,
                        )
                    }
                }
            }
            None => boule_consensus::consensus_params::ConsensusParamHistory::new(genesis_params),
        };

        let min_block_interval = param_history.at(last_committed.view).min_block_interval();

        let role = role_for(
            self_id,
            validator_history.set_at(View::ZERO).for_view(View::ZERO),
        );
        Ok(Self {
            self_id,
            core,
            pacemaker,
            mempool,
            storage,
            wal,
            validator_set: active_set,
            role,
            validator_history,
            signing_view: Arc::new(AtomicU64::new(0)),
            validator_key_history,
            operator_key_history,
            bls_key_history: None,
            bls_signer: None,
            timeout_policy,
            timeout_buckets: HashMap::new(),
            timeout_buckets_capacity: config.limits.timeout_buckets_capacity,
            eviction_counters,
            commit_notifier: None,
            gossip_sink_overflows: None,
            peer_outbound_overflows: None,
            block_sync_credit: Arc::new(block_sync::BlockSyncCreditWindow::new()),
            block_sync_range_inflight: HashMap::new(),
            peers_connected: HashSet::new(),
            block_sync_neighbour_rr: 0,
            peer_heights: HashMap::new(),
            last_committed_height,
            app,
            loopback_stack: Vec::new(),
            draining_loopback: false,
            min_block_interval,
            param_history,
            weak_subjectivity_checkpoint: config.weak_subjectivity_checkpoint,
            staged_validator_updates: Vec::new(),
            staged_effects: Vec::new(),
            staged_governance_reconfig: None,
            last_proposal_at: None,
            stashed_proposal: None,
            dropped_commands,
            equivocations_detected: Arc::new(AtomicU64::new(0)),
            proposal_equivocations_detected: Arc::new(AtomicU64::new(0)),
            seen_votes: equivocation::SeenVotes::new(),
            seen_proposals: equivocation::SeenProposals::new(),
            equivocation_proofs_built: 0,
            committed_evidence,
            endpoint_registry,
            liveness_tracker: LivenessTracker::default(),
            evidence_minted: std::collections::HashSet::new(),
            state_divergence_detected: Arc::new(AtomicU64::new(0)),
            vote_divergence_check_enabled: true,
            proposal_command_rejections: Arc::new(AtomicU64::new(0)),
            last_committed_view: last_committed.view,
            status_tx: None,
            rate_limiter: None,
            disconnect_via: None,
            snapshot_policy: config.snapshot_policy,
            min_v_eff_delay: config.min_v_eff_delay,
            recent_qcs: Mutex::new(RecentQcCache::default()),
            block_retention_window: config.block_retention_window,
            snapshot_sync: boule_consensus::snapshot_sync::SnapshotSync::new(
                config.snapshot_policy,
            ),
            chain_id,
            el_behind: false,
            el_behind_height_gap: 0,
            el_behind_sustain: 0,
        })
    }

    pub fn current_view(&self) -> View {
        self.pacemaker.current_view()
    }

    pub fn signing_view_handle(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.signing_view)
    }

    fn verify_weak_subjectivity_on_startup(&self) {
        let Some((cp_height, _)) = self.weak_subjectivity_checkpoint else {
            return;
        };
        if self.last_committed_height.load(Ordering::Relaxed) < cp_height.0 {
            return;
        }
        let stored = self.storage.get(&height_storage_key(cp_height));
        let hash: BlockHash = match stored {
            Ok(Some(raw)) if raw.len() == 32 => {
                let mut h = [0u8; 32];
                h.copy_from_slice(&raw);
                h
            }
            _ => {
                tracing::warn!(
                    target: TRACE_TARGET,
                    checkpoint_height = cp_height.0,
                    "weak-subjectivity checkpoint height is not in the durable block index \
                     (pruned below retention?); skipping the startup re-check — it was enforced \
                     at commit time",
                );
                return;
            }
        };

        if let Some(msg) =
            weak_subjectivity_violation(self.weak_subjectivity_checkpoint, cp_height, hash)
        {
            panic!("consensus: {msg}; halting on startup (#642)");
        }
        tracing::info!(
            target: TRACE_TARGET,
            checkpoint_height = cp_height.0,
            "weak-subjectivity checkpoint verified against the committed chain",
        );
    }

    async fn el_frontier(&self) -> Option<u64> {
        let executed = self.app.executed_height()?;
        let frontier = match self.app.el_head().await {
            Some(head) if head.0 < executed.0 => {
                tracing::warn!(
                    target: TRACE_TARGET,
                    tracked = executed.0,
                    el_head = head.0,
                    "el_catchup: reth's actual head is below the tracked frontier \
                     (unclean crash?); replaying from the EL's real head",
                );
                head.0
            }
            _ => executed.0,
        };
        Some(frontier)
    }

    async fn el_catchup_replay(&self, min_gap: u64) {
        let committed = self.last_committed_height.load(Ordering::Relaxed);

        let Some(frontier) = self.el_frontier().await else {
            return;
        };
        if committed == 0 || committed.saturating_sub(frontier) < min_gap.max(1) {
            return;
        }
        let behind = committed - frontier;

        let tip_hash: BlockHash = match self.storage.get(&height_storage_key(Height(committed))) {
            Ok(Some(raw)) if raw.len() == 32 => {
                let mut h = [0u8; 32];
                h.copy_from_slice(&raw);
                h
            }
            _ => {
                tracing::warn!(
                    target: TRACE_TARGET,
                    executed = frontier,
                    committed,
                    "el_catchup: no committed tip hash at the committed height; skipping EL replay",
                );
                return;
            }
        };
        let gap = match load_block_range_from_storage(
            &*self.storage,
            tip_hash,
            Height(frontier + 1),
            Height(committed),
            behind as usize,
        ) {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!(target: TRACE_TARGET, error = %e, "el_catchup: loading the gap range failed; skipping EL replay");
                return;
            }
        };
        if (gap.len() as u64) < behind {
            tracing::warn!(
                target: TRACE_TARGET,
                executed = frontier,
                committed,
                behind,
                retained = gap.len(),
                "el_catchup: execution layer is behind past the block-retention window; \
                 the committed gap is not fully stored, so it cannot be replayed from \
                 consensus. Handing off to the EL's devp2p self-sync from peers (#831).",
            );

            if let Some(tip) = gap.last() {
                if let Err(e) = self.app.el_devp2p_handoff(tip).await {
                    tracing::warn!(target: TRACE_TARGET, error = %e, "el_catchup: el_devp2p_handoff failed");
                }
            }
            return;
        }
        tracing::info!(
            target: TRACE_TARGET,
            executed = frontier,
            committed,
            blocks = gap.len(),
            "el_catchup: replaying committed payloads to catch the execution layer up",
        );
        for block in &gap {
            let ctx = self.commit_app_context(block);
            if let Err(e) = self.app.commit(&ctx, block).await {
                tracing::warn!(
                    target: TRACE_TARGET,
                    height = block.header.height.0,
                    error = %e,
                    "el_catchup: replaying a committed block failed; stopping replay",
                );
                break;
            }
        }
        let now = self.app.executed_height().map(|h| h.0).unwrap_or(committed);
        tracing::info!(
            target: TRACE_TARGET,
            executed = now,
            committed,
            "el_catchup: EL replay finished",
        );
    }

    pub async fn run(
        mut self,
        broadcaster: Arc<dyn Broadcaster>,
        discovery: Arc<dyn Discovery>,
        mut event_rx: mpsc::Receiver<ProtocolEvent>,
        signer: Arc<dyn Signer>,
        mut shutdown: oneshot::Receiver<()>,
    ) -> anyhow::Result<()> {
        let mut discovery_events = discovery.subscribe();

        self.peers_connected = discovery.known_peers().into_iter().collect();

        if self.rate_limiter.is_some() {
            self.disconnect_via = Some(Arc::clone(&discovery));
        }

        let (timer_tx, mut timer_rx) = mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        let (retry_timer_tx, mut retry_timer_rx) = mpsc::channel::<()>(4);
        let mut retry_timer = BlockSyncRetryTimer::new(retry_timer_tx);
        let mut retry_timer_delay: Option<Duration> = None;

        let (el_catchup_tx, mut el_catchup_rx) = mpsc::channel::<()>(1);
        let mut el_catchup_timer = BlockSyncRetryTimer::new(el_catchup_tx);

        tracing::info!(
            target: TRACE_TARGET,
            self_id = %node_id_to_base58(&self.self_id),
            last_committed_height = self.last_committed_height.load(Ordering::Relaxed),
            last_committed_view = self.last_committed_view.0,
            high_qc_view = ?self.core.state().high_qc.as_ref().map(|q| q.view().0),
            last_voted_view = self.core.state().last_voted_view.0,
            locked_view = ?self.core.state().locked.as_ref().map(|l| l.view.0),
            validator_set_size = self.validator_set.len(),
            "consensus_resumed",
        );

        self.verify_weak_subjectivity_on_startup();

        self.el_catchup_replay(1).await;

        el_catchup_timer.arm(EL_CATCHUP_TICK);

        self.publish_status();

        let boot_view = self
            .core
            .state()
            .high_qc
            .as_ref()
            .map(|qc| qc.view())
            .unwrap_or(View::ZERO)
            .max(self.core.state().last_voted_view);
        let boot_actions = self.step_pacemaker(PacemakerEvent::OnQc(boot_view));
        self.apply_pacemaker_actions(boot_actions, broadcaster.as_ref(), &mut view_timer, &signer)
            .await?;
        self.publish_status();

        loop {
            tokio::select! {
                biased;

                _ = &mut shutdown => break,

                Some(view) = timer_rx.recv() => {
                    let pm_actions = self.step_pacemaker(PacemakerEvent::OnTimeout(view));
                    self.apply_pacemaker_actions(pm_actions, broadcaster.as_ref(), &mut view_timer, &signer)
                        .await?;
                }

                () = tokio::time::sleep_until(
                    self.last_proposal_at
                        .map(|t| t + self.min_block_interval)
                        .unwrap_or_else(tokio::time::Instant::now),
                ), if self.stashed_proposal.is_some() => {
                    if let Some(msg) = self.stashed_proposal.take() {
                        self.broadcast_consensus_msg(msg, broadcaster.as_ref(), &mut view_timer, &signer)
                            .await?;
                    }
                }

                Some(()) = retry_timer_rx.recv() => {

                    let actions = self.core.step_block_sync_retry_tick();
                    self.apply_safety_actions(actions, broadcaster.as_ref(), &mut view_timer, &signer)
                        .await?;

                    self.maintain_block_sync_range_retry(
                        broadcaster.as_ref(),
                        BLOCK_SYNC_RETRY_INITIAL_DELAY,
                    )
                    .await?;
                }

                Some(()) = el_catchup_rx.recv() => {

                    self.el_catchup_replay(EL_CATCHUP_LIVE_GAP_THRESHOLD).await;

                    let committed = self.last_committed_height.load(Ordering::Relaxed);
                    let gap = match self.el_frontier().await {
                        Some(frontier) => committed.saturating_sub(frontier),

                        None => 0,
                    };
                    let was_behind = self.el_behind;
                    let (behind, sustain) =
                        el_behind_next(self.el_behind, self.el_behind_sustain, gap);
                    self.el_behind = behind;
                    self.el_behind_sustain = sustain;
                    self.el_behind_height_gap = gap;
                    if behind && !was_behind {

                        tracing::warn!(
                            target: TRACE_TARGET,
                            committed,
                            height_gap = gap,
                            threshold = EL_BEHIND_READY_THRESHOLD,
                            "el_behind: execution layer is persistently behind the \
                             committed frontier; this validator is a dead proposer \
                             (skips every leader view) and is now draining from /ready (#828)",
                        );
                    }
                    self.publish_status();

                    el_catchup_timer.arm(EL_CATCHUP_TICK);
                }

                disc = discovery_events.recv() => {
                    match disc {
                        Ok(DiscoveryEvent::PeerAdded(node_id)) => {
                            tracing::debug!("consensus: peer added {node_id:?}");
                            self.peers_connected.insert(node_id);

                            let actions = self.snapshot_sync.add_candidate(node_id);
                            self.apply_snapshot_sync_actions(
                                actions,
                                broadcaster.as_ref(),
                                &mut view_timer,
                                &signer,
                            )
                            .await?;
                        }
                        Ok(DiscoveryEvent::PeerRemoved(node_id)) => {
                            tracing::debug!("consensus: peer removed {node_id:?}");
                            self.peers_connected.remove(&node_id);

                            self.peer_heights.remove(&node_id);

                            let actions = self.snapshot_sync.on_peer_disconnected(node_id);
                            self.apply_snapshot_sync_actions(
                                actions,
                                broadcaster.as_ref(),
                                &mut view_timer,
                                &signer,
                            )
                            .await?;
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => {

                            self.peers_connected = discovery.known_peers().into_iter().collect();
                        }
                        Err(broadcast::error::RecvError::Closed) => {

                        }
                    }
                }

                Some(event) = event_rx.recv() => {
                    match event {
                        ProtocolEvent::Message { from, payload } => {

                            if !self.admit_inbound(from, &payload).await {
                                continue;
                            }

                            let qc_verification = dispatch::QcVerification::Verify {
                                bls_key_history: self.bls_key_history.as_ref(),
                                operator_key_history: Some(&self.operator_key_history),
                                min_v_eff_delay: self.min_v_eff_delay,
                                genesis_hash: self.core.state().genesis_hash,
                            };
                            match dispatch::ingress_with_qc_verification(
                                from,
                                &payload,
                                &self.validator_history,
                                &self.validator_key_history,
                                &qc_verification,
                                &self.chain_id,
                            ) {
                                Ok(dispatches) => {
                                    for d in dispatches {
                                        self.apply_dispatch(d, broadcaster.as_ref(), &mut view_timer, &signer)
                                            .await?;
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!("consensus: ingress rejected from {from:?}: {e}");
                                }
                            }
                        }

                        ProtocolEvent::PeerConnected { .. } => {}
                        ProtocolEvent::PeerDisconnected { node_id } => {
                            if let Some(limiter) = self.rate_limiter.as_ref() {
                                limiter.forget_peer(node_id);
                            }
                        }
                    }
                }

                else => break,
            }

            self.maintain_block_sync_retry_timer(&mut retry_timer, &mut retry_timer_delay);

            self.publish_status();
        }

        view_timer.cancel();
        retry_timer.cancel();
        Ok(())
    }

    fn maintain_block_sync_retry_timer(
        &self,
        retry_timer: &mut BlockSyncRetryTimer,
        retry_timer_delay: &mut Option<Duration>,
    ) {
        let any_inflight =
            self.core.has_any_block_sync_inflight() || !self.block_sync_range_inflight.is_empty();
        if any_inflight {
            if !retry_timer.is_armed() {
                let delay = next_retry_delay(
                    *retry_timer_delay,
                    BLOCK_SYNC_RETRY_INITIAL_DELAY,
                    BLOCK_SYNC_RETRY_MAX_DELAY,
                );
                retry_timer.arm(delay);
                *retry_timer_delay = Some(delay);
            }
        } else {
            retry_timer.cancel();
            *retry_timer_delay = None;
        }
    }
}
