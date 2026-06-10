use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use prometheus::{Encoder, Gauge, IntGauge, Registry, TextEncoder};
use tokio::sync::watch;

use boule_consensus::status::ConsensusStatus;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthView {
    pub consensus_enabled: bool,

    pub is_validator: bool,

    pub has_peers: bool,

    pub committed_progress: bool,

    pub healthy_view: bool,

    pub halted: bool,

    pub el_behind: bool,
}

const HEALTHY_VIEW_LAG: u64 = 8;

impl HealthView {
    pub fn from_status(status: &ConsensusStatus, peer_count: usize) -> Self {
        let is_validator = status.validator_set.iter().any(|v| v == &status.node_id);
        let committed_progress = status.last_committed_height.0 > 0;
        let lag = status
            .current_view
            .0
            .saturating_sub(status.last_committed_view.0);

        let healthy_view = !committed_progress || lag <= HEALTHY_VIEW_LAG;
        Self {
            consensus_enabled: true,
            is_validator,
            has_peers: peer_count > 0,
            committed_progress,
            healthy_view,
            halted: false,
            el_behind: status.el_behind,
        }
    }

    pub fn halted(mut self) -> Self {
        self.halted = true;
        self
    }

    pub fn gossip_only() -> Self {
        Self {
            consensus_enabled: false,
            is_validator: false,
            has_peers: false,
            committed_progress: false,
            healthy_view: true,
            halted: false,
            el_behind: false,
        }
    }

    pub fn is_ready(&self) -> bool {
        if self.halted {
            return false;
        }
        if !self.consensus_enabled {
            return true;
        }
        if !self.healthy_view || !self.committed_progress {
            return false;
        }
        if self.is_validator && !self.has_peers {
            return false;
        }

        if self.is_validator && self.el_behind {
            return false;
        }
        true
    }
}

pub fn render_prometheus(
    status: &ConsensusStatus,
    peer_count: usize,
    halted: bool,
) -> Result<String, prometheus::Error> {
    let reg = Registry::new();
    let mut health = HealthView::from_status(status, peer_count);
    if halted {
        health = health.halted();
    }

    let int_gauge = |name: &str, help: &str, val: i64| -> Result<(), prometheus::Error> {
        let g = IntGauge::new(name, help)?;
        g.set(val);
        reg.register(Box::new(g))
    };
    let bool_gauge = |name: &str, help: &str, val: bool| -> Result<(), prometheus::Error> {
        int_gauge(name, help, i64::from(val))
    };

    int_gauge(
        "boule_consensus_current_view",
        "Current HotStuff view number.",
        status.current_view.0 as i64,
    )?;
    int_gauge(
        "boule_consensus_committed_height",
        "Height of the last committed block.",
        status.last_committed_height.0 as i64,
    )?;
    int_gauge(
        "boule_consensus_committed_view",
        "View of the last committed block.",
        status.last_committed_view.0 as i64,
    )?;
    bool_gauge(
        "boule_consensus_is_validator",
        "1 if this node is in the active validator set, else 0.",
        health.is_validator,
    )?;
    int_gauge(
        "boule_consensus_validator_set_size",
        "Number of validators in the active set.",
        status.validator_set.len() as i64,
    )?;
    int_gauge(
        "boule_consensus_mempool_size",
        "Number of commands currently buffered in the mempool.",
        status.mempool_size as i64,
    )?;
    int_gauge(
        "boule_consensus_pending_blocks",
        "Number of blocks pending in the safety core.",
        status.pending_blocks_count as i64,
    )?;
    int_gauge(
        "boule_consensus_delinquent_validators",
        "Count of validators below the liveness participation floor (#540).",
        status.delinquent_validators.len() as i64,
    )?;

    if let Some(permille) = status.cluster_participation_permille {
        let g = Gauge::new(
            "boule_consensus_cluster_participation_ratio",
            "Cluster-wide mean credited participation over the liveness window (0..1).",
        )?;
        g.set(permille as f64 / 1000.0);
        reg.register(Box::new(g))?;
    }

    int_gauge(
        "boule_consensus_equivocations_detected",
        "Cumulative vote-equivocation incidents detected by the safety core.",
        status.equivocations_detected as i64,
    )?;
    int_gauge(
        "boule_consensus_proposal_equivocations_detected",
        "Cumulative proposal-equivocation incidents detected by the safety core.",
        status.proposal_equivocations_detected as i64,
    )?;
    int_gauge(
        "boule_consensus_state_divergence_detected",
        "Cumulative state-machine divergences detected at vote time.",
        status.state_divergence_detected as i64,
    )?;
    int_gauge(
        "boule_consensus_dropped_commands",
        "Cumulative commands the block builder dropped on apply error.",
        status.dropped_commands as i64,
    )?;

    int_gauge(
        "boule_backpressure_gossip_sink_overflow_total",
        "Cumulative gossip-sink drops on full per-peer queue.",
        status.backpressure.gossip_sink_overflow_total as i64,
    )?;
    int_gauge(
        "boule_backpressure_peer_outbound_overflow_total",
        "Cumulative per-peer outbound-frame drops on full write channel.",
        status.backpressure.peer_outbound_overflow_total as i64,
    )?;
    int_gauge(
        "boule_backpressure_p2p_egress_byte_drops_total",
        "Cumulative egress frames dropped by the per-peer byte-rate limiter.",
        status.backpressure.p2p_egress_byte_drops_total as i64,
    )?;

    int_gauge(
        "boule_p2p_peers_connected",
        "Number of peer connections the p2p manager currently holds.",
        peer_count as i64,
    )?;
    int_gauge(
        "boule_consensus_peers_connected",
        "Number of peers the consensus layer currently talks to.",
        status.peers_connected.len() as i64,
    )?;

    bool_gauge(
        "boule_node_ready",
        "1 if the node reports ready on /ready, else 0.",
        health.is_ready(),
    )?;

    bool_gauge(
        "boule_consensus_halted",
        "1 if the consensus task has halted (fail-stop), else 0.",
        health.halted,
    )?;

    bool_gauge(
        "boule_consensus_el_behind",
        "1 if this node's execution layer is persistently behind the committed frontier, else 0.",
        health.el_behind,
    )?;
    int_gauge(
        "boule_consensus_el_behind_height_gap",
        "Height gap (committed - EL frontier) at the most recent catch-up sample.",
        status.el_behind_height_gap as i64,
    )?;

    let mut buf = Vec::new();
    TextEncoder::new().encode(&reg.gather(), &mut buf)?;
    String::from_utf8(buf).map_err(|e| prometheus::Error::Msg(e.to_string()))
}

#[derive(Clone)]
pub struct ObservabilityState {
    pub status_rx: Option<watch::Receiver<Arc<ConsensusStatus>>>,

    pub peer_count: Arc<dyn PeerCount>,
}

pub trait PeerCount: Send + Sync {
    fn count(&self) -> futures_util::future::BoxFuture<'static, usize>;
}

pub fn router(state: ObservabilityState) -> Router {
    Router::new()
        .route("/metrics", get(metrics))
        .route("/health", get(health))
        .route("/ready", get(ready))
        .with_state(state)
}

async fn current_status(state: &ObservabilityState) -> Option<Arc<ConsensusStatus>> {
    state.status_rx.as_ref().map(|rx| rx.borrow().clone())
}

impl ObservabilityState {
    fn consensus_halted(&self) -> bool {
        match &self.status_rx {
            Some(rx) => rx.has_changed().is_err(),
            None => false,
        }
    }
}

async fn metrics(State(state): State<ObservabilityState>) -> impl IntoResponse {
    let peer_count = state.peer_count.count().await;
    let halted = state.consensus_halted();
    let body = match current_status(&state).await {
        Some(status) => render_prometheus(&status, peer_count, halted),

        None => render_prometheus(&gossip_only_status(peer_count), peer_count, halted),
    };
    match body {
        Ok(text) => (
            StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                "text/plain; version=0.0.4",
            )],
            text,
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("metrics encode error: {e}"),
        )
            .into_response(),
    }
}

async fn health(State(state): State<ObservabilityState>) -> impl IntoResponse {
    let enabled = state.status_rx.is_some();
    let halted = state.consensus_halted();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": if halted { "halted" } else { "ok" },
            "consensus_enabled": enabled,
            "halted": halted,
        })),
    )
}

async fn ready(State(state): State<ObservabilityState>) -> impl IntoResponse {
    let peer_count = state.peer_count.count().await;
    let halted = state.consensus_halted();
    let view = match current_status(&state).await {
        Some(status) => HealthView::from_status(&status, peer_count),
        None => HealthView::gossip_only(),
    };
    let view = if halted { view.halted() } else { view };
    let ready = view.is_ready();
    let code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        code,
        Json(serde_json::json!({
            "ready": ready,
            "halted": view.halted,
            "is_validator": view.is_validator,
            "has_peers": view.has_peers,
            "committed_progress": view.committed_progress,
            "healthy_view": view.healthy_view,
        })),
    )
}

fn gossip_only_status(_peer_count: usize) -> ConsensusStatus {
    ConsensusStatus {
        node_id: String::new(),
        self_role: "replica".to_string(),
        current_view: boule_consensus::View::ZERO,
        last_voted_view: boule_consensus::View::ZERO,
        last_committed_height: boule_consensus::Height::ZERO,
        last_committed_view: boule_consensus::View::ZERO,
        locked: None,
        high_qc: None,
        vote_buckets: Vec::new(),
        timeout_buckets: Vec::new(),
        parked_proposals: Vec::new(),
        pending_blocks_count: 0,
        peers_connected: Vec::new(),
        validator_set: Vec::new(),
        validator_keys: Vec::new(),
        mempool_size: 0,
        cache_evictions: Default::default(),
        dropped_commands: 0,
        equivocations_detected: 0,
        proposal_equivocations_detected: 0,
        equivocation_proofs_built: 0,
        equivocation_evidence_committed: 0,
        state_divergence_detected: 0,
        proposal_command_rejections: 0,
        backpressure: Default::default(),
        delinquent_validators: Vec::new(),
        cluster_participation_permille: None,
        el_behind: false,
        el_behind_height_gap: 0,
    }
}
