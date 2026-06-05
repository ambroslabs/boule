//! Operational observability surface (#808): Prometheus `/metrics` plus
//! liveness (`/health`) and readiness (`/ready`) endpoints, mounted on the
//! node's **public** API listener so a load balancer / monitoring stack can
//! reach them without touching the privileged admin surface (#807).
//!
//! # Sources, not new instrumentation
//!
//! Everything here is derived from signals the node already publishes:
//!
//! - the [`ConsensusStatus`] snapshot the consensus event loop pushes onto a
//!   [`tokio::sync::watch`] channel after every tick (current view, committed
//!   height, validator set, peer set, mempool depth, liveness/participation
//!   from the existing tracker, and the audit/back-pressure counters), and
//! - the p2p peer count, read from the same peer manager `/peers` answers.
//!
//! We deliberately *don't* sprinkle counters across the hot path: the watch
//! snapshot is the single, contention-free source of truth, so `/metrics`
//! re-renders it on demand. That keeps the set bounded to the
//! operationally-useful signals an operator actually graphs.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use prometheus::{Encoder, Gauge, IntGauge, Registry, TextEncoder};
use tokio::sync::watch;

use boule_consensus::status::ConsensusStatus;

/// Snapshot of node health, derived from the latest [`ConsensusStatus`].
///
/// Split out from the HTTP handlers so the liveness/readiness *policy* is
/// unit-testable without the axum stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthView {
    /// `true` once consensus is wired (the watch channel exists). The
    /// process being up to answer the request is itself the liveness
    /// signal, so `/health` is always `200` while the server runs — this
    /// flag only distinguishes a consensus-enabled node from a
    /// gossip-only one in the body.
    pub consensus_enabled: bool,
    /// This node is in the active validator set for the current view.
    pub is_validator: bool,
    /// The node has at least one consensus peer connection. A lone
    /// validator with no peers cannot make progress, so this gates
    /// readiness for a validator.
    pub has_peers: bool,
    /// Consensus has committed at least one block past genesis, i.e. the
    /// node is participating in a live chain rather than sitting at a
    /// cold start. Used as the "synced to head" proxy in the trusted-set
    /// model, where there is no external head oracle.
    pub committed_progress: bool,
    /// The current view is advancing relative to the last committed view
    /// (the node is not wedged far behind in view with no commits). True
    /// when `current_view` is within a small bound of the last committed
    /// view, or no block has committed yet (cold start is "healthy view,
    /// not yet ready").
    pub healthy_view: bool,
}

/// How far `current_view` may run ahead of `last_committed_view` before the
/// node is considered to be in an unhealthy (stuck-advancing-without-
/// committing) view for readiness purposes. A handful of views of slack
/// covers normal pipelining and a transient timeout round.
const HEALTHY_VIEW_LAG: u64 = 8;

impl HealthView {
    /// Derive the health view from a consensus snapshot plus the live peer
    /// count. `consensus_enabled` is `false` only on a gossip-only node
    /// (no `[consensus]` section), in which case the snapshot is absent.
    pub fn from_status(status: &ConsensusStatus, peer_count: usize) -> Self {
        let is_validator = status.validator_set.iter().any(|v| v == &status.node_id);
        let committed_progress = status.last_committed_height.0 > 0;
        let lag = status
            .current_view
            .0
            .saturating_sub(status.last_committed_view.0);
        // Cold start (nothing committed yet) is a healthy view: the node is
        // not wedged, it just hasn't pipelined a commit yet.
        let healthy_view = !committed_progress || lag <= HEALTHY_VIEW_LAG;
        Self {
            consensus_enabled: true,
            is_validator,
            has_peers: peer_count > 0,
            committed_progress,
            healthy_view,
        }
    }

    /// Gossip-only node: no consensus, so readiness reduces to "the process
    /// is up". Reported `ready` so a non-validating gossip node behind a LB
    /// is not perpetually drained.
    pub fn gossip_only() -> Self {
        Self {
            consensus_enabled: false,
            is_validator: false,
            has_peers: false,
            committed_progress: false,
            healthy_view: true,
        }
    }

    /// Readiness verdict for `/ready`: is the node fit to receive traffic?
    ///
    /// - Gossip-only nodes are always ready (process up is the only signal).
    /// - A **validator** must be in a healthy view, have committed progress,
    ///   and have at least one peer — i.e. actually participating.
    /// - A **non-validating** consensus node only needs a healthy view +
    ///   committed progress (it follows the chain; it has no quorum role),
    ///   matching the full/RPC-node mode the testnet runs.
    pub fn is_ready(&self) -> bool {
        if !self.consensus_enabled {
            return true;
        }
        if !self.healthy_view || !self.committed_progress {
            return false;
        }
        if self.is_validator && !self.has_peers {
            return false;
        }
        true
    }
}

/// Render a [`ConsensusStatus`] + live peer count into Prometheus text
/// exposition format. Bounded to the operationally-useful gauges; every
/// series is sourced from the snapshot so there is no hot-path
/// instrumentation cost.
///
/// Returns the encoded body; an encoding failure (which cannot happen for
/// this fixed, well-formed gauge set) surfaces as an `Err` the handler maps
/// to a `500`.
pub fn render_prometheus(
    status: &ConsensusStatus,
    peer_count: usize,
) -> Result<String, prometheus::Error> {
    let reg = Registry::new();
    let health = HealthView::from_status(status, peer_count);

    // --- helpers ---------------------------------------------------------
    let int_gauge = |name: &str, help: &str, val: i64| -> Result<(), prometheus::Error> {
        let g = IntGauge::new(name, help)?;
        g.set(val);
        reg.register(Box::new(g))
    };
    let bool_gauge = |name: &str, help: &str, val: bool| -> Result<(), prometheus::Error> {
        int_gauge(name, help, i64::from(val))
    };

    // --- consensus health ------------------------------------------------
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

    // Cluster participation, in [0,1], from the existing liveness tracker.
    if let Some(permille) = status.cluster_participation_permille {
        let g = Gauge::new(
            "boule_consensus_cluster_participation_ratio",
            "Cluster-wide mean credited participation over the liveness window (0..1).",
        )?;
        g.set(permille as f64 / 1000.0);
        reg.register(Box::new(g))?;
    }

    // --- audit / safety counters (monotonic over the run) ----------------
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

    // --- back-pressure drop counters -------------------------------------
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

    // --- p2p connectivity -------------------------------------------------
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

    // --- derived health/readiness (handy for alerting without /ready) ----
    bool_gauge(
        "boule_node_ready",
        "1 if the node reports ready on /ready, else 0.",
        health.is_ready(),
    )?;

    let mut buf = Vec::new();
    TextEncoder::new().encode(&reg.gather(), &mut buf)?;
    String::from_utf8(buf).map_err(|e| prometheus::Error::Msg(e.to_string()))
}

/// Shared state for the public observability router: the consensus status
/// watch receiver (absent on a gossip-only node) and a closure that reports
/// the live peer count.
#[derive(Clone)]
pub struct ObservabilityState {
    /// `None` on a gossip-only node (no `[consensus]` section). Health then
    /// reduces to "process up", metrics to the p2p-only series.
    pub status_rx: Option<watch::Receiver<Arc<ConsensusStatus>>>,
    /// Live peer-count probe. Async so it can round-trip the peer manager,
    /// matching how `/peers` is served.
    pub peer_count: Arc<dyn PeerCount>,
}

/// Object-safe live peer-count probe, so the router does not depend on the
/// concrete p2p command channel type.
pub trait PeerCount: Send + Sync {
    /// Current number of connected peers. Implementations must not block.
    fn count(&self) -> futures_util::future::BoxFuture<'static, usize>;
}

/// Build the public observability router: `/metrics`, `/health`, `/ready`.
/// Merged into the public listener's router in `node::run`.
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

async fn metrics(State(state): State<ObservabilityState>) -> impl IntoResponse {
    let peer_count = state.peer_count.count().await;
    let body = match current_status(&state).await {
        Some(status) => render_prometheus(&status, peer_count),
        // Gossip-only: still expose the p2p peer gauge so the node is not a
        // metrics black hole. Render against a zeroed snapshot — but only the
        // p2p series carry meaning there, which the help text reflects.
        None => render_prometheus(&gossip_only_status(peer_count), peer_count),
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

/// `/health` — liveness. The process answering at all *is* the signal, so
/// this is always `200 OK`. The body distinguishes consensus-enabled from
/// gossip-only for human eyeballs.
async fn health(State(state): State<ObservabilityState>) -> impl IntoResponse {
    let enabled = state.status_rx.is_some();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "consensus_enabled": enabled,
        })),
    )
}

/// `/ready` — readiness. `200` when [`HealthView::is_ready`] holds, else
/// `503` so a load balancer drains the node until it is participating.
async fn ready(State(state): State<ObservabilityState>) -> impl IntoResponse {
    let peer_count = state.peer_count.count().await;
    let view = match current_status(&state).await {
        Some(status) => HealthView::from_status(&status, peer_count),
        None => HealthView::gossip_only(),
    };
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
            "is_validator": view.is_validator,
            "has_peers": view.has_peers,
            "committed_progress": view.committed_progress,
            "healthy_view": view.healthy_view,
        })),
    )
}

/// A zeroed consensus snapshot used to render the p2p-only metric series on a
/// gossip-only node. All consensus gauges read zero (accurate — there is no
/// consensus), and `node_id` is empty so `is_validator` is false.
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boule_consensus::status::ConsensusStatus;
    use boule_consensus::{Height, View};

    fn base_status() -> ConsensusStatus {
        ConsensusStatus {
            node_id: "self-node".to_string(),
            self_role: "replica".to_string(),
            current_view: View(10),
            last_voted_view: View(9),
            last_committed_height: Height(8),
            last_committed_view: View(9),
            locked: None,
            high_qc: None,
            vote_buckets: Vec::new(),
            timeout_buckets: Vec::new(),
            parked_proposals: Vec::new(),
            pending_blocks_count: 2,
            peers_connected: vec!["peer-a".to_string(), "peer-b".to_string()],
            validator_set: vec!["self-node".to_string(), "peer-a".to_string()],
            validator_keys: Vec::new(),
            mempool_size: 3,
            cache_evictions: Default::default(),
            dropped_commands: 1,
            equivocations_detected: 4,
            proposal_equivocations_detected: 0,
            equivocation_proofs_built: 0,
            equivocation_evidence_committed: 0,
            state_divergence_detected: 0,
            proposal_command_rejections: 0,
            backpressure: Default::default(),
            delinquent_validators: Vec::new(),
            cluster_participation_permille: Some(950),
        }
    }

    #[test]
    fn metrics_render_expected_series() {
        let status = base_status();
        let text = render_prometheus(&status, 5).expect("render");

        // A handful of representative series + values.
        assert!(text.contains("boule_consensus_current_view 10"));
        assert!(text.contains("boule_consensus_committed_height 8"));
        assert!(text.contains("boule_consensus_is_validator 1"));
        assert!(text.contains("boule_consensus_validator_set_size 2"));
        assert!(text.contains("boule_consensus_mempool_size 3"));
        assert!(text.contains("boule_p2p_peers_connected 5"));
        assert!(text.contains("boule_consensus_equivocations_detected 4"));
        assert!(text.contains("boule_consensus_cluster_participation_ratio 0.95"));
        // Health rolls up to ready (validator, has peers, committed, healthy).
        assert!(text.contains("boule_node_ready 1"));

        // Every series carries a HELP + TYPE header — valid exposition format.
        assert!(text.contains("# HELP boule_consensus_current_view"));
        assert!(text.contains("# TYPE boule_consensus_current_view gauge"));
    }

    #[test]
    fn non_validator_metric_is_zero() {
        let mut status = base_status();
        status.validator_set = vec!["peer-a".to_string()];
        let text = render_prometheus(&status, 1).expect("render");
        assert!(text.contains("boule_consensus_is_validator 0"));
    }

    #[test]
    fn participation_gauge_absent_when_unknown() {
        let mut status = base_status();
        status.cluster_participation_permille = None;
        let text = render_prometheus(&status, 1).expect("render");
        assert!(!text.contains("boule_consensus_cluster_participation_ratio"));
    }

    #[test]
    fn validator_ready_requires_peers_and_progress() {
        let status = base_status();
        let h = HealthView::from_status(&status, 2);
        assert!(h.is_validator);
        assert!(h.has_peers);
        assert!(h.committed_progress);
        assert!(h.healthy_view);
        assert!(h.is_ready());
    }

    #[test]
    fn validator_not_ready_without_peers() {
        let status = base_status();
        let h = HealthView::from_status(&status, 0);
        assert!(h.is_validator);
        assert!(!h.has_peers);
        assert!(
            !h.is_ready(),
            "lone validator with no peers must not be ready"
        );
    }

    #[test]
    fn not_ready_before_first_commit() {
        let mut status = base_status();
        status.last_committed_height = Height(0);
        status.last_committed_view = View(0);
        let h = HealthView::from_status(&status, 2);
        assert!(!h.committed_progress);
        assert!(
            h.healthy_view,
            "cold start is a healthy view, just not ready"
        );
        assert!(!h.is_ready());
    }

    #[test]
    fn not_ready_when_view_runs_far_ahead_of_commits() {
        let mut status = base_status();
        status.current_view = View(1000);
        status.last_committed_view = View(9);
        let h = HealthView::from_status(&status, 2);
        assert!(
            !h.healthy_view,
            "view far ahead of last commit is unhealthy"
        );
        assert!(!h.is_ready());
    }

    #[test]
    fn non_validating_consensus_node_ready_without_peers() {
        // A follower (not in the set) only needs a healthy view + progress.
        let mut status = base_status();
        status.validator_set = vec!["peer-a".to_string(), "peer-b".to_string()];
        let h = HealthView::from_status(&status, 0);
        assert!(!h.is_validator);
        assert!(h.is_ready());
    }

    #[test]
    fn gossip_only_is_always_ready() {
        let h = HealthView::gossip_only();
        assert!(!h.consensus_enabled);
        assert!(h.is_ready());
    }

    // --- HTTP-level tests over the live router ---------------------------

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt; // `oneshot`

    /// Test `PeerCount` returning a fixed value.
    struct FixedPeers(usize);
    impl PeerCount for FixedPeers {
        fn count(&self) -> futures_util::future::BoxFuture<'static, usize> {
            let n = self.0;
            Box::pin(async move { n })
        }
    }

    fn state_with(status: ConsensusStatus, peers: usize) -> ObservabilityState {
        let (_tx, rx) = watch::channel(Arc::new(status));
        ObservabilityState {
            status_rx: Some(rx),
            peer_count: Arc::new(FixedPeers(peers)),
        }
    }

    async fn body_string(resp: axum::response::Response) -> String {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn metrics_endpoint_renders_prometheus_text() {
        let router = router(state_with(base_status(), 4));
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(ct.starts_with("text/plain"));
        let body = body_string(resp).await;
        assert!(body.contains("boule_consensus_current_view 10"));
        assert!(body.contains("boule_p2p_peers_connected 4"));
        assert!(body.contains("# TYPE boule_node_ready gauge"));
    }

    #[tokio::test]
    async fn health_is_always_ok() {
        let router = router(state_with(base_status(), 0));
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_string(resp).await.contains("\"status\":\"ok\""));
    }

    #[tokio::test]
    async fn ready_returns_200_for_healthy_validator() {
        let router = router(state_with(base_status(), 2));
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_string(resp).await.contains("\"ready\":true"));
    }

    #[tokio::test]
    async fn ready_returns_503_for_validator_without_peers() {
        let router = router(state_with(base_status(), 0));
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(body_string(resp).await.contains("\"ready\":false"));
    }

    #[tokio::test]
    async fn gossip_only_metrics_and_ready_still_serve() {
        let state = ObservabilityState {
            status_rx: None,
            peer_count: Arc::new(FixedPeers(3)),
        };
        let router = router(state);

        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            body_string(resp)
                .await
                .contains("boule_p2p_peers_connected 3")
        );

        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// The public-surface router (observability merged the way `node::run`
    /// builds the public listener) exposes NO privileged routes: both
    /// `POST /admin/rotate-key` and `POST /mempool/submit` 404 here. They
    /// live only on the separate admin listener (#807).
    #[tokio::test]
    async fn public_router_does_not_expose_privileged_routes() {
        let public = router(state_with(base_status(), 1));

        for path in ["/admin/rotate-key", "/mempool/submit"] {
            let resp = public
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .body(Body::from("x"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "privileged route {path} must be absent from the public surface",
            );
        }
    }
}
