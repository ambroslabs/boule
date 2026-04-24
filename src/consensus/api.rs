//! HTTP admin surface for the consensus subsystem.
//!
//! Exposes read-only endpoints mounted into the node's main
//! [`axum::Router`] when `[consensus]` is configured:
//!
//! - `GET /consensus/status` — latest [`ConsensusStatus`] snapshot
//!   published by the consensus event loop. See
//!   [`crate::consensus::status`] for the JSON shape.
//!
//! On a gossip-only node (no `[consensus]` section), this router is
//! not mounted, and axum's default 404 applies — matching the
//! acceptance criterion from the design issue.

#![warn(missing_docs)]

use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use tokio::sync::watch;

use super::status::ConsensusStatus;

/// Build the consensus-admin router.
///
/// `status_rx` is the receiver side of the [`tokio::sync::watch`]
/// channel the consensus event loop publishes into. Cloning the
/// receiver is cheap (the watch channel interns the current value in
/// an `Arc`), so passing the receiver by value into the router is fine.
///
/// # Staleness
///
/// The value is eventually consistent, lagging by up to one event-loop
/// iteration. In exchange, reading it never contends with the event
/// loop's hot path. The initial value is published once at startup
/// before [`ConsensusNode::run`](super::node::ConsensusNode::run) enters
/// its select, so the endpoint returns a sane "current_view=0" snapshot
/// rather than a 500 if it's hit in the brief window before the first
/// tick.
pub fn router(status_rx: watch::Receiver<Arc<ConsensusStatus>>) -> Router {
    Router::new()
        .route("/consensus/status", get(get_status))
        .with_state(status_rx)
}

async fn get_status(
    State(rx): State<watch::Receiver<Arc<ConsensusStatus>>>,
) -> Json<ConsensusStatus> {
    // `.borrow()` returns a `Ref` guarded by an internal RwLock that
    // the sender only takes briefly at publish time. Cloning the inner
    // value copies the status struct (small, a handful of Vecs); we
    // release the borrow before returning so we never block the
    // publisher while serializing.
    let status: ConsensusStatus = (**rx.borrow()).clone();
    Json(status)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::consensus::status::ConsensusStatus;

    fn empty_status() -> ConsensusStatus {
        ConsensusStatus {
            node_id: "node".to_string(),
            self_role: "replica".to_string(),
            current_view: 0,
            last_voted_view: 0,
            last_committed_height: 0,
            last_committed_view: 0,
            locked: None,
            high_qc: None,
            vote_buckets: Vec::new(),
            timeout_buckets: Vec::new(),
            parked_proposals: Vec::new(),
            pending_blocks_count: 0,
            peers_connected: Vec::new(),
            validator_set: Vec::new(),
            mempool_size: 0,
        }
    }

    #[tokio::test]
    async fn handler_returns_latest_published_snapshot() {
        let (tx, rx) = watch::channel(Arc::new(empty_status()));

        let mut updated = empty_status();
        updated.current_view = 42;
        updated.node_id = "updated-node".to_string();
        tx.send(Arc::new(updated)).unwrap();

        let Json(status) = get_status(State(rx)).await;
        assert_eq!(status.current_view, 42);
        assert_eq!(status.node_id, "updated-node");
    }

    #[tokio::test]
    async fn handler_returns_initial_snapshot_when_no_update_published() {
        // Mirrors the "event loop hasn't ticked yet" case in the
        // acceptance criteria: the endpoint must return a sane initial
        // state (all-zeros), never a 500.
        let (_tx, rx) = watch::channel(Arc::new(empty_status()));
        let Json(status) = get_status(State(rx)).await;
        assert_eq!(status.current_view, 0);
        assert_eq!(status.last_committed_height, 0);
        assert!(status.locked.is_none());
    }
}
