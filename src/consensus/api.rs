//! Public consensus API surface.
//!
//! Two flavors of API live here:
//!
//! - The read-only HTTP admin router ([`router`]), mounted into the
//!   node's main [`axum::Router`] when `[consensus]` is configured.
//! - The [`CommitNotifier`] trait — a stable subscription point for
//!   "what just committed?" that consumers like observer-mode nodes
//!   (#308), out-of-process Application integrations (#225), and
//!   external tooling (block explorers, metrics, snap-sync) can plug
//!   into without modifying [`crate::consensus::node`].
//!
//! HTTP endpoints currently exposed:
//!
//! - `GET /consensus/status` — latest [`ConsensusStatus`] snapshot
//!   published by the consensus event loop. See
//!   [`crate::consensus::status`] for the JSON shape.
//!
//! On a gossip-only node (no `[consensus]` section), the HTTP router
//! is not mounted, and axum's default 404 applies — matching the
//! acceptance criterion from the design issue.

#![warn(missing_docs)]

use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use tokio::sync::watch;

use super::View;
use super::status::ConsensusStatus;
use crate::replication::block::Block;

/// Hook fired by the consensus pipeline after each block has been
/// applied to the state machine, persisted, and had its reconfig and
/// rotation payloads committed.
///
/// Plug-in surface for consumers that want the post-commit stream
/// without running the safety core's egress: observer-mode nodes
/// (#308 Tier A), out-of-process Applications (#225 M1), and external
/// tooling such as block explorers, metrics scrapers, and snap-sync
/// daemons.
///
/// # Threading
///
/// `on_commit` is invoked synchronously from the consensus event loop.
/// Implementations **must not block**: forward to a channel, increment
/// an atomic, or log. Anything heavier (HTTP fan-out, disk writes that
/// can stall) belongs on a separate task that drains a channel this
/// notifier feeds.
///
/// # Example
///
/// ```ignore
/// use std::sync::Arc;
/// use tokio::sync::mpsc;
///
/// use ambros_p2p::consensus::api::{CommitNotifier, MpscCommitNotifier};
/// use ambros_p2p::consensus::node::ConsensusNode;
///
/// # fn build(node: ConsensusNode) -> ConsensusNode {
/// let (tx, mut rx) = mpsc::unbounded_channel();
/// let notifier: Arc<dyn CommitNotifier> =
///     Arc::new(MpscCommitNotifier::new(tx));
/// let node = node.with_commit_notifier(notifier);
///
/// // Elsewhere, drain `rx` to react to commits:
/// // tokio::spawn(async move {
/// //     while let Some(block) = rx.recv().await { /* index, fan out, … */ }
/// // });
/// # node
/// # }
/// ```
pub trait CommitNotifier: Send + Sync {
    /// Notify of a newly committed block.
    ///
    /// `state_commitment` and `view` mirror
    /// `block.header.state_commitment` and `block.header.view`. They
    /// are passed alongside the block as a stable summary signature so
    /// observers that only care about post-commit state digests do not
    /// need to reach into block-header internals.
    ///
    /// `block` is borrowed; clone inside the implementation if the
    /// observer needs to retain it past the call (e.g. forwarding on a
    /// channel).
    fn on_commit(&self, block: &Block, state_commitment: &[u8; 32], view: View);
}

/// [`CommitNotifier`] adapter that forwards each committed block to a
/// [`tokio::sync::mpsc::UnboundedSender`].
///
/// This is the impl used by the in-process simulator (and any other
/// single-consumer subscriber): each node owns its own unbounded
/// channel, the harness drains the receiver, and a closed channel is
/// treated as a shutdown signal — `send` errors are swallowed because
/// the consensus loop must not stall on a downstream observer
/// disappearing.
pub struct MpscCommitNotifier {
    tx: tokio::sync::mpsc::UnboundedSender<Block>,
}

impl MpscCommitNotifier {
    /// Wrap an unbounded channel sender as a [`CommitNotifier`].
    pub fn new(tx: tokio::sync::mpsc::UnboundedSender<Block>) -> Self {
        Self { tx }
    }
}

impl CommitNotifier for MpscCommitNotifier {
    fn on_commit(&self, block: &Block, _state_commitment: &[u8; 32], _view: View) {
        let _ = self.tx.send(block.clone());
    }
}

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
            cache_evictions: crate::consensus::status::CacheEvictionStatus::default(),
            dropped_commands: 0,
            equivocations_detected: 0,
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
