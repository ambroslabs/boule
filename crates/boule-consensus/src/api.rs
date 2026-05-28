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
//!   into without modifying [`crate::node`].
//!
//! HTTP endpoints currently exposed:
//!
//! - `GET /consensus/status` — latest [`ConsensusStatus`] snapshot
//!   published by the consensus event loop. See
//!   [`crate::status`] for the JSON shape.
//!
//! On a gossip-only node (no `[consensus]` section), the HTTP router
//! is not mounted, and axum's default 404 applies — matching the
//! acceptance criterion from the design issue.

#![warn(missing_docs)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use tokio::sync::watch;

#[cfg(test)]
use super::Height;
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
/// use boule::consensus::api::{CommitNotifier, MpscCommitNotifier};
/// use boule::consensus::node::ConsensusNode;
///
/// # fn build(node: ConsensusNode) -> ConsensusNode {
/// let (tx, mut rx) = mpsc::channel(4096);
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
/// [`tokio::sync::mpsc::Sender`].
///
/// Used by the in-process simulator and any other single-consumer
/// subscriber. Each node owns its own bounded channel; the harness
/// drains the receiver. `on_commit` calls `try_send` because it must
/// not stall the consensus event loop — if the receiver has fallen
/// behind capacity, the block is dropped and an internal counter is
/// bumped so a test can assert no drops occurred. A closed channel is
/// treated as a shutdown signal; the error is swallowed.
///
/// Capacity should be picked so that bursts between drains fit
/// comfortably; for the sim, [`crate::sim::SIM_COMMIT_CHANNEL_CAP`]
/// is a generous default. Drops are a sim bug — the harness either
/// drains slowly enough that the cap is too low, or it forgot to drain
/// at all.
pub struct MpscCommitNotifier {
    tx: tokio::sync::mpsc::Sender<Block>,
    overflows: Arc<AtomicU64>,
}

impl MpscCommitNotifier {
    /// Wrap a bounded channel sender as a [`CommitNotifier`].
    pub fn new(tx: tokio::sync::mpsc::Sender<Block>) -> Self {
        Self {
            tx,
            overflows: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Shared handle to the overflow counter. Increments every time
    /// `on_commit` calls `try_send` and gets `Full` back. The harness
    /// can poll this to assert no drops happened in a deterministic
    /// test, or sum across nodes to surface back-pressure on the
    /// commit fan-out as a whole.
    pub fn overflow_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.overflows)
    }

    /// Read the current overflow count.
    pub fn overflow_count(&self) -> u64 {
        self.overflows.load(Ordering::Relaxed)
    }
}

impl CommitNotifier for MpscCommitNotifier {
    fn on_commit(&self, block: &Block, _state_commitment: &[u8; 32], _view: View) {
        match self.tx.try_send(block.clone()) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                // Receiver fell behind. See struct doc — this is a sim
                // bug class (cap too low, or harness forgot to drain).
                // Drop the block, bump the counter, and warn so a wedged
                // test surfaces the cause instead of OOMing.
                self.overflows.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    target: "boule::consensus::api",
                    "MpscCommitNotifier dropped commit on full channel"
                );
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                // Receiver gone — typical at shutdown. Stay quiet.
            }
        }
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
    use crate::status::ConsensusStatus;

    fn empty_status() -> ConsensusStatus {
        ConsensusStatus {
            node_id: "node".to_string(),
            self_role: "replica".to_string(),
            current_view: View(0),
            last_voted_view: View(0),
            last_committed_height: Height(0),
            last_committed_view: View(0),
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
            cache_evictions: crate::status::CacheEvictionStatus::default(),
            dropped_commands: 0,
            equivocations_detected: 0,
            proposal_equivocations_detected: 0,
            backpressure: crate::status::BackpressureStatus::default(),
        }
    }

    #[tokio::test]
    async fn handler_returns_latest_published_snapshot() {
        let (tx, rx) = watch::channel(Arc::new(empty_status()));

        let mut updated = empty_status();
        updated.current_view = View(42);
        updated.node_id = "updated-node".to_string();
        tx.send(Arc::new(updated)).unwrap();

        let Json(status) = get_status(State(rx)).await;
        assert_eq!(status.current_view, View(42));
        assert_eq!(status.node_id, "updated-node");
    }

    #[tokio::test]
    async fn handler_returns_initial_snapshot_when_no_update_published() {
        // Mirrors the "event loop hasn't ticked yet" case in the
        // acceptance criteria: the endpoint must return a sane initial
        // state (all-zeros), never a 500.
        let (_tx, rx) = watch::channel(Arc::new(empty_status()));
        let Json(status) = get_status(State(rx)).await;
        assert_eq!(status.current_view, View(0));
        assert_eq!(status.last_committed_height, Height(0));
        assert!(status.locked.is_none());
    }

    #[tokio::test]
    async fn mpsc_commit_notifier_drops_and_counts_when_channel_full() {
        // Capacity 1 channel, never drained. First commit fits, the
        // next two must drop and bump the overflow counter so a
        // wedged-receiver test surfaces the cause.
        let (tx, _rx_held_open) = tokio::sync::mpsc::channel::<Block>(1);
        let notifier = MpscCommitNotifier::new(tx);
        let block = Block::genesis([0; 32], [0; 32]);

        notifier.on_commit(&block, &[0; 32], View(1));
        assert_eq!(notifier.overflow_count(), 0);

        notifier.on_commit(&block, &[0; 32], View(2));
        notifier.on_commit(&block, &[0; 32], View(3));
        assert_eq!(notifier.overflow_count(), 2);

        // The shared counter handle observes the same value.
        let shared = notifier.overflow_counter();
        assert_eq!(shared.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn mpsc_commit_notifier_swallows_closed_channel_silently() {
        // Receiver dropped first ⇒ Closed. The notifier must not panic
        // and must not bump the overflow counter (Closed ≠ Full).
        let (tx, rx) = tokio::sync::mpsc::channel::<Block>(8);
        drop(rx);
        let notifier = MpscCommitNotifier::new(tx);
        let block = Block::genesis([0; 32], [0; 32]);

        notifier.on_commit(&block, &[0; 32], View(1));
        assert_eq!(notifier.overflow_count(), 0);
    }
}
