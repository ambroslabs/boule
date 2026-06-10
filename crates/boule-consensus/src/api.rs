use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use tokio::sync::watch;

use super::View;
use super::status::ConsensusStatus;
use crate::replication::block::Block;
use crate::replication::mempool::Mempool;

pub trait CommitNotifier: Send + Sync {
    fn on_commit(&self, block: &Block, state_commitment: &[u8; 32], view: View);
}

pub struct MpscCommitNotifier {
    tx: tokio::sync::mpsc::Sender<Block>,
    overflows: Arc<AtomicU64>,
}

impl MpscCommitNotifier {
    pub fn new(tx: tokio::sync::mpsc::Sender<Block>) -> Self {
        Self {
            tx,
            overflows: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn overflow_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.overflows)
    }

    pub fn overflow_count(&self) -> u64 {
        self.overflows.load(Ordering::Relaxed)
    }
}

impl CommitNotifier for MpscCommitNotifier {
    fn on_commit(&self, block: &Block, _state_commitment: &[u8; 32], _view: View) {
        match self.tx.try_send(block.clone()) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                self.overflows.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    target: "boule_core::consensus::api",
                    "MpscCommitNotifier dropped commit on full channel"
                );
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
        }
    }
}

pub fn router(status_rx: watch::Receiver<Arc<ConsensusStatus>>) -> Router {
    Router::new()
        .route("/consensus/status", get(get_status))
        .with_state(status_rx)
}

async fn get_status(
    State(rx): State<watch::Receiver<Arc<ConsensusStatus>>>,
) -> Json<ConsensusStatus> {
    let status: ConsensusStatus = (**rx.borrow()).clone();
    Json(status)
}

pub fn submit_router(mempool: Arc<dyn Mempool>) -> Router {
    Router::new()
        .route("/mempool/submit", post(submit_tx))
        .with_state(mempool)
}

async fn submit_tx(
    State(mempool): State<Arc<dyn Mempool>>,
    body: Bytes,
) -> (StatusCode, &'static str) {
    if body.is_empty() {
        return (StatusCode::BAD_REQUEST, "empty command rejected");
    }
    match mempool.insert(body) {
        Ok(true) => (StatusCode::ACCEPTED, "accepted"),
        Ok(false) => (StatusCode::OK, "duplicate"),

        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "mempool full"),
    }
}
