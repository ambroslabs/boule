use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use boule_consensus::replication::mempool::Mempool;
use boule_consensus::status::ConsensusStatus;
use boule_core::crypto::signed::{NodeSigner, Signer};
use boule_core::identity::node_id_to_base58;
use boule_core::transport::overlay::Discovery;

use crate::rotation_handle::{RotationHandle, RotationReceipt};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateKeyRequest {
    pub new_key_backend: String,

    #[serde(default)]
    pub new_key_path: Option<PathBuf>,

    #[serde(default)]
    pub new_key_passphrase_env: Option<String>,

    #[serde(default)]
    pub v_eff: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateKeyResponse {
    pub validator: String,

    pub new_pubkey: String,

    pub v_eff: u64,

    pub current_view: u64,
}

impl From<RotationReceipt> for RotateKeyResponse {
    fn from(r: RotationReceipt) -> Self {
        Self {
            validator: node_id_to_base58(&r.validator),
            new_pubkey: node_id_to_base58(&r.new_pubkey),
            v_eff: r.v_eff,
            current_view: r.current_view,
        }
    }
}

pub fn router(
    handle: Arc<RotationHandle>,
    mempool: Arc<dyn Mempool>,
    status_rx: Option<watch::Receiver<Arc<ConsensusStatus>>>,
    discovery: Arc<dyn Discovery>,
    auth_token: Option<String>,
) -> Router {
    let mut router = Router::new()
        .route("/admin/rotate-key", post(rotate_key))
        .with_state(handle)
        .merge(boule_consensus::api::submit_router(mempool))
        .merge(peers_router(discovery));
    if let Some(rx) = status_rx {
        router = router.merge(boule_consensus::api::router(rx));
    }
    if let Some(token) = auth_token {
        router = router.layer(middleware::from_fn_with_state(
            Arc::new(token),
            require_bearer,
        ));
    }
    router
}

fn peers_router(discovery: Arc<dyn Discovery>) -> Router {
    Router::new()
        .route("/peers", get(list_peers))
        .with_state(discovery)
}

async fn list_peers(State(discovery): State<Arc<dyn Discovery>>) -> Json<Vec<String>> {
    Json(
        discovery
            .known_peers()
            .iter()
            .map(node_id_to_base58)
            .collect(),
    )
}

pub async fn require_bearer(
    State(expected): State<Arc<String>>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match presented {
        Some(tok) if constant_time_eq(tok.as_bytes(), expected.as_bytes()) => {
            Ok(next.run(req).await)
        }
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

async fn rotate_key(
    State(handle): State<Arc<RotationHandle>>,
    Json(req): Json<RotateKeyRequest>,
) -> Result<Json<RotateKeyResponse>, (StatusCode, String)> {
    let receipt = rotate_with_key_spec(
        &handle,
        &req.new_key_backend,
        req.new_key_path.clone(),
        req.new_key_passphrase_env.clone(),
        req.v_eff,
    )
    .map_err(|e| (StatusCode::BAD_REQUEST, format!("{e:#}")))?;
    Ok(Json(receipt.into()))
}

pub fn rotate_with_key_spec(
    handle: &RotationHandle,
    new_key_backend: &str,
    new_key_path: Option<PathBuf>,
    new_key_passphrase_env: Option<String>,
    v_eff: Option<u64>,
) -> anyhow::Result<RotationReceipt> {
    let new_cfg = boule_consensus::validator_rotation::build_new_identity_config_for_rotation(
        new_key_backend,
        new_key_path,
        new_key_passphrase_env,
    )?;
    let new_identity = boule_core::config::build_provider(&new_cfg)?.load_or_init()?;
    let new_signer: Arc<dyn Signer> = Arc::new(NodeSigner::from_identity(&new_identity)?);
    handle.rotate(new_signer, v_eff)
}
