//! Operator admin HTTP surface (#707): `POST /admin/rotate-key`, the
//! runtime trigger that hot-rotates this node's consensus signing key with
//! no restart.
//!
//! This is the operator-facing front end for
//! [`RotationHandle`](crate::rotation_handle::RotationHandle) (the
//! mechanism). The node — which has filesystem access to wherever the
//! operator provisioned the new key — loads/mints that key from the
//! backend named in the request, then drives the rotation: build the
//! dual-signed tx, admit it into the mempool, schedule the live swap.
//!
//! # Security posture (#807)
//!
//! This is a **privileged** surface and is isolated from the public API
//! listener two ways (defense in depth):
//!
//! 1. **Separate listener.** [`router`] is mounted only on the admin
//!    listener (`[api.admin] listen_addr`), never merged into the public
//!    router. When the admin listener is unset, these routes are not served
//!    at all. The public listener exposes only read-only + observability
//!    endpoints.
//! 2. **Bearer auth (belt).** When a token is configured (`[api.admin]
//!    auth_token` / `auth_token_env`), every request must carry
//!    `Authorization: Bearer <token>`; a missing/wrong token gets `401`.
//!
//! Triggering a rotation is *not* a key-theft vector even without auth:
//! building the rotation tx needs this node's current signing key to produce
//! `sig_old`, so a caller who reaches this endpoint cannot make the network
//! accept a key the chain never recorded. The worst case is a self-inflicted
//! liveness fault (the node schedules a swap to a key whose tx never commits
//! and goes silent at `v_eff`), recoverable by rotating again. The mempool
//! submit endpoint shares this listener for the same reason.

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use boule_consensus::replication::mempool::Mempool;
use boule_core::crypto::signed::{NodeSigner, Signer};
use boule_core::identity::node_id_to_base58;

use crate::rotation_handle::{RotationHandle, RotationReceipt};

/// Body of `POST /admin/rotate-key`. Names the new signing key (by the same
/// backend abstraction the rotation CLI uses) and an optional effective
/// view; the node loads/mints the key and schedules the rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateKeyRequest {
    /// New consensus key backend: `file` or `encrypted-file` (the
    /// provisioning-capable backends — the node mints the key if absent).
    pub new_key_backend: String,
    /// Path for the new consensus key (required for the file backends).
    #[serde(default)]
    pub new_key_path: Option<PathBuf>,
    /// Env var holding the new key's passphrase (`encrypted-file`).
    #[serde(default)]
    pub new_key_passphrase_env: Option<String>,
    /// Effective view for the swap. Omit for a safe default
    /// (`current_view + DEFAULT_V_EFF_MARGIN`); a too-close value is
    /// rejected.
    #[serde(default)]
    pub v_eff: Option<u64>,
}

/// Success response: the rotation the node scheduled, keys base58-encoded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateKeyResponse {
    /// Stable validator id (unchanged by rotation).
    pub validator: String,
    /// Key the validator will sign under at and after `v_eff`.
    pub new_pubkey: String,
    /// Effective view the swap takes hold at.
    pub v_eff: u64,
    /// Node's current view when the rotation was triggered.
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

/// Build the **privileged** admin router — `POST /admin/rotate-key` and
/// `POST /mempool/submit` — for mounting on the dedicated admin listener
/// (#807). Never merge this into the public listener's router.
///
/// When `auth_token` is `Some`, a bearer-token auth layer wraps every route:
/// requests must carry `Authorization: Bearer <token>` or they get `401`.
/// When `None`, the listener relies on network isolation alone (the operator
/// is expected to have bound a loopback / trusted interface; `Config::validate`
/// warns if it is neither loopback nor token-protected).
pub fn router(
    handle: Arc<RotationHandle>,
    mempool: Arc<dyn Mempool>,
    auth_token: Option<String>,
) -> Router {
    let mut router = Router::new()
        .route("/admin/rotate-key", post(rotate_key))
        .with_state(handle)
        // Reuse the consensus crate's mempool-submit router so there is one
        // definition of the submit semantics; it is privileged (lets a caller
        // inject txs into the block builder's pool), so it lives here on the
        // admin listener rather than on the public one (#807).
        .merge(boule_consensus::api::submit_router(mempool));
    if let Some(token) = auth_token {
        router = router.layer(middleware::from_fn_with_state(
            Arc::new(token),
            require_bearer,
        ));
    }
    router
}

/// Bearer-token gate for the privileged routes. Compares the
/// `Authorization: Bearer <token>` header against the configured secret in
/// constant time and rejects anything else with `401`.
async fn require_bearer(
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

/// Length-aware constant-time byte comparison, so the auth check does not
/// leak the token via early-exit timing.
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

/// Load (or mint) the new signing key from the named backend, then drive
/// [`RotationHandle::rotate`]. Split out from the HTTP handler so the
/// load-then-rotate path is unit-testable without the axum stack.
///
/// The new key is loaded on the *node* (which has filesystem access to where
/// the operator provisioned it), not the caller — the request only names the
/// backend + path.
pub fn rotate_with_key_spec(
    handle: &RotationHandle,
    new_key_backend: &str,
    new_key_path: Option<PathBuf>,
    new_key_passphrase_env: Option<String>,
    v_eff: Option<u64>,
) -> anyhow::Result<RotationReceipt> {
    // Reuse the rotation CLI's backend→config mapping: only the
    // provisioning-capable backends (file / encrypted-file) are accepted,
    // and the key is minted if absent.
    let new_cfg = boule_consensus::validator_rotation::build_new_identity_config_for_rotation(
        new_key_backend,
        new_key_path,
        new_key_passphrase_env,
    )?;
    let new_identity = boule_core::config::build_provider(&new_cfg)?.load_or_init()?;
    let new_signer: Arc<dyn Signer> = Arc::new(NodeSigner::from_identity(&new_identity)?);
    handle.rotate(new_signer, v_eff)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    use boule_consensus::replication::impls::InMemoryMempool;
    use boule_consensus::replication::mempool::Mempool;
    use boule_consensus::validator_rotation::DualSignedRotation;
    use boule_core::crypto::sig_scheme::SignatureSchemeChoice;
    use boule_core::crypto::signed::ChainId;
    use boule_core::identity::NodeIdentity;
    use rcgen::{KeyPair as RcgenKeyPair, PKCS_ED25519};
    use tempfile::TempDir;
    use zeroize::Zeroizing;

    use crate::rotatable_signer::RotatableSigner;

    fn fresh_signer() -> Arc<dyn Signer> {
        let kp = RcgenKeyPair::generate_for(&PKCS_ED25519).unwrap();
        let id = NodeIdentity {
            pkcs8_der: Zeroizing::new(kp.serialize_der()),
        };
        Arc::new(NodeSigner::from_identity(&id).unwrap())
    }

    #[test]
    fn rotate_with_key_spec_mints_key_and_schedules_rotation() {
        let genesis = fresh_signer();
        let view = Arc::new(AtomicU64::new(5));
        let signer = Arc::new(RotatableSigner::new(
            Arc::clone(&genesis),
            Arc::clone(&view),
        ));
        let mempool: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(64));
        let handle = RotationHandle::new(
            genesis.node_id(),
            ChainId::TEST,
            SignatureSchemeChoice::Ed25519Collected,
            Arc::clone(&view),
            Arc::clone(&mempool),
            Arc::clone(&signer),
        );

        let dir = TempDir::new().unwrap();
        let new_key = dir.path().join("new.key");
        assert!(!new_key.exists());

        let receipt = rotate_with_key_spec(&handle, "file", Some(new_key.clone()), None, Some(60))
            .expect("rotate must succeed");

        assert!(new_key.exists(), "the new key file must be minted");
        assert_eq!(receipt.v_eff, 60);
        assert_eq!(receipt.validator, genesis.node_id());

        // The minted key is the one the node now schedules + signs the tx
        // under. Reload it to confirm the reported pubkey + verify the tx.
        let minted =
            boule_core::config::build_provider(&boule_core::config::IdentityConfig::File {
                path: new_key.clone(),
                allow_insecure_perms: false,
            })
            .unwrap()
            .try_load()
            .unwrap()
            .unwrap();
        let minted_signer = NodeSigner::from_identity(&minted).unwrap();
        assert_eq!(receipt.new_pubkey, minted_signer.node_id());

        let proposed = mempool.propose(16);
        assert_eq!(proposed.len(), 1);
        let env = DualSignedRotation::decode_command(&proposed[0]).unwrap();
        env.verify(&genesis.node_id(), &ChainId::TEST)
            .expect("admitted rotation tx must verify");
        assert_eq!(env.payload.new_pubkey, minted_signer.node_id());
    }

    #[test]
    fn rotate_with_key_spec_rejects_read_only_backend() {
        let genesis = fresh_signer();
        let view = Arc::new(AtomicU64::new(0));
        let signer = Arc::new(RotatableSigner::new(
            Arc::clone(&genesis),
            Arc::clone(&view),
        ));
        let mempool: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(64));
        let handle = RotationHandle::new(
            genesis.node_id(),
            ChainId::TEST,
            SignatureSchemeChoice::Ed25519Collected,
            view,
            mempool,
            signer,
        );
        // `env` can't mint a fresh key — must be rejected before any rotation.
        let err = rotate_with_key_spec(&handle, "env", None, None, Some(60)).unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn response_encodes_keys_as_base58() {
        let r = RotationReceipt {
            validator: [1u8; 32],
            new_pubkey: [2u8; 32],
            v_eff: 60,
            current_view: 5,
        };
        let resp: RotateKeyResponse = r.into();
        assert_eq!(resp.validator, node_id_to_base58(&[1u8; 32]));
        assert_eq!(resp.new_pubkey, node_id_to_base58(&[2u8; 32]));
        assert_eq!(resp.v_eff, 60);
        assert_eq!(resp.current_view, 5);
    }

    // --- privileged-router auth + isolation (#807) -----------------------

    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt; // `oneshot`

    /// Build a privileged admin router over a fresh handle + mempool.
    fn admin_router(token: Option<String>) -> (Router, Arc<dyn Mempool>) {
        let genesis = fresh_signer();
        let view = Arc::new(AtomicU64::new(0));
        let signer = Arc::new(RotatableSigner::new(
            Arc::clone(&genesis),
            Arc::clone(&view),
        ));
        let mempool: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(64));
        let handle = Arc::new(RotationHandle::new(
            genesis.node_id(),
            ChainId::TEST,
            SignatureSchemeChoice::Ed25519Collected,
            view,
            Arc::clone(&mempool),
            signer,
        ));
        (super::router(handle, Arc::clone(&mempool), token), mempool)
    }

    #[tokio::test]
    async fn admin_router_without_token_admits_submit() {
        let (router, mempool) = admin_router(None);
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mempool/submit")
                    .body(Body::from("a-tx"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        assert_eq!(mempool.len(), 1);
    }

    #[tokio::test]
    async fn admin_router_with_token_rejects_missing_and_wrong_bearer() {
        let (router, mempool) = admin_router(Some("s3cret".to_string()));

        // No Authorization header → 401.
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mempool/submit")
                    .body(Body::from("tx"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Wrong token → 401.
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mempool/submit")
                    .header("authorization", "Bearer nope")
                    .body(Body::from("tx"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Both rejections happened before the handler ran — pool untouched.
        assert_eq!(mempool.len(), 0);
    }

    #[tokio::test]
    async fn admin_router_with_token_accepts_correct_bearer() {
        let (router, mempool) = admin_router(Some("s3cret".to_string()));
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mempool/submit")
                    .header("authorization", "Bearer s3cret")
                    .body(Body::from("tx"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        assert_eq!(mempool.len(), 1);
    }

    #[tokio::test]
    async fn admin_router_mounts_rotate_key() {
        // Sanity: the privileged rotate-key route is present on the admin
        // router (a malformed body still routes — it 400s, not 404s).
        let (router, _mempool) = admin_router(None);
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/rotate-key")
                    .header("content-type", "application/json")
                    .body(Body::from("not-json"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn constant_time_eq_matches_and_rejects() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }
}
