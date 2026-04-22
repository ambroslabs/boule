pub mod types;

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};

use crate::gossip::store::GossipStore;
use crate::gossip::{GossipMessage, InsertResult};
use bytes::Bytes;
use crate::gossip::wire::WireMessage;
use crate::p2p::{PeerCommand, NodeId};
use crate::p2p::tls::node_id_to_base58;

use types::{MessageItem, PostMessageRequest, PostMessageResponse};

#[derive(Clone)]
struct AppState {
    store: Arc<GossipStore>,
    cmd_tx: mpsc::Sender<PeerCommand>,
}

pub async fn serve(
    store: Arc<GossipStore>,
    cmd_tx: mpsc::Sender<PeerCommand>,
    listener: tokio::net::TcpListener,
) {
    let state = AppState { store, cmd_tx };

    let app = Router::new()
        .route("/messages", get(list_messages).post(post_message))
        .route("/peers", get(list_peers))
        .with_state(state);

    info!("HTTP API listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

async fn post_message(
    State(state): State<AppState>,
    Json(req): Json<PostMessageRequest>,
) -> impl IntoResponse {
    if req.expiry <= Utc::now() {
        return (StatusCode::BAD_REQUEST, "expiry is in the past").into_response();
    }

    let msg = GossipMessage {
        content: req.content,
        expiry: req.expiry,
    };

    let hash = msg.content_hash();

    match state.store.try_insert(msg.clone()) {
        InsertResult::Inserted => {
            let encoded = serde_json::to_vec(&WireMessage::Gossip(msg))
                .expect("WireMessage serialization cannot fail");
            if state
                .cmd_tx
                .send(PeerCommand::Broadcast { msg: Bytes::from(encoded) })
                .await
                .is_err()
            {
                warn!("PeerManager channel closed; message stored locally but not broadcast");
            }
        }
        InsertResult::AlreadySeen => {
            // Idempotent — return the hash as if it were new.
        }
        InsertResult::Expired => {
            return (StatusCode::BAD_REQUEST, "expiry is in the past").into_response();
        }
    }

    (StatusCode::CREATED, Json(PostMessageResponse { hash: hex::encode(hash) })).into_response()
}

async fn list_messages(State(state): State<AppState>) -> Json<Vec<MessageItem>> {
    let msgs = state.store.list_live();
    Json(
        msgs.into_iter()
            .map(|m| MessageItem {
                content: m.content,
                expiry: m.expiry,
            })
            .collect(),
    )
}

async fn list_peers(State(state): State<AppState>) -> Json<Vec<String>> {
    let (tx, rx) = oneshot::channel::<Vec<NodeId>>();
    let _ = state.cmd_tx.send(PeerCommand::ListPeers { reply: tx }).await;
    // If PeerManager has exited, the oneshot sender is dropped and rx.await returns
    // RecvError; unwrap_or_default() maps that to an empty Vec, which is correct.
    let peers = rx.await.unwrap_or_default();
    Json(peers.iter().map(node_id_to_base58).collect())
}
