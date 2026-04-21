pub mod types;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;
use tokio::sync::{mpsc, oneshot};
use tracing::info;

use crate::gossip::store::GossipStore;
use crate::gossip::{GossipMessage, InsertResult};
use crate::p2p::{P2pCommand, PeerId};
use crate::wire::WireMessage;

use types::{MessageItem, PostMessageRequest, PostMessageResponse};

#[derive(Clone)]
struct AppState {
    store: Arc<GossipStore>,
    cmd_tx: mpsc::Sender<P2pCommand>,
}

pub async fn serve(
    store: Arc<GossipStore>,
    cmd_tx: mpsc::Sender<P2pCommand>,
    listen_addr: SocketAddr,
) {
    let state = AppState { store, cmd_tx };

    let app = Router::new()
        .route("/messages", get(list_messages).post(post_message))
        .route("/peers", get(list_peers))
        .with_state(state);

    info!("HTTP API listening on {listen_addr}");
    let listener = tokio::net::TcpListener::bind(listen_addr).await.unwrap();
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
            let _ = state
                .cmd_tx
                .send(P2pCommand::Broadcast {
                    msg: WireMessage::Gossip(msg),
                })
                .await;
        }
        InsertResult::AlreadySeen => {
            // Idempotent — return the hash as if it were new.
        }
        InsertResult::Expired => {
            return (StatusCode::BAD_REQUEST, "expiry is in the past").into_response();
        }
    }

    Json(PostMessageResponse { hash: hex::encode(hash) }).into_response()
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

async fn list_peers(State(state): State<AppState>) -> Json<Vec<PeerId>> {
    let (tx, rx) = oneshot::channel();
    let _ = state.cmd_tx.send(P2pCommand::ListPeers { reply: tx }).await;
    let peers = rx.await.unwrap_or_default();
    Json(peers)
}
