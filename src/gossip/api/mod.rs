pub mod types;

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use bytes::Bytes;
use tokio::sync::mpsc;
use tracing::warn;

use crate::clock::Clock;
use crate::gossip::store::GossipStore;
use crate::gossip::wire::WireMessage;
use crate::gossip::{GossipMessage, InsertResult};
use crate::p2p::ProtocolOutbound;

use types::{MessageItem, PostMessageRequest, PostMessageResponse};

#[derive(Clone)]
struct AppState {
    store: Arc<GossipStore>,
    gossip_tx: mpsc::Sender<ProtocolOutbound>,
    clock: Arc<dyn Clock>,
}

pub fn router(
    store: Arc<GossipStore>,
    gossip_tx: mpsc::Sender<ProtocolOutbound>,
    clock: Arc<dyn Clock>,
) -> Router {
    let state = AppState {
        store,
        gossip_tx,
        clock,
    };
    Router::new()
        .route("/messages", get(list_messages).post(post_message))
        .with_state(state)
}

async fn post_message(
    State(state): State<AppState>,
    Json(req): Json<PostMessageRequest>,
) -> impl IntoResponse {
    let now = state.clock.now_wall();
    if req.expiry <= now {
        return (StatusCode::BAD_REQUEST, "expiry is in the past").into_response();
    }

    let msg = GossipMessage {
        content: req.content,
        expiry: req.expiry,
    };

    let hash = msg.content_hash();

    match state.store.try_insert(msg.clone(), now) {
        InsertResult::Inserted => {
            let encoded = serde_json::to_vec(&WireMessage::Gossip(msg))
                .expect("WireMessage serialization cannot fail");
            if state
                .gossip_tx
                .send(ProtocolOutbound::Broadcast(Bytes::from(encoded)))
                .await
                .is_err()
            {
                warn!("gossip send channel closed; message stored locally but not broadcast");
            }
        }
        InsertResult::AlreadySeen => {
            // Idempotent — return the hash as if it were new.
        }
        InsertResult::Expired => {
            return (StatusCode::BAD_REQUEST, "expiry is in the past").into_response();
        }
    }

    (
        StatusCode::CREATED,
        Json(PostMessageResponse {
            hash: hex::encode(hash),
        }),
    )
        .into_response()
}

async fn list_messages(State(state): State<AppState>) -> Json<Vec<MessageItem>> {
    let msgs = state.store.list_live(state.clock.now_wall());
    Json(
        msgs.into_iter()
            .map(|m| MessageItem {
                content: m.content,
                expiry: m.expiry,
            })
            .collect(),
    )
}
