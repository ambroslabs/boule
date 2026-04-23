//! HTTP admin surface for the gossip overlay.
//!
//! Mounted into the node's main [`axum::Router`] alongside the peer admin
//! endpoints. Endpoints:
//!
//! - `POST /messages` — submit a new gossip message. Stored locally and
//!   broadcast to every connected peer. See [`types::PostMessageRequest`].
//! - `GET /messages` — list currently live messages (not yet expired).
//!
//! The wire format used between peers is [`wire::WireMessage`](crate::gossip::wire::WireMessage);
//! these HTTP types are independent of that and exist only for the admin
//! surface.

#![warn(missing_docs)]

/// HTTP request/response types. See [`types::PostMessageRequest`] for the
/// primary input shape.
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

/// Build the gossip HTTP router.
///
/// # Parameters
///
/// - `store`: the shared in-memory gossip store. Writes go here; reads
///   flow out of here through `/messages`.
/// - `gossip_tx`: outbound side of the gossip [`ProtocolHandle`](crate::p2p::ProtocolHandle).
///   `POST /messages` pushes a [`ProtocolOutbound::Broadcast`] here so the
///   peer manager fans out the message to every connected peer.
/// - `clock`: wall-clock source used for expiry comparisons.
///
/// # Invariants
///
/// - `store` and `gossip_tx` must correspond to the same registered
///   protocol ID: [`gossip::PROTOCOL_ID`](crate::gossip::PROTOCOL_ID).
///   Mixing up protocol handles would silently route messages to the
///   wrong application.
/// - Works equally whether or not any peer is currently connected; with
///   zero peers `POST /messages` still succeeds locally and the warn log
///   notes that the broadcast channel was closed.
///
/// # Example
///
/// See `main.rs`:
///
/// ```no_run
/// use std::sync::Arc;
///
/// use ambros_p2p::clock::{Clock, TokioClock};
/// use ambros_p2p::gossip::{self, store::GossipStore};
/// use ambros_p2p::p2p::{self, PeerCommand, ProtocolOutbound};
/// use tokio::sync::mpsc;
///
/// # fn wiring(
/// #     p2p_cmd_tx: mpsc::Sender<PeerCommand>,
/// #     gossip_send_tx: mpsc::Sender<ProtocolOutbound>,
/// # ) {
/// let store = Arc::new(GossipStore::new());
/// let clock: Arc<dyn Clock> = Arc::new(TokioClock::new());
/// let app = axum::Router::new()
///     .merge(p2p::api::router(p2p_cmd_tx))
///     .merge(gossip::api::router(store, gossip_send_tx, clock));
/// # let _ = app;
/// # }
/// ```
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
