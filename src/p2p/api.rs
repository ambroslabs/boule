use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use tokio::sync::{mpsc, oneshot};

use super::tls::node_id_to_base58;
use super::{NodeId, PeerCommand};

pub fn router(cmd_tx: mpsc::Sender<PeerCommand>) -> Router {
    Router::new()
        .route("/peers", get(list_peers))
        .with_state(cmd_tx)
}

async fn list_peers(State(cmd_tx): State<mpsc::Sender<PeerCommand>>) -> Json<Vec<String>> {
    let (tx, rx) = oneshot::channel::<Vec<NodeId>>();
    let _ = cmd_tx.send(PeerCommand::ListPeers { reply: tx }).await;
    let peers = rx.await.unwrap_or_default();
    Json(peers.iter().map(node_id_to_base58).collect())
}
