use std::sync::Arc;

use tracing::{info, warn};

use crate::gossip::store::GossipStore;
use crate::gossip::InsertResult;
use crate::p2p::tls::node_id_to_base58;
use crate::p2p::{PeerCommand, PeerEvent};
use crate::wire::WireMessage;

pub async fn run(
    mut event_rx: tokio::sync::mpsc::Receiver<PeerEvent>,
    cmd_tx: tokio::sync::mpsc::Sender<PeerCommand>,
    store: Arc<GossipStore>,
) {
    while let Some(event) = event_rx.recv().await {
        match event {
            PeerEvent::PeerConnected { node_id } => {
                info!("peer connected: {}", node_id_to_base58(&node_id));
            }
            PeerEvent::PeerDisconnected { node_id } => {
                info!("peer disconnected: {}", node_id_to_base58(&node_id));
            }
            PeerEvent::MessageReceived { node_id, msg } => {
                let id = node_id_to_base58(&node_id);
                let WireMessage::Gossip(gossip_msg) = msg.clone();
                match store.try_insert(gossip_msg) {
                    InsertResult::Inserted => {
                        info!("gossip message inserted, broadcasting (from {id})");
                        let _ = cmd_tx.send(PeerCommand::Broadcast { msg }).await;
                    }
                    InsertResult::AlreadySeen => {
                        // normal dedup — no log spam
                    }
                    InsertResult::Expired => {
                        warn!("received expired gossip message from {id}, discarding");
                    }
                }
            }
        }
    }
}
