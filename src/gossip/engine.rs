use std::sync::Arc;

use tracing::{info, warn};

use crate::gossip::store::GossipStore;
use crate::gossip::InsertResult;
use crate::p2p::{PeerCommand, PeerEvent};
use crate::wire::WireMessage;

pub async fn run(
    mut event_rx: tokio::sync::mpsc::Receiver<PeerEvent>,
    cmd_tx: tokio::sync::mpsc::Sender<PeerCommand>,
    store: Arc<GossipStore>,
) {
    while let Some(event) = event_rx.recv().await {
        match event {
            PeerEvent::PeerConnected { peer_id } => {
                info!("peer connected: {peer_id}");
            }
            PeerEvent::PeerDisconnected { peer_id } => {
                info!("peer disconnected: {peer_id}");
            }
            PeerEvent::MessageReceived { peer_id, msg } => {
                let WireMessage::Gossip(gossip_msg) = msg.clone();
                match store.try_insert(gossip_msg) {
                    InsertResult::Inserted => {
                        info!("gossip message inserted, broadcasting (from {peer_id})");
                        let _ = cmd_tx.send(PeerCommand::Broadcast { msg }).await;
                    }
                    InsertResult::AlreadySeen => {
                        // normal dedup — no log spam
                    }
                    InsertResult::Expired => {
                        warn!("received expired gossip message from {peer_id}, discarding");
                    }
                }
            }
        }
    }
}
