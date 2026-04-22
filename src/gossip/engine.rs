use std::sync::Arc;

use bytes::Bytes;
use tracing::{info, warn};

use crate::gossip::InsertResult;
use crate::gossip::store::GossipStore;
use crate::gossip::wire::WireMessage;
use crate::p2p::tls::node_id_to_base58;
use crate::p2p::{ProtocolEvent, ProtocolHandle, ProtocolOutbound};

pub async fn run(handle: ProtocolHandle, store: Arc<GossipStore>) {
    let ProtocolHandle {
        send_tx,
        mut event_rx,
    } = handle;

    while let Some(event) = event_rx.recv().await {
        match event {
            ProtocolEvent::PeerConnected { node_id } => {
                info!("peer connected: {}", node_id_to_base58(&node_id));
            }
            ProtocolEvent::PeerDisconnected { node_id } => {
                info!("peer disconnected: {}", node_id_to_base58(&node_id));
            }
            ProtocolEvent::Message { from, payload } => {
                let id = node_id_to_base58(&from);
                match serde_json::from_slice::<WireMessage>(&payload) {
                    Ok(WireMessage::Gossip(gossip_msg)) => {
                        match store.try_insert(gossip_msg.clone()) {
                            InsertResult::Inserted => {
                                info!("gossip message inserted, broadcasting (from {id})");
                                match serde_json::to_vec(&WireMessage::Gossip(gossip_msg)) {
                                    Ok(encoded) => {
                                        let _ = send_tx
                                            .send(ProtocolOutbound::Broadcast(Bytes::from(encoded)))
                                            .await;
                                    }
                                    Err(e) => warn!("failed to re-serialize gossip message: {e}"),
                                }
                            }
                            InsertResult::AlreadySeen => {}
                            InsertResult::Expired => {
                                warn!("received expired gossip message from {id}, discarding");
                            }
                        }
                    }
                    Err(e) => {
                        warn!("failed to deserialize message from {id}: {e}");
                    }
                }
            }
        }
    }
}
