use std::sync::Arc;

use bytes::Bytes;
use tracing::{info, warn};

use crate::clock::Clock;
use crate::gossip::InsertResult;
use crate::gossip::store::GossipStore;
use crate::gossip::wire::WireMessage;
use crate::p2p::tls::node_id_to_base58;
use crate::p2p::{ProtocolEvent, ProtocolHandle, ProtocolOutbound};

pub async fn run(handle: ProtocolHandle, store: Arc<GossipStore>, clock: Arc<dyn Clock>) {
    let ProtocolHandle {
        send_tx,
        mut event_rx,
    } = handle;

    while let Some(event) = event_rx.recv().await {
        match event {
            ProtocolEvent::PeerConnected { node_id, .. } => {
                info!("peer connected: {}", node_id_to_base58(&node_id));
            }
            ProtocolEvent::PeerDisconnected { node_id } => {
                info!("peer disconnected: {}", node_id_to_base58(&node_id));
            }
            ProtocolEvent::Message { from, payload } => {
                let id = node_id_to_base58(&from);
                match serde_json::from_slice::<WireMessage>(&payload) {
                    Ok(WireMessage::Gossip(gossip_msg)) => {
                        match store.try_insert(gossip_msg.clone(), clock.now_wall()) {
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

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use bytes::{BufMut, BytesMut};
    use tokio::io::{AsyncWriteExt, duplex};
    use tokio::sync::{broadcast, mpsc, oneshot};

    use crate::gossip::{self, PROTOCOL_ID};
    use crate::p2p::manager::{self, ManagerMsg};
    use crate::p2p::{NodeId, PeerCommand};

    fn nid(byte: u8) -> NodeId {
        [byte; 32]
    }

    fn addr() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    /// Oversize gossip frame: the p2p multiplexer must close the
    /// connection before the bytes are ever decoded. Guards the claim in
    /// #68 that Byzantine peers can't label a 1 MB payload as gossip when
    /// gossip has registered a tighter cap.
    #[tokio::test]
    async fn oversize_gossip_frame_closes_connection() {
        let (cmd_tx, cmd_rx) = mpsc::channel::<PeerCommand>(16);
        let (internal_tx, internal_rx) = mpsc::channel::<ManagerMsg>(64);
        let (peer_gone_tx, mut peer_gone_rx) = broadcast::channel::<NodeId>(16);
        let (discovery_tx, _) = broadcast::channel::<crate::p2p::overlay::DiscoveryEvent>(16);
        let itx = internal_tx.clone();
        tokio::spawn(async move {
            manager::run(
                nid(1),
                cmd_rx,
                internal_rx,
                itx,
                peer_gone_tx,
                discovery_tx,
                None,
            )
            .await;
        });

        // Register gossip with its declared cap so the connection task
        // rejects anything larger at framing time.
        let (reg_tx, reg_rx) = oneshot::channel();
        cmd_tx
            .send(PeerCommand::RegisterProtocol {
                id: PROTOCOL_ID,
                max_frame_bytes: Some(gossip::MAX_FRAME_BYTES),
                reply: reg_tx,
            })
            .await
            .unwrap();
        let _gossip_handle = reg_rx.await.unwrap();

        // Attach a peer.
        let (local, mut remote) = duplex(256 * 1024);
        internal_tx
            .send(ManagerMsg::NewConnection {
                node_id: nid(5),
                addr: addr(),
                direction: crate::p2p::limits::Direction::Inbound,
                stream: Box::new(local),
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Write a gossip-tagged frame whose body exceeds MAX_FRAME_BYTES.
        let body_len = gossip::MAX_FRAME_BYTES + 32;
        let mut buf = BytesMut::with_capacity(4 + body_len);
        buf.put_u32(body_len as u32);
        buf.put_u8(PROTOCOL_ID);
        buf.extend_from_slice(&vec![0u8; body_len - 1]);
        remote.write_all(&buf).await.unwrap();

        let gone = tokio::time::timeout(Duration::from_millis(500), peer_gone_rx.recv())
            .await
            .expect("peer-gone broadcast times out")
            .expect("peer-gone channel closed");
        assert_eq!(gone, nid(5));
    }
}
