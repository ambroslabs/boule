use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{error, warn};

use crate::p2p::tls::{node_id_to_base58, NodeId, TlsStream};
use crate::p2p::PeerEvent;
use crate::wire::WireMessage;

const MAX_FRAME_LEN: usize = 1024 * 1024; // 1 MB

pub async fn run(
    node_id: NodeId,
    stream: TlsStream,
    mut write_rx: mpsc::Receiver<WireMessage>,
    event_tx: mpsc::Sender<PeerEvent>,
) {
    let id = node_id_to_base58(&node_id);
    let codec = LengthDelimitedCodec::builder()
        .max_frame_length(MAX_FRAME_LEN)
        .new_codec();
    let mut framed = Framed::new(stream, codec);

    let _ = event_tx.send(PeerEvent::PeerConnected { node_id }).await;

    loop {
        tokio::select! {
            result = framed.next() => {
                match result {
                    Some(Ok(buf)) => {
                        match serde_json::from_slice::<WireMessage>(&buf) {
                            Ok(msg) => {
                                let _ = event_tx
                                    .send(PeerEvent::MessageReceived { node_id, msg })
                                    .await;
                            }
                            Err(e) => {
                                warn!("failed to deserialize message from {id}: {e}");
                            }
                        }
                    }
                    Some(Err(e)) => {
                        error!("read error from {id}: {e}");
                        break;
                    }
                    None => break, // EOF
                }
            }

            msg = write_rx.recv() => {
                match msg {
                    Some(msg) => {
                        match serde_json::to_vec(&msg) {
                            Ok(encoded) => {
                                if let Err(e) = framed.send(Bytes::from(encoded)).await {
                                    error!("write error to {id}: {e}");
                                    break;
                                }
                            }
                            Err(e) => {
                                error!("failed to serialize message for {id}: {e}");
                            }
                        }
                    }
                    None => break, // write channel closed — shutting down
                }
            }
        }
    }

    if event_tx
        .send(PeerEvent::PeerDisconnected { node_id })
        .await
        .is_err()
    {
        warn!("event channel closed before PeerDisconnected could be sent for {id}");
    }
}
