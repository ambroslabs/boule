use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{error, warn};

use crate::p2p::{P2pEvent, PeerId};
use crate::wire::WireMessage;

const MAX_FRAME_LEN: usize = 1024 * 1024; // 1 MB

pub fn make_framed(stream: TcpStream) -> Framed<TcpStream, LengthDelimitedCodec> {
    let codec = LengthDelimitedCodec::builder()
        .max_frame_length(MAX_FRAME_LEN)
        .new_codec();
    Framed::new(stream, codec)
}

pub async fn run(
    peer_id: PeerId,
    stream: TcpStream,
    mut write_rx: mpsc::Receiver<WireMessage>,
    event_tx: mpsc::Sender<P2pEvent>,
) {
    let mut framed = make_framed(stream);

    let _ = event_tx
        .send(P2pEvent::PeerConnected { peer_id })
        .await;

    loop {
        tokio::select! {
            // Incoming frame from peer
            result = framed.next() => {
                match result {
                    Some(Ok(buf)) => {
                        match serde_json::from_slice::<WireMessage>(&buf) {
                            Ok(msg) => {
                                let _ = event_tx
                                    .send(P2pEvent::MessageReceived { peer_id, msg })
                                    .await;
                            }
                            Err(e) => {
                                warn!("failed to deserialize message from {peer_id}: {e}");
                            }
                        }
                    }
                    Some(Err(e)) => {
                        error!("read error from {peer_id}: {e}");
                        break;
                    }
                    None => {
                        // EOF
                        break;
                    }
                }
            }

            // Outgoing message to peer
            msg = write_rx.recv() => {
                match msg {
                    Some(msg) => {
                        match serde_json::to_vec(&msg) {
                            Ok(encoded) => {
                                if let Err(e) = framed.send(Bytes::from(encoded)).await {
                                    error!("write error to {peer_id}: {e}");
                                    break;
                                }
                            }
                            Err(e) => {
                                error!("failed to serialize message for {peer_id}: {e}");
                            }
                        }
                    }
                    None => {
                        // write channel closed — we're being shut down
                        break;
                    }
                }
            }
        }
    }

    let _ = event_tx
        .send(P2pEvent::PeerDisconnected { peer_id })
        .await;
}
