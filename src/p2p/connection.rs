use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::error;

use crate::p2p::manager::{AnyStream, ManagerMsg};
use crate::p2p::tls::{node_id_to_base58, NodeId};

const MAX_FRAME_LEN: usize = 1024 * 1024; // 1 MB

pub async fn run(
    node_id: NodeId,
    stream: AnyStream,
    mut write_rx: mpsc::Receiver<Bytes>,
    inbound_tx: mpsc::Sender<ManagerMsg>,
) {
    let id = node_id_to_base58(&node_id);
    let codec = LengthDelimitedCodec::builder()
        .max_frame_length(MAX_FRAME_LEN)
        .new_codec();
    let mut framed = Framed::new(stream, codec);

    loop {
        tokio::select! {
            result = framed.next() => {
                match result {
                    Some(Ok(buf)) => {
                        let _ = inbound_tx
                            .send(ManagerMsg::InboundMessage { node_id, msg: Bytes::from(buf) })
                            .await;
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
                        if let Err(e) = framed.send(msg).await {
                            error!("write error to {id}: {e}");
                            break;
                        }
                    }
                    None => break, // write channel closed — shutting down
                }
            }
        }
    }
}
