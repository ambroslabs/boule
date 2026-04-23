use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use parking_lot::RwLock;
use tokio::sync::mpsc;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::error;

use crate::p2p::manager::{AnyStream, ManagerMsg};
use crate::p2p::tls::{NodeId, node_id_to_base58};

/// Global transport-level cap. Acts as the codec's `max_frame_length`, so a
/// peer that sends a length prefix above this is rejected before any body
/// bytes are buffered. Protocols that register an explicit
/// `max_frame_bytes <= DEFAULT_MAX_FRAME_LEN` are additionally checked after
/// the frame is read.
pub const DEFAULT_MAX_FRAME_LEN: usize = 1024 * 1024; // 1 MB

/// Shared per-protocol frame-size cap registry, populated by
/// `PeerCommand::RegisterProtocol`. Each connection task consults it to
/// reject oversize frames for protocols that declared a tighter cap than
/// [`DEFAULT_MAX_FRAME_LEN`].
pub type ProtocolCaps = Arc<RwLock<HashMap<u8, usize>>>;

pub async fn run(
    node_id: NodeId,
    stream: AnyStream,
    mut write_rx: mpsc::Receiver<Bytes>,
    inbound_tx: mpsc::Sender<ManagerMsg>,
    protocol_caps: ProtocolCaps,
) {
    let id = node_id_to_base58(&node_id);
    let codec = LengthDelimitedCodec::builder()
        .max_frame_length(DEFAULT_MAX_FRAME_LEN)
        .new_codec();
    let mut framed = Framed::new(stream, codec);

    loop {
        tokio::select! {
            result = framed.next() => {
                match result {
                    Some(Ok(buf)) => {
                        if let Some(&protocol_id) = buf.first() {
                            if let Some(cap) = protocol_caps.read().get(&protocol_id).copied() {
                                if buf.len() > cap {
                                    error!(
                                        "oversize frame from {id}: protocol {protocol_id:#04x} frame is {} bytes > cap {} bytes",
                                        buf.len(),
                                        cap
                                    );
                                    break;
                                }
                            }
                        }
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::{BufMut, BytesMut};
    use tokio::io::{AsyncWriteExt, duplex};

    use super::*;

    fn nid(byte: u8) -> NodeId {
        [byte; 32]
    }

    fn empty_caps() -> ProtocolCaps {
        Arc::new(RwLock::new(HashMap::new()))
    }

    /// Boilerplate: spawn a connection task against a duplex stream. Returns
    /// `(remote_end, write_tx, inbound_rx, join_handle)`.
    fn spawn_connection() -> (
        tokio::io::DuplexStream,
        mpsc::Sender<Bytes>,
        mpsc::Receiver<ManagerMsg>,
        tokio::task::JoinHandle<()>,
    ) {
        spawn_connection_with_caps(empty_caps())
    }

    fn spawn_connection_with_caps(
        caps: ProtocolCaps,
    ) -> (
        tokio::io::DuplexStream,
        mpsc::Sender<Bytes>,
        mpsc::Receiver<ManagerMsg>,
        tokio::task::JoinHandle<()>,
    ) {
        let (local, remote) = duplex(64 * 1024);
        let (write_tx, write_rx) = mpsc::channel::<Bytes>(16);
        let (inbound_tx, inbound_rx) = mpsc::channel::<ManagerMsg>(16);
        let join = tokio::spawn(async move {
            run(nid(7), Box::new(local), write_rx, inbound_tx, caps).await;
        });
        (remote, write_tx, inbound_rx, join)
    }

    /// Encode a length-prefixed frame by hand, matching the codec's wire
    /// format (4-byte big-endian length, then body).
    fn length_prefixed(body: &[u8]) -> BytesMut {
        let mut buf = BytesMut::with_capacity(4 + body.len());
        buf.put_u32(body.len() as u32);
        buf.extend_from_slice(body);
        buf
    }

    #[tokio::test]
    async fn frame_round_trips_via_write_channel() {
        let (mut remote, write_tx, _inbound_rx, _join) = spawn_connection();

        write_tx.send(Bytes::from_static(b"hello")).await.unwrap();

        let mut out = vec![0u8; 9];
        use tokio::io::AsyncReadExt;
        remote.read_exact(&mut out).await.unwrap();
        assert_eq!(out, vec![0, 0, 0, 5, b'h', b'e', b'l', b'l', b'o']);
    }

    #[tokio::test]
    async fn zero_length_body_round_trips() {
        let (mut remote, write_tx, mut inbound_rx, _join) = spawn_connection();

        // Send an empty frame outbound and verify it's framed as a 0-length
        // prefix, then send one back inbound and verify it's delivered as an
        // empty payload (not dropped).
        write_tx.send(Bytes::new()).await.unwrap();
        use tokio::io::AsyncReadExt;
        let mut hdr = [0u8; 4];
        remote.read_exact(&mut hdr).await.unwrap();
        assert_eq!(hdr, [0, 0, 0, 0]);

        // Now push an inbound zero-length frame and confirm the connection
        // task surfaces it.
        let frame = length_prefixed(b"");
        remote.write_all(&frame).await.unwrap();

        let msg = tokio::time::timeout(Duration::from_millis(500), inbound_rx.recv())
            .await
            .expect("timed out")
            .expect("connection exited");
        match msg {
            ManagerMsg::InboundMessage { node_id, msg } => {
                assert_eq!(node_id, nid(7));
                assert!(msg.is_empty());
            }
            _ => panic!("expected InboundMessage, got a different ManagerMsg variant"),
        }
    }

    #[tokio::test]
    async fn partial_read_is_reassembled() {
        let (mut remote, _write_tx, mut inbound_rx, _join) = spawn_connection();

        let body = b"abcdefghijklmnop"; // 16 bytes
        let mut buf = length_prefixed(body);
        // Split the frame into two chunks mid-body: header + first 5 bytes,
        // then the rest. The framed codec must reassemble them into a
        // single message.
        let second = buf.split_off(4 + 5);
        remote.write_all(&buf).await.unwrap();
        // Small delay so the codec has a chance to read the partial chunk
        // before the second arrives — this is the "partial read" scenario.
        tokio::time::sleep(Duration::from_millis(20)).await;
        remote.write_all(&second).await.unwrap();

        let msg = tokio::time::timeout(Duration::from_millis(500), inbound_rx.recv())
            .await
            .expect("timed out")
            .expect("connection exited");
        match msg {
            ManagerMsg::InboundMessage { msg, .. } => assert_eq!(msg.as_ref(), body),
            _ => panic!("expected InboundMessage, got a different ManagerMsg variant"),
        }
    }

    #[tokio::test]
    async fn eof_mid_frame_exits_cleanly() {
        let (mut remote, _write_tx, mut inbound_rx, join) = spawn_connection();

        // Send a length prefix that promises 16 bytes, then only send 4.
        let mut header = BytesMut::new();
        header.put_u32(16);
        remote.write_all(&header).await.unwrap();
        remote.write_all(b"part").await.unwrap();
        // Drop `remote` → EOF on the connection's read half mid-frame.
        drop(remote);

        // The connection task should exit — `run` returns. No frame should
        // be published upstream.
        tokio::time::timeout(Duration::from_millis(500), join)
            .await
            .expect("connection task did not exit after EOF mid-frame")
            .expect("connection task panicked");
        // Receiving returns None because the connection task's sender was
        // dropped when the function returned.
        assert!(inbound_rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected() {
        let (mut remote, _write_tx, mut inbound_rx, join) = spawn_connection();

        // Send a length prefix > DEFAULT_MAX_FRAME_LEN so the codec returns
        // an error before reading the body.
        let mut header = BytesMut::new();
        header.put_u32((DEFAULT_MAX_FRAME_LEN as u32) + 1);
        remote.write_all(&header).await.unwrap();

        // The connection should exit with an error, not surface the frame.
        tokio::time::timeout(Duration::from_millis(500), join)
            .await
            .expect("connection task did not exit after oversized frame")
            .expect("connection task panicked");
        assert!(inbound_rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn per_protocol_cap_rejects_oversize_frame() {
        // Register protocol 0x42 with a tight 100-byte cap. A 50-byte body
        // (tag + payload = 51 bytes) passes through; a 200-byte body closes
        // the connection before the manager ever sees it.
        let caps = Arc::new(RwLock::new(HashMap::from([(0x42u8, 100usize)])));
        let (mut remote, _write_tx, mut inbound_rx, join) = spawn_connection_with_caps(caps);

        // Small frame under the cap: accepted.
        let mut ok = BytesMut::new();
        ok.put_u8(0x42);
        ok.extend_from_slice(&[0u8; 50]);
        remote.write_all(&length_prefixed(&ok)).await.unwrap();
        let msg = tokio::time::timeout(Duration::from_millis(500), inbound_rx.recv())
            .await
            .expect("timed out")
            .expect("connection exited");
        match msg {
            ManagerMsg::InboundMessage { msg, .. } => assert_eq!(msg.len(), 51),
            _ => panic!("expected InboundMessage"),
        }

        // Large frame over the cap: connection closes.
        let mut big = BytesMut::new();
        big.put_u8(0x42);
        big.extend_from_slice(&[0u8; 200]);
        remote.write_all(&length_prefixed(&big)).await.unwrap();

        tokio::time::timeout(Duration::from_millis(500), join)
            .await
            .expect("connection task did not exit after per-protocol oversize")
            .expect("connection task panicked");
        // No further InboundMessage for the oversize frame.
        assert!(inbound_rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn per_protocol_cap_ignored_for_unknown_protocol_id() {
        // Only protocol 0x42 has a cap registered; a frame tagged 0x99 is
        // bounded only by DEFAULT_MAX_FRAME_LEN.
        let caps = Arc::new(RwLock::new(HashMap::from([(0x42u8, 100usize)])));
        let (mut remote, _write_tx, mut inbound_rx, _join) = spawn_connection_with_caps(caps);

        let mut msg = BytesMut::new();
        msg.put_u8(0x99);
        msg.extend_from_slice(&[0u8; 500]); // well over 0x42's cap
        remote.write_all(&length_prefixed(&msg)).await.unwrap();

        let got = tokio::time::timeout(Duration::from_millis(500), inbound_rx.recv())
            .await
            .expect("timed out")
            .expect("connection exited");
        match got {
            ManagerMsg::InboundMessage { msg, .. } => assert_eq!(msg.len(), 501),
            _ => panic!("expected InboundMessage"),
        }
    }

    #[tokio::test]
    async fn write_channel_closed_exits_loop() {
        let (_remote, write_tx, _inbound_rx, join) = spawn_connection();
        drop(write_tx);
        // With no way to send outbound frames, and no inbound bytes to
        // read, the connection task should eventually notice and terminate.
        // Note: the select loop also reads inbound, so it won't exit just
        // from write_rx being closed — the test confirms the process
        // doesn't panic when we drop the other side.
        drop(_remote);
        tokio::time::timeout(Duration::from_millis(500), join)
            .await
            .expect("connection task did not exit")
            .expect("connection task panicked");
    }
}
