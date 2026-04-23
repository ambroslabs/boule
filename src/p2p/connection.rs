use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use parking_lot::RwLock;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{debug, error};

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

/// Upper bound on how long we'll wait for the TLS `close_notify` + TCP FIN
/// round-trip on the shutdown path. A dead peer must not be able to pin the
/// task after the read/write loop has already decided to exit.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

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
                        // rustls surfaces "peer closed TCP without
                        // close_notify" as `UnexpectedEof`. That's a
                        // peer-side hygiene issue — nothing actionable on
                        // our end — so don't log it as ERROR. Genuine I/O
                        // failures (decrypt errors, malformed frames) still
                        // surface at error level.
                        if e.kind() == std::io::ErrorKind::UnexpectedEof {
                            debug!("peer {id} closed without TLS close_notify: {e}");
                        } else {
                            error!("read error from {id}: {e}");
                        }
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

    // Orderly close: flush any pending writes and send TLS `close_notify`
    // before dropping the TCP stream. `poll_shutdown` on a rustls stream
    // emits close_notify; on the sim's in-memory stream it's a no-op. Guard
    // with a timeout so a dead peer can't wedge us.
    let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, framed.get_mut().shutdown()).await;
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll};

    use bytes::{BufMut, BytesMut};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, duplex};

    use super::*;

    fn nid(byte: u8) -> NodeId {
        [byte; 32]
    }

    fn empty_caps() -> ProtocolCaps {
        Arc::new(RwLock::new(HashMap::new()))
    }

    /// Stream wrapper that records whether `poll_shutdown` was invoked. Lets
    /// the unit tests assert the connection task flushes a clean close on
    /// exit, without having to stand up a real TLS handshake.
    struct ShutdownSpy<S> {
        inner: S,
        shutdown_called: Arc<AtomicBool>,
    }

    impl<S: AsyncRead + Unpin> AsyncRead for ShutdownSpy<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for ShutdownSpy<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.shutdown_called.store(true, Ordering::SeqCst);
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
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

    /// On the orderly-shutdown path, the connection task must call
    /// `poll_shutdown` on the underlying stream. Over TLS this is what
    /// emits `close_notify`; the `ShutdownSpy` wrapper lets us verify the
    /// call without the cost of standing up a real TLS handshake.
    #[tokio::test]
    async fn orderly_exit_calls_shutdown_on_stream() {
        let (local, remote) = duplex(64 * 1024);
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let spy = ShutdownSpy {
            inner: local,
            shutdown_called: Arc::clone(&shutdown_flag),
        };

        let (write_tx, write_rx) = mpsc::channel::<Bytes>(16);
        let (inbound_tx, _inbound_rx) = mpsc::channel::<ManagerMsg>(16);
        let join = tokio::spawn(async move {
            run(nid(7), Box::new(spy), write_rx, inbound_tx, empty_caps()).await;
        });

        // Initiate orderly shutdown from our side: drop the write sender
        // and close the remote so the read half observes EOF. The loop
        // breaks and then must flush a clean close.
        drop(write_tx);
        drop(remote);

        tokio::time::timeout(Duration::from_secs(2), join)
            .await
            .expect("connection task did not exit")
            .expect("connection task panicked");

        assert!(
            shutdown_flag.load(Ordering::SeqCst),
            "connection::run must call poll_shutdown on orderly exit \
             (so TLS close_notify is sent on real connections)"
        );
    }

    // ── Property tests (issue #52) ──────────────────────────────────────────

    use proptest::prelude::*;
    use tokio_util::codec::{Decoder, Encoder};

    fn fresh_codec() -> LengthDelimitedCodec {
        LengthDelimitedCodec::builder()
            .max_frame_length(DEFAULT_MAX_FRAME_LEN)
            .new_codec()
    }

    proptest! {
        // Any body up to the cap encodes into a single length-prefixed frame
        // that decodes back to the original bytes. Catches off-by-one errors
        // at buffer boundaries and the empty-body case in one sweep.
        #[test]
        fn prop_length_delimited_round_trips(
            body in proptest::collection::vec(any::<u8>(), 0..=8192),
        ) {
            let mut encoder = fresh_codec();
            let mut buf = BytesMut::new();
            encoder.encode(Bytes::from(body.clone()), &mut buf).unwrap();

            let mut decoder = fresh_codec();
            let frame = decoder.decode(&mut buf).unwrap().expect("complete frame decodes");
            prop_assert_eq!(frame.as_ref(), body.as_slice());

            // Anything left in the buffer after one frame came out is a bug.
            prop_assert!(buf.is_empty());
            prop_assert!(decoder.decode(&mut buf).unwrap().is_none());
        }

        // Feeding arbitrary bytes to the decoder must never panic. The
        // codec either returns an incomplete frame (Ok(None)), a valid
        // frame whose length prefix fit the cap (Ok(Some(_))), or an
        // oversize / truncated-prefix error — none of which may unwind.
        #[test]
        fn prop_decode_arbitrary_bytes_never_panics(
            bytes in proptest::collection::vec(any::<u8>(), 0..=4096),
        ) {
            let mut decoder = fresh_codec();
            let mut buf = BytesMut::from(bytes.as_slice());
            // Drain until the decoder stops producing frames or errors out.
            // A malformed / oversize length prefix must surface as Err and
            // must not panic regardless of what the random bytes looked like.
            for _ in 0..8 {
                match decoder.decode(&mut buf) {
                    Ok(Some(_)) => continue,
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        }
    }

    /// End-to-end orderly shutdown over real TLS: one side runs
    /// `connection::run` and closes cleanly; the other side reads framed
    /// bytes and must see a clean EOF (`None`) instead of rustls'
    /// `UnexpectedEof` ("peer closed connection without sending TLS
    /// close_notify").
    #[tokio::test]
    async fn tls_peer_sees_clean_eof_on_orderly_shutdown() {
        use rcgen::{KeyPair, PKCS_ED25519};
        use tokio_rustls::{TlsConnector, rustls};
        use zeroize::Zeroizing;

        use crate::p2p::identity::NodeIdentity;
        use crate::p2p::tls::TlsIdentity;

        fn fresh_tls() -> Arc<TlsIdentity> {
            let kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
            let id = NodeIdentity {
                pkcs8_der: Zeroizing::new(kp.serialize_der()),
            };
            Arc::new(TlsIdentity::from_identity(&id).unwrap())
        }

        let client_id = fresh_tls();
        let server_id = fresh_tls();

        let (client_io, server_io) = duplex(64 * 1024);
        let connector = TlsConnector::from(Arc::clone(&client_id.client_config));
        let acceptor = server_id.acceptor.clone();

        // Drive the handshake — accept on a spawned task, connect on the
        // current one, so both sides make progress concurrently.
        let accept_task = tokio::spawn(async move { acceptor.accept(server_io).await });
        let server_name = rustls::pki_types::ServerName::try_from("ambros-p2p").unwrap();
        let client_tls = connector.connect(server_name, client_io).await.unwrap();
        let server_tls = accept_task.await.unwrap().unwrap();

        // Client side runs the production connection task.
        let (client_write_tx, client_write_rx) = mpsc::channel::<Bytes>(16);
        let (client_inbound_tx, _client_inbound_rx) = mpsc::channel::<ManagerMsg>(16);
        let client_join = tokio::spawn(async move {
            run(
                nid(7),
                Box::new(client_tls),
                client_write_rx,
                client_inbound_tx,
                empty_caps(),
            )
            .await;
        });

        // Trigger orderly close on the client side.
        drop(client_write_tx);

        // Server side reads from the TLS stream with the same framing. It
        // must observe a clean EOF rather than an `UnexpectedEof` that
        // production code would surface as ERROR.
        let codec = LengthDelimitedCodec::builder()
            .max_frame_length(DEFAULT_MAX_FRAME_LEN)
            .new_codec();
        let mut server_framed = Framed::new(server_tls, codec);

        let result = tokio::time::timeout(Duration::from_secs(5), server_framed.next())
            .await
            .expect("server-side framed read timed out waiting for EOF");

        match result {
            None => { /* clean EOF — close_notify was received */ }
            Some(Ok(frame)) => panic!("expected EOF, got a frame of {} bytes", frame.len()),
            Some(Err(e)) => panic!(
                "expected clean EOF, got read error (kind={:?}): {e}",
                e.kind()
            ),
        }

        client_join.await.expect("client connection task panicked");
    }
}
