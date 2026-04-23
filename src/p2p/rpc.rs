//! Matched request/response RPC on top of the protocol multiplexer.
//!
//! Opt-in layer: a caller gets a `ProtocolHandle` for a protocol ID (as usual)
//! and hands it to [`RpcBuilder::spawn`] to obtain an [`Rpc`]. Both peers in a
//! conversation must agree to run RPC on the same protocol ID; within that
//! protocol, each endpoint is distinguished by a `u16` method ID.
//!
//! Frame layout inside the protocol payload:
//!
//! ```text
//! | request_id: u64 BE | kind: u8 | method_id: u16 BE | payload: bytes |
//! ```
//!
//! `kind` is one of [`KIND_REQUEST`], [`KIND_RESPONSE`], [`KIND_ERROR`].

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::sync::{mpsc, oneshot};
use tracing::warn;

use crate::clock::{self, Clock};
use crate::p2p::tls::{NodeId, node_id_to_base58};
use crate::p2p::{ProtocolEvent, ProtocolHandle, ProtocolOutbound};

pub const KIND_REQUEST: u8 = 0x01;
pub const KIND_RESPONSE: u8 = 0x02;
pub const KIND_ERROR: u8 = 0x03;

const HEADER_LEN: usize = 8 + 1 + 2;

/// Default ceiling on in-flight requests per peer. Above this, `call` returns
/// [`RpcError::Busy`] immediately.
pub const DEFAULT_MAX_OUTSTANDING_PER_PEER: usize = 256;

/// Payload the server sends on the error frame when the requested method has
/// no handler registered. Small fixed string so callers can detect it.
pub const NO_SUCH_METHOD: &[u8] = b"rpc: no such method";

/// Error cases surfaced by [`Rpc::call`].
#[derive(Debug)]
pub enum RpcError {
    /// The request did not complete within the caller-provided timeout.
    Timeout,
    /// The peer disconnected before a reply arrived.
    PeerGone,
    /// The per-peer outstanding-request limit was already reached.
    Busy,
    /// The RPC task has been shut down (the `ProtocolHandle` it owns was
    /// closed). Calls made after shutdown return this.
    Shutdown,
    /// Peer responded with an `Error` frame. The payload is whatever bytes the
    /// remote handler returned.
    Remote(Bytes),
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::Timeout => write!(f, "rpc timeout"),
            RpcError::PeerGone => write!(f, "peer disconnected"),
            RpcError::Busy => write!(f, "rpc busy: per-peer limit reached"),
            RpcError::Shutdown => write!(f, "rpc task shut down"),
            RpcError::Remote(b) => write!(f, "remote error ({} bytes)", b.len()),
        }
    }
}

impl std::error::Error for RpcError {}

/// Future returned by an [`RpcHandler`]. `Ok` bytes become a `Response` frame;
/// `Err` bytes become an `Error` frame. Both are opaque — the application
/// picks its own serialization.
pub type HandlerFuture = Pin<Box<dyn Future<Output = Result<Bytes, Bytes>> + Send>>;

/// Server-side handler for one method ID.
pub trait RpcHandler: Send + Sync + 'static {
    fn handle(&self, peer: NodeId, payload: Bytes) -> HandlerFuture;
}

impl<F, Fut> RpcHandler for F
where
    F: Fn(NodeId, Bytes) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Bytes, Bytes>> + Send + 'static,
{
    fn handle(&self, peer: NodeId, payload: Bytes) -> HandlerFuture {
        Box::pin((self)(peer, payload))
    }
}

/// Builds an [`Rpc`] from a set of registered handlers and configuration.
pub struct RpcBuilder {
    handlers: HashMap<u16, Arc<dyn RpcHandler>>,
    max_outstanding_per_peer: usize,
}

impl Default for RpcBuilder {
    fn default() -> Self {
        Self {
            handlers: HashMap::new(),
            max_outstanding_per_peer: DEFAULT_MAX_OUTSTANDING_PER_PEER,
        }
    }
}

impl RpcBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a handler for `method_id`. Later registrations overwrite
    /// earlier ones for the same ID.
    pub fn handler<H: RpcHandler>(mut self, method_id: u16, handler: H) -> Self {
        self.handlers.insert(method_id, Arc::new(handler));
        self
    }

    /// Override the per-peer outstanding-request ceiling.
    #[allow(dead_code)] // public tuning knob; exercised by unit tests only for now
    pub fn max_outstanding_per_peer(mut self, n: usize) -> Self {
        self.max_outstanding_per_peer = n.max(1);
        self
    }

    /// Consume the builder and the protocol handle, spawn the RPC task, and
    /// return a cloneable [`Rpc`] handle. `clock` is used for the per-call
    /// timeout in [`Rpc::call`].
    pub fn spawn(self, handle: ProtocolHandle, clock: Arc<dyn Clock>) -> Rpc {
        let (op_tx, op_rx) = mpsc::channel::<Op>(256);
        let task = RpcTask {
            send_tx: handle.send_tx,
            event_rx: handle.event_rx,
            op_rx,
            handlers: Arc::new(self.handlers),
            outstanding: HashMap::new(),
            max_outstanding_per_peer: self.max_outstanding_per_peer,
        };
        tokio::spawn(task.run());
        Rpc {
            op_tx,
            next_request_id: Arc::new(AtomicU64::new(1)),
            clock,
        }
    }
}

/// Cloneable client handle to the running RPC task.
#[derive(Clone)]
pub struct Rpc {
    op_tx: mpsc::Sender<Op>,
    next_request_id: Arc<AtomicU64>,
    clock: Arc<dyn Clock>,
}

impl Rpc {
    /// Issue an RPC request and await its response. Resolves with
    /// [`RpcError::Timeout`] if `timeout` elapses first, [`RpcError::PeerGone`]
    /// if the peer disconnects first, or [`RpcError::Busy`] if the per-peer
    /// outstanding limit is already full.
    pub async fn call(
        &self,
        peer: NodeId,
        method_id: u16,
        payload: Bytes,
        timeout: Duration,
    ) -> Result<Bytes, RpcError> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let (reply_tx, reply_rx) = oneshot::channel();

        self.op_tx
            .send(Op::Call {
                peer,
                request_id,
                method_id,
                payload,
                reply: reply_tx,
            })
            .await
            .map_err(|_| RpcError::Shutdown)?;

        match clock::timeout(&*self.clock, timeout, reply_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(RpcError::Shutdown),
            Err(_) => {
                let _ = self.op_tx.send(Op::Cancel { peer, request_id }).await;
                Err(RpcError::Timeout)
            }
        }
    }
}

// ── Internal ────────────────────────────────────────────────────────────────

enum Op {
    Call {
        peer: NodeId,
        request_id: u64,
        method_id: u16,
        payload: Bytes,
        reply: oneshot::Sender<Result<Bytes, RpcError>>,
    },
    Cancel {
        peer: NodeId,
        request_id: u64,
    },
}

struct RpcTask {
    send_tx: mpsc::Sender<ProtocolOutbound>,
    event_rx: mpsc::Receiver<ProtocolEvent>,
    op_rx: mpsc::Receiver<Op>,
    handlers: Arc<HashMap<u16, Arc<dyn RpcHandler>>>,
    outstanding: HashMap<NodeId, HashMap<u64, oneshot::Sender<Result<Bytes, RpcError>>>>,
    max_outstanding_per_peer: usize,
}

impl RpcTask {
    async fn run(mut self) {
        loop {
            tokio::select! {
                op = self.op_rx.recv() => match op {
                    Some(Op::Call { peer, request_id, method_id, payload, reply }) => {
                        self.handle_call(peer, request_id, method_id, payload, reply).await;
                    }
                    Some(Op::Cancel { peer, request_id }) => {
                        self.cancel(peer, request_id);
                    }
                    None => break,
                },
                event = self.event_rx.recv() => match event {
                    Some(ev) => self.handle_event(ev).await,
                    None => break,
                },
            }
        }

        // On shutdown, fail every pending call so callers don't hang.
        for (_, map) in self.outstanding.drain() {
            for (_, tx) in map {
                let _ = tx.send(Err(RpcError::Shutdown));
            }
        }
    }

    async fn handle_call(
        &mut self,
        peer: NodeId,
        request_id: u64,
        method_id: u16,
        payload: Bytes,
        reply: oneshot::Sender<Result<Bytes, RpcError>>,
    ) {
        let per_peer = self.outstanding.entry(peer).or_default();
        if per_peer.len() >= self.max_outstanding_per_peer {
            let _ = reply.send(Err(RpcError::Busy));
            return;
        }
        per_peer.insert(request_id, reply);

        let frame = encode_frame(request_id, KIND_REQUEST, method_id, &payload);
        if self
            .send_tx
            .send(ProtocolOutbound::SendTo {
                node_id: peer,
                payload: frame,
            })
            .await
            .is_err()
        {
            if let Some(per_peer) = self.outstanding.get_mut(&peer) {
                if let Some(tx) = per_peer.remove(&request_id) {
                    let _ = tx.send(Err(RpcError::Shutdown));
                }
            }
        }
    }

    fn cancel(&mut self, peer: NodeId, request_id: u64) {
        if let Some(per_peer) = self.outstanding.get_mut(&peer) {
            per_peer.remove(&request_id);
            if per_peer.is_empty() {
                self.outstanding.remove(&peer);
            }
        }
    }

    async fn handle_event(&mut self, event: ProtocolEvent) {
        match event {
            ProtocolEvent::PeerConnected { .. } => {}
            ProtocolEvent::PeerDisconnected { node_id } => {
                if let Some(map) = self.outstanding.remove(&node_id) {
                    for (_, tx) in map {
                        let _ = tx.send(Err(RpcError::PeerGone));
                    }
                }
            }
            ProtocolEvent::Message { from, payload } => match decode_frame(&payload) {
                Ok(Frame {
                    request_id,
                    kind,
                    method_id,
                    body,
                }) => match kind {
                    KIND_REQUEST => {
                        self.dispatch_request(from, request_id, method_id, body);
                    }
                    KIND_RESPONSE => {
                        self.complete(from, request_id, Ok(body));
                    }
                    KIND_ERROR => {
                        self.complete(from, request_id, Err(RpcError::Remote(body)));
                    }
                    other => {
                        warn!(
                            "rpc: unknown kind {other:#04x} (request_id={request_id}) from {}",
                            node_id_to_base58(&from)
                        );
                    }
                },
                Err(e) => {
                    warn!(
                        "rpc: malformed frame from {}: {e}",
                        node_id_to_base58(&from)
                    );
                }
            },
        }
    }

    fn complete(&mut self, peer: NodeId, request_id: u64, result: Result<Bytes, RpcError>) {
        if let Some(per_peer) = self.outstanding.get_mut(&peer) {
            if let Some(tx) = per_peer.remove(&request_id) {
                let _ = tx.send(result);
                if per_peer.is_empty() {
                    self.outstanding.remove(&peer);
                }
                return;
            }
        }
        warn!(
            "rpc: stray response (request_id={request_id}) from {}",
            node_id_to_base58(&peer)
        );
    }

    fn dispatch_request(&self, peer: NodeId, request_id: u64, method_id: u16, payload: Bytes) {
        let handler = self.handlers.get(&method_id).cloned();
        let send_tx = self.send_tx.clone();
        tokio::spawn(async move {
            let (kind, body) = match handler {
                Some(h) => match h.handle(peer, payload).await {
                    Ok(body) => (KIND_RESPONSE, body),
                    Err(body) => (KIND_ERROR, body),
                },
                None => (KIND_ERROR, Bytes::from_static(NO_SUCH_METHOD)),
            };
            let frame = encode_frame(request_id, kind, method_id, &body);
            let _ = send_tx
                .send(ProtocolOutbound::SendTo {
                    node_id: peer,
                    payload: frame,
                })
                .await;
        });
    }
}

// ── Frame codec ─────────────────────────────────────────────────────────────

struct Frame {
    request_id: u64,
    kind: u8,
    method_id: u16,
    body: Bytes,
}

fn encode_frame(request_id: u64, kind: u8, method_id: u16, payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(HEADER_LEN + payload.len());
    buf.put_u64(request_id);
    buf.put_u8(kind);
    buf.put_u16(method_id);
    buf.extend_from_slice(payload);
    buf.freeze()
}

fn decode_frame(buf: &Bytes) -> Result<Frame, &'static str> {
    if buf.len() < HEADER_LEN {
        return Err("frame shorter than header");
    }
    let request_id = u64::from_be_bytes(buf[0..8].try_into().unwrap());
    let kind = buf[8];
    let method_id = u16::from_be_bytes(buf[9..11].try_into().unwrap());
    let body = buf.slice(HEADER_LEN..);
    Ok(Frame {
        request_id,
        kind,
        method_id,
        body,
    })
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use crate::clock::TokioClock;

    fn test_clock() -> Arc<dyn Clock> {
        Arc::new(TokioClock::new())
    }

    /// Shared state controlling an in-memory bridge between two
    /// `ProtocolHandle`s.
    struct Bridge {
        alive: Arc<AtomicBool>,
        a: NodeId,
        b: NodeId,
        a_event_tx: mpsc::Sender<ProtocolEvent>,
        b_event_tx: mpsc::Sender<ProtocolEvent>,
    }

    impl Bridge {
        async fn disconnect(&self) {
            self.alive.store(false, Ordering::SeqCst);
            let _ = self
                .a_event_tx
                .send(ProtocolEvent::PeerDisconnected { node_id: self.b })
                .await;
            let _ = self
                .b_event_tx
                .send(ProtocolEvent::PeerDisconnected { node_id: self.a })
                .await;
        }
    }

    /// Wire two `ProtocolHandle`s so that A's outbound messages arrive as B's
    /// inbound Message events (and vice versa). `PeerConnected` is fired
    /// synchronously so the RPC task sees it before any call.
    async fn paired_handles(a: NodeId, b: NodeId) -> (ProtocolHandle, ProtocolHandle, Bridge) {
        let (a_send_tx, mut a_send_rx) = mpsc::channel::<ProtocolOutbound>(64);
        let (b_send_tx, mut b_send_rx) = mpsc::channel::<ProtocolOutbound>(64);
        let (a_event_tx, a_event_rx) = mpsc::channel::<ProtocolEvent>(64);
        let (b_event_tx, b_event_rx) = mpsc::channel::<ProtocolEvent>(64);

        let alive = Arc::new(AtomicBool::new(true));

        {
            let alive = Arc::clone(&alive);
            let other = b_event_tx.clone();
            tokio::spawn(async move {
                while let Some(out) = a_send_rx.recv().await {
                    if !alive.load(Ordering::SeqCst) {
                        continue;
                    }
                    let payload = match out {
                        ProtocolOutbound::SendTo { payload, .. } => payload,
                        ProtocolOutbound::Broadcast(p) => p,
                    };
                    let _ = other
                        .send(ProtocolEvent::Message { from: a, payload })
                        .await;
                }
            });
        }
        {
            let alive = Arc::clone(&alive);
            let other = a_event_tx.clone();
            tokio::spawn(async move {
                while let Some(out) = b_send_rx.recv().await {
                    if !alive.load(Ordering::SeqCst) {
                        continue;
                    }
                    let payload = match out {
                        ProtocolOutbound::SendTo { payload, .. } => payload,
                        ProtocolOutbound::Broadcast(p) => p,
                    };
                    let _ = other
                        .send(ProtocolEvent::Message { from: b, payload })
                        .await;
                }
            });
        }

        a_event_tx
            .send(ProtocolEvent::PeerConnected { node_id: b })
            .await
            .unwrap();
        b_event_tx
            .send(ProtocolEvent::PeerConnected { node_id: a })
            .await
            .unwrap();

        (
            ProtocolHandle {
                send_tx: a_send_tx,
                event_rx: a_event_rx,
            },
            ProtocolHandle {
                send_tx: b_send_tx,
                event_rx: b_event_rx,
            },
            Bridge {
                alive,
                a,
                b,
                a_event_tx,
                b_event_tx,
            },
        )
    }

    fn nid(byte: u8) -> NodeId {
        [byte; 32]
    }

    #[test]
    fn frame_round_trips() {
        let encoded = encode_frame(0xDEAD_BEEF_CAFE_BABE, KIND_REQUEST, 0x1234, b"hello");
        let decoded = decode_frame(&encoded).expect("decodes");
        assert_eq!(decoded.request_id, 0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(decoded.kind, KIND_REQUEST);
        assert_eq!(decoded.method_id, 0x1234);
        assert_eq!(decoded.body.as_ref(), b"hello");
    }

    #[test]
    fn frame_short_is_rejected() {
        assert!(decode_frame(&Bytes::from_static(b"short")).is_err());
    }

    #[tokio::test]
    async fn request_response_round_trip() {
        let (ha, hb, _bridge) = paired_handles(nid(1), nid(2)).await;

        // Client on side A, echo server on side B.
        let client = RpcBuilder::new().spawn(ha, test_clock());
        let _server = RpcBuilder::new()
            .handler(42u16, |_peer: NodeId, body: Bytes| async move { Ok(body) })
            .spawn(hb, test_clock());

        let reply = client
            .call(
                nid(2),
                42,
                Bytes::from_static(b"ping"),
                Duration::from_secs(2),
            )
            .await
            .expect("call succeeds");
        assert_eq!(reply.as_ref(), b"ping");
    }

    #[tokio::test]
    async fn server_error_surfaces_as_remote() {
        let (ha, hb, _bridge) = paired_handles(nid(1), nid(2)).await;
        let client = RpcBuilder::new().spawn(ha, test_clock());
        let _server = RpcBuilder::new()
            .handler(7u16, |_peer: NodeId, _body: Bytes| async move {
                Err(Bytes::from_static(b"boom"))
            })
            .spawn(hb, test_clock());

        let err = client
            .call(nid(2), 7, Bytes::new(), Duration::from_secs(2))
            .await
            .expect_err("should fail");
        match err {
            RpcError::Remote(b) => assert_eq!(b.as_ref(), b"boom"),
            other => panic!("expected Remote, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unknown_method_produces_remote_error() {
        let (ha, hb, _bridge) = paired_handles(nid(1), nid(2)).await;
        let client = RpcBuilder::new().spawn(ha, test_clock());
        let _server = RpcBuilder::new().spawn(hb, test_clock()); // no handlers

        let err = client
            .call(nid(2), 999, Bytes::new(), Duration::from_secs(2))
            .await
            .expect_err("should fail");
        match err {
            RpcError::Remote(b) => assert_eq!(b.as_ref(), NO_SUCH_METHOD),
            other => panic!("expected Remote, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn timeout_fires_when_peer_never_replies() {
        let (ha, hb, _bridge) = paired_handles(nid(1), nid(2)).await;
        let client = RpcBuilder::new().spawn(ha, test_clock());
        // Handler that never resolves.
        let _server = RpcBuilder::new()
            .handler(1u16, |_peer: NodeId, _body: Bytes| async move {
                std::future::pending::<Result<Bytes, Bytes>>().await
            })
            .spawn(hb, test_clock());

        let err = client
            .call(nid(2), 1, Bytes::new(), Duration::from_millis(100))
            .await
            .expect_err("should time out");
        assert!(matches!(err, RpcError::Timeout), "got {err:?}");
    }

    #[tokio::test]
    async fn peer_gone_resolves_in_flight_requests() {
        let (ha, hb, bridge) = paired_handles(nid(1), nid(2)).await;
        let client = RpcBuilder::new().spawn(ha, test_clock());
        let _server = RpcBuilder::new()
            .handler(1u16, |_peer: NodeId, _body: Bytes| async move {
                std::future::pending::<Result<Bytes, Bytes>>().await
            })
            .spawn(hb, test_clock());

        let client_clone = client.clone();
        let call = tokio::spawn(async move {
            client_clone
                .call(nid(2), 1, Bytes::new(), Duration::from_secs(5))
                .await
        });

        // Give the RPC task time to register the request before disconnecting.
        tokio::time::sleep(Duration::from_millis(50)).await;
        bridge.disconnect().await;

        let result = call.await.unwrap();
        match result {
            Err(RpcError::PeerGone) => {}
            other => panic!("expected PeerGone, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn busy_when_outstanding_limit_hit() {
        let (ha, hb, _bridge) = paired_handles(nid(1), nid(2)).await;
        let client = RpcBuilder::new()
            .max_outstanding_per_peer(1)
            .spawn(ha, test_clock());
        // Server handler blocks forever so the first call stays in flight.
        let _server = RpcBuilder::new()
            .handler(1u16, |_peer: NodeId, _body: Bytes| async move {
                std::future::pending::<Result<Bytes, Bytes>>().await
            })
            .spawn(hb, test_clock());

        let client1 = client.clone();
        let pending = tokio::spawn(async move {
            client1
                .call(nid(2), 1, Bytes::new(), Duration::from_secs(5))
                .await
        });

        // Give the task time to register the first call.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let err = client
            .call(nid(2), 1, Bytes::new(), Duration::from_secs(1))
            .await
            .expect_err("second call should be rejected");
        assert!(matches!(err, RpcError::Busy), "got {err:?}");

        pending.abort();
    }

    #[tokio::test]
    async fn distinct_request_ids_allow_interleaved_replies() {
        let (ha, hb, _bridge) = paired_handles(nid(1), nid(2)).await;
        let client = RpcBuilder::new().spawn(ha, test_clock());
        let _server = RpcBuilder::new()
            .handler(5u16, |_peer: NodeId, body: Bytes| async move {
                // Add an arbitrary delay per request so replies can interleave.
                let delay_ms = if body.as_ref() == b"slow" { 80 } else { 10 };
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                Ok(body)
            })
            .spawn(hb, test_clock());

        let c1 = client.clone();
        let c2 = client.clone();
        let slow = tokio::spawn(async move {
            c1.call(
                nid(2),
                5,
                Bytes::from_static(b"slow"),
                Duration::from_secs(2),
            )
            .await
        });
        let fast = tokio::spawn(async move {
            c2.call(
                nid(2),
                5,
                Bytes::from_static(b"fast"),
                Duration::from_secs(2),
            )
            .await
        });

        let fast_reply = fast.await.unwrap().unwrap();
        let slow_reply = slow.await.unwrap().unwrap();
        assert_eq!(fast_reply.as_ref(), b"fast");
        assert_eq!(slow_reply.as_ref(), b"slow");
    }
}
