//! In-memory `AsyncRead + AsyncWrite` stream that funnels writes through the
//! [`SimNetwork`] scheduler instead of delivering them synchronously.
//!
//! Each [`SimStream`] is one half of a connection (e.g. node A's view of the
//! A↔B link). Writes are handed to the network with the source/destination
//! `NodeId`s; the network applies link config (latency, drop, partition,
//! bandwidth, reorder) and schedules a future `Deliver` event. Reads pull
//! bytes from a per-direction inbox that the network appends to on delivery.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::p2p::NodeId;

use super::network::SimNetwork;

/// Per-direction inbox. The network appends bytes on delivery; the stream's
/// read half drains them. When both halves are dropped the writer side
/// flips `closed` so the reader sees EOF.
pub(crate) struct Inbox {
    pub bytes: Vec<u8>,
    pub waker: Option<Waker>,
    pub closed: bool,
}

impl Inbox {
    pub fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            bytes: Vec::new(),
            waker: None,
            closed: false,
        }))
    }
}

pub struct SimStream {
    network: Arc<SimNetwork>,
    /// Source identity for messages this stream emits.
    from: NodeId,
    /// Destination identity for messages this stream emits.
    to: NodeId,
    /// Where bytes from the peer get delivered.
    inbox: Arc<Mutex<Inbox>>,
}

impl SimStream {
    pub(crate) fn new(
        network: Arc<SimNetwork>,
        from: NodeId,
        to: NodeId,
        inbox: Arc<Mutex<Inbox>>,
    ) -> Self {
        Self {
            network,
            from,
            to,
            inbox,
        }
    }
}

impl AsyncRead for SimStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut inbox = self.inbox.lock().unwrap();
        if inbox.bytes.is_empty() {
            if inbox.closed {
                return Poll::Ready(Ok(())); // EOF
            }
            inbox.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = inbox.bytes.len().min(buf.remaining());
        let drained: Vec<u8> = inbox.bytes.drain(..n).collect();
        buf.put_slice(&drained);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for SimStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // The scheduler always accepts the full write — backpressure is
        // modelled at delivery time via latency/bandwidth, not at write time.
        let n = self.network.enqueue_write(self.from, self.to, buf);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
