//! Periodic peer-list push task and the receive-side merge helper.
//!
//! Once per [`PeerListGossipConfig::interval`], the publisher samples up
//! to [`PeerListGossipConfig::fanout`] currently-direct peers (uniformly
//! random) and pushes a postcard-encoded snapshot of the local
//! [`super::peer_table::PeerTable`] to each. Recipients call
//! [`apply_peer_list_frame`] to decode and merge the entries into
//! their own table.
//!
//! This module is independent of the rest of the gossip overlay — it
//! takes a small `Sender` abstraction so PR 4 can plug it into the
//! single overlay event loop without redoing the publication logic.
//!
//! # Why push, not pull
//!
//! Push gossip means each node periodically sends what it knows; pull
//! means each node periodically asks what others know. Push is
//! simpler (no request/response state machine), and bandwidth at
//! validator-set scale is negligible — even a 1024-entry table
//! encodes to a few tens of KiB and we push at a 5 s cadence by
//! default. If the peer table ever grows past O(10⁴) entries (which
//! would imply an entirely different deployment shape) we can
//! revisit.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use rand::SeedableRng;
use rand::seq::SliceRandom;
use rand_chacha::ChaCha20Rng;
use tokio::sync::oneshot;
use tracing::{debug, warn};

use crate::clock::Clock;

use super::super::super::tls::NodeId;
use super::peer_table::PeerTable;
use super::wire::{OverlayFrame, PeerEntry};

/// Knobs the binary will eventually expose under `[overlay]` in
/// `config.toml`. Defaults match the breakdown comment on issue #137.
#[derive(Debug, Clone)]
pub struct PeerListGossipConfig {
    /// How often the publisher fires.
    pub interval: Duration,
    /// Maximum number of direct neighbours to push to per tick.
    pub fanout: usize,
    /// Optional cap on the size of the pushed snapshot. `None` means
    /// "send everything"; `Some(n)` truncates to the freshest `n`
    /// entries (sorted by `last_seen_unix_ms` descending). Useful as a
    /// belt-and-braces guard if a future config bumps
    /// `PeerTable::capacity` past comfortable wire sizes.
    pub max_entries: Option<usize>,
}

impl Default for PeerListGossipConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(5),
            fanout: 3,
            max_entries: None,
        }
    }
}

/// Object-safe wrapper for sending an overlay frame to a specific
/// peer. PR 4 will satisfy this with a struct that wraps the
/// [`super::super::super::PeerCommand::RegisterProtocol`]
/// `mpsc::Sender<ProtocolOutbound>`. Tests satisfy it with a recording
/// mock.
pub trait OverlayUnicast: Send + Sync + 'static {
    /// Send `payload` to `target`. Best-effort — drops on
    /// backpressure / shutdown are acceptable; the next tick will
    /// resend whatever the receiver missed.
    fn send_to(&self, target: NodeId, payload: Bytes);
}

/// Object-safe wrapper for sampling the currently-direct peer set.
pub trait DirectPeers: Send + Sync + 'static {
    /// Return a freshly-allocated snapshot of the set of peers we
    /// currently have an open p2p connection to. Order is irrelevant
    /// — the publisher shuffles before sampling.
    fn snapshot(&self) -> Vec<NodeId>;
}

/// `(node_id, listen_addr)` injected into every published peer-list
/// frame so receivers learn the publisher's listening address.
///
/// Without this, a node that learned about a peer only via an inbound
/// connection would carry the peer's ephemeral source port in its
/// `PeerTable` and gossip a non-dialable address. The remedy is for
/// every node to self-advertise: each tick the publisher prepends its
/// own `(node_id, listen_addr, now_unix_ms)` to the snapshot before
/// encoding.
#[derive(Debug, Clone, Copy)]
pub struct SelfAdvertise {
    /// Local NodeId.
    pub node_id: NodeId,
    /// Local listening address (post-`bind`, with the actual port).
    pub addr: SocketAddr,
}

/// Build the postcard wire bytes for a peer-list push, optionally
/// capped at `max_entries` freshest entries. When `self_entry` is
/// provided, it's prepended to the snapshot — see [`SelfAdvertise`].
pub fn build_peer_list_frame(
    table: &PeerTable,
    self_entry: Option<PeerEntry>,
    max_entries: Option<usize>,
) -> Bytes {
    let mut entries = table.snapshot();
    if let Some(e) = self_entry {
        entries.push(e);
    }
    if let Some(cap) = max_entries
        && entries.len() > cap
    {
        entries.sort_by_key(|e| std::cmp::Reverse(e.last_seen_unix_ms));
        entries.truncate(cap);
    }
    let frame = OverlayFrame::PeerList(entries);
    Bytes::from(postcard::to_stdvec(&frame).expect("postcard encode of PeerList cannot fail"))
}

fn now_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Decode a received overlay frame and, if it's a peer-list, merge
/// it. Returns the list of [`NodeId`]s whose record changed in the
/// table (newly inserted, address changed, or refreshed forward).
///
/// `Forward` frames are returned as `Err(payload_bytes)` so the
/// caller (PR 4's overlay loop) can route them to the dedup +
/// fanout path. Bytes that fail to decode as an [`OverlayFrame`] log
/// at warn and are silently dropped — a malformed frame from a peer
/// shouldn't tear down the whole overlay.
pub fn apply_overlay_frame(table: &PeerTable, raw: &[u8]) -> Result<Vec<NodeId>, FrameOutcome> {
    let frame: OverlayFrame = match postcard::from_bytes(raw) {
        Ok(f) => f,
        Err(e) => {
            warn!("dropping malformed overlay frame: {e}");
            return Err(FrameOutcome::Malformed);
        }
    };
    match frame {
        OverlayFrame::PeerList(entries) => Ok(table.merge(entries)),
        OverlayFrame::Forward {
            msg_id,
            originator,
            target,
            payload,
        } => Err(FrameOutcome::Forward {
            msg_id,
            originator,
            target,
            payload,
        }),
    }
}

/// Variants of a non-`PeerList` outcome from
/// [`apply_overlay_frame`].
#[derive(Debug)]
pub enum FrameOutcome {
    /// Bytes failed to decode. Already logged at warn.
    Malformed,
    /// A forwarded application payload. PR 4's overlay loop dedups +
    /// re-fanouts.
    Forward {
        /// Per-broadcast id; the dedup ring keys on this.
        msg_id: super::wire::MsgId,
        /// Original sender of the broadcast. Surfaced upstream as the
        /// `from` field of the delivered [`crate::p2p::ProtocolEvent::Message`]
        /// regardless of how many gossip hops the frame traversed.
        originator: NodeId,
        /// Intended unicast recipient, if any. `None` means broadcast
        /// (every receiver surfaces); `Some(peer)` means only `peer`
        /// surfaces upstream — other receivers still re-fanout so the
        /// frame can reach `peer` through the gossip mesh. See
        /// [`OverlayFrame::Forward`] and issue #182.
        target: Option<NodeId>,
        /// Application payload to surface upstream if the dedup
        /// check passes.
        payload: bytes::Bytes,
    },
}

/// Run the peer-list publisher until `shutdown` fires.
///
/// Generic over the unicast channel and the direct-peer source so
/// tests can plug in mocks without spinning up the full p2p stack.
/// When `self_advertise` is `Some`, every published frame includes a
/// fresh `(node_id, addr, now)` self-entry — the canonical mechanism
/// for teaching peers our listening address.
#[allow(clippy::too_many_arguments)]
pub async fn run_peer_list_publisher(
    config: PeerListGossipConfig,
    table: PeerTable,
    direct: Arc<dyn DirectPeers>,
    sink: Arc<dyn OverlayUnicast>,
    clock: Arc<dyn Clock>,
    rng_seed: u64,
    self_advertise: Option<SelfAdvertise>,
    mut shutdown: oneshot::Receiver<()>,
) {
    let mut rng = ChaCha20Rng::seed_from_u64(rng_seed);
    let mut interval = clock.interval(config.interval);

    // Discard the immediate-tick that `Clock::interval` fires on
    // construction (matching `tokio::time::interval`'s behaviour) so
    // we don't emit a peer-list before the table has had a chance to
    // populate at startup.
    interval.tick().await;

    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => return,
            _ = interval.tick() => {
                tick_once(
                    &config,
                    &table,
                    direct.as_ref(),
                    sink.as_ref(),
                    self_advertise,
                    &mut rng,
                );
            }
        }
    }
}

fn tick_once(
    config: &PeerListGossipConfig,
    table: &PeerTable,
    direct: &dyn DirectPeers,
    sink: &dyn OverlayUnicast,
    self_advertise: Option<SelfAdvertise>,
    rng: &mut ChaCha20Rng,
) {
    let mut peers = direct.snapshot();
    if peers.is_empty() {
        debug!("peer-list publisher: no direct peers, skipping tick");
        return;
    }
    peers.shuffle(rng);
    peers.truncate(config.fanout);

    let self_entry = self_advertise.map(|s| PeerEntry {
        node_id: s.node_id,
        addr: s.addr,
        last_seen_unix_ms: now_unix_ms(),
    });
    let frame = build_peer_list_frame(table, self_entry, config.max_entries);
    for target in peers {
        sink.send_to(target, frame.clone());
    }
}

/// Convert a [`Vec<NodeId>`] direct-peer source (e.g. the snapshot
/// returned by the manager's `ListPeers` command) into a
/// [`DirectPeers`] impl that locks a `parking_lot::RwLock` and
/// snapshots on every call.
///
/// Used by PR 4's overlay loop wiring; exposed here so tests can also
/// drive it.
pub struct LockedVec(pub parking_lot::RwLock<Vec<NodeId>>);

impl LockedVec {
    /// Build an empty source.
    pub fn new() -> Self {
        Self(parking_lot::RwLock::new(Vec::new()))
    }

    /// Replace the current snapshot.
    pub fn set(&self, peers: Vec<NodeId>) {
        *self.0.write() = peers;
    }
}

impl Default for LockedVec {
    fn default() -> Self {
        Self::new()
    }
}

impl DirectPeers for LockedVec {
    fn snapshot(&self) -> Vec<NodeId> {
        self.0.read().clone()
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use bytes::Bytes;
    use parking_lot::Mutex;

    use crate::clock::TokioClock;

    use super::super::wire::{MsgId, OverlayFrame, PeerEntry};
    use super::*;

    fn nid(byte: u8) -> NodeId {
        let mut id = [0u8; 32];
        id[0] = byte;
        id
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[derive(Default)]
    struct RecordingSink {
        sent: Mutex<Vec<(NodeId, Bytes)>>,
    }

    impl OverlayUnicast for RecordingSink {
        fn send_to(&self, target: NodeId, payload: Bytes) {
            self.sent.lock().push((target, payload));
        }
    }

    #[test]
    fn build_frame_round_trips_table() {
        let table = PeerTable::new(nid(0), 16);
        table.upsert(nid(1), addr(7001), 100);
        table.upsert(nid(2), addr(7002), 200);

        let bytes = build_peer_list_frame(&table, None, None);
        let decoded: OverlayFrame = postcard::from_bytes(&bytes).expect("decode");
        let OverlayFrame::PeerList(entries) = decoded else {
            panic!("expected PeerList variant");
        };
        let mut got: Vec<_> = entries.iter().map(|e| e.node_id).collect();
        got.sort();
        assert_eq!(got, vec![nid(1), nid(2)]);
    }

    #[test]
    fn build_frame_caps_at_max_entries_freshest_first() {
        let table = PeerTable::new(nid(0), 16);
        table.upsert(nid(1), addr(7001), 100);
        table.upsert(nid(2), addr(7002), 300);
        table.upsert(nid(3), addr(7003), 200);

        let bytes = build_peer_list_frame(&table, None, Some(2));
        let decoded: OverlayFrame = postcard::from_bytes(&bytes).expect("decode");
        let OverlayFrame::PeerList(entries) = decoded else {
            panic!("expected PeerList variant");
        };
        assert_eq!(entries.len(), 2);
        let ids: Vec<_> = entries.iter().map(|e| e.node_id).collect();
        // Freshest two: nid(2) (last_seen=300) and nid(3) (last_seen=200).
        assert!(ids.contains(&nid(2)));
        assert!(ids.contains(&nid(3)));
        assert!(!ids.contains(&nid(1)));
    }

    #[test]
    fn apply_peer_list_frame_merges_into_table() {
        let table = PeerTable::new(nid(0), 16);
        table.upsert(nid(1), addr(7001), 100);

        let incoming = OverlayFrame::PeerList(vec![
            PeerEntry {
                node_id: nid(1),
                addr: addr(7001),
                last_seen_unix_ms: 200,
            },
            PeerEntry {
                node_id: nid(2),
                addr: addr(7002),
                last_seen_unix_ms: 150,
            },
        ]);
        let bytes = postcard::to_stdvec(&incoming).unwrap();
        let changed = apply_overlay_frame(&table, &bytes).expect("PeerList");
        let mut sorted = changed;
        sorted.sort();
        assert_eq!(sorted, vec![nid(1), nid(2)]);
    }

    #[test]
    fn apply_overlay_frame_returns_forward_to_caller() {
        let table = PeerTable::new(nid(0), 16);
        let id: MsgId = [9u8; 16];
        let orig = nid(42);
        let frame = OverlayFrame::Forward {
            msg_id: id,
            originator: orig,
            target: None,
            payload: Bytes::from_static(b"hello"),
        };
        let bytes = postcard::to_stdvec(&frame).unwrap();
        match apply_overlay_frame(&table, &bytes) {
            Err(FrameOutcome::Forward {
                msg_id,
                originator,
                target,
                payload,
            }) => {
                assert_eq!(msg_id, id);
                assert_eq!(originator, orig);
                assert_eq!(target, None);
                assert_eq!(&payload[..], b"hello");
            }
            other => panic!("expected Forward, got {other:?}"),
        }
    }

    #[test]
    fn apply_overlay_frame_forwards_target_through_to_caller() {
        let table = PeerTable::new(nid(0), 16);
        let id: MsgId = [11u8; 16];
        let orig = nid(1);
        let tgt = nid(7);
        let frame = OverlayFrame::Forward {
            msg_id: id,
            originator: orig,
            target: Some(tgt),
            payload: Bytes::from_static(b"unicast"),
        };
        let bytes = postcard::to_stdvec(&frame).unwrap();
        match apply_overlay_frame(&table, &bytes) {
            Err(FrameOutcome::Forward {
                target, payload, ..
            }) => {
                assert_eq!(target, Some(tgt));
                assert_eq!(&payload[..], b"unicast");
            }
            other => panic!("expected Forward, got {other:?}"),
        }
    }

    #[test]
    fn apply_overlay_frame_drops_malformed() {
        let table = PeerTable::new(nid(0), 16);
        let bytes = vec![0xFFu8; 4];
        match apply_overlay_frame(&table, &bytes) {
            Err(FrameOutcome::Malformed) => {}
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn publisher_fans_out_to_random_subset_per_tick() {
        let table = PeerTable::new(nid(0), 16);
        for i in 1..=5u8 {
            table.upsert(nid(i), addr(7000 + i as u16), 100);
        }
        let direct = Arc::new(LockedVec::new());
        direct.set((1..=5u8).map(nid).collect());
        let sink = Arc::new(RecordingSink::default());
        let clock: Arc<dyn Clock> = Arc::new(TokioClock::new());

        let cfg = PeerListGossipConfig {
            interval: Duration::from_secs(5),
            fanout: 3,
            max_entries: None,
        };

        let (sd_tx, sd_rx) = oneshot::channel();
        let task = tokio::spawn({
            let direct = direct.clone() as Arc<dyn DirectPeers>;
            let sink = sink.clone() as Arc<dyn OverlayUnicast>;
            let table = table.clone();
            let clock = clock.clone();
            run_peer_list_publisher(
                cfg, table, direct, sink, clock, /* seed */ 7, None, sd_rx,
            )
        });

        // Advance past the immediate-tick discard + first scheduled tick.
        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;

        let _ = sd_tx.send(());
        let _ = task.await;

        let sent = sink.sent.lock();
        assert!(!sent.is_empty(), "publisher fired at least once");
        // Each tick fans out up to fanout=3 distinct peers.
        for window in sent.chunks(3) {
            let mut targets: Vec<NodeId> = window.iter().map(|(t, _)| *t).collect();
            targets.sort();
            targets.dedup();
            assert_eq!(targets.len(), window.len(), "no duplicates in a tick");
        }
        // Every payload is a valid PeerList encoding.
        for (_, payload) in sent.iter() {
            match postcard::from_bytes::<OverlayFrame>(payload).unwrap() {
                OverlayFrame::PeerList(_) => {}
                other => panic!("expected PeerList, got {other:?}"),
            }
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn publisher_skips_when_no_direct_peers() {
        let table = PeerTable::new(nid(0), 16);
        let direct = Arc::new(LockedVec::new()); // empty
        let sink = Arc::new(RecordingSink::default());
        let clock: Arc<dyn Clock> = Arc::new(TokioClock::new());

        let cfg = PeerListGossipConfig {
            interval: Duration::from_secs(5),
            fanout: 3,
            max_entries: None,
        };

        let (sd_tx, sd_rx) = oneshot::channel();
        let task = tokio::spawn({
            let direct = direct.clone() as Arc<dyn DirectPeers>;
            let sink = sink.clone() as Arc<dyn OverlayUnicast>;
            let table = table.clone();
            let clock = clock.clone();
            run_peer_list_publisher(
                cfg, table, direct, sink, clock, /* seed */ 7, None, sd_rx,
            )
        });

        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;

        let _ = sd_tx.send(());
        let _ = task.await;

        assert!(sink.sent.lock().is_empty(), "no direct peers, no sends");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn two_node_handshake_converges() {
        // Direct two-table convergence: A pushes, B receives, B
        // pushes, A receives. After two ticks both tables hold both
        // entries.
        let a_id = nid(1);
        let b_id = nid(2);
        let a = PeerTable::new(a_id, 16);
        let b = PeerTable::new(b_id, 16);

        // Each side starts knowing only its peer.
        a.upsert(b_id, addr(7002), 100);
        b.upsert(a_id, addr(7001), 100);

        // Now seed each side with a third peer that's only known to it.
        a.upsert(nid(3), addr(7003), 100);
        b.upsert(nid(4), addr(7004), 100);

        // Direct sets (mocked): A sees B, B sees A.
        let a_direct = Arc::new(LockedVec::new());
        a_direct.set(vec![b_id]);
        let b_direct = Arc::new(LockedVec::new());
        b_direct.set(vec![a_id]);

        // The two publishers send into each other's tables.
        struct CrossSink {
            target_table: PeerTable,
        }
        impl OverlayUnicast for CrossSink {
            fn send_to(&self, _target: NodeId, payload: Bytes) {
                let _ = apply_overlay_frame(&self.target_table, &payload);
            }
        }

        let a_sink = Arc::new(CrossSink {
            target_table: b.clone(),
        });
        let b_sink = Arc::new(CrossSink {
            target_table: a.clone(),
        });

        let clock: Arc<dyn Clock> = Arc::new(TokioClock::new());
        let cfg = PeerListGossipConfig {
            interval: Duration::from_secs(1),
            fanout: 3,
            max_entries: None,
        };

        let (sd_a_tx, sd_a_rx) = oneshot::channel();
        let (sd_b_tx, sd_b_rx) = oneshot::channel();

        let task_a = tokio::spawn({
            let direct = a_direct.clone() as Arc<dyn DirectPeers>;
            let sink = a_sink.clone() as Arc<dyn OverlayUnicast>;
            let table = a.clone();
            let clock = clock.clone();
            let cfg = cfg.clone();
            run_peer_list_publisher(cfg, table, direct, sink, clock, 1, None, sd_a_rx)
        });
        let task_b = tokio::spawn({
            let direct = b_direct.clone() as Arc<dyn DirectPeers>;
            let sink = b_sink.clone() as Arc<dyn OverlayUnicast>;
            let table = b.clone();
            let clock = clock.clone();
            let cfg = cfg.clone();
            run_peer_list_publisher(cfg, table, direct, sink, clock, 2, None, sd_b_rx)
        });

        // A few ticks to converge.
        for _ in 0..4 {
            tokio::time::advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
            tokio::task::yield_now().await;
        }

        let _ = sd_a_tx.send(());
        let _ = sd_b_tx.send(());
        let _ = task_a.await;
        let _ = task_b.await;

        // Both tables should know about all four ids (their two
        // initial peers, plus each other's third peer).
        // Note: each side's self_id is filtered, so A doesn't track
        // a_id and B doesn't track b_id.
        assert!(a.contains(&b_id));
        assert!(a.contains(&nid(3)));
        assert!(a.contains(&nid(4)));
        assert!(b.contains(&a_id));
        assert!(b.contains(&nid(3)));
        assert!(b.contains(&nid(4)));
    }
}
