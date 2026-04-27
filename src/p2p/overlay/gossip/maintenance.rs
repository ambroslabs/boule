//! Partial-mesh maintenance loop.
//!
//! Once per [`MeshMaintenanceConfig::interval`], compares the
//! currently-direct peer count against `target_degree` and, if there's
//! a deficit, asks the [`Dialer`] to start outbound dial loops for
//! enough fresh candidates from the [`super::peer_table::PeerTable`]
//! to close the gap.
//!
//! # What "direct" means
//!
//! "Direct" peers are those the local p2p manager currently has an
//! open authenticated connection to. The maintenance loop reads this
//! via the [`super::peer_list_task::DirectPeers`] trait so it shares
//! a snapshot abstraction with the peer-list publisher and stays
//! testable without spinning up the full transport.
//!
//! # Selection bias
//!
//! Today: **uniform random** over the unconnected, *reachable* portion
//! of the peer table. The breakdown comment on #137 documents this as
//! the v1 choice; latency / stake / reputation biasing is an explicit
//! follow-up. The selection RNG is seeded from the caller so sim
//! tests get byte-identical traces.
//!
//! # Outbound-only peers (#138)
//!
//! Peers advertising `reachable = false` (the issue #138 outbound-only
//! mode, `[p2p] inbound_disabled = true`) are filtered out of the
//! candidate pool — there is no listener to dial against. They stay
//! in the [`PeerTable`] so peer-list gossip can still propagate them,
//! and so we still see them as direct peers if and when they dial in
//! to *us*. They simply don't count as outbound candidates.
//!
//! # Idempotency / dial deduplication
//!
//! Once a dialer is spawned for a given `NodeId`, the maintenance
//! loop remembers it in an internal "dialing" set and never spawns a
//! second one for the same peer. The `dialer::reconnect_loop` itself
//! takes care of reconnecting if the peer drops, so a one-shot
//! per-peer spawn is the right abstraction. Peers we've spawned
//! dialers for that subsequently *appear* in `direct_peers` count
//! against the target degree as expected; if they drop, the
//! reconnect loop reconnects them (we don't trigger a new dial).
//!
//! # Trimming above K
//!
//! Not implemented yet — the maintenance loop only fills upward.
//! Validator clusters churn slowly enough that growing past
//! `target_degree` happens only briefly when a previously-unreachable
//! peer comes back online and we're already at K with replacements.
//! A future enhancement can add proactive trim if profiling shows
//! we're sitting above K under steady-state.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rand::SeedableRng;
use rand::seq::SliceRandom;
use rand_chacha::ChaCha20Rng;
use tokio::sync::oneshot;
use tracing::{debug, info};

use crate::clock::Clock;

use super::super::super::tls::NodeId;
use super::peer_list_task::DirectPeers;
use super::peer_table::PeerTable;

/// Knobs for [`run_mesh_maintenance`]. Defaults match the breakdown
/// comment on issue #137.
#[derive(Debug, Clone)]
pub struct MeshMaintenanceConfig {
    /// How often the loop wakes up and re-evaluates the deficit.
    pub interval: Duration,
    /// Upper bound on the number of direct peers we want to maintain.
    /// When `direct_peers().len() < target_degree`, the loop spawns
    /// dialers for the difference.
    pub target_degree: usize,
}

impl Default for MeshMaintenanceConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(5),
            target_degree: 8,
        }
    }
}

/// Object-safe wrapper for spawning an outbound dialer task. The
/// production impl wraps
/// [`super::super::super::dialer::DialerCtx::spawn`]; tests satisfy
/// it with a recording mock.
pub trait Dialer: Send + Sync + 'static {
    /// Start an outbound dial loop targeting `addr`.
    ///
    /// When `expected` is `Some`, the dialer asserts the peer's TLS
    /// identity matches that NodeId before announcing the connection
    /// (the partial-mesh maintenance path: we know who we expect
    /// because the `PeerEntry` came from a peer-list gossip frame).
    ///
    /// When `expected` is `None`, the dialer accepts whatever
    /// identity the peer presents — TOFU semantics, used by the
    /// bootstrap path where an operator points at an address without
    /// pinning its node ID.
    ///
    /// Best-effort — the dialer task is fire-and-forget; the
    /// maintenance loop tracks per-peer "we already started a dialer"
    /// state internally.
    fn dial(&self, addr: SocketAddr, expected: Option<NodeId>);
}

/// Run the partial-mesh maintenance loop until `shutdown` fires.
///
/// `direct` is sampled every tick to read the live direct-peer
/// count. `table` is consulted for unconnected candidates when there
/// is a deficit.
pub async fn run_mesh_maintenance(
    config: MeshMaintenanceConfig,
    table: PeerTable,
    direct: Arc<dyn DirectPeers>,
    dialer: Arc<dyn Dialer>,
    clock: Arc<dyn Clock>,
    rng_seed: u64,
    mut shutdown: oneshot::Receiver<()>,
) {
    let mut rng = ChaCha20Rng::seed_from_u64(rng_seed);
    let mut interval = clock.interval(config.interval);
    let mut already_dialing: HashSet<NodeId> = HashSet::new();

    // Discard the immediate-tick (matching the peer-list publisher);
    // the first real tick fires after `interval`.
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
                    dialer.as_ref(),
                    &mut already_dialing,
                    &mut rng,
                );
            }
        }
    }
}

/// Single maintenance pass — exposed for tests so they can drive the
/// loop deterministically without paused timers.
pub fn tick_once(
    config: &MeshMaintenanceConfig,
    table: &PeerTable,
    direct: &dyn DirectPeers,
    dialer: &dyn Dialer,
    already_dialing: &mut HashSet<NodeId>,
    rng: &mut ChaCha20Rng,
) -> usize {
    let direct_now = direct.snapshot();
    if direct_now.len() >= config.target_degree {
        return 0;
    }

    let direct_set: HashSet<NodeId> = direct_now.iter().copied().collect();
    let deficit = config.target_degree - direct_now.len();

    // Candidate set: peers in the table we are neither connected to
    // nor already dialing, and that advertise `reachable = true`.
    // `entry.node_id != self_id` is enforced by `PeerTable::upsert`
    // itself (the table filters self-references).
    //
    // Issue #138: `snapshot_reachable` already excludes peers running
    // `[p2p] inbound_disabled = true`, so the maintenance loop never
    // wastes a TCP connect attempt on a host that has no listener.
    let mut candidates: Vec<_> = table
        .snapshot_reachable()
        .into_iter()
        .filter(|e| !direct_set.contains(&e.node_id))
        .filter(|e| !already_dialing.contains(&e.node_id))
        .collect();
    if candidates.is_empty() {
        debug!(
            deficit,
            "mesh maintenance: deficit but no unconnected candidates in peer table"
        );
        return 0;
    }
    candidates.shuffle(rng);
    candidates.truncate(deficit);

    let spawned = candidates.len();
    for entry in candidates {
        info!(
            "mesh maintenance: dialing {} at {}",
            super::super::super::tls::node_id_to_base58(&entry.node_id),
            entry.addr
        );
        already_dialing.insert(entry.node_id);
        // Maintenance path knows the expected NodeId (came from a
        // peer-list gossip frame); pass it so the dialer can verify
        // the TLS handshake.
        dialer.dial(entry.addr, Some(entry.node_id));
    }
    spawned
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use parking_lot::Mutex;

    use super::super::peer_list_task::LockedVec;
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
    struct RecordingDialer {
        dialed: Mutex<Vec<(SocketAddr, Option<NodeId>)>>,
    }

    impl Dialer for RecordingDialer {
        fn dial(&self, a: SocketAddr, expected: Option<NodeId>) {
            self.dialed.lock().push((a, expected));
        }
    }

    fn cfg(target: usize) -> MeshMaintenanceConfig {
        MeshMaintenanceConfig {
            interval: Duration::from_secs(5),
            target_degree: target,
        }
    }

    #[test]
    fn fills_deficit_in_a_single_tick() {
        let table = PeerTable::new(nid(0), 32);
        for i in 1..=10u8 {
            table.upsert(nid(i), addr(7000 + i as u16), 100);
        }
        let direct = LockedVec::new(); // empty
        let dialer = RecordingDialer::default();
        let mut dialing = HashSet::new();
        let mut rng = ChaCha20Rng::seed_from_u64(1);

        let spawned = tick_once(&cfg(8), &table, &direct, &dialer, &mut dialing, &mut rng);
        assert_eq!(spawned, 8);
        assert_eq!(dialer.dialed.lock().len(), 8);
        assert_eq!(dialing.len(), 8);

        // All dialed targets are valid candidates from the table and
        // distinct.
        let dialed = dialer.dialed.lock().clone();
        // Maintenance path always passes Some(NodeId).
        let mut ids: Vec<NodeId> = dialed
            .iter()
            .map(|(_, id)| id.expect("maintenance path passes Some"))
            .collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 8);
    }

    #[test]
    fn does_nothing_when_at_target_degree() {
        let table = PeerTable::new(nid(0), 32);
        for i in 1..=10u8 {
            table.upsert(nid(i), addr(7000 + i as u16), 100);
        }
        let direct = LockedVec::new();
        direct.set((1..=8u8).map(nid).collect());
        let dialer = RecordingDialer::default();
        let mut dialing = HashSet::new();
        let mut rng = ChaCha20Rng::seed_from_u64(2);

        let spawned = tick_once(&cfg(8), &table, &direct, &dialer, &mut dialing, &mut rng);
        assert_eq!(spawned, 0);
        assert!(dialer.dialed.lock().is_empty());
    }

    #[test]
    fn excludes_already_connected_peers_from_candidates() {
        let table = PeerTable::new(nid(0), 32);
        for i in 1..=10u8 {
            table.upsert(nid(i), addr(7000 + i as u16), 100);
        }
        let direct = LockedVec::new();
        direct.set(vec![nid(1), nid(2), nid(3)]); // 3 of 10 connected
        let dialer = RecordingDialer::default();
        let mut dialing = HashSet::new();
        let mut rng = ChaCha20Rng::seed_from_u64(3);

        let spawned = tick_once(&cfg(8), &table, &direct, &dialer, &mut dialing, &mut rng);
        assert_eq!(spawned, 5); // deficit = 8 - 3 = 5

        let dialed = dialer.dialed.lock();
        for (_, id) in dialed.iter() {
            let id = id.expect("maintenance path passes Some");
            assert!(
                !direct.snapshot().contains(&id),
                "dialed an already-direct peer {id:?}"
            );
        }
    }

    #[test]
    fn does_not_redial_peers_already_being_dialed() {
        let table = PeerTable::new(nid(0), 32);
        for i in 1..=10u8 {
            table.upsert(nid(i), addr(7000 + i as u16), 100);
        }
        let direct = LockedVec::new();
        let dialer = RecordingDialer::default();
        let mut dialing = HashSet::new();
        let mut rng = ChaCha20Rng::seed_from_u64(4);

        // First tick: deficit 8, candidates 10 → spawn 8. After this,
        // 8 peers are in `dialing`, 2 remain unspawned.
        let first = tick_once(&cfg(8), &table, &direct, &dialer, &mut dialing, &mut rng);
        assert_eq!(first, 8);

        // Direct still empty (mock dialer doesn't actually connect).
        // Second tick should NOT re-dial the same 8 peers; it sees the
        // remaining deficit but only 2 candidates are unspawned.
        let second = tick_once(&cfg(8), &table, &direct, &dialer, &mut dialing, &mut rng);
        assert_eq!(second, 2);
        assert_eq!(dialer.dialed.lock().len(), 10);
    }

    #[test]
    fn empty_table_emits_no_dials() {
        let table = PeerTable::new(nid(0), 32);
        let direct = LockedVec::new();
        let dialer = RecordingDialer::default();
        let mut dialing = HashSet::new();
        let mut rng = ChaCha20Rng::seed_from_u64(5);

        let spawned = tick_once(&cfg(8), &table, &direct, &dialer, &mut dialing, &mut rng);
        assert_eq!(spawned, 0);
        assert!(dialer.dialed.lock().is_empty());
    }

    #[test]
    fn unreachable_peers_are_never_dialed() {
        // Issue #138: outbound-only peers (advertising reachable=false)
        // must be filtered out of the candidate pool. A reachable node
        // with target_degree=4 and a table of 1 reachable + 6
        // unreachable should only dial the one reachable peer.
        let table = PeerTable::new(nid(0), 32);
        table.upsert_with_reachable(nid(1), addr(7001), 100, true);
        for i in 2..=7u8 {
            table.upsert_with_reachable(nid(i), addr(7000 + i as u16), 100, false);
        }
        let direct = LockedVec::new(); // empty
        let dialer = RecordingDialer::default();
        let mut dialing = HashSet::new();
        let mut rng = ChaCha20Rng::seed_from_u64(13);

        let spawned = tick_once(&cfg(4), &table, &direct, &dialer, &mut dialing, &mut rng);
        assert_eq!(spawned, 1, "only the reachable candidate may be dialed");
        let dialed = dialer.dialed.lock();
        assert_eq!(dialed.len(), 1);
        assert_eq!(dialed[0].1, Some(nid(1)));
    }

    #[test]
    fn small_table_can_only_partially_fill_deficit() {
        let table = PeerTable::new(nid(0), 32);
        for i in 1..=3u8 {
            table.upsert(nid(i), addr(7000 + i as u16), 100);
        }
        let direct = LockedVec::new();
        let dialer = RecordingDialer::default();
        let mut dialing = HashSet::new();
        let mut rng = ChaCha20Rng::seed_from_u64(6);

        let spawned = tick_once(&cfg(8), &table, &direct, &dialer, &mut dialing, &mut rng);
        assert_eq!(spawned, 3); // can't manufacture peers we don't know
    }

    #[test]
    fn convergence_to_target_degree_when_dials_succeed() {
        // Simulate: every dial "succeeds" and shows up in the direct
        // set on the next tick. Target degree 8; table has 25
        // candidates. We expect convergence in a single tick.
        let table = PeerTable::new(nid(0), 64);
        for i in 1..=25u8 {
            table.upsert(nid(i), addr(7000 + i as u16), 100);
        }
        let direct = LockedVec::new();
        let dialer = RecordingDialer::default();
        let mut dialing = HashSet::new();
        let mut rng = ChaCha20Rng::seed_from_u64(7);

        let first = tick_once(&cfg(8), &table, &direct, &dialer, &mut dialing, &mut rng);
        assert_eq!(first, 8);

        // Pretend every dialed peer connected.
        let dialed_ids: Vec<NodeId> = dialer
            .dialed
            .lock()
            .iter()
            .map(|(_, id)| id.expect("maintenance path passes Some"))
            .collect();
        direct.set(dialed_ids);

        // Subsequent ticks must be no-ops.
        for _ in 0..5 {
            let n = tick_once(&cfg(8), &table, &direct, &dialer, &mut dialing, &mut rng);
            assert_eq!(n, 0);
        }
        // Mock-dialer record stays at 8.
        assert_eq!(dialer.dialed.lock().len(), 8);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn run_mesh_maintenance_dials_at_least_once() {
        use crate::clock::TokioClock;

        let table = PeerTable::new(nid(0), 32);
        for i in 1..=10u8 {
            table.upsert(nid(i), addr(7000 + i as u16), 100);
        }
        let direct = Arc::new(LockedVec::new());
        let recording = Arc::new(RecordingDialer::default());

        let direct_dyn: Arc<dyn DirectPeers> = direct.clone();
        let dialer_dyn: Arc<dyn Dialer> = recording.clone();
        let clock: Arc<dyn Clock> = Arc::new(TokioClock::new());

        let (sd_tx, sd_rx) = oneshot::channel();
        let task = tokio::spawn(run_mesh_maintenance(
            cfg(4),
            table,
            direct_dyn,
            dialer_dyn,
            clock,
            /* seed */ 99,
            sd_rx,
        ));

        // Two advance-yield cycles: the first lets the task poll
        // through the immediate-tick discard, the second fires the
        // first real tick that calls `tick_once`.
        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;

        let _ = sd_tx.send(());
        let _ = task.await;

        let dialed = recording.dialed.lock();
        assert_eq!(dialed.len(), 4, "fired one tick that filled deficit=4");
    }
}
