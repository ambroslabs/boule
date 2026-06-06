//! Partial-mesh maintenance loop.
//!
//! Once per [`MeshMaintenanceConfig::interval`], compares the
//! currently-direct peer count against `outbound_target` and, if
//! there's a deficit, asks the [`Dialer`] to start outbound dial
//! loops for enough fresh candidates from the
//! [`super::peer_table::PeerTable`] to close the gap.
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
//! `outbound_target` happens only briefly when a previously-unreachable
//! peer comes back online and we're already at K with replacements.
//! A future enhancement (#513, sub of #187) adds proactive trim once
//! the realised outbound count drifts above the target for ≥ 2
//! consecutive ticks.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rand::SeedableRng;
use rand::seq::SliceRandom;
use rand_chacha::ChaCha20Rng;
use tokio::sync::oneshot;
use tracing::{debug, info};

use boule_core::clock::Clock;

use super::super::super::tls::NodeId;
use super::peer_list_task::DirectPeers;
use super::peer_table::PeerTable;

/// Knobs for [`run_mesh_maintenance`]. Defaults match the breakdown
/// comment on issue #137 plus the direct-peer budget split from #187.
#[derive(Debug, Clone)]
pub struct MeshMaintenanceConfig {
    /// How often the loop wakes up and re-evaluates the deficit.
    pub interval: Duration,
    /// Soft floor on the number of outbound direct peers we want to
    /// maintain. When `direct_peers().len() < outbound_target`, the
    /// loop spawns dialers for the difference. Renamed from
    /// `target_degree` in #187 to disambiguate from the new inbound
    /// and total caps.
    pub outbound_target: usize,
    /// Sentry-topology persistent peers (#827, cf. Tendermint
    /// `persistent_peers`). The trim path **never** evicts a peer in
    /// this set, even when the realised outbound count drifts above
    /// `outbound_target` — so the critical validator↔sentry links stay
    /// up under churn/load.
    pub persistent: HashSet<NodeId>,
}

impl Default for MeshMaintenanceConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(5),
            outbound_target: 8,
            persistent: HashSet::new(),
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

    /// Tear down a previously-dialed outbound peer (#187 / #513).
    /// Used by the trim path to drop the most-recently-added outbound
    /// peer when the realised outbound count drifts above
    /// `outbound_target` for two consecutive ticks. Best-effort: the
    /// production impl wraps `PeerCommand::Disconnect`, which the
    /// manager processes asynchronously. The default no-op exists
    /// so tests / impls that don't exercise trim can stay terse.
    fn disconnect(&self, _node_id: NodeId) {}
}

/// Per-loop state carried across [`tick_once`] invocations. Holds the
/// "we already kicked off a dialer for this peer" tracking + the
/// trim streak counter.
///
/// `dialed_membership` and `dialed_order` are kept in sync so the
/// trim path can pop the most-recently-added entry in O(1) while the
/// hot deficit-fill path retains O(1) membership checks. Insertions
/// and removals only happen in `tick_once`, so the two stay
/// consistent without external synchronisation.
#[derive(Debug, Default)]
pub struct MaintenanceState {
    /// Membership set for `dialed_order`. Same NodeIds, optimised for
    /// the hot deficit-fill path.
    dialed_membership: HashSet<NodeId>,
    /// Maintenance-loop-initiated dial targets in insertion order.
    /// The trim path pops from the back to drop the most-recently-
    /// added outbound peer (#187). Bootstrap dials (which go through
    /// [`super::discovery::GossipDiscovery`]) are intentionally not
    /// recorded here — operator-explicit peers stay outside the
    /// trim's scope.
    dialed_order: Vec<NodeId>,
    /// Number of consecutive ticks the realised outbound count has
    /// been strictly above `outbound_target`. Reset to zero on any
    /// tick where we're at-or-below target. Trim only fires once this
    /// reaches 2 — single-tick spikes (e.g. a peer reconnecting while
    /// we're already at K) intentionally don't cause churn.
    over_target_streak: u32,
}

impl MaintenanceState {
    /// Start a fresh state. Equivalent to `MaintenanceState::default()`
    /// but spelled out for readability at the call sites.
    pub fn new() -> Self {
        Self::default()
    }

    /// `true` when `node_id` has been dispatched to the dialer by a
    /// previous [`tick_once`] call. Used to suppress redundant dials
    /// across ticks (the dialer's own reconnect loop handles drops).
    pub fn is_dialing(&self, node_id: &NodeId) -> bool {
        self.dialed_membership.contains(node_id)
    }

    /// Record that we just spawned a dialer for `node_id`. Idempotent
    /// in the sense that pushing the same id twice keeps it in
    /// `dialed_order` once (we never call this twice for the same id
    /// in `tick_once`, but the impl is defensive against future
    /// drift).
    fn record_dial(&mut self, node_id: NodeId) {
        if self.dialed_membership.insert(node_id) {
            self.dialed_order.push(node_id);
        }
    }

    /// Number of dialer-initiated peers currently tracked. Visible to
    /// tests so they can assert trim's effect on the bookkeeping.
    #[cfg(test)]
    pub fn dialed_count(&self) -> usize {
        self.dialed_order.len()
    }
}

/// Cumulative counters for the maintenance loop, shared between the
/// running task and any status / introspection reader via an [`Arc`].
///
/// This is the egress-side analogue of
/// [`ConnectionLimiter::rejects`](boule_core::transport::limits::ConnectionLimiter::rejects):
/// that counter covers admit-side rejections, this one covers the trim
/// path's outbound tear-downs. Trim disconnects bypass the limiter
/// entirely — they go out via `PeerCommand::Disconnect` rather than
/// `try_admit` — so without this counter a node churning above
/// `outbound_target` is invisible to anything but INFO-log grepping.
#[derive(Debug, Default)]
pub struct MaintenanceMetrics {
    /// Cumulative outbound peers torn down by the trim path. One per
    /// `dialer.disconnect` the loop issued because the realised
    /// outbound count drifted above `outbound_target` for two
    /// consecutive ticks.
    trims: AtomicU64,
}

impl MaintenanceMetrics {
    /// Cumulative trim disconnects since the loop started.
    pub fn trims(&self) -> u64 {
        self.trims.load(Ordering::Relaxed)
    }

    /// Fold one tick's [`TickOutcome::trimmed`] into the running
    /// total. Called once per tick by [`run_mesh_maintenance`]; the
    /// per-tick count is exactly the number of `dialer.disconnect`
    /// calls that tick issued.
    fn record_trims(&self, n: usize) {
        if n > 0 {
            self.trims.fetch_add(n as u64, Ordering::Relaxed);
        }
    }
}

/// Run the partial-mesh maintenance loop until `shutdown` fires.
///
/// `direct` is sampled every tick to read the live direct-peer
/// count. `table` is consulted for unconnected candidates when there
/// is a deficit.
#[allow(clippy::too_many_arguments)]
pub async fn run_mesh_maintenance(
    config: MeshMaintenanceConfig,
    table: PeerTable,
    direct: Arc<dyn DirectPeers>,
    dialer: Arc<dyn Dialer>,
    clock: Arc<dyn Clock>,
    rng_seed: u64,
    metrics: Arc<MaintenanceMetrics>,
    mut shutdown: oneshot::Receiver<()>,
) {
    let mut rng = ChaCha20Rng::seed_from_u64(rng_seed);
    let mut interval = clock.interval(config.interval);
    let mut state = MaintenanceState::new();

    // Discard the immediate-tick (matching the peer-list publisher);
    // the first real tick fires after `interval`.
    interval.tick().await;

    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => return,
            _ = interval.tick() => {
                let outcome = tick_once(
                    &config,
                    &table,
                    direct.as_ref(),
                    dialer.as_ref(),
                    &mut state,
                    &mut rng,
                );
                metrics.record_trims(outcome.trimmed);
            }
        }
    }
}

/// Outcome of a single [`tick_once`] call. Tests assert against this
/// directly to distinguish the deficit-fill path from the trim path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TickOutcome {
    /// Number of new dialer tasks spawned this tick (deficit fill).
    pub spawned: usize,
    /// Number of outbound peers torn down this tick (trim above
    /// `outbound_target`, #187). Mutually exclusive with `spawned`:
    /// trim only fires when we are above target, and dialing only
    /// fires when we are below.
    pub trimmed: usize,
}

/// Single maintenance pass — exposed for tests so they can drive the
/// loop deterministically without paused timers.
///
/// Invariants:
/// - When `direct.len() < outbound_target`, fills the deficit by
///   spawning fresh dialers (subject to the candidate pool's size)
///   and resets the trim streak.
/// - When `direct.len() == outbound_target`, no-op and resets the
///   trim streak.
/// - When `direct.len() > outbound_target`: increments the trim
///   streak. On the *second* consecutive tick above target, drops
///   the most-recently-added dialer-initiated peers until the
///   realised outbound count is back at target.
pub fn tick_once(
    config: &MeshMaintenanceConfig,
    table: &PeerTable,
    direct: &dyn DirectPeers,
    dialer: &dyn Dialer,
    state: &mut MaintenanceState,
    rng: &mut ChaCha20Rng,
) -> TickOutcome {
    let direct_now = direct.snapshot();
    let direct_count = direct_now.len();

    // Above target: candidate trim path (#187 / #513).
    if direct_count > config.outbound_target {
        state.over_target_streak = state.over_target_streak.saturating_add(1);
        if state.over_target_streak < 2 {
            // First tick above target: stay our hand. Single-tick
            // spikes (e.g. a previously-unreachable peer reconnects
            // and pushes us briefly above K) shouldn't cause churn.
            debug!(
                direct = direct_count,
                outbound_target = config.outbound_target,
                "mesh maintenance: above target on first tick — deferring trim"
            );
            return TickOutcome::default();
        }
        // Second consecutive tick above target — trim down. Only
        // peers the maintenance loop itself initiated dials for are
        // candidates; bootstrap peers (operator-explicit) stay
        // intact even if they push us above target.
        let direct_set: HashSet<NodeId> = direct_now.iter().copied().collect();
        let mut excess = direct_count.saturating_sub(config.outbound_target);
        let mut trimmed = 0usize;

        // Walk the dialed-order vector from the back (LIFO of
        // dialer-initiated peers), disconnecting peers that are
        // currently direct. The "currently direct" filter matters
        // because a dialer we spawned may not yet have produced a
        // direct connection — those don't count toward the realised
        // outbound count and shouldn't be torn down.
        while excess > 0 {
            // Borrow `dialed_order` and look for a tail entry whose
            // peer is direct. Walking from the back keeps the LIFO
            // promise; if the tail entry isn't direct yet, we still
            // want to skip past it without losing it from the
            // tracking set.
            let tail_idx = state.dialed_order.len();
            if tail_idx == 0 {
                break;
            }
            let mut found_at: Option<usize> = None;
            for i in (0..tail_idx).rev() {
                let id = state.dialed_order[i];
                // Persistent peers (sentry topology, #827) are never
                // trimmed: skip them so a validator↔sentry link is
                // preserved even above `outbound_target`.
                if config.persistent.contains(&id) {
                    continue;
                }
                if direct_set.contains(&id) {
                    found_at = Some(i);
                    break;
                }
            }
            let Some(idx) = found_at else {
                // No dialer-initiated peer is currently direct;
                // anything pushing us above target must be inbound
                // or bootstrap. Trim cannot legitimately act on
                // those, so stop.
                break;
            };
            let id = state.dialed_order.remove(idx);
            state.dialed_membership.remove(&id);
            info!(
                peer = %super::super::super::tls::node_id_to_base58(&id),
                "mesh maintenance: trimming outbound peer (above outbound_target)"
            );
            dialer.disconnect(id);
            trimmed += 1;
            excess -= 1;
        }

        if trimmed > 0 {
            // Reset the streak once we acted; if we still drift above
            // target on subsequent ticks, the streak rebuilds and
            // trim re-fires after another two ticks.
            state.over_target_streak = 0;
        }
        return TickOutcome {
            spawned: 0,
            trimmed,
        };
    }

    // At-or-below target: any pending trim streak is over.
    state.over_target_streak = 0;

    if direct_count == config.outbound_target {
        return TickOutcome::default();
    }

    let direct_set: HashSet<NodeId> = direct_now.iter().copied().collect();
    let deficit = config.outbound_target - direct_count;

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
        .filter(|e| !state.is_dialing(&e.node_id))
        .collect();
    if candidates.is_empty() {
        debug!(
            deficit,
            "mesh maintenance: deficit but no unconnected candidates in peer table"
        );
        return TickOutcome::default();
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
        state.record_dial(entry.node_id);
        // Maintenance path knows the expected NodeId (came from a
        // peer-list gossip frame); pass it so the dialer can verify
        // the TLS handshake.
        dialer.dial(entry.addr, Some(entry.node_id));
    }
    TickOutcome {
        spawned,
        trimmed: 0,
    }
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
        disconnected: Mutex<Vec<NodeId>>,
    }

    impl Dialer for RecordingDialer {
        fn dial(&self, a: SocketAddr, expected: Option<NodeId>) {
            self.dialed.lock().push((a, expected));
        }
        fn disconnect(&self, node_id: NodeId) {
            self.disconnected.lock().push(node_id);
        }
    }

    fn cfg(target: usize) -> MeshMaintenanceConfig {
        MeshMaintenanceConfig {
            interval: Duration::from_secs(5),
            outbound_target: target,
            persistent: HashSet::new(),
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
        let mut state = MaintenanceState::new();
        let mut rng = ChaCha20Rng::seed_from_u64(1);

        let outcome = tick_once(&cfg(8), &table, &direct, &dialer, &mut state, &mut rng);
        assert_eq!(outcome.spawned, 8);
        assert_eq!(outcome.trimmed, 0);
        assert_eq!(dialer.dialed.lock().len(), 8);
        assert_eq!(state.dialed_count(), 8);

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
    fn does_nothing_when_at_outbound_target() {
        let table = PeerTable::new(nid(0), 32);
        for i in 1..=10u8 {
            table.upsert(nid(i), addr(7000 + i as u16), 100);
        }
        let direct = LockedVec::new();
        direct.set((1..=8u8).map(nid).collect());
        let dialer = RecordingDialer::default();
        let mut state = MaintenanceState::new();
        let mut rng = ChaCha20Rng::seed_from_u64(2);

        let outcome = tick_once(&cfg(8), &table, &direct, &dialer, &mut state, &mut rng);
        assert_eq!(outcome.spawned, 0);
        assert_eq!(outcome.trimmed, 0);
        assert!(dialer.dialed.lock().is_empty());
        assert!(dialer.disconnected.lock().is_empty());
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
        let mut state = MaintenanceState::new();
        let mut rng = ChaCha20Rng::seed_from_u64(3);

        let outcome = tick_once(&cfg(8), &table, &direct, &dialer, &mut state, &mut rng);
        assert_eq!(outcome.spawned, 5); // deficit = 8 - 3 = 5

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
        let mut state = MaintenanceState::new();
        let mut rng = ChaCha20Rng::seed_from_u64(4);

        // First tick: deficit 8, candidates 10 → spawn 8. After this,
        // 8 peers are in `state.dialed_*`, 2 remain unspawned.
        let first = tick_once(&cfg(8), &table, &direct, &dialer, &mut state, &mut rng);
        assert_eq!(first.spawned, 8);

        // Direct still empty (mock dialer doesn't actually connect).
        // Second tick should NOT re-dial the same 8 peers; it sees the
        // remaining deficit but only 2 candidates are unspawned.
        let second = tick_once(&cfg(8), &table, &direct, &dialer, &mut state, &mut rng);
        assert_eq!(second.spawned, 2);
        assert_eq!(dialer.dialed.lock().len(), 10);
    }

    #[test]
    fn empty_table_emits_no_dials() {
        let table = PeerTable::new(nid(0), 32);
        let direct = LockedVec::new();
        let dialer = RecordingDialer::default();
        let mut state = MaintenanceState::new();
        let mut rng = ChaCha20Rng::seed_from_u64(5);

        let outcome = tick_once(&cfg(8), &table, &direct, &dialer, &mut state, &mut rng);
        assert_eq!(outcome.spawned, 0);
        assert!(dialer.dialed.lock().is_empty());
    }

    #[test]
    fn unreachable_peers_are_never_dialed() {
        // Issue #138: outbound-only peers (advertising reachable=false)
        // must be filtered out of the candidate pool. A reachable node
        // with outbound_target=4 and a table of 1 reachable + 6
        // unreachable should only dial the one reachable peer.
        let table = PeerTable::new(nid(0), 32);
        table.upsert_with_reachable(nid(1), addr(7001), 100, true);
        for i in 2..=7u8 {
            table.upsert_with_reachable(nid(i), addr(7000 + i as u16), 100, false);
        }
        let direct = LockedVec::new(); // empty
        let dialer = RecordingDialer::default();
        let mut state = MaintenanceState::new();
        let mut rng = ChaCha20Rng::seed_from_u64(13);

        let outcome = tick_once(&cfg(4), &table, &direct, &dialer, &mut state, &mut rng);
        assert_eq!(
            outcome.spawned, 1,
            "only the reachable candidate may be dialed"
        );
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
        let mut state = MaintenanceState::new();
        let mut rng = ChaCha20Rng::seed_from_u64(6);

        let outcome = tick_once(&cfg(8), &table, &direct, &dialer, &mut state, &mut rng);
        assert_eq!(outcome.spawned, 3); // can't manufacture peers we don't know
    }

    #[test]
    fn convergence_to_outbound_target_when_dials_succeed() {
        // Simulate: every dial "succeeds" and shows up in the direct
        // set on the next tick. Target degree 8; table has 25
        // candidates. We expect convergence in a single tick.
        let table = PeerTable::new(nid(0), 64);
        for i in 1..=25u8 {
            table.upsert(nid(i), addr(7000 + i as u16), 100);
        }
        let direct = LockedVec::new();
        let dialer = RecordingDialer::default();
        let mut state = MaintenanceState::new();
        let mut rng = ChaCha20Rng::seed_from_u64(7);

        let first = tick_once(&cfg(8), &table, &direct, &dialer, &mut state, &mut rng);
        assert_eq!(first.spawned, 8);

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
            let n = tick_once(&cfg(8), &table, &direct, &dialer, &mut state, &mut rng);
            assert_eq!(n.spawned, 0);
            assert_eq!(n.trimmed, 0);
        }
        // Mock-dialer record stays at 8.
        assert_eq!(dialer.dialed.lock().len(), 8);
    }

    /// #187 / #513: a single tick above target must not trim — that
    /// gives a previously-unreachable peer that briefly pushed us
    /// over the target a chance to settle. The streak counter
    /// prevents single-tick spikes from causing churn.
    #[test]
    fn first_tick_above_target_defers_trim() {
        let table = PeerTable::new(nid(0), 64);
        let direct = LockedVec::new();
        // 5 direct peers, target = 4. First tick: above by one, but
        // streak hasn't reached 2 yet → no-op.
        direct.set((1..=5u8).map(nid).collect());
        // Pretend peers 1..=5 were all maintenance-loop-dialed (so
        // they're trim candidates) by recording dials retroactively.
        // The test exercises trim via state, not via the candidate
        // pool, so the table can stay empty.
        let dialer = RecordingDialer::default();
        let mut state = MaintenanceState::new();
        for i in 1..=5u8 {
            state.record_dial(nid(i));
        }
        let mut rng = ChaCha20Rng::seed_from_u64(101);

        let outcome = tick_once(&cfg(4), &table, &direct, &dialer, &mut state, &mut rng);
        assert_eq!(outcome.trimmed, 0, "no trim on first tick above target");
        assert_eq!(outcome.spawned, 0);
        assert!(dialer.disconnected.lock().is_empty());
    }

    /// #187 / #513 acceptance: a node booted with a peer table well
    /// above `outbound_target` is brought back to target within 2
    /// maintenance ticks. The first tick observes the over-target
    /// streak; the second tick trims down.
    #[test]
    fn trim_brings_count_back_within_two_ticks() {
        let table = PeerTable::new(nid(0), 64);
        let direct = LockedVec::new();
        // 12 direct peers, target = 4 — well above target.
        direct.set((1..=12u8).map(nid).collect());
        let dialer = RecordingDialer::default();
        let mut state = MaintenanceState::new();
        // All 12 are maintenance-loop-dialed (so they're trim
        // candidates). Record in ascending order so the LIFO trim
        // pops 12, then 11, ...
        for i in 1..=12u8 {
            state.record_dial(nid(i));
        }
        let mut rng = ChaCha20Rng::seed_from_u64(102);

        // Tick 1: defer (streak = 1).
        let first = tick_once(&cfg(4), &table, &direct, &dialer, &mut state, &mut rng);
        assert_eq!(first.trimmed, 0);
        assert!(dialer.disconnected.lock().is_empty());

        // Tick 2: trim 8 peers (12 - 4 = 8) so direct count drops to
        // target. LIFO order means the last-dialed (12, 11, 10, ...)
        // are torn down first.
        let second = tick_once(&cfg(4), &table, &direct, &dialer, &mut state, &mut rng);
        assert_eq!(second.trimmed, 8);
        assert_eq!(second.spawned, 0);

        let trimmed_ids: Vec<NodeId> = dialer.disconnected.lock().clone();
        assert_eq!(trimmed_ids.len(), 8);
        // Most-recently-added are torn down: 12, 11, 10, 9, 8, 7, 6, 5.
        let expected: Vec<NodeId> = (5..=12u8).rev().map(nid).collect();
        assert_eq!(trimmed_ids, expected);

        // The state's dialed bookkeeping shrinks to match.
        assert_eq!(state.dialed_count(), 4);
    }

    /// Trim only acts on peers the maintenance loop initiated — a
    /// bootstrap or inbound peer pushing us above target is *not*
    /// torn down (the operator put it there explicitly, or someone
    /// else dialed us). The trim then has nothing to act on and
    /// stops after disconnecting only the maintenance-initiated
    /// peers it can reach.
    #[test]
    fn trim_skips_non_dialer_initiated_peers() {
        let table = PeerTable::new(nid(0), 64);
        let direct = LockedVec::new();
        // 6 direct peers; only 2 of them are dialer-initiated.
        direct.set((1..=6u8).map(nid).collect());
        let dialer = RecordingDialer::default();
        let mut state = MaintenanceState::new();
        // Mark only nid(5) and nid(6) as maintenance-initiated.
        state.record_dial(nid(5));
        state.record_dial(nid(6));
        let mut rng = ChaCha20Rng::seed_from_u64(103);

        // Tick 1: defer.
        let _ = tick_once(&cfg(2), &table, &direct, &dialer, &mut state, &mut rng);
        // Tick 2: trim. Excess = 4, but only 2 candidates exist; trim
        // both and stop (nid(1)..=nid(4) are out of trim's scope).
        let outcome = tick_once(&cfg(2), &table, &direct, &dialer, &mut state, &mut rng);
        assert_eq!(outcome.trimmed, 2);
        let trimmed: Vec<NodeId> = dialer.disconnected.lock().clone();
        assert_eq!(trimmed, vec![nid(6), nid(5)]);
        assert_eq!(state.dialed_count(), 0);
    }

    /// A persistent peer (sentry topology, #827) is never trimmed even
    /// when it sits above `outbound_target` across multiple ticks — the
    /// validator↔sentry link must survive churn/load.
    #[test]
    fn persistent_peer_never_trimmed() {
        let table = PeerTable::new(nid(0), 64);
        let direct = LockedVec::new();
        // 3 direct peers, target = 1 → 2 over target. nid(1) is the
        // persistent (validator) link; nid(2), nid(3) are trimmable.
        direct.set(vec![nid(1), nid(2), nid(3)]);
        let dialer = RecordingDialer::default();
        let mut state = MaintenanceState::new();
        for i in 1..=3u8 {
            state.record_dial(nid(i));
        }
        let mut rng = ChaCha20Rng::seed_from_u64(827);

        let persistent: HashSet<NodeId> = [nid(1)].into_iter().collect();
        let cfg = MeshMaintenanceConfig {
            interval: Duration::from_secs(5),
            outbound_target: 1,
            persistent,
        };

        // Tick 1: defer (streak = 1).
        let first = tick_once(&cfg, &table, &direct, &dialer, &mut state, &mut rng);
        assert_eq!(first.trimmed, 0);

        // Tick 2: trim. Excess = 2; only nid(2)/nid(3) are eligible —
        // the persistent nid(1) is skipped and stays connected.
        let second = tick_once(&cfg, &table, &direct, &dialer, &mut state, &mut rng);
        assert_eq!(second.trimmed, 2);
        let trimmed: Vec<NodeId> = dialer.disconnected.lock().clone();
        assert!(
            !trimmed.contains(&nid(1)),
            "persistent peer must never be trimmed",
        );
        assert!(trimmed.contains(&nid(2)));
        assert!(trimmed.contains(&nid(3)));
    }

    /// A persistent peer alone over the target produces zero trims —
    /// `TickOutcome.trimmed == 0`.
    #[test]
    fn persistent_peer_alone_over_target_yields_no_trim() {
        let table = PeerTable::new(nid(0), 64);
        let direct = LockedVec::new();
        // 2 direct peers, both persistent, target = 1 → 1 over target,
        // but neither is eligible for trim.
        direct.set(vec![nid(1), nid(2)]);
        let dialer = RecordingDialer::default();
        let mut state = MaintenanceState::new();
        state.record_dial(nid(1));
        state.record_dial(nid(2));
        let mut rng = ChaCha20Rng::seed_from_u64(8270);

        let persistent: HashSet<NodeId> = [nid(1), nid(2)].into_iter().collect();
        let cfg = MeshMaintenanceConfig {
            interval: Duration::from_secs(5),
            outbound_target: 1,
            persistent,
        };

        // Two ticks above target; trim never fires on persistent peers.
        let _ = tick_once(&cfg, &table, &direct, &dialer, &mut state, &mut rng);
        let outcome = tick_once(&cfg, &table, &direct, &dialer, &mut state, &mut rng);
        assert_eq!(outcome.trimmed, 0, "no persistent peer may be trimmed");
        assert!(dialer.disconnected.lock().is_empty());
    }

    /// Streak resets to zero on a tick at-or-below target; if a
    /// later tick goes above again, trim takes another two ticks.
    #[test]
    fn streak_resets_on_at_or_below_target_tick() {
        let table = PeerTable::new(nid(0), 64);
        let direct = LockedVec::new();
        let dialer = RecordingDialer::default();
        let mut state = MaintenanceState::new();
        for i in 1..=6u8 {
            state.record_dial(nid(i));
        }
        let mut rng = ChaCha20Rng::seed_from_u64(104);

        // Tick A: above target → streak=1, no trim.
        direct.set((1..=6u8).map(nid).collect());
        let _ = tick_once(&cfg(4), &table, &direct, &dialer, &mut state, &mut rng);
        assert!(dialer.disconnected.lock().is_empty());

        // Tick B: at-or-below target → streak resets.
        direct.set((1..=4u8).map(nid).collect());
        let _ = tick_once(&cfg(4), &table, &direct, &dialer, &mut state, &mut rng);
        assert!(dialer.disconnected.lock().is_empty());

        // Tick C: above target again → streak=1 (NOT 2 — reset
        // happened), still no trim.
        direct.set((1..=6u8).map(nid).collect());
        let _ = tick_once(&cfg(4), &table, &direct, &dialer, &mut state, &mut rng);
        assert!(
            dialer.disconnected.lock().is_empty(),
            "streak reset must require two fresh consecutive ticks"
        );

        // Tick D: above target two ticks running → trim.
        let outcome = tick_once(&cfg(4), &table, &direct, &dialer, &mut state, &mut rng);
        assert_eq!(outcome.trimmed, 2);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn run_mesh_maintenance_dials_at_least_once() {
        use boule_core::clock::TokioClock;

        let table = PeerTable::new(nid(0), 32);
        for i in 1..=10u8 {
            table.upsert(nid(i), addr(7000 + i as u16), 100);
        }
        let direct = Arc::new(LockedVec::new());
        let recording = Arc::new(RecordingDialer::default());

        let direct_dyn: Arc<dyn DirectPeers> = direct.clone();
        let dialer_dyn: Arc<dyn Dialer> = recording.clone();
        let clock: Arc<dyn Clock> = Arc::new(TokioClock::new());

        let metrics = Arc::new(MaintenanceMetrics::default());
        let (sd_tx, sd_rx) = oneshot::channel();
        let task = tokio::spawn(run_mesh_maintenance(
            cfg(4),
            table,
            direct_dyn,
            dialer_dyn,
            clock,
            /* seed */ 99,
            metrics,
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

    #[test]
    fn maintenance_metrics_accumulate_trims() {
        let m = MaintenanceMetrics::default();
        assert_eq!(m.trims(), 0, "fresh counter starts at zero");
        // A no-op tick (nothing trimmed) leaves the counter untouched.
        m.record_trims(0);
        assert_eq!(m.trims(), 0);
        // Subsequent trimming ticks fold their per-tick counts in.
        m.record_trims(3);
        m.record_trims(2);
        assert_eq!(m.trims(), 5);
    }

    /// End-to-end through the real loop: the counter reflects the
    /// `TickOutcome::trimmed` the trim path produced. Drives three
    /// real ticks — fill, defer (streak=1), trim (streak=2) — and
    /// asserts the metric matches the disconnects the dialer saw.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn run_mesh_maintenance_counts_trim_disconnects() {
        use boule_core::clock::TokioClock;

        let table = PeerTable::new(nid(0), 32);
        for i in 1..=12u8 {
            table.upsert(nid(i), addr(7000 + i as u16), 100);
        }
        let direct = Arc::new(LockedVec::new());
        let recording = Arc::new(RecordingDialer::default());
        let metrics = Arc::new(MaintenanceMetrics::default());

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
            /* seed */ 7,
            metrics.clone(),
            sd_rx,
        ));

        // Discard the immediate-tick.
        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;

        // Tick 1: direct is empty → fill the deficit of 4. These four
        // become the only dialer-initiated (and thus trimmable) peers.
        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;
        let dialed: Vec<NodeId> = recording
            .dialed
            .lock()
            .iter()
            .map(|(_, id)| id.expect("maintenance path passes Some"))
            .collect();
        assert_eq!(dialed.len(), 4);
        assert_eq!(metrics.trims(), 0, "fill ticks trim nothing");

        // Make the four dialer-initiated peers direct, plus four
        // inbound peers the trim path must leave alone → 8 direct,
        // target 4.
        let mut now_direct = dialed.clone();
        now_direct.extend([nid(200), nid(201), nid(202), nid(203)]);
        direct.set(now_direct);

        // Tick 2: above target, first consecutive tick → defer.
        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;
        assert_eq!(metrics.trims(), 0, "first over-target tick defers trim");

        // Tick 3: above target, second consecutive tick → trim the
        // four dialer-initiated peers (inbound peers are out of scope).
        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;

        let _ = sd_tx.send(());
        let _ = task.await;

        assert_eq!(
            recording.disconnected.lock().len(),
            4,
            "trimmed the four dialer-initiated peers",
        );
        assert_eq!(
            metrics.trims(),
            4,
            "counter equals the cumulative trim disconnects",
        );
    }
}
