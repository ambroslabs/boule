//! Unit tests for the pacemaker state machine plus a multi-pacemaker
//! liveness simulation covering the `f = 1` scenario from #22's
//! verification criteria.
//!
//! The sim uses a hand-rolled synchronous bus because the pacemaker has
//! no I/O — a full driver would just add indirection. The bus is a plain
//! loop over the four pacemakers and a mock safety-core that issues
//! QCs / TCs when quorum is reached.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use crate::View;
use crate::pacemaker::leader::{LeaderSelector, RoundRobinSelector};
use crate::pacemaker::timeout::{ExponentialBackoff, TimeoutPolicy};
use crate::pacemaker::{Action, AdvanceCause, Event, HonestyThresholdEvidence, Pacemaker};
use crate::validator_set::ValidatorSet;
use boule_core::identity::NodeId;

// ---------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------

/// Build a deterministic `[u8; 32]` NodeId from a single discriminator.
fn nid(b: u8) -> NodeId {
    [b; 32]
}

const BASE_MS: u64 = 100;
const MAX_MS: u64 = 10_000;

fn base_timeout() -> Duration {
    Duration::from_millis(BASE_MS)
}

fn vid(b: u8) -> crate::validator_set::ValidatorId {
    crate::validator_set::ValidatorId::from_genesis_pubkey(nid(b))
}

fn validators() -> Arc<ValidatorSet> {
    Arc::new(ValidatorSet::new(vec![vid(1), vid(2), vid(3), vid(4)]))
}

fn selector(vs: Arc<ValidatorSet>) -> Arc<dyn LeaderSelector> {
    Arc::new(RoundRobinSelector::from_genesis_set(vs))
}

fn policy() -> Arc<dyn TimeoutPolicy> {
    Arc::new(ExponentialBackoff::new(
        Duration::from_millis(BASE_MS),
        Duration::from_millis(MAX_MS),
    ))
}

/// Build a pacemaker whose `self_id` is `nid(self_byte)` over the
/// four-validator set `[nid(1), nid(2), nid(3), nid(4)]`.
fn make_pm(self_byte: u8) -> Pacemaker {
    Pacemaker::new(nid(self_byte), selector(validators()), policy())
}

fn find_reset_timer(actions: &[Action]) -> Option<Duration> {
    actions.iter().find_map(|a| match a {
        Action::ResetTimer(d) => Some(*d),
        _ => None,
    })
}

/// Mint an `OnRoundSync` evidence token for tests by feeding a bucket
/// at the threshold (1, 1) — exercises the same `from_bucket` API the
/// integration uses without depending on `n / 3 + 1` arithmetic here.
fn round_sync_evidence() -> HonestyThresholdEvidence {
    HonestyThresholdEvidence::from_bucket(1, 1).expect("threshold met")
}

// ---------------------------------------------------------------------
// Unit tests — the eight step()-semantics cases from the issue
// ---------------------------------------------------------------------

#[test]
fn two_timeouts_then_tc_advances_to_view_1() {
    let mut pm = make_pm(1);
    let _ = pm.step(Event::OnTimeout(View(0)));
    let _ = pm.step(Event::OnTimeout(View(0)));
    assert_eq!(pm.current_view(), View(0));
    assert_eq!(pm.consecutive_failures(), 2);

    let actions = pm.step(Event::OnTimeoutCert(View(0)));
    assert_eq!(pm.current_view(), View(1));
    assert_eq!(pm.consecutive_failures(), 0);
    assert_eq!(
        actions[0],
        Action::AdvanceToView {
            view: View(1),
            cause: AdvanceCause::Tc,
        }
    );
    assert_eq!(find_reset_timer(&actions), Some(base_timeout()));
}

#[test]
fn qc_for_future_view_jumps_and_resets_failures() {
    let mut pm = make_pm(1);
    let _ = pm.step(Event::OnTimeout(View(0)));
    let _ = pm.step(Event::OnTimeout(View(0)));
    assert_eq!(pm.consecutive_failures(), 2);

    let actions = pm.step(Event::OnQc(View(5)));
    assert_eq!(pm.current_view(), View(6));
    assert_eq!(pm.high_qc_view(), View(5));
    assert_eq!(pm.consecutive_failures(), 0);
    assert_eq!(
        actions[0],
        Action::AdvanceToView {
            view: View(6),
            cause: AdvanceCause::Qc,
        }
    );
    assert_eq!(find_reset_timer(&actions), Some(base_timeout()));
}

#[test]
fn stale_qc_is_noop() {
    let mut pm = make_pm(1);
    // Jump forward so 0 is stale.
    let _ = pm.step(Event::OnQc(View(5)));
    assert_eq!(pm.current_view(), View(6));

    let actions = pm.step(Event::OnQc(View(0)));
    assert!(actions.is_empty());
    assert_eq!(pm.current_view(), View(6));
    assert_eq!(pm.high_qc_view(), View(5));
}

#[test]
fn timeout_for_non_current_view_is_ignored() {
    let mut pm = make_pm(1);
    // Advance to view 4 via TC.
    let _ = pm.step(Event::OnTimeoutCert(View(3)));
    assert_eq!(pm.current_view(), View(4));

    // Stale view.
    assert!(pm.step(Event::OnTimeout(View(2))).is_empty());
    // Future view.
    assert!(pm.step(Event::OnTimeout(View(7))).is_empty());
    assert_eq!(pm.consecutive_failures(), 0);
}

#[test]
fn backoff_grows_with_successive_timeouts() {
    let mut pm = make_pm(1);
    let a1 = pm.step(Event::OnTimeout(View(0)));
    let a2 = pm.step(Event::OnTimeout(View(0)));
    let a3 = pm.step(Event::OnTimeout(View(0)));

    assert_eq!(
        find_reset_timer(&a1),
        Some(Duration::from_millis(BASE_MS * 2))
    );
    assert_eq!(
        find_reset_timer(&a2),
        Some(Duration::from_millis(BASE_MS * 4))
    );
    assert_eq!(
        find_reset_timer(&a3),
        Some(Duration::from_millis(BASE_MS * 8))
    );
    assert_eq!(pm.consecutive_failures(), 3);
    assert_eq!(
        pm.current_view(),
        View(0),
        "OnTimeout must not advance the view"
    );
}

#[test]
fn become_leader_fires_iff_self_is_leader_of_new_view() {
    // validators sorted: [nid(1), nid(2), nid(3), nid(4)]
    // RoundRobin for view 1 -> validators[1] = nid(2).
    // So self = nid(2) should see BecomeLeader(1); self = nid(1) should not.
    let mut as_leader = make_pm(2);
    let actions = as_leader.step(Event::OnQc(View(0)));
    assert!(
        actions.contains(&Action::BecomeLeader(View(1))),
        "self is leader of view 1: {actions:?}"
    );
    // Emission order: AdvanceToView, BecomeLeader, ResetTimer.
    assert_eq!(
        actions[0],
        Action::AdvanceToView {
            view: View(1),
            cause: AdvanceCause::Qc,
        }
    );
    assert_eq!(actions[1], Action::BecomeLeader(View(1)));
    assert!(matches!(actions[2], Action::ResetTimer(_)));

    let mut as_follower = make_pm(1);
    let actions = as_follower.step(Event::OnQc(View(0)));
    assert!(
        !actions.iter().any(|a| matches!(a, Action::BecomeLeader(_))),
        "self is not leader of view 1: {actions:?}"
    );
}

#[test]
fn proposal_received_resets_timer_at_current_backoff() {
    let mut pm = make_pm(1);
    // One prior timeout -> failures = 1.
    let _ = pm.step(Event::OnTimeout(View(0)));
    assert_eq!(pm.consecutive_failures(), 1);

    let actions = pm.step(Event::OnProposalReceived(View(0)));
    // Should ResetTimer at policy.timeout(1) = 2 * base; failures must
    // NOT drop to 0 just because a proposal arrived.
    assert_eq!(actions.len(), 1);
    assert_eq!(
        actions[0],
        Action::ResetTimer(Duration::from_millis(BASE_MS * 2))
    );
    assert_eq!(pm.consecutive_failures(), 1);
}

// ── #218: OnRoundSync ─────────────────────────────────────────────────────

/// Round sync jumps the pacemaker *to* `v` (not `v + 1` like
/// `OnQc`/`OnTimeoutCert`) when `v` is strictly ahead of the current
/// view. The `cause` field surfaces `RoundSync` so an operator
/// reading the trace can distinguish single-signer round-sync from
/// quorum-of-evidence advances.
#[test]
fn round_sync_jumps_to_v_not_v_plus_one_for_future_view() {
    let mut pm = make_pm(1);
    let actions = pm.step(Event::OnRoundSync {
        view: View(7),
        evidence: round_sync_evidence(),
    });
    assert_eq!(
        pm.current_view(),
        View(7),
        "advance is *to* v, not to v + 1"
    );
    assert!(
        actions.iter().any(|a| matches!(
            a,
            Action::AdvanceToView {
                view: View(7),
                cause: AdvanceCause::RoundSync
            }
        )),
        "expected AdvanceToView(7, RoundSync), got {actions:?}",
    );
    assert_eq!(pm.consecutive_failures(), 0, "advance resets failures");
}

/// Round-sync hints for the current view or older views are no-ops:
/// the only way to advance is strict `>`. Same idempotency contract as
/// `OnQc` / `OnTimeoutCert` for stale events.
#[test]
fn round_sync_for_current_or_stale_view_is_noop() {
    let mut pm = make_pm(1);
    let _ = pm.step(Event::OnQc(View(4)));
    assert_eq!(pm.current_view(), View(5));

    // Stale.
    let actions = pm.step(Event::OnRoundSync {
        view: View(3),
        evidence: round_sync_evidence(),
    });
    assert!(
        actions.is_empty(),
        "stale round-sync is a no-op: {actions:?}"
    );
    assert_eq!(pm.current_view(), View(5));

    // Current.
    let actions = pm.step(Event::OnRoundSync {
        view: View(5),
        evidence: round_sync_evidence(),
    });
    assert!(
        actions.is_empty(),
        "current-view round-sync is a no-op: {actions:?}"
    );
    assert_eq!(pm.current_view(), View(5));
}

/// Round sync must not promote `high_qc_view` — the whole point of
/// keeping `OnRoundSync` distinct from `OnQc` is that a single signer
/// is enough evidence for "I should be at this view too" but is *not*
/// enough evidence to claim a QC was assembled at the prior view.
#[test]
fn round_sync_does_not_advance_high_qc_view() {
    let mut pm = make_pm(1);
    let _ = pm.step(Event::OnQc(View(2)));
    assert_eq!(pm.high_qc_view(), View(2));

    let _ = pm.step(Event::OnRoundSync {
        view: View(7),
        evidence: round_sync_evidence(),
    });
    assert_eq!(pm.current_view(), View(7));
    assert_eq!(
        pm.high_qc_view(),
        View(2),
        "round-sync must leave high_qc_view untouched — only OnQc moves it",
    );
}

/// Audit finding 2-3 (issue #419): the honesty-threshold gate is typed
/// into the API. `HonestyThresholdEvidence::from_bucket` returns `None`
/// when the bucket is below the threshold, so a future producer cannot
/// construct an `OnRoundSync` payload without observing `f + 1`
/// distinct signers — the bucket-size *is* the gate.
#[test]
fn honesty_threshold_evidence_below_bucket_is_none() {
    assert!(
        HonestyThresholdEvidence::from_bucket(0, 1).is_none(),
        "0 < 1: no evidence",
    );
    assert!(
        HonestyThresholdEvidence::from_bucket(1, 2).is_none(),
        "1 < 2: no evidence",
    );
    assert!(
        HonestyThresholdEvidence::from_bucket(2, 2).is_some(),
        "2 >= 2: evidence",
    );
    assert!(
        HonestyThresholdEvidence::from_bucket(5, 2).is_some(),
        "above-threshold buckets also yield evidence",
    );
}

#[test]
fn tc_resets_failures_so_next_timeout_uses_base() {
    let mut pm = make_pm(1);
    // Two timeouts at view 0.
    let _ = pm.step(Event::OnTimeout(View(0)));
    let _ = pm.step(Event::OnTimeout(View(0)));
    assert_eq!(pm.consecutive_failures(), 2);

    // TC advances to view 1 and resets.
    let _ = pm.step(Event::OnTimeoutCert(View(0)));
    assert_eq!(pm.current_view(), View(1));
    assert_eq!(pm.consecutive_failures(), 0);

    // Next timeout at view 1 arms ResetTimer at 2 * base, not 16 * base.
    let actions = pm.step(Event::OnTimeout(View(1)));
    assert_eq!(
        find_reset_timer(&actions),
        Some(Duration::from_millis(BASE_MS * 2))
    );
}

// ---------------------------------------------------------------------
// Sim liveness tests — 4 nodes, one permanently offline
// ---------------------------------------------------------------------

/// Mock safety core and message bus. Collects timeouts / proposals from
/// live nodes and broadcasts `OnTimeoutCert` / `OnQc` when a quorum is
/// reached.
///
/// The bus is driven by a loop in each test scenario: inject an event,
/// drain the actions, record them, and let the mock decide whether a
/// quorum has formed.
struct Bus {
    /// `Some(pm)` for live nodes, `None` for the offline node.
    pms: Vec<Option<Pacemaker>>,
    quorum: usize,
    /// For each view, indices of live nodes that have emitted a timeout.
    timeouts: BTreeMap<View, Vec<usize>>,
    /// For each view, indices of live nodes that have acknowledged a
    /// proposal (`OnProposalReceived` → treat as a vote).
    votes: BTreeMap<View, Vec<usize>>,
    /// Events that still need to be delivered to each live node.
    pending: Vec<Vec<Event>>,
}

impl Bus {
    fn new(pms: Vec<Option<Pacemaker>>, quorum: usize) -> Self {
        let n = pms.len();
        Self {
            pms,
            quorum,
            timeouts: BTreeMap::new(),
            votes: BTreeMap::new(),
            pending: vec![Vec::new(); n],
        }
    }

    fn live_indices(&self) -> Vec<usize> {
        (0..self.pms.len())
            .filter(|i| self.pms[*i].is_some())
            .collect()
    }

    /// Queue `event` for every live node.
    fn broadcast_to_live(&mut self, event: Event) {
        for i in self.live_indices() {
            self.pending[i].push(event);
        }
    }

    /// Record a timeout observation from node `i` for `view`. If quorum
    /// is reached (first time), queue `OnTimeoutCert(view)` for every
    /// live node.
    fn record_timeout(&mut self, i: usize, view: View) {
        let seen = self.timeouts.entry(view).or_default();
        if !seen.contains(&i) {
            seen.push(i);
        }
        if seen.len() == self.quorum {
            self.broadcast_to_live(Event::OnTimeoutCert(view));
        }
    }

    /// Record a vote (proposal-received ack) from node `i` for `view`.
    /// If quorum is reached (first time), queue `OnQc(view)` for every
    /// live node.
    fn record_vote(&mut self, i: usize, view: View) {
        let seen = self.votes.entry(view).or_default();
        if !seen.contains(&i) {
            seen.push(i);
        }
        if seen.len() == self.quorum {
            self.broadcast_to_live(Event::OnQc(view));
        }
    }

    /// Deliver one queued event to node `i`, record the resulting
    /// actions, and return `true` if an event was delivered.
    fn deliver_one(&mut self, i: usize) -> bool {
        let Some(event) = self.pending[i].pop() else {
            return false;
        };
        // Mock safety core: observing a proposal at this node counts as
        // a vote from this node. Record before stepping the pacemaker so
        // a QC can accumulate as each live node processes the proposal.
        if let Event::OnProposalReceived(v) = event {
            self.record_vote(i, v);
        }
        let Some(pm) = self.pms[i].as_mut() else {
            return false;
        };
        let actions = pm.step(event);
        for a in actions {
            match a {
                Action::SendTimeout(v) => {
                    // Timeout message reaches every live node including
                    // the sender; each counts toward the TC quorum.
                    for j in self.live_indices() {
                        self.record_timeout(j, v);
                    }
                }
                Action::AdvanceToView { .. } | Action::BecomeLeader(_) | Action::ResetTimer(_) => {
                    // No network effect in the sim. Each scenario
                    // manually bootstraps the first proposal / timeout
                    // it cares about, so cascading view advancement is
                    // out of scope.
                }
            }
        }
        true
    }

    /// Run until no live node has pending events.
    fn run_until_quiescent(&mut self) {
        // Bound iterations to catch runaway loops in a buggy harness.
        for _ in 0..10_000 {
            let mut made_progress = false;
            for i in 0..self.pms.len() {
                if self.deliver_one(i) {
                    made_progress = true;
                }
            }
            if !made_progress {
                return;
            }
        }
        panic!("sim did not quiesce within 10k iterations");
    }
}

fn live_pms(bus: &Bus) -> impl Iterator<Item = &Pacemaker> {
    bus.pms.iter().filter_map(|p| p.as_ref())
}

/// Build 4 pacemakers over `[nid(1), nid(2), nid(3), nid(4)]` with node
/// `offline_idx` set to `None`. Uses quorum = 3 (2f+1 for f=1).
fn four_node_bus(offline_idx: usize) -> Bus {
    let vs = validators();
    let sel = selector(vs.clone());
    let pol = policy();
    let ids = [nid(1), nid(2), nid(3), nid(4)];
    let pms: Vec<Option<Pacemaker>> = (0..4)
        .map(|i| {
            if i == offline_idx {
                None
            } else {
                Some(Pacemaker::new(ids[i], sel.clone(), pol.clone()))
            }
        })
        .collect();
    Bus::new(pms, 3)
}

#[test]
fn liveness_via_qc_when_leader_is_live() {
    // Leader of view 0 = validators[0] = nid(1) (index 0). Take node 3
    // offline so the leader is alive.
    let mut bus = four_node_bus(3);

    // Simulate the leader broadcasting a proposal to every live node.
    // Each node's delivery of OnProposalReceived(0) triggers a vote in
    // the mock safety core; after quorum (3), the bus broadcasts
    // OnQc(0) and every live pacemaker advances to view 1.
    bus.broadcast_to_live(Event::OnProposalReceived(View(0)));
    bus.run_until_quiescent();

    for pm in live_pms(&bus) {
        assert_eq!(
            pm.current_view(),
            View(1),
            "live node did not advance past view 0"
        );
        assert_eq!(
            pm.high_qc_view(),
            View(0),
            "QC for view 0 should be recorded"
        );
    }
}

#[test]
fn liveness_via_tc_when_leader_is_offline() {
    // Leader of view 0 = validators[0] = nid(1) (index 0). Take node 0
    // offline so view 0 stalls and must be abandoned via TC.
    let mut bus = four_node_bus(0);

    // No proposal arrives — each live node's local timer fires for view 0.
    for i in bus.live_indices() {
        bus.pending[i].push(Event::OnTimeout(View(0)));
    }
    bus.run_until_quiescent();

    // The bus should have gathered 3 timeouts and broadcast a TC.
    // Every live pacemaker should now be at view 1.
    for pm in live_pms(&bus) {
        assert_eq!(
            pm.current_view(),
            View(1),
            "live node did not advance past view 0"
        );
        assert_eq!(pm.consecutive_failures(), 0, "TC must reset backoff");
    }

    // The new leader of view 1 = validators[1] = nid(2) — which is live.
    // Sanity-check that at least one live node saw BecomeLeader(1) over
    // the course of the sim by re-querying the selector directly.
    let sel = selector(validators());
    assert_eq!(sel.leader_for_view(View(1)), nid(2));
}
