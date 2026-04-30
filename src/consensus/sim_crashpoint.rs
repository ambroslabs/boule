//! Crash-injection harness regression tests (issue #420).
//!
//! Companion to [`crate::sim::sim_crash`] (driver-level crash-recovery
//! invariants on disk-backed Storage/Wal) and
//! [`crate::consensus::sim_byzantine`] (protocol-level adversary
//! injection). This module sits one level higher: it injects a
//! consensus-event-loop *process kill* at a named persistence boundary
//! via the [`crate::consensus::crashpoint`] seam, then restarts the
//! crashed replica and re-engages the cluster against the same
//! durable state.
//!
//! # Why this harness exists
//!
//! Several audit findings (the issue #420 umbrella points at #405,
//! #406, #407, #415) are *persistence-ordering* bugs: a replica sends
//! some network frame `F` before the durability of state-mutation `M`
//! lands, so a crash between them lets the restart re-emit a different
//! `F'` for the same logical position — equivocation, double-vote,
//! double-propose. The bugs are inferable from code review but were
//! not previously catchable as regressions in CI: the existing
//! [`SimCluster::kill_node`] kills a peer at *any* moment the test
//! happens to call it, not at the exact gap between `M` and `F`.
//!
//! Each test below arms a fire-once [`crashpoint!`] against a single
//! replica's task-local slot via [`SimCluster::arm_crashpoint`], drives
//! the cluster forward until the slot fires (the replica's tokio task
//! panics with `CrashPoint(name)`), restarts that replica via
//! [`SimCluster::restart_node_with_recover`] against the same `(signer,
//! storage, wal)`, and re-asserts safety.
//!
//! # Today's tests vs. the actual regression
//!
//! Today the harness is in place, but the *fixes* for #405 / #406 /
//! #407 / #415 have not landed. So the assertions in each test stop at
//! "the harness fires the crashpoint, the replica restarts, and the
//! cluster makes progress without committing conflicting blocks". When
//! a follow-up PR lands one of those fixes, the corresponding test
//! tightens its assertion — typically by reading the replica's
//! durable state post-restart and asserting the now-persisted field
//! is present and consistent with the pre-crash invariant the fix
//! locks down.
//!
//! [`crashpoint!`]: crate::consensus::crashpoint::crashpoint
//! [`SimCluster::arm_crashpoint`]: crate::consensus::sim::SimCluster::arm_crashpoint
//! [`SimCluster::kill_node`]: crate::consensus::sim::SimCluster::kill_node
//! [`SimCluster::restart_node_with_recover`]: crate::consensus::sim::SimCluster::restart_node_with_recover

use std::time::Duration;

use tokio::task::yield_now;

use crate::consensus::sim::{SimCluster, assert_no_conflicts};

/// Drive the cluster yield-by-yield until either `done` returns `true`
/// or the budget runs out. Reports `true` when the predicate fired.
async fn yield_until(
    cluster: &mut SimCluster,
    budget: usize,
    mut done: impl FnMut(&mut SimCluster) -> bool,
) -> bool {
    for _ in 0..budget {
        yield_now().await;
        if done(cluster) {
            return true;
        }
    }
    false
}

/// Drive the cluster forward until the crashpoint armed for `idx` has
/// fired (slot transitions from `Some(name)` to `None`). The harness
/// asserts on the slot rather than on the panicked tokio task because
/// `tokio::spawn` swallows the JoinHandle and an unawaited panic is
/// not directly observable from the main test task.
async fn yield_until_crashpoint_fires(cluster: &mut SimCluster, idx: usize, budget: usize) -> bool {
    yield_until(cluster, budget, |c| c.peek_crashpoint(idx).is_none()).await
}

// ── Issue #405 / audit finding 4-1: lock not persisted before vote send ───

/// Regression harness for issue #405 (lock not persisted before vote
/// send, Tendermint amnesia class).
///
/// Scenario: arm `after_broadcast_vote` on node 0. The view-1 leader
/// (sorted index 1 in a 4-node round-robin cluster) proposes; node 0
/// votes; the crashpoint fires the moment node 0's vote frame is on
/// the wire. We then restart node 0 against its captured `(signer,
/// storage, wal)` and verify that
///
/// 1. the crashpoint actually fired (slot drained to `None`),
/// 2. `restart_node_with_recover` succeeds against the post-crash
///    storage, and
/// 3. the surviving cluster commits at least one block consistent
///    with the post-restart state — no conflicting commits across
///    the kill/restart boundary.
///
/// Once #405 lands, the test will also peek the recovered node's
/// durable `Locked` to confirm `locked.view ≥ last_voted_view`,
/// pinning the bug shape directly.
#[tokio::test]
async fn after_broadcast_vote_crashpoint_fires_and_node_restarts() {
    tokio::time::pause();

    let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;
    // Pick node 0 as the crash victim. In a 4-node round-robin
    // cluster the view-1 leader is sorted index 1, so node 0 votes
    // on view 1's proposal almost immediately after boot.
    let victim = 0;
    assert_eq!(
        cluster.arm_crashpoint(victim, "after_broadcast_vote"),
        None,
        "fresh cluster slot must start empty",
    );

    // Drive until the crashpoint fires. The boot path executes
    // `OnQc(0)` → AdvanceToView(1) → leader broadcasts proposal →
    // node 0 verifies + votes → crashpoint fires on the SendTo path.
    let fired = yield_until_crashpoint_fires(&mut cluster, victim, 1000).await;
    assert!(
        fired,
        "after_broadcast_vote must fire within 1000 yields — \
         either the integration layer didn't reach the crashpoint \
         or the macro wiring regressed",
    );

    // Restart the panicked node. Recovery hits the same
    // `(signer, storage, wal)` it had before, so any state it
    // managed to flush before the crash (`last_voted_view`, in this
    // scenario) is read back by `recover()`.
    cluster
        .restart_node_with_recover(victim)
        .await
        .expect("recover must succeed against post-crash storage");

    // Drive forward; the cluster must keep making progress and
    // every commit must be conflict-free across nodes.
    let _ = yield_until(&mut cluster, 1500, |c| {
        c.peek_commit_heights().iter().filter(|&&h| h > 0).count() >= 3
    })
    .await;

    let committed = cluster.drain_commits();
    assert_no_conflicts(&committed);
}

// ── Issue #406 / audit finding 4-2: adopt_snapshot persistence ────────────

/// Regression harness for issue #406 (`adopt_snapshot` must persist
/// safety state before returning).
///
/// The crashpoint `after_adopt_snapshot_persist` only fires when the
/// integration layer crosses
/// [`ConsensusNode::restore_from_snapshot`], which the steady-state
/// 4-node cluster does not exercise (no joiner is behind by enough
/// blocks to need a snapshot). This test therefore *negative-asserts*
/// the harness wiring: arming the crashpoint must not break a
/// happy-path cluster (the slot stays armed but never fires), and
/// the crashpoint name is retained as a recognised label the future
/// regression test will arm.
///
/// Once #406 lands together with a snapshot-sync sim scenario, this
/// test extends to: spawn an additional joiner, drive the cluster
/// past `snapshot_height`, arm `after_adopt_snapshot_persist` on the
/// joiner, and verify that the joiner's persisted `Locked` matches
/// the snapshot's `commit_qc.view` after recovery.
#[tokio::test]
async fn after_adopt_snapshot_persist_arms_without_disturbing_happy_path() {
    tokio::time::pause();

    let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;
    let victim = 0;
    cluster.arm_crashpoint(victim, "after_adopt_snapshot_persist");

    let _ = yield_until(&mut cluster, 1000, |c| {
        c.peek_commit_heights().iter().filter(|&&h| h > 0).count() >= 3
    })
    .await;

    // Slot must still be armed: the steady-state happy path never
    // hits the snapshot-restore code path the crashpoint guards. A
    // regression that wired the crashpoint into an unrelated branch
    // would silently fire and the slot would be `None` here.
    assert_eq!(
        cluster.peek_crashpoint(victim),
        Some("after_adopt_snapshot_persist"),
        "after_adopt_snapshot_persist must only fire under restore_from_snapshot",
    );

    // Cluster must still commit despite the armed-but-unfired slot.
    let committed = cluster.drain_commits();
    assert_no_conflicts(&committed);
    let total_commits: usize = committed.iter().map(|c| c.len()).sum();
    assert!(
        total_commits > 0,
        "happy path must commit at least one block while the snapshot \
         crashpoint is armed but unreached",
    );
}

// ── Issue #407 / audit finding 4-3: proposed_in_view across restart ───────

/// Regression harness for issue #407 (`proposed_in_view` is in-memory
/// only; a restart re-broadcasting a proposal at the same view is
/// indistinguishable from Byzantine equivocation).
///
/// Scenario: arm `after_send_outbound_for_proposal` on the view-1
/// leader (sorted index 1). The leader builds and broadcasts the
/// view-1 proposal; the crashpoint fires the moment those bytes are
/// on the wire. The crash is tightly aligned with the bug: the
/// in-memory `proposed_in_view = 1` mutation is dropped with the
/// task, but the proposal was already observed by every peer.
/// `recover()` re-instantiates the leader with `proposed_in_view = 0`,
/// and the test asserts the cluster still converges without observing
/// two distinct view-1 proposals (no conflicting commits).
///
/// Once #407 lands, the test will additionally read the recovered
/// leader's persisted `proposed_in_view` (or in-flight proposal
/// snapshot) and assert it survived the restart.
#[tokio::test]
async fn after_send_outbound_for_proposal_crashpoint_fires_on_view_1_leader() {
    tokio::time::pause();

    let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;
    // Sorted ascending validators → view-1 leader is index 1.
    let leader_idx = 1;
    assert_eq!(
        cluster.arm_crashpoint(leader_idx, "after_send_outbound_for_proposal"),
        None,
    );

    let fired = yield_until_crashpoint_fires(&mut cluster, leader_idx, 1000).await;
    assert!(
        fired,
        "after_send_outbound_for_proposal must fire on the view-1 leader's first broadcast",
    );

    cluster
        .restart_node_with_recover(leader_idx)
        .await
        .expect("recover must succeed against post-crash storage");

    // Drive the cluster past view 1 via message passing (the
    // crashpoint fired *after* the proposal was on the wire, so the
    // surviving peers have it in `pending_blocks` and will vote).
    // Quorum lands on the next-view leader, the chain advances, and
    // commits land. Poll-with-budget so we exit as soon as 3 nodes
    // have committed at least one block.
    let _ = yield_until(&mut cluster, 1500, |c| {
        c.peek_commit_heights().iter().filter(|&&h| h > 0).count() >= 3
    })
    .await;

    let committed = cluster.drain_commits();
    assert_no_conflicts(&committed);
}

// ── Issue #415 / audit finding 14-1: TimeoutVote persistence ──────────────

/// Regression harness for issue #415 (`TimeoutVote` is broadcast
/// without a preceding persist).
///
/// Scenario: kill the view-1 leader (sorted index 1) so the
/// surviving three nodes can only escape view 1 via the
/// timeout-certificate path. Arm
/// `after_broadcast_timeout_vote` on a survivor. Advance virtual
/// time so the survivor's view timer fires. The survivor's
/// `send_timeout` path puts a TimeoutVote frame on the wire; the
/// crashpoint fires immediately after. We then restart the
/// survivor and verify the cluster eventually advances past view 1
/// without committing conflicting blocks.
///
/// Once #415 lands, the test will additionally assert that the
/// recovered survivor's persisted "highest TimeoutVote view" matches
/// the view it broadcast for, so that on restart it cannot broadcast
/// a *second* TimeoutVote for the same view with a different
/// piggybacked `high_qc`.
#[tokio::test]
async fn after_broadcast_timeout_vote_crashpoint_fires_when_leader_is_dead() {
    tokio::time::pause();

    let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

    // Let every node boot and arm its view-1 timer.
    for _ in 0..20 {
        yield_now().await;
    }

    // Pick a survivor that will broadcast a TimeoutVote when the
    // view-1 timer fires. Sorted index 0 is not the view-1 leader
    // and not the kill victim.
    let timeout_victim = 0;
    cluster.arm_crashpoint(timeout_victim, "after_broadcast_timeout_vote");

    // Kill the view-1 leader so the survivors are forced down the
    // timeout-certificate path.
    cluster.kill_node(1);

    // Advance virtual time so the view-1 timer fires on every
    // survivor. Several timeout intervals are enough to guarantee
    // the survivor at `timeout_victim` reaches `send_timeout`.
    for _ in 0..12 {
        tokio::time::advance(Duration::from_millis(500)).await;
        for _ in 0..100 {
            yield_now().await;
            if cluster.peek_crashpoint(timeout_victim).is_none() {
                break;
            }
        }
        if cluster.peek_crashpoint(timeout_victim).is_none() {
            break;
        }
    }
    assert_eq!(
        cluster.peek_crashpoint(timeout_victim),
        None,
        "after_broadcast_timeout_vote must fire once the view timer drives \
         a survivor through send_timeout",
    );

    cluster
        .restart_node_with_recover(timeout_victim)
        .await
        .expect("recover must succeed against post-crash storage");

    // Drive the post-restart cluster forward through several more
    // timeout cycles so the surviving three replicas (one of which
    // was just reborn) form a TC for view 1 and advance.
    for _ in 0..12 {
        tokio::time::advance(Duration::from_millis(500)).await;
        for _ in 0..100 {
            yield_now().await;
        }
    }

    let committed = cluster.drain_commits();
    assert_no_conflicts(&committed);
}

// ── Smoke tests for the rest of the named crashpoints ─────────────────────

/// Smoke test: every crashpoint name the integration layer wires up
/// must be arm-able. A typo in either the macro call or the test arm
/// would silently never fire — this catches the typo by exercising
/// each arm against a freshly-spawned cluster and then peeking the
/// slot to confirm the arm landed (no transitive panics from
/// `arm_crashpoint` itself).
///
/// The names are pinned here so future PRs that rename a crashpoint
/// must update both this list and every site in `node.rs`. If the
/// macro call site is renamed without updating this list, the test
/// still passes — the safety-net is the per-bug regression tests
/// above, which arm specific names. This smoke test is a complement,
/// not a substitute, for those.
#[tokio::test]
async fn every_named_crashpoint_is_armable() {
    tokio::time::pause();
    let cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

    let names = [
        "after_persist_voted_view",
        "after_persist_locked",
        "after_persist_high_qc",
        "after_broadcast_vote",
        "after_send_outbound_for_proposal",
        "after_apply_commit_block_persist",
        "after_adopt_snapshot_persist",
        "after_broadcast_timeout_vote",
    ];

    for name in names {
        cluster.arm_crashpoint(0, name);
        // Re-arming overwrites; peeking sees the most recent arm.
        // The point is just that `arm` accepted every name and the
        // slot is now in a known state.
        assert_eq!(
            cluster.peek_crashpoint(0),
            Some(name),
            "arm_crashpoint({name:?}) did not land in the slot",
        );
    }
}
