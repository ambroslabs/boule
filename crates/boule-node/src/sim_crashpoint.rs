//! Crash-injection harness regression tests (issue #420).
//!
//! Companion to [`boule_consensus::sim_byzantine`] (protocol-level
//! adversary injection). This module injects a consensus-event-loop
//! *process kill* at a named persistence boundary via the
//! [`boule_consensus::crashpoint`] seam, then restarts the crashed
//! replica and re-engages the cluster against the same durable state.
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
//! [`crashpoint!`]: boule_consensus::crashpoint::crashpoint
//! [`SimCluster::arm_crashpoint`]: boule_consensus::sim::SimCluster::arm_crashpoint
//! [`SimCluster::kill_node`]: boule_consensus::sim::SimCluster::kill_node
//! [`SimCluster::restart_node_with_recover`]: boule_consensus::sim::SimCluster::restart_node_with_recover

use std::time::Duration;

use tokio::task::yield_now;

use boule_consensus::sim::{SimCluster, assert_no_conflicts};

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

/// Regression for issue #405 (lock not persisted before vote send,
/// Tendermint amnesia class).
///
/// The audit finding: pre-fix, `HotStuffCore::on_proposal_received`
/// emitted `Action::Broadcast(Vote)` *before* `Action::Persist(Locked)`
/// for the same proposal. Because `apply_safety_actions` flushes the
/// persist buffer before each non-`Persist` action, the lock landed on
/// disk only after the vote left the wire. A crash in that window
/// (this crashpoint, `after_broadcast_vote`) left disk with
/// `last_voted_view` advanced past the in-memory promotion: on restart,
/// `state.locked` reverted to whatever was on disk at the moment of the
/// crash, *one promotion stale*.
///
/// Bug-shape, in terms of the durable safety triple at any vote
/// view `N` where the 2-chain rule fired (`N ≥ 3` in our chain):
/// pre-fix, durable `last_voted_view = N` but durable `locked.view`
/// reflects the promotion from view `N-1` (or `None` if `N == 3` was
/// the first promotion the node ever saw); post-fix, durable
/// `locked.view = N - 2` because the just-cast vote's grandparent IS
/// the freshly-promoted lock.
///
/// This test therefore:
///
/// 1. Lets the cluster warm up until node 0's durable
///    `last_voted_view ≥ 3` — guaranteeing at least one B4 promotion
///    has fired locally on node 0.
/// 2. Arms `after_broadcast_vote` on node 0 (an idempotent re-arm of
///    its task-local slot — the harness re-arms after every fire).
/// 3. Drives until the crashpoint fires the moment node 0's next
///    vote frame is on the wire.
/// 4. Restarts node 0 against its captured `(signer, storage, wal)`.
/// 5. Reads the post-restart durable safety triple directly from
///    storage and asserts `lock.view + 2 ≥ last_voted_view` — the
///    invariant pre-fix violated at every vote view `N ≥ 4`.
/// 6. Asserts the cluster keeps making progress with no conflicting
///    commits.
#[tokio::test]
async fn after_broadcast_vote_crashpoint_fires_and_node_restarts() {
    use boule_consensus::View;
    use crate::consensus_node::{
        STORAGE_KEY_LAST_VOTED_VIEW, STORAGE_KEY_LOCKED, decode_locked, decode_voted_view,
    };

    tokio::time::pause();

    let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;
    let victim = 0;
    let storage = cluster
        .node_storage(victim)
        .expect("mesh-mode cluster must expose per-node storage");

    // Phase 1: warm up. We need durable `last_voted_view ≥ 3` on
    // node 0 so the crash later lands at a vote whose action vector
    // also includes a B4 promotion — which is exactly the gap audit
    // finding 4-1 names. View 1's vote has no promotion (genesis
    // grandparent), view 2's likewise; view 3 is the first promotion
    // every honest replica observes.
    let warmed = yield_until(&mut cluster, 2000, |_| {
        storage
            .get(STORAGE_KEY_LAST_VOTED_VIEW)
            .ok()
            .flatten()
            .and_then(|raw| decode_voted_view(&raw).ok())
            .is_some_and(|v| v >= View(3))
    })
    .await;
    assert!(
        warmed,
        "warmup did not see durable last_voted_view ≥ 3 on node 0 within 2000 yields",
    );

    // Phase 2: arm after at least one B4 promotion has fired. The
    // slot was empty pre-arm — peek to confirm — and after arm the
    // very next `after_broadcast_vote` crossing fires the panic.
    assert_eq!(
        cluster.peek_crashpoint(victim),
        None,
        "slot must be empty before we arm — no other crashpoint should be in flight",
    );
    assert_eq!(
        cluster.arm_crashpoint(victim, "after_broadcast_vote"),
        None,
        "arm must replace nothing",
    );

    let fired = yield_until_crashpoint_fires(&mut cluster, victim, 1000).await;
    assert!(
        fired,
        "after_broadcast_vote must fire within 1000 yields — \
         either the integration layer didn't reach the crashpoint \
         or the macro wiring regressed",
    );

    // Phase 3: restart. Recovery reopens the captured storage, so
    // anything node 0 flushed pre-crash is what `recover()` reads
    // back; anything that didn't flush before the crashpoint is
    // gone.
    cluster
        .restart_node_with_recover(victim)
        .await
        .expect("recover must succeed against post-crash storage");

    // Phase 4: pin the bug shape directly. Read the durable
    // `(last_voted_view, locked)` pair the recovered node booted
    // against; assert the post-fix invariant
    // `lock.view + 2 ≥ last_voted_view`.
    //
    // Pre-fix this assertion fails at any `N ≥ 4`: durable
    // `last_voted_view = N` (the just-cast vote flushed before the
    // broadcast crashpoint), but durable `locked.view` still
    // reflects the promotion from view `N - 1` (because view `N`'s
    // promotion was queued after the broadcast and never flushed).
    // Post-fix the just-cast vote's `Persist(Locked)` lands first,
    // so `locked.view + 2 = last_voted_view` exactly.
    let durable_voted = decode_voted_view(
        &storage
            .get(STORAGE_KEY_LAST_VOTED_VIEW)
            .unwrap()
            .expect("durable last_voted_view must exist after a vote-side crash"),
    )
    .unwrap();
    assert!(
        durable_voted >= View(3),
        "durable last_voted_view regressed below the warmup floor: got {durable_voted}",
    );
    let durable_locked = storage
        .get(STORAGE_KEY_LOCKED)
        .unwrap()
        .map(|raw| decode_locked(&raw).unwrap());
    let lock = durable_locked.expect(
        "audit finding 4-1 (#405): durable Locked is None after crashing on a vote-broadcast \
         past the first 2-chain promotion. Pre-fix, the lock persist was queued behind the \
         vote broadcast and never flushed; post-fix, Persist(Locked) precedes Broadcast(Vote) \
         and the lock is durable",
    );
    assert!(
        lock.view + 2 >= durable_voted,
        "audit finding 4-1 (#405): durable lock.view {} stale w.r.t. vote view {} \
         (expected lock.view + 2 ≥ last_voted_view, since the just-cast vote's grandparent \
         IS the freshly-promoted lock). The lock landed on disk one promotion behind, which \
         is the on-disk shape that lets a restarted replica vote on a conflicting branch \
         that satisfies the stale lock's extension rule",
        lock.view,
        durable_voted,
    );

    // Phase 5: cluster keeps making progress, no conflicting commits.
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

/// Regression for issue #407 (`proposed_in_view` is in-memory only; a
/// restart re-broadcasting a proposal at the same view is
/// indistinguishable from Byzantine equivocation).
///
/// Scenario: arm `after_send_outbound_for_proposal` on the view-1
/// leader (sorted index 1). The leader builds and broadcasts the
/// view-1 proposal; the crashpoint fires the moment those bytes are
/// on the wire. The crash is tightly aligned with the bug: the
/// in-memory `proposed_in_view = 1` mutation would be dropped with
/// the task, but the proposal was already observed by every peer.
///
/// Pre-fix the in-memory guard would reset to `0` on restart, leaving
/// nothing on disk to stop a re-mint at view 1. The fix routes
/// `proposed_in_view` through a new `StateUpdate::ProposedInView`
/// variant that the safety core emits *before* the matching
/// `Broadcast(Proposal)`, so the dispatcher's persist-flush-before-
/// non-Persist contract puts the value under
/// `STORAGE_KEY_PROPOSED_IN_VIEW` before the proposal bytes leave.
/// `ConsensusNode::recover` reads it back and threads it into the
/// safety core via `HotStuffCore::with_proposed_in_view`, so the
/// in-memory guard re-fires on the next `try_propose_as_leader(1)`.
///
/// Two assertions pin the fix:
/// 1. After `restart_node_with_recover`, the leader's storage carries
///    `STORAGE_KEY_PROPOSED_IN_VIEW = 1` — the durable mirror landed
///    before the crashpoint fired.
/// 2. The cluster converges without committing conflicting blocks —
///    the existing safety property the harness already covered.
#[tokio::test]
async fn after_send_outbound_for_proposal_crashpoint_fires_on_view_1_leader() {
    use crate::consensus_node::{STORAGE_KEY_PROPOSED_IN_VIEW, decode_proposed_in_view};

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

    // The crashpoint fires *after* `send_outbound` returns for the
    // Broadcast(Proposal). Since `apply_safety_actions` flushes the
    // Persist buffer before any non-Persist action runs, the
    // ProposedInView write must already be on disk by the time the
    // proposal bytes left — and so it must survive the panic.
    let raw = cluster
        .peek_storage(leader_idx)
        .get(STORAGE_KEY_PROPOSED_IN_VIEW)
        .expect("storage.get must not error")
        .expect(
            "STORAGE_KEY_PROPOSED_IN_VIEW must be persisted before the proposal \
             broadcast leaves: the audit-4-3 / #407 self-equivocation guard relies \
             on this value surviving the crash",
        );
    assert_eq!(
        decode_proposed_in_view(&raw).expect("decode proposed_in_view"),
        boule_consensus::View(1),
        "the leader minted at view 1, so the persisted guard must equal 1",
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

/// Regression for issue #415 (`TimeoutVote` is broadcast without a
/// preceding persist; a crash between the sign and the wire send lets
/// a restarted replica mint a *second* signed `TimeoutVote(v)` whose
/// `high_qc` snapshot differs from the first — slashable equivocation
/// evidence under any future TimeoutVote-collection mechanism).
///
/// Scenario: kill the view-1 leader (sorted index 1) so the surviving
/// three nodes can only escape view 1 via the timeout-certificate
/// path. Arm `after_broadcast_timeout_vote` on a survivor. Advance
/// virtual time so the survivor's view-1 timer fires, dropping it
/// through `send_timeout`. The crashpoint fires immediately after the
/// frame leaves; the on-disk `STORAGE_KEY_LAST_TIMEOUT_VOTE` slot must
/// already carry the just-broadcast envelope (the fix persists
/// *before* the wire send returns). We then restart the survivor and
/// verify (a) the persisted envelope survived, (b) the cluster
/// eventually advances past view 1 without committing conflicting
/// blocks, and (c) the persisted envelope was not mutated during the
/// post-restart timer re-fires — i.e. the reborn replica replayed the
/// same payload byte-for-byte rather than minting a fresh one with
/// `state.high_qc` it had since advanced past.
#[tokio::test]
async fn after_broadcast_timeout_vote_crashpoint_fires_when_leader_is_dead() {
    use crate::consensus_node::{STORAGE_KEY_LAST_TIMEOUT_VOTE, decode_last_timeout_vote};

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

    // The crashpoint fires *after* `send_outbound` returns for the
    // TimeoutVote broadcast. The fix persists the envelope before
    // that call, so the on-disk slot must already carry a
    // TimeoutVote — pinning the audit-14-1 / #415 invariant: the
    // canonical envelope this replica committed to for the timed-out
    // view is durable before the bytes leave the host.
    //
    // Pre-fix: this slot did not exist at all (`send_timeout` had no
    // persistence step), so the lookup below returned `None` and the
    // `.expect()` tripped — the regression assertion that tightens
    // when #415 lands.
    let storage = cluster.peek_storage(timeout_victim);
    let pre_restart_raw = storage
        .get(STORAGE_KEY_LAST_TIMEOUT_VOTE)
        .expect("storage.get must not error")
        .expect(
            "STORAGE_KEY_LAST_TIMEOUT_VOTE must be persisted before the TimeoutVote \
             broadcast leaves: the audit-14-1 / #415 equivocation guard relies on \
             this envelope surviving the crash",
        );
    let pre_restart = decode_last_timeout_vote(&pre_restart_raw).expect("decode timeout vote");

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

    // Equivocation invariant (#415): if the reborn replica ever
    // re-broadcasts a TimeoutVote at the *same* view it was timing
    // out on pre-crash, the persisted envelope must replay
    // byte-for-byte rather than mint a fresh one with `state.high_qc`
    // it has since advanced past. Pre-fix, `send_timeout` would
    // happily sign a second envelope with a different `high_qc.view`.
    // A bump to a strictly later view is fine — that is a new
    // persisted entry for a view the replica never previously
    // committed to.
    let post_restart_raw = storage
        .get(STORAGE_KEY_LAST_TIMEOUT_VOTE)
        .expect("storage.get must not error")
        .expect("post-restart storage must still carry a persisted TimeoutVote");
    let post_restart = decode_last_timeout_vote(&post_restart_raw).expect("decode timeout vote");
    if post_restart.view == pre_restart.view {
        assert_eq!(
            post_restart_raw,
            pre_restart_raw,
            "audit finding 14-1 (#415): persisted TimeoutVote at view {} mutated across \
             restart (high_qc.view {:?} → {:?}) — the reborn replica minted a *second* \
             signed envelope at the same view, which is the equivocation gap the fix \
             exists to close",
            pre_restart.view,
            pre_restart.high_qc.as_ref().map(|q| q.view),
            post_restart.high_qc.as_ref().map(|q| q.view),
        );
    }

    let committed = cluster.drain_commits();
    assert_no_conflicts(&committed);
}

/// Tighter bug-shape regression for issue #415: arm
/// `after_persist_timeout_vote` so the crashpoint fires *between* the
/// persist and the wire broadcast. Pre-fix that crashpoint did not
/// exist — the persist was missing entirely — so this test would have
/// hung waiting for it to fire. Post-fix the persist is the very next
/// step before broadcast, so the slot fires once the survivor's
/// view-1 timer drops it through `send_timeout` for the first time.
///
/// The post-crash assertion is identical to the broader test above:
/// the persisted envelope must already exist, must pin the timed-out
/// view, and must remain byte-identical after the restart-driven
/// replay.
#[tokio::test]
async fn after_persist_timeout_vote_crashpoint_fires_before_broadcast() {
    use crate::consensus_node::{STORAGE_KEY_LAST_TIMEOUT_VOTE, decode_last_timeout_vote};

    tokio::time::pause();

    let mut cluster = SimCluster::spawn(4, Duration::from_millis(50)).await;

    for _ in 0..20 {
        yield_now().await;
    }

    let timeout_victim = 0;
    cluster.arm_crashpoint(timeout_victim, "after_persist_timeout_vote");
    cluster.kill_node(1);

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
        "after_persist_timeout_vote must fire once the view timer drives a \
         survivor through send_timeout — pre-fix the persist did not exist \
         and this slot would never have fired",
    );

    let storage = cluster.peek_storage(timeout_victim);
    let pre_restart_raw = storage
        .get(STORAGE_KEY_LAST_TIMEOUT_VOTE)
        .expect("storage.get must not error")
        .expect("the persist must precede the broadcast — the slot's purpose");
    let pre_restart = decode_last_timeout_vote(&pre_restart_raw).expect("decode timeout vote");

    cluster
        .restart_node_with_recover(timeout_victim)
        .await
        .expect("recover must succeed against post-crash storage");

    for _ in 0..12 {
        tokio::time::advance(Duration::from_millis(500)).await;
        for _ in 0..100 {
            yield_now().await;
        }
    }

    let post_restart_raw = storage
        .get(STORAGE_KEY_LAST_TIMEOUT_VOTE)
        .expect("storage.get must not error")
        .expect("post-restart storage must still carry the persisted TimeoutVote");
    let post_restart = decode_last_timeout_vote(&post_restart_raw).expect("decode timeout vote");
    if post_restart.view == pre_restart.view {
        assert_eq!(
            post_restart_raw, pre_restart_raw,
            "audit finding 14-1 (#415): persisted TimeoutVote bytes must be identical \
             across the restart replay — the reborn replica must re-broadcast the same \
             envelope rather than mint a second one with `high_qc` it has since advanced",
        );
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
        "after_persist_timeout_vote",
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
