//! Canonical crash-recovery tests for
//! [`SimDriver::restart_node_preserving_state`] (#65).
//!
//! Milestone 7 (HotStuff safety core, #23) will need to assert the core
//! invariant *"a replica that crashes after persisting `last_voted_view = V`
//! and restarts never votes again in view V"*. Every such safety test boils
//! down to the same scaffolding: build a sim with disk backings, drive a
//! replica to persist some state, crash + restart it, re-check the
//! persisted state. This module pins that scaffolding down once so the
//! safety-core tests can copy the pattern instead of re-inventing it.
//!
//! These tests run at the driver / storage layer only. They deliberately
//! don't depend on gossip or consensus semantics — the invariants they
//! check are purely "did the disk-backed Storage/Wal survive the restart
//! exactly the way the durability contract promises?".

use chrono::{TimeZone as _, Utc};

use crate::sim::network::TraceEntry;
use crate::sim::{GossipFactory, SimDriver, TempDirDiskBacking};
use crate::storage::{Lsn, StorageExt as _};

/// Canonical crash-recovery loop: write, flush, restart, re-read.
///
/// Asserts every clause of the durability contract that
/// [`SimDriver::restart_node_preserving_state`] is supposed to uphold:
///
///   1. Flushed KV puts (including multi-op batches) are readable
///      post-restart.
///   2. Flushed WAL entries iterate back in append order.
///   3. The next WAL LSN is strictly greater than every LSN previously
///      returned — monotonicity survives the restart.
///   4. Unflushed WAL entries may or may not survive — either outcome is
///      consistent with the contract — but they never corrupt the view of
///      the flushed prefix.
///
/// This is the template every milestone-7 safety-core test will start from.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn crash_recovery_preserves_flushed_storage_and_wal_state() {
    let backing = TempDirDiskBacking::new().expect("tempdir");
    let mut driver =
        SimDriver::new_with_backing(3, /* seed */ 300, Utc::now(), GossipFactory, backing)
            .await
            .expect("disk backing must open");

    // Phase 1: persist KV state + flushed WAL entries on node 2.
    {
        let node = driver.node(2);
        node.storage
            .batch(|b| {
                b.put(b"last_voted_view", &7u64.to_be_bytes());
                b.put(b"locked_qc", b"qc-bytes-v1");
                Ok(())
            })
            .unwrap();

        let lsn_a = node.wal.append(b"block-A").unwrap();
        let lsn_b = node.wal.append(b"block-B").unwrap();
        let lsn_c = node.wal.append(b"block-C").unwrap();
        node.wal.flush().unwrap();
        assert!(
            lsn_a < lsn_b && lsn_b < lsn_c,
            "appended LSNs must be strictly monotonic",
        );

        // Append one more entry and leave it unflushed; the contract lets
        // this one disappear across the crash, but its absence must not
        // break the flushed prefix.
        node.wal.append(b"block-unflushed").unwrap();
    }

    // Phase 2: crash + restart.
    driver.restart_node_preserving_state(2).await.unwrap();

    // Phase 3: re-verify invariants against the reborn handles.
    let reborn = driver.node(2);

    // 1. Flushed KV state survives the restart.
    let view_bytes = reborn
        .storage
        .get(b"last_voted_view")
        .unwrap()
        .expect("last_voted_view must survive restart");
    assert_eq!(view_bytes.as_ref(), &7u64.to_be_bytes());
    let locked_qc = reborn
        .storage
        .get(b"locked_qc")
        .unwrap()
        .expect("locked_qc must survive restart");
    assert_eq!(locked_qc.as_ref(), b"qc-bytes-v1");

    // 2. Flushed WAL entries iterate back in the original append order.
    let entries: Vec<_> = reborn
        .wal
        .iter_from(Lsn::ZERO)
        .unwrap()
        .collect::<anyhow::Result<Vec<_>>>()
        .unwrap();
    let flushed: Vec<&[u8]> = entries
        .iter()
        .filter(|(_, v)| v.as_ref() != b"block-unflushed")
        .map(|(_, v)| v.as_ref())
        .collect();
    assert_eq!(
        flushed,
        vec![b"block-A".as_ref(), b"block-B", b"block-C"],
        "flushed WAL prefix must iterate back in order",
    );

    // 3. Monotonic LSN survives the restart: the next append must get a
    //    raw LSN strictly greater than every LSN the pre-crash instance
    //    returned (LSNs 1..=3 are locked, 4 was reserved by the unflushed
    //    entry — whether it survives or gets reassigned, the next *new*
    //    append must not reuse 1..=3).
    let next_lsn = reborn.wal.append(b"post-restart").unwrap();
    assert!(
        next_lsn.raw() > 3,
        "next LSN must be > 3 (last flushed), got {}",
        next_lsn.raw(),
    );

    // 4. Consistency: the flushed prefix is still the same set we wrote,
    //    regardless of whether the unflushed entry survived.
    reborn.wal.flush().unwrap();
    let final_entries: Vec<_> = reborn
        .wal
        .iter_from(Lsn::ZERO)
        .unwrap()
        .collect::<anyhow::Result<Vec<_>>>()
        .unwrap();
    let final_flushed: Vec<&[u8]> = final_entries
        .iter()
        .filter(|(_, v)| v.as_ref() != b"block-unflushed" && v.as_ref() != b"post-restart")
        .map(|(_, v)| v.as_ref())
        .collect();
    assert_eq!(
        final_flushed,
        vec![b"block-A".as_ref(), b"block-B", b"block-C"],
        "flushed prefix must remain identical post-restart",
    );
}

/// Restarting a node must leave *every other* node's on-disk state
/// untouched. This pins the "isolation" half of the backing contract:
/// nothing about the restart helper reaches into a peer's state.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn restart_does_not_touch_peer_storage() {
    let backing = TempDirDiskBacking::new().expect("tempdir");
    let mut driver =
        SimDriver::new_with_backing(3, /* seed */ 301, Utc::now(), GossipFactory, backing)
            .await
            .expect("disk backing must open");

    for i in 0..3 {
        driver
            .node(i)
            .storage
            .put(b"role", format!("node-{i}").as_bytes())
            .unwrap();
        driver
            .node(i)
            .wal
            .append(format!("entry-from-{i}").as_bytes())
            .unwrap();
        driver.node(i).wal.flush().unwrap();
    }

    driver.restart_node_preserving_state(1).await.unwrap();

    for i in [0usize, 2] {
        let got = driver.node(i).storage.get(b"role").unwrap();
        assert_eq!(
            got.as_deref(),
            Some(format!("node-{i}").as_bytes()),
            "peer {i} KV must not be touched by peer-restart",
        );
        let entries: Vec<_> = driver
            .node(i)
            .wal
            .iter_from(Lsn::ZERO)
            .unwrap()
            .collect::<anyhow::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1.as_ref(), format!("entry-from-{i}").as_bytes());
    }

    // And the reborn node sees *its own* prior state — not a peer's.
    let reborn = driver.node(1);
    assert_eq!(
        reborn.storage.get(b"role").unwrap().as_deref(),
        Some(&b"node-1"[..])
    );
    let reborn_entries: Vec<_> = reborn
        .wal
        .iter_from(Lsn::ZERO)
        .unwrap()
        .collect::<anyhow::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(reborn_entries.len(), 1);
    assert_eq!(reborn_entries[0].1.as_ref(), b"entry-from-1");
}

/// Run one full crash-recovery scenario and return its network trace.
/// Used below to pin determinism across the restart.
async fn crash_recovery_scenario(seed: u64) -> Vec<TraceEntry> {
    // Fixed virtual wall-clock start so the trace's timestamps are
    // byte-identical between runs. Each run still creates its own
    // `TempDir` under a random name, but the trace records `NodeId`,
    // byte length, and virtual time — none of which depend on the path.
    let start = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
    let backing = TempDirDiskBacking::new().expect("tempdir");
    let mut driver = SimDriver::new_with_backing(3, seed, start, GossipFactory, backing)
        .await
        .expect("disk backing must open");

    driver.node(2).wal.append(b"pre-crash").unwrap();
    driver.node(2).wal.flush().unwrap();
    driver
        .node(2)
        .storage
        .put(b"view", &1u64.to_be_bytes())
        .unwrap();

    driver.restart_node_preserving_state(2).await.unwrap();

    driver.node(2).wal.append(b"post-crash").unwrap();
    driver.node(2).wal.flush().unwrap();

    driver.run_until_quiescent().await;
    driver.drain_trace()
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn restart_preserves_byte_identical_trace_under_same_seed() {
    // Same seed → same script → same trace. This pins the determinism
    // guarantee of `restart_node_preserving_state`: the helper consumes no
    // network RNG, so two runs of the crash-recovery scenario produce
    // byte-identical traces despite the intervening kill + rebuild.
    let trace_a = crash_recovery_scenario(/* seed */ 9090).await;
    let trace_b = crash_recovery_scenario(/* seed */ 9090).await;
    assert_eq!(
        trace_a,
        trace_b,
        "crash-recovery traces diverged under same seed: {} vs {} entries",
        trace_a.len(),
        trace_b.len(),
    );
}
