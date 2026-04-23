//! Fault-injection coverage for the simulator: exercises the fault
//! primitives that HotStuff debugging will lean on (reorder windows,
//! per-direction latency, stacked partition + drop + latency/jitter).
//! Each test uses a fixed seed and virtual start time so the outcomes
//! are byte-identical across runs — the same pattern as
//! `two_runs_with_same_seed_produce_byte_identical_traces` in
//! `sim_gossip.rs`.

use std::time::Duration;

use chrono::{TimeZone as _, Utc};

use crate::clock::Clock;
use crate::gossip::GossipMessage;
use crate::sim::{LatencyDist, LinkConfig, SimDriver};

/// Deterministic gossip message: content + fixed expiry so the serialized
/// bytes are identical across runs.
fn fixed_gossip(content: &str, expiry_unix_secs: i64) -> GossipMessage {
    GossipMessage {
        content: content.to_string(),
        expiry: Utc.timestamp_opt(expiry_unix_secs, 0).unwrap(),
    }
}

fn fixed_start() -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(1_700_000_000, 0).unwrap()
}

// ---- Test 1: reorder window ----

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn reorder_window_permutes_within_batch_but_preserves_across_batches() {
    // Two nodes, (0→1) has reorder_window=4 and constant 10ms latency.
    // Inject 4 messages and drive to quiescence, then another 4 and
    // drive again. The reorder buffer shuffles each batch internally,
    // and because batch 2 is enqueued at a later virtual time, batch 2
    // strictly follows batch 1 in the delivered order — reorder never
    // leaks across window boundaries.
    let driver = SimDriver::new_with_start(2, /* seed */ 71, fixed_start()).await;

    let link_cfg = LinkConfig {
        latency: LatencyDist::Constant(Duration::from_millis(10)),
        reorder_window: 4,
        ..LinkConfig::ideal()
    };
    driver.set_link_directional(0, 1, link_cfg);
    // Reverse direction left at default (ideal) — node 1's re-broadcasts
    // back to node 0 carry zero latency and don't interfere with the
    // (0→1) trace we inspect.

    // ---- Batch 1 ----
    for i in 0..4 {
        driver
            .node(0)
            .inject_gossip(
                fixed_gossip(&format!("msg-{i}"), 2_000_000_000),
                &*driver.clock as &dyn Clock,
            )
            .await;
    }
    driver.run_until_quiescent().await;

    // ---- Batch 2 ----
    for i in 4..8 {
        driver
            .node(0)
            .inject_gossip(
                fixed_gossip(&format!("msg-{i}"), 2_000_000_000),
                &*driver.clock as &dyn Clock,
            )
            .await;
    }
    driver.run_until_quiescent().await;

    let node0 = driver.node_id(0);
    let node1 = driver.node_id(1);
    let trace = driver.drain_trace();

    let forward_ids: Vec<u64> = trace
        .iter()
        .filter(|t| t.from == node0 && t.to == node1)
        .map(|t| t.id.0)
        .collect();

    assert_eq!(
        forward_ids.len(),
        8,
        "expected 8 events on (0→1), saw {}: {:?}",
        forward_ids.len(),
        forward_ids,
    );

    // Reorder never crosses batches: the four IDs delivered first come
    // from the first batch, the later four from the second batch.
    let (batch1, batch2) = forward_ids.split_at(4);
    let max_b1 = *batch1.iter().max().unwrap();
    let min_b2 = *batch2.iter().min().unwrap();
    assert!(
        max_b1 < min_b2,
        "batch boundary crossed: batch1={batch1:?} batch2={batch2:?}",
    );

    // Reorder actually happened — at least one batch is not the identity
    // permutation of its own IDs.
    let is_sorted = |b: &[u64]| b.windows(2).all(|w| w[0] <= w[1]);
    assert!(
        !(is_sorted(batch1) && is_sorted(batch2)),
        "reorder_window did not permute either batch: batch1={batch1:?} batch2={batch2:?}",
    );
}

// ---- Test 2: asymmetric (directional) latency ----

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn asymmetric_latency_shows_up_in_observed_round_trip_time() {
    // 10ms forward, 500ms reverse. Gossip at node 0 triggers one write
    // on (0→1) at +10ms; node 1's re-broadcast writes back on (1→0) at
    // +500ms relative to that arrival, so the round-trip is ~510ms.
    let driver = SimDriver::new_with_start(2, /* seed */ 100, fixed_start()).await;

    driver.set_link_directional(
        0,
        1,
        LinkConfig {
            latency: LatencyDist::Constant(Duration::from_millis(10)),
            ..LinkConfig::ideal()
        },
    );
    driver.set_link_directional(
        1,
        0,
        LinkConfig {
            latency: LatencyDist::Constant(Duration::from_millis(500)),
            ..LinkConfig::ideal()
        },
    );

    driver
        .node(0)
        .inject_gossip(
            fixed_gossip("ping", 2_000_000_000),
            &*driver.clock as &dyn Clock,
        )
        .await;
    driver.run_until_quiescent().await;

    let node0 = driver.node_id(0);
    let node1 = driver.node_id(1);
    let trace = driver.drain_trace();

    let t_forward = trace
        .iter()
        .find(|t| t.from == node0 && t.to == node1)
        .expect("no (0→1) trace entry")
        .time;
    let t_reverse = trace
        .iter()
        .find(|t| t.from == node1 && t.to == node0)
        .expect("no (1→0) trace entry — node 1 should re-broadcast");

    let start = fixed_start();
    let forward_ms = t_forward.signed_duration_since(start).num_milliseconds();
    let reverse_ms = t_reverse
        .time
        .signed_duration_since(start)
        .num_milliseconds();

    // Forward ~10ms, reverse ~510ms. The reverse delivery is latency_rev
    // after the forward arrived, i.e. ~500ms later. Use a 400ms lower
    // bound for robustness.
    assert!(
        forward_ms < 50,
        "forward delivery should be ~10ms, saw {forward_ms}ms",
    );
    assert!(
        reverse_ms - forward_ms >= 400,
        "directional asymmetry not observed: forward={forward_ms}ms \
         reverse={reverse_ms}ms (delta={delta}ms, expected ≥ 400)",
        delta = reverse_ms - forward_ms,
    );
}

// ---- Test 3: combined partition + drop + latency/jitter ----

/// Five nodes split into group A = {0,1} and group B = {2,3,4}. Inside
/// each group every link has 30% drop and Normal(mean=200ms, std=50ms)
/// latency. Inter-group links are cut via partition_groups — so by
/// construction no cross-contamination is possible. Inject `alpha` at
/// node 0, `beta` at node 2.
async fn combined_faults_scenario(seed: u64) -> Vec<crate::sim::network::TraceEntry> {
    let driver = SimDriver::new_with_start(5, seed, fixed_start()).await;

    let group_a = [0, 1];
    let group_b = [2, 3, 4];
    driver.partition_groups(&group_a, &group_b);

    let faulty = LinkConfig {
        latency: LatencyDist::Normal {
            mean: Duration::from_millis(200),
            std_dev: Duration::from_millis(50),
        },
        drop_rate: 0.3,
        ..LinkConfig::ideal()
    };
    // Intra-group links: 0↔1 in group A; 2↔3, 2↔4, 3↔4 in group B.
    driver.set_link(0, 1, faulty.clone());
    driver.set_link(2, 3, faulty.clone());
    driver.set_link(2, 4, faulty.clone());
    driver.set_link(3, 4, faulty);

    driver
        .node(0)
        .inject_gossip(
            fixed_gossip("alpha", 2_000_000_000),
            &*driver.clock as &dyn Clock,
        )
        .await;
    driver
        .node(2)
        .inject_gossip(
            fixed_gossip("beta", 2_000_000_000),
            &*driver.clock as &dyn Clock,
        )
        .await;
    driver.run_until_quiescent().await;

    let per_node = driver.per_node_contents();
    // Group A should see only "alpha"; group B only "beta". The partition
    // prevents any leakage; the drop/jitter must not starve intra-group
    // flooding.
    assert_eq!(
        per_node[0],
        vec!["alpha".to_string()],
        "node 0 (group A) contents: {:?}",
        per_node[0],
    );
    assert_eq!(
        per_node[1],
        vec!["alpha".to_string()],
        "node 1 (group A) did not converge under combined faults: {:?}",
        per_node[1],
    );
    for i in [2, 3, 4] {
        assert_eq!(
            per_node[i],
            vec!["beta".to_string()],
            "node {i} (group B) did not converge under combined faults: {:?}",
            per_node[i],
        );
    }

    driver.drain_trace()
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn combined_faults_allow_intra_partition_progress_without_cross_contamination() {
    let trace = combined_faults_scenario(/* seed */ 3).await;
    assert!(!trace.is_empty(), "combined-fault trace unexpectedly empty",);
}

// ---- Test 4: combined-fault determinism fingerprint ----

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn combined_faults_two_runs_with_same_seed_produce_byte_identical_traces() {
    let trace_a = combined_faults_scenario(/* seed */ 3).await;
    let trace_b = combined_faults_scenario(/* seed */ 3).await;
    assert!(!trace_a.is_empty(), "trace unexpectedly empty");
    assert_eq!(
        trace_a,
        trace_b,
        "combined-fault runs diverged: {} vs {} entries",
        trace_a.len(),
        trace_b.len(),
    );
}
