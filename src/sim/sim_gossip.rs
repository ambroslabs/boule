//! First consumer of the simulator: the gossip engine, run unchanged inside
//! the sim, must propagate a single message across N nodes connected in a
//! full mesh — including under network faults injected by the driver.
//!
//! Tests live under `src/sim/` rather than `tests/` because the crate has no
//! library target — integration tests in the latter cannot reach internals.

use std::time::Duration;

use chrono::{Duration as ChronoDuration, TimeZone as _, Utc};

use crate::clock::Clock;
use crate::gossip::GossipMessage;
use crate::sim::{LatencyDist, LinkConfig, SimDriver};

fn gossip(content: &str) -> GossipMessage {
    GossipMessage {
        content: content.to_string(),
        expiry: Utc::now() + ChronoDuration::seconds(60),
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn five_nodes_propagate_a_single_gossip_message() {
    let driver = SimDriver::new(5, /* seed */ 0).await;

    driver
        .node(0)
        .inject_gossip(gossip("hello"), &*driver.clock as &dyn Clock)
        .await;

    driver.run_until_quiescent().await;

    let now = driver.clock.now_wall();
    for (i, node) in driver.nodes().iter().enumerate() {
        let live = node.messages(now);
        assert_eq!(
            live.len(),
            1,
            "node {i} expected 1 live message, got {}",
            live.len()
        );
        assert_eq!(live[0].content, "hello");
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn gossip_converges_under_uniform_latency() {
    let driver = SimDriver::new(5, /* seed */ 1).await;

    // Every link adds 5–25ms of virtual latency.
    let cfg = LinkConfig {
        latency: LatencyDist::Uniform {
            min: Duration::from_millis(5),
            max: Duration::from_millis(25),
        },
        ..LinkConfig::ideal()
    };
    for i in 0..5 {
        for j in (i + 1)..5 {
            driver.set_link(i, j, cfg.clone());
        }
    }

    driver
        .node(0)
        .inject_gossip(gossip("latency-test"), &*driver.clock as &dyn Clock)
        .await;
    driver.run_until_quiescent().await;

    let now = driver.clock.now_wall();
    for (i, node) in driver.nodes().iter().enumerate() {
        assert_eq!(
            node.messages(now).len(),
            1,
            "node {i} did not receive the gossip message",
        );
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn gossip_converges_with_some_links_dropping() {
    let driver = SimDriver::new(5, /* seed */ 2).await;

    // 30% drop rate on every link. Gossip's flooding (re-broadcast on first
    // sight) should still get the message everywhere because each node has
    // 4 paths to every other node.
    let cfg = LinkConfig {
        drop_rate: 0.3,
        ..LinkConfig::ideal()
    };
    for i in 0..5 {
        for j in (i + 1)..5 {
            driver.set_link(i, j, cfg.clone());
        }
    }

    driver
        .node(0)
        .inject_gossip(gossip("drop-test"), &*driver.clock as &dyn Clock)
        .await;
    driver.run_until_quiescent().await;

    let now = driver.clock.now_wall();
    for (i, node) in driver.nodes().iter().enumerate() {
        assert_eq!(
            node.messages(now).len(),
            1,
            "node {i} did not converge under 30% link drop (seed=2)",
        );
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn partition_isolates_then_heal_restores_propagation() {
    // Five nodes split into {0, 1} and {2, 3, 4}. Inject message A at
    // node 0: only nodes 0 and 1 see it. Heal the partition and inject
    // message B at node 0: all five see B (A does not back-fill — this
    // gossip implementation has no anti-entropy on reconnect, which is
    // expected behaviour for now).
    let driver = SimDriver::new(5, /* seed */ 3).await;

    let group_a = [0, 1];
    let group_b = [2, 3, 4];
    driver.partition_groups(&group_a, &group_b);

    driver
        .node(0)
        .inject_gossip(gossip("A-during-partition"), &*driver.clock as &dyn Clock)
        .await;
    driver.run_until_quiescent().await;

    let now = driver.clock.now_wall();
    for &i in &group_a {
        let msgs = driver.node(i).messages(now);
        assert_eq!(
            msgs.len(),
            1,
            "node {i} (group A) should have A while partitioned",
        );
        assert_eq!(msgs[0].content, "A-during-partition");
    }
    for &i in &group_b {
        assert!(
            driver.node(i).messages(now).is_empty(),
            "node {i} (group B) must not see A while partitioned",
        );
    }

    driver.heal_groups(&group_a, &group_b);

    driver
        .node(0)
        .inject_gossip(gossip("B-after-heal"), &*driver.clock as &dyn Clock)
        .await;
    driver.run_until_quiescent().await;

    let now = driver.clock.now_wall();
    for &i in &group_a {
        let contents: Vec<_> = driver
            .node(i)
            .messages(now)
            .into_iter()
            .map(|m| m.content)
            .collect();
        assert!(
            contents.contains(&"A-during-partition".to_string())
                && contents.contains(&"B-after-heal".to_string()),
            "group A node {i} should have both messages after heal, saw: {contents:?}",
        );
    }
    for &i in &group_b {
        let contents: Vec<_> = driver
            .node(i)
            .messages(now)
            .into_iter()
            .map(|m| m.content)
            .collect();
        assert!(
            contents == vec!["B-after-heal".to_string()],
            "group B node {i} should have only B after heal, saw: {contents:?}",
        );
    }
}

// ---- Adversary API / determinism ----

/// Gossip message with a fixed expiry, used by determinism tests that need
/// identical `GossipMessage` bytes across runs.
fn fixed_gossip(content: &str, expiry_unix_secs: i64) -> GossipMessage {
    GossipMessage {
        content: content.to_string(),
        expiry: Utc.timestamp_opt(expiry_unix_secs, 0).unwrap(),
    }
}

/// Run one determinism scenario: 5-node mesh with uniform latency + 10%
/// drops, two gossip messages injected at different nodes. Returns the
/// delivery trace.
async fn determinism_scenario(seed: u64) -> Vec<crate::sim::network::TraceEntry> {
    let start = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
    let driver = SimDriver::new_with_start(5, seed, start).await;

    let cfg = LinkConfig {
        latency: LatencyDist::Uniform {
            min: Duration::from_millis(1),
            max: Duration::from_millis(10),
        },
        drop_rate: 0.1,
        ..LinkConfig::ideal()
    };
    for i in 0..5 {
        for j in (i + 1)..5 {
            driver.set_link(i, j, cfg.clone());
        }
    }

    driver
        .node(0)
        .inject_gossip(
            fixed_gossip("alpha", 2_000_000_000),
            &*driver.clock as &dyn Clock,
        )
        .await;
    driver
        .node(3)
        .inject_gossip(
            fixed_gossip("beta", 2_000_000_000),
            &*driver.clock as &dyn Clock,
        )
        .await;
    driver.run_until_quiescent().await;

    driver.drain_trace()
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn two_runs_with_same_seed_produce_byte_identical_traces() {
    let trace_a = determinism_scenario(/* seed */ 42).await;
    let trace_b = determinism_scenario(/* seed */ 42).await;
    assert!(!trace_a.is_empty(), "trace unexpectedly empty");
    assert_eq!(
        trace_a,
        trace_b,
        "fixed-seed runs diverged: {} vs {} entries",
        trace_a.len(),
        trace_b.len(),
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn different_seeds_can_diverge() {
    // Not strictly required, but a smoke check that the seed actually
    // influences the trace — otherwise the determinism test above would
    // pass vacuously.
    let trace_a = determinism_scenario(1).await;
    let trace_b = determinism_scenario(2).await;
    assert_ne!(
        trace_a, trace_b,
        "seeds 1 and 2 produced identical traces \
         (scheduler may have become seed-insensitive)",
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn paused_node_does_not_observe_messages_until_resumed() {
    let driver = SimDriver::new(5, 10).await;

    // Node 2 is frozen before any traffic.
    driver.pause_node(2);

    driver
        .node(0)
        .inject_gossip(gossip("paused-test"), &*driver.clock as &dyn Clock)
        .await;
    driver.run_until_quiescent().await;

    // Paused node's reader never woke, so its gossip engine never processed
    // inbound bytes.
    assert!(
        driver.node(2).messages(driver.clock.now_wall()).is_empty(),
        "paused node should not have processed gossip",
    );
    // Everyone else converged.
    for i in [0, 1, 3, 4] {
        assert_eq!(
            driver.node(i).messages(driver.clock.now_wall()).len(),
            1,
            "node {i} should have the message",
        );
    }

    driver.resume_node(2);
    driver.run_until_quiescent().await;

    driver.assert_all_have("paused-test");
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn killed_node_disappears_from_the_mesh() {
    let driver = SimDriver::new(5, 11).await;

    driver.kill_node(4);

    driver
        .node(0)
        .inject_gossip(gossip("after-kill"), &*driver.clock as &dyn Clock)
        .await;
    driver.run_until_quiescent().await;

    // Nodes 0-3 converge.
    for i in 0..4 {
        let contents: Vec<_> = driver
            .node(i)
            .messages(driver.clock.now_wall())
            .into_iter()
            .map(|m| m.content)
            .collect();
        assert_eq!(contents, vec!["after-kill".to_string()], "node {i}");
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn deliver_next_bypasses_scheduled_time() {
    // Two nodes, 500ms constant latency. Inject at node 0; the gossip
    // broadcast is now in flight for 500ms of virtual time. Force one of
    // the pending events to deliver immediately and confirm node 1
    // processes the message before we advance the clock.
    let driver = SimDriver::new(2, 20).await;
    let cfg = LinkConfig {
        latency: LatencyDist::Constant(Duration::from_millis(500)),
        ..LinkConfig::ideal()
    };
    driver.set_link(0, 1, cfg);

    driver
        .node(0)
        .inject_gossip(gossip("urgent"), &*driver.clock as &dyn Clock)
        .await;

    // Let the write task push the event into the queue without pumping the
    // scheduler.
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    let in_flight = driver.in_flight_events();
    assert!(
        !in_flight.is_empty(),
        "expected at least one in-flight event after injection",
    );
    let id = in_flight[0].id;

    let delivered = driver.deliver_next(id);
    assert!(delivered, "deliver_next returned false for event {id:?}");

    // Give node 1's reader + gossip engine a chance to process without
    // advancing the clock past the original scheduled time (+500ms).
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    driver.assert_all_have("urgent");
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn duplicate_event_causes_second_delivery_but_dedup_wins() {
    // Three nodes, 100ms latency everywhere. Inject once, duplicate one of
    // the in-flight broadcast events, then drive to quiescence. The trace
    // should contain two separate deliveries of the same payload (proving
    // duplication happened); gossip's content-hash dedup means each node's
    // store still holds exactly one copy.
    let driver = SimDriver::new(3, 30).await;
    let cfg = LinkConfig {
        latency: LatencyDist::Constant(Duration::from_millis(100)),
        ..LinkConfig::ideal()
    };
    for i in 0..3 {
        for j in (i + 1)..3 {
            driver.set_link(i, j, cfg.clone());
        }
    }

    driver
        .node(0)
        .inject_gossip(gossip("dup-test"), &*driver.clock as &dyn Clock)
        .await;

    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    let in_flight = driver.in_flight_events();
    // Pick the first broadcast event from node 0 to duplicate.
    let target = in_flight
        .iter()
        .find(|e| e.byte_len > 0)
        .expect("at least one in-flight event");
    let target_bytes = target.byte_len;
    let target_to = target.to;
    let dup_id = driver
        .duplicate_event(target.id)
        .expect("duplicate_event returned None");
    assert_ne!(dup_id, target.id);

    driver.run_until_quiescent().await;

    driver.assert_all_converged_to(&["dup-test"]);

    // Trace: at least two deliveries to `target_to` of `target_bytes`
    // bytes from node 0 — the original and the duplicate.
    let trace = driver.trace();
    let node0 = driver.node_id(0);
    let matching = trace
        .iter()
        .filter(|t| t.from == node0 && t.to == target_to && t.byte_len == target_bytes)
        .count();
    assert!(
        matching >= 2,
        "expected >= 2 trace entries from node0 to {target_to:?} with {target_bytes} bytes, saw {matching}",
    );
}
