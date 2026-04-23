//! First consumer of the simulator: the gossip engine, run unchanged inside
//! the sim, must propagate a single message across N nodes connected in a
//! full mesh — including under network faults injected by the driver.
//!
//! Tests live under `src/sim/` rather than `tests/` because the crate has no
//! library target — integration tests in the latter cannot reach internals.

use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};

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
