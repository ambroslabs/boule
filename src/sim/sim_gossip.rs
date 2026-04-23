//! First consumer of the simulator: the gossip engine, run unchanged inside
//! the sim, must propagate a single message across N nodes connected in a
//! full mesh.
//!
//! The simulator's deterministic-event-queue and fault-injection knobs aren't
//! present yet (they land in sub-tasks #30 and #32 of issue #19), so this
//! verifies only the "runs unchanged inside the sim" half of #19's
//! verification criteria. The "5 nodes, random drops, partition, heal,
//! converge" test will join this module once those land.
//!
//! Tests live under `src/sim/` rather than `tests/` because the crate has no
//! library target — integration tests in the latter cannot reach internals.

use chrono::{Duration as ChronoDuration, Utc};

use crate::clock::Clock;
use crate::gossip::GossipMessage;
use crate::sim::SimDriver;

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn five_nodes_propagate_a_single_gossip_message() {
    let driver = SimDriver::new(5, /* seed */ 0).await;

    let msg = GossipMessage {
        content: "hello".to_string(),
        expiry: Utc::now() + ChronoDuration::seconds(60),
    };

    driver
        .node(0)
        .inject_gossip(msg.clone(), &*driver.clock as &dyn Clock)
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
