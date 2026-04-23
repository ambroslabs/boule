//! Tests for per-node [`SimClock`] skew/offset.
//!
//! Real replicas do not share a clock. The simulator lets tests seed each
//! node with a fixed offset from shared virtual time so pacemaker-style
//! liveness code can be probed under conditions we can't otherwise
//! reproduce. These tests pin both the visible semantics (a node's local
//! timer fires at `shared = local_t - offset`) and the determinism
//! contract (same seed → identical offsets).

use std::sync::Arc;
use std::time::Duration;

use chrono::{TimeZone as _, Utc};
use rand::Rng as _;
use tokio::sync::oneshot;

use crate::clock::Clock;
use crate::sim::{GossipFactory, MemoryBacking, SimDriver};

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn per_node_skew_makes_ahead_node_fire_earlier_in_shared_time() {
    // Node 0 runs 1s ahead of shared time; node 1 is unskewed. Both
    // schedule a timer for their *local* t=100s, computed by subtracting
    // their skewed `now_wall` from the target. Node 0 therefore sleeps
    // only 99s of shared virtual time and fires first.
    let start = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
    let driver = SimDriver::new_with_skew(
        2,
        /* seed */ 0,
        start,
        GossipFactory,
        MemoryBacking,
        |idx, _rng| {
            if idx == 0 {
                Duration::from_secs(1)
            } else {
                Duration::ZERO
            }
        },
    )
    .await
    .expect("memory backing infallible");

    let clock_a = driver.clock.for_node(driver.node_id(0));
    let clock_b = driver.clock.for_node(driver.node_id(1));

    // Sanity: views report their skewed `now_wall`.
    assert_eq!(clock_a.now_wall(), start + chrono::Duration::seconds(1));
    assert_eq!(clock_b.now_wall(), start);

    let target = start + chrono::Duration::seconds(100);

    let (tx_a, mut rx_a) = oneshot::channel();
    let (tx_b, mut rx_b) = oneshot::channel();

    let shared_for_a = Arc::clone(&driver.clock);
    let ca = Arc::clone(&clock_a);
    tokio::spawn(async move {
        let local_now = ca.now_wall();
        let dur = (target - local_now).to_std().expect("target in the future");
        ca.sleep(dur).await;
        let _ = tx_a.send(shared_for_a.now_wall());
    });

    let shared_for_b = Arc::clone(&driver.clock);
    let cb = Arc::clone(&clock_b);
    tokio::spawn(async move {
        let local_now = cb.now_wall();
        let dur = (target - local_now).to_std().expect("target in the future");
        cb.sleep(dur).await;
        let _ = tx_b.send(shared_for_b.now_wall());
    });

    // Let both spawned tasks register their sleeps before we advance.
    tokio::task::yield_now().await;

    // At shared+99s, node 0's 99-second sleep completes; node 1's
    // 100-second sleep is still pending.
    driver.advance(Duration::from_secs(99)).await;
    tokio::task::yield_now().await;
    let fire_a = rx_a
        .try_recv()
        .expect("node 0 should have fired at shared+99s");
    assert_eq!(fire_a, start + chrono::Duration::seconds(99));
    assert!(
        rx_b.try_recv().is_err(),
        "node 1 must not fire before shared+100s",
    );

    // One more second: node 1 fires.
    driver.advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    let fire_b = rx_b
        .try_recv()
        .expect("node 1 should have fired at shared+100s");
    assert_eq!(fire_b, start + chrono::Duration::seconds(100));
    assert!(fire_a < fire_b, "A (ahead) must fire before B (unskewed)");
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn per_node_skew_is_deterministic_across_runs_with_same_seed() {
    // `new_with_skew` seeds a dedicated RNG from the driver seed so that
    // two runs with the same seed produce identical per-node offsets.
    let start = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
    let skew = |_idx: usize, rng: &mut rand_chacha::ChaCha20Rng| {
        Duration::from_millis(rng.random_range(0..5_000))
    };

    let driver_a = SimDriver::new_with_skew(
        /* n */ 5,
        /* seed */ 123,
        start,
        GossipFactory,
        MemoryBacking,
        skew,
    )
    .await
    .unwrap();
    let driver_b = SimDriver::new_with_skew(
        /* n */ 5,
        /* seed */ 123,
        start,
        GossipFactory,
        MemoryBacking,
        skew,
    )
    .await
    .unwrap();

    let offsets_a: Vec<Duration> = (0..5)
        .map(|i| driver_a.clock.offset_for(driver_a.node_id(i)))
        .collect();
    let offsets_b: Vec<Duration> = (0..5)
        .map(|i| driver_b.clock.offset_for(driver_b.node_id(i)))
        .collect();

    assert_eq!(
        offsets_a, offsets_b,
        "same seed must yield identical offsets"
    );

    // Smoke check that the skew function actually produced some non-zero
    // offsets (otherwise the determinism assertion would pass vacuously).
    assert!(
        offsets_a.iter().any(|d| !d.is_zero()),
        "skew closure should have produced at least one non-zero offset",
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn per_node_skew_does_not_perturb_non_skewed_trace() {
    // Regression: the default `new_with_backing` path (no skew) must
    // produce a byte-identical trace to a run that explicitly supplies
    // an all-zero skew function.
    use crate::gossip::GossipMessage;
    use chrono::Duration as ChronoDuration;

    async fn drive(with_explicit_zero_skew: bool) -> Vec<crate::sim::network::TraceEntry> {
        let start = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let driver = if with_explicit_zero_skew {
            SimDriver::new_with_skew(
                3,
                /* seed */ 7,
                start,
                GossipFactory,
                MemoryBacking,
                |_, _| Duration::ZERO,
            )
            .await
            .unwrap()
        } else {
            SimDriver::new_with_backing(3, /* seed */ 7, start, GossipFactory, MemoryBacking)
                .await
                .unwrap()
        };

        driver
            .node(0)
            .inject_gossip(
                GossipMessage {
                    content: "zero-skew".to_string(),
                    expiry: start + ChronoDuration::seconds(60),
                },
                &*driver.clock as &dyn Clock,
            )
            .await;
        driver.run_until_quiescent().await;
        driver.drain_trace()
    }

    let trace_default = drive(false).await;
    let trace_zero = drive(true).await;
    assert_eq!(trace_default, trace_zero);
}
