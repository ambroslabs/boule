//! Tests for the Byzantine message-mutation hooks on `SimNetwork` (#46).
//!
//! The hooks run at delivery time and may replace the outgoing bytes, spoof
//! the sender, redirect the receiver, drop the event, or split it into
//! duplicates. These tests cover the headline cases plus the determinism
//! guarantee that the mutator path remains byte-identical across runs.
//!
//! # See also
//!
//! Protocol-level Byzantine adversaries (equivocation, vote
//! withholding, stale replays, forged QCs, timeout-vote spam) live in
//! [`crate::consensus::sim_byzantine`]. That module sits at the
//! `HotStuffCore` action boundary rather than the network byte
//! boundary; together the two cover the full BFT-input surface called
//! out in #132.

use std::sync::Arc;
use std::time::Duration;

use chrono::{Duration as ChronoDuration, TimeZone as _, Utc};

use crate::clock::Clock;
use crate::gossip::GossipMessage;
use crate::sim::network::TraceEntry;
use crate::sim::{EventMutator, LatencyDist, LinkConfig, MutatorInput, MutatorOutput, SimDriver};

fn gossip(content: &str) -> GossipMessage {
    GossipMessage {
        content: content.to_string(),
        expiry: Utc::now() + ChronoDuration::seconds(60),
    }
}

fn fixed_gossip(content: &str, expiry_unix_secs: i64) -> GossipMessage {
    GossipMessage {
        content: content.to_string(),
        expiry: Utc.timestamp_opt(expiry_unix_secs, 0).unwrap(),
    }
}

/// Corrupts the first byte of every non-empty payload. Since the sender's
/// [`LengthDelimitedCodec`] puts the 4-byte frame length at position 0, this
/// is enough to break framing on the receiver side.
struct FlipFirstByte;
impl EventMutator for FlipFirstByte {
    fn mutate(&self, input: &MutatorInput) -> Vec<MutatorOutput> {
        let mut bytes = input.bytes.clone();
        if !bytes.is_empty() {
            bytes[0] ^= 0x01;
        }
        vec![MutatorOutput {
            from: input.from,
            to: input.to,
            bytes,
        }]
    }
}

/// Replaces the payload with a same-length run of zeros. Receivers still see
/// bytes arrive (so the trace records a delivery) but the codec/decoder
/// rejects them, matching a 100% drop rate in end-to-end effect.
struct ZeroPayload;
impl EventMutator for ZeroPayload {
    fn mutate(&self, input: &MutatorInput) -> Vec<MutatorOutput> {
        vec![MutatorOutput {
            from: input.from,
            to: input.to,
            bytes: vec![0u8; input.bytes.len()],
        }]
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn per_link_bit_flip_prevents_receiver_from_accepting_frame() {
    // Two nodes connected by the single link 0 → 1. The mutator flips one
    // byte of every write; the receiver's length-prefix codec then rejects
    // the frame before the gossip engine ever sees it.
    let driver = SimDriver::new(2, /* seed */ 100).await;
    driver.set_link_mutator(0, 1, Arc::new(FlipFirstByte));

    driver
        .node(0)
        .inject_gossip(gossip("secret"), &*driver.clock as &dyn Clock)
        .await;
    driver.run_until_quiescent().await;

    let now = driver.clock.now_wall();
    assert_eq!(
        driver.node(0).messages(now).len(),
        1,
        "sender keeps its locally-injected copy",
    );
    assert!(
        driver.node(1).messages(now).is_empty(),
        "receiver must reject the frame corrupted in flight",
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn global_zero_payload_mutator_behaves_like_a_total_drop() {
    // 5-node full mesh. A global mutator zeroes every payload, so every
    // receiver sees well-formed deliveries but each one fails to decode —
    // nothing propagates beyond the injecting node.
    let driver = SimDriver::new(5, /* seed */ 101).await;
    driver.set_mutator(Arc::new(ZeroPayload));

    driver
        .node(0)
        .inject_gossip(gossip("payload-gone"), &*driver.clock as &dyn Clock)
        .await;
    driver.run_until_quiescent().await;

    let now = driver.clock.now_wall();
    assert_eq!(
        driver.node(0).messages(now).len(),
        1,
        "injecting node holds its locally-inserted copy",
    );
    for i in 1..5 {
        assert!(
            driver.node(i).messages(now).is_empty(),
            "node {i} must not receive the zeroed payload",
        );
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn clear_mutators_restores_normal_delivery() {
    // After installing both a global and a per-link mutator, clearing them
    // should return the network to its pristine ideal-delivery behaviour.
    let driver = SimDriver::new(3, /* seed */ 102).await;
    driver.set_mutator(Arc::new(ZeroPayload));
    driver.set_link_mutator(0, 1, Arc::new(FlipFirstByte));
    driver.clear_mutators();

    driver
        .node(0)
        .inject_gossip(gossip("clean"), &*driver.clock as &dyn Clock)
        .await;
    driver.run_until_quiescent().await;

    driver.assert_all_have("clean");
}

/// Run one determinism scenario with a bit-flipping mutator installed on
/// every link of a 5-node mesh with uniform latency and 10% drops.
async fn determinism_scenario_with_mutator(seed: u64) -> Vec<TraceEntry> {
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

    driver.set_mutator(Arc::new(FlipFirstByte));

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
async fn mutator_runs_are_byte_identical_under_the_same_seed() {
    let trace_a = determinism_scenario_with_mutator(/* seed */ 77).await;
    let trace_b = determinism_scenario_with_mutator(/* seed */ 77).await;
    assert!(
        !trace_a.is_empty(),
        "mutator trace unexpectedly empty — scenario did not exercise the hook",
    );
    assert_eq!(
        trace_a,
        trace_b,
        "mutator-path runs diverged under same seed: {} vs {} entries",
        trace_a.len(),
        trace_b.len(),
    );
}
