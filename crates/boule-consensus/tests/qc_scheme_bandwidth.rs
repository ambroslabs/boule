//! Issue #295 — Ed25519-collected vs BLS-aggregated QC bandwidth/CPU
//! comparison at validator-set sizes spanning the production regime.
//!
//! For each `n` (and resulting quorum `q = 2n/3 + 1`):
//!
//! - Wire size of the QC (postcard-encoded), to measure the
//!   collected-vs-aggregated tradeoff.
//! - Aggregation time at the leader: build a QC by folding `q`
//!   partials.
//! - Verification time on receipt: a single QC verification call.
//!
//! Numbers are reported in a small table to stdout. The test is marked
//! `#[ignore]` so CI's main test pass stays fast; run explicitly via:
//!
//! ```sh
//! cargo test --release --test qc_scheme_bandwidth --ignored -- --nocapture
//! ```
//!
//! `--release` matters — debug builds dominate the BLS pairing check by
//! 100×+ and would mislead the comparison.
//!
//! # Reading the output
//!
//! - Ed25519's wire size grows linearly with `q` (one 64-byte sig per
//!   signer). BLS's wire size is constant in the aggregate plus the
//!   bitmap.
//! - Ed25519 verifies in `O(q)` `ring::ED25519::verify` calls. BLS
//!   verifies in one pairing check independent of `q`.
//! - Aggregation cost: Ed25519 is essentially a memcpy per partial.
//!   BLS does a G2 deserialize + add + reserialize per partial under
//!   the current trait shape. A future optimization (#293 follow-up
//!   that holds the in-memory `AggregateSignature` rather than
//!   round-tripping bytes) would speed this up; the bench will catch
//!   that improvement when it lands.

use std::time::{Duration, Instant};

use boule::crypto::sig_scheme::{BlsAggregated, BlsPublicKey, BlsSecretKey};
use boule::crypto::signed::{NodeSigner, Signer};
use boule::identity::NodeId;
use boule::identity::NodeIdentity;
use boule_consensus::hotstuff::qc::{QuorumCertificate, Vote as ConsensusVote, quorum_size};
use rcgen::{KeyPair as RcgenKeyPair, PKCS_ED25519};
use zeroize::Zeroizing;

/// Validator-set sizes to bench. Includes 4 (the smallest BFT
/// committee), 16 / 32 (Cosmos-Hub-ish), 100 (the parent issue's
/// stated point at which BLS becomes load-bearing), and 200 (the rough
/// upper end of collected-sig viability).
const SIZES: &[usize] = &[4, 16, 32, 100, 200];

/// Iterations averaged per measurement. Trades stability against
/// total wall clock — the bench is `#[ignore]`'d so a few seconds is
/// fine.
const ITERATIONS: u32 = 8;

#[derive(Clone, Copy)]
struct Stats {
    wire_bytes: usize,
    aggregate: Duration,
    verify: Duration,
}

#[test]
#[ignore = "benchmark; run with --release --ignored -- --nocapture"]
fn ed25519_collected_vs_bls_aggregated_qc_bench() {
    println!();
    println!(
        "{:<6} {:<6} {:>12} {:>14} {:>14} {:>14} {:>14}",
        "n", "quorum", "ed wire B", "ed agg µs", "ed verify µs", "bls wire B", "bls verify µs",
    );
    println!("{}", "─".repeat(86));

    for &n in SIZES {
        let q = quorum_size(n);
        let ed_stats = bench_ed25519(n, q);
        let bls_stats = bench_bls(n, q);

        println!(
            "{:<6} {:<6} {:>12} {:>14.1} {:>14.1} {:>14} {:>14.1}",
            n,
            q,
            ed_stats.wire_bytes,
            ed_stats.aggregate.as_secs_f64() * 1e6,
            ed_stats.verify.as_secs_f64() * 1e6,
            bls_stats.wire_bytes,
            bls_stats.verify.as_secs_f64() * 1e6,
        );

        // Sanity bounds: BLS wire size is dominated by the constant
        // 96-byte aggregate plus the bitmap; Ed25519 wire size grows
        // linearly with q. By n=200 (q=134), the gap should be
        // pronounced.
        if n >= 100 {
            assert!(
                bls_stats.wire_bytes < ed_stats.wire_bytes,
                "BLS QC wire bytes {} should be smaller than Ed25519 {} at n={n}",
                bls_stats.wire_bytes,
                ed_stats.wire_bytes,
            );
        }
    }
    println!();
}

fn bench_ed25519(n: usize, q: usize) -> Stats {
    // Pre-generate signers and the message they sign over.
    let signers: Vec<NodeSigner> = (0..n).map(|_| fresh_ed_signer()).collect();
    let pubkeys: Vec<NodeId> = signers.iter().map(|s| s.node_id()).collect();
    let block_hash = [0xAB; 32];
    let view = boule_consensus::View(1);
    let payload = ConsensusVote { view, block_hash };
    let message = postcard::to_stdvec(&payload).expect("vote payload encoding");

    // Pre-sign every partial — done once, outside the timed loop.
    let partials: Vec<[u8; 64]> = signers.iter().map(|s| s.sign(&message)).collect();

    let mut agg_total = Duration::ZERO;
    let mut verify_total = Duration::ZERO;
    let mut wire_bytes = 0usize;

    for _ in 0..ITERATIONS {
        // Aggregate.
        let t = Instant::now();
        let mut qc = QuorumCertificate::new(view, block_hash, n);
        for (i, sig) in partials.iter().take(q).enumerate() {
            qc.add_signature(i, *sig);
        }
        agg_total += t.elapsed();

        // Wire size.
        wire_bytes = postcard::to_stdvec(&qc).expect("qc encoding").len();

        // Verify.
        let t = Instant::now();
        qc.verify_aggregate(&message, &pubkeys)
            .expect("ed25519 QC verify");
        verify_total += t.elapsed();
    }

    Stats {
        wire_bytes,
        aggregate: agg_total / ITERATIONS,
        verify: verify_total / ITERATIONS,
    }
}

fn bench_bls(n: usize, q: usize) -> Stats {
    // Pre-generate BLS signers and the message they sign over.
    let signers: Vec<(BlsSecretKey, BlsPublicKey)> = (0..n).map(bls_signer).collect();
    let pubkeys: Vec<BlsPublicKey> = signers.iter().map(|(_, pk)| *pk).collect();
    let block_hash = [0xCD; 32];
    let view = boule_consensus::View(1);
    let payload = ConsensusVote { view, block_hash };
    let message = postcard::to_stdvec(&payload).expect("vote payload encoding");

    // Pre-sign every partial — done once.
    let partials: Vec<[u8; 96]> = signers
        .iter()
        .map(|(sk, _)| BlsAggregated::sign_partial(sk, &message).expect("BLS sign"))
        .collect();

    let mut agg_total = Duration::ZERO;
    let mut verify_total = Duration::ZERO;
    let mut wire_bytes = 0usize;

    for _ in 0..ITERATIONS {
        // Aggregate.
        let t = Instant::now();
        let mut qc = QuorumCertificate::new_bls(view, block_hash, n);
        for (i, partial) in partials.iter().take(q).enumerate() {
            qc.add_bls_partial(i, *partial);
        }
        agg_total += t.elapsed();

        // Wire size.
        wire_bytes = postcard::to_stdvec(&qc).expect("qc encoding").len();

        // Verify.
        let t = Instant::now();
        qc.verify_aggregate_bls(&message, &pubkeys)
            .expect("BLS QC verify");
        verify_total += t.elapsed();
    }

    Stats {
        wire_bytes,
        aggregate: agg_total / ITERATIONS,
        verify: verify_total / ITERATIONS,
    }
}

fn fresh_ed_signer() -> NodeSigner {
    let kp = RcgenKeyPair::generate_for(&PKCS_ED25519).unwrap();
    let identity = NodeIdentity {
        pkcs8_der: Zeroizing::new(kp.serialize_der()),
    };
    NodeSigner::from_identity(&identity).unwrap()
}

fn bls_signer(seed: usize) -> (BlsSecretKey, BlsPublicKey) {
    // Spread seed across the IKM bytes so distinct indices yield
    // distinct keys regardless of byte ordering.
    let mut ikm = [0u8; 32];
    for (i, byte) in ikm.iter_mut().enumerate() {
        *byte = ((seed.wrapping_mul(0x9E37_79B9) >> (i * 4)) & 0xFF) as u8;
    }
    BlsAggregated::keygen(&ikm).expect("seeded BLS keygen")
}
