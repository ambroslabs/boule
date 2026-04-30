//! libFuzzer target for the ingress→safety-core path under
//! [`QcVerification::Skip`] (audit finding 14-5, issue #424).
//!
//! Postcard decoding itself is panic-safe; what this target pins down
//! is everything *downstream* of decode on the [`ingress_wire`] entry
//! point — the exact path the production node and most tests take when
//! `QcVerification::Skip` is in effect.
//!
//! `src/consensus/wire_fuzz.rs` already covers the decode-side shape
//! coverage with a proptest-driven harness, but proptest's per-iteration
//! cost (real Ed25519 signing) caps the number of cases it can run in a
//! reasonable wall-clock. libFuzzer trades that cost for raw bytes plus
//! coverage-guided mutation, so this target is the one that gets run for
//! hours rather than seconds.
//!
//! # Catches
//!
//! - panics in QC well-formedness paths under malformed bitmaps
//! - stray-bit conditions on `SignerBitmap` past `len`
//! - signer-bitmap overflow / signature-count-vs-signers divergence
//! - any decode-time invariant the wire types' constructors enforce
//!   that postcard's positional decode bypasses
//!
//! # Path
//!
//! `bytes -> WireMessage -> ingress_wire(QcVerification::Skip)`. Only a
//! panic counts as a failure; both `Ok(_)` and `Err(_)` returns are
//! expected and ignored.
//!
//! # Recommended runtime
//!
//! - Smoke: `cargo +nightly fuzz run dispatch_ingress_skip -- -max_total_time=60`
//! - Per-PR opt-in: 10 min (`-max_total_time=600`)
//! - Nightly soak: 6 h (`-max_total_time=21600`)
//!
//! See `fuzz/README.md` for the full runbook.

#![no_main]

use std::sync::LazyLock;

use ambros_p2p::consensus::dispatch::ingress_wire;
use ambros_p2p::consensus::node::WireMessage;
use ambros_p2p::consensus::validator_history::ValidatorSetHistory;
use ambros_p2p::consensus::validator_key_history::ValidatorKeyHistory;
use ambros_p2p::consensus::validator_set::{ValidatorId, ValidatorSet};
use ambros_p2p::crypto::signed::ChainId;
use libfuzzer_sys::fuzz_target;

/// Tiny fixed validator set. Four validators is the smallest size that
/// exercises a real (≥3) BFT quorum boundary while keeping the
/// `is_well_formed` bitmap math non-trivial. NodeIds are deterministic
/// `[1; 32] .. [4; 32]` so committed corpus seeds with `signer = [k; 32]`
/// pass the membership check and reach the envelope-sig path.
const N_VALIDATORS: u8 = 4;

/// Production callers derive the chain id from `genesis_block.hash()`;
/// we use the all-zero binding here so the fuzz target stays stable
/// across any test-only changes to `ChainId::TEST`.
const CHAIN_ID: ChainId = ChainId::from_genesis_hash([0u8; 32]);

static HISTORY: LazyLock<ValidatorSetHistory> = LazyLock::new(|| {
    let members: Vec<ValidatorId> = (1..=N_VALIDATORS)
        .map(|b| ValidatorId::from_genesis_pubkey([b; 32]))
        .collect();
    ValidatorSetHistory::from_genesis(ValidatorSet::new(members))
});

static KEY_HISTORY: LazyLock<ValidatorKeyHistory> =
    LazyLock::new(|| ValidatorKeyHistory::from_set_history(&HISTORY));

fuzz_target!(|data: &[u8]| {
    let Ok(msg) = postcard::from_bytes::<WireMessage>(data) else {
        return;
    };
    // Pick a `from` peer that's a member of the validator set so frames
    // whose dispatch path branches on `from` don't all early-out on a
    // membership check elsewhere. The exact value doesn't matter — any
    // 32 bytes is a legal `NodeId` — but using a real validator id
    // keeps the harness honest about the production setting.
    let from = [1u8; 32];
    let _ = ingress_wire(from, msg, &HISTORY, &KEY_HISTORY, &CHAIN_ID);
});
