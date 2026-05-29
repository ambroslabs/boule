//! Regenerate the committed initial corpus for `dispatch_ingress_skip`.
//!
//! Mirrors the wire-shape coverage of `crates/boule-node/src/wire_fuzz.rs`:
//! one decodable sample per [`WireMessage`] variant, plus a handful of
//! edge cases (empty payloads, max-view, non-genesis parent) that the
//! proptest generators in `wire_fuzz.rs` already cover. libFuzzer's
//! coverage-guided mutator takes over from there.
//!
//! Run from the repo root:
//!
//! ```sh
//! cd fuzz && cargo run --release --bin seed_corpus
//! ```
//!
//! The output directory is `fuzz/corpus/dispatch_ingress_skip/`, which
//! is what `cargo fuzz run dispatch_ingress_skip` reads from by default.
//! The binary is idempotent — rerunning it overwrites existing files
//! with byte-identical content (each sample is constructed
//! deterministically), so re-seeding produces a clean diff if the wire
//! format ever changes.
//!
//! # Why fixed dummy NodeIds, not real signers
//!
//! `wire_fuzz.rs` signs with real Ed25519 keys because each proptest
//! iteration is its own context — runtime keygen is amortized via a
//! `OnceLock` pool, but each generator still has access to private
//! keys at run time. libFuzzer operates on raw bytes: it can't produce
//! a valid signature from arbitrary input, and there's no signer pool
//! visible to the fuzzer. Seeding with dummy NodeIds whose membership
//! check passes (`signer = [k; 32]` for `k in 1..=4`, matching the
//! fuzz target's validator set) covers the variants up to
//! envelope-sig verification; anything past that is for libFuzzer's
//! mutator to discover.

use std::io::Write;
use std::path::{Path, PathBuf};

use boule::crypto::signed::Signed;
use boule::identity::NodeId;
use boule_consensus::hotstuff::qc::{NewView, Proposal, QuorumCertificate, TimeoutVote, Vote};
use boule_consensus::replication::block::{Block, BlockHeader};
use boule_consensus::wire::{BlockResponsePayload, WireMessage};
use boule_consensus::{Height, View};
use bytes::Bytes;

const N_VALIDATORS: usize = 4;

/// Same NodeId space as the fuzz target's validator set: `[1; 32]
/// .. [4; 32]`. Using a real validator NodeId here lets the
/// signer-membership check in [`boule_consensus::dispatch::ingress_wire`]
/// pass, so the seed exercises the path into envelope-sig verification.
fn validator_node_id(idx: u8) -> NodeId {
    [idx; 32]
}

fn write_sample(dir: &Path, name: &str, bytes: &[u8]) {
    let path = dir.join(format!("{name}.bin"));
    let mut file =
        std::fs::File::create(&path).unwrap_or_else(|e| panic!("create {}: {e}", path.display()));
    file.write_all(bytes)
        .unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    println!("wrote {} ({} bytes)", path.display(), bytes.len());
}

fn encode(msg: &WireMessage) -> Vec<u8> {
    postcard::to_stdvec(msg).expect("WireMessage is postcard-serializable")
}

fn signed<T>(payload: T, signer_idx: u8) -> Signed<T> {
    Signed {
        payload,
        signer: validator_node_id(signer_idx),
        sig: [0u8; 64],
    }
}

/// Build a placeholder Ed25519-collected QC over `(view, block_hash)`
/// with a full quorum of placeholder signatures. The aggregate is
/// well-formed under [`is_well_formed`] — libFuzzer mutates from there
/// to explore stray-bit and length-mismatch territory.
///
/// [`is_well_formed`]: boule::crypto::sig_scheme::SignerBitmap::is_well_formed
fn placeholder_qc(view: u64, block_hash: [u8; 32]) -> QuorumCertificate {
    let mut qc = QuorumCertificate::new(view, block_hash, N_VALIDATORS);
    for i in 0..N_VALIDATORS {
        qc.add_signature(i, [i as u8 + 1; 64]);
    }
    qc
}

fn placeholder_block(parent_hash: [u8; 32], height: u64, view: u64, proposer: NodeId) -> Block {
    let header = BlockHeader {
        parent_hash,
        height: Height(height),
        view: View(view),
        proposer,
        state_commitment: [view as u8; 32],
        commands_commitment: Block::commands_commitment(&[]),
        validator_history_commitment: [0; 32],
    };
    Block {
        header,
        commands: Vec::new(),
    }
}

fn main() {
    let dir: PathBuf = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("corpus/dispatch_ingress_skip"));
    std::fs::create_dir_all(&dir).expect("create corpus dir");

    let genesis = Block::genesis([0; 32], [0; 32]);
    let genesis_hash = genesis.hash();

    // ── Unsigned variants (no envelope; reach the dispatch path
    //    unconditionally) ───────────────────────────────────────────────
    write_sample(
        &dir,
        "block_request_zero",
        &encode(&WireMessage::BlockRequest([0u8; 32])),
    );
    write_sample(
        &dir,
        "block_request_genesis",
        &encode(&WireMessage::BlockRequest(genesis_hash)),
    );
    write_sample(
        &dir,
        "snapshot_manifest_request_latest",
        &encode(&WireMessage::SnapshotManifestRequest { height: None }),
    );
    write_sample(
        &dir,
        "snapshot_manifest_request_at_h",
        &encode(&WireMessage::SnapshotManifestRequest { height: Some(7) }),
    );
    write_sample(
        &dir,
        "snapshot_manifest_response_none",
        &encode(&WireMessage::SnapshotManifestResponse(None)),
    );
    write_sample(
        &dir,
        "snapshot_chunk_request",
        &encode(&WireMessage::SnapshotChunkRequest {
            height: 1,
            chunk_idx: 0,
        }),
    );
    write_sample(
        &dir,
        "snapshot_chunk_response_none",
        &encode(&WireMessage::SnapshotChunkResponse {
            height: 1,
            chunk_idx: 0,
            payload: None,
        }),
    );
    write_sample(
        &dir,
        "snapshot_chunk_response_some",
        &encode(&WireMessage::SnapshotChunkResponse {
            height: 1,
            chunk_idx: 0,
            payload: Some(Bytes::from_static(&[0xAB; 16])),
        }),
    );

    // ── Signed variants (envelope-sig will not verify against the
    //    placeholder `[0; 64]`; the seed still lands the wire-shape and
    //    drives the mutator toward QC well-formedness paths) ───────────
    let signer_idx: u8 = 1;
    let signer = validator_node_id(signer_idx);

    let prop_genesis_child = Proposal {
        block: placeholder_block(genesis_hash, 1, 1, signer),
        justify: placeholder_qc(0, genesis_hash),
    };
    write_sample(
        &dir,
        "proposal_genesis_child",
        &encode(&WireMessage::Proposal(signed(
            prop_genesis_child,
            signer_idx,
        ))),
    );

    let prop_orphan = Proposal {
        block: placeholder_block([0xFE; 32], 5, 17, signer),
        justify: placeholder_qc(16, [0xFE; 32]),
    };
    write_sample(
        &dir,
        "proposal_orphan_parent",
        &encode(&WireMessage::Proposal(signed(prop_orphan, signer_idx))),
    );

    let vote = Vote {
        view: View(1),
        block_hash: genesis_hash,
    };
    write_sample(
        &dir,
        "vote_no_partial",
        &encode(&WireMessage::Vote(signed(vote.clone(), signer_idx), None)),
    );
    write_sample(
        &dir,
        "vote_with_partial",
        &encode(&WireMessage::Vote(
            signed(vote, signer_idx),
            Some([0u8; 96]),
        )),
    );

    let new_view = NewView {
        high_qc: placeholder_qc(3, [0x11; 32]),
    };
    write_sample(
        &dir,
        "new_view",
        &encode(&WireMessage::NewView(signed(new_view, signer_idx))),
    );

    let timeout_no_qc = TimeoutVote {
        view: View(7),
        high_qc: None,
    };
    write_sample(
        &dir,
        "timeout_vote_no_qc",
        &encode(&WireMessage::TimeoutVote(signed(timeout_no_qc, signer_idx))),
    );

    let timeout_with_qc = TimeoutVote {
        view: View(7),
        high_qc: Some(placeholder_qc(6, [0x22; 32])),
    };
    write_sample(
        &dir,
        "timeout_vote_with_qc",
        &encode(&WireMessage::TimeoutVote(signed(
            timeout_with_qc,
            signer_idx,
        ))),
    );

    let block_resp_some = BlockResponsePayload {
        requested_hash: genesis_hash,
        block: Some(genesis.clone()),
    };
    write_sample(
        &dir,
        "block_response_some",
        &encode(&WireMessage::BlockResponse(signed(
            block_resp_some,
            signer_idx,
        ))),
    );

    let block_resp_none = BlockResponsePayload {
        requested_hash: [0xCD; 32],
        block: None,
    };
    write_sample(
        &dir,
        "block_response_none",
        &encode(&WireMessage::BlockResponse(signed(
            block_resp_none,
            signer_idx,
        ))),
    );
}
