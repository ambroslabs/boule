//! A1 **Phase-5 two-instance determinism proof** (#793/#785): drive *two*
//! independent custom-EL instances (A = proposer, B = verifier) over the real
//! Engine API and prove they converge **byte-for-byte** on the canonical
//! Registry (`0x…0b12`).
//!
//! For each block (a settled-only block, then a full key + weight + settled
//! block whose `extra_data` exceeds the Ethereum 32-byte cap):
//! 1. **A builds** it (`forkchoiceUpdatedV3(attrs)` → `getPayloadV4`) — the build
//!    path, with the relaxed-cap `ConsensusBuilder`.
//! 2. **B verifies** the *same* sealed payload (`newPayloadV4` + `fcU`) — the
//!    verify path, with the relaxed-cap `convert_payload_to_block`. B never sees
//!    the build attribute; it reconstructs the write set from the propagated
//!    header `extra_data` alone (the EIP-4788 determinism model).
//! 3. Assert **A and B agree on the block hash** (so their state roots, and thus
//!    their `0x…0b12` storage, are identical) and that `keyAt` / `weightOf` /
//!    `settledView` read back from `0x…0b12` match on *both* instances.
//!
//! Both instances must run the *same* genesis (canonical Registry at `0x…0b12`).
//!
//! ```text
//! drive-custom-el-2inst <jwtA.hex> <jwtB.hex> [engineA] [ethA] [engineB] [ethB]
//! ```
//! Defaults: A on 8551/8545, B on 8561/8555.

use anyhow::{Context, Result, bail};
use boule_consensus::View;
use boule_consensus::replication::application::ValidatorUpdate;
use boule_core::identity::NodeId;
use boule_reth::engine::ElStatus;
use boule_reth::registry::RecordKey;
use boule_reth::registry_payload::RegistryPayload;
use boule_reth::{BuiltBlock, HttpTransport, RethEngine};
use serde_json::json;
use std::time::Duration;

/// The canonical Registry predeploy address both instances read/write (#793).
const REGISTRY_ADDR: &str = boule_reth::registry::REGISTRY_ADDRESS;

const KEY_AT: [u8; 4] = [0x3a, 0x9e, 0x35, 0x8a];
const WEIGHT_OF: [u8; 4] = [0x4c, 0x10, 0x8d, 0x6d];
const SETTLED_VIEW: [u8; 4] = [0x7a, 0x68, 0x6e, 0xf2];

fn left_pad32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    out
}

async fn eth_call(t: &HttpTransport, calldata: Vec<u8>) -> Result<Vec<u8>> {
    let data = format!("0x{}", hex::encode(calldata));
    let res = t
        .eth(
            "eth_call",
            json!([{ "to": REGISTRY_ADDR, "data": data }, "latest"]),
        )
        .await?;
    let hex = res.as_str().context("eth_call result hex")?;
    hex::decode(hex.trim_start_matches("0x")).context("eth_call result not hex")
}

/// Read the three registry surfaces (keyAt, weightOf, settledView) at the head.
async fn read_registry(
    t: &HttpTransport,
    validator: &NodeId,
    v_eff: View,
    weight_validator: &NodeId,
) -> Result<(Vec<u8>, u64, u64)> {
    let mut kcd = KEY_AT.to_vec();
    kcd.extend_from_slice(validator);
    kcd.extend_from_slice(&left_pad32(&v_eff.0.to_be_bytes()));
    let got_k = eth_call(t, kcd).await?;
    let len = u64::from_be_bytes(got_k[32 + 24..64].try_into().unwrap()) as usize;
    let key = got_k[64..64 + len].to_vec();

    let mut wcd = WEIGHT_OF.to_vec();
    wcd.extend_from_slice(weight_validator);
    let got_w = eth_call(t, wcd).await?;
    let weight = u64::from_be_bytes(got_w[24..32].try_into().unwrap());

    let got_s = eth_call(t, SETTLED_VIEW.to_vec()).await?;
    let settled = u64::from_be_bytes(got_s[24..32].try_into().unwrap());

    Ok((key, weight, settled))
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let jwt_a = args.next().context("usage: <jwtA> <jwtB> [urls...]")?;
    let jwt_b = args.next().context("usage: <jwtA> <jwtB> [urls...]")?;
    let engine_a = args
        .next()
        .unwrap_or_else(|| "http://127.0.0.1:8551".into());
    let eth_a = args
        .next()
        .unwrap_or_else(|| "http://127.0.0.1:8545".into());
    let engine_b = args
        .next()
        .unwrap_or_else(|| "http://127.0.0.1:8561".into());
    let eth_b = args
        .next()
        .unwrap_or_else(|| "http://127.0.0.1:8555".into());

    let secret_a = hex::decode(
        std::fs::read_to_string(&jwt_a)?
            .trim()
            .trim_start_matches("0x"),
    )?;
    let secret_b = hex::decode(
        std::fs::read_to_string(&jwt_b)?
            .trim()
            .trim_start_matches("0x"),
    )?;

    let ta = HttpTransport::new(engine_a, eth_a.clone(), secret_a, None);
    let tb = HttpTransport::new(engine_b, eth_b.clone(), secret_b, None);

    // Both must boot the same genesis → identical genesis EVM block.
    let (gen_a, _) = boule_reth::fetch_genesis(&eth_a)
        .await
        .context("fetch genesis A (is instance A up?)")?;
    let (gen_b, _) = boule_reth::fetch_genesis(&eth_b)
        .await
        .context("fetch genesis B (is instance B up?)")?;
    check(
        gen_a == gen_b,
        &format!("both instances share a genesis ({gen_a})"),
    )?;

    let fee = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
    let ea = RethEngine::new(&ta, fee);
    let eb = RethEngine::new(&tb, fee);

    // The full-payload write set we will read back on both instances.
    let validator: NodeId = [0x42; 32];
    let v_eff = View::new(15);
    let key128: [u8; 128] = std::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(1));
    let weight_validator: NodeId = [0x77; 32];
    let weight = 4242u64;
    let settled_full = View::new(11);

    // ── Block 1: settled-only (the common small block). A builds, B verifies. ──
    let p1 = RegistryPayload::new(vec![], &[], Some(View::new(9)));
    let b1 = build_on_a_verify_on_b(&ea, &eb, &gen_a, 1, &p1.to_attribute_hex()).await?;
    eprintln!("[block 1] settled-only: A and B agree on {}", b1.block_hash);

    // ── Block 2: full payload (key + weight + settled), > 32-byte extra_data. ──
    let p2 = RegistryPayload::new(
        vec![RecordKey {
            validator,
            v_eff,
            key128,
        }],
        &[ValidatorUpdate {
            node_id: weight_validator,
            weight,
        }],
        Some(settled_full),
    );
    let b2 = build_on_a_verify_on_b(&ea, &eb, &b1.block_hash, 2, &p2.to_attribute_hex()).await?;
    eprintln!(
        "[block 2] full payload ({} bytes extra_data): A and B agree on {}",
        p2.encode().len(),
        b2.block_hash
    );

    // ── Both instances must read back the identical write set from 0x…0b12. ──
    let (ka, wa, sa) = read_registry(&ta, &validator, v_eff, &weight_validator).await?;
    let (kb, wb, sb) = read_registry(&tb, &validator, v_eff, &weight_validator).await?;
    check(ka == key128 && kb == key128, "keyAt == key128 on A and B")?;
    check(
        wa == weight && wb == weight,
        &format!("weightOf == {weight} on A ({wa}) and B ({wb})"),
    )?;
    check(
        sa == settled_full.0 && sb == settled_full.0,
        &format!("settledView == {} on A ({sa}) and B ({sb})", settled_full.0),
    )?;
    check(
        ka == kb && wa == wb && sa == sb,
        "A and B read identical registry state",
    )?;

    eprintln!(
        "\nA1 PHASE-5 TWO-INSTANCE DETERMINISM PROOF PASSED: two independent custom \
         ELs converged on identical block hashes AND identical canonical-Registry \
         ({REGISTRY_ADDR}) state for a key + weight + settled block."
    );
    Ok(())
}

/// A builds block `n` on `parent` carrying `attr`; B verifies the *same* sealed
/// payload via `newPayloadV4` (reconstructing the write set from `extra_data`
/// alone). Asserts both commit VALID and agree on the block hash.
async fn build_on_a_verify_on_b(
    ea: &RethEngine<'_>,
    eb: &RethEngine<'_>,
    parent: &str,
    n: u64,
    attr: &str,
) -> Result<BuiltBlock> {
    let built = ea
        .build_block(parent, n, Duration::from_millis(500), attr)
        .await
        .with_context(|| format!("A build_block {n}"))?;
    let (ca, sa) = ea
        .commit_block(&built.execution_payload)
        .await
        .with_context(|| format!("A commit_block {n}"))?;
    check(sa == ElStatus::Valid, "A committed VALID")?;
    check(ca == built.block_hash, "A head == built hash")?;

    // B receives ONLY the sealed payload (no build attribute) and must reproduce
    // the identical block — the verify path's relaxed-cap converter + executor.
    let (cb, sb) = eb
        .commit_block(&built.execution_payload)
        .await
        .with_context(|| format!("B newPayloadV4 {n}"))?;
    check(sb == ElStatus::Valid, "B verified VALID")?;
    check(
        cb == built.block_hash,
        "B head == A's built hash (determinism)",
    )?;
    Ok(built)
}

fn check(cond: bool, msg: &str) -> Result<()> {
    if cond {
        eprintln!("ok: {msg}");
        Ok(())
    } else {
        bail!("FAIL: {msg}");
    }
}
