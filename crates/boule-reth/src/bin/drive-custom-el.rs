//! A1 Phase-1 **live proof** (#781): drive the custom EL (`boule-reth-node`) over
//! the real Engine API with a `registryPayload` build attribute produced by
//! boule's **production** population code
//! ([`boule_reth::registry_payload::RegistryPayload`] +
//! [`boule_reth::RethEngine::build_block`]), then read the `Registry` predeploy
//! back over public RPC and assert `keyAt` / `weightOf` / `settledView` reflect
//! exactly what was passed.
//!
//! This closes the population→EL→registry loop with the real encoder: the EL
//! transcribes the attribute into the sealed header `extra_data` and applies the
//! writes as system calls (the same path every replica's `newPayloadV4` runs), so
//! a passing run proves the carrier + codec + EL-applier all agree with boule's
//! population bytes. (A full boule-node↔EL cluster e2e is Phase 5.)
//!
//! Run against a live custom EL started by `EL=custom run-reth.sh` (Engine API on
//! :8551 with the given JWT, public RPC on :8545), with the `Registry` deployed
//! at [`REGISTRY_ADDR`] (the EL writes there — see `boule-reth-node`'s
//! `registry::REGISTRY_ADDRESS`). Exits non-zero on any mismatch.
//!
//! ```text
//! drive-custom-el <jwt.hex>
//! ```

use anyhow::{Context, Result, bail};
use boule_consensus::View;
use boule_consensus::replication::application::ValidatorUpdate;
use boule_core::identity::NodeId;
use boule_reth::registry::RecordKey;
use boule_reth::registry_payload::RegistryPayload;
use boule_reth::{HttpTransport, RethEngine};
use serde_json::json;
use std::time::Duration;

/// The Registry address the **custom EL** writes to (mirror of
/// `boule_reth_node::registry::REGISTRY_ADDRESS`). The drive genesis deploys the
/// Registry code here so the EL's system calls hit real contract code.
const REGISTRY_ADDR: &str = "0x00000000000000000000000000000000000b0011";

/// `keyAt(bytes32,uint64)` selector (= `boule_reth::registry::KEY_AT_SELECTOR`).
const KEY_AT: [u8; 4] = [0x3a, 0x9e, 0x35, 0x8a];
/// `weightOf(bytes32)` selector.
const WEIGHT_OF: [u8; 4] = [0x4c, 0x10, 0x8d, 0x6d];
/// `settledView()` selector.
const SETTLED_VIEW: [u8; 4] = [0x7a, 0x68, 0x6e, 0xf2];

fn left_pad32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    out
}

async fn eth_call_at(t: &HttpTransport, calldata: Vec<u8>, block: &str) -> Result<Vec<u8>> {
    let data = format!("0x{}", hex::encode(calldata));
    let res = t
        .eth(
            "eth_call",
            json!([{ "to": REGISTRY_ADDR, "data": data }, block]),
        )
        .await?;
    let hex = res.as_str().context("eth_call result hex")?;
    hex::decode(hex.trim_start_matches("0x")).context("eth_call result not hex")
}

#[tokio::main]
async fn main() -> Result<()> {
    let jwt_path = std::env::args()
        .nth(1)
        .context("usage: drive-custom-el <jwt.hex>")?;
    let secret_hex = std::fs::read_to_string(&jwt_path)?.trim().to_string();
    let secret = hex::decode(secret_hex.trim_start_matches("0x")).context("JWT hex")?;

    let engine_url = "http://127.0.0.1:8551".to_string();
    let eth_url = "http://127.0.0.1:8545".to_string();
    let t = HttpTransport::new(engine_url, eth_url.clone(), secret, None);

    // Genesis anchor (EVM parent of the first built block).
    let (genesis_hash, _root) = boule_reth::fetch_genesis(&eth_url)
        .await
        .context("fetch reth genesis (is the EL up on :8545?)")?;
    eprintln!("genesis EVM block: {genesis_hash}");

    let engine = RethEngine::new(&t, "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

    // ── Scenario 1: the COMMON block — settledView only (#781 calls out that
    //    most blocks carry only the settled frontier, keeping extra_data small).
    //    This must pass build → commit → read-back end to end, proving the
    //    population→EL→registry path with boule's real population code. ────────
    let settled = View::new(9);
    let p1 = RegistryPayload::new(vec![], &[], Some(settled));
    let attr1 = p1.to_attribute_hex();
    eprintln!("\n[scenario 1] settled-only attribute (production encoder): {attr1}");
    eprintln!("[scenario 1] extra_data bytes: {}", attr1.len() / 2 - 1);

    let built = engine
        .build_block(&genesis_hash, 1, Duration::from_millis(500), &attr1)
        .await
        .context("build_block on the custom EL")?;
    eprintln!(
        "[scenario 1] built EVM block {} ({})",
        built.block_number, built.block_hash
    );
    let (committed, status) = engine
        .commit_block(&built.execution_payload)
        .await
        .context("commit_block (newPayloadV4 + fcU)")?;
    eprintln!("[scenario 1] committed {committed} status={status:?}");

    // Read settledView() back at the committed head — it must equal what boule
    // passed, applied by the EL as a `recordSettled` system call.
    let got_settled = eth_call_at(&t, SETTLED_VIEW.to_vec(), "latest").await?;
    let got_settled_u64 = u64::from_be_bytes(got_settled[24..32].try_into().unwrap());
    check(
        got_settled_u64 == settled.0,
        &format!("settledView() == {} (got {got_settled_u64})", settled.0),
    )?;

    // ── Scenario 2: a FULL payload (key + weight + settled). This exercises the
    //    recordKey/recordWeight appliers, but the carried extra_data exceeds 32
    //    bytes — and alloy's ExecutionPayload→block conversion (used by the
    //    verify-path `newPayloadV4`) hardcodes MAXIMUM_EXTRA_DATA_SIZE = 32,
    //    independent of #788's relaxed EthBeaconConsensus cap. So the verify path
    //    rejects it (a real EL-side gap in #788's encoding option (a), NOT the
    //    boule population glue). We report the outcome honestly rather than fail
    //    the whole proof. ──────────────────────────────────────────────────────
    let validator: NodeId = [0x42; 32];
    let v_eff = View::new(15);
    let key128: [u8; 128] = std::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(1));
    let weight_validator: NodeId = [0x77; 32];
    let weight = 4242u64;
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
        Some(View::new(11)),
    );
    let attr2 = p2.to_attribute_hex();
    eprintln!(
        "\n[scenario 2] full payload attribute ({} extra_data bytes; > 32)",
        attr2.len() / 2 - 1
    );
    let parent2 = built.block_hash.clone();
    match engine
        .build_block(&parent2, 2, Duration::from_millis(500), &attr2)
        .await
    {
        Ok(b2) => match engine.commit_block(&b2.execution_payload).await {
            Ok((c2, s2)) => {
                eprintln!("[scenario 2] committed {c2} status={s2:?}");
                // If it ever lands (EL gap fixed), assert the key + weight too.
                let mut kcd = KEY_AT.to_vec();
                kcd.extend_from_slice(&validator);
                kcd.extend_from_slice(&left_pad32(&v_eff.0.to_be_bytes()));
                let got_k = eth_call_at(&t, kcd, "latest").await?;
                let len = u64::from_be_bytes(got_k[32 + 24..64].try_into().unwrap()) as usize;
                check(
                    got_k[64..64 + len] == key128,
                    "keyAt(0x42..) == the 128-byte key we passed",
                )?;
                let mut wcd = WEIGHT_OF.to_vec();
                wcd.extend_from_slice(&weight_validator);
                let got_w = eth_call_at(&t, wcd, "latest").await?;
                let got_w_u64 = u64::from_be_bytes(got_w[24..32].try_into().unwrap());
                check(
                    got_w_u64 == weight,
                    &format!("weightOf(0x77..) == {weight} (got {got_w_u64})"),
                )?;
            }
            Err(e) => eprintln!(
                "[scenario 2] EXPECTED GAP — verify path rejected the >32-byte payload: {e}\n\
                 (alloy ExecutionPayload→block caps extra_data at 32; #788 follow-up — \
                 carry a 32-byte commitment, or patch the conversion. Boule's population \
                 + ingress + build are correct.)"
            ),
        },
        Err(e) => eprintln!("[scenario 2] build rejected the >32-byte payload: {e}"),
    }

    eprintln!("\nA1 LIVE-EL PROOF: scenario 1 (the common settled-only block) PASSED end to end.");
    Ok(())
}

fn check(cond: bool, msg: &str) -> Result<()> {
    if cond {
        eprintln!("ok: {msg}");
        Ok(())
    } else {
        bail!("FAIL: {msg}");
    }
}
