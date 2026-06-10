use anyhow::{Context, Result, bail};
use boule_consensus::View;
use boule_consensus::replication::application::ValidatorUpdate;
use boule_core::identity::NodeId;
use boule_reth::registry::RecordKey;
use boule_reth::registry_payload::RegistryPayload;
use boule_reth::{HttpTransport, RethEngine};
use serde_json::json;
use std::time::Duration;

const REGISTRY_ADDR: &str = boule_reth::registry::REGISTRY_ADDRESS;

const KEY_AT: [u8; 4] = [0x3a, 0x9e, 0x35, 0x8a];

const WEIGHT_OF: [u8; 4] = [0x4c, 0x10, 0x8d, 0x6d];

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

    let (genesis_hash, _root) = boule_reth::fetch_genesis(&eth_url)
        .await
        .context("fetch reth genesis (is the EL up on :8545?)")?;
    eprintln!("genesis EVM block: {genesis_hash}");

    let engine = RethEngine::new(&t, "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

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

    let got_settled = eth_call_at(&t, SETTLED_VIEW.to_vec(), "latest").await?;
    let got_settled_u64 = u64::from_be_bytes(got_settled[24..32].try_into().unwrap());
    check(
        got_settled_u64 == settled.0,
        &format!("settledView() == {} (got {got_settled_u64})", settled.0),
    )?;

    let validator: NodeId = [0x42; 32];
    let v_eff = View::new(15);
    let key128: [u8; 128] = std::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(1));
    let weight_validator: NodeId = [0x77; 32];
    let weight = 4242u64;
    let settled2 = View::new(11);
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
        Some(settled2),
    );
    let attr2 = p2.to_attribute_hex();
    eprintln!(
        "\n[scenario 2] full payload attribute ({} extra_data bytes; > 32)",
        attr2.len() / 2 - 1
    );
    let parent2 = built.block_hash.clone();
    let b2 = engine
        .build_block(&parent2, 2, Duration::from_millis(500), &attr2)
        .await
        .context("build_block (full payload) on the custom EL")?;
    eprintln!(
        "[scenario 2] built EVM block {} ({})",
        b2.block_number, b2.block_hash
    );
    let (c2, s2) = engine
        .commit_block(&b2.execution_payload)
        .await
        .context("commit_block (full payload, newPayloadV4 + fcU)")?;
    eprintln!("[scenario 2] committed {c2} status={s2:?}");
    check(
        s2 == boule_reth::engine::ElStatus::Valid,
        "full payload accepted by newPayloadV4 (status VALID)",
    )?;

    let mut kcd = KEY_AT.to_vec();
    kcd.extend_from_slice(&validator);
    kcd.extend_from_slice(&left_pad32(&v_eff.0.to_be_bytes()));
    let got_k = eth_call_at(&t, kcd, "latest").await?;
    let len = u64::from_be_bytes(got_k[32 + 24..64].try_into().unwrap()) as usize;
    check(
        got_k[64..64 + len] == key128,
        "keyAt(0x42..) == the 128-byte key we passed (at 0x…0b12)",
    )?;

    let mut wcd = WEIGHT_OF.to_vec();
    wcd.extend_from_slice(&weight_validator);
    let got_w = eth_call_at(&t, wcd, "latest").await?;
    let got_w_u64 = u64::from_be_bytes(got_w[24..32].try_into().unwrap());
    check(
        got_w_u64 == weight,
        &format!("weightOf(0x77..) == {weight} (got {got_w_u64}) (at 0x…0b12)"),
    )?;

    let got_settled2 = eth_call_at(&t, SETTLED_VIEW.to_vec(), "latest").await?;
    let got_settled2_u64 = u64::from_be_bytes(got_settled2[24..32].try_into().unwrap());
    check(
        got_settled2_u64 == settled2.0,
        &format!(
            "settledView() == {} (got {got_settled2_u64}) (at 0x…0b12)",
            settled2.0
        ),
    )?;

    eprintln!(
        "\nA1 LIVE-EL PROOF: scenario 1 (settled-only) AND scenario 2 (key + weight + \
         settled, full payload) PASSED end to end — all reads from the canonical \
         Registry at {REGISTRY_ADDR}."
    );
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
