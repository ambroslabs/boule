//! RPC helper for the single-node `boule↔custom-EL` e2e (`single-node-el-e2e.sh`,
//! #785/#777) on a box without foundry's `cast`. Two subcommands over plain
//! HTTP JSON-RPC against the EL's public `eth_*` endpoint (:8545):
//!
//! - `deposit <NODE_ID_HEX> <AMOUNT_WEI>` — sign + submit an EIP-1559
//!   `Staking.deposit(bytes32)` tx (value = amount) from the prefunded anvil dev
//!   account, so boule's staking read path mints a seated-weight change the EL
//!   mirrors via `recordWeight`.
//! - `read <NODE_ID_HEX> <V_EFF>` — read the Registry (0x…0b12) back:
//!   `weightOf`, `totalWeight`, `historyLength`, `keyAt(_, v_eff)` (its byte
//!   length), and `settledView`, printed as `KEY=VALUE` lines for the shell.
//! - `block-number` — current EL head height.
//!
//! Replaces the `cast send` / `cast call` the demo scripts assume.

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use anyhow::{Context, Result, bail};
use boule_reth::HttpTransport;
use boule_reth::registry::{
    HISTORY_LENGTH_SELECTOR, KEY_AT_SELECTOR, REGISTRY_ADDRESS, SETTLED_VIEW_SELECTOR,
    TOTAL_WEIGHT_SELECTOR, WEIGHT_OF_SELECTOR,
};
use serde_json::json;

const STAKING_ADDRESS: &str = "0x0000000000000000000000000000000000000b0e";
const DEPOSIT_SELECTOR: [u8; 4] = [0xb2, 0x14, 0xfa, 0xa5]; // deposit(bytes32)
/// anvil dev account #0 (prefunded in the dev genesis).
const DEV_PK: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

fn transport() -> HttpTransport {
    // No JWT needed for the public eth RPC; pass an empty secret.
    HttpTransport::new(
        "http://127.0.0.1:8551".into(),
        "http://127.0.0.1:8545".into(),
        Vec::new(),
        None,
    )
}

fn parse_hex32(s: &str) -> Result<[u8; 32]> {
    let b = hex::decode(s.trim_start_matches("0x")).context("hex32")?;
    anyhow::ensure!(b.len() == 32, "expected 32 bytes, got {}", b.len());
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    Ok(out)
}

fn left_pad32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    out
}

async fn eth_call(t: &HttpTransport, to: &str, calldata: Vec<u8>) -> Result<Vec<u8>> {
    let data = format!("0x{}", hex::encode(calldata));
    let res = t
        .eth("eth_call", json!([{ "to": to, "data": data }, "latest"]))
        .await?;
    let h = res.as_str().context("eth_call result hex")?;
    hex::decode(h.trim_start_matches("0x")).context("eth_call result not hex")
}

async fn u64_word(t: &HttpTransport, sel: [u8; 4], arg: Option<[u8; 32]>) -> Result<u64> {
    let mut cd = sel.to_vec();
    if let Some(a) = arg {
        cd.extend_from_slice(&a);
    }
    let out = eth_call(t, REGISTRY_ADDRESS, cd).await?;
    if out.len() < 32 {
        return Ok(0);
    }
    Ok(u64::from_be_bytes(out[24..32].try_into().unwrap()))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let t = transport();
    match args.first().map(String::as_str) {
        Some("block-number") => {
            let res = t.eth("eth_blockNumber", json!([])).await?;
            let h = res.as_str().unwrap_or("0x0");
            println!(
                "{}",
                u64::from_str_radix(h.trim_start_matches("0x"), 16).unwrap_or(0)
            );
        }
        Some("deposit") => {
            let node = parse_hex32(&args[1])?;
            let amount: u128 = args[2].parse().context("AMOUNT_WEI")?;
            // calldata: deposit(bytes32) selector ‖ node id word
            let mut cd = DEPOSIT_SELECTOR.to_vec();
            cd.extend_from_slice(&node);

            let signer: PrivateKeySigner = DEV_PK.parse().context("dev pk")?;
            // chain id from the EL.
            let cid_hex = t.eth("eth_chainId", json!([])).await?;
            let chain_id = u64::from_str_radix(
                cid_hex.as_str().unwrap_or("0x0").trim_start_matches("0x"),
                16,
            )
            .unwrap_or(0);
            // pending nonce of the dev account.
            let from = format!("0x{}", hex::encode(signer.address()));
            let nonce_hex = t
                .eth("eth_getTransactionCount", json!([from, "pending"]))
                .await?;
            let nonce = u64::from_str_radix(
                nonce_hex.as_str().unwrap_or("0x0").trim_start_matches("0x"),
                16,
            )
            .unwrap_or(0);

            let to: Address = STAKING_ADDRESS.parse().unwrap();
            let tx = TxEip1559 {
                chain_id,
                nonce,
                gas_limit: 200_000,
                max_fee_per_gas: 2_000_000_000,
                max_priority_fee_per_gas: 1_000_000_000,
                to: TxKind::Call(to),
                value: U256::from(amount),
                access_list: Default::default(),
                input: Bytes::from(cd),
            };
            let sig = signer
                .sign_hash_sync(&tx.signature_hash())
                .context("sign deposit tx")?;
            let env: TxEnvelope = tx.into_signed(sig).into();
            let raw = format!("0x{}", hex::encode(env.encoded_2718()));
            let res = t.eth("eth_sendRawTransaction", json!([raw])).await?;
            match res.as_str() {
                Some(h) => println!("{h}"),
                None => bail!("eth_sendRawTransaction returned no hash: {res}"),
            }
        }
        Some("read") => {
            let node = parse_hex32(&args[1])?;
            let v_eff: u64 = args[2].parse().context("V_EFF")?;
            let weight = u64_word(&t, WEIGHT_OF_SELECTOR, Some(node)).await?;
            let total = u64_word(&t, TOTAL_WEIGHT_SELECTOR, None).await?;
            let hist = u64_word(&t, HISTORY_LENGTH_SELECTOR, Some(node)).await?;
            let settled = u64_word(&t, SETTLED_VIEW_SELECTOR, None).await?;
            // keyAt(node, v_eff) -> dynamic bytes; read its length.
            let mut kcd = KEY_AT_SELECTOR.to_vec();
            kcd.extend_from_slice(&node);
            kcd.extend_from_slice(&left_pad32(&v_eff.to_be_bytes()));
            let k = eth_call(&t, REGISTRY_ADDRESS, kcd).await?;
            // ABI: head[0] = offset(0x20); at offset: len word, then bytes.
            let key_len = if k.len() >= 64 {
                u64::from_be_bytes(k[32 + 24..64].try_into().unwrap())
            } else {
                0
            };
            println!("weightOf={weight}");
            println!("totalWeight={total}");
            println!("historyLength={hist}");
            println!("settledView={settled}");
            println!("keyAtLen={key_len}");
        }
        other => bail!(
            "usage: el-e2e-ops (block-number | deposit <id> <wei> | read <id> <v_eff>); got {other:?}"
        ),
    }
    Ok(())
}
