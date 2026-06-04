//! RPC helper for the single-node `boule↔custom-EL` e2e (`single-node-el-e2e.sh`,
//! #785/#777) on a box without foundry's `cast`. Subcommands over plain HTTP
//! JSON-RPC against the EL's public `eth_*` endpoint (:8545):
//!
//! - `deposit <NODE_ID_HEX> <AMOUNT_WEI>` — sign + submit an EIP-1559
//!   `Staking.deposit(bytes32)` tx (value = amount) from the prefunded anvil dev
//!   account, so boule's staking read path mints a seated-weight change the EL
//!   mirrors via `recordWeight`.
//! - `read <NODE_ID_HEX> <V_EFF>` — read the Registry (0x…0b12) back:
//!   `weightOf`, `totalWeight`, `historyLength`, `keyAt(_, v_eff)` (its byte
//!   length), and `settledView`, printed as `KEY=VALUE` lines for the shell.
//! - `block-number` — current EL head height.
//! - `submit-equivocation <VALIDATOR> <CHAINID> <VIEW> <BLOCKA> <SIGA> <BLOCKB>
//!   <SIGB>` — submit a forged equivocation proof (from `gen-equivocation`) to
//!   the `Slashing` predeploy (0x…0b13); prints whether the tx emitted a
//!   `Slashed` log (`SLASHED=1`/`0`) and the gas/status, exercising the slashing
//!   verify-against-EL-key path end to end.
//! - `gov-digest <PROPOSAL_ID> <VALIDATOR>` — `Governance.approveDigest`, the
//!   32-byte message a validator must BLS-sign to approve (for `bls-sign --msg`).
//! - `gov-approve <PROPOSAL_ID> <COMMAND_HEX> <VALIDATOR> <BLS_SIG_HEX>` — submit
//!   a BLS-signed `Governance.approve`; prints `APPROVED=1`/`0` (whether this tx
//!   crossed the ⅔ supermajority and emitted `Approved`) and the running tally.
//! - `gov-state <PROPOSAL_ID>` — `Governance.approvals`/`isApproved` for a
//!   proposal, as `KEY=VALUE` lines.
//!
//! Replaces the `cast send` / `cast call` the demo scripts assume.

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, FixedBytes, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{SolCall, sol};
use anyhow::{Context, Result, bail};
use boule_reth::HttpTransport;
use boule_reth::governance::{APPROVED_TOPIC, GOVERNANCE_ADDRESS};
use boule_reth::registry::{
    HISTORY_LENGTH_SELECTOR, KEY_AT_SELECTOR, REGISTRY_ADDRESS, SETTLED_VIEW_SELECTOR,
    TOTAL_WEIGHT_SELECTOR, WEIGHT_OF_SELECTOR,
};
use boule_reth::slashing::{SLASHED_TOPIC, SLASHING_ADDRESS};
use serde_json::json;

const STAKING_ADDRESS: &str = "0x0000000000000000000000000000000000000b0e";
const DEPOSIT_SELECTOR: [u8; 4] = [0xb2, 0x14, 0xfa, 0xa5]; // deposit(bytes32)
/// anvil dev account #0 (prefunded in the dev genesis).
const DEV_PK: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

// ABI shapes for the predeploy calls the helper ABI-encodes (matching the
// Solidity selectors pinned in slashing.rs / governance.rs).
sol! {
    function submitEquivocation(
        bytes32 validator,
        bytes chainId,
        uint64 view_,
        bytes32 blockA,
        bytes sigA,
        bytes32 blockB,
        bytes sigB
    ) external;
    function approve(bytes32 proposalId, bytes reconfigCommand, bytes32 validator, bytes blsSig) external;
    function approveDigest(bytes32 proposalId, bytes32 validator) external view returns (bytes32);
    function approvals(bytes32 proposalId) external view returns (uint64);
    function isApproved(bytes32 proposalId) external view returns (bool);
}

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

fn parse_hex(s: &str) -> Result<Vec<u8>> {
    hex::decode(s.trim_start_matches("0x")).context("hex")
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

/// Sign + submit an EIP-1559 call to `to` with `calldata`/`value` from the dev
/// account, returning the tx hash.
async fn send_tx(t: &HttpTransport, to: &str, calldata: Vec<u8>, value: u128) -> Result<String> {
    let signer: PrivateKeySigner = DEV_PK.parse().context("dev pk")?;
    let cid_hex = t.eth("eth_chainId", json!([])).await?;
    let chain_id = u64::from_str_radix(
        cid_hex.as_str().unwrap_or("0x0").trim_start_matches("0x"),
        16,
    )
    .unwrap_or(0);
    let from = format!("0x{}", hex::encode(signer.address()));
    let nonce_hex = t
        .eth("eth_getTransactionCount", json!([from, "pending"]))
        .await?;
    let nonce = u64::from_str_radix(
        nonce_hex.as_str().unwrap_or("0x0").trim_start_matches("0x"),
        16,
    )
    .unwrap_or(0);
    let to: Address = to.parse().context("to address")?;
    let tx = TxEip1559 {
        chain_id,
        nonce,
        gas_limit: 1_500_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        to: TxKind::Call(to),
        value: U256::from(value),
        access_list: Default::default(),
        input: Bytes::from(calldata),
    };
    let sig = signer
        .sign_hash_sync(&tx.signature_hash())
        .context("sign tx")?;
    let env: TxEnvelope = tx.into_signed(sig).into();
    let raw = format!("0x{}", hex::encode(env.encoded_2718()));
    let res = t.eth("eth_sendRawTransaction", json!([raw])).await?;
    match res.as_str() {
        Some(h) => Ok(h.to_string()),
        None => bail!("eth_sendRawTransaction returned no hash: {res}"),
    }
}

/// Poll for the receipt of `tx_hash` (the dev EL mines via real consensus, so it
/// may take a few blocks); returns `(status_ok, topic0s)` once mined.
async fn await_receipt(t: &HttpTransport, tx_hash: &str) -> Result<(bool, Vec<(String, String)>)> {
    for _ in 0..60 {
        let r = t.eth("eth_getTransactionReceipt", json!([tx_hash])).await?;
        if r.is_null() {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            continue;
        }
        let status_ok = r["status"].as_str() == Some("0x1");
        let mut logs = Vec::new();
        if let Some(arr) = r["logs"].as_array() {
            for log in arr {
                let addr = log["address"].as_str().unwrap_or_default().to_string();
                let topic0 = log["topics"][0].as_str().unwrap_or_default().to_string();
                logs.push((addr, topic0));
            }
        }
        return Ok((status_ok, logs));
    }
    bail!("receipt for {tx_hash} never appeared")
}

fn eq_ci(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let t = transport();
    match args.first().map(String::as_str) {
        // keccak256 <HEX> — boule's proposalId binding is keccak256(command).
        Some("keccak256") => {
            use sha3::{Digest, Keccak256};
            let bytes = parse_hex(&args[1])?;
            let h = Keccak256::digest(&bytes);
            println!("0x{}", hex::encode(h));
        }
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
            let mut cd = DEPOSIT_SELECTOR.to_vec();
            cd.extend_from_slice(&node);
            let h = send_tx(&t, STAKING_ADDRESS, cd, amount).await?;
            println!("{h}");
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
        // submit-equivocation <VALIDATOR> <CHAINID> <VIEW> <BLOCKA> <SIGA> <BLOCKB> <SIGB>
        Some("submit-equivocation") => {
            let cd = submitEquivocationCall {
                validator: FixedBytes(parse_hex32(&args[1])?),
                chainId: parse_hex(&args[2])?.into(),
                view_: args[3].parse().context("VIEW")?,
                blockA: FixedBytes(parse_hex32(&args[4])?),
                sigA: parse_hex(&args[5])?.into(),
                blockB: FixedBytes(parse_hex32(&args[6])?),
                sigB: parse_hex(&args[7])?.into(),
            }
            .abi_encode();
            let h = send_tx(&t, SLASHING_ADDRESS, cd, 0).await?;
            let (ok, logs) = await_receipt(&t, &h).await?;
            let slashed = logs.iter().any(|(addr, topic0)| {
                eq_ci(addr, SLASHING_ADDRESS) && eq_ci(topic0, SLASHED_TOPIC)
            });
            println!("TXH={h}");
            println!("STATUS={}", if ok { 1 } else { 0 });
            println!("SLASHED={}", if slashed { 1 } else { 0 });
        }
        // gov-digest <PROPOSAL_ID> <VALIDATOR>
        Some("gov-digest") => {
            let cd = approveDigestCall {
                proposalId: FixedBytes(parse_hex32(&args[1])?),
                validator: FixedBytes(parse_hex32(&args[2])?),
            }
            .abi_encode();
            let out = eth_call(&t, GOVERNANCE_ADDRESS, cd).await?;
            anyhow::ensure!(
                out.len() == 32,
                "approveDigest returned {} bytes",
                out.len()
            );
            println!("0x{}", hex::encode(out));
        }
        // gov-approve <PROPOSAL_ID> <COMMAND_HEX> <VALIDATOR> <BLS_SIG_HEX>
        Some("gov-approve") => {
            let proposal = parse_hex32(&args[1])?;
            let cd = approveCall {
                proposalId: FixedBytes(proposal),
                reconfigCommand: parse_hex(&args[2])?.into(),
                validator: FixedBytes(parse_hex32(&args[3])?),
                blsSig: parse_hex(&args[4])?.into(),
            }
            .abi_encode();
            let h = send_tx(&t, GOVERNANCE_ADDRESS, cd, 0).await?;
            let (ok, logs) = await_receipt(&t, &h).await?;
            let approved = logs
                .iter()
                .any(|(addr, t0)| eq_ci(addr, GOVERNANCE_ADDRESS) && eq_ci(t0, APPROVED_TOPIC));
            // read the running tally back
            let tally = {
                let c = approvalsCall {
                    proposalId: FixedBytes(proposal),
                }
                .abi_encode();
                let out = eth_call(&t, GOVERNANCE_ADDRESS, c).await?;
                if out.len() >= 32 {
                    u64::from_be_bytes(out[24..32].try_into().unwrap())
                } else {
                    0
                }
            };
            println!("TXH={h}");
            println!("STATUS={}", if ok { 1 } else { 0 });
            println!("APPROVED={}", if approved { 1 } else { 0 });
            println!("approvals={tally}");
        }
        // gov-state <PROPOSAL_ID>
        Some("gov-state") => {
            let proposal = parse_hex32(&args[1])?;
            let c = approvalsCall {
                proposalId: FixedBytes(proposal),
            }
            .abi_encode();
            let out = eth_call(&t, GOVERNANCE_ADDRESS, c).await?;
            let tally = if out.len() >= 32 {
                u64::from_be_bytes(out[24..32].try_into().unwrap())
            } else {
                0
            };
            let ic = isApprovedCall {
                proposalId: FixedBytes(proposal),
            }
            .abi_encode();
            let out = eth_call(&t, GOVERNANCE_ADDRESS, ic).await?;
            let is_approved = out.last().copied().unwrap_or(0) == 1;
            println!("approvals={tally}");
            println!("isApproved={}", if is_approved { 1 } else { 0 });
        }
        other => bail!(
            "usage: el-e2e-ops (block-number | keccak256 <hex> | deposit <id> <wei> | read <id> <v_eff> | \
             submit-equivocation <validator> <chainId> <view> <blockA> <sigA> <blockB> <sigB> | \
             gov-digest <proposalId> <validator> | \
             gov-approve <proposalId> <command> <validator> <blsSig> | \
             gov-state <proposalId>); got {other:?}"
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use boule_reth::governance::{APPROVE_DIGEST_SELECTOR, APPROVE_SELECTOR};
    use boule_reth::slashing::SUBMIT_EQUIVOCATION_SELECTOR;

    /// The `sol!` ABI shapes this helper encodes must produce the exact 4-byte
    /// selectors pinned (and genesis-bytecode-checked) in the library, so the
    /// helper calls the predeploy functions it intends to.
    #[test]
    fn sol_selectors_match_pinned_constants() {
        assert_eq!(
            submitEquivocationCall::SELECTOR,
            SUBMIT_EQUIVOCATION_SELECTOR
        );
        assert_eq!(approveCall::SELECTOR, APPROVE_SELECTOR);
        assert_eq!(approveDigestCall::SELECTOR, APPROVE_DIGEST_SELECTOR);
    }
}
