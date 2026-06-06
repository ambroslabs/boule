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
/// `disperse(address[])` selector — splits `msg.value` equally to all recipients.
const DISPERSE_SELECTOR: [u8; 4] = [0x23, 0x81, 0x7f, 0xcd];
/// Creation bytecode for `Disperse.sol` (compiled with solc 0.8.24 --optimize).
/// Deployed once by `massfund`, then funds many wallets per tx (no per-account
/// nonce bottleneck — the whole point of the mass-funding contract).
const DISPERSE_BIN: &str = "608060405234801561000f575f80fd5b506102188061001d5f395ff3fe60806040526004361061001d575f3560e01c806323817fcd14610021575b5f80fd5b61003461002f366004610113565b610036565b005b5f6100418234610182565b90505f5b8281101561010d575f848483818110610060576100606101a1565b905060200201602081019061007591906101b5565b6001600160a01b0316836040515f6040518083038185875af1925050503d805f81146100bc576040519150601f19603f3d011682016040523d82523d5f602084013e6100c1565b606091505b50509050806101045760405162461bcd60e51b815260206004820152600b60248201526a1cd95b990819985a5b195960aa1b604482015260640160405180910390fd5b50600101610045565b50505050565b5f8060208385031215610124575f80fd5b823567ffffffffffffffff8082111561013b575f80fd5b818501915085601f83011261014e575f80fd5b81358181111561015c575f80fd5b8660208260051b8501011115610170575f80fd5b60209290920196919550909350505050565b5f8261019c57634e487b7160e01b5f52601260045260245ffd5b500490565b634e487b7160e01b5f52603260045260245ffd5b5f602082840312156101c5575f80fd5b81356001600160a01b03811681146101db575f80fd5b939250505056fea2646970667358221220bcf8b46303b45b5092d4d547a628bd677d3b43b2223709d3f899587568df19f564736f6c63430008180033";

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
    // `ETH_URL` overrides the default so this can drive a remote node.
    let eth = std::env::var("ETH_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".into());
    HttpTransport::new("http://127.0.0.1:8551".into(), eth, Vec::new(), None)
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

async fn fetch_chain_id(t: &HttpTransport) -> Result<u64> {
    let h = t.eth("eth_chainId", json!([])).await?;
    Ok(u64::from_str_radix(h.as_str().unwrap_or("0x0").trim_start_matches("0x"), 16).unwrap_or(0))
}
async fn fetch_nonce(t: &HttpTransport, addr: &str) -> Result<u64> {
    let h = t
        .eth("eth_getTransactionCount", json!([addr, "pending"]))
        .await?;
    Ok(u64::from_str_radix(h.as_str().unwrap_or("0x0").trim_start_matches("0x"), 16).unwrap_or(0))
}
async fn fetch_block(t: &HttpTransport) -> Result<u64> {
    let h = t.eth("eth_blockNumber", json!([])).await?;
    Ok(u64::from_str_radix(h.as_str().unwrap_or("0x0").trim_start_matches("0x"), 16).unwrap_or(0))
}
/// Sign a plain 21k-gas value transfer (no nonce/chain RPC — caller manages them).
fn sign_transfer(
    signer: &PrivateKeySigner,
    nonce: u64,
    to: Address,
    value: U256,
    chain_id: u64,
) -> Result<String> {
    let tx = TxEip1559 {
        chain_id,
        nonce,
        gas_limit: 21_000,
        max_fee_per_gas: 5_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        to: TxKind::Call(to),
        value,
        access_list: Default::default(),
        input: Bytes::new(),
    };
    let sig = signer.sign_hash_sync(&tx.signature_hash())?;
    let env: TxEnvelope = tx.into_signed(sig).into();
    Ok(format!("0x{}", hex::encode(env.encoded_2718())))
}

/// loadtest <num_wallets> <duration_secs> <target_tps(0=unbounded)>
/// Fund N wallets from the dev account, then fire transfers between them and
/// measure submit-rate vs mined-rate (does the chain keep up, or wedge?).
async fn loadtest(t: &HttpTransport, n: usize, dur_secs: u64, target_tps: u64) -> Result<()> {
    let chain_id = fetch_chain_id(t).await?;
    let dev: PrivateKeySigner = DEV_PK.parse().context("dev pk")?;
    let dev_addr = format!("0x{}", hex::encode(dev.address()));
    let wallets: Vec<PrivateKeySigner> = (0..n).map(|_| PrivateKeySigner::random()).collect();
    let addrs: Vec<Address> = wallets.iter().map(|w| w.address()).collect();
    // fund each wallet 1 ETH from the dev account (sequential nonces)
    let mut dev_nonce = fetch_nonce(t, &dev_addr).await?;
    let fund = U256::from(100_000_000_000_000_000u128); // 0.1 ETH
    let mut last = String::new();
    eprintln!("funding {n} wallets (1 ETH each) in batches...");
    for (idx, a) in addrs.iter().enumerate() {
        let raw = sign_transfer(&dev, dev_nonce, *a, fund, chain_id)?;
        if let Ok(r) = t.eth("eth_sendRawTransaction", json!([raw])).await {
            last = r.as_str().unwrap_or("").to_string();
        }
        dev_nonce += 1;
        // reth caps pending txs per sender; drain every 12 so funding from the
        // single dev account doesn't get rejected past the per-account limit.
        if (idx + 1) % 12 == 0 {
            let _ = await_receipt(t, &last).await;
        }
    }
    let _ = await_receipt(t, &last).await;
    let mut funded = 0usize;
    for a in &addrs {
        let b = t
            .eth(
                "eth_getBalance",
                json!([format!("0x{}", hex::encode(a)), "latest"]),
            )
            .await
            .ok();
        if b.and_then(|x| x.as_str().map(|s| s != "0x0"))
            .unwrap_or(false)
        {
            funded += 1;
        }
    }
    eprintln!("funded {funded}/{n} wallets");
    run_load(t, wallets, dur_secs, target_tps).await
}

/// genfund <N> <KEYSFILE> — generate N wallets, fund 1 ETH each from the dev
/// account (batched under reth's per-account limit), and write their private
/// keys (one hex per line) so a separate `loadkeys` run can drive load from them.
async fn genfund(t: &HttpTransport, n: usize, path: &str) -> Result<()> {
    let chain_id = fetch_chain_id(t).await?;
    let dev: PrivateKeySigner = DEV_PK.parse().context("dev pk")?;
    let dev_addr = format!("0x{}", hex::encode(dev.address()));
    let wallets: Vec<PrivateKeySigner> = (0..n).map(|_| PrivateKeySigner::random()).collect();
    let mut dev_nonce = fetch_nonce(t, &dev_addr).await?;
    let fund = U256::from(100_000_000_000_000_000u128); // 0.1 ETH
    let mut last = String::new();
    let mut funded = 0usize;
    // Submit each funding tx, RETRYING THE SAME WALLET on error rather than
    // advancing the nonce — a nonce gap here strands every later tx as
    // future-nonce and leaves wallets silently unfunded (the bug that made the
    // spread test send from empty wallets). On backpressure (account-slots /
    // txpool full) we drain, re-sync the nonce from chain, and retry.
    for (idx, w) in wallets.iter().enumerate() {
        loop {
            let raw = sign_transfer(&dev, dev_nonce, w.address(), fund, chain_id)?;
            match t.eth("eth_sendRawTransaction", json!([raw])).await {
                Ok(r) => {
                    last = r.as_str().unwrap_or("").to_string();
                    dev_nonce += 1;
                    funded += 1;
                    break;
                }
                Err(e) => {
                    let msg = e.to_string().to_lowercase();
                    if msg.contains("nonce too low") || msg.contains("already known") {
                        // it actually landed; the RPC reply just raced — advance.
                        dev_nonce += 1;
                        funded += 1;
                        break;
                    }
                    if msg.contains("insufficient funds") {
                        anyhow::bail!(
                            "genfund: faucet can't fund wallet {idx} (nonce {dev_nonce}): {e}"
                        );
                    }
                    // backpressure (txpool full / account slots): drain in-flight
                    // to free capacity, then retry the SAME nonce — never skip.
                    if !last.is_empty() {
                        let _ = await_receipt(t, &last).await;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
        if (idx + 1) % 64 == 0 {
            let _ = await_receipt(t, &last).await;
        }
    }
    let _ = await_receipt(t, &last).await;
    eprintln!("genfund: confirmed-submit {funded}/{n} funding txs");
    let mut out = String::new();
    for w in &wallets {
        out.push_str(&format!("0x{}\n", hex::encode(w.to_bytes())));
    }
    std::fs::write(path, out)?;
    eprintln!("genfund: {n} wallets funded; keys -> {path}");
    Ok(())
}

/// Sign an arbitrary EIP-1559 tx (Create or Call) with explicit gas — caller
/// manages nonce/chain. Used for the Disperse deploy + batched disperse calls.
fn sign_tx(
    signer: &PrivateKeySigner,
    nonce: u64,
    to: TxKind,
    value: U256,
    input: Vec<u8>,
    gas_limit: u64,
    chain_id: u64,
) -> Result<String> {
    let tx = TxEip1559 {
        chain_id,
        nonce,
        gas_limit,
        max_fee_per_gas: 5_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        to,
        value,
        access_list: Default::default(),
        input: Bytes::from(input),
    };
    let sig = signer.sign_hash_sync(&tx.signature_hash())?;
    let env: TxEnvelope = tx.into_signed(sig).into();
    Ok(format!("0x{}", hex::encode(env.encoded_2718())))
}

/// Poll for the receipt of a contract-creation tx; returns its `contractAddress`.
async fn await_contract_address(t: &HttpTransport, tx_hash: &str) -> Result<String> {
    for _ in 0..60 {
        let r = t.eth("eth_getTransactionReceipt", json!([tx_hash])).await?;
        if r.is_null() {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            continue;
        }
        anyhow::ensure!(r["status"].as_str() == Some("0x1"), "deploy tx reverted");
        let addr = r["contractAddress"]
            .as_str()
            .context("no contractAddress in receipt")?;
        return Ok(addr.to_string());
    }
    bail!("deploy receipt for {tx_hash} never appeared")
}

/// massfund <N> <KEYSFILE> [WEI_EACH] — deploy the Disperse contract once, then
/// fund N fresh wallets WEI_EACH each via batched `disperse(address[])` calls
/// (≤200 recipients per tx). One tx funds a whole batch, so funding is bounded
/// by block throughput, not by the dev account's per-account nonce limit — the
/// fix for the slow/clog-prone genfund faucet loop. Writes the keys at the end.
async fn massfund(t: &HttpTransport, n: usize, path: &str, wei_each: u128) -> Result<()> {
    const BATCH: usize = 200;
    let chain_id = fetch_chain_id(t).await?;
    let dev: PrivateKeySigner = DEV_PK.parse().context("dev pk")?;
    let dev_addr = format!("0x{}", hex::encode(dev.address()));
    let wallets: Vec<PrivateKeySigner> = (0..n).map(|_| PrivateKeySigner::random()).collect();
    let addrs: Vec<Address> = wallets.iter().map(|w| w.address()).collect();
    let mut nonce = fetch_nonce(t, &dev_addr).await?;

    // 1. deploy Disperse once
    let code = hex::decode(DISPERSE_BIN).context("disperse bytecode")?;
    let raw = sign_tx(
        &dev,
        nonce,
        TxKind::Create,
        U256::ZERO,
        code,
        1_000_000,
        chain_id,
    )?;
    let dh = t.eth("eth_sendRawTransaction", json!([raw])).await?;
    let dh = dh.as_str().context("deploy hash")?.to_string();
    nonce += 1;
    let disperse_addr = await_contract_address(t, &dh).await?;
    let disperse: Address = disperse_addr.parse().context("disperse addr")?;
    eprintln!("massfund: Disperse deployed at {disperse_addr}");

    // 2. fund recipients in batches — one disperse() tx per batch
    let mut funded = 0usize;
    for chunk in addrs.chunks(BATCH) {
        // calldata = selector ++ abi.encode(address[]): offset, length, words
        let mut cd = DISPERSE_SELECTOR.to_vec();
        cd.extend_from_slice(&left_pad32(&[0x20]));
        cd.extend_from_slice(&left_pad32(&(chunk.len() as u64).to_be_bytes()));
        for a in chunk {
            cd.extend_from_slice(&left_pad32(a.as_slice()));
        }
        let value = U256::from(wei_each) * U256::from(chunk.len() as u64);
        // ~40k gas/recipient (new-account value transfer) + overhead
        let gas = 60_000 + chunk.len() as u64 * 40_000;
        let raw = sign_tx(
            &dev,
            nonce,
            TxKind::Call(disperse),
            value,
            cd,
            gas,
            chain_id,
        )?;
        let h = loop {
            match t.eth("eth_sendRawTransaction", json!([raw])).await {
                Ok(r) => break r.as_str().unwrap_or("").to_string(),
                Err(e) => {
                    if e.to_string().to_lowercase().contains("insufficient funds") {
                        bail!("massfund: faucet can't fund batch at {funded}: {e}");
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
            }
        };
        nonce += 1;
        let (ok, _) = await_receipt(t, &h).await?;
        anyhow::ensure!(ok, "disperse batch reverted (gas? value?) at {funded}");
        funded += chunk.len();
        eprintln!("massfund: funded {funded}/{n}");
    }

    let mut out = String::new();
    for w in &wallets {
        out.push_str(&format!("0x{}\n", hex::encode(w.to_bytes())));
    }
    std::fs::write(path, out)?;
    eprintln!("massfund: {funded} wallets funded ({wei_each} wei each); keys -> {path}");
    Ok(())
}

/// loadkeys <KEYSFILE> <DUR> <TPS> — drive load from pre-funded wallet keys
/// (so many nodes can run in parallel against one funded wallet pool).
async fn loadkeys(t: &HttpTransport, path: &str, dur_secs: u64, target_tps: u64) -> Result<()> {
    let data = std::fs::read_to_string(path)?;
    let wallets: Vec<PrivateKeySigner> = data
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.trim().parse())
        .collect::<std::result::Result<_, _>>()
        .context("parse wallet keys")?;
    eprintln!("loadkeys: {} wallets from {path}", wallets.len());
    run_load(t, wallets, dur_secs, target_tps).await
}

/// Tx-storm load phase from already-funded `wallets`; prints submit/mined/backlog.
async fn run_load(
    t: &HttpTransport,
    wallets: Vec<PrivateKeySigner>,
    dur_secs: u64,
    target_tps: u64,
) -> Result<()> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    let n = wallets.len();
    let chain_id = fetch_chain_id(t).await?;
    let addrs: Vec<Address> = wallets.iter().map(|w| w.address()).collect();
    let ta = Arc::new(transport());
    let submitted = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));
    let start_h = fetch_block(t).await?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(dur_secs);
    let per_wallet_delay = if target_tps > 0 {
        std::time::Duration::from_secs_f64(n as f64 / target_tps as f64)
    } else {
        std::time::Duration::ZERO
    };
    eprintln!(
        "load: {n} wallets, {dur_secs}s, target_tps={} ...",
        if target_tps == 0 {
            "unbounded".into()
        } else {
            target_tps.to_string()
        }
    );
    let mut handles = vec![];
    for (i, w) in wallets.into_iter().enumerate() {
        let (sub, err, tx, ads, d) = (
            submitted.clone(),
            errors.clone(),
            ta.clone(),
            addrs.clone(),
            per_wallet_delay,
        );
        handles.push(tokio::spawn(async move {
            let addr = format!("0x{}", hex::encode(w.address()));
            let mut nonce = 0u64;
            while tokio::time::Instant::now() < deadline {
                let j = (i + 1 + nonce as usize) % ads.len();
                let to = ads[if j == i { (j + 1) % ads.len() } else { j }];
                if let Ok(raw) = sign_transfer(&w, nonce, to, U256::from(1u64), chain_id) {
                    match tx.eth("eth_sendRawTransaction", json!([raw])).await {
                        Ok(_) => {
                            sub.fetch_add(1, Ordering::Relaxed);
                            nonce += 1;
                        }
                        Err(_) => {
                            // txpool backpressure / nonce drift: re-sync the nonce
                            // from chain and back off so we don't spam-retry a
                            // rejected nonce (which would DoS the RPC).
                            err.fetch_add(1, Ordering::Relaxed);
                            if let Ok(n) = fetch_nonce(&tx, &addr).await {
                                nonce = n;
                            }
                            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        }
                    }
                }
                if !d.is_zero() {
                    tokio::time::sleep(d).await;
                }
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }
    let subs = submitted.load(Ordering::Relaxed);
    let errs = errors.load(Ordering::Relaxed);
    // let the mempool tail drain, then count included via on-chain nonces
    tokio::time::sleep(std::time::Duration::from_secs(8)).await;
    let mut included = 0u64;
    for a in &addrs {
        included += fetch_nonce(t, &format!("0x{}", hex::encode(a)))
            .await
            .unwrap_or(0);
    }
    let end_h = fetch_block(t).await?;
    println!("=== loadtest result ===");
    println!(
        "submitted: {subs} (errors {errs}) in {dur_secs}s = {:.1} tx/s submit-rate",
        subs as f64 / dur_secs as f64
    );
    println!(
        "mined:     {included} txs across {} blocks = {:.1} tx/s mined-rate",
        end_h - start_h,
        included as f64 / dur_secs as f64
    );
    println!(
        "backlog:   {} txs submitted-but-not-yet-mined (mempool drained?)",
        subs.saturating_sub(included)
    );
    Ok(())
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
        // fund <ADDRESS> <AMOUNT_WEI> — plain value transfer (no calldata) from
        // the prefunded dev account to an EOA. Drives a faucet-style top-up.
        Some("fund") => {
            let to = args.get(1).context("usage: fund <ADDRESS> <AMOUNT_WEI>")?;
            let amount: u128 = args
                .get(2)
                .context("AMOUNT_WEI")?
                .parse()
                .context("AMOUNT_WEI")?;
            let h = send_tx(&t, to, Vec::new(), amount).await?;
            println!("{h}");
        }
        // loadtest <NUM_WALLETS> <DURATION_SECS> <TARGET_TPS|0>
        Some("loadtest") => {
            let n: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(10);
            let dur: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(30);
            let tps: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
            loadtest(&t, n, dur, tps).await?;
        }
        // genfund <N> <KEYSFILE> — fund N wallets centrally, write their keys.
        Some("genfund") => {
            let n: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(100);
            let path = args
                .get(2)
                .map(String::as_str)
                .unwrap_or("/tmp/wallets.keys");
            genfund(&t, n, path).await?;
        }
        // massfund <N> <KEYSFILE> [WEI_EACH] — deploy Disperse, fund N wallets
        // in batches (one tx each), write keys. Defaults WEI_EACH = 0.05 ETH.
        Some("massfund") => {
            let n: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(100);
            let path = args
                .get(2)
                .map(String::as_str)
                .unwrap_or("/tmp/wallets.keys");
            let wei: u128 = args
                .get(3)
                .and_then(|s| s.parse().ok())
                .unwrap_or(50_000_000_000_000_000); // 0.05 ETH
            massfund(&t, n, path, wei).await?;
        }
        // loadkeys <KEYSFILE> <DUR> <TPS> — load from pre-funded wallet keys.
        Some("loadkeys") => {
            let path = args
                .get(1)
                .map(String::as_str)
                .unwrap_or("/tmp/wallets.keys");
            let dur: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(30);
            let tps: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
            loadkeys(&t, path, dur, tps).await?;
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
