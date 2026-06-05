//! Build a **deployment** reth `genesis.json` for a public testnet: seed the
//! `Registry` predeploy with the deployment's *minted* validator set (keys +
//! weights + `totalWeight` — the weighted-quorum surface from block zero), set
//! a public EVM `chainId`, and prefund an operator-chosen list of EOAs.
//!
//! Unlike [`gen-genesis`](gen-genesis) (which seeds the deterministic dev
//! validator set for harnesses), this binary takes the *real* validators the
//! deployment minted — so it composes with `boule init` (node keys) and
//! `gen-bls-genesis --multi` (chain-bound BLS keys + PoPs). The testnet
//! generator (`gen-testnet.sh`) wires the three together.
//!
//! Usage:
//! ```text
//! gen-testnet-genesis \
//!     --chain-id <U64> \
//!     --out <PATH> \
//!     [--prefund <0xADDR>:<WEI> ...] \
//!     --validator <NODE_ID_B58>:<BLS_PUBKEY_HEX>:<WEIGHT> ...
//! ```
//!
//! - `--validator` repeats once per validator. `BLS_PUBKEY_HEX` is the
//!   compressed-G1 BLS pubkey `gen-bls-genesis` prints (`bls_pubkey_<i>=…`).
//!   `WEIGHT` is the validator's genesis stake (a positive integer) — the
//!   Registry **must** seed non-zero weights or weighted quorum is inert.
//! - `--prefund` repeats; `WEI` is decimal wei. A faucet account (#806) is just
//!   another `--prefund` entry — this binary has no coupling to the faucet.
//! - `--out` is the genesis path (default: stdout).
//!
//! The seeded storage is byte-identical to what a live reth answers for
//! `weightOf` / `totalWeight` (pinned by the `genesis_seed_storage` tests in
//! `registry.rs` against `eth_getStorageAt`).

use boule_core::crypto::sig_scheme::BlsPublicKey;
use boule_core::identity::base58_to_node_id;
use boule_reth::{GenesisValidator, PrefundAlloc, build_deployment_genesis};

fn parse_validator(spec: &str) -> anyhow::Result<GenesisValidator> {
    // NODE_ID_B58:BLS_PUBKEY_HEX:WEIGHT — split from the right twice so a
    // base58 id (no colons) stays intact.
    let parts: Vec<&str> = spec.splitn(3, ':').collect();
    anyhow::ensure!(
        parts.len() == 3,
        "--validator expects <NODE_ID_B58>:<BLS_PUBKEY_HEX>:<WEIGHT>, got {spec:?}"
    );
    let node_id = base58_to_node_id(parts[0])?;
    let pk_bytes = hex::decode(parts[1].trim_start_matches("0x"))
        .map_err(|e| anyhow::anyhow!("validator {:?}: bad BLS pubkey hex: {e}", parts[0]))?;
    let pubkey: BlsPublicKey = pk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("validator {:?}: BLS pubkey must be 48 bytes", parts[0]))?;
    let weight: u64 = parts[2]
        .parse()
        .map_err(|e| anyhow::anyhow!("validator {:?}: bad weight: {e}", parts[0]))?;
    anyhow::ensure!(
        weight > 0,
        "validator {:?}: weight must be > 0 (a zero-weight validator can't reach quorum)",
        parts[0]
    );
    Ok((node_id, pubkey, weight))
}

fn parse_prefund(spec: &str) -> anyhow::Result<PrefundAlloc> {
    let (addr, wei) = spec
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("--prefund expects <0xADDR>:<WEI>, got {spec:?}"))?;
    let addr = addr.trim();
    let bytes = hex::decode(addr.trim_start_matches("0x"))
        .map_err(|e| anyhow::anyhow!("prefund {addr:?}: bad address hex: {e}"))?;
    anyhow::ensure!(
        bytes.len() == 20,
        "prefund {addr:?}: address must be 20 bytes (40 hex chars)"
    );
    let balance: u128 = wei
        .trim()
        .parse()
        .map_err(|e| anyhow::anyhow!("prefund {addr:?}: bad wei amount {wei:?}: {e}"))?;
    Ok((addr.to_string(), balance))
}

fn main() -> anyhow::Result<()> {
    let mut chain_id: Option<u64> = None;
    let mut out: Option<String> = None;
    let mut validators: Vec<GenesisValidator> = Vec::new();
    let mut prefund: Vec<PrefundAlloc> = Vec::new();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--chain-id" => {
                let v = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--chain-id needs a value"))?;
                chain_id = Some(
                    v.parse()
                        .map_err(|e| anyhow::anyhow!("bad --chain-id: {e}"))?,
                );
            }
            "--out" => {
                out = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--out needs a value"))?,
                );
            }
            "--validator" => {
                let spec = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--validator needs a value"))?;
                validators.push(parse_validator(&spec)?);
            }
            "--prefund" => {
                let spec = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--prefund needs a value"))?;
                prefund.push(parse_prefund(&spec)?);
            }
            "-h" | "--help" => {
                eprintln!(
                    "usage: gen-testnet-genesis --chain-id <U64> [--out PATH] \
                     [--prefund <0xADDR>:<WEI> ...] \
                     --validator <NODE_ID_B58>:<BLS_PUBKEY_HEX>:<WEIGHT> ..."
                );
                return Ok(());
            }
            other => anyhow::bail!("unknown argument {other:?} (see --help)"),
        }
    }

    let chain_id = chain_id.ok_or_else(|| anyhow::anyhow!("--chain-id is required"))?;
    anyhow::ensure!(
        !validators.is_empty(),
        "at least one --validator is required (an empty validator set can't reach quorum)"
    );

    let genesis = build_deployment_genesis(chain_id, validators, prefund)
        .map_err(|e| anyhow::anyhow!("building deployment genesis: {e}"))?;
    let json = serde_json::to_string_pretty(&genesis)? + "\n";

    match out {
        Some(path) => std::fs::write(&path, json)
            .map_err(|e| anyhow::anyhow!("writing genesis to {path}: {e}"))?,
        None => {
            use std::io::Write as _;
            std::io::stdout().write_all(json.as_bytes())?;
        }
    }
    Ok(())
}
