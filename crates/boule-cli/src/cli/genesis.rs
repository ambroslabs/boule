//! `boule genesis` — generate the reth EL genesis + chain-bound BLS PoPs (#887,
//! folding the former `gen-genesis` / `gen-bls-genesis` bins).
//!
//! Reth-only: built into `boule` under the `reth` feature, because the predeploy
//! genesis needs solc-compiled bytecode at build time (pulled in via the reth
//! backend). The genesis builder and BLS PoP minting themselves are reth-SDK-free
//! library functions in `boule-reth`; this subcommand is the thin CLI over them.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use boule_core::identity::{base58_to_node_id, node_id_to_base58};

#[derive(Subcommand)]
pub enum GenesisCmd {
    /// Emit a reth genesis JSON with the `Registry` predeploy seeded with a
    /// deterministic dev validator set (weights `1..=N`), so a fresh chain has
    /// a working weighted-quorum surface from block zero.
    Dev(DevArgs),
    /// Mint (or load) validator BLS keys and print their chain-bound
    /// `[[consensus.validators_bls]]` genesis rows (#410 PoP) for a chain whose
    /// genesis seed is a reth EL state root.
    BlsPop(BlsPopArgs),
}

#[derive(Args)]
pub struct DevArgs {
    /// Number of dev validators to seed (weights are `1..=N`).
    #[arg(long, default_value_t = 4)]
    validators: usize,
    /// Output path for the genesis JSON (default: stdout).
    #[arg(short = 'o', long = "out")]
    out: Option<PathBuf>,
}

#[derive(Args)]
pub struct BlsPopArgs {
    /// The chain's 32-byte genesis seed as hex (the reth EL genesis state
    /// root); `0x` prefix optional.
    #[arg(long)]
    genesis_seed: String,
    /// One or more validators as `<NODE_ID_BASE58>:<BLS_KEY_PATH>`. The
    /// `chain_id` (PoP pre-image) is derived over the whole set, so a 2-of-N
    /// BLS quorum's PoPs all verify on every node. A single validator is just
    /// the `N == 1` case.
    #[arg(long = "validator", value_name = "NODE_ID:KEY_PATH", required = true)]
    validators: Vec<String>,
    /// Tolerate group/world-readable perms on freshly minted key files (dev/e2e
    /// convenience). Off by default — production keys should be `0600`.
    #[arg(long)]
    allow_insecure_key_perms: bool,
}

pub(crate) fn handle_dev(args: DevArgs) -> anyhow::Result<()> {
    anyhow::ensure!(args.validators >= 1, "--validators must be >= 1");
    let genesis = boule_reth::build_dev_genesis(args.validators);
    let json = serde_json::to_string_pretty(&genesis)? + "\n";
    match args.out {
        Some(path) => std::fs::write(&path, json)
            .map_err(|e| anyhow::anyhow!("writing genesis to {}: {e}", path.display()))?,
        None => {
            use std::io::Write as _;
            std::io::stdout().write_all(json.as_bytes())?;
        }
    }
    Ok(())
}

pub(crate) fn handle_bls_pop(args: BlsPopArgs) -> anyhow::Result<()> {
    let seed = parse_seed(&args.genesis_seed)?;

    let mut validators = Vec::with_capacity(args.validators.len());
    for spec in &args.validators {
        let (b58, path) = spec
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("expected <NODE_ID_BASE58>:<KEY_PATH>, got {spec:?}"))?;
        let node_id = base58_to_node_id(b58)?;
        validators.push((node_id, PathBuf::from(path)));
    }

    let rows = boule_reth::mint_genesis_bls_pops(&validators, seed, args.allow_insecure_key_perms)?;
    for (i, row) in rows.iter().enumerate() {
        println!("node_id_{i}={}", node_id_to_base58(&row.node_id));
        println!("bls_pubkey_{i}={}", hex::encode(row.pubkey));
        println!("bls_pop_{i}={}", hex::encode(&row.pop_sig));
    }
    Ok(())
}

fn parse_seed(seed_hex: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(seed_hex.trim_start_matches("0x"))?;
    anyhow::ensure!(bytes.len() == 32, "--genesis-seed must be 32 bytes of hex");
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}
