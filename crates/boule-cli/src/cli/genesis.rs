use std::path::PathBuf;

use clap::{Args, Subcommand};

use boule_core::identity::{base58_to_node_id, node_id_to_base58};

#[derive(Subcommand)]
pub enum GenesisCmd {
    Dev(DevArgs),

    BlsPop(BlsPopArgs),
}

#[derive(Args)]
pub struct DevArgs {
    #[arg(long, default_value_t = 4)]
    validators: usize,

    #[arg(short = 'o', long = "out")]
    out: Option<PathBuf>,
}

#[derive(Args)]
pub struct BlsPopArgs {
    #[arg(long)]
    genesis_seed: String,

    #[arg(long = "validator", value_name = "NODE_ID:KEY_PATH", required = true)]
    validators: Vec<String>,

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
