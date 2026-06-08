//! Mint (or load) the validator BLS keys and emit their chain-bound
//! `[[consensus.validators_bls]]` genesis rows (#410 PoP) for a BLS chain whose
//! genesis seed is a reth EL state root.
//!
//! The testnet driver mints BLS PoPs against the all-zeros genesis seed; a
//! reth-backed chain instead seeds `genesis_seed_hex` with reth's genesis EVM
//! state root, so the chain_id (and thus the PoP pre-image) differs. This helper
//! reproduces the driver's mint/derive/sign sequence with the supplied seed, so
//! the `boule↔custom-EL` e2es can stand up a real BLS chain (the only scheme
//! that exercises the EL-applied `recordKey` write).
//!
//! Two modes:
//!
//! - **Single validator (legacy):**
//!   `gen-bls-genesis <NODE_ID_BASE58> <BLS_KEY_PATH> <GENESIS_SEED_HEX>`
//!   prints `bls_pubkey=…` / `bls_pop=…` (one `KEY=VALUE` line each).
//!
//! - **Multi validator:**
//!   `gen-bls-genesis --multi <GENESIS_SEED_HEX> <NODE_ID_BASE58>:<KEY_PATH> …`
//!   derives the **joint** chain_id over the WHOLE validator set (the same way
//!   `[consensus.validators]` parsing does — set-order independent) and signs
//!   each validator's PoP against it, so a 2-of-N BLS quorum's PoPs all verify on
//!   every node. Prints, per validator `i` (in input order): `node_id_<i>=…`,
//!   `bls_pubkey_<i>=…`, `bls_pop_<i>=…`. Needed for the multi-node convergence
//!   e2e (#785 part b), which the single-validator chain_id cannot serve.

use boule_consensus::genesis::derive_chain_id_from_parts;
use boule_core::crypto::bls_key::{BlsKeyFile, BlsKeyProvider};
use boule_core::crypto::sig_scheme::BlsAggregated;
use boule_core::identity::base58_to_node_id;

fn parse_seed(seed_hex: &str) -> anyhow::Result<[u8; 32]> {
    let mut seed = [0u8; 32];
    let seed_bytes = hex::decode(seed_hex.trim_start_matches("0x"))?;
    anyhow::ensure!(seed_bytes.len() == 32, "GENESIS_SEED_HEX must be 32 bytes");
    seed.copy_from_slice(&seed_bytes);
    Ok(seed)
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.first().map(String::as_str) == Some("--multi") {
        // --multi <SEED_HEX> <node_b58>:<key_path> ...
        anyhow::ensure!(
            args.len() >= 3,
            "usage: gen-bls-genesis --multi <SEED_HEX> <node_b58>:<key_path> ..."
        );
        let seed = parse_seed(&args[1])?;

        // Load every validator's id + BLS key first (input order preserved).
        let mut ids = Vec::new();
        let mut secrets = Vec::new();
        let mut bls = Vec::new();
        for spec in &args[2..] {
            let (b58, path) = spec
                .split_once(':')
                .ok_or_else(|| anyhow::anyhow!("expected <node_b58>:<key_path>, got {spec:?}"))?;
            let node_id = base58_to_node_id(b58)?;
            let identity = BlsKeyFile::new(path.into())
                .with_allow_insecure_perms(true)
                .load_or_init()?;
            ids.push(node_id);
            bls.push((node_id, identity.public));
            secrets.push((node_id, identity.secret));
        }

        // Joint chain_id over the WHOLE validator set (set-order independent).
        let chain_id = derive_chain_id_from_parts(&ids, &bls, &[], seed);

        for (i, (node_id, secret)) in secrets.iter().enumerate() {
            let pop = BlsAggregated::sign_pop(secret, &chain_id)
                .map_err(|e| anyhow::anyhow!("signing chain-bound BLS PoP: {e:?}"))?;
            let pubkey = bls[i].1;
            println!(
                "node_id_{i}={}",
                boule_core::identity::node_id_to_base58(node_id)
            );
            println!("bls_pubkey_{i}={}", hex::encode(pubkey));
            println!("bls_pop_{i}={}", hex::encode(pop.sig));
        }
        return Ok(());
    }

    // Single-validator (legacy) mode.
    let node_id_b58 = args.first().cloned().expect("arg1: NODE_ID_BASE58");
    let bls_key_path = args.get(1).cloned().expect("arg2: BLS_KEY_PATH");
    let seed_hex = args
        .get(2)
        .cloned()
        .expect("arg3: GENESIS_SEED_HEX (64 hex chars)");

    let node_id = base58_to_node_id(&node_id_b58)?;
    let seed = parse_seed(&seed_hex)?;

    // Mint (or reload) the validator's BLS key. Dev e2e: tolerate group/world
    // perms on the freshly created file.
    let identity = BlsKeyFile::new(bls_key_path.into())
        .with_allow_insecure_perms(true)
        .load_or_init()?;

    // chain_id from the exact genesis parts the node will commit to: this sole
    // validator, its BLS pubkey, no operator keys, the reth seed.
    let chain_id = derive_chain_id_from_parts(&[node_id], &[(node_id, identity.public)], &[], seed);
    let pop = BlsAggregated::sign_pop(&identity.secret, &chain_id)
        .map_err(|e| anyhow::anyhow!("signing chain-bound BLS PoP: {e:?}"))?;

    println!("bls_pubkey={}", hex::encode(identity.public));
    println!("bls_pop={}", hex::encode(pop.sig));
    Ok(())
}
