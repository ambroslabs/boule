//! Mint (or load) a single validator's BLS key and emit its chain-bound
//! `[[consensus.validators_bls]]` genesis row (#410 PoP) for a BLS chain whose
//! genesis seed is a reth EL state root.
//!
//! The testnet driver mints BLS PoPs against the all-zeros genesis seed; a
//! reth-backed chain instead seeds `genesis_seed_hex` with reth's genesis EVM
//! state root, so the chain_id (and thus the PoP pre-image) differs. This tiny
//! helper reproduces the driver's mint/derive/sign sequence with the supplied
//! seed, so the single-node `boule↔custom-EL` e2e can stand up a real BLS chain
//! (the only scheme that exercises the EL-applied `recordKey` write).
//!
//! Usage:
//! ```text
//! gen-bls-genesis <NODE_ID_BASE58> <BLS_KEY_PATH> <GENESIS_SEED_HEX>
//! ```
//! Prints the `bls_pubkey` and `bls_pop` hex (one `KEY=VALUE` line each) on
//! stdout for the caller to splice into the node config.

use boule_consensus::genesis::derive_chain_id_from_parts;
use boule_core::crypto::bls_key::{BlsKeyFile, BlsKeyProvider};
use boule_core::crypto::sig_scheme::{BlsAggregated, SignatureSchemeChoice};
use boule_core::identity::base58_to_node_id;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let node_id_b58 = args.next().expect("arg1: NODE_ID_BASE58");
    let bls_key_path = args.next().expect("arg2: BLS_KEY_PATH");
    let seed_hex = args.next().expect("arg3: GENESIS_SEED_HEX (64 hex chars)");

    let node_id = base58_to_node_id(&node_id_b58)?;
    let mut seed = [0u8; 32];
    let seed_bytes = hex::decode(seed_hex.trim_start_matches("0x"))?;
    anyhow::ensure!(seed_bytes.len() == 32, "GENESIS_SEED_HEX must be 32 bytes");
    seed.copy_from_slice(&seed_bytes);

    // Mint (or reload) the validator's BLS key. Dev e2e: tolerate group/world
    // perms on the freshly created file.
    let identity = BlsKeyFile::new(bls_key_path.into())
        .with_allow_insecure_perms(true)
        .load_or_init()?;

    // chain_id from the exact genesis parts the node will commit to: this sole
    // validator, the BLS scheme, its BLS pubkey, no operator keys, the reth seed.
    let chain_id = derive_chain_id_from_parts(
        &[node_id],
        SignatureSchemeChoice::BlsAggregated,
        &[(node_id, identity.public)],
        &[],
        seed,
    );
    let pop = BlsAggregated::sign_pop(&identity.secret, &chain_id)
        .map_err(|e| anyhow::anyhow!("signing chain-bound BLS PoP: {e:?}"))?;

    println!("bls_pubkey={}", hex::encode(identity.public));
    println!("bls_pop={}", hex::encode(pop.sig));
    Ok(())
}
