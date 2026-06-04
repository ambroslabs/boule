//! Deployment genesis builder: seed the genesis validator set's BLS keys,
//! per-validator weights, and the initial `totalWeight` into the `Registry`
//! predeploy's `alloc` storage.
//!
//! The committed [`genesis.template.json`](../genesis.template.json) (compiled
//! by `build.rs` into the git-ignored `genesis.json`) carries the predeploy
//! **code** but no validator keys/weights — those are *per-deployment*. Without
//! seeding, a fresh chain starts at `totalWeight == 0`, so every weighted-quorum
//! feature (governance tally #729, param auth #746) is inert: `weightOf` is `0`
//! for all validators and any `approve` reverts "not a seated validator".
//!
//! This module wires the genesis so a deployment's `Registry` storage mirrors,
//! at block zero, the same `(NodeId, weight)` set that seeds consensus's
//! [`BondedStakeLedger`] — using [`crate::registry::genesis_seed_storage_json`] under
//! the hood. After seeding, a live reth answers `weightOf(validator) == weight`
//! and `totalWeight() == Σ weight` from genesis with **no** `recordWeight` tx.
//!
//! - [`seed_registry_genesis`] is the general primitive: merge a genesis
//!   validator set into any base genesis `Value` (a per-deployment builder calls
//!   this with the deployment's real validators).
//! - [`build_dev_genesis`] / [`dev_genesis_validators`] are the wired dev/test
//!   path: seed the embedded base genesis with a deterministic dev validator set
//!   so e2e/harnesses get a working weight surface without a manual setup step.
//!
//! [`BondedStakeLedger`]:
//!   boule_consensus::replication::stake_source::BondedStakeLedger

use boule_core::crypto::sig_scheme::{BlsAggregated, BlsKeyError, BlsPublicKey};
use boule_core::identity::NodeId;
use serde_json::Value;

use crate::registry::{REGISTRY_ADDRESS, genesis_seed_storage_json};

/// One genesis validator's seed: its 32-byte on-chain id (boule [`NodeId`]),
/// its compressed BLS G1 pubkey (converted to 128-byte EIP-2537 on seed), and
/// its genesis weight (= its genesis stake in [`BondedStakeLedger`]).
///
/// [`BondedStakeLedger`]:
///   boule_consensus::replication::stake_source::BondedStakeLedger
pub type GenesisValidator = (NodeId, BlsPublicKey, u64);

/// Errors building a seeded genesis.
#[derive(Debug)]
pub enum GenesisSeedError {
    /// A validator's compressed BLS pubkey is not a valid G1 point.
    BlsKey(BlsKeyError),
    /// The base genesis has no `alloc` object, or no `Registry` predeploy entry
    /// at [`REGISTRY_ADDRESS`] — so there is nowhere to seed the weights. The
    /// `Registry` must already be present (with its `code`/`contract`) in the
    /// base genesis; seeding only adds its `storage`.
    NoRegistryAlloc,
    /// The base genesis JSON is structurally wrong (e.g. `alloc` is not an
    /// object, or the `Registry` entry is not an object).
    MalformedGenesis,
}

impl std::fmt::Display for GenesisSeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GenesisSeedError::BlsKey(e) => write!(f, "invalid genesis BLS pubkey: {e:?}"),
            GenesisSeedError::NoRegistryAlloc => write!(
                f,
                "base genesis has no Registry predeploy at {REGISTRY_ADDRESS} to seed weights into"
            ),
            GenesisSeedError::MalformedGenesis => {
                write!(
                    f,
                    "base genesis is malformed (alloc / Registry not an object)"
                )
            }
        }
    }
}

impl std::error::Error for GenesisSeedError {}

impl From<BlsKeyError> for GenesisSeedError {
    fn from(e: BlsKeyError) -> Self {
        GenesisSeedError::BlsKey(e)
    }
}

/// The base genesis the dev/test path seeds into: the build-time–generated
/// `genesis.json` (predeploy code, anvil-prefunded accounts, Prague-at-genesis
/// config) with **no** validator keys/weights. Embedded so the seeded genesis
/// needs no on-disk file.
const BASE_GENESIS_JSON: &str = include_str!("../genesis.json");

/// Merge a genesis validator set's BLS keys + weights + `totalWeight` into
/// `genesis["alloc"][REGISTRY_ADDRESS]["storage"]`, in place — the general
/// genesis-builder primitive.
///
/// `genesis` must already contain the `Registry` predeploy entry (with its
/// `code`/`contract`); this only adds its `storage` words, derived from
/// [`genesis_seed_storage_json`]. Existing `storage` keys (if any) are merged
/// with, not clobbered by, the seed (the seed wins on a slot collision). After
/// this, a live reth booted from `genesis` answers `weightOf`/`totalWeight`
/// for the genesis set from block zero.
pub fn seed_registry_genesis(
    genesis: &mut Value,
    validators: impl IntoIterator<Item = GenesisValidator>,
) -> Result<(), GenesisSeedError> {
    let seed = genesis_seed_storage_json(validators)?;

    let alloc = genesis
        .get_mut("alloc")
        .ok_or(GenesisSeedError::NoRegistryAlloc)?
        .as_object_mut()
        .ok_or(GenesisSeedError::MalformedGenesis)?;

    // reth's genesis loader compares alloc addresses case-insensitively, but the
    // template writes a lowercase key; match it directly first, then fall back to
    // a case-insensitive lookup so a differently-cased base genesis still works.
    let reg_key = if alloc.contains_key(REGISTRY_ADDRESS) {
        REGISTRY_ADDRESS.to_string()
    } else {
        alloc
            .keys()
            .find(|k| k.eq_ignore_ascii_case(REGISTRY_ADDRESS))
            .cloned()
            .ok_or(GenesisSeedError::NoRegistryAlloc)?
    };

    let reg = alloc
        .get_mut(&reg_key)
        .expect("key just resolved from this map")
        .as_object_mut()
        .ok_or(GenesisSeedError::MalformedGenesis)?;

    let storage = reg
        .entry("storage")
        .or_insert_with(|| Value::Object(serde_json::Map::new()))
        .as_object_mut()
        .ok_or(GenesisSeedError::MalformedGenesis)?;

    for (slot, value) in seed {
        storage.insert(slot, value);
    }
    Ok(())
}

/// Build a full genesis `Value` from the embedded base genesis, seeding it with
/// `validators` (their keys + weights + `totalWeight`). The general
/// deployment-builder entry point when you want a fresh seeded genesis rather
/// than mutating one in place.
pub fn build_seeded_genesis(
    validators: impl IntoIterator<Item = GenesisValidator>,
) -> Result<Value, GenesisSeedError> {
    let mut genesis: Value =
        serde_json::from_str(BASE_GENESIS_JSON).expect("embedded genesis.json parses");
    seed_registry_genesis(&mut genesis, validators)?;
    Ok(genesis)
}

/// A deterministic dev/test genesis validator set: `n` validators whose
/// `NodeId` is `[i+1; 32]`, whose BLS pubkey is the deterministic
/// [`BlsAggregated`] key derived from IKM `[i+1, 0, …]`, and whose weight is
/// `i + 1` (so weights differ — `1, 2, …, n` — exercising the weighted path,
/// not a uniform set that a bug could mask).
///
/// Used by [`build_dev_genesis`] so harnesses/e2e get a non-zero
/// `totalWeight` and seated `weightOf` out of the box. Not for production: a
/// real deployment seeds its own minted validator keys (via
/// [`seed_registry_genesis`]).
pub fn dev_genesis_validators(n: usize) -> Vec<GenesisValidator> {
    (0..n)
        .map(|i| {
            let mut node_id = [0u8; 32];
            node_id.fill((i + 1) as u8);
            let mut ikm = [0u8; 32];
            ikm[0] = (i + 1) as u8;
            let (_sk, pk) = BlsAggregated::keygen(&ikm).expect("dev BLS keygen");
            (node_id, pk, (i + 1) as u64)
        })
        .collect()
}

/// Build the wired dev/test genesis: the embedded base genesis seeded with
/// [`dev_genesis_validators(n)`](dev_genesis_validators). The result has a
/// non-zero `totalWeight` and a seated `weightOf` for each of the `n` dev
/// validators at block zero — no `recordWeight` tx needed.
pub fn build_dev_genesis(n: usize) -> Value {
    build_seeded_genesis(dev_genesis_validators(n))
        .expect("dev validators have valid BLS keys and a Registry predeploy")
}

#[cfg(test)]
mod tests {
    use super::*;
    use boule_core::crypto::sig_scheme::bls_pubkey_to_eip2537_g1;
    use sha3::{Digest, Keccak256};

    fn keccak(bytes: &[u8]) -> [u8; 32] {
        let mut h = Keccak256::new();
        h.update(bytes);
        h.finalize().into()
    }

    /// `weight[validator]` slot = `keccak256(validator ‖ uint256(1))`; the value
    /// is the `uint64` weight right-aligned in the 32-byte word. Independent
    /// re-derivation of the slot math (the registry's slot layout is pinned to
    /// live-reth ground truth in `registry.rs`).
    fn weight_slot_hex(validator: &NodeId) -> String {
        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(validator);
        preimage[63] = 1; // WEIGHT_MAPPING_SLOT
        format!("0x{}", hex::encode(keccak(&preimage)))
    }

    /// A seeded genesis carries the Registry's `storage` with the right
    /// `weightOf`/`totalWeight` words for a sample set — pinned to the
    /// independently re-derived weight slot and to `totalWeight` at slot 2.
    #[test]
    fn seeded_genesis_has_weights_and_total_weight() {
        let v1: NodeId = [0x11; 32];
        let v2: NodeId = [0x22; 32];
        let (pk1, pk2) = {
            let g = dev_genesis_validators(2);
            (g[0].1, g[1].1)
        };
        let genesis = build_seeded_genesis([(v1, pk1, 3), (v2, pk2, 5)]).unwrap();

        let storage = genesis["alloc"][REGISTRY_ADDRESS]["storage"]
            .as_object()
            .expect("Registry storage seeded");

        // weightOf(v1) == 3, weightOf(v2) == 5.
        for (v, w) in [(&v1, 3u8), (&v2, 5u8)] {
            let slot = weight_slot_hex(v);
            let got = storage
                .get(&slot)
                .unwrap_or_else(|| panic!("weight slot for {} seeded", hex::encode(v)))
                .as_str()
                .unwrap();
            let mut want = [0u8; 32];
            want[31] = w;
            assert_eq!(got, format!("0x{}", hex::encode(want)), "weightOf word");
        }

        // totalWeight at slot 2 == 3 + 5 == 8.
        let total_slot = "0x0000000000000000000000000000000000000000000000000000000000000002";
        let mut want_total = [0u8; 32];
        want_total[31] = 8;
        assert_eq!(
            storage.get(total_slot).and_then(Value::as_str),
            Some(format!("0x{}", hex::encode(want_total)).as_str()),
            "totalWeight == Σ weight",
        );

        // The 128-byte EIP-2537 key bytes are present (genesis validators are
        // slashable from block zero), proving keys are seeded alongside weights.
        let key128 = bls_pubkey_to_eip2537_g1(&pk1).unwrap();
        let first_chunk = format!("0x{}", hex::encode(&key128[..32]));
        assert!(
            storage
                .values()
                .any(|v| v.as_str() == Some(first_chunk.as_str())),
            "first 32-byte chunk of v1's 128-byte key seeded",
        );
    }

    /// `build_dev_genesis` produces a non-zero `totalWeight` and a seated
    /// `weightOf` for each dev validator — the out-of-the-box working surface
    /// the harnesses rely on (no `recordWeight`). Weights are `1..=n`.
    #[test]
    fn dev_genesis_seeds_nonzero_total_weight() {
        let n = 4;
        let genesis = build_dev_genesis(n);
        let storage = genesis["alloc"][REGISTRY_ADDRESS]["storage"]
            .as_object()
            .expect("Registry storage seeded");

        let total_slot = "0x0000000000000000000000000000000000000000000000000000000000000002";
        // Σ 1..=4 == 10.
        let mut want_total = [0u8; 32];
        want_total[31] = 10;
        assert_eq!(
            storage.get(total_slot).and_then(Value::as_str),
            Some(format!("0x{}", hex::encode(want_total)).as_str()),
        );

        for (i, (node_id, _pk, weight)) in dev_genesis_validators(n).into_iter().enumerate() {
            assert_eq!(weight, (i + 1) as u64);
            let slot = weight_slot_hex(&node_id);
            let mut want = [0u8; 32];
            want[31] = weight as u8;
            assert_eq!(
                storage.get(&slot).and_then(Value::as_str),
                Some(format!("0x{}", hex::encode(want)).as_str()),
                "weightOf(dev validator {i}) == {weight}",
            );
        }
    }

    /// Seeding fails closed if the base genesis has no `Registry` predeploy to
    /// seed into — rather than silently producing an inert chain.
    #[test]
    fn seed_into_genesis_without_registry_errors() {
        let mut genesis = serde_json::json!({ "alloc": {} });
        let v = dev_genesis_validators(1);
        let err = seed_registry_genesis(&mut genesis, v).unwrap_err();
        assert!(matches!(err, GenesisSeedError::NoRegistryAlloc));
    }

    /// Seeding preserves any pre-existing `storage` entries and predeploy
    /// fields (it adds words, never clobbers the rest of the alloc).
    #[test]
    fn seeding_preserves_existing_alloc() {
        let mut genesis = serde_json::json!({
            "alloc": {
                REGISTRY_ADDRESS: {
                    "balance": "0x0",
                    "code": "0xdead",
                    "storage": {
                        "0x00000000000000000000000000000000000000000000000000000000000000ff":
                            "0x00000000000000000000000000000000000000000000000000000000000000aa"
                    }
                }
            }
        });
        seed_registry_genesis(&mut genesis, dev_genesis_validators(1)).unwrap();
        let reg = &genesis["alloc"][REGISTRY_ADDRESS];
        assert_eq!(reg["code"], "0xdead", "code preserved");
        let storage = reg["storage"].as_object().unwrap();
        assert_eq!(
            storage["0x00000000000000000000000000000000000000000000000000000000000000ff"],
            "0x00000000000000000000000000000000000000000000000000000000000000aa",
            "pre-existing storage word preserved",
        );
        // totalWeight (== 1 for one dev validator of weight 1) was added.
        let total_slot = "0x0000000000000000000000000000000000000000000000000000000000000002";
        assert!(storage.contains_key(total_slot), "totalWeight word added");
    }
}
