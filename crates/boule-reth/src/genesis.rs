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

use std::path::PathBuf;

use boule_consensus::genesis::derive_chain_id_from_parts;
use boule_core::crypto::bls_key::{BlsKeyFile, BlsKeyProvider};
use boule_core::crypto::sig_scheme::{BlsAggregated, BlsKeyError, BlsPublicKey};
use boule_core::identity::NodeId;
use serde_json::Value;

use crate::registry::{REGISTRY_ADDRESS, genesis_seed_storage_json};
use crate::staking::{STAKING_ADDRESS, owner_seed_storage_json};

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
    /// A deployment genesis was requested with an **empty** validator set
    /// (#823 item 4). An empty set seeds `totalWeight == 0`, so consensus can
    /// never reach quorum and every weighted-quorum feature is inert — fail
    /// closed at build time rather than emit a dead chain. (The
    /// `gen-testnet-genesis` CLI already guards this; the library fn now does
    /// too, so every caller is protected.)
    EmptyValidatorSet,
    /// The base genesis has no `Staking` predeploy entry at [`STAKING_ADDRESS`]
    /// to seed the [`withdraw`-gating](crate::staking) `owner` into, or the
    /// supplied owner address is malformed (#821). The `Staking` predeploy must
    /// be present (with its `code`/`contract`) in the base genesis; seeding only
    /// adds its `owner` storage word.
    StakingOwner(String),
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
            GenesisSeedError::EmptyValidatorSet => write!(
                f,
                "deployment genesis requires a non-empty validator set \
                 (an empty set seeds totalWeight == 0 and can never reach quorum)"
            ),
            GenesisSeedError::StakingOwner(msg) => {
                write!(f, "seeding Staking owner at {STAKING_ADDRESS}: {msg}")
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

/// Seed the `Staking` predeploy's `withdraw`-gating `owner` (#821) into
/// `genesis["alloc"][STAKING_ADDRESS]["storage"]`, in place. After this, the
/// staking predeploy's `withdraw(nodeId, amount)` reverts for every caller
/// except `owner`, so only the trusted deployment owner can drive a validator
/// unbond/removal — closing the open-internet validator-removal vector (an
/// unauthenticated `Withdraw` boule would read back as a `StakeOp::Unbond`).
///
/// `owner` is a 20-byte EVM address (any case, with or without `0x`). The
/// `Staking` predeploy entry must already be present in `genesis` (with its
/// `code`/`contract`); this only adds its `owner` storage word. Errors if the
/// predeploy is absent or the owner address is malformed.
pub fn seed_staking_owner(genesis: &mut Value, owner: &str) -> Result<(), GenesisSeedError> {
    let (slot, value) = owner_seed_storage_json(owner).map_err(GenesisSeedError::StakingOwner)?;

    let alloc = genesis
        .get_mut("alloc")
        .ok_or_else(|| GenesisSeedError::StakingOwner("base genesis has no alloc".into()))?
        .as_object_mut()
        .ok_or(GenesisSeedError::MalformedGenesis)?;

    // The template writes a lowercase key; match it directly first, then fall
    // back to a case-insensitive lookup (reth compares alloc addresses
    // case-insensitively).
    let staking_key = if alloc.contains_key(STAKING_ADDRESS) {
        STAKING_ADDRESS.to_string()
    } else {
        alloc
            .keys()
            .find(|k| k.eq_ignore_ascii_case(STAKING_ADDRESS))
            .cloned()
            .ok_or_else(|| {
                GenesisSeedError::StakingOwner(format!(
                    "no Staking predeploy at {STAKING_ADDRESS} to seed the owner into"
                ))
            })?
    };

    let staking = alloc
        .get_mut(&staking_key)
        .expect("key just resolved from this map")
        .as_object_mut()
        .ok_or(GenesisSeedError::MalformedGenesis)?;

    let storage = staking
        .entry("storage")
        .or_insert_with(|| Value::Object(serde_json::Map::new()))
        .as_object_mut()
        .ok_or(GenesisSeedError::MalformedGenesis)?;

    storage.insert(slot, Value::from(value));
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

/// One prefunded externally-owned account in genesis: `(20-byte address,
/// balance in wei)`. The deployment builder writes `alloc[address].balance`
/// for each — so a fresh chain has funded EOAs (e.g. a faucet account, a dev
/// signer) from block zero with no funding tx.
///
/// `address` is the 20-byte EVM address (any case); `balance` is the decimal
/// wei amount rendered as the `0x…` hex genesis `alloc` expects.
pub type PrefundAlloc = (String, u128);

/// Build a deployment genesis: the embedded base genesis with (1) the
/// `Registry` predeploy seeded with `validators` (keys + weights + totalWeight,
/// the weighted-quorum surface from block zero); (2) the EVM `config.chainId`
/// set to `chain_id` (the public testnet's EVM chain-id, distinct from the
/// boule consensus chain-id derived from the genesis parts); (3) every
/// `(address, balance)` in `prefund` written to `alloc[address].balance`; and
/// (4) the `Staking` predeploy's `withdraw`-gating `owner` seeded to
/// `staking_owner` (#821), so only that address can drive a validator
/// unbond/removal.
///
/// This is the per-deployment entry point the testnet tooling
/// (`gen-testnet-genesis`) calls: it takes the deployment's *minted* validators
/// (not the dev set) plus an operator-chosen chain-id, prefund list, and
/// staking owner.
///
/// **Fails closed on an empty validator set (#823 item 4):** an empty set seeds
/// `totalWeight == 0`, so consensus can never reach quorum — this returns
/// [`GenesisSeedError::EmptyValidatorSet`] rather than emit a dead chain. (The
/// CLI already guarded this; the library fn now does too.)
///
/// Note on `settledView`: every genesis key entry is `vEff = 0`, so the
/// Registry's `settledView` scalar (slot 3) is already correct at its EVM
/// default of `0` for the genesis set — slashing proofs for `view <=
/// settledView` cover all genesis validators without seeding a redundant zero
/// word. See [`crate::registry::genesis_seed_storage`].
pub fn build_deployment_genesis(
    chain_id: u64,
    validators: impl IntoIterator<Item = GenesisValidator>,
    prefund: impl IntoIterator<Item = PrefundAlloc>,
    staking_owner: &str,
) -> Result<Value, GenesisSeedError> {
    // Fail closed on an empty validator set (#823 item 4): an empty set seeds
    // totalWeight == 0 and can never reach quorum. Collect so we can check
    // before consuming the iterator into the seeder.
    let validators: Vec<GenesisValidator> = validators.into_iter().collect();
    if validators.is_empty() {
        return Err(GenesisSeedError::EmptyValidatorSet);
    }

    let mut genesis = build_seeded_genesis(validators)?;

    // (4) Gate the staking predeploy's `withdraw` behind the deployment owner
    // (#821) — close the open-internet validator-removal vector.
    seed_staking_owner(&mut genesis, staking_owner)?;

    // Override the EVM chain-id.
    genesis
        .get_mut("config")
        .and_then(Value::as_object_mut)
        .ok_or(GenesisSeedError::MalformedGenesis)?
        .insert("chainId".to_string(), Value::from(chain_id));

    // Prefund EOAs (faucet / dev accounts). Merge into any existing alloc
    // entry for the address (preserving e.g. code) rather than clobbering.
    let alloc = genesis
        .get_mut("alloc")
        .ok_or(GenesisSeedError::MalformedGenesis)?
        .as_object_mut()
        .ok_or(GenesisSeedError::MalformedGenesis)?;
    for (address, balance) in prefund {
        let entry = alloc
            .entry(address)
            .or_insert_with(|| Value::Object(serde_json::Map::new()))
            .as_object_mut()
            .ok_or(GenesisSeedError::MalformedGenesis)?;
        entry.insert("balance".to_string(), Value::from(format!("0x{balance:x}")));
    }
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

/// One validator's chain-bound BLS genesis row: its `NodeId`, BLS public key,
/// and the proof-of-possession signed over the chain's `chain_id` (#410 PoP).
/// Feeds a `[[consensus.validators_bls]]` genesis entry.
#[derive(Debug, Clone)]
pub struct BlsPopRow {
    /// The validator's boule [`NodeId`] (32 bytes).
    pub node_id: NodeId,
    /// The validator's BLS public key.
    pub pubkey: BlsPublicKey,
    /// The PoP signature bytes (over the chain's `chain_id`).
    pub pop_sig: Vec<u8>,
}

/// Mint (or load) the BLS keys at `key_paths` and emit each validator's
/// chain-bound PoP for a chain whose genesis seed is `genesis_seed` (#410).
///
/// The `chain_id` (PoP pre-image) is derived over the **whole** validator set
/// — set-order independent, exactly as `[consensus.validators]` parsing does —
/// so a 2-of-N BLS quorum's PoPs all verify on every node. Input order is
/// preserved in the returned rows. A single-validator deployment is just the
/// `n == 1` case.
///
/// Dev/e2e callers tolerate group/world-readable perms on the freshly created
/// key files (`allow_insecure_perms = true`); a production deployment should
/// pass `false`.
///
/// This is the reusable primitive behind the CLI's `boule genesis bls-pop`
/// subcommand; it reproduces the testnet driver's mint/derive/sign sequence
/// against an explicit reth genesis seed.
pub fn mint_genesis_bls_pops(
    validators: &[(NodeId, PathBuf)],
    genesis_seed: [u8; 32],
    allow_insecure_perms: bool,
) -> anyhow::Result<Vec<BlsPopRow>> {
    anyhow::ensure!(!validators.is_empty(), "at least one validator is required");

    // Load every validator's BLS key first (input order preserved).
    let mut ids = Vec::with_capacity(validators.len());
    let mut bls = Vec::with_capacity(validators.len());
    let mut secrets = Vec::with_capacity(validators.len());
    for (node_id, path) in validators {
        let identity = BlsKeyFile::new(path.clone())
            .with_allow_insecure_perms(allow_insecure_perms)
            .load_or_init()?;
        ids.push(*node_id);
        bls.push((*node_id, identity.public));
        secrets.push(identity.secret);
    }

    // Joint chain_id over the WHOLE validator set (set-order independent).
    let chain_id = derive_chain_id_from_parts(&ids, &bls, &[], genesis_seed);

    let mut rows = Vec::with_capacity(validators.len());
    for (i, secret) in secrets.iter().enumerate() {
        let pop = BlsAggregated::sign_pop(secret, &chain_id)
            .map_err(|e| anyhow::anyhow!("signing chain-bound BLS PoP: {e:?}"))?;
        rows.push(BlsPopRow {
            node_id: ids[i],
            pubkey: bls[i].1,
            pop_sig: pop.sig.to_vec(),
        });
    }
    Ok(rows)
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

    /// The deployment builder overrides the EVM chain-id, prefunds the
    /// requested EOAs, and still seeds the weighted-quorum surface — the three
    /// per-deployment knobs the testnet tooling drives.
    #[test]
    fn deployment_genesis_sets_chain_id_and_prefunds() {
        let (pk0, pk1) = {
            let g = dev_genesis_validators(2);
            (g[0].1, g[1].1)
        };
        let v0: NodeId = [0xa0; 32];
        let v1: NodeId = [0xa1; 32];
        let faucet = "0x00000000000000000000000000000000000Facc7";
        let dev_eoa = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"; // already in base
        let genesis = build_deployment_genesis(
            424242,
            [(v0, pk0, 4u64), (v1, pk1, 6u64)],
            [
                (faucet.to_string(), 1_000_000_000_000_000_000_000u128), // 1000 ETH
                (dev_eoa.to_string(), 7u128),
            ],
            "0x00000000000000000000000000000000000Facc7",
        )
        .unwrap();

        // (1) chain-id overridden.
        assert_eq!(genesis["config"]["chainId"], Value::from(424242u64));

        // (2) faucet prefunded with the exact wei (rendered as 0x-hex).
        assert_eq!(
            genesis["alloc"][faucet]["balance"],
            Value::from(format!("0x{:x}", 1_000_000_000_000_000_000_000u128)),
        );
        // An existing alloc entry's balance is overridden in place.
        assert_eq!(genesis["alloc"][dev_eoa]["balance"], Value::from("0x7"));

        // (3) weighted-quorum surface still seeded: totalWeight == 4 + 6 == 10.
        let storage = genesis["alloc"][REGISTRY_ADDRESS]["storage"]
            .as_object()
            .expect("Registry storage seeded");
        let total_slot = "0x0000000000000000000000000000000000000000000000000000000000000002";
        let mut want_total = [0u8; 32];
        want_total[31] = 10;
        assert_eq!(
            storage.get(total_slot).and_then(Value::as_str),
            Some(format!("0x{}", hex::encode(want_total)).as_str()),
        );

        // settledView (slot 3) is NOT seeded — genesis vEff=0 keys make its EVM
        // default of 0 correct, so seeding a zero word would be redundant.
        let settled_slot = "0x0000000000000000000000000000000000000000000000000000000000000003";
        assert!(
            !storage.contains_key(settled_slot),
            "settledView must rely on the EVM zero default for the genesis set",
        );

        // (4) the Staking predeploy's `owner` (slot 0) is seeded to the
        // requested address, right-aligned — so `withdraw` is gated (#821).
        let staking_storage = genesis["alloc"][STAKING_ADDRESS]["storage"]
            .as_object()
            .expect("Staking storage seeded with owner");
        let owner_slot = "0x0000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(
            staking_storage.get(owner_slot).and_then(Value::as_str),
            Some("0x00000000000000000000000000000000000000000000000000000000000facc7"),
            "Staking.owner seeded right-aligned at slot 0",
        );
    }

    /// #823 item 4: the deployment builder fails closed on an empty validator
    /// set rather than emitting a chain that seeds `totalWeight == 0` and can
    /// never reach quorum. (The CLI already guarded this; the library fn now
    /// does too, so every caller is protected.)
    #[test]
    fn deployment_genesis_rejects_empty_validator_set() {
        let err = build_deployment_genesis(
            424242,
            std::iter::empty::<GenesisValidator>(),
            std::iter::empty::<PrefundAlloc>(),
            "0x00000000000000000000000000000000000Facc7",
        )
        .unwrap_err();
        assert!(
            matches!(err, GenesisSeedError::EmptyValidatorSet),
            "empty validator set must fail closed, got {err:?}",
        );
    }

    /// A malformed staking-owner address fails the deployment build closed
    /// (#821) — better a hard build error than a silently-misconfigured gate.
    #[test]
    fn deployment_genesis_rejects_malformed_staking_owner() {
        let (pk0,) = (dev_genesis_validators(1)[0].1,);
        let err = build_deployment_genesis(
            424242,
            [([0xa0; 32], pk0, 4u64)],
            std::iter::empty::<PrefundAlloc>(),
            "0xdeadbeef", // not 20 bytes
        )
        .unwrap_err();
        assert!(
            matches!(err, GenesisSeedError::StakingOwner(_)),
            "malformed owner must fail closed, got {err:?}",
        );
    }

    /// `seed_staking_owner` is idempotent on the embedded base genesis (the
    /// Staking predeploy is present) and writes the owner right-aligned at slot
    /// 0; the dev genesis (built without seeding an owner) leaves it unset, so
    /// `owner == address(0)` disables `withdraw` (fails closed).
    #[test]
    fn dev_genesis_leaves_staking_owner_unset() {
        let genesis = build_dev_genesis(2);
        let staking = &genesis["alloc"][STAKING_ADDRESS];
        // No storage (or no slot-0 owner word) → owner defaults to address(0),
        // so `withdraw` reverts for everyone until an owner is seeded.
        let owner_slot = "0x0000000000000000000000000000000000000000000000000000000000000000";
        let seeded = staking["storage"]
            .as_object()
            .map(|s| s.contains_key(owner_slot))
            .unwrap_or(false);
        assert!(
            !seeded,
            "dev genesis must not seed a staking owner (withdraw stays disabled)",
        );
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
