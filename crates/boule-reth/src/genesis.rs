use std::path::PathBuf;

use boule_consensus::genesis::derive_chain_id_from_parts;
use boule_core::crypto::bls_key::{BlsKeyFile, BlsKeyProvider};
use boule_core::crypto::sig_scheme::{BlsAggregated, BlsKeyError, BlsPublicKey};
use boule_core::identity::NodeId;
use serde_json::Value;

use crate::registry::{REGISTRY_ADDRESS, genesis_seed_storage_json};
use crate::staking::{STAKING_ADDRESS, owner_seed_storage_json};

pub type GenesisValidator = (NodeId, BlsPublicKey, u64);

#[derive(Debug)]
pub enum GenesisSeedError {
    BlsKey(BlsKeyError),

    NoRegistryAlloc,

    MalformedGenesis,

    EmptyValidatorSet,

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

const BASE_GENESIS_JSON: &str = include_str!("../genesis.json");

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

pub fn seed_staking_owner(genesis: &mut Value, owner: &str) -> Result<(), GenesisSeedError> {
    let (slot, value) = owner_seed_storage_json(owner).map_err(GenesisSeedError::StakingOwner)?;

    let alloc = genesis
        .get_mut("alloc")
        .ok_or_else(|| GenesisSeedError::StakingOwner("base genesis has no alloc".into()))?
        .as_object_mut()
        .ok_or(GenesisSeedError::MalformedGenesis)?;

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

pub fn build_seeded_genesis(
    validators: impl IntoIterator<Item = GenesisValidator>,
) -> Result<Value, GenesisSeedError> {
    let mut genesis: Value =
        serde_json::from_str(BASE_GENESIS_JSON).expect("embedded genesis.json parses");
    seed_registry_genesis(&mut genesis, validators)?;
    Ok(genesis)
}

pub type PrefundAlloc = (String, u128);

pub fn build_deployment_genesis(
    chain_id: u64,
    validators: impl IntoIterator<Item = GenesisValidator>,
    prefund: impl IntoIterator<Item = PrefundAlloc>,
    staking_owner: &str,
) -> Result<Value, GenesisSeedError> {
    let validators: Vec<GenesisValidator> = validators.into_iter().collect();
    if validators.is_empty() {
        return Err(GenesisSeedError::EmptyValidatorSet);
    }

    let mut genesis = build_seeded_genesis(validators)?;

    seed_staking_owner(&mut genesis, staking_owner)?;

    genesis
        .get_mut("config")
        .and_then(Value::as_object_mut)
        .ok_or(GenesisSeedError::MalformedGenesis)?
        .insert("chainId".to_string(), Value::from(chain_id));

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

pub fn build_dev_genesis(n: usize) -> Value {
    build_seeded_genesis(dev_genesis_validators(n))
        .expect("dev validators have valid BLS keys and a Registry predeploy")
}

#[derive(Debug, Clone)]
pub struct BlsPopRow {
    pub node_id: NodeId,

    pub pubkey: BlsPublicKey,

    pub pop_sig: Vec<u8>,
}

pub fn mint_genesis_bls_pops(
    validators: &[(NodeId, PathBuf)],
    genesis_seed: [u8; 32],
    allow_insecure_perms: bool,
) -> anyhow::Result<Vec<BlsPopRow>> {
    anyhow::ensure!(!validators.is_empty(), "at least one validator is required");

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
