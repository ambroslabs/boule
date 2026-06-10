use anyhow::Context as _;

use crate::replication::block::Block;
use crate::validator_set::ValidatorSet;
use boule_core::config::ConsensusConfig;
use boule_core::identity::{NodeId, base58_to_node_id};

pub fn derive_chain_id(
    cfg: &ConsensusConfig,
) -> anyhow::Result<boule_core::crypto::signed::ChainId> {
    if cfg.validators.is_empty() {
        anyhow::bail!("[consensus.validators] must list at least one node");
    }
    let mut ids: Vec<NodeId> = Vec::with_capacity(cfg.validators.len());
    for raw in &cfg.validators {
        let id = base58_to_node_id(raw)
            .map_err(|e| anyhow::anyhow!("decoding validator NodeId {raw:?}: {e}"))?;
        ids.push(id);
    }
    let bls_full = cfg
        .resolve_genesis_bls_keys()
        .context("decoding genesis BLS validator table")?;
    let bls_pubkeys: Vec<(NodeId, boule_core::crypto::sig_scheme::BlsPublicKey)> = bls_full
        .into_iter()
        .map(|(nid, pk, _pop)| (nid, pk))
        .collect();
    let mut seed = [0u8; 32];
    if let Some(hex) = &cfg.genesis_seed_hex {
        seed = decode_hex32(hex)
            .ok_or_else(|| anyhow::anyhow!("genesis_seed_hex must be 64 hex chars (32 bytes)"))?;
    }
    let operator_keys = cfg
        .resolve_genesis_operator_keys()
        .context("decoding genesis operator-key table")?;
    Ok(derive_chain_id_from_parts(
        &ids,
        &bls_pubkeys,
        &operator_keys,
        seed,
    ))
}

pub fn derive_chain_id_from_parts(
    validator_node_ids: &[NodeId],
    genesis_bls: &[(NodeId, boule_core::crypto::sig_scheme::BlsPublicKey)],
    genesis_operator_keys: &[(NodeId, NodeId)],
    genesis_seed: [u8; 32],
) -> boule_core::crypto::signed::ChainId {
    let validator_ids: Vec<crate::validator_set::ValidatorId> = validator_node_ids
        .iter()
        .copied()
        .map(crate::validator_set::ValidatorId::from_genesis_pubkey)
        .collect();
    let validator_set = ValidatorSet::new(validator_ids);
    let commitment = compute_genesis_validator_history_commitment(
        &validator_set,
        genesis_bls,
        genesis_operator_keys,
    );
    let genesis = Block::genesis(genesis_seed, commitment);
    boule_core::crypto::signed::ChainId::from_genesis_hash(genesis.hash())
}

pub fn build_genesis(
    cfg: &ConsensusConfig,
    validator_set: &ValidatorSet,
    genesis_bls: &[(NodeId, boule_core::crypto::sig_scheme::BlsPublicKey)],
) -> anyhow::Result<Block> {
    let mut seed = [0u8; 32];
    if let Some(hex) = &cfg.genesis_seed_hex {
        let bytes = decode_hex32(hex)
            .ok_or_else(|| anyhow::anyhow!("genesis_seed_hex must be 64 hex chars (32 bytes)"))?;
        seed = bytes;
    }
    let operator_keys = cfg.resolve_genesis_operator_keys()?;
    let commitment =
        compute_genesis_validator_history_commitment(validator_set, genesis_bls, &operator_keys);
    Ok(Block::genesis(seed, commitment))
}

fn compute_genesis_validator_history_commitment(
    validator_set: &ValidatorSet,
    genesis_bls: &[(NodeId, boule_core::crypto::sig_scheme::BlsPublicKey)],
    genesis_operator_keys: &[(NodeId, NodeId)],
) -> [u8; 32] {
    let set_hist =
        crate::validator_history::ValidatorSetHistory::from_genesis(validator_set.clone());
    let key_hist =
        crate::validator_key_history::ValidatorKeyHistory::new(validator_set.iter().copied());
    let bls_hist = Some(crate::bls_key_history::BlsKeyHistory::with_genesis(
        genesis_bls.iter().copied(),
    ));

    let operator_hist = if genesis_operator_keys.is_empty() {
        None
    } else {
        Some(
            crate::operator_key_history::OperatorKeyHistory::with_genesis(
                genesis_operator_keys.iter().map(|(v, op)| {
                    (
                        crate::validator_set::ValidatorId::from_genesis_pubkey(*v),
                        *op,
                    )
                }),
            ),
        )
    };
    crate::history_commitment::validator_history_commitment_v2(
        &set_hist,
        &key_hist,
        bls_hist.as_ref(),
        operator_hist.as_ref(),
    )
}

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_nibble(s.as_bytes()[2 * i])?;
        let lo = hex_nibble(s.as_bytes()[2 * i + 1])?;
        *byte = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}
