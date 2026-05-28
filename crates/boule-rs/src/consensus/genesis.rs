//! Genesis-block construction and [`ChainId`] derivation.
//!
//! These compute a deployment's genesis block and chain ID from a
//! [`ConsensusConfig`] (or the raw parts), pulling in the genesis-time
//! validator-set / key / BLS-key histories. They live in `consensus`
//! rather than in the node runtime so CLI tooling (`reconfig`,
//! `rotation`) and the `testnet` driver can derive a chain ID without
//! booting a node.
//!
//! [`ChainId`]: crate::crypto::signed::ChainId

use anyhow::Context as _;

use crate::config::ConsensusConfig;
use crate::consensus::validator_set::ValidatorSet;
use crate::identity::{NodeId, base58_to_node_id};
use crate::replication::block::Block;

/// Derive the deployment's [`ChainId`] from a [`ConsensusConfig`]
/// without booting a full consensus node. Used by CLI tooling
/// (`reconfig add-validator` etc.) that needs to mint or verify
/// chain-bound BLS proofs-of-possession (#410) before the node is
/// actually running.
///
/// Performs only the structural validation of `validators_bls`
/// (decoding hex, length match, no duplicates) — the cryptographic
/// PoP check is exactly what the caller is preparing to perform, so
/// it would be redundant here.
///
/// [`ChainId`]: crate::crypto::signed::ChainId
pub fn derive_chain_id(cfg: &ConsensusConfig) -> anyhow::Result<crate::crypto::signed::ChainId> {
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
    let bls_pubkeys: Vec<(NodeId, crate::crypto::sig_scheme::BlsPublicKey)> = bls_full
        .into_iter()
        .map(|(nid, pk, _pop)| (nid, pk))
        .collect();
    let mut seed = [0u8; 32];
    if let Some(hex) = &cfg.genesis_seed_hex {
        seed = decode_hex32(hex)
            .ok_or_else(|| anyhow::anyhow!("genesis_seed_hex must be 64 hex chars (32 bytes)"))?;
    }
    Ok(derive_chain_id_from_parts(
        &ids,
        cfg.signature_scheme,
        &bls_pubkeys,
        seed,
    ))
}

/// Lower-level [`ChainId`] derivation that takes only the inputs the
/// genesis-block construction needs, without going through a fully-
/// populated [`ConsensusConfig`]. Used by the `testnet` driver
/// (which mints validator BLS keys before any config has been written
/// and needs the chain_id to mint chain-bound PoPs, #410).
///
/// `validator_node_ids` is the cluster's validator pubkeys in their
/// genesis order — the function sorts them through [`ValidatorSet`]
/// the same way `[consensus.validators]` parsing does, so the input
/// order doesn't matter as long as it's the same set on every node.
///
/// [`ChainId`]: crate::crypto::signed::ChainId
pub fn derive_chain_id_from_parts(
    validator_node_ids: &[NodeId],
    signature_scheme: crate::crypto::sig_scheme::SignatureSchemeChoice,
    genesis_bls: &[(NodeId, crate::crypto::sig_scheme::BlsPublicKey)],
    genesis_seed: [u8; 32],
) -> crate::crypto::signed::ChainId {
    let validator_ids: Vec<crate::consensus::validator_set::ValidatorId> = validator_node_ids
        .iter()
        .copied()
        .map(crate::consensus::validator_set::ValidatorId::from_genesis_pubkey)
        .collect();
    let validator_set = ValidatorSet::new(validator_ids);
    let commitment =
        compute_genesis_validator_history_commitment(&validator_set, signature_scheme, genesis_bls);
    let genesis = Block::genesis(genesis_seed, commitment);
    crate::crypto::signed::ChainId::from_genesis_hash(genesis.hash())
}

/// Build the genesis block from the optional `genesis_seed_hex` config
/// field. Defaults to all-zeros when unset.
///
/// `validator_history_commitment` is computed from the genesis-time
/// validator-set / key / BLS-key histories so a recovering node can
/// cross-check its persisted history blobs against the chain's claim
/// (#325 PR B). The triple is the canonical input to
/// [`crate::consensus::history_commitment::validator_history_commitment_v1`].
pub fn build_genesis(
    cfg: &ConsensusConfig,
    validator_set: &ValidatorSet,
    genesis_bls: &[(NodeId, crate::crypto::sig_scheme::BlsPublicKey)],
) -> anyhow::Result<Block> {
    let mut seed = [0u8; 32];
    if let Some(hex) = &cfg.genesis_seed_hex {
        let bytes = decode_hex32(hex)
            .ok_or_else(|| anyhow::anyhow!("genesis_seed_hex must be 64 hex chars (32 bytes)"))?;
        seed = bytes;
    }
    let commitment = compute_genesis_validator_history_commitment(
        validator_set,
        cfg.signature_scheme,
        genesis_bls,
    );
    Ok(Block::genesis(seed, commitment))
}

/// Compute the canonical genesis-time `validator_history_commitment`
/// (#325 PR B). Shared between [`build_genesis`] and the recovery
/// path's "what should the genesis block's commitment be?" derivation
/// so both produce byte-identical hashes from the same inputs.
fn compute_genesis_validator_history_commitment(
    validator_set: &ValidatorSet,
    scheme: crate::crypto::sig_scheme::SignatureSchemeChoice,
    genesis_bls: &[(NodeId, crate::crypto::sig_scheme::BlsPublicKey)],
) -> [u8; 32] {
    let set_hist = crate::consensus::validator_history::ValidatorSetHistory::from_genesis(
        validator_set.clone(),
    );
    let key_hist = crate::consensus::validator_key_history::ValidatorKeyHistory::new(
        validator_set.iter().copied(),
    );
    let bls_hist = match scheme {
        crate::crypto::sig_scheme::SignatureSchemeChoice::BlsAggregated => Some(
            crate::consensus::bls_key_history::BlsKeyHistory::with_genesis(
                genesis_bls.iter().copied(),
            ),
        ),
        crate::crypto::sig_scheme::SignatureSchemeChoice::Ed25519Collected => None,
    };
    crate::consensus::history_commitment::validator_history_commitment_v1(
        &set_hist,
        &key_hist,
        bls_hist.as_ref(),
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
