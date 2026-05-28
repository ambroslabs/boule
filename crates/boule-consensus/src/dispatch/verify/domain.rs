//! Chain-id pre-image binding (#324).
//!
//! Single helper that wraps [`boule::crypto::signed::preimage`] for
//! the dispatch-layer call sites. Reconstructs the canonical
//! signing pre-image for a [`Vote`] over `(view, block_hash)` so the
//! QC aggregate verifier and the BLS partial verifier see the same
//! bytes the voter signed in `Signed::sign(vote, signer, chain_id)`.

use crate::View;
use crate::hotstuff::qc::Vote;
use boule::crypto::signed::{ChainId, preimage};
use crate::replication::block::BlockHash;

/// Reconstruct the canonical Vote signing pre-image for `(view,
/// block_hash)` under `chain_id`. Used by both the QC aggregate
/// verifier (which reconstructs the pre-image off the QC's view +
/// block_hash) and the BLS partial verifier (which uses the same
/// bytes against the signer's BLS pubkey).
pub(in crate::dispatch) fn vote_preimage(
    view: View,
    block_hash: BlockHash,
    chain_id: &ChainId,
) -> anyhow::Result<Vec<u8>> {
    preimage::<Vote>(&Vote { view, block_hash }, chain_id)
}
