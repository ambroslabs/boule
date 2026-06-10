use crate::View;
use crate::hotstuff::qc::Vote;
use crate::replication::block::BlockHash;
use boule_core::crypto::signed::{ChainId, preimage};

pub(in crate::dispatch) fn vote_preimage(
    view: View,
    block_hash: BlockHash,
    chain_id: &ChainId,
) -> anyhow::Result<Vec<u8>> {
    preimage::<Vote>(&Vote { view, block_hash }, chain_id)
}
