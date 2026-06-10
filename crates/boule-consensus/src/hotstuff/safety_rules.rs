use std::collections::{HashMap, HashSet};

use crate::replication::block::{Block, BlockHash};

use super::qc::{Proposal, QuorumCertificate};
use super::state::HotStuffState;

pub fn extends(
    block_hash: &BlockHash,
    ancestor_hash: &BlockHash,
    pending: &HashMap<BlockHash, Block>,
) -> bool {
    if block_hash == ancestor_hash {
        return true;
    }
    let mut seen: HashSet<BlockHash> = HashSet::new();
    let mut current = *block_hash;
    loop {
        if !seen.insert(current) {
            return false;
        }
        let Some(block) = pending.get(&current) else {
            return false;
        };
        let parent = block.header.parent_hash;
        if parent == *ancestor_hash {
            return true;
        }
        if parent == [0u8; 32] {
            return false;
        }
        current = parent;
    }
}

pub fn safe_to_vote(proposal: &Proposal, state: &HotStuffState) -> bool {
    let view = proposal.block.header.view;
    if view <= state.last_voted_view {
        return false;
    }
    let Some(locked) = state.locked else {
        return true;
    };

    if extends(
        &proposal.block.hash(),
        &locked.block_hash,
        &state.pending_blocks,
    ) {
        return true;
    }

    proposal.justify.view > locked.view
}

pub fn should_update_high_qc(qc: &QuorumCertificate, state: &HotStuffState) -> bool {
    match &state.high_qc {
        None => true,
        Some(existing) => qc.view > existing.view(),
    }
}

pub fn three_chain_commit(new_qc: &QuorumCertificate, state: &HotStuffState) -> Option<Block> {
    let b3 = state.pending_blocks.get(&new_qc.block_hash)?;
    if b3.header.view != new_qc.view {
        return None;
    }
    let b2 = state.pending_blocks.get(&b3.header.parent_hash)?;
    if b2.header.view + 1 != b3.header.view {
        return None;
    }
    let b1 = state.pending_blocks.get(&b2.header.parent_hash)?;
    if b1.header.view + 1 != b2.header.view {
        return None;
    }
    Some(b1.clone())
}
