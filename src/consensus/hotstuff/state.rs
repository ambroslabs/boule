//! The data [`HotStuffState`] the safety core carries between steps.
//!
//! `HotStuffState` is deliberately a dumb struct: fields are public so
//! the tests in [`super::safety_rules`] and (in 7.C) the dispatcher in
//! `step.rs` can hand-build any state they need without going through a
//! constructor. No method here makes a safety decision — every decision
//! lives in [`super::safety_rules`].

use std::collections::HashMap;

use crate::consensus::View;
use crate::consensus::validator_set::ValidatorSet;
use crate::replication::block::{Block, BlockHash};

use super::qc::QuorumCertificate;

/// All state the HotStuff safety core needs to answer "is this proposal
/// safe to vote for?" / "what (if anything) should be committed?".
///
/// Kept flat and `Clone`-able so replay harnesses can snapshot it.
#[derive(Debug, Clone)]
pub struct HotStuffState {
    /// View the pacemaker has most recently told us we're in. The
    /// safety core never advances this on its own — only
    /// `Event::PacemakerAdvance` does.
    pub current_view: View,

    /// Highest-view QC whose block this replica has promised (via the
    /// two-chain rule) not to diverge from. HotStuff's *extension* rule
    /// forbids voting for any proposal whose block doesn't extend
    /// `locked_qc.block_hash`.
    pub locked_qc: Option<QuorumCertificate>,

    /// Highest-view QC this replica has seen anywhere (proposal,
    /// NewView, freshly assembled). Used to piggyback our most recent
    /// proof of progress when we send a NewView, and as the justify
    /// for proposals we build.
    pub high_qc: Option<QuorumCertificate>,

    /// View of the most recent block this replica has voted on.
    /// Prevents double-voting within a view.
    pub last_voted_view: View,

    /// Committee the replica is operating under. Dynamic validator-set
    /// churn is out of scope for milestone 7 (#23).
    pub validator_set: ValidatorSet,

    /// Blocks the replica has observed but not yet committed. Keyed by
    /// header hash (`Block::hash()`). Parent chains are walked through
    /// this map. 7.C prunes entries below the latest commit; 7.B only
    /// inserts.
    pub pending_blocks: HashMap<BlockHash, Block>,

    /// Hash of the genesis block. Recorded once at construction for
    /// convenience — walking `parent_hash` links lands at this value
    /// once, and its parent is `[0; 32]`.
    pub genesis_hash: BlockHash,
}

impl HotStuffState {
    /// Build a fresh state rooted at `genesis`. The genesis block is
    /// pre-inserted into `pending_blocks` so parent-walking safety
    /// predicates can terminate on it. Locked/high QC start as `None`.
    pub fn new(validator_set: ValidatorSet, genesis: Block) -> Self {
        let genesis_hash = genesis.hash();
        let mut pending = HashMap::new();
        pending.insert(genesis_hash, genesis);
        Self {
            current_view: 0,
            locked_qc: None,
            high_qc: None,
            last_voted_view: 0,
            validator_set,
            pending_blocks: pending,
            genesis_hash,
        }
    }

    /// Insert (or overwrite) a pending block. The key is `block.hash()`
    /// so re-inserting the same block is a cheap no-op.
    pub fn insert_pending(&mut self, block: Block) {
        self.pending_blocks.insert(block.hash(), block);
    }

    /// Lookup a pending block by its header hash.
    pub fn get_pending(&self, hash: &BlockHash) -> Option<&Block> {
        self.pending_blocks.get(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::NodeId;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    #[test]
    fn new_seeds_genesis_into_pending() {
        let vs = ValidatorSet::new(vec![nid(1), nid(2), nid(3), nid(4)]);
        let genesis = Block::genesis([0x77; 32]);
        let g_hash = genesis.hash();
        let state = HotStuffState::new(vs.clone(), genesis.clone());
        assert_eq!(state.current_view, 0);
        assert_eq!(state.last_voted_view, 0);
        assert!(state.locked_qc.is_none());
        assert!(state.high_qc.is_none());
        assert_eq!(state.genesis_hash, g_hash);
        assert_eq!(state.get_pending(&g_hash), Some(&genesis));
    }

    #[test]
    fn insert_pending_is_idempotent() {
        let vs = ValidatorSet::new(vec![nid(1)]);
        let genesis = Block::genesis([0; 32]);
        let mut state = HotStuffState::new(vs, genesis.clone());
        let before = state.pending_blocks.len();
        state.insert_pending(genesis.clone());
        state.insert_pending(genesis);
        assert_eq!(state.pending_blocks.len(), before);
    }
}
