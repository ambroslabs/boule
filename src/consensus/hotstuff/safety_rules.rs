//! Pure HotStuff safety predicates.
//!
//! Every function here is a free function over plain data — no `&mut
//! self`, no I/O, no randomness. 7.C's `step()` composes these into
//! the public state machine; keeping the rules total and pure here is
//! what makes the safety property testable in isolation.
//!
//! All predicates assume blocks referenced by hash have been inserted
//! into [`HotStuffState::pending_blocks`] by the caller. Nothing here
//! implicitly fetches missing blocks; missing-parent handling is the
//! dispatcher's job (7.C's `RequestBlock`).

use std::collections::{HashMap, HashSet};

use crate::replication::block::{Block, BlockHash};

use super::qc::{Proposal, QuorumCertificate};
use super::state::HotStuffState;

/// Walk the parent-chain starting at `block_hash`; return `true` iff
/// `ancestor_hash` is reachable.
///
/// Terminates on (a) finding the ancestor, (b) hitting a hash that
/// isn't in `pending` (unknown block — treat as non-extending), (c)
/// walking off the root (a block whose `parent_hash` is `[0; 32]`), or
/// (d) detecting a cycle via the visited set. Cases (b)–(d) return
/// `false`.
///
/// Reflexive: `extends(h, h, _) == true` — a block extends itself.
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
            // Cycle — not a legitimate chain.
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
            // Reached genesis's parent sentinel without a match.
            return false;
        }
        current = parent;
    }
}

/// HotStuff voting rule.
///
/// A replica votes for `proposal` iff:
///
/// 1. `proposal.block.view > state.last_voted_view` (never vote twice
///    at the same view — prevents local double-voting), **and**
/// 2. no lock is held, **or** the *extension rule* fires (proposal's
///    block extends the locked block), **or** the *liveness rule*
///    fires (proposal carries a fresher justify than the lock).
///
/// The block must already be present in `state.pending_blocks` for the
/// extension walk; 7.C's dispatcher inserts it before calling this.
pub fn safe_to_vote(proposal: &Proposal, state: &HotStuffState) -> bool {
    let view = proposal.block.header.view;
    if view <= state.last_voted_view {
        return false;
    }
    let Some(locked) = state.locked else {
        // No lock yet — any fresh-view proposal is safe.
        return true;
    };
    // Extension rule.
    if extends(
        &proposal.block.hash(),
        &locked.block_hash,
        &state.pending_blocks,
    ) {
        return true;
    }
    // Liveness rule.
    proposal.justify.view > locked.view
}

/// `true` when `qc` is strictly newer than the state's current
/// [`HotStuffState::high_qc`] — i.e., the replica should adopt it.
pub fn should_update_high_qc(qc: &QuorumCertificate, state: &HotStuffState) -> bool {
    match &state.high_qc {
        None => true,
        Some(existing) => qc.view > existing.view,
    }
}

/// Chained-HotStuff three-chain commit rule.
///
/// Given a freshly-formed QC `new_qc` over some block `b3`, look at
/// `b3`'s parent `b2` and grandparent `b1`. If the three blocks have
/// *consecutive* views (`b1.view + 1 == b2.view`, `b2.view + 1 ==
/// b3.view`), the oldest of the three — `b1` — is committed. This is
/// the canonical three-chain of the HotStuff paper.
///
/// Returns `None` when:
/// - `new_qc.block_hash` isn't in `pending_blocks` (block unknown),
/// - the QC's claimed view doesn't match `b3.header.view` (malformed),
/// - either ancestor is missing from `pending_blocks`, or
/// - the views aren't strictly consecutive (a one-chain or a gap).
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

#[cfg(test)]
mod tests {
    use super::super::state::Locked;
    use super::*;
    use crate::consensus::validator_set::ValidatorSet;
    use crate::p2p::NodeId;
    use crate::replication::block::{Block, BlockHeader};

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn validators() -> ValidatorSet {
        ValidatorSet::new(vec![nid(1), nid(2), nid(3), nid(4)])
    }

    /// Chain the given view sequence, each block parented to its
    /// predecessor. Returns the vector of blocks, oldest first. `views[0]`
    /// becomes the child of genesis.
    fn chain_from_genesis(genesis: &Block, views: &[u64]) -> Vec<Block> {
        let mut out = Vec::with_capacity(views.len());
        let mut parent_hash = genesis.hash();
        for (i, &view) in views.iter().enumerate() {
            let height = genesis.header.height + (i as u64) + 1;
            let header = BlockHeader {
                parent_hash,
                height,
                view,
                proposer: nid(1),
                state_commitment: [0; 32],
                commands_commitment: Block::commands_commitment(&[]),
                validator_history_commitment: [0; 32],
            };
            let block = Block {
                header,
                commands: Vec::new(),
            };
            parent_hash = block.hash();
            out.push(block);
        }
        out
    }

    fn state_with_chain(chain: &[Block], genesis: Block) -> HotStuffState {
        let mut state = HotStuffState::new(validators(), genesis);
        for b in chain {
            state.insert_pending(b.clone());
        }
        state
    }

    fn dummy_qc(view: u64, block_hash: BlockHash) -> QuorumCertificate {
        QuorumCertificate::new(view, block_hash, validators().len())
    }

    // ── extends ─────────────────────────────────────────────────

    #[test]
    fn extends_is_reflexive() {
        let g = Block::genesis([0; 32], [0; 32]);
        let state = HotStuffState::new(validators(), g.clone());
        let h = g.hash();
        assert!(extends(&h, &h, &state.pending_blocks));
    }

    #[test]
    fn extends_finds_direct_parent() {
        let g = Block::genesis([0; 32], [0; 32]);
        let chain = chain_from_genesis(&g, &[1]);
        let state = state_with_chain(&chain, g.clone());
        assert!(extends(&chain[0].hash(), &g.hash(), &state.pending_blocks));
    }

    #[test]
    fn extends_finds_grandparent() {
        let g = Block::genesis([0; 32], [0; 32]);
        let chain = chain_from_genesis(&g, &[1, 2]);
        let state = state_with_chain(&chain, g.clone());
        assert!(extends(&chain[1].hash(), &g.hash(), &state.pending_blocks));
    }

    #[test]
    fn extends_rejects_unrelated_sibling() {
        let g = Block::genesis([0; 32], [0; 32]);
        let chain_a = chain_from_genesis(&g, &[1]);
        // Build a sibling at view 2 rooted on g as well (parent = genesis).
        let sibling = Block {
            header: BlockHeader {
                parent_hash: g.hash(),
                height: 1,
                view: 2,
                proposer: nid(2),
                state_commitment: [1; 32],
                commands_commitment: Block::commands_commitment(&[]),
                validator_history_commitment: [0; 32],
            },
            commands: Vec::new(),
        };
        let mut state = HotStuffState::new(validators(), g.clone());
        state.insert_pending(chain_a[0].clone());
        state.insert_pending(sibling.clone());

        // sibling does not extend chain_a[0].
        assert!(!extends(
            &sibling.hash(),
            &chain_a[0].hash(),
            &state.pending_blocks
        ));
    }

    #[test]
    fn extends_returns_false_when_ancestor_unknown() {
        let g = Block::genesis([0; 32], [0; 32]);
        let chain = chain_from_genesis(&g, &[1]);
        let state = state_with_chain(&chain, g);
        assert!(!extends(
            &chain[0].hash(),
            &[0x99; 32],
            &state.pending_blocks
        ));
    }

    #[test]
    fn extends_returns_false_on_missing_link() {
        // Insert grandchild but not its parent — walk stops at missing.
        let g = Block::genesis([0; 32], [0; 32]);
        let chain = chain_from_genesis(&g, &[1, 2]);
        let mut state = HotStuffState::new(validators(), g.clone());
        state.insert_pending(chain[1].clone()); // note: not chain[0]
        assert!(!extends(&chain[1].hash(), &g.hash(), &state.pending_blocks));
    }

    #[test]
    fn extends_terminates_on_cycle() {
        // Construct a pair of blocks whose parent pointers form a cycle.
        // We can't do this "naturally" since Block hashes depend on
        // parent_hash, so we forge the map directly.
        let a_hash = [0xAA; 32];
        let b_hash = [0xBB; 32];
        let a = Block {
            header: BlockHeader {
                parent_hash: b_hash,
                height: 5,
                view: 5,
                proposer: nid(1),
                state_commitment: [0; 32],
                commands_commitment: Block::commands_commitment(&[]),
                validator_history_commitment: [0; 32],
            },
            commands: Vec::new(),
        };
        let b = Block {
            header: BlockHeader {
                parent_hash: a_hash,
                height: 4,
                view: 4,
                proposer: nid(1),
                state_commitment: [0; 32],
                commands_commitment: Block::commands_commitment(&[]),
                validator_history_commitment: [0; 32],
            },
            commands: Vec::new(),
        };
        let mut pending: HashMap<BlockHash, Block> = HashMap::new();
        pending.insert(a_hash, a);
        pending.insert(b_hash, b);
        // Asking whether a extends some unrelated hash should terminate
        // (not infinite-loop) and return false.
        assert!(!extends(&a_hash, &[0xCC; 32], &pending));
    }

    // ── safe_to_vote ────────────────────────────────────────────

    fn proposal(block: Block, justify: QuorumCertificate) -> Proposal {
        Proposal { block, justify }
    }

    #[test]
    fn safe_to_vote_rejects_view_not_greater_than_last_voted() {
        let g = Block::genesis([0; 32], [0; 32]);
        let chain = chain_from_genesis(&g, &[5]);
        let mut state = state_with_chain(&chain, g.clone());
        state.last_voted_view = 5;
        let p = proposal(chain[0].clone(), dummy_qc(0, g.hash()));
        assert!(!safe_to_vote(&p, &state));
    }

    #[test]
    fn safe_to_vote_accepts_fresh_view_when_unlocked() {
        let g = Block::genesis([0; 32], [0; 32]);
        let chain = chain_from_genesis(&g, &[1]);
        let state = state_with_chain(&chain, g.clone());
        let p = proposal(chain[0].clone(), dummy_qc(0, g.hash()));
        assert!(safe_to_vote(&p, &state));
    }

    #[test]
    fn safe_to_vote_accepts_when_extends_locked() {
        // Lock is on block at view 3. Propose a new block whose chain
        // extends that block: extension rule fires.
        let g = Block::genesis([0; 32], [0; 32]);
        let chain = chain_from_genesis(&g, &[3, 4]);
        let locked_block = &chain[0];
        let new_block = &chain[1];
        let mut state = state_with_chain(&chain, g.clone());
        state.locked = Some(Locked {
            view: 3,
            height: locked_block.header.height,
            block_hash: locked_block.hash(),
        });
        state.last_voted_view = 3;
        let p = proposal(new_block.clone(), dummy_qc(3, locked_block.hash()));
        assert!(safe_to_vote(&p, &state));
    }

    #[test]
    fn safe_to_vote_rejects_when_doesnt_extend_and_justify_stale() {
        // Locked on view 5, propose a sibling at view 6 with justify.view=3
        // that doesn't extend the locked block → neither rule fires.
        let g = Block::genesis([0; 32], [0; 32]);
        let locked_block = chain_from_genesis(&g, &[5])[0].clone();
        // Fork: different block at view 6 rooted on genesis directly.
        let fork = Block {
            header: BlockHeader {
                parent_hash: g.hash(),
                height: 1,
                view: 6,
                proposer: nid(3),
                state_commitment: [0; 32],
                commands_commitment: Block::commands_commitment(&[]),
                validator_history_commitment: [0; 32],
            },
            commands: Vec::new(),
        };
        let mut state = HotStuffState::new(validators(), g.clone());
        state.insert_pending(locked_block.clone());
        state.insert_pending(fork.clone());
        state.locked = Some(Locked {
            view: 5,
            height: locked_block.header.height,
            block_hash: locked_block.hash(),
        });
        state.last_voted_view = 5;

        let stale_justify = dummy_qc(3, g.hash());
        let p = proposal(fork, stale_justify);
        assert!(!safe_to_vote(&p, &state));
    }

    #[test]
    fn safe_to_vote_accepts_liveness_rule_when_justify_fresher() {
        // Same setup as above but the justify is view 9 > locked.view = 5.
        let g = Block::genesis([0; 32], [0; 32]);
        let locked_block = chain_from_genesis(&g, &[5])[0].clone();
        let fork = Block {
            header: BlockHeader {
                parent_hash: g.hash(),
                height: 1,
                view: 10,
                proposer: nid(3),
                state_commitment: [0; 32],
                commands_commitment: Block::commands_commitment(&[]),
                validator_history_commitment: [0; 32],
            },
            commands: Vec::new(),
        };
        let mut state = HotStuffState::new(validators(), g.clone());
        state.insert_pending(locked_block.clone());
        state.insert_pending(fork.clone());
        state.locked = Some(Locked {
            view: 5,
            height: locked_block.header.height,
            block_hash: locked_block.hash(),
        });
        state.last_voted_view = 5;

        let fresh_justify = dummy_qc(9, [0xEE; 32]);
        let p = proposal(fork, fresh_justify);
        assert!(safe_to_vote(&p, &state));
    }

    // ── should_update_high_qc ──────────────────────────────────

    #[test]
    fn should_update_high_qc_when_empty() {
        let state = HotStuffState::new(validators(), Block::genesis([0; 32], [0; 32]));
        assert!(should_update_high_qc(&dummy_qc(0, [0; 32]), &state));
    }

    #[test]
    fn should_update_high_qc_requires_strictly_greater_view() {
        let mut state = HotStuffState::new(validators(), Block::genesis([0; 32], [0; 32]));
        state.high_qc = Some(dummy_qc(5, [1; 32]));
        assert!(!should_update_high_qc(&dummy_qc(5, [2; 32]), &state));
        assert!(!should_update_high_qc(&dummy_qc(4, [2; 32]), &state));
        assert!(should_update_high_qc(&dummy_qc(6, [2; 32]), &state));
    }

    // ── three_chain_commit ──────────────────────────────────────

    #[test]
    fn three_chain_commit_commits_grandparent_on_consecutive_views() {
        let g = Block::genesis([0; 32], [0; 32]);
        let chain = chain_from_genesis(&g, &[1, 2, 3]);
        let state = state_with_chain(&chain, g);
        let new_qc = dummy_qc(3, chain[2].hash());

        let committed = three_chain_commit(&new_qc, &state).expect("three-chain fires");
        assert_eq!(committed.hash(), chain[0].hash());
        assert_eq!(committed.header.view, 1);
    }

    #[test]
    fn three_chain_commit_returns_none_on_view_gap() {
        let g = Block::genesis([0; 32], [0; 32]);
        // Views 1, 2, 5 — not strictly consecutive (gap between 2 and 5).
        let chain = chain_from_genesis(&g, &[1, 2, 5]);
        let state = state_with_chain(&chain, g);
        let new_qc = dummy_qc(5, chain[2].hash());
        assert!(three_chain_commit(&new_qc, &state).is_none());
    }

    #[test]
    fn three_chain_commit_returns_none_on_two_chain_only() {
        // We only have two blocks past genesis — `b1` walks off to
        // genesis, which has view 0, and 0 + 1 != 1 is false... wait,
        // genesis has view 0 and first block has view 1, so
        // 0 + 1 == 1 holds. This test uses non-consecutive gap
        // between genesis view 0 and first block view 2.
        let g = Block::genesis([0; 32], [0; 32]);
        let chain = chain_from_genesis(&g, &[2, 3]);
        let state = state_with_chain(&chain, g);
        let new_qc = dummy_qc(3, chain[1].hash());
        // b3 = chain[1] (view 3), b2 = chain[0] (view 2, consecutive),
        // b1 = genesis (view 0, NOT consecutive with view 2) → None.
        assert!(three_chain_commit(&new_qc, &state).is_none());
    }

    #[test]
    fn three_chain_commit_returns_none_on_unknown_qc_block() {
        let g = Block::genesis([0; 32], [0; 32]);
        let state = HotStuffState::new(validators(), g);
        let new_qc = dummy_qc(7, [0xAB; 32]);
        assert!(three_chain_commit(&new_qc, &state).is_none());
    }

    #[test]
    fn three_chain_commit_returns_none_on_view_block_mismatch() {
        let g = Block::genesis([0; 32], [0; 32]);
        let chain = chain_from_genesis(&g, &[1, 2, 3]);
        let state = state_with_chain(&chain, g);
        // QC claims view 9 over a block whose header view is 3 → malformed.
        let bogus = dummy_qc(9, chain[2].hash());
        assert!(three_chain_commit(&bogus, &state).is_none());
    }

    #[test]
    fn three_chain_commit_handles_genesis_rooted_three_chain() {
        // Views 1, 2, 3 with genesis as parent of view 1. b1 = block at
        // view 1, committed when we QC view 3.
        let g = Block::genesis([0; 32], [0; 32]);
        let chain = chain_from_genesis(&g, &[1, 2, 3]);
        let state = state_with_chain(&chain, g);
        let new_qc = dummy_qc(3, chain[2].hash());
        let committed = three_chain_commit(&new_qc, &state).unwrap();
        assert_eq!(committed.header.view, 1);
    }
}
