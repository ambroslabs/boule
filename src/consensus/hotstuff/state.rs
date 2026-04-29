//! The data [`HotStuffState`] the safety core carries between steps.
//!
//! `HotStuffState` is deliberately a dumb struct: fields are public so
//! the tests in [`super::safety_rules`] and (in 7.C) the dispatcher in
//! `step.rs` can hand-build any state they need without going through a
//! constructor. No method here makes a safety decision — every decision
//! lives in [`super::safety_rules`].

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::consensus::View;
use crate::consensus::limits::CacheEvictionCounters;
use crate::consensus::validator_history::ValidatorSetHistory;
use crate::consensus::validator_set::ValidatorSet;
use crate::replication::block::{Block, BlockHash};

use super::qc::QuorumCertificate;

/// Tracing target for eviction logs. Same string as
/// [`crate::consensus::node::TRACE_TARGET`] so a single
/// `RUST_LOG=ambros_p2p::consensus=info` filter catches every cache
/// drop the consensus layer emits.
const TRACE_TARGET: &str = "ambros_p2p::consensus";

/// How many parent links above `high_qc.block_hash` to protect from
/// cap-based eviction. The two-chain lock-promotion walk reaches one
/// block past `high_qc`, the three-chain commit walk reaches two —
/// keeping the QC's grandparent chain pinned guarantees those walks
/// always find what they need even if the safety core is otherwise
/// thrashing under flood.
const PROTECTED_HIGH_QC_DEPTH: usize = 4;

/// The block this replica has promised (via the two-chain rule) not to
/// diverge from.
///
/// Carries the block's `view`, `height`, and `block_hash` rather than
/// the full [`QuorumCertificate`]. The safety core never reads a
/// signature set off the lock: [`super::safety_rules::safe_to_vote`]
/// inspects `view` (liveness rule) and `block_hash` (extension rule),
/// and two-chain promotion in `step::on_proposal_received` uses
/// `height` for the monotonicity check. Nothing ships the lock on the
/// wire (`NewView` carries `high_qc`). This matches how the HotStuff
/// paper's Algorithm 4 tracks the lock as a node reference — see
/// `docs/consensus/hotstuff-notes.md#the-bjustify-problem-relevant-to-b4`.
///
/// `height` is part of the lock rather than derived from
/// `pending_blocks` because views can skip (validate_structural only
/// requires `child.view > parent.view`) while heights increment by
/// one. Comparing by height for two-chain promotion keeps the
/// monotonicity Lemma 6 of the paper's Appendix B relies on; using
/// `view` would let a Byzantine proposer wedge us into a stuck state
/// by claiming a huge view on a short chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Locked {
    pub view: View,
    pub height: u64,
    pub block_hash: BlockHash,
}

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

    /// Block this replica has promised (via the two-chain rule) not to
    /// diverge from. HotStuff's *extension* rule forbids voting for any
    /// proposal whose block doesn't extend `locked.block_hash`.
    pub locked: Option<Locked>,

    /// Highest-view QC this replica has seen anywhere (proposal,
    /// NewView, freshly assembled). Used to piggyback our most recent
    /// proof of progress when we send a NewView, and as the justify
    /// for proposals we build.
    pub high_qc: Option<QuorumCertificate>,

    /// View of the most recent block this replica has voted on.
    /// Prevents double-voting within a view.
    pub last_voted_view: View,

    /// Committee the replica is operating under at the *current* view.
    /// Mirrors `validator_history.current_set()` at the boundary that
    /// most recently took effect; integration callers without a view
    /// context (e.g. block-sync peer pick) can read this as "the
    /// committee right now". Anywhere a specific view is in scope —
    /// vote tally, leader pick, QC well-formedness — read
    /// `validator_history.set_at(view)` instead, so verification does
    /// not drift across reconfiguration boundaries (#140).
    pub validator_set: ValidatorSet,

    /// View-keyed validator-set history (#248). Until #272 lands the
    /// commit-time application path this contains only the genesis
    /// boundary, so `set_at(view)` is the same set for every view and
    /// behaviour matches the pre-history single-set safety core.
    pub validator_history: ValidatorSetHistory,

    /// Blocks the replica has observed but not yet committed. Keyed by
    /// header hash (`Block::hash()`). Parent chains are walked through
    /// this map. 7.C prunes entries below the latest commit; 7.B only
    /// inserts.
    pub pending_blocks: HashMap<BlockHash, Block>,

    /// Hash of the genesis block. Recorded once at construction for
    /// convenience — walking `parent_hash` links lands at this value
    /// once, and its parent is `[0; 32]`.
    pub genesis_hash: BlockHash,

    /// Cap on `pending_blocks`. `usize::MAX` (the default) disables
    /// cap-based eviction entirely, matching pre-#135 behaviour. The
    /// integration layer overrides via
    /// [`HotStuffState::set_pending_blocks_limit`].
    pending_blocks_capacity: usize,

    /// Counter handle bumped on each cap-based eviction. Shared with
    /// the [`crate::consensus::hotstuff::step::HotStuffCore`] that
    /// owns this state so the integration layer surfaces a single
    /// aggregate count.
    eviction_counters: CacheEvictionCounters,
}

impl HotStuffState {
    /// Build a fresh state rooted at `genesis`. The genesis block is
    /// pre-inserted into `pending_blocks` so parent-walking safety
    /// predicates can terminate on it. Locked and `high_qc` start as
    /// `None`.
    pub fn new(validator_set: ValidatorSet, genesis: Block) -> Self {
        let genesis_hash = genesis.hash();
        let mut pending = HashMap::new();
        pending.insert(genesis_hash, genesis);
        let validator_history = ValidatorSetHistory::from_genesis(validator_set.clone());
        Self {
            current_view: 0,
            locked: None,
            high_qc: None,
            last_voted_view: 0,
            validator_set,
            validator_history,
            pending_blocks: pending,
            genesis_hash,
            // Default to "unbounded" so unit tests in
            // [`super::safety_rules`] and [`super::step`] keep their
            // pre-#135 behaviour. The integration layer flips this to
            // a finite cap via [`Self::set_pending_blocks_limit`] in
            // [`super::step::HotStuffCore::with_limits`].
            pending_blocks_capacity: usize::MAX,
            eviction_counters: CacheEvictionCounters::default(),
        }
    }

    /// Wire a finite cap and a shared counter handle into the
    /// `pending_blocks` map. Called by
    /// [`super::step::HotStuffCore::with_limits`] at construction so
    /// the safety state shares a single counter with the safety
    /// core's own caches.
    pub(crate) fn set_pending_blocks_limit(
        &mut self,
        capacity: usize,
        counters: CacheEvictionCounters,
    ) {
        self.pending_blocks_capacity = capacity;
        self.eviction_counters = counters;
    }

    /// Insert (or overwrite) a pending block. The key is `block.hash()`
    /// so re-inserting the same block is a cheap no-op.
    ///
    /// Cap-aware: when the map is at
    /// [`Self::pending_blocks_capacity`], the lowest-`height`
    /// non-protected block is dropped before the new entry lands.
    /// Protected blocks are the genesis block and the `high_qc`
    /// chain (up to [`PROTECTED_HIGH_QC_DEPTH`] parent hops); these
    /// are exactly the blocks the two-chain and three-chain safety
    /// walks need to terminate.
    pub fn insert_pending(&mut self, block: Block) {
        let hash = block.hash();
        if !self.pending_blocks.contains_key(&hash) {
            self.evict_pending_to_fit_one();
        }
        self.pending_blocks.insert(hash, block);
    }

    /// Lookup a pending block by its header hash.
    pub fn get_pending(&self, hash: &BlockHash) -> Option<&Block> {
        self.pending_blocks.get(hash)
    }

    /// Drop the lowest-`height` non-protected entry if `pending_blocks`
    /// is at cap. No-op when the cap is `usize::MAX` (unit-test
    /// default) or when there is space for one more block.
    fn evict_pending_to_fit_one(&mut self) {
        if self.pending_blocks.len() < self.pending_blocks_capacity {
            return;
        }
        let protected = self.protected_block_hashes();
        // Eviction key: `(height, hash)`. Tie-break on hash so two
        // forks at the same height pick the same victim across
        // replicas — useful when reasoning about deterministic
        // replays under flood, even though the safety core itself
        // never depends on `pending_blocks` ordering.
        let Some((victim_hash, victim_height)) = self
            .pending_blocks
            .iter()
            .filter(|(hash, _)| !protected.contains(*hash))
            .map(|(hash, block)| (*hash, block.header.height))
            .min_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)))
        else {
            // Every block is protected (genesis + the full high_qc
            // chain reaches the cap). The new insert is allowed
            // anyway; the cap is a soft target, not a hard ceiling
            // when honoring it would compromise safety walks.
            tracing::info!(
                target: TRACE_TARGET,
                cache = "pending_blocks",
                policy = "cap_skipped_all_protected",
                cap = self.pending_blocks_capacity,
                size = self.pending_blocks.len(),
                "consensus_cache_evicted",
            );
            return;
        };
        if self.pending_blocks.remove(&victim_hash).is_some() {
            self.eviction_counters.inc_pending_blocks(1);
            tracing::info!(
                target: TRACE_TARGET,
                cache = "pending_blocks",
                policy = "cap",
                evicted_height = victim_height,
                cap = self.pending_blocks_capacity,
                size_after = self.pending_blocks.len(),
                "consensus_cache_evicted",
            );
        }
    }

    /// Set of hashes that must NOT be evicted: genesis, plus up to
    /// [`PROTECTED_HIGH_QC_DEPTH`] blocks reachable via `parent_hash`
    /// links from `high_qc.block_hash`.
    fn protected_block_hashes(&self) -> std::collections::HashSet<BlockHash> {
        let mut out = std::collections::HashSet::new();
        out.insert(self.genesis_hash);
        if let Some(qc) = &self.high_qc {
            let mut cursor = qc.block_hash;
            for _ in 0..PROTECTED_HIGH_QC_DEPTH {
                if !out.insert(cursor) {
                    break;
                }
                let Some(b) = self.pending_blocks.get(&cursor) else {
                    break;
                };
                cursor = b.header.parent_hash;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::NodeId;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn vid(b: u8) -> crate::consensus::validator_set::ValidatorId {
        crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(nid(b))
    }

    #[test]
    fn new_seeds_genesis_into_pending() {
        let vs = ValidatorSet::new(vec![vid(1), vid(2), vid(3), vid(4)]);
        let genesis = Block::genesis([0x77; 32], [0; 32]);
        let g_hash = genesis.hash();
        let state = HotStuffState::new(vs.clone(), genesis.clone());
        assert_eq!(state.current_view, 0);
        assert_eq!(state.last_voted_view, 0);
        assert!(state.locked.is_none());
        assert!(state.high_qc.is_none());
        assert_eq!(state.genesis_hash, g_hash);
        assert_eq!(state.get_pending(&g_hash), Some(&genesis));
    }

    #[test]
    fn insert_pending_is_idempotent() {
        let vs = ValidatorSet::new(vec![vid(1)]);
        let genesis = Block::genesis([0; 32], [0; 32]);
        let mut state = HotStuffState::new(vs, genesis.clone());
        let before = state.pending_blocks.len();
        state.insert_pending(genesis.clone());
        state.insert_pending(genesis);
        assert_eq!(state.pending_blocks.len(), before);
    }
}
