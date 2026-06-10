use std::collections::HashMap;

use crate::limits::{CacheEvictionCounters, CacheLimits};
use crate::replication::block::{Block, BlockHash};
use crate::{Height, View};
use boule_core::crypto::signed::Signed;
use boule_core::identity::NodeId;

use super::qc::{ConsensusMsg, NewView, Proposal, QuorumCertificate, VerifiedQc, Vote};
use super::safety_rules::{safe_to_vote, should_update_high_qc, three_chain_commit};
use super::state::{HotStuffState, Locked};
use crate::validator_set::{ValidatorId, ValidatorSet};
use boule_core::crypto::sig_scheme::BlsPartialSig;

const TRACE_TARGET: &str = "boule_core::consensus";

mod block_sync;
mod eviction;
mod handlers;
mod proposal;
mod types;
pub use types::*;

pub struct HotStuffCore {
    self_id: NodeId,
    state: HotStuffState,

    vote_bucket: HashMap<(View, BlockHash), QuorumCertificate>,

    vote_dedupe: HashMap<(View, ValidatorId), BlockHash>,

    proposal_dedupe: HashMap<(View, ValidatorId), BlockHash>,

    parked_proposals: HashMap<BlockHash, Signed<Proposal>>,

    block_sync_inflight: HashMap<BlockHash, BlockSyncInflight>,

    proposed_in_view: View,

    limits: CacheLimits,

    eviction_counters: CacheEvictionCounters,
}

#[derive(Debug, Clone, Copy)]
struct BlockSyncInflight {
    original_sender: NodeId,

    attempts: u32,

    last_asked_view: View,

    expected_height: Height,
}

impl HotStuffCore {
    pub fn new(self_id: NodeId, state: HotStuffState) -> Self {
        Self::with_limits(
            self_id,
            state,
            CacheLimits::unbounded_for_tests(),
            CacheEvictionCounters::default(),
        )
    }

    pub fn with_limits(
        self_id: NodeId,
        mut state: HotStuffState,
        limits: CacheLimits,
        eviction_counters: CacheEvictionCounters,
    ) -> Self {
        state.set_pending_blocks_limit(limits.pending_blocks_capacity, eviction_counters.clone());
        Self {
            self_id,
            state,
            vote_bucket: HashMap::new(),
            vote_dedupe: HashMap::new(),
            proposal_dedupe: HashMap::new(),
            parked_proposals: HashMap::new(),
            block_sync_inflight: HashMap::new(),
            proposed_in_view: View::ZERO,
            limits,
            eviction_counters,
        }
    }

    pub fn with_proposed_in_view(mut self, view: View) -> Self {
        self.proposed_in_view = view;
        self
    }

    pub fn proposed_in_view(&self) -> View {
        self.proposed_in_view
    }

    pub fn eviction_counters(&self) -> &CacheEvictionCounters {
        &self.eviction_counters
    }

    pub fn self_id(&self) -> NodeId {
        self.self_id
    }

    pub fn state(&self) -> &HotStuffState {
        &self.state
    }

    pub fn insert_validator_boundary(
        &mut self,
        v_eff: View,
        set: ValidatorSet,
    ) -> anyhow::Result<()> {
        let new_set = set.clone();
        self.state.validator_history.insert_boundary(v_eff, set)?;
        if v_eff <= self.state.current_view {
            self.state.validator_set = new_set;
        }
        Ok(())
    }

    pub fn vote_buckets(&self) -> impl Iterator<Item = (&(View, BlockHash), &QuorumCertificate)> {
        self.vote_bucket.iter()
    }

    pub fn parked_proposals(&self) -> impl Iterator<Item = &Signed<Proposal>> {
        self.parked_proposals.values()
    }

    pub fn insert_pending_block(&mut self, block: Block) {
        let hash = block.hash();
        self.state.insert_pending(block);
        self.block_sync_inflight.remove(&hash);
    }

    pub fn set_high_qc(&mut self, qc: VerifiedQc) {
        self.state.high_qc = Some(qc);
    }

    #[must_use = "callers must flush the returned Persist actions atomically; see audit finding 4-3"]
    pub fn adopt_snapshot(
        &mut self,
        snapshot_block: Block,
        commit_qc: VerifiedQc,
        snapshot_view: View,
    ) -> Vec<Action> {
        let block_hash = snapshot_block.hash();
        let height = snapshot_block.header.height;
        self.state.insert_pending(snapshot_block);
        let locked = super::Locked {
            view: snapshot_view,
            height,
            block_hash,
        };
        self.state.locked = Some(locked);
        self.state.high_qc = Some(commit_qc.clone());
        if snapshot_view > self.state.last_voted_view {
            self.state.last_voted_view = snapshot_view;
        }
        vec![
            Action::Persist(StateUpdate::VotedInView {
                view: snapshot_view,
            }),
            Action::Persist(StateUpdate::Locked(locked)),
            Action::Persist(StateUpdate::HighQc(commit_qc.into_inner())),
        ]
    }

    pub fn step(&mut self, event: Event) -> Vec<Action> {
        let actions = match event {
            Event::ProposalReceived(verified) => {
                let (signed, leader_id) = verified.into_parts();
                let view = signed.payload.block.header.view;
                let block_hash = signed.payload.block.hash();
                let mut actions = Vec::new();
                if let Some(ev) = self.check_proposal_dedupe(view, leader_id, block_hash) {
                    actions.push(ev);
                }
                actions.extend(self.on_proposal_received(signed));
                actions
            }
            Event::VoteReceived(variant) => self.on_vote_received(variant),
            Event::NewViewReceived(verified) => self.on_new_view_received(verified.into_inner()),
            Event::PacemakerAdvance(v) => self.on_pacemaker_advance(v),
        };

        #[cfg(debug_assertions)]
        debug_assert_lock_durable_before_vote(&actions);

        actions
    }

    pub fn replay(mut self, events: impl IntoIterator<Item = Event>) -> Vec<Vec<Action>> {
        events.into_iter().map(|e| self.step(e)).collect()
    }
}

#[cfg(debug_assertions)]
fn debug_assert_lock_durable_before_vote(actions: &[Action]) {
    let mut seen_vote_at: Option<usize> = None;
    for (i, action) in actions.iter().enumerate() {
        match action {
            Action::Broadcast(ConsensusMsg::Vote(_)) => {
                seen_vote_at.get_or_insert(i);
            }
            Action::Persist(StateUpdate::Locked(_)) => {
                debug_assert!(
                    seen_vote_at.is_none(),
                    "audit invariant I4 violated: Persist(StateUpdate::Locked) at index {i} \
                     emitted after Broadcast(Vote) at index {} in the same step output \
                     ({} actions). The lock would persist after the vote leaves the wire, \
                     re-opening the amnesia window of audit finding 4-1 (#405): {actions:?}",
                    seen_vote_at.unwrap(),
                    actions.len(),
                );
            }
            _ => {}
        }
    }
}

fn round_robin_leader(vs: &ValidatorSet, view: View) -> NodeId {
    let len = vs.len();
    debug_assert!(len > 0, "validator set must be non-empty");

    vs.get((view.0 as usize) % len)
        .expect("validator set is non-empty")
        .into_node_id()
}

fn block_sync_backoff_views(attempts: u32, initial: u64, max: u64) -> u64 {
    if attempts == 0 || initial == 0 {
        return 0;
    }
    let shift = (attempts - 1).min(63);
    let raw = initial.checked_shl(shift).unwrap_or(u64::MAX);
    raw.min(max)
}

fn pick_block_sync_peer(
    original_sender: NodeId,
    attempts: u32,
    per_peer_attempts: u32,
    validator_set: &ValidatorSet,
    self_id: NodeId,
) -> NodeId {
    let per_peer = per_peer_attempts.max(1);

    let next_attempt = attempts.saturating_add(1);
    let round = ((next_attempt - 1) / per_peer) as usize;
    if round == 0 {
        return original_sender;
    }
    let len = validator_set.len();
    if len == 0 {
        return original_sender;
    }

    let sender_vid = crate::validator_set::ValidatorId::from_genesis_pubkey(original_sender);
    let sender_idx = validator_set.index_of(&sender_vid).unwrap_or(0);

    let mut ring: Vec<NodeId> = Vec::with_capacity(len);
    for offset in 1..=len {
        let candidate = validator_set
            .get((sender_idx + offset) % len)
            .expect("validator_set indexing in bounds")
            .into_node_id();
        if candidate != self_id {
            ring.push(candidate);
        }
    }
    if ring.is_empty() {
        return original_sender;
    }
    ring[(round - 1) % ring.len()]
}
