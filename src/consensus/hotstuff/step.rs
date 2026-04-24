//! HotStuff safety-core state machine.
//!
//! 7.A gave us the wire payload types in [`super::qc`]; 7.B gave us the
//! pure predicates over [`super::state::HotStuffState`]; this module
//! (7.C / #93) composes them into the `Event → Vec<Action>` dispatcher
//! that is the entire public API of the safety core.
//!
//! # Scaffolding
//!
//! The current commit only lays down the type skeleton (items A1–A6 of
//! the breakdown on #93) so downstream commits can fill in dispatch one
//! branch at a time. `step()` is a stub returning `Vec::new()`; every
//! dispatch rule is introduced by a later commit alongside the unit
//! test that pins its behavior.
//!
//! # Purity
//!
//! Everything here is deliberately I/O-free: no `tokio`, no
//! [`crate::clock::Clock`], no storage, no network. Inputs are
//! [`Event`]s; outputs are [`Action`]s. Signatures on inbound
//! [`Signed`] payloads are assumed verified by the integration layer
//! (#24) before `step` is called — the core trusts the envelope so
//! replay harnesses can feed a deterministic trace without recomputing
//! Ed25519.
//!
//! [`Signed`]: crate::crypto::signed::Signed

use std::collections::HashMap;
use std::sync::Arc;

use crate::consensus::View;
use crate::crypto::signed::Signed;
use crate::p2p::NodeId;
use crate::replication::block::{Block, BlockHash};

use super::qc::{ConsensusMsg, NewView, Proposal, QuorumCertificate, Vote};
use super::safety_rules::{safe_to_vote, should_update_high_qc, three_chain_commit};
use super::state::{HotStuffState, Locked};
use crate::consensus::validator_set::ValidatorSet;

/// Inputs the safety core reacts to.
///
/// Every cause of a state change goes through one of these variants —
/// `step()` is a total function of `(HotStuffCore, Event) -> Vec<Action>`.
///
/// `PacemakerAdvance` is the one variant the core never produces from
/// its own outputs: it is injected by the integration layer when the
/// pacemaker (#88) fires `AdvanceToView`, severing the liveness and
/// safety halves cleanly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A signed proposal arrived on the wire.
    ProposalReceived(Signed<Proposal>),
    /// A signed vote arrived on the wire. Only meaningful to the leader
    /// of `vote.view + 1`; other replicas drop it in [`HotStuffCore::step`].
    VoteReceived(Signed<Vote>),
    /// A signed `NewView` arrived on the wire.
    NewViewReceived(Signed<NewView>),
    /// The pacemaker has advanced the local view. Never emitted by the
    /// safety core itself — always injected from the integration layer
    /// after a pacemaker `AdvanceToView` fires.
    PacemakerAdvance(View),
}

/// A durable state change the integration layer must persist (WAL /
/// on-disk state) so the same value survives a restart.
///
/// `StateUpdate`s are produced, never consumed, by the safety core. The
/// core updates its own in-memory [`super::state::HotStuffState`]
/// immediately and emits the corresponding `StateUpdate` so the driver
/// can mirror the change durably before any outbound `Action` that
/// depends on it leaves the machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateUpdate {
    /// Replica voted in `view`. Persist so we never double-vote across
    /// restarts — the safety property of HotStuff depends on this
    /// survivor guarantee.
    VotedInView { view: View },
    /// Replica promoted its lock via the two-chain rule. Only the
    /// (view, block_hash) pair is durable — the safety core never
    /// reads signer data off the lock, and nothing ships it on the
    /// wire (`NewView` carries `high_qc`, not the lock). See
    /// `docs/consensus/hotstuff-notes.md#the-bjustify-problem-relevant-to-b4`.
    Locked(Locked),
    /// Replica adopted a fresher `high_qc` (seen via a proposal's
    /// justify, a freshly-formed QC, or a `NewView`).
    HighQc(QuorumCertificate),
}

/// Effects the safety core asks the integration layer to perform.
///
/// The core never performs these itself; it returns them from `step`
/// and the integration layer (#24) translates each variant into real
/// side effects (broadcasting bytes, syncing the WAL, committing to the
/// state machine). The emission order within a single `step` call is
/// deterministic and is part of the tested surface — later commits
/// introduce that ordering alongside the unit tests that pin it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send `msg` to every validator in the set.
    Broadcast(ConsensusMsg),
    /// Send `msg` to a single validator. Used for votes addressed to
    /// the leader of the next view.
    SendTo(NodeId, ConsensusMsg),
    /// Persist `update` durably before any outbound network effect that
    /// semantically depends on it is flushed.
    Persist(StateUpdate),
    /// Commit `block` to the state machine. Emitted when the three-chain
    /// rule fires on a freshly-adopted QC.
    Commit(Block),
    /// Parent of a received proposal is not in `pending_blocks`; ask
    /// the named peer for the block identified by the hash. The peer is
    /// typically the sender of the proposal that couldn't be resolved.
    RequestBlock(BlockHash, NodeId),
}

/// Integration-layer hook that turns "I am the leader and I have a
/// fresh justify-QC" into a concrete [`Block`].
///
/// The safety core never invents block contents — that's the mempool's
/// and state machine's job. Keeping this as a trait (rather than a
/// hard-coded dependency on either) preserves the #21 swap-components
/// story and keeps `HotStuffCore` unit-testable in isolation.
///
/// # Determinism
///
/// Implementations used under [`HotStuffCore::replay`] or the property
/// test **must** be deterministic for a given `(parent, view, high_qc)`
/// triple. Non-determinism here would let the property-test shrinker
/// produce seeds that fail irreproducibly, which defeats the whole
/// point of seed-based regression capture.
///
/// [`HotStuffCore::replay`]: HotStuffCore::replay
pub trait BlockBuilder: Send + Sync {
    /// Produce a child block extending `parent` at `view` with
    /// `high_qc` as the proposal's justify. Implementations fill in
    /// `header.proposer` from context known to the integration layer;
    /// the safety core does not thread its own `NodeId` in here.
    fn build(&self, parent: &Block, view: View, high_qc: &QuorumCertificate) -> Block;
}

/// HotStuff safety core: the `Event → Vec<Action>` state machine.
///
/// Construct with the local [`NodeId`], an initial [`HotStuffState`],
/// and a [`BlockBuilder`] the integration layer plugs in. Drive it by
/// calling [`step`] for each event; the returned actions are the
/// integration layer's to carry out.
///
/// # Purity
///
/// No `tokio`, no clock, no storage, no network. The machine is
/// deterministic: identical `(state, event-sequence)` inputs produce
/// identical `Vec<Vec<Action>>` outputs — which is exactly what
/// [`replay`] exploits to turn a failing property-test seed into a
/// reproducible regression.
///
/// [`step`]: HotStuffCore::step
/// [`replay`]: HotStuffCore::replay
pub struct HotStuffCore {
    self_id: NodeId,
    state: HotStuffState,
    /// Partial QCs the leader is accumulating, keyed by
    /// `(vote.view, vote.block_hash)`. A bucket becomes a full QC once
    /// `signer_count >= quorum_size(validator_set.len())`.
    vote_bucket: HashMap<(View, BlockHash), QuorumCertificate>,
    /// Proposals we received before their parent landed. Keyed by the
    /// proposal's own block hash so a later `PacemakerAdvance` can
    /// re-evaluate every parked child whose parent has since arrived.
    parked_proposals: HashMap<BlockHash, Signed<Proposal>>,
    builder: Arc<dyn BlockBuilder>,
}

impl HotStuffCore {
    /// Build a fresh core around `state`, with `builder` supplying
    /// block contents when this replica is the leader.
    pub fn new(self_id: NodeId, state: HotStuffState, builder: Arc<dyn BlockBuilder>) -> Self {
        Self {
            self_id,
            state,
            vote_bucket: HashMap::new(),
            parked_proposals: HashMap::new(),
            builder,
        }
    }

    /// The local node's identity, as supplied at construction.
    pub fn self_id(&self) -> NodeId {
        self.self_id
    }

    /// Borrow the current safety-core state. Read-only by design — the
    /// only way to mutate is through [`step`].
    ///
    /// [`step`]: HotStuffCore::step
    pub fn state(&self) -> &HotStuffState {
        &self.state
    }

    /// React to `event` and return the [`Action`]s the integration
    /// layer must carry out, in emission order.
    ///
    /// Dispatch lands one branch at a time; the rules for events whose
    /// branches aren't in place yet return an empty vector (a harmless
    /// safe-by-default).
    pub fn step(&mut self, event: Event) -> Vec<Action> {
        match event {
            Event::ProposalReceived(signed) => self.on_proposal_received(signed),
            Event::VoteReceived(signed) => self.on_vote_received(signed),
            Event::NewViewReceived(signed) => self.on_new_view_received(signed),
            Event::PacemakerAdvance(v) => self.on_pacemaker_advance(v),
        }
    }

    /// Handle an inbound [`Proposal`]. Branches land in separate
    /// commits per the #93 breakdown.
    fn on_proposal_received(&mut self, signed: Signed<Proposal>) -> Vec<Action> {
        let parent_hash = signed.payload.block.header.parent_hash;
        // B1: parent isn't in `pending_blocks` — we can't evaluate
        // extension against our locked block without it. Ask the
        // sender for the missing block and park the child so a later
        // `PacemakerAdvance` (or explicit re-drive) can re-run
        // dispatch once the parent arrives.
        if !self.state.pending_blocks.contains_key(&parent_hash) {
            let child_hash = signed.payload.block.hash();
            let sender = signed.signer;
            self.parked_proposals.insert(child_hash, signed);
            return vec![Action::RequestBlock(parent_hash, sender)];
        }

        // B2: insert the proposed block into `pending_blocks` so the
        // `safe_to_vote` extension walk has something to follow, then
        // run the predicate.
        self.state.insert_pending(signed.payload.block.clone());

        let mut actions = Vec::new();
        if safe_to_vote(&signed.payload, &self.state) {
            let view = signed.payload.block.header.view;
            let block_hash = signed.payload.block.hash();

            // Persist the vote-view before anything fires on the wire:
            // the survivor guarantee HotStuff safety rests on is that
            // a restarted replica never votes twice at the same view.
            self.state.last_voted_view = view;
            actions.push(Action::Persist(StateUpdate::VotedInView { view }));

            // B3: adopt the proposal's justify as `high_qc` if it's
            // strictly fresher. Gating this on `safe_to_vote` firing
            // is deliberate — if we rejected the proposal we
            // wouldn't vote on its chain, and we shouldn't trust its
            // justify either. The independent NewView path in C3
            // provides a separate adoption route when we trust the
            // sender but haven't seen a proposal.
            if should_update_high_qc(&signed.payload.justify, &self.state) {
                let qc = signed.payload.justify.clone();
                self.state.high_qc = Some(qc.clone());
                actions.push(Action::Persist(StateUpdate::HighQc(qc)));
            }

            // Send the vote to the next-view leader, who will assemble
            // the QC and use it as the justify of the next proposal.
            let next_leader = round_robin_leader(&self.state.validator_set, view + 1);
            actions.push(Action::SendTo(
                next_leader,
                ConsensusMsg::Vote(Vote { view, block_hash }),
            ));
        }

        // B4: Two-Chain lock promotion.
        //
        // Walk `b* → b'' (parent, in pending_blocks thanks to B1/B2) →
        // b' (grandparent, present only if we saw the proposal that
        // originally proposed b'')`. If `b'` exists and sits at a
        // strictly greater height than our current lock, promote —
        // emit `Persist(Locked(..))` and mirror the update on
        // `state.locked`.
        //
        // Runs regardless of `safe_to_vote` firing: the paper's
        // Algorithm 4 runs `update(bnew)` unconditionally, and the
        // safety proof (Appendix B, Lemma 6) covers unconditional
        // lock updates. Refusing to update here would turn a liveness
        // concern into a safety one — we'd stay stuck on an older
        // lock even when a fresher one is demonstrably safer.
        //
        // Height-based comparison follows the paper; using view would
        // let a Byzantine proposer wedge us with a short chain
        // claiming a huge view. See
        // `docs/consensus/hotstuff-notes.md#the-chain-rules`.
        let two_chain_candidate: Option<Locked> = self
            .state
            .pending_blocks
            .get(&parent_hash)
            .and_then(|b_prime_prime| {
                let grandparent_hash = b_prime_prime.header.parent_hash;
                self.state
                    .pending_blocks
                    .get(&grandparent_hash)
                    .map(|b_prime| Locked {
                        view: b_prime.header.view,
                        height: b_prime.header.height,
                        block_hash: grandparent_hash,
                    })
            });
        if let Some(candidate) = two_chain_candidate {
            // Treat a missing lock as "height 0" for the monotonicity
            // check: the paper initializes `block ← b0` (genesis,
            // height 0), so promoting to a positive-height `b'`
            // matches, and locking on genesis stays a no-op.
            let current_height = self.state.locked.map(|l| l.height).unwrap_or(0);
            if candidate.height > current_height {
                self.state.locked = Some(candidate);
                actions.push(Action::Persist(StateUpdate::Locked(candidate)));
            }
        }

        // B5: Three-Chain commit.
        //
        // Feed the proposal's justify (a QC over `b''`) to
        // `three_chain_commit`; if it fires, `b` — the
        // great-grandparent — is committed. The predicate is strict:
        // it requires `b2.view + 1 == b3.view` and `b1.view + 1 ==
        // b2.view`, which in our no-dummy-nodes world is the direct-
        // parent chain Appendix B.1 ("Why direct parent") warns must
        // not be relaxed. Unlike B4 (lock), weakening the commit
        // check actively breaks safety, not just liveness.
        //
        // On commit, prune `pending_blocks` of every entry at or
        // below the committed height. The committed block is
        // decided, and nothing in the safety rules needs to walk
        // past it: `safe_to_vote`'s extension walks stop at the
        // lock (which sits strictly above the commit), and future
        // three-chain / two-chain walks only reach back three
        // blocks. Retaining older entries would leak memory
        // unboundedly.
        if let Some(committed) = three_chain_commit(&signed.payload.justify, &self.state) {
            let commit_height = committed.header.height;
            actions.push(Action::Commit(committed));
            self.state
                .pending_blocks
                .retain(|_, b| b.header.height > commit_height);
        }

        actions
    }

    /// Handle an inbound [`Vote`]. Only meaningful to the leader of
    /// `vote.view + 1`; other replicas drop. When the added partial
    /// signature takes a bucket across quorum for the first time, the
    /// leader adopts the freshly-formed QC as `high_qc` (emitting
    /// `Persist(HighQc)`) and broadcasts a new [`Proposal`] that
    /// carries the QC as its justify.
    ///
    /// Mirrors Algorithm 4's `onReceiveVote` (paper §6), with the
    /// onBeat-triggered `onPropose` collapsed into the same step.
    /// That collapse is acceptable for the safety core — the
    /// integration layer (#24) can choose to batch proposals
    /// application-side by queueing multiple votes before forwarding
    /// to `step`.
    fn on_vote_received(&mut self, signed: Signed<Vote>) -> Vec<Action> {
        let vote = &signed.payload;

        // C1a: only the leader of the next view cares about this vote.
        // The QC this vote contributes to is the justify for that
        // leader's next proposal.
        let next_view = vote.view + 1;
        if round_robin_leader(&self.state.validator_set, next_view) != self.self_id {
            return Vec::new();
        }

        // C1b: the voter must be a known validator; otherwise we have
        // no index into the `SignerBitmap`. A well-behaved integration
        // layer already filters these in signature verification, but
        // we repeat the check here for defence-in-depth against a
        // replay or test-wiring bug.
        let Some(voter_idx) = self.state.validator_set.index_of(&signed.signer) else {
            return Vec::new();
        };

        // C1c: accumulate into the bucket for this `(view, block_hash)`
        // pair. `QuorumCertificate::add_signature` is idempotent on
        // the set-bit — duplicate votes from the same signer are
        // no-ops.
        let key = (vote.view, vote.block_hash);
        let validator_set_len = self.state.validator_set.len();
        let qc = self.vote_bucket.entry(key).or_insert_with(|| {
            QuorumCertificate::new(vote.view, vote.block_hash, validator_set_len)
        });
        let had_quorum = qc.has_quorum(&self.state.validator_set);
        qc.add_signature(voter_idx, signed.sig);
        let has_quorum_now = qc.has_quorum(&self.state.validator_set);

        // C2: only fire on the transition from sub-quorum to quorum.
        // Late votes arriving after the QC formed are absorbed
        // silently: `add_signature` idempotently ignores set bits,
        // `has_quorum` stays true, so this block is skipped.
        if had_quorum || !has_quorum_now {
            return Vec::new();
        }

        let formed = qc.clone();
        let mut actions = Vec::new();

        // Adopt as `high_qc` if strictly fresher, mirroring the
        // `updateQCHigh(qc)` call at the end of `onReceiveVote`
        // in the paper's Algorithm 4.
        if should_update_high_qc(&formed, &self.state) {
            self.state.high_qc = Some(formed.clone());
            actions.push(Action::Persist(StateUpdate::HighQc(formed.clone())));
        }

        // Propose the next block if we have the parent on hand.
        // In normal operation the leader also previously received
        // the proposal for `block_hash`; edge cases where we don't
        // have it (leader restart, etc.) safely skip the broadcast
        // — the pacemaker handles the resulting view stall via its
        // usual timeout path.
        if let Some(parent) = self.state.pending_blocks.get(&formed.block_hash).cloned() {
            let new_block = self.builder.build(&parent, next_view, &formed);
            actions.push(Action::Broadcast(ConsensusMsg::Proposal(Proposal {
                block: new_block,
                justify: formed,
            })));
        }

        actions
    }

    /// Handle an inbound [`NewView`]. Other replicas' way of telling
    /// us "here's the highest QC I've seen". If it beats our current
    /// `high_qc`, adopt — emit `Persist(HighQc(..))`. Otherwise ignore.
    ///
    /// This is the out-of-band adoption path that's intentionally not
    /// gated on `safe_to_vote` (unlike B3): we trust the sender
    /// exactly as much as we trust any validator handing us a QC,
    /// which is "as much as the integration layer verified the
    /// envelope". The QC itself carries its own quorum proof;
    /// `should_update_high_qc`'s strict view comparison prevents the
    /// stalest-writes-win anti-pattern.
    fn on_new_view_received(&mut self, signed: Signed<NewView>) -> Vec<Action> {
        let qc = signed.payload.high_qc;
        if !should_update_high_qc(&qc, &self.state) {
            return Vec::new();
        }
        self.state.high_qc = Some(qc.clone());
        vec![Action::Persist(StateUpdate::HighQc(qc))]
    }

    /// Handle a [`Event::PacemakerAdvance(v)`] signal from the outer
    /// driver. Three things happen, in order:
    ///
    /// 1. Record the new view on `state.current_view`. The safety
    ///    core never advances views on its own — this is the only
    ///    path that writes `current_view`, so the pacemaker stays
    ///    authoritative over liveness.
    /// 2. Re-evaluate `parked_proposals`: any entry whose parent is
    ///    now in `pending_blocks` gets its proposal re-dispatched
    ///    through `on_proposal_received`. Nested re-parking is
    ///    handled by `on_proposal_received`'s B1 branch.
    /// 3. If we have a `high_qc` to advertise, emit
    ///    `Broadcast(ConsensusMsg::NewView { high_qc })`. At startup
    ///    before any proposal has landed, `high_qc` is `None` and we
    ///    skip the broadcast — `NewView` has no `Option<QC>` to
    ///    fall back on, and an all-zero synthesized QC would mislead
    ///    anyone receiving it. In practice a real node sees the
    ///    first proposal before the first pacemaker-driven view
    ///    change, so this window is narrow.
    ///
    /// Emission order: un-park retry actions first (any
    /// `Persist`/`SendTo`/`Broadcast` they produce), then the
    /// `Broadcast(NewView)` sentinel last.
    fn on_pacemaker_advance(&mut self, v: View) -> Vec<Action> {
        self.state.current_view = v;

        let mut actions = Vec::new();

        // Un-park retries. Collect child hashes whose parent has since
        // arrived, then drain-and-re-dispatch them one at a time. The
        // two-step (collect, then remove+re-run) avoids holding an
        // immutable borrow on `parked_proposals` while
        // `on_proposal_received` mutates `self`.
        let ready: Vec<BlockHash> = self
            .parked_proposals
            .iter()
            .filter_map(|(child_hash, signed)| {
                let parent_hash = signed.payload.block.header.parent_hash;
                if self.state.pending_blocks.contains_key(&parent_hash) {
                    Some(*child_hash)
                } else {
                    None
                }
            })
            .collect();
        for child_hash in ready {
            if let Some(signed) = self.parked_proposals.remove(&child_hash) {
                let retry_actions = self.on_proposal_received(signed);
                actions.extend(retry_actions);
            }
        }

        if let Some(high_qc) = self.state.high_qc.clone() {
            actions.push(Action::Broadcast(ConsensusMsg::NewView(NewView {
                high_qc,
            })));
        }

        actions
    }

    /// Feed a trace of events through `step` in order, returning one
    /// `Vec<Action>` per event. Consumes `self` so callers can't
    /// accidentally keep a reference into the core across the replay.
    pub fn replay(mut self, events: impl IntoIterator<Item = Event>) -> Vec<Vec<Action>> {
        events.into_iter().map(|e| self.step(e)).collect()
    }
}

/// Round-robin leader for `view` over `vs`. Mirrors
/// [`crate::consensus::pacemaker::leader::RoundRobinSelector`]. The
/// safety core doesn't own an `Arc<dyn LeaderSelector>` in milestone
/// 7.C because its constructor doesn't take one; this keeps the two
/// modules from having to agree on a selector instance. Swappable
/// selectors are the integration layer's job (#24).
fn round_robin_leader(vs: &ValidatorSet, view: View) -> NodeId {
    let len = vs.len();
    debug_assert!(len > 0, "validator set must be non-empty");
    *vs.get((view as usize) % len)
        .expect("validator set is non-empty")
}

#[cfg(test)]
mod tests {
    //! Unit tests and the shared fixtures they build on.
    //!
    //! We hand-construct `Signed<T>` envelopes rather than signing with
    //! real Ed25519 keys: the safety core explicitly does **not**
    //! verify signatures (that's the integration layer's job per #24),
    //! so tests can put any byte pattern in the `sig` field and the
    //! core will trust it. The upside is determinism — no keypair
    //! generation in hot test paths — and the downside is that these
    //! envelopes would be rejected on the wire, which is exactly the
    //! boundary we want.
    //!
    //! `TestBlockBuilder` and friends live here rather than in a
    //! separate `testing` submodule because clippy's
    //! `items_after_test_module` forbids a second top-level test
    //! module past this one; keeping everything under a single
    //! `#[cfg(test)] mod tests` root makes room for future `mod
    //! property` additions as nested submodules.

    use super::*;
    use crate::consensus::validator_set::ValidatorSet;
    use crate::replication::block::BlockHeader;

    // ── Fixture constants and helpers ────────────────────────────────

    /// Stand-in [`NodeId`] constructor. Tests only ever identify nodes
    /// by the discriminator byte, so `nid(3)` is shorthand for the
    /// all-`0x03` node id that sorts into position 2 of the canonical
    /// four-validator set.
    pub(crate) fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    /// The canonical four-validator set used across the step tests.
    /// Sorted order matches the byte value: `[nid(1), nid(2), nid(3), nid(4)]`.
    pub(crate) fn validators() -> ValidatorSet {
        ValidatorSet::new(vec![nid(1), nid(2), nid(3), nid(4)])
    }

    /// Build a [`Signed<Vote>`] whose `sig` bytes are
    /// `[sender[0]; 64]` — distinct per sender so tests can inspect
    /// QC signature ordering if needed. The core doesn't verify
    /// signatures; any byte pattern is accepted.
    pub(crate) fn signed_vote(view: View, block_hash: BlockHash, sender: NodeId) -> Signed<Vote> {
        Signed {
            payload: Vote { view, block_hash },
            signer: sender,
            sig: [sender[0]; 64],
        }
    }

    /// Build a [`Signed<NewView>`] from `sender` carrying `high_qc`.
    /// Same zero-verification stance as the proposal/vote helpers.
    pub(crate) fn signed_newview(high_qc: QuorumCertificate, sender: NodeId) -> Signed<NewView> {
        Signed {
            payload: NewView { high_qc },
            signer: sender,
            sig: [0u8; 64],
        }
    }

    /// Build an all-zero-signature [`Signed<Proposal>`] from `sender`.
    /// The safety core never verifies the envelope; the `sig` bytes
    /// are deliberately meaningless so tests stay deterministic.
    pub(crate) fn signed_proposal(
        block: Block,
        justify: QuorumCertificate,
        sender: NodeId,
    ) -> Signed<Proposal> {
        Signed {
            payload: Proposal { block, justify },
            signer: sender,
            sig: [0u8; 64],
        }
    }

    /// Build a skeletal [`QuorumCertificate`] — right view and block
    /// hash, no signatures populated — sized for the canonical
    /// four-validator set. Adequate for the safety-rule predicates
    /// because they only read `view` / `block_hash`.
    pub(crate) fn dummy_qc(view: View, block_hash: BlockHash) -> QuorumCertificate {
        QuorumCertificate::new(view, block_hash, validators().len())
    }

    /// Chain `views` blocks onto `genesis`, each parented to its
    /// predecessor; `views[0]` becomes genesis's child. Height advances
    /// alongside the index so the chain respects
    /// [`crate::replication::block::validate_structural`].
    ///
    /// `proposer` is stamped into every header; callers that need a
    /// per-block proposer can mutate the returned blocks.
    pub(crate) fn chain_from_genesis(
        genesis: &Block,
        views: &[View],
        proposer: NodeId,
    ) -> Vec<Block> {
        let mut out = Vec::with_capacity(views.len());
        let mut parent_hash = genesis.hash();
        for (i, &view) in views.iter().enumerate() {
            let height = genesis.header.height + (i as u64) + 1;
            let header = BlockHeader {
                parent_hash,
                height,
                view,
                proposer,
                state_commitment: [0; 32],
                commands_commitment: Block::commands_commitment(&[]),
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

    /// Deterministic [`BlockBuilder`] used wherever a core's
    /// leader-path needs a block stamped out. Stamps an empty-commands
    /// child with zero `state_commitment` — the execution layer is
    /// out of scope here.
    pub(crate) struct TestBlockBuilder {
        pub proposer: NodeId,
    }

    impl BlockBuilder for TestBlockBuilder {
        fn build(&self, parent: &Block, view: View, _high_qc: &QuorumCertificate) -> Block {
            let header = BlockHeader {
                parent_hash: parent.hash(),
                height: parent.header.height + 1,
                view,
                proposer: self.proposer,
                state_commitment: [0; 32],
                commands_commitment: Block::commands_commitment(&[]),
            };
            Block {
                header,
                commands: Vec::new(),
            }
        }
    }

    /// Build a fresh [`HotStuffCore`] whose `self_id` is `nid(self_byte)`
    /// over the canonical four-validator set, rooted at a standard
    /// all-zero-state-commitment genesis block.
    pub(crate) fn make_core(self_byte: u8) -> HotStuffCore {
        let state = HotStuffState::new(validators(), Block::genesis([0; 32]));
        let builder = Arc::new(TestBlockBuilder {
            proposer: nid(self_byte),
        });
        HotStuffCore::new(nid(self_byte), state, builder)
    }

    /// Build an orphan block whose `parent_hash` is `orphan_parent` and
    /// whose own contents are deterministic given the view. Used to
    /// exercise the missing-parent dispatch branch.
    fn orphan_child(orphan_parent: BlockHash, view: View, proposer: NodeId) -> Block {
        let header = BlockHeader {
            parent_hash: orphan_parent,
            height: 1,
            view,
            proposer,
            state_commitment: [0; 32],
            commands_commitment: Block::commands_commitment(&[]),
        };
        Block {
            header,
            commands: Vec::new(),
        }
    }

    // ── B1: missing-parent branch ───────────────────────────────────

    #[test]
    fn proposal_with_unknown_parent_parks_and_requests_block() {
        let mut core = make_core(1);
        let sender = nid(2);
        let orphan_parent: BlockHash = [0xAA; 32];
        let child = orphan_child(orphan_parent, 1, nid(3));
        let child_hash = child.hash();

        // Justify can be any QC — dispatch doesn't inspect it on the
        // missing-parent branch because it returns before the
        // safe-to-vote check.
        let justify = dummy_qc(0, core.state().genesis_hash);
        let signed = signed_proposal(child, justify, sender);

        let actions = core.step(Event::ProposalReceived(signed));

        // Single RequestBlock aimed at the sender with the orphan
        // parent hash. The safety state is untouched: we have not
        // voted, not locked, not updated high_qc.
        assert_eq!(actions, vec![Action::RequestBlock(orphan_parent, sender)]);
        assert!(core.parked_proposals.contains_key(&child_hash));
        assert_eq!(core.state().last_voted_view, 0);
        assert!(core.state().locked.is_none());
        assert!(core.state().high_qc.is_none());
    }

    #[test]
    fn reparking_same_proposal_is_idempotent() {
        // Repeated delivery of the same orphan proposal must neither
        // grow `parked_proposals` unboundedly nor silently drop the
        // second `RequestBlock` — the integration layer might resend
        // the probe if the first went unanswered.
        let mut core = make_core(1);
        let sender = nid(2);
        let orphan_parent: BlockHash = [0xAA; 32];
        let child = orphan_child(orphan_parent, 1, nid(3));
        let justify = dummy_qc(0, core.state().genesis_hash);
        let signed = signed_proposal(child, justify, sender);

        let _ = core.step(Event::ProposalReceived(signed.clone()));
        let second = core.step(Event::ProposalReceived(signed));

        assert_eq!(
            second,
            vec![Action::RequestBlock(orphan_parent, sender)],
            "re-delivery must still produce a RequestBlock so the \
             driver can retry the fetch",
        );
        assert_eq!(core.parked_proposals.len(), 1);
    }

    // ── B2 / B3: happy-path vote and HighQc adoption ─────────────────

    // Round-robin leader for the canonical four-validator set:
    // `[nid(1), nid(2), nid(3), nid(4)]`. view 1 → nid(2),
    // view 2 → nid(3). These are hard-coded in the test assertions
    // below on purpose — if the RoundRobinSelector mapping ever
    // changes, the tests should fail loudly rather than silently
    // keep using a stale leader.

    #[test]
    fn first_proposal_emits_persist_vote_and_adopts_high_qc() {
        let mut core = make_core(1);
        let genesis = Block::genesis([0; 32]);
        let block = chain_from_genesis(&genesis, &[1], nid(2))[0].clone();
        let block_hash = block.hash();
        let justify = dummy_qc(0, genesis.hash());
        let signed = signed_proposal(block, justify.clone(), nid(2));

        let actions = core.step(Event::ProposalReceived(signed));

        assert_eq!(
            actions,
            vec![
                Action::Persist(StateUpdate::VotedInView { view: 1 }),
                Action::Persist(StateUpdate::HighQc(justify)),
                Action::SendTo(
                    nid(3),
                    ConsensusMsg::Vote(Vote {
                        view: 1,
                        block_hash,
                    }),
                ),
            ],
            "happy-path emission order is VotedInView → HighQc → SendTo(Vote)",
        );
        assert_eq!(core.state().last_voted_view, 1);
        assert_eq!(
            core.state().high_qc.as_ref().map(|q| q.view),
            Some(0),
            "high_qc adopted from the proposal's justify",
        );
    }

    // ── D3: vote-only-once at same view ──────────────────────────────

    #[test]
    fn second_proposal_at_same_view_emits_no_vote() {
        let mut core = make_core(1);
        let genesis = Block::genesis([0; 32]);
        let justify = dummy_qc(0, genesis.hash());

        // First proposal at view 1 — vote emitted.
        let block_a = chain_from_genesis(&genesis, &[1], nid(2))[0].clone();
        let _ = core.step(Event::ProposalReceived(signed_proposal(
            block_a,
            justify.clone(),
            nid(2),
        )));
        assert_eq!(core.state().last_voted_view, 1);

        // Second proposal at view 1 with a DIFFERENT block. Same
        // view, different state_commitment → different hash. This is
        // the fork-attempt shape the safe-to-vote view check rules
        // out; we assert explicitly that no `Vote` action is
        // produced, and that `high_qc` / `last_voted_view` stay put
        // (HighQc adoption is gated on safe_to_vote firing).
        let block_b = Block {
            header: BlockHeader {
                parent_hash: genesis.hash(),
                height: 1,
                view: 1,
                proposer: nid(2),
                state_commitment: [0xFF; 32],
                commands_commitment: Block::commands_commitment(&[]),
            },
            commands: Vec::new(),
        };
        let block_b_hash = block_b.hash();
        let signed_b = signed_proposal(block_b, justify, nid(2));
        let second = core.step(Event::ProposalReceived(signed_b));

        assert!(
            second.is_empty(),
            "a second proposal at the same view must emit no actions: {second:?}",
        );
        assert_eq!(core.state().last_voted_view, 1);
        // The forked block IS inserted into pending_blocks — the
        // core tracks the fork even though it won't vote on it —
        // which matters for the three-chain commit rule later.
        assert!(core.state().pending_blocks.contains_key(&block_b_hash));
    }

    // ── D4: refuse-to-vote when both extension and liveness fail ─────

    /// Build a "fork at `view`, rooted on genesis" — the canonical
    /// shape the safety-rule tests use to exercise non-extension.
    fn fork_rooted_on_genesis(genesis_hash: BlockHash, view: View) -> Block {
        Block {
            header: BlockHeader {
                parent_hash: genesis_hash,
                height: 1,
                view,
                proposer: nid(3),
                state_commitment: [view as u8; 32],
                commands_commitment: Block::commands_commitment(&[]),
            },
            commands: Vec::new(),
        }
    }

    #[test]
    fn refuses_to_vote_when_not_extending_lock_and_justify_stale() {
        let mut core = make_core(1);
        let genesis = Block::genesis([0; 32]);

        // Lock the core on a block at view 5.
        let locked_block = chain_from_genesis(&genesis, &[5], nid(2))[0].clone();
        let locked_hash = locked_block.hash();
        let locked_height = locked_block.header.height;
        core.state.insert_pending(locked_block);
        core.state.locked = Some(Locked {
            view: 5,
            height: locked_height,
            block_hash: locked_hash,
        });
        core.state.last_voted_view = 5;

        // Fork at view 6 rooted directly on genesis (does NOT extend
        // the locked block at view 5) with a justify at view 3 —
        // strictly older than the lock. Neither the extension rule
        // nor the liveness rule fires; safe_to_vote returns false.
        let fork = fork_rooted_on_genesis(genesis.hash(), 6);
        let fork_hash = fork.hash();
        let stale_justify = dummy_qc(3, genesis.hash());
        let signed = signed_proposal(fork, stale_justify, nid(3));

        let actions = core.step(Event::ProposalReceived(signed));

        assert!(
            actions.is_empty(),
            "stale justify + non-extension must yield no actions: {actions:?}",
        );
        assert_eq!(
            core.state().last_voted_view,
            5,
            "last_voted_view untouched when refusing to vote",
        );
        assert_eq!(
            core.state().locked.map(|l| l.view),
            Some(5),
            "lock is not disturbed by a refused proposal",
        );
        // The fork IS inserted into pending_blocks — a later proposal
        // whose chain happens to pass through this fork can still
        // walk through it; the safety rules, not the storage layer,
        // are what gate voting.
        assert!(core.state().pending_blocks.contains_key(&fork_hash));
    }

    #[test]
    fn liveness_rule_permits_vote_on_fork_when_justify_fresher_than_lock() {
        // Companion to the refuse test above. Same lock setup, but
        // the fork's justify is view 9 > locked view 5. The liveness
        // rule fires and the core votes even though the fork does
        // not extend the locked block. Without this path, a slow
        // node that locked on a dead branch would never catch up.
        let mut core = make_core(1);
        let genesis = Block::genesis([0; 32]);

        let locked_block = chain_from_genesis(&genesis, &[5], nid(2))[0].clone();
        let locked_hash = locked_block.hash();
        let locked_height = locked_block.header.height;
        core.state.insert_pending(locked_block);
        core.state.locked = Some(Locked {
            view: 5,
            height: locked_height,
            block_hash: locked_hash,
        });
        core.state.last_voted_view = 5;

        let fork = fork_rooted_on_genesis(genesis.hash(), 10);
        let fork_hash = fork.hash();
        let fresh_justify = dummy_qc(9, [0xEE; 32]);
        let signed = signed_proposal(fork, fresh_justify.clone(), nid(3));

        let actions = core.step(Event::ProposalReceived(signed));

        assert_eq!(
            actions,
            vec![
                Action::Persist(StateUpdate::VotedInView { view: 10 }),
                Action::Persist(StateUpdate::HighQc(fresh_justify)),
                // leader(11) over `[nid(1), nid(2), nid(3), nid(4)]`:
                // 11 % 4 = 3 → nid(4).
                Action::SendTo(
                    nid(4),
                    ConsensusMsg::Vote(Vote {
                        view: 10,
                        block_hash: fork_hash,
                    }),
                ),
            ],
        );
        assert_eq!(core.state().last_voted_view, 10);
        assert_eq!(core.state().high_qc.as_ref().map(|q| q.view), Some(9));
    }

    // ── D5: Byzantine fork at same view from different proposers ─────

    #[test]
    fn byzantine_second_proposer_at_same_view_does_not_extract_a_vote() {
        // Distinct from D3's vote-only-once test: there the second
        // proposal came from the same proposer (shaped like a
        // retry). Here the second proposal comes from a DIFFERENT
        // validator — the Byzantine shape — pretending to lead the
        // same view. Either the view-freshness check or a
        // higher-level "wrong leader" filter could block this; the
        // test pins that *at least* the view-freshness check does,
        // which is the lower bound the safety core needs to uphold
        // regardless of what the integration layer (#24) filters.
        let mut core = make_core(1);
        let genesis = Block::genesis([0; 32]);
        let justify = dummy_qc(0, genesis.hash());

        // The legitimate view-1 leader (nid(2)) proposes first.
        let block_a = chain_from_genesis(&genesis, &[1], nid(2))[0].clone();
        let block_a_hash = block_a.hash();
        let first = core.step(Event::ProposalReceived(signed_proposal(
            block_a,
            justify.clone(),
            nid(2),
        )));
        assert!(
            first
                .iter()
                .any(|a| matches!(a, Action::SendTo(_, ConsensusMsg::Vote(_)))),
            "legitimate first proposal is expected to produce a Vote: {first:?}",
        );

        // Byzantine nid(3) stuffs a conflicting block at the same
        // view. `safe_to_vote` rejects on view-freshness grounds;
        // the core emits no action at all.
        let block_b = Block {
            header: BlockHeader {
                parent_hash: genesis.hash(),
                height: 1,
                view: 1,
                proposer: nid(3),
                state_commitment: [0xCC; 32],
                commands_commitment: Block::commands_commitment(&[]),
            },
            commands: Vec::new(),
        };
        let block_b_hash = block_b.hash();
        let second = core.step(Event::ProposalReceived(signed_proposal(
            block_b,
            justify,
            nid(3),
        )));

        assert!(
            second.is_empty(),
            "Byzantine fork must not extract a second vote: {second:?}",
        );
        assert_eq!(core.state().last_voted_view, 1);
        // Both branches of the fork stay tracked in pending_blocks:
        // a future three-chain walk might need either of them, and
        // removing a block because we didn't vote on it would be a
        // storage leak back into safety semantics.
        assert!(core.state().pending_blocks.contains_key(&block_a_hash));
        assert!(core.state().pending_blocks.contains_key(&block_b_hash));
    }

    // ── B4: two-chain lock promotion ────────────────────────────────

    #[test]
    fn two_chain_promotes_lock_to_grandparent() {
        // Build genesis → block1 (view 1) → block2 (view 2), then
        // receive a proposal at view 3 whose parent is block2. The
        // two-chain walk reaches block1 as the grandparent; B4
        // promotes the lock to it. On the same step, B5's
        // three-chain walk `block2 → block1 → genesis` fires —
        // consecutive views 2←1←0 — so `Commit(genesis)` is also
        // emitted after B4's `Persist(Locked)`.
        let mut core = make_core(1);
        let genesis = Block::genesis([0; 32]);
        let prefix = chain_from_genesis(&genesis, &[1, 2], nid(2));
        let block1 = prefix[0].clone();
        let block2 = prefix[1].clone();
        core.state.insert_pending(block1.clone());
        core.state.insert_pending(block2.clone());

        // block3 extends block2 at view 3. We construct it via a
        // fresh `chain_from_genesis` so it descends from the same
        // block1/block2 we just inserted.
        let full_chain = chain_from_genesis(&genesis, &[1, 2, 3], nid(2));
        let block3 = full_chain[2].clone();
        let block3_hash = block3.hash();
        let justify = dummy_qc(2, block2.hash());
        let signed = signed_proposal(block3, justify.clone(), nid(2));

        let actions = core.step(Event::ProposalReceived(signed));

        let expected_lock = Locked {
            view: 1,
            height: 1,
            block_hash: block1.hash(),
        };
        // Emission order: B2/B3 (VotedInView, HighQc, SendTo(Vote)),
        // then B4 (Persist(Locked)), then B5 (Commit(genesis)).
        // leader(4) over `[nid(1), nid(2), nid(3), nid(4)]`:
        // 4 % 4 = 0 → nid(1).
        assert_eq!(
            actions,
            vec![
                Action::Persist(StateUpdate::VotedInView { view: 3 }),
                Action::Persist(StateUpdate::HighQc(justify)),
                Action::SendTo(
                    nid(1),
                    ConsensusMsg::Vote(Vote {
                        view: 3,
                        block_hash: block3_hash,
                    }),
                ),
                Action::Persist(StateUpdate::Locked(expected_lock)),
                Action::Commit(genesis.clone()),
            ],
            "B2/B3/B4/B5 emissions in order",
        );
        assert_eq!(core.state().locked, Some(expected_lock));
        // Genesis was committed → pruned from pending_blocks.
        assert!(!core.state().pending_blocks.contains_key(&genesis.hash()));
        // Above the commit height survives.
        assert!(core.state().pending_blocks.contains_key(&block1.hash()));
        assert!(core.state().pending_blocks.contains_key(&block2.hash()));
    }

    #[test]
    fn two_chain_does_not_move_lock_backward() {
        // Preset the lock at a height strictly above anything the
        // proposal could promote to (it'd only see block1 at height
        // 1). A regression that always promoted would emit a stray
        // `Persist(Locked)` here; a regression that compared by
        // view instead of height could also silently rewrite the
        // lock.
        let mut core = make_core(1);
        let genesis = Block::genesis([0; 32]);
        let prefix = chain_from_genesis(&genesis, &[1, 2], nid(2));
        core.state.insert_pending(prefix[0].clone());
        core.state.insert_pending(prefix[1].clone());

        let preset = Locked {
            view: 99,
            height: 99,
            block_hash: [0xAB; 32],
        };
        core.state.locked = Some(preset);

        // Proposal at view 100 extending block2; b' is block1 at
        // height 1 — strictly below the current lock at height 99.
        let block3 = Block {
            header: BlockHeader {
                parent_hash: prefix[1].hash(),
                height: 3,
                view: 100,
                proposer: nid(2),
                state_commitment: [0; 32],
                commands_commitment: Block::commands_commitment(&[]),
            },
            commands: Vec::new(),
        };
        let justify = dummy_qc(2, prefix[1].hash());
        let signed = signed_proposal(block3, justify, nid(2));

        let actions = core.step(Event::ProposalReceived(signed));

        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::Persist(StateUpdate::Locked(_)))),
            "lock must not move backward: {actions:?}",
        );
        assert_eq!(core.state().locked, Some(preset), "state.locked untouched",);
    }

    // ── B5: three-chain commit + prune ──────────────────────────────

    #[test]
    fn three_chain_commits_great_grandparent_and_prunes_below() {
        // Build a 4-deep chain past genesis: `v1, v2, v3, v4`. Pre-load
        // all of them into `pending_blocks`, then send a proposal at
        // view 5 whose parent is v4 and whose justify is QC(v4). The
        // three-chain walk from the justify (`v4 → v3 → v2`) is
        // strictly consecutive, so B5 commits v2 and prunes everything
        // at height ≤ 2.
        let mut core = make_core(1);
        let genesis = Block::genesis([0; 32]);
        let chain = chain_from_genesis(&genesis, &[1, 2, 3, 4], nid(2));
        for block in &chain {
            core.state.insert_pending(block.clone());
        }
        let block_v1 = chain[0].clone();
        let block_v2 = chain[1].clone();
        let block_v3 = chain[2].clone();
        let block_v4 = chain[3].clone();

        let full = chain_from_genesis(&genesis, &[1, 2, 3, 4, 5], nid(2));
        let block_v5 = full[4].clone();
        let justify = dummy_qc(4, block_v4.hash());
        let signed = signed_proposal(block_v5.clone(), justify, nid(2));

        let actions = core.step(Event::ProposalReceived(signed));

        // Exactly one Commit, and it's over v2 — the QC's
        // great-grandparent. Not genesis (that would be the
        // great-great-grandparent, outside the predicate's walk) and
        // not v3 (that's only the grandparent).
        let commits: Vec<&Block> = actions
            .iter()
            .filter_map(|a| match a {
                Action::Commit(b) => Some(b),
                _ => None,
            })
            .collect();
        assert_eq!(commits.len(), 1, "exactly one Commit action: {actions:?}",);
        assert_eq!(commits[0], &block_v2);

        // Pruning removes every entry at height ≤ 2: genesis (h=0),
        // v1 (h=1), v2 (h=2, the committed block itself).
        let pending = &core.state().pending_blocks;
        assert!(!pending.contains_key(&genesis.hash()));
        assert!(!pending.contains_key(&block_v1.hash()));
        assert!(!pending.contains_key(&block_v2.hash()));
        // Everything strictly above the commit survives — future
        // two-chain / three-chain walks on subsequent proposals will
        // need these.
        assert!(pending.contains_key(&block_v3.hash()));
        assert!(pending.contains_key(&block_v4.hash()));
        assert!(pending.contains_key(&block_v5.hash()));
    }

    #[test]
    fn three_chain_does_not_fire_on_view_gap() {
        // Chain with a view gap: views 1, 2, 5 past genesis. When the
        // dispatcher walks `b3 → b2 → b1` starting from a QC(v=5),
        // the check `b2.view + 1 == b3.view` fails (v=2 + 1 ≠ 5).
        // `three_chain_commit` returns None, dispatch emits no
        // `Commit`, and `pending_blocks` is not pruned — genesis in
        // particular stays. Appendix B.1 ("Why direct parent") makes
        // this the one arm of `update` that must remain strict.
        let mut core = make_core(1);
        let genesis = Block::genesis([0; 32]);
        let chain = chain_from_genesis(&genesis, &[1, 2, 5], nid(2));
        for block in &chain {
            core.state.insert_pending(block.clone());
        }

        // Proposal at view 6, parent=v5, justify=QC(v5).
        let full = chain_from_genesis(&genesis, &[1, 2, 5, 6], nid(2));
        let block_v6 = full[3].clone();
        let justify = dummy_qc(5, chain[2].hash());
        let signed = signed_proposal(block_v6, justify, nid(2));

        let actions = core.step(Event::ProposalReceived(signed));

        assert!(
            !actions.iter().any(|a| matches!(a, Action::Commit(_))),
            "view gap must suppress commit: {actions:?}",
        );
        // Genesis is still in pending_blocks because no prune ran.
        assert!(core.state().pending_blocks.contains_key(&genesis.hash()));
    }

    // ── D2: happy-path three consecutive proposals → Commit ─────────

    #[test]
    fn three_consecutive_proposals_commit_block_at_view_zero() {
        // End-to-end happy path from #93's verification list: feed the
        // core three proposals at views 1, 2, 3 through distinct
        // `step()` calls. On the third, B5 commits the "block at view
        // 0" — genesis — per the Chained HotStuff three-chain rule.
        // Lock promotion fires for the first time on the third
        // proposal (the grandparent finally becomes visible). The
        // first two proposals emit only vote + high_qc adoption.
        //
        // This is the integration shape that exercises state
        // accumulating across multiple `step` invocations — each
        // unit test above holds one step; D2 is the only test that
        // pins the cross-step behavior end-to-end.
        let mut core = make_core(1);
        let genesis = Block::genesis([0; 32]);
        let chain = chain_from_genesis(&genesis, &[1, 2, 3], nid(2));
        let block_v1 = chain[0].clone();
        let block_v2 = chain[1].clone();
        let block_v3 = chain[2].clone();

        // ── Step 1 — proposal at view 1, parent=genesis ────────────
        let justify_v0 = dummy_qc(0, genesis.hash());
        let signed_v1 = signed_proposal(block_v1.clone(), justify_v0.clone(), nid(2));
        let step1 = core.step(Event::ProposalReceived(signed_v1));

        // B4 skips (grandparent is genesis's [0; 32] sentinel).
        // B5 skips (great-grandparent missing).
        // leader(2) = 2 % 4 = 2 → validators[2] = nid(3).
        assert_eq!(
            step1,
            vec![
                Action::Persist(StateUpdate::VotedInView { view: 1 }),
                Action::Persist(StateUpdate::HighQc(justify_v0)),
                Action::SendTo(
                    nid(3),
                    ConsensusMsg::Vote(Vote {
                        view: 1,
                        block_hash: block_v1.hash(),
                    }),
                ),
            ],
            "first proposal: vote + high_qc only",
        );
        assert!(core.state().locked.is_none());
        assert_eq!(core.state().last_voted_view, 1);

        // ── Step 2 — proposal at view 2, parent=block_v1 ───────────
        let justify_v1 = dummy_qc(1, block_v1.hash());
        let signed_v2 = signed_proposal(block_v2.clone(), justify_v1.clone(), nid(2));
        let step2 = core.step(Event::ProposalReceived(signed_v2));

        // B4: b'' = block_v1 (h=1), b' = genesis (h=0). Candidate at
        // height 0 doesn't beat the `None → 0` baseline, so no
        // promote. B5: walk hits genesis as b2 (h=0) and the
        // sentinel as b1 — returns None.
        // leader(3) = 3 % 4 = 3 → validators[3] = nid(4).
        assert_eq!(
            step2,
            vec![
                Action::Persist(StateUpdate::VotedInView { view: 2 }),
                Action::Persist(StateUpdate::HighQc(justify_v1)),
                Action::SendTo(
                    nid(4),
                    ConsensusMsg::Vote(Vote {
                        view: 2,
                        block_hash: block_v2.hash(),
                    }),
                ),
            ],
            "second proposal: still vote + high_qc only",
        );
        assert!(core.state().locked.is_none());
        assert_eq!(core.state().last_voted_view, 2);

        // ── Step 3 — proposal at view 3, parent=block_v2 ───────────
        let justify_v2 = dummy_qc(2, block_v2.hash());
        let signed_v3 = signed_proposal(block_v3.clone(), justify_v2.clone(), nid(2));
        let step3 = core.step(Event::ProposalReceived(signed_v3));

        // B4 fires: b'' = v2 (h=2), b' = v1 (h=1). Current lock
        // baseline is 0, so candidate h=1 wins. Persist(Locked(v1)).
        // B5 fires: walk v2 → v1 → genesis with consecutive views
        // 2,1,0. Commit genesis; prune height ≤ 0.
        // leader(4) = 4 % 4 = 0 → validators[0] = nid(1).
        let expected_lock = Locked {
            view: 1,
            height: 1,
            block_hash: block_v1.hash(),
        };
        assert_eq!(
            step3,
            vec![
                Action::Persist(StateUpdate::VotedInView { view: 3 }),
                Action::Persist(StateUpdate::HighQc(justify_v2)),
                Action::SendTo(
                    nid(1),
                    ConsensusMsg::Vote(Vote {
                        view: 3,
                        block_hash: block_v3.hash(),
                    }),
                ),
                Action::Persist(StateUpdate::Locked(expected_lock)),
                Action::Commit(genesis.clone()),
            ],
            "third proposal: vote + high_qc + lock promote + Commit(genesis)",
        );
        assert_eq!(core.state().last_voted_view, 3);
        assert_eq!(core.state().locked, Some(expected_lock));
        // Genesis pruned; v1, v2, v3 remain.
        let pending = &core.state().pending_blocks;
        assert!(!pending.contains_key(&genesis.hash()));
        assert!(pending.contains_key(&block_v1.hash()));
        assert!(pending.contains_key(&block_v2.hash()));
        assert!(pending.contains_key(&block_v3.hash()));
    }

    // ── C1/C2: VoteReceived leader path ─────────────────────────────

    #[test]
    fn vote_dropped_when_not_leader_of_next_view() {
        // self = nid(1). Vote at view 2 → next view = 3. Leader of
        // view 3 = validators[3 % 4] = validators[3] = nid(4), not
        // nid(1). The vote must be dropped silently — no bucket
        // entry, no actions. C1a's cheapest branch.
        let mut core = make_core(1);
        let vote = signed_vote(2, [0xAA; 32], nid(2));

        let actions = core.step(Event::VoteReceived(vote));

        assert!(actions.is_empty(), "not-leader drops vote: {actions:?}");
        assert!(
            core.vote_bucket.is_empty(),
            "bucket must not accumulate when we're not the leader",
        );
    }

    #[test]
    fn subquorum_votes_accumulate_without_actions() {
        // self = nid(1), leader of view 4. Feed two valid votes at
        // view 3 (quorum over n=4 is 3). The bucket should grow to
        // two signatures, but neither `step` call produces any
        // actions — C2's first-crosses-threshold gate only fires on
        // the transition to quorum, which we haven't reached.
        let mut core = make_core(1);
        let block_hash: BlockHash = [0xAA; 32];

        let step1 = core.step(Event::VoteReceived(signed_vote(3, block_hash, nid(2))));
        assert!(step1.is_empty(), "first sub-quorum vote is silent");

        let step2 = core.step(Event::VoteReceived(signed_vote(3, block_hash, nid(3))));
        assert!(step2.is_empty(), "second sub-quorum vote is silent");

        let bucket = core
            .vote_bucket
            .get(&(3, block_hash))
            .expect("bucket keyed by (view, block_hash) must exist after two votes");
        assert_eq!(bucket.signer_count(), 2, "both signatures recorded",);
        assert!(
            !bucket.has_quorum(&core.state.validator_set),
            "2 of 4 is below the quorum threshold of 3",
        );
    }

    #[test]
    fn quorum_emits_high_qc_persist_then_broadcast_proposal() {
        // self = nid(1), leader of view 4. Install `block_v3` into
        // `pending_blocks` so the parent lookup at quorum time
        // succeeds. Feed three votes at view 3 — the threshold over
        // n=4 — and assert the third one emits, in order:
        //   1. Persist(HighQc(formed_qc))
        //   2. Broadcast(Proposal { block: new_v4, justify: formed_qc })
        // where `new_v4` is what the `TestBlockBuilder` stamps over
        // block_v3 at view 4.
        let mut core = make_core(1);
        let genesis = Block::genesis([0; 32]);
        let block_v3 = chain_from_genesis(&genesis, &[3], nid(2))[0].clone();
        let block_v3_hash = block_v3.hash();
        core.state.insert_pending(block_v3.clone());

        // First two votes accumulate silently.
        let step1 = core.step(Event::VoteReceived(signed_vote(3, block_v3_hash, nid(2))));
        let step2 = core.step(Event::VoteReceived(signed_vote(3, block_v3_hash, nid(3))));
        assert!(step1.is_empty(), "first sub-quorum vote silent: {step1:?}");
        assert!(step2.is_empty(), "second sub-quorum vote silent: {step2:?}");

        // Third vote crosses the threshold. Reconstruct the expected
        // QC by signing in the same (bitmap) order the dispatcher
        // would — validator indices 1, 2, 3 for nid(2), nid(3), nid(4).
        let mut expected_qc = QuorumCertificate::new(3, block_v3_hash, 4);
        expected_qc.add_signature(1, [nid(2)[0]; 64]);
        expected_qc.add_signature(2, [nid(3)[0]; 64]);
        expected_qc.add_signature(3, [nid(4)[0]; 64]);

        // The builder extends block_v3 (height 1) with an empty-commands
        // child at height 2, view 4, proposer nid(1).
        let expected_new_block = Block {
            header: BlockHeader {
                parent_hash: block_v3_hash,
                height: block_v3.header.height + 1,
                view: 4,
                proposer: nid(1),
                state_commitment: [0; 32],
                commands_commitment: Block::commands_commitment(&[]),
            },
            commands: Vec::new(),
        };

        let step3 = core.step(Event::VoteReceived(signed_vote(3, block_v3_hash, nid(4))));

        assert_eq!(
            step3,
            vec![
                Action::Persist(StateUpdate::HighQc(expected_qc.clone())),
                Action::Broadcast(ConsensusMsg::Proposal(Proposal {
                    block: expected_new_block,
                    justify: expected_qc.clone(),
                })),
            ],
            "quorum transition emits HighQc persist then Broadcast(Proposal)",
        );
        assert_eq!(core.state().high_qc.as_ref(), Some(&expected_qc));
    }

    // ── D8: PacemakerAdvance base contract ──────────────────────────

    #[test]
    fn pacemaker_advance_updates_view_and_broadcasts_new_view_when_high_qc_known() {
        let mut core = make_core(1);
        assert_eq!(core.state().current_view, 0);

        // Early: no high_qc yet → view updates but we skip the
        // broadcast. The skip window only exists between construction
        // and the first proposal landing.
        let early = core.step(Event::PacemakerAdvance(1));
        assert!(
            early.is_empty(),
            "no high_qc yet → no NewView broadcast: {early:?}",
        );
        assert_eq!(core.state().current_view, 1);

        // Seed a high_qc as if a proposal had adopted one.
        let qc = dummy_qc(5, [0xAA; 32]);
        core.state.high_qc = Some(qc.clone());

        // Later PacemakerAdvance → view updates AND the broadcast
        // carries the current high_qc.
        let later = core.step(Event::PacemakerAdvance(7));
        assert_eq!(
            later,
            vec![Action::Broadcast(ConsensusMsg::NewView(NewView {
                high_qc: qc,
            }))],
        );
        assert_eq!(core.state().current_view, 7);
    }

    // ── C3: NewViewReceived ────────────────────────────────────────

    #[test]
    fn newview_adopts_fresher_high_qc_and_ignores_stale() {
        let mut core = make_core(1);
        let block_hash: BlockHash = [0x11; 32];

        // Empty `high_qc` → any incoming QC is strictly fresher and
        // adopted. Emission: single `Persist(HighQc(qc))`.
        let qc_v5 = dummy_qc(5, block_hash);
        let fresh = core.step(Event::NewViewReceived(signed_newview(
            qc_v5.clone(),
            nid(2),
        )));
        assert_eq!(
            fresh,
            vec![Action::Persist(StateUpdate::HighQc(qc_v5.clone()))],
        );
        assert_eq!(core.state().high_qc.as_ref(), Some(&qc_v5));

        // Same view — `should_update_high_qc` requires strictly
        // greater, so no action, no state change.
        let qc_v5_alt = dummy_qc(5, [0x22; 32]);
        let same = core.step(Event::NewViewReceived(signed_newview(qc_v5_alt, nid(3))));
        assert!(same.is_empty(), "same-view NewView is a no-op: {same:?}");
        assert_eq!(core.state().high_qc.as_ref(), Some(&qc_v5));

        // Strictly older — dropped.
        let qc_v3 = dummy_qc(3, [0x33; 32]);
        let stale = core.step(Event::NewViewReceived(signed_newview(qc_v3, nid(4))));
        assert!(stale.is_empty(), "stale NewView is a no-op: {stale:?}");
        assert_eq!(core.state().high_qc.as_ref(), Some(&qc_v5));

        // Strictly newer — adopted, overwriting the previous.
        let qc_v9 = dummy_qc(9, [0x99; 32]);
        let newer = core.step(Event::NewViewReceived(signed_newview(
            qc_v9.clone(),
            nid(2),
        )));
        assert_eq!(
            newer,
            vec![Action::Persist(StateUpdate::HighQc(qc_v9.clone()))],
        );
        assert_eq!(core.state().high_qc.as_ref(), Some(&qc_v9));
    }

    #[test]
    fn post_quorum_votes_do_not_rebroadcast() {
        // Form the QC with 3 votes as before, then feed two additional
        // votes: (a) from `nid(1)` — a new signer not yet in the QC
        // — and (b) a duplicate from `nid(2)` — already in the QC.
        // Neither step may re-fire the `Broadcast(Proposal)` — C2's
        // first-crosses-threshold gate already fired, and `has_quorum`
        // stays true forever after.
        //
        // The bucket is intentionally not cleared on quorum, so these
        // late deliveries land in it as idempotent sinks rather than
        // re-materializing an empty QC and re-firing.
        let mut core = make_core(1);
        let genesis = Block::genesis([0; 32]);
        let block_v3 = chain_from_genesis(&genesis, &[3], nid(2))[0].clone();
        let block_v3_hash = block_v3.hash();
        core.state.insert_pending(block_v3.clone());

        // Drive to quorum: first three votes.
        let _ = core.step(Event::VoteReceived(signed_vote(3, block_v3_hash, nid(2))));
        let _ = core.step(Event::VoteReceived(signed_vote(3, block_v3_hash, nid(3))));
        let _ = core.step(Event::VoteReceived(signed_vote(3, block_v3_hash, nid(4))));

        // Late vote from a new signer — still a no-op at the dispatch
        // surface even though the bucket grows to 4 sigs.
        let step_late_new = core.step(Event::VoteReceived(signed_vote(3, block_v3_hash, nid(1))));
        assert!(
            step_late_new.is_empty(),
            "late vote from new signer must not re-broadcast: {step_late_new:?}",
        );

        // Duplicate vote from an existing signer — `add_signature` is
        // a no-op on the set-bit; dispatch also early-returns.
        let step_dup = core.step(Event::VoteReceived(signed_vote(3, block_v3_hash, nid(2))));
        assert!(
            step_dup.is_empty(),
            "duplicate vote must not re-broadcast: {step_dup:?}",
        );

        // Bucket should now carry all four validator signatures
        // (added by nid(2), nid(3), nid(4), nid(1)), and still be at
        // quorum. The duplicate didn't bump the count.
        let bucket = core
            .vote_bucket
            .get(&(3, block_v3_hash))
            .expect("bucket keyed by (3, block_v3_hash) must still exist");
        assert_eq!(bucket.signer_count(), 4);
        assert!(bucket.has_quorum(&core.state.validator_set));
    }

    #[test]
    fn vote_from_non_validator_signer_is_dropped() {
        // self = nid(1) is the leader of view 4 (4 % 4 = 0), so a
        // vote at view 3 would normally accumulate. But this vote
        // comes from `nid(99)` — not in the validator set. C1b
        // drops because `ValidatorSet::index_of` returns None, and
        // without an index we have no slot in the `SignerBitmap` to
        // record the signature.
        let mut core = make_core(1);
        let vote = signed_vote(3, [0xAA; 32], nid(99));

        let actions = core.step(Event::VoteReceived(vote));

        assert!(
            actions.is_empty(),
            "non-validator signer drops: {actions:?}",
        );
        assert!(
            core.vote_bucket.is_empty(),
            "bucket must not grow on unknown signer",
        );
    }

    // ── D7: parked proposal re-dispatch after parent arrives ────────

    #[test]
    fn parked_proposal_redispatches_on_pacemaker_advance_once_parent_is_present() {
        // Phase 1: receive a proposal for v2 while its parent v1
        // isn't in `pending_blocks` — B1 parks it and emits
        // `RequestBlock(v1_hash, sender)`.
        //
        // Phase 2: simulate v1 arriving via some out-of-band path
        // (e.g., a RequestBlock response handled by the integration
        // layer) by inserting it directly into `pending_blocks`.
        //
        // Phase 3: `PacemakerAdvance(3)` finds v2's parent now
        // present, re-dispatches v2 through `on_proposal_received`,
        // and then broadcasts `NewView` carrying the just-adopted
        // high_qc.
        let mut core = make_core(1);
        let genesis = Block::genesis([0; 32]);
        let chain = chain_from_genesis(&genesis, &[1, 2], nid(2));
        let block_v1 = chain[0].clone();
        let block_v2 = chain[1].clone();
        let block_v2_hash = block_v2.hash();
        let justify_v1 = dummy_qc(1, block_v1.hash());

        // Phase 1 — parent missing, proposal parks.
        let initial = core.step(Event::ProposalReceived(signed_proposal(
            block_v2.clone(),
            justify_v1.clone(),
            nid(2),
        )));
        assert_eq!(initial, vec![Action::RequestBlock(block_v1.hash(), nid(2))],);
        assert!(core.parked_proposals.contains_key(&block_v2_hash));

        // Phase 2 — parent lands some other way.
        core.state.insert_pending(block_v1.clone());

        // Phase 3 — advance the view; un-park fires.
        let advance = core.step(Event::PacemakerAdvance(3));

        // Re-dispatch of v2 yields the normal B2/B3 actions:
        // VotedInView + HighQc + SendTo(leader(3)=nid(4), Vote).
        // B4/B5 skip (grandparent is genesis's sentinel).
        // Then C4's trailing `Broadcast(NewView)` carries the just-
        // adopted high_qc.
        assert_eq!(
            advance,
            vec![
                Action::Persist(StateUpdate::VotedInView { view: 2 }),
                Action::Persist(StateUpdate::HighQc(justify_v1.clone())),
                Action::SendTo(
                    nid(4),
                    ConsensusMsg::Vote(Vote {
                        view: 2,
                        block_hash: block_v2_hash,
                    }),
                ),
                Action::Broadcast(ConsensusMsg::NewView(NewView {
                    high_qc: justify_v1,
                })),
            ],
            "un-park re-dispatch + NewView broadcast",
        );
        assert_eq!(core.state().current_view, 3);
        assert!(
            !core.parked_proposals.contains_key(&block_v2_hash),
            "parked entry removed after successful re-dispatch",
        );
    }

    // ── D9: replay determinism ─────────────────────────────────────

    #[test]
    fn replay_is_deterministic_over_a_mixed_trace() {
        // Two freshly-constructed cores fed the same event trace
        // through `replay` must produce byte-identical outputs. This
        // is the property the integration layer (#24) relies on to
        // turn a failing sim trace into a reproducible regression,
        // and the one the E-series property test will stress under
        // arbitrary interleavings.
        //
        // The trace hits every dispatch branch: PacemakerAdvance,
        // ProposalReceived, VoteReceived, NewViewReceived. It also
        // drives a commit and a quorum-triggered broadcast, so the
        // action vectors across steps vary in shape.
        fn build_trace() -> Vec<Event> {
            let genesis = Block::genesis([0; 32]);
            let chain = chain_from_genesis(&genesis, &[1, 2, 3], nid(2));
            let block_v1_hash = chain[0].hash();
            let block_v2_hash = chain[1].hash();
            let block_v3_hash = chain[2].hash();

            vec![
                Event::PacemakerAdvance(1),
                Event::ProposalReceived(signed_proposal(
                    chain[0].clone(),
                    dummy_qc(0, genesis.hash()),
                    nid(2),
                )),
                Event::ProposalReceived(signed_proposal(
                    chain[1].clone(),
                    dummy_qc(1, block_v1_hash),
                    nid(2),
                )),
                Event::ProposalReceived(signed_proposal(
                    chain[2].clone(),
                    dummy_qc(2, block_v2_hash),
                    nid(2),
                )),
                Event::VoteReceived(signed_vote(3, block_v3_hash, nid(2))),
                Event::VoteReceived(signed_vote(3, block_v3_hash, nid(3))),
                Event::VoteReceived(signed_vote(3, block_v3_hash, nid(4))),
                Event::NewViewReceived(signed_newview(dummy_qc(99, [0x99; 32]), nid(4))),
                Event::PacemakerAdvance(100),
            ]
        }

        let run1 = make_core(1).replay(build_trace());
        let run2 = make_core(1).replay(build_trace());

        assert_eq!(run1, run2, "replay must be deterministic for a fixed trace",);
        assert_eq!(run1.len(), 9, "one action vector per event");

        // Spot-checks so the test fails informatively if a future
        // dispatch change widens or shrinks a step's output.
        assert!(
            run1[0].is_empty(),
            "step 1 (PacemakerAdvance, no high_qc) emits nothing",
        );
        assert!(
            run1[3].iter().any(|a| matches!(a, Action::Commit(_))),
            "step 4 (third proposal) must emit Commit(genesis)",
        );
        assert!(
            run1[6]
                .iter()
                .any(|a| matches!(a, Action::Broadcast(ConsensusMsg::Proposal(_)))),
            "step 7 (quorum fires) must broadcast a Proposal",
        );
        assert!(
            run1[8]
                .iter()
                .any(|a| matches!(a, Action::Broadcast(ConsensusMsg::NewView(_)))),
            "step 9 (PacemakerAdvance) must broadcast NewView",
        );
    }

    // ── E1 / E4: Multi-replica property-test harness ────────────────
    //
    // The harness lives as a nested `mod property` so clippy's
    // `items_after_test_module` stays happy (only one top-level
    // `#[cfg(test)] mod tests` in the file). Later commits add the
    // invariant function and the proptest driver; this module ships
    // the deterministic fixture plus a hand-built end-to-end test
    // that proves the bus wiring before any randomization.

    mod property {
        //! Deterministic simulator for `n = 3f + 1` honest HotStuff
        //! replicas.
        //!
        //! `ReplicaSet` owns one [`HotStuffCore`] per validator, plus
        //! a per-replica inbox of pending [`Event`]s. `apply_actions`
        //! converts each replica's emitted [`Action`]s into the
        //! appropriate inbox pushes on the other replicas — the
        //! "fake bus" from #93's property-test spec. No clock, no
        //! network; just deterministic delivery.
        //!
        //! `Persist` and `RequestBlock` actions are ignored in the
        //! sim: the harness doesn't model durability (the cores'
        //! in-memory state is the source of truth) and every block
        //! the cores need is delivered inline via `ProposalReceived`
        //! events, so no fetch path is necessary.

        use std::collections::{BTreeMap, VecDeque};

        use super::*;

        /// The four-nids-with-increasing-bytes layout from the unit
        /// tests generalized to arbitrary `n`: validator `i` has
        /// NodeId `[i as u8 + 1; 32]` so `validators[i].cmp(validators[j])`
        /// matches `i.cmp(&j)` — the `RoundRobinSelector` inside each
        /// core maps view `v` to validator index `v % n`.
        pub(crate) fn validator_set(n: usize) -> ValidatorSet {
            let members: Vec<NodeId> = (1..=n as u8).map(|b| [b; 32]).collect();
            ValidatorSet::new(members)
        }

        pub(crate) struct ReplicaSet {
            /// Honest cores, indexed 0..n_honest. Byzantine validators
            /// have no core — their NodeIds appear in `validators`
            /// (so leader election still maps views to them), but
            /// they produce events only via the adversary strategies
            /// in the property tests below.
            pub cores: Vec<HotStuffCore>,
            /// Per-honest-replica event inbox.
            pub inboxes: Vec<VecDeque<Event>>,
            /// Per-honest-replica committed-blocks ledger.
            pub commits: Vec<BTreeMap<u64, Block>>,
            pub validators: ValidatorSet,
            pub genesis: Block,
            /// How many of the trailing `validators` entries are
            /// Byzantine. Honest validator indices are `0..n_honest`
            /// where `n_honest = validators.len() - byzantine_count`.
            pub byzantine_count: usize,
        }

        impl ReplicaSet {
            /// Build `n` all-honest replicas. Shorthand for
            /// `new_with_byzantine(n, 0)`.
            pub fn new(n: usize) -> Self {
                Self::new_with_byzantine(n, 0)
            }

            /// Build `n_total` validators with the last `byzantine_count`
            /// treated as Byzantine: their NodeIds appear in
            /// `validators` for leader-election purposes, but no
            /// honest core runs for them, and messages addressed to
            /// them via `SendTo` are dropped (adversarial void).
            pub fn new_with_byzantine(n_total: usize, byzantine_count: usize) -> Self {
                assert!(
                    byzantine_count < n_total,
                    "byzantine_count must be strictly less than n_total",
                );
                let n_honest = n_total - byzantine_count;
                let validators = validator_set(n_total);
                let genesis = Block::genesis([0; 32]);
                let cores: Vec<HotStuffCore> = (0..n_honest)
                    .map(|i| {
                        let nid = *validators.get(i).unwrap();
                        let state = HotStuffState::new(validators.clone(), genesis.clone());
                        let builder = Arc::new(TestBlockBuilder { proposer: nid });
                        HotStuffCore::new(nid, state, builder)
                    })
                    .collect();
                let inboxes = (0..n_honest).map(|_| VecDeque::new()).collect();
                let commits = (0..n_honest).map(|_| BTreeMap::new()).collect();
                Self {
                    cores,
                    inboxes,
                    commits,
                    validators,
                    genesis,
                    byzantine_count,
                }
            }

            /// Number of honest replicas the harness is running.
            pub fn len(&self) -> usize {
                self.cores.len()
            }

            /// Byzantine NodeIds — the trailing validator slots that
            /// have no core. Property tests use this list to pick
            /// signers for adversarial events.
            pub fn byzantine_nids(&self) -> Vec<NodeId> {
                let n_honest = self.cores.len();
                (n_honest..n_honest + self.byzantine_count)
                    .map(|i| *self.validators.get(i).unwrap())
                    .collect()
            }

            /// Map a NodeId to an honest-replica index, if that
            /// NodeId belongs to an honest validator. Returns `None`
            /// for Byzantine (or unknown) ids. `apply_actions`
            /// uses this to drop `SendTo` destined for Byzantine —
            /// the adversary sees the message but doesn't process
            /// it through any harness-owned core.
            pub fn honest_index_of(&self, nid: &NodeId) -> Option<usize> {
                let idx = self.validators.index_of(nid)?;
                if idx < self.cores.len() {
                    Some(idx)
                } else {
                    None
                }
            }

            /// Queue `event` for honest `replica`'s next `deliver_one`.
            pub fn inject(&mut self, replica: usize, event: Event) {
                self.inboxes[replica].push_back(event);
            }

            /// Queue `event` for every honest replica's inbox.
            pub fn inject_all(&mut self, event: Event) {
                for i in 0..self.cores.len() {
                    self.inject(i, event.clone());
                }
            }

            /// Pop the next pending event for `replica` and feed it
            /// through `step`. Returns `true` if an event was
            /// delivered, `false` if the inbox was empty.
            pub fn deliver_one(&mut self, replica: usize) -> bool {
                let Some(event) = self.inboxes[replica].pop_front() else {
                    return false;
                };
                let actions = self.cores[replica].step(event);
                self.apply_actions(replica, actions);
                true
            }

            fn apply_actions(&mut self, source: usize, actions: Vec<Action>) {
                let source_nid = *self.validators.get(source).unwrap();
                for action in actions {
                    match action {
                        Action::Broadcast(msg) => {
                            // Only honest replicas have inboxes;
                            // Byzantine "receipt" is a no-op.
                            for target in 0..self.cores.len() {
                                self.inboxes[target]
                                    .push_back(event_from_msg(source_nid, msg.clone()));
                            }
                        }
                        Action::SendTo(target_id, msg) => {
                            // Drop silently if the target is
                            // Byzantine — the adversary sees it on
                            // the wire, but we don't model what they
                            // do with it beyond the strategies in
                            // the property tests.
                            if let Some(target) = self.honest_index_of(&target_id) {
                                self.inboxes[target].push_back(event_from_msg(source_nid, msg));
                            }
                        }
                        Action::Commit(block) => {
                            self.commits[source].insert(block.header.height, block);
                        }
                        // Safety-core effects the harness doesn't
                        // model. `Persist` is durability, `RequestBlock`
                        // is sync; both are integration-layer jobs.
                        Action::Persist(_) | Action::RequestBlock(_, _) => {}
                    }
                }
            }

            /// Round-robin deliver for up to `max_rounds` passes, or
            /// until every inbox is empty. Does NOT panic on
            /// non-quiescence: honest HotStuff is self-sustaining
            /// (each successful view triggers the next), so tests
            /// bound the run explicitly and inspect the recorded
            /// commits afterwards.
            pub fn run_bounded(&mut self, max_rounds: usize) {
                for _ in 0..max_rounds {
                    let mut progress = false;
                    for i in 0..self.cores.len() {
                        if self.deliver_one(i) {
                            progress = true;
                        }
                    }
                    if !progress {
                        return;
                    }
                }
            }

            /// Seed a fully-signed QC over `(view, block_hash)` —
            /// exactly what `HotStuff::add_signature` would produce
            /// from `n` real validators voting. Used for crafting
            /// the kickoff proposal; not something the safety core
            /// would ever build internally.
            pub fn synth_qc(&self, view: View, block_hash: BlockHash) -> QuorumCertificate {
                let mut qc = QuorumCertificate::new(view, block_hash, self.validators.len());
                for i in 0..self.validators.len() {
                    qc.add_signature(i, [i as u8 + 1; 64]);
                }
                qc
            }
        }

        /// Wrap a `ConsensusMsg` from `source` in the corresponding
        /// `Signed<_>` envelope and promote it to the matching
        /// `Event` kind. Signatures aren't verified by the safety
        /// core, so we stamp a zero sig.
        fn event_from_msg(source: NodeId, msg: ConsensusMsg) -> Event {
            let sig = [0u8; 64];
            match msg {
                ConsensusMsg::Proposal(payload) => Event::ProposalReceived(Signed {
                    payload,
                    signer: source,
                    sig,
                }),
                ConsensusMsg::Vote(payload) => Event::VoteReceived(Signed {
                    payload,
                    signer: source,
                    sig,
                }),
                ConsensusMsg::NewView(payload) => Event::NewViewReceived(Signed {
                    payload,
                    signer: source,
                    sig,
                }),
            }
        }

        // ── Hand-built deterministic driver ────────────────────────

        /// Build a view-1 kickoff proposal rooted on `genesis` with a
        /// synthesized genesis QC as its justify. The leader of view
        /// 1 (`validators[1]`) would normally produce this after
        /// collecting view-0 NewView messages; we bypass bootstrap
        /// by injecting it as an incoming event.
        fn kickoff_proposal(replicas: &ReplicaSet) -> Signed<Proposal> {
            let genesis_qc = replicas.synth_qc(0, replicas.genesis.hash());
            let leader_idx = 1 % replicas.len();
            let leader_nid = *replicas.validators.get(leader_idx).unwrap();
            let builder = TestBlockBuilder {
                proposer: leader_nid,
            };
            let block_v1 = builder.build(&replicas.genesis, 1, &genesis_qc);
            Signed {
                payload: Proposal {
                    block: block_v1,
                    justify: genesis_qc,
                },
                signer: leader_nid,
                sig: [0u8; 64],
            }
        }

        /// The safety invariant this whole milestone is built around:
        /// for every pair of replicas `(i, j)` and every height `h`,
        /// if both committed a block at height `h`, the blocks agree
        /// byte-for-byte. Panics with a precise `(i, j, h)` message
        /// on the first violation so a failed proptest shrinks to a
        /// single offending height rather than a diff of two maps.
        ///
        /// "Commit at the same height" is the cross-replica analog of
        /// HotStuff's `Theorem 2` ("conflicting nodes cannot both be
        /// committed"): at any fixed height, there must be exactly
        /// one committed block across the honest set.
        pub(crate) fn assert_no_conflicting_commits(replicas: &ReplicaSet) {
            let n = replicas.len();
            for i in 0..n {
                for j in (i + 1)..n {
                    for (height, block_i) in &replicas.commits[i] {
                        let Some(block_j) = replicas.commits[j].get(height) else {
                            continue;
                        };
                        assert_eq!(
                            block_i.hash(),
                            block_j.hash(),
                            "replicas {i} and {j} committed conflicting blocks at \
                             height {height}: hash {:?} vs {:?}",
                            block_i.hash(),
                            block_j.hash(),
                        );
                    }
                }
            }
        }

        #[test]
        fn four_honest_replicas_agree_on_a_commit() {
            // Smoke test: n = 3f + 1 for f = 1. Kick off view 1 by
            // broadcasting a hand-crafted proposal to every replica,
            // run the bus for a bounded number of rounds, and assert
            // (a) at least one commit per replica, (b) no pair of
            // replicas has conflicting commits.
            //
            // This is the minimum proof that the bus correctly
            // relays `SendTo(leader, Vote)` and `Broadcast(Proposal)`
            // between cores, and that the invariant we'll actually
            // check against Byzantine inputs in PR β holds trivially
            // for honest inputs.
            let mut replicas = ReplicaSet::new(4);
            let kickoff = kickoff_proposal(&replicas);
            replicas.inject_all(Event::ProposalReceived(kickoff));

            // Honest HotStuff keeps going indefinitely; bound the
            // run and inspect commits afterwards. 64 rounds is
            // comfortably past the ~8 rounds to the first commit on
            // this schedule.
            replicas.run_bounded(64);

            // Every replica committed at least one block.
            for i in 0..replicas.len() {
                assert!(
                    !replicas.commits[i].is_empty(),
                    "replica {i} recorded no commits: did the bus hang?",
                );
            }

            assert_no_conflicting_commits(&replicas);

            // The first committed block (lowest height) must match
            // across replicas.
            let (&h0, b0) = replicas.commits[0].iter().next().unwrap();
            for i in 1..replicas.len() {
                let other = replicas.commits[i]
                    .get(&h0)
                    .unwrap_or_else(|| panic!("replica {i} missing commit at height {h0}"));
                assert_eq!(
                    other.hash(),
                    b0.hash(),
                    "replica {i}'s block at height {h0} diverges from replica 0's",
                );
            }
        }

        // ── E3 (honest-only slice) ──────────────────────────────────
        //
        // Randomize the delivery schedule: at each step, pick which
        // replica gets to drain one event from its inbox. Unlike the
        // strict round-robin above, this exercises arbitrary
        // interleavings of inter-replica messages — including
        // pathological skews like "replica 0 drains ten events
        // before anyone else delivers once".
        //
        // With no Byzantine replicas the invariant holds trivially
        // (safety rests on the cores themselves, which we've already
        // unit-tested to death). The point of this proptest is to
        // stress the harness: if `apply_actions` has an ordering
        // bug, or if the cores carry implicit schedule-dependent
        // state, the invariant will fail under some seed. PR β
        // extends this with Byzantine event generators; this PR
        // ships the plumbing first so that β's failures are
        // unambiguously Byzantine-driven rather than harness-driven.

        use proptest::prelude::*;

        proptest! {
            #[test]
            fn honest_replicas_never_conflict_under_random_delivery(
                schedule in proptest::collection::vec(0usize..4, 1..=200),
            ) {
                let mut replicas = ReplicaSet::new(4);
                let kickoff = kickoff_proposal(&replicas);
                replicas.inject_all(Event::ProposalReceived(kickoff));

                for replica in schedule {
                    replicas.deliver_one(replica);
                }

                assert_no_conflicting_commits(&replicas);
            }
        }

        // ── β2: Byzantine vote strategy ─────────────────────────────
        //
        // A single enum carries both honest-delivery schedule steps
        // and Byzantine vote injections. Keeping them in one
        // `Vec<ByzantineVoteStep>` (rather than two parallel
        // sequences) lets proptest's shrinker trim the trace
        // uniformly — a failure shrinks to the minimal prefix that
        // triggers the invariant violation.
        //
        // "Byzantine vote" covers double-voting (same Byzantine
        // signer, different (view, block_hash)), voting for forked
        // / phantom blocks (block_hash chosen arbitrarily, likely
        // not in any honest `pending_blocks`), and stale/out-of-
        // order delivery (view bounded low, injected at arbitrary
        // schedule positions). Those three Byzantine attack vectors
        // collapse to "arbitrary signed vote from a Byzantine id".

        #[derive(Debug, Clone)]
        enum ByzantineVoteStep {
            Deliver(usize),
            InjectVote {
                view: View,
                block_hash: BlockHash,
                target_honest: usize,
            },
        }

        fn byzantine_vote_step_strategy(
            n_honest: usize,
        ) -> impl Strategy<Value = ByzantineVoteStep> {
            prop_oneof![
                // Honest deliveries: heavier weight so the run
                // actually makes progress between injections. 3:1
                // is a coarse dial; if Byzantine rates ever need
                // tuning the only effect is test latency vs.
                // strategy coverage.
                3 => (0..n_honest).prop_map(ByzantineVoteStep::Deliver),
                1 => (0u64..8, prop::array::uniform32(any::<u8>()), 0..n_honest).prop_map(
                    |(view, block_hash, target_honest)| ByzantineVoteStep::InjectVote {
                        view,
                        block_hash,
                        target_honest,
                    },
                ),
            ]
        }

        proptest! {
            #[test]
            fn byzantine_votes_never_break_safety(
                schedule in proptest::collection::vec(
                    byzantine_vote_step_strategy(3),
                    1..=200,
                ),
            ) {
                let mut replicas = ReplicaSet::new_with_byzantine(4, 1);
                let byz_nid = replicas.byzantine_nids()[0];
                let kickoff = kickoff_proposal(&replicas);
                replicas.inject_all(Event::ProposalReceived(kickoff));

                for step in schedule {
                    match step {
                        ByzantineVoteStep::Deliver(i) => {
                            replicas.deliver_one(i);
                        }
                        ByzantineVoteStep::InjectVote {
                            view,
                            block_hash,
                            target_honest,
                        } => {
                            let vote = Signed {
                                payload: Vote { view, block_hash },
                                signer: byz_nid,
                                sig: [0u8; 64],
                            };
                            replicas.inject(target_honest, Event::VoteReceived(vote));
                        }
                    }
                }

                assert_no_conflicting_commits(&replicas);
            }
        }
    }
}
