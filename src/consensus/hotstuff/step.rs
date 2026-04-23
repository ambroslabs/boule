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
use super::state::HotStuffState;

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
    /// Replica promoted its `locked_qc` via the two-chain rule.
    LockedQc(QuorumCertificate),
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
    /// **Scaffold.** Every dispatch rule from #93 is introduced by a
    /// later commit alongside the unit test that pins its behavior;
    /// for now, `step` is the identity-over-no-effect function.
    pub fn step(&mut self, _event: Event) -> Vec<Action> {
        Vec::new()
    }

    /// Feed a trace of events through `step` in order, returning one
    /// `Vec<Action>` per event. Consumes `self` so callers can't
    /// accidentally keep a reference into the core across the replay.
    pub fn replay(mut self, events: impl IntoIterator<Item = Event>) -> Vec<Vec<Action>> {
        events.into_iter().map(|e| self.step(e)).collect()
    }
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
}
