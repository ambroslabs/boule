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

use crate::consensus::View;
use crate::crypto::signed::Signed;
use crate::p2p::NodeId;
use crate::replication::block::{Block, BlockHash};

use super::qc::{ConsensusMsg, NewView, Proposal, QuorumCertificate, Vote};

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

#[cfg(test)]
pub(crate) mod testing {
    //! Deterministic `BlockBuilder` impls the unit and property tests
    //! reach for. Gated behind `cfg(test)` so non-test builds don't
    //! accidentally ship them.

    use super::*;
    use crate::replication::block::BlockHeader;

    /// `BlockBuilder` that stamps an empty-commands child over `parent`
    /// with a caller-configured `proposer` and a zero
    /// `state_commitment`. The header is deterministic in `(parent,
    /// view, proposer)`; the `high_qc` argument is intentionally
    /// ignored because these tests don't exercise the execution layer.
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
}
