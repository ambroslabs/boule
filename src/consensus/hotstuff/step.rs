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

use super::qc::{NewView, Proposal, Vote};

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
