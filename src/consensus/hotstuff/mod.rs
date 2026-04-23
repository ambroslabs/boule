//! HotStuff safety core.
//!
//! Safety (never committing conflicting blocks) lives here; liveness
//! (view advancement, timeouts) lives in [`super::pacemaker`]. Keeping
//! them separate makes each half small enough to unit-test against a
//! mock of the other — the central modularity discipline of issues
//! #22–#24.
//!
//! # Purity
//!
//! Everything in this module is deliberately I/O-free: no `tokio`, no
//! [`crate::clock::Clock`], no network, no [`crate::storage`]. Inputs
//! are [`Event`]s; outputs are [`Action`]s. The milestone 8 integration
//! layer (#24) translates returned actions into real effects (syncing
//! WAL, sending messages, advancing views). This is what lets the core
//! run unmodified in the deterministic simulator and in production.
//!
//! ```text
//!  ┌───────────────┐  Event  ┌────────────────┐  Vec<Action>  ┌───────────────┐
//!  │  pacemaker +  │────────▶│ HotStuffCore   │──────────────▶│ integration   │
//!  │   network     │         │  ::step(ev)    │               │ layer (#24)   │
//!  └───────────────┘         └────────────────┘               └───────────────┘
//! ```
//!
//! # Module layout
//!
//! - [`qc`] (7.A / #91): [`qc::QuorumCertificate`], [`qc::SignerBitmap`],
//!   the wire-payload types [`qc::Proposal`] / [`qc::Vote`] /
//!   [`qc::NewView`], and the [`qc::ConsensusMsg`] envelope that wraps
//!   them.
//! - `state.rs` (7.B / #92): [`HotStuffState`] and the pure safety
//!   predicates (`extends`, `safe_to_vote`, `three_chain_commit`, …).
//! - `step.rs` (7.C / #93): [`Event`] / [`Action`] / the `HotStuffCore`
//!   state machine and `step()` dispatcher.
//!
//! 7.A ships the types; 7.B and 7.C fill in the rest.

// Types in this module are wired up across 7.A/7.B/7.C. Until 7.C
// lands, some of them have no consumers; matches the dead-code
// allowance used in [`super`] for the same reason.
#![allow(dead_code)]

pub mod qc;
pub mod safety_rules;
pub mod state;
pub mod step;

pub use qc::{ConsensusMsg, NewView, Proposal, QuorumCertificate, SignerBitmap, Vote, quorum_size};
pub use state::HotStuffState;
pub use step::{Action, BlockBuilder, Event, HotStuffCore, StateUpdate};
