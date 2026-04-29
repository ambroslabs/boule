//! HotStuff-style BFT consensus layer.
//!
//! Consensus sits above [`crate::replication`] (state machine, mempool,
//! block format) and [`crate::storage`] (durable state), and ships its
//! messages through [`crate::p2p`]. The design discipline of this crate —
//! small object-safe traits, `Arc<dyn Trait>` at the edges, pure state
//! machines in the core — applies here especially hard: HotStuff
//! implementations are historically buggy when safety, liveness, and I/O
//! get tangled together.
//!
//! # Roadmap (#21–#24)
//!
//! - Milestone 6 (#22): [`pacemaker`] — view synchronization and leader
//!   rotation. **Pure state machine, no `tokio`, no I/O.** Broken into:
//!   - 6.A (#86): [`pacemaker::leader`] and [`validator_set`] + this module
//!     skeleton.
//!   - 6.B (#87): `pacemaker::timeout`.
//!   - 6.C (#88): the `Pacemaker` state machine itself.
//! - Milestone 7 (#23): HotStuff safety core as a pure state machine.
//!   Composes with pacemaker, does not call into it.
//! - Milestone 8 (#24): integration layer that translates safety-core and
//!   pacemaker actions into real timers, network sends, and storage writes.
//!
//! # `View`
//!
//! The [`View`] alias is a `u64` matching `BlockHeader::view` in
//! [`crate::replication::block`]. HotStuff relies on views being strictly
//! increasing; the pacemaker is the only module allowed to advance it.

// Some items in sub-modules are consumed across PRs; allow until wired up.
#![allow(dead_code)]

pub mod api;
pub mod bls_key_history;
pub mod dispatch;
pub mod history_commitment;
pub mod hotstuff;
pub mod limits;
pub mod node;
pub mod pacemaker;
pub mod reconfig;
pub mod snapshot_sync;
pub mod status;
pub mod validator_history;
pub mod validator_key_history;
pub mod validator_rotation;
pub mod validator_set;
pub mod view_timer;

#[cfg(test)]
pub mod sim;

#[cfg(test)]
mod sim_byzantine;

#[cfg(test)]
mod wire_fuzz;

/// HotStuff view number.
pub type View = u64;

#[allow(unused_imports)]
pub use validator_set::ValidatorSet;
