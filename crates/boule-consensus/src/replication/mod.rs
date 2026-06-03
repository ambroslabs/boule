//! Replicated-state primitives consumed by consensus.
//!
//! Consensus replicates *something* — a state machine — and draws the
//! commands it replicates from *somewhere* — a mempool. To keep consensus
//! testable independently of any real application, both concerns sit behind
//! small, object-safe traits in this module rather than concrete types.
//!
//! The roadmap for this layer is issue #21 (milestone 5), broken into:
//!
//! - 5.A (#80): [`StateMachine`] trait and the reference
//!   [`CounterStateMachine`] (this file and [`state_machine`] / [`impls`]).
//! - 5.B (#81): a `Block` type with structural validation.
//! - 5.C (#82): a `Mempool` trait and in-memory reference impl.
//!
//! # Where this fits
//!
//! HotStuff (#23) replicates ordered commands by agreeing on blocks; the
//! execution path (#24) applies those commands to a [`StateMachine`] and
//! stamps the resulting [`StateMachine::state_commitment`] into the next
//! block header. Snapshots let a replica trim its log without losing the
//! ability to serve a newly joining peer.
//!
//! Like [`boule_core::storage`] and [`boule_core::clock`], traits here are consumed
//! as `Arc<dyn Trait>` — backends are swapped at the edges, not plumbed
//! through generics.

// Traits and types defined here are consumed by future consensus milestones
// (#22–#24). Allow dead code until then, matching `storage/mod.rs` and
// `crypto/mod.rs`.
#![allow(dead_code)]

pub mod application;
pub mod block;
pub mod impls;
pub mod mempool;
pub mod reward_ledger;
pub mod snapshot;
pub mod stake_source;
pub mod state_machine;

#[allow(unused_imports)]
pub use application::{Application, CommitResult, ValidatorUpdate};
#[allow(unused_imports)]
pub use block::{Block, BlockHash, BlockHeader, validate_structural};
#[allow(unused_imports)]
pub use impls::{CounterStateMachine, InMemoryMempool};
#[allow(unused_imports)]
pub use mempool::Mempool;
#[allow(unused_imports)]
pub use snapshot::{SnapshotManifest, SnapshotPolicy, SnapshotStore};
#[allow(unused_imports)]
pub use stake_source::{BondedStakeLedger, StakeOp, StakeSource};
#[allow(unused_imports)]
pub use state_machine::StateMachine;
