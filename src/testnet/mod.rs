//! Parameterized testnet driver: spawn a multi-process ambros-p2p
//! cluster on a single host, drive scenarios against it, and verify
//! safety invariants from the outside.
//!
//! This module is the library half of the `testnet` binary defined in
//! `src/bin/testnet.rs`. Splitting it out lets integration tests call
//! the driver functions directly (without spawning a subprocess) and
//! lets each command live as a focused module.
//!
//! See `docs/testnet-local.md` §9b for the user-facing walkthrough.

pub mod admin;
pub mod cli;
pub mod events;
pub mod lifecycle;
pub mod safety;
pub mod scenario;
pub mod telemetry;
pub mod topology;
pub mod wait;
pub mod workdir;
