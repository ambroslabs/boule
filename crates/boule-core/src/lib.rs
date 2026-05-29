//! `boule-core` — bottom-layer primitives for boule, a peer-to-peer
//! runtime hosting a HotStuff-style BFT consensus layer.
//!
//! This crate is published as `boule-core` but imported as `boule` (its
//! library name). It holds the leaf abstractions the rest of the
//! workspace builds on and depends on nothing else in it: the consensus
//! core (`boule-consensus`), the TCP transport implementation
//! (`boule-transport-tcp`), the node runtime (`boule-node`), and the CLI
//! (`boule-cli`) all sit above it.
//!
//! # Modules
//!
//! - [`crypto`] — Ed25519 / BLS signing schemes and
//!   [`crypto::signed::Signed`] application-level envelopes that survive
//!   being forwarded through intermediaries or reconstructed from storage.
//! - [`identity`] — a node's Ed25519 identity (which IS its overlay
//!   address) plus the key-provider backends that load it.
//! - [`storage`] — [`storage::Storage`] (mutable KV) and [`storage::Wal`]
//!   (append-only log) traits, with an in-memory backend for the simulator
//!   and a `redb`-backed backend for crash-safe durability.
//! - [`clock`] — object-safe time; real [`clock::TokioClock`] in
//!   production, a virtual clock in tests.
//! - [`config`] — configuration structs, TOML loading, and
//!   identity-provider construction.
//! - [`paths`] — cross-platform default locations for config and durable
//!   state.
//! - [`cli`] — output-format helpers shared with `boule-cli`.
//! - [`transport`] — object-safe [`transport::overlay::Broadcaster`] /
//!   [`transport::overlay::Discovery`] traits and the [`transport::limits`]
//!   rate-limit policy; concrete transports (`boule-transport-tcp`)
//!   implement them.
//!
//! # Running a node
//!
//! See the top-level [`README.md`](https://github.com/ambroslabs/boule/blob/main/README.md)
//! for the full layer map and build / run / test instructions.

pub mod cli;
pub mod clock;
pub mod config;
pub mod crypto;
pub mod identity;
pub mod paths;
pub mod storage;
pub mod transport;
