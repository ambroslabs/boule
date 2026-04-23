//! `ambros-p2p` — a peer-to-peer runtime built to host a HotStuff-style BFT
//! consensus layer.
//!
//! The crate ships both a library target (these modules) and a binary target
//! (`src/main.rs`) that wires them into a running node. Keeping the layering
//! below consensus in a library lets `cargo test --doc` compile the examples
//! here and lets future integration work import the pieces directly.
//!
//! # Layer map
//!
//! ```text
//!                  ┌──────────────────────────────┐
//!                  │          consensus           │  (future; see #21–#24)
//!                  └──────────────┬───────────────┘
//!        signed envelopes         │         durable state
//!                ┌────────────────┴─────────────────┐
//!                ▼                                  ▼
//!   ┌─────────────────────┐              ┌─────────────────────┐
//!   │     crypto (§)      │              │    storage (§)      │
//!   │  Ed25519 signing    │              │ Storage + Wal KV    │
//!   └─────────────────────┘              └─────────────────────┘
//!                │                                  │
//!                │          dissemination           │
//!                │       ┌──────────────────┐       │
//!                └──────▶│    gossip (§)    │◀──────┘
//!                        │  store + engine  │
//!                        └────────┬─────────┘
//!                                 │ ProtocolHandle
//!                                 ▼
//!                        ┌──────────────────┐
//!                        │      p2p (§)     │
//!                        │  TLS transport,  │
//!                        │  rpc, manager    │
//!                        └────────┬─────────┘
//!                                 │ Clock + network I/O
//!                 ┌───────────────┴───────────────┐
//!                 ▼                               ▼
//!        ┌─────────────────┐              ┌─────────────────┐
//!        │    clock (§)    │              │     sim (§)     │
//!        │  real / virtual │              │ deterministic   │
//!        │      time       │              │ test harness    │
//!        └─────────────────┘              └─────────────────┘
//! ```
//!
//! - [`p2p`] — TLS-authenticated transport, a protocol multiplexer, a peer
//!   manager, and a request/response [`p2p::rpc`] layer on top of it. The
//!   node's [`p2p::identity`] (Ed25519) IS its overlay address.
//! - [`gossip`] — best-effort dissemination of opaque application messages,
//!   built on a [`p2p::ProtocolHandle`].
//! - [`crypto`] — application-level signed envelopes that survive being
//!   forwarded through intermediaries or reconstructed from storage
//!   (consensus votes and proposals will wrap in these).
//! - [`clock`] — object-safe time abstraction; real [`clock::TokioClock`]
//!   in production, virtual `SimClock` in tests.
//! - `sim` — test-only deterministic simulator that plugs in at the
//!   [`p2p::ConnectionProtocol`] seam, replaces the network with in-memory
//!   pipes, and drives virtual time. Behind `#[cfg(test)]` so it does not
//!   ship in the binary.
//! - [`storage`] — [`storage::Storage`] (mutable KV) and [`storage::Wal`]
//!   (append-only log) traits. An in-memory backend serves the simulator;
//!   a `redb`-backed backend provides crash-safe durability. This is where
//!   HotStuff's `last_voted_view` and `locked_qc` will live.
//!
//! # Where consensus fits
//!
//! Consensus is not yet present. When it lands it will be driven by a new
//! top-level module that:
//!
//! 1. Reads and writes durable state through [`storage::Storage`] /
//!    [`storage::Wal`].
//! 2. Produces [`crypto::signed::Signed`]-wrapped votes and proposals.
//! 3. Ships those over a new protocol ID through [`p2p::rpc`] or a direct
//!    [`p2p::ProtocolHandle`].
//! 4. Schedules timeouts through [`clock::Clock`] so it runs unmodified
//!    under both real time and the deterministic simulator.
//!
//! The HotStuff roadmap is tracked in issues #21–#24; this crate-level
//! doc is the companion to that roadmap.
//!
//! # Running a node
//!
//! See the top-level [`README.md`](https://github.com/zrbecker/ambros-p2p/blob/main/README.md)
//! for build / run / test instructions and the configuration reference.

pub mod clock;
pub mod config;
pub mod crypto;
pub mod gossip;
pub mod p2p;
pub mod ping;
pub mod replication;
#[cfg(test)]
mod sim;
pub mod storage;
