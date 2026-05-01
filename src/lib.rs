//! `ambros-p2p` — a peer-to-peer runtime hosting a HotStuff-style BFT
//! consensus layer.
//!
//! The crate ships both a library target (these modules) and a binary target
//! (`src/main.rs`) that wires them into a running node. Keeping the layering
//! in a library lets `cargo test --doc` compile the examples here and lets
//! integration tests + the `start` subcommand share one definition of "what
//! a running node looks like" via [`node::run`].
//!
//! # Layer map
//!
//! ```text
//!                  ┌──────────────────────────────┐
//!                  │          consensus           │  HotStuff-style BFT
//!                  └──────────────┬───────────────┘
//!        signed envelopes         │         durable state
//!                ┌────────────────┴─────────────────┐
//!                ▼                                  ▼
//!   ┌─────────────────────┐              ┌─────────────────────┐
//!   │     crypto (§)      │              │    storage (§)      │
//!   │  Ed25519 signing    │              │ Storage + Wal KV    │
//!   └─────────────────────┘              └─────────────────────┘
//!                │                                  │
//!                └──────────────┬───────────────────┘
//!                               │ ProtocolHandle
//!                               ▼
//!                      ┌──────────────────┐
//!                      │      p2p (§)     │
//!                      │  TLS transport,  │
//!                      │  rpc, manager    │
//!                      └────────┬─────────┘
//!                               │ Clock + network I/O
//!                               ▼
//!                      ┌──────────────────┐
//!                      │    clock (§)     │
//!                      │  real / virtual  │
//!                      │       time       │
//!                      └──────────────────┘
//! ```
//!
//! - [`consensus`] — HotStuff-style BFT replica, including the safety
//!   core, the pacemaker, and the wire protocol. Reads and writes
//!   durable state through [`storage::Storage`] / [`storage::Wal`],
//!   wraps votes and proposals in [`crypto::signed::Signed`], and
//!   schedules its timers through [`clock::Clock`] so it runs
//!   unmodified under both real time and the deterministic simulator.
//! - [`p2p`] — TLS-authenticated transport, a protocol multiplexer, a peer
//!   manager, and a request/response [`p2p::rpc`] layer on top of it. The
//!   node's [`p2p::identity`] (Ed25519) IS its overlay address.
//! - [`crypto`] — application-level signed envelopes that survive being
//!   forwarded through intermediaries or reconstructed from storage.
//! - [`clock`] — object-safe time abstraction; real [`clock::TokioClock`]
//!   in production, virtual `SimClock` in tests.
//! - [`storage`] — [`storage::Storage`] (mutable KV) and [`storage::Wal`]
//!   (append-only log) traits. An in-memory backend serves the simulator;
//!   a `redb`-backed backend provides crash-safe durability. HotStuff's
//!   `last_voted_view` and `locked_qc` live here.
//! - [`node`] — the top-level runtime that ties everything together.
//!   `main.rs` calls [`node::run`] under the `start` subcommand.
//! - [`paths`] — cross-platform default locations for config and durable
//!   state; the binary's `init` and `start` subcommands consult these
//!   when `--config` is omitted.
//!
//! # Running a node
//!
//! See the top-level [`README.md`](https://github.com/zrbecker/ambros-p2p/blob/main/README.md)
//! for build / run / test instructions and the configuration reference,
//! and `docs/testnet-local.md` for a walkthrough of the
//! `ambros-p2p init` → `ambros-p2p start` flow.

pub mod cli;
pub mod clock;
pub mod config;
pub mod consensus;
pub mod crypto;
pub mod node;
pub mod p2p;
pub mod paths;
pub mod replication;
pub mod storage;
pub mod testnet;
