// Step 2 of issue #19 lands the scaffolding for the simulator. Several
// methods and fields are unused until subsequent sub-issues consume them
// (e.g. `SimDriver::advance` and the network's RNG land here so they're
// available when fault injection in #30 plugs in).
#![allow(dead_code)]

//! Deterministic in-process simulation harness for consensus testing.
//!
//! The simulator wires N nodes together using the existing
//! [`crate::p2p::ConnectionProtocol`] seam, replacing the TCP/TLS transport
//! with in-memory duplex pipes. Time is virtual — driven by the test through
//! [`SimDriver::advance`] — and `tokio::time::*` is paused so any clock-driven
//! code under test (cleanup tasks, RPC timeouts) cooperates with the test's
//! pace rather than racing wall-clock.
//!
//! # Scope of this module
//!
//! Step 2 of the issue #19 breakdown lands the core wiring with an *ideal*
//! network: no latency, no drops, no partitions. The hooks for those
//! (per-link state on [`network::SimNetwork`]) exist but are stubs; fault
//! injection lands in a follow-up sub-issue.
//!
//! # Determinism
//!
//! Each call to [`SimDriver::new`] takes a `seed`, which seeds the network's
//! [`rand_chacha::ChaCha20Rng`]. With the test running on a `current_thread`
//! tokio runtime under `start_paused = true`, two runs of the same script
//! against the same seed should produce identical observable behaviour. A
//! rigorous byte-identical-trace test lands in a follow-up sub-issue.

pub mod clock;
pub mod driver;
pub mod network;
pub mod stream;
pub mod transport;

pub use clock::SimClock;
pub use driver::SimDriver;
pub use network::{LatencyDist, LinkConfig};

#[cfg(test)]
mod sim_gossip;
