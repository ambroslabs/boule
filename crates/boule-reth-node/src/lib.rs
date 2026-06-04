//! boule-reth-node — the custom reth execution-layer node (Option A, #777).
//!
//! This crate embeds reth **as a library** (no source fork) and composes a
//! custom node via `NodeBuilder` that applies boule's registry writes
//! (`recordKey` / `recordWeight` / `recordSettled`) as **deterministic system
//! calls** at the block boundary — the EIP-4788 model — instead of as signed
//! transactions. Every replica (proposer and verifier) computes the identical
//! write, so `recordWeight` is integrity-correct even under a Byzantine proposer
//! (the reason Option B was rejected; see #777).
//!
//! ## The pipeline
//!
//! ```text
//!   boule consensus computes (keys, weights, settledView)
//!     │  (the authoritative per-block registry write set)
//!     ▼
//!   forkchoiceUpdatedV3(BoulePayloadAttributes { registryPayload: hex })   [ingress]
//!     │   engine_types.rs
//!     ▼
//!   BoulePayloadBuilder transcribes it into header `extra_data`            [build]
//!     │   payload.rs  (extra_data is the carrier; a PayloadAttributes field
//!     │                is build-only and is dropped before sealing)
//!     ▼
//!   sealed block ──propagate──▶ newPayloadV4 on every replica              [verify]
//!     │
//!     ▼
//!   CustomBlockExecutor reads `extra_data` (same bytes on build AND verify) [apply]
//!     │   executor.rs → apply_pre_execution_changes
//!     ▼
//!   SYSTEM-caller system calls to the Registry predeploy: recordKey*,
//!   recordWeight*, recordSettled  → byte-identical Registry storage.
//! ```
//!
//! ## Modules
//! - [`registry`] — the `(keys, weights, settledView)` payload + its `extra_data`
//!   codec + the three system-call appliers.
//! - [`executor`] — `ConfigureEvm` + `ConfigureEngineEvm` + `BlockExecutor`.
//! - [`payload`] — the custom payload builder (extra_data transcription).
//! - [`engine_types`] — custom `PayloadAttributes` / `EngineTypes` / validator.
//! - [`consensus`] — relaxed `extra_data` cap (encoding option a).
//! - [`node`] — the `NodeBuilder` assembly.

pub mod consensus;
pub mod engine_types;
pub mod executor;
pub mod node;
pub mod payload;
pub mod registry;

pub use node::BouleNode;
pub use registry::{KeyRecord, RegistryPayload, WeightRecord};
