//! Per-concern verifiers for inbound consensus frames.
//!
//! Each submodule owns one verification check; the Proposal/Vote/
//! NewView/TimeoutVote ingress arms compose them in
//! [`super::ingress`]. Splitting the gates by concern (rather than by
//! match arm) keeps each audit-cluster issue (#318–#322, #324, #325
//! PR C) confined to a single file.
//!
//! - [`envelope`]: signer membership + Ed25519 envelope signature
//!   over the chain-id-bound pre-image.
//! - [`qc`]: QC aggregate verification (Ed25519 + BLS) and the
//!   soft-verify path for the [`TimeoutVote`](crate::hotstuff::qc::TimeoutVote)
//!   piggyback.
//! - [`bls_partial`]: required BLS partial-signature gate on Vote
//!   frames over a `bls_aggregated` chain.
//! - [`domain`]: chain-id pre-image binding (#324) — wraps
//!   [`boule_core::crypto::signed::preimage`] for the call sites here.
//! - [`proposal_history`]: validator-history commitment check on
//!   inbound Proposals (#325 PR C).

pub(super) mod bls_partial;
pub(super) mod domain;
pub(super) mod envelope;
pub(super) mod equivocation;
pub(super) mod proposal_history;
pub(super) mod qc;
