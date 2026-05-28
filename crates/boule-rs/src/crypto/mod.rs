//! Application-level cryptography.
//!
//! TLS secures each hop. For consensus primitives — votes, proposals —
//! we need signatures that survive being forwarded through intermediaries
//! or reconstructed from storage, and that can be verified by any peer
//! that knows the sender's `NodeId`. That lives here.

// Milestone 1: the envelope + signer API are consumed by future milestones
// (voting, proposals) that don't exist yet. Allow dead code until then.
#![allow(dead_code)]

pub mod bls_key;
pub mod sig_scheme;
pub mod signed;
