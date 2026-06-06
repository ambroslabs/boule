//! libp2p transport backend for boule — the migration target (#840) that
//! will replace `boule-transport-tcp`'s custom gossip overlay.
//!
//! The migration is staged behind the `boule_core::transport::overlay`
//! `Broadcaster` / `Discovery` seam, so consensus is untouched; this crate
//! provides an alternative implementation of that seam over a single libp2p
//! `Swarm`:
//!
//! - **gossipsub** → [`Broadcaster::broadcast`](boule_core::transport::overlay::Broadcaster::broadcast)
//!   (Phase 2, #842)
//! - **request-response** → [`Broadcaster::send_to`](boule_core::transport::overlay::Broadcaster::send_to)
//!   + block-sync (Phase 3, #843)
//! - **identify + kad** → [`Discovery`](boule_core::transport::overlay::Discovery)
//!   (Phase 4, #844)
//!
//! ## Phase 0 (this commit)
//!
//! Only the [`identity`] adapter (`NodeId` ↔ libp2p `PeerId`) is implemented.
//! It is the foundational, fully-testable piece every later phase builds on:
//! it proves the addressing model maps 1:1 without a side table. The
//! [`OverlayMode::Libp2p`](boule_core::config::OverlayMode::Libp2p) backend is
//! selectable in config but fails closed until Phase 1 lands the `Swarm`.

pub mod identity;
