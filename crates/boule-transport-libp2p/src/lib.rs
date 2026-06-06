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
//! ## Implemented so far
//!
//! - [`identity`] — the `NodeId` ↔ libp2p `PeerId` adapter + the
//!   PKCS#8 → libp2p `Keypair` bridge that reuses the consensus key
//!   (Phase 0, #840).
//! - [`swarm`] — the tokio libp2p `Swarm` over tcp + TLS + yamux, carrying
//!   `identify` (Phase 1, #841).
//!
//! The [`OverlayMode::Libp2p`](boule_core::config::OverlayMode::Libp2p)
//! backend is selectable in config but does not yet wire the `Swarm` into the
//! `Broadcaster`/`Discovery` seam — that begins in Phase 2 (#842).

pub mod identity;
pub mod swarm;
