//! HotStuff pacemaker: view synchronization and leader rotation.
//!
//! The pacemaker is the liveness half of HotStuff — it drives view
//! changes, timeouts, and leader rotation. Safety (never committing
//! conflicting blocks) lives in the milestone 7 safety core (#23).
//! Keeping the two modules separate makes each one small enough to test
//! against a mock of the other, which is the central modularity
//! discipline of issue #22.
//!
//! # Purity
//!
//! Everything here is deliberately I/O-free: no `tokio`, no
//! [`crate::clock::Clock`], no network. Inputs are events; outputs are
//! values. The milestone 8 integration layer (#24) translates the
//! returned actions into real effects (arming timers, sending messages).
//! This is what lets the pacemaker run unmodified in the deterministic
//! simulator and in production.
//!
//! # Module layout (lands across 6.A/6.B/6.C)
//!
//! - [`leader`] (6.A / #86): [`leader::LeaderSelector`] trait + default
//!   [`leader::RoundRobinSelector`].
//! - `timeout` (6.B / #87): `TimeoutPolicy` trait + exponential backoff.
//! - `Pacemaker` state machine (6.C / #88): `step(Event) -> Vec<Action>`.

pub mod leader;
