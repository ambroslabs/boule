//! HotStuff-style BFT consensus layer.
//!
//! Consensus sits above [`crate::replication`] (state machine, mempool,
//! block format) and [`boule::storage`] (durable state), and ships its
//! messages through `boule_transport_tcp`. The design discipline of this crate —
//! small object-safe traits, `Arc<dyn Trait>` at the edges, pure state
//! machines in the core — applies here especially hard: HotStuff
//! implementations are historically buggy when safety, liveness, and I/O
//! get tangled together.
//!
//! # Roadmap (#21–#24)
//!
//! - Milestone 6 (#22): [`pacemaker`] — view synchronization and leader
//!   rotation. **Pure state machine, no `tokio`, no I/O.** Broken into:
//!   - 6.A (#86): [`pacemaker::leader`] and [`validator_set`] + this module
//!     skeleton.
//!   - 6.B (#87): `pacemaker::timeout`.
//!   - 6.C (#88): the `Pacemaker` state machine itself.
//! - Milestone 7 (#23): HotStuff safety core as a pure state machine.
//!   Composes with pacemaker, does not call into it.
//! - Milestone 8 (#24): integration layer that translates safety-core and
//!   pacemaker actions into real timers, network sends, and storage writes.
//!
//! # `View` and `Height`
//!
//! [`View`] and [`Height`] are newtype wrappers over `u64`, matching
//! `BlockHeader::view` and `BlockHeader::height` in
//! [`crate::replication::block`]. HotStuff relies on views being strictly
//! increasing; the pacemaker is the only module allowed to advance it.
//! Heights chain monotonically by `+1`.
//!
//! The two are *distinct types* on purpose (audit finding 5-4): nothing
//! in the consensus crate compares a `View` to a `Height`, and the
//! compiler now enforces that. `serde(transparent)` keeps the wire
//! format byte-identical to a bare `u64`.

use std::ops::{Add, AddAssign, Sub, SubAssign};

use serde::{Deserialize, Serialize};

pub mod api;
pub mod block_sync_retry_timer;
pub mod bls_key_history;
pub mod crashpoint;
pub mod dispatch;
pub mod genesis;
pub mod history_commitment;
pub mod hotstuff;
pub mod limits;
pub mod pacemaker;
pub mod reconfig;
pub mod replication;
pub mod snapshot_sync;
pub mod status;
pub mod validator_history;
pub mod validator_key_history;
pub mod validator_rotation;
pub mod validator_set;
pub mod view_timer;
pub mod wire;

/// HotStuff view number — strictly increasing across pacemaker rounds.
///
/// Distinct from [`Height`] (chain position) at the type level: the
/// safety core compares `view` for the liveness rule and `height` for
/// two-chain promotion (Lemma 6 of the HotStuff paper Appendix B).
/// Newtypes catch silent confusion between the two — see audit
/// finding 5-4.
///
/// `serde(transparent)` and `repr(transparent)` keep both the wire
/// format and the in-memory layout byte-identical to a bare `u64`,
/// so introducing the newtype is forward- and backward-compatible.
///
/// Permitted arithmetic: `View + View`, `View - View`, `View + u64`,
/// `View - u64`. Not permitted: any operation that would mix `View`
/// and [`Height`] — those produce a compile error.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(transparent)]
#[repr(transparent)]
pub struct View(pub u64);

/// Block-chain position — strictly increases by `+1` from genesis.
///
/// Distinct from [`View`] (HotStuff round number) at the type level:
/// see [`View`] for the rationale behind the split.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(transparent)]
#[repr(transparent)]
pub struct Height(pub u64);

macro_rules! impl_consensus_scalar {
    ($T:ident) => {
        impl $T {
            /// The zero value of this scalar.
            pub const ZERO: Self = Self(0);

            /// The maximum representable value (`u64::MAX`).
            pub const MAX: Self = Self(u64::MAX);

            /// Construct a value from a raw `u64`.
            pub const fn new(v: u64) -> Self {
                Self(v)
            }

            /// Borrow the underlying `u64`.
            pub const fn as_u64(self) -> u64 {
                self.0
            }

            /// `Some(self + 1)` unless this would overflow `u64`.
            pub fn checked_add(self, rhs: Self) -> Option<Self> {
                self.0.checked_add(rhs.0).map(Self)
            }

            /// `Some(self - rhs)` unless `rhs > self`.
            pub fn checked_sub(self, rhs: Self) -> Option<Self> {
                self.0.checked_sub(rhs.0).map(Self)
            }

            /// Saturating subtraction — never underflows.
            pub const fn saturating_sub(self, rhs: Self) -> Self {
                Self(self.0.saturating_sub(rhs.0))
            }

            /// Saturating addition — never overflows.
            pub const fn saturating_add(self, rhs: Self) -> Self {
                Self(self.0.saturating_add(rhs.0))
            }
        }

        impl From<u64> for $T {
            fn from(v: u64) -> Self {
                Self(v)
            }
        }

        impl From<$T> for u64 {
            fn from(v: $T) -> Self {
                v.0
            }
        }

        impl Add for $T {
            type Output = Self;
            fn add(self, rhs: Self) -> Self {
                Self(self.0 + rhs.0)
            }
        }

        impl Sub for $T {
            type Output = Self;
            fn sub(self, rhs: Self) -> Self {
                Self(self.0 - rhs.0)
            }
        }

        impl AddAssign for $T {
            fn add_assign(&mut self, rhs: Self) {
                self.0 += rhs.0;
            }
        }

        impl SubAssign for $T {
            fn sub_assign(&mut self, rhs: Self) {
                self.0 -= rhs.0;
            }
        }

        impl Add<u64> for $T {
            type Output = Self;
            fn add(self, rhs: u64) -> Self {
                Self(self.0 + rhs)
            }
        }

        impl Sub<u64> for $T {
            type Output = Self;
            fn sub(self, rhs: u64) -> Self {
                Self(self.0 - rhs)
            }
        }

        impl AddAssign<u64> for $T {
            fn add_assign(&mut self, rhs: u64) {
                self.0 += rhs;
            }
        }

        impl SubAssign<u64> for $T {
            fn sub_assign(&mut self, rhs: u64) {
                self.0 -= rhs;
            }
        }

        impl std::fmt::Display for $T {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

impl_consensus_scalar!(View);
impl_consensus_scalar!(Height);

#[allow(unused_imports)]
pub use validator_set::ValidatorSet;

#[cfg(test)]
mod consensus_scalar_tests {
    use super::*;

    #[test]
    fn view_serde_is_transparent_over_u64() {
        let v = View(42);
        let wire_view = postcard::to_stdvec(&v).unwrap();
        let wire_u64 = postcard::to_stdvec(&42u64).unwrap();
        assert_eq!(wire_view, wire_u64);
        let back: View = postcard::from_bytes(&wire_view).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn height_serde_is_transparent_over_u64() {
        let h = Height(7);
        let wire_height = postcard::to_stdvec(&h).unwrap();
        let wire_u64 = postcard::to_stdvec(&7u64).unwrap();
        assert_eq!(wire_height, wire_u64);
        let back: Height = postcard::from_bytes(&wire_height).unwrap();
        assert_eq!(back, h);
    }

    #[test]
    fn view_addition_and_comparison() {
        assert_eq!(View(2) + View(3), View(5));
        assert_eq!(View(5) - View(2), View(3));
        assert!(View(1) < View(2));
        let mut v = View(4);
        v += View(1);
        assert_eq!(v, View(5));
        v -= 2u64;
        assert_eq!(v, View(3));
    }

    #[test]
    fn checked_arithmetic() {
        assert_eq!(View(u64::MAX).checked_add(View(1)), None);
        assert_eq!(View(0).checked_sub(View(1)), None);
        assert_eq!(Height(5).saturating_sub(Height(10)), Height(0));
    }

    // The following SHOULD NOT compile:
    //   View(0) < Height(0);
    //   View(0) + Height(0);
    //   let _: View = Height(0).into();
    //
    // We don't enforce this with a compile-fail test (the workspace
    // doesn't host a trybuild harness yet), but the type relationships
    // above are what the audit relies on.
}
