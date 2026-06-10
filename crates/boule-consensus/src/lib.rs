use std::ops::{Add, AddAssign, Sub, SubAssign};

use serde::{Deserialize, Serialize};

pub mod api;
pub mod block_sync_retry_timer;
pub mod bls_key_history;
pub mod consensus_params;
pub mod dispatch;
pub mod endpoint_registry;
pub mod equivocation_evidence;
pub mod genesis;
pub mod history_commitment;
pub mod hotstuff;
pub mod limits;
pub mod liveness_tracker;
pub mod node_role;
pub mod operator_key_history;
pub mod pacemaker;
pub mod rate_limit;
pub mod reconfig;
pub mod reconfig_consent;
pub mod replication;
pub mod snapshot_sync;
pub mod status;
pub mod validator_history;
pub mod validator_key_history;
pub mod validator_rotation;
pub mod validator_set;
pub mod view_timer;
pub mod wire;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(transparent)]
#[repr(transparent)]
pub struct View(pub u64);

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(transparent)]
#[repr(transparent)]
pub struct Height(pub u64);

macro_rules! impl_consensus_scalar {
    ($T:ident) => {
        impl $T {
            pub const ZERO: Self = Self(0);

            pub const MAX: Self = Self(u64::MAX);

            pub const fn new(v: u64) -> Self {
                Self(v)
            }

            pub const fn as_u64(self) -> u64 {
                self.0
            }

            pub fn checked_add(self, rhs: Self) -> Option<Self> {
                self.0.checked_add(rhs.0).map(Self)
            }

            pub fn checked_sub(self, rhs: Self) -> Option<Self> {
                self.0.checked_sub(rhs.0).map(Self)
            }

            pub const fn saturating_sub(self, rhs: Self) -> Self {
                Self(self.0.saturating_sub(rhs.0))
            }

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
