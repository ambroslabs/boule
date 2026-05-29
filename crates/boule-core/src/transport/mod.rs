//! Transport interface for boule.
//!
//! The object-safe [`overlay::Broadcaster`] / [`overlay::Discovery`] traits
//! abstract the peer model so the node runtime treats the underlying
//! topology as a black box, and [`limits`] holds the transport-agnostic
//! rate-limit policy (message classification, token buckets, connection
//! caps). Concrete transports (e.g. `boule-transport-tcp`) implement these;
//! the node runtime programs against them.

pub mod limits;
pub mod overlay;
