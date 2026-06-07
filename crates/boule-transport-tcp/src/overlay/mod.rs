//! Object-safe traits that abstract the peer model so the consensus
//! layer can treat the underlying topology as a black box.
//!
//! Consensus is transport-agnostic: `ConsensusNode::run` takes
//! `Arc<dyn Broadcaster>` + `Arc<dyn Discovery>` and never names a
//! concrete overlay. Two seams keep it that way:
//!
//! - [`boule_core::transport::overlay::Broadcaster`] hides the *outbound*
//!   dispatch decision behind two methods: `broadcast` (fan out to every
//!   "currently reachable" peer) and `send_to` (a single named peer).
//! - [`boule_core::transport::overlay::Discovery`] hides the
//!   *peer-membership* surface behind `known_peers` (snapshot),
//!   `add_bootstrap` (request a dial to a freshly learned address), and
//!   `subscribe` (event stream of add/remove deltas).
//!
//! # Delivery contract
//!
//! Implementations of [`boule_core::transport::overlay::Broadcaster`]
//! guarantee **at-least-once** delivery on a best-effort basis: a frame
//! may be delivered more than once under retries (e.g. when gossip lands
//! and a frame is forwarded by two neighbours), and there is **no
//! ordering guarantee** across distinct calls. Receivers are responsible
//! for deduplication; consensus already does this via the per-view
//! vote/proposal buckets in `boule_consensus::hotstuff`.
//!
//! Both `broadcast` and `send_to` return a future so the caller can
//! preserve the existing `await`-on-send backpressure. A successfully
//! awaited send means the bytes have been handed to the underlying
//! transport queue, not that any peer has decoded them.
//!
//! # Self-addressed traffic
//!
//! `send_to(self_id, …)` is dropped on the wire; the consensus layer
//! handles self-loopback above this seam in
//! `ConsensusNode::apply_safety_actions` (see issue #118).
//!
//! # Implementations
//!
//! - [`crate::overlay::gossip`] — the partial-mesh gossip overlay (issue
//!   #137). The production overlay, and the only one wired into
//!   `node::run`.
//! - `memory` — in-memory [`crate::overlay::Broadcaster`] /
//!   [`crate::overlay::Discovery`] **test fakes**
//!   ([`crate::overlay::MemoryBroadcaster`] /
//!   [`crate::overlay::MemoryDiscovery`]). Not a transport: they let
//!   tests drive a transport-agnostic `ConsensusNode` over plain
//!   channels without standing up TCP+TLS.
//!
//! # Non-goals (deferred to follow-up issues)
//!
//! - NAT traversal.
//! - Dynamic membership / validator-set changes.

pub mod gossip;

// `MemoryBroadcaster`/`MemoryDiscovery` moved to `boule-core` (test doubles,
// transport-agnostic); re-exported here for back-compat.
pub use boule_core::transport::overlay::{
    Broadcaster, Discovery, DiscoveryEvent, MemoryBroadcaster, MemoryDiscovery,
};
