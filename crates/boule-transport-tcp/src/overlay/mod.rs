//! Object-safe traits that abstract the full-mesh peer model so the
//! consensus layer can treat the underlying topology as a black box.
//!
//! The current peer manager (`super::manager`) keeps an explicit
//! connection to every other validator and broadcasts by iterating that
//! table. That model is fine for a single-operator testnet but doesn't
//! fit the multi-operator deployment laid out in issue #131:
//!
//! - No operator wants to maintain N–1 explicit peering relationships.
//! - Adding a validator shouldn't require a coordinated config push.
//! - NAT-asymmetric operators need ways to be reached without being dialed.
//! - New operators need a way to *find* the network beyond a few bootstrap
//!   addresses.
//!
//! Two seams suffice to keep consensus topology-agnostic:
//!
//! - [`boule_core::transport::overlay::Broadcaster`] hides the *outbound* dispatch decision behind two
//!   methods: `broadcast` (fan out to every "currently reachable" peer)
//!   and `send_to` (a single named peer). The mesh implementation
//!   ([`crate::overlay::MeshBroadcaster`]) routes both through the existing peer-manager
//!   channel; a future gossip implementation will pick a fanout subset
//!   and rely on the receiver to forward.
//! - [`boule_core::transport::overlay::Discovery`] hides the *peer-membership* surface behind
//!   `known_peers` (snapshot), `add_bootstrap` (request a dial to a
//!   freshly learned address), and `subscribe` (event stream of
//!   add/remove deltas). The mesh implementation ([`crate::overlay::MeshDiscovery`])
//!   maintains a local cache fed by the manager's add/remove broadcast.
//!
//! # Delivery contract
//!
//! Implementations of [`boule_core::transport::overlay::Broadcaster`] guarantee **at-least-once**
//! delivery on a best-effort basis: a frame may be delivered more than
//! once under retries (e.g. when gossip lands and a frame is forwarded
//! by two neighbours), and there is **no ordering guarantee** across
//! distinct calls — even on the mesh today, broadcasting and
//! send_to-ing concurrently can interleave on receivers in any order.
//! Receivers are responsible for deduplication; consensus already does
//! this via the per-view vote/proposal buckets in
//! `boule_consensus::hotstuff`.
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
//! - `mesh` — the legacy full-mesh impl that ships today. Still the
//!   default until the gossip overlay is ready to take over.
//! - [`crate::overlay::gossip`] — partial-mesh gossip overlay (issue #137). Currently
//!   under construction; types live here but nothing wires them up
//!   yet.
//!
//! # Non-goals (deferred to follow-up issues)
//!
//! - NAT traversal.
//! - Dynamic membership / validator-set changes.

mod mesh;

pub mod gossip;

pub use boule_core::transport::overlay::{Broadcaster, Discovery, DiscoveryEvent};
pub use mesh::{MeshBroadcaster, MeshDiscovery};
