//! Bounded-cache configuration and eviction counters for the consensus
//! layer.
//!
//! HotStuff's safety core and the integration layer hold a handful of
//! in-memory data structures that, in the absence of explicit caps,
//! grow linearly with the number of distinct messages an attacker (or a
//! recovering-from-partition honest peer) can present:
//!
//! - [`HotStuffCore`](super::hotstuff::step::HotStuffCore) accumulates
//!   partial QCs in `vote_bucket`, keyed by `(view, block_hash)`. A
//!   Byzantine peer that flips one bit of `block_hash` per message
//!   generates an unbounded number of distinct keys.
//! - The same core parks proposals whose parent has not yet arrived in
//!   `parked_proposals`, keyed by the proposal's own block hash —
//!   another flood vector since the attacker can mint distinct
//!   `(view, parent)` tuples cheaply.
//! - The safety core's
//!   [`HotStuffState::pending_blocks`](super::hotstuff::state::HotStuffState::pending_blocks)
//!   map is pruned on commit, but the gap between proposals and the
//!   commit that prunes them is what an attacker exploits.
//! - The integration layer's
//!   [`timeout_buckets`](super::node::ConsensusNode) is keyed by `View`
//!   and is dropped on TC formation, but a flood of timeout votes for
//!   far-future views can grow it before any TC ever fires.
//!
//! [`CacheLimits`] is the configuration knob (parsed from the
//! `[consensus.limits]` table; see [`crate::config::ConsensusLimits`])
//! and [`CacheEvictionCounters`] is the runtime accounting struct that
//! every cache increments on each forced drop.
//!
//! # Eviction policies, at a glance
//!
//! | Cache               | Cap                              | Policy                                                                 |
//! |---------------------|----------------------------------|------------------------------------------------------------------------|
//! | `vote_bucket`       | `vote_bucket_capacity`           | Drop the lowest-`view` entry on insert at cap; drop everything `view < gc_below` on `gc_below` advance. |
//! | `parked_proposals`  | `parked_proposals_capacity`      | Drop the lowest-`view` parked proposal on insert at cap.               |
//! | `pending_blocks`    | `pending_blocks_capacity`        | Drop the lowest-`height` entry on insert at cap, never the genesis nor any block reachable from `high_qc` within three parent links. |
//! | `timeout_buckets`   | `timeout_buckets_capacity`       | Drop the lowest-`view` bucket on insert at cap (TC-formation cleanup is unchanged). |
//!
//! Eviction is logged at INFO (per the issue: eviction under load is
//! expected behaviour, not a warning) with a `cache=` field so an
//! operator can grep the structured logs for sustained drops on a
//! specific cache.

use std::sync::atomic::{AtomicU64, Ordering};

/// Per-cache caps. Exposed both as a configuration shape (parsed from
/// the `[consensus.limits]` TOML table) and as the constructor argument
/// for [`super::hotstuff::step::HotStuffCore`] / the consensus
/// integration layer.
///
/// Defaults are sized for a healthy four-validator cluster with a
/// generous cushion: a steady-state node only ever holds a handful of
/// entries in any of these maps, and the caps are intentionally
/// 1–2 orders of magnitude above that so eviction only ever fires
/// under flood. Operators tuning a larger cluster (or a stricter
/// memory budget) override these via `[consensus.limits]`.
#[derive(Debug, Clone, Copy)]
pub struct CacheLimits {
    /// Maximum distinct `(view, block_hash)` partial-QC entries the
    /// safety core's `vote_bucket` will hold. On insert at cap, the
    /// lowest-`view` entry is dropped.
    pub vote_bucket_capacity: usize,
    /// Maximum distinct parked proposals the safety core will hold
    /// while waiting for parent blocks to arrive via block-sync.
    pub parked_proposals_capacity: usize,
    /// Maximum distinct uncommitted blocks the safety core's
    /// `pending_blocks` map will hold. Eviction never drops genesis
    /// nor blocks reachable from `high_qc` within three parent links.
    pub pending_blocks_capacity: usize,
    /// Maximum distinct timeout-vote buckets the integration layer
    /// holds. Independent of the on-TC-formation drop already in
    /// place; this cap protects against flooding that never reaches
    /// quorum.
    pub timeout_buckets_capacity: usize,
    /// Initial views to wait between successive `RequestBlock` retries
    /// for the same parent hash. Backoff doubles each attempt up to
    /// [`Self::block_sync_max_backoff_views`]. A value of `0` disables
    /// backoff (every `PacemakerAdvance` re-emits, matching the
    /// pre-#196 behaviour preserved by [`Self::unbounded_for_tests`]).
    pub block_sync_initial_backoff_views: u64,
    /// Cap on the per-parent-hash retry gap in views. The exponential
    /// schedule saturates here so a long-stuck parent doesn't push
    /// the next retry arbitrarily far into the future.
    pub block_sync_max_backoff_views: u64,
    /// How many `RequestBlock` retries the safety core sends to the
    /// same peer before rotating to the next validator in the ring.
    /// `0` is treated as `1` (one attempt per peer before rotating).
    pub block_sync_per_peer_attempts: u32,
    /// Total `RequestBlock` retries the safety core will issue for a
    /// single parent hash before dropping every parked proposal that
    /// depends on it. `u32::MAX` disables the budget; eviction then
    /// only fires under the cap-based [`Self::parked_proposals_capacity`]
    /// path.
    pub block_sync_max_attempts: u32,
}

impl CacheLimits {
    /// Permissive defaults that effectively disable cap-based
    /// eviction. Used in property tests and any other harness that
    /// shouldn't have its assertions perturbed by eviction. Production
    /// callers should source from [`Self::production_defaults`] (which
    /// matches the `[consensus.limits]` TOML defaults).
    pub fn unbounded_for_tests() -> Self {
        Self {
            vote_bucket_capacity: usize::MAX,
            parked_proposals_capacity: usize::MAX,
            pending_blocks_capacity: usize::MAX,
            timeout_buckets_capacity: usize::MAX,
            // Backoff disabled (0/0) so every `PacemakerAdvance` fires
            // a retry, `per_peer_attempts = u32::MAX` so retries
            // always go to the original sender (no rotation), and
            // `max_attempts = u32::MAX` so block-sync never gives
            // up — preserves the pre-#196 "ask the same peer
            // forever" behaviour the property tests and wire-fuzz
            // harness assume. The rotate-and-drop path is opt-in:
            // only tests that explicitly set bounded values
            // exercise it.
            block_sync_initial_backoff_views: 0,
            block_sync_max_backoff_views: 0,
            block_sync_per_peer_attempts: u32::MAX,
            block_sync_max_attempts: u32::MAX,
        }
    }

    /// The defaults a node uses when the operator omits
    /// `[consensus.limits]` from `config.toml`. Mirrored in
    /// [`crate::config::ConsensusLimits`] so the two shapes never
    /// drift.
    pub fn production_defaults() -> Self {
        Self {
            vote_bucket_capacity: DEFAULT_VOTE_BUCKET_CAPACITY,
            parked_proposals_capacity: DEFAULT_PARKED_PROPOSALS_CAPACITY,
            pending_blocks_capacity: DEFAULT_PENDING_BLOCKS_CAPACITY,
            timeout_buckets_capacity: DEFAULT_TIMEOUT_BUCKETS_CAPACITY,
            block_sync_initial_backoff_views: DEFAULT_BLOCK_SYNC_INITIAL_BACKOFF_VIEWS,
            block_sync_max_backoff_views: DEFAULT_BLOCK_SYNC_MAX_BACKOFF_VIEWS,
            block_sync_per_peer_attempts: DEFAULT_BLOCK_SYNC_PER_PEER_ATTEMPTS,
            block_sync_max_attempts: DEFAULT_BLOCK_SYNC_MAX_ATTEMPTS,
        }
    }
}

/// Default cap on the `vote_bucket` map. Sized for four to a few dozen
/// validators across a Byzantine-flood window of a few hundred views.
pub const DEFAULT_VOTE_BUCKET_CAPACITY: usize = 1024;
/// Default cap on `parked_proposals`. Each parked proposal is at most
/// one in-flight `RequestBlock` retry per pacemaker tick, so this also
/// caps the per-tick block-sync request rate.
pub const DEFAULT_PARKED_PROPOSALS_CAPACITY: usize = 256;
/// Default cap on `pending_blocks`. Generous for a steady-state node
/// (which only needs a handful of blocks above the commit frontier),
/// tight enough that a flood of distinct future-height blocks gets
/// pruned before consuming meaningful memory.
pub const DEFAULT_PENDING_BLOCKS_CAPACITY: usize = 1024;
/// Default cap on the integration layer's timeout-vote buckets.
pub const DEFAULT_TIMEOUT_BUCKETS_CAPACITY: usize = 1024;
/// Default initial views between successive `RequestBlock` retries on
/// the same parent hash. The first retry is eligible after one
/// `PacemakerAdvance`; subsequent retries double the gap up to
/// [`DEFAULT_BLOCK_SYNC_MAX_BACKOFF_VIEWS`].
pub const DEFAULT_BLOCK_SYNC_INITIAL_BACKOFF_VIEWS: u64 = 1;
/// Default ceiling on the per-parent-hash retry gap in views. With the
/// default initial of `1` and the doubling schedule, the gap saturates
/// here after roughly four attempts.
pub const DEFAULT_BLOCK_SYNC_MAX_BACKOFF_VIEWS: u64 = 8;
/// Default attempts at the same peer before rotating to the next
/// validator in the ring. Two gives the original sender a brief retry
/// window (one redelivery in case the first probe was lost in flight)
/// before fanning out.
pub const DEFAULT_BLOCK_SYNC_PER_PEER_ATTEMPTS: u32 = 2;
/// Default total `RequestBlock` budget per parent hash. With the
/// default `per_peer = 2`, eight attempts cover the original sender
/// plus three rotation rounds, which exhausts the four-validator
/// ring twice. After this, the parked proposals depending on the
/// missing parent are dropped and the
/// [`CacheEvictionCounters::block_sync_dropped`] counter ticks.
pub const DEFAULT_BLOCK_SYNC_MAX_ATTEMPTS: u32 = 8;

/// Atomic counters tracking forced evictions across the consensus
/// caches. Cheap to clone (each inner counter is an `Arc<AtomicU64>`)
/// so the integration layer can hand a separate handle to the safety
/// core and to the timeout-vote handler without sharing a `Mutex`.
#[derive(Debug, Clone, Default)]
pub struct CacheEvictionCounters {
    inner: std::sync::Arc<CacheEvictionCountersInner>,
}

#[derive(Debug, Default)]
struct CacheEvictionCountersInner {
    vote_bucket: AtomicU64,
    parked_proposals: AtomicU64,
    pending_blocks: AtomicU64,
    timeout_buckets: AtomicU64,
    block_sync_dropped: AtomicU64,
}

impl CacheEvictionCounters {
    /// Cumulative number of `vote_bucket` entries dropped since the
    /// counter was created — both cap-based and `gc_below` evictions
    /// contribute. Reads are `Relaxed`; the snapshot may lag a
    /// concurrent eviction by one increment, which is harmless for an
    /// observability counter.
    pub fn vote_bucket(&self) -> u64 {
        self.inner.vote_bucket.load(Ordering::Relaxed)
    }
    /// Cumulative number of `parked_proposals` entries dropped under
    /// cap pressure.
    pub fn parked_proposals(&self) -> u64 {
        self.inner.parked_proposals.load(Ordering::Relaxed)
    }
    /// Cumulative number of `pending_blocks` entries dropped under cap
    /// pressure. The on-commit prune (`retain(height > committed)`)
    /// does not increment this counter — only forced cap evictions do,
    /// since on-commit pruning is expected steady-state behaviour, not
    /// a sign of memory pressure.
    pub fn pending_blocks(&self) -> u64 {
        self.inner.pending_blocks.load(Ordering::Relaxed)
    }
    /// Cumulative number of timeout-vote buckets dropped under cap
    /// pressure. The on-TC-formation drop
    /// (`timeout_buckets.retain(|&v, _| v > view)`) does not
    /// increment this counter; only cap-based evictions do.
    pub fn timeout_buckets(&self) -> u64 {
        self.inner.timeout_buckets.load(Ordering::Relaxed)
    }
    /// Cumulative number of parked proposals dropped after the
    /// `RequestBlock` retry budget was exhausted (see
    /// [`CacheLimits::block_sync_max_attempts`]). Distinct from
    /// [`Self::parked_proposals`], which only counts cap-based
    /// evictions: this counter measures stuck-block-sync drops.
    pub fn block_sync_dropped(&self) -> u64 {
        self.inner.block_sync_dropped.load(Ordering::Relaxed)
    }

    pub(crate) fn inc_vote_bucket(&self, n: u64) {
        if n > 0 {
            self.inner.vote_bucket.fetch_add(n, Ordering::Relaxed);
        }
    }
    pub(crate) fn inc_parked_proposals(&self, n: u64) {
        if n > 0 {
            self.inner.parked_proposals.fetch_add(n, Ordering::Relaxed);
        }
    }
    pub(crate) fn inc_pending_blocks(&self, n: u64) {
        if n > 0 {
            self.inner.pending_blocks.fetch_add(n, Ordering::Relaxed);
        }
    }
    pub(crate) fn inc_timeout_buckets(&self, n: u64) {
        if n > 0 {
            self.inner.timeout_buckets.fetch_add(n, Ordering::Relaxed);
        }
    }
    pub(crate) fn inc_block_sync_dropped(&self, n: u64) {
        if n > 0 {
            self.inner
                .block_sync_dropped
                .fetch_add(n, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let l = CacheLimits::production_defaults();
        // Sanity bounds: caps must be > 0 (a zero-cap cache rejects
        // every insert and immediately deadlocks the safety core).
        assert!(l.vote_bucket_capacity > 0);
        assert!(l.parked_proposals_capacity > 0);
        assert!(l.pending_blocks_capacity > 0);
        assert!(l.timeout_buckets_capacity > 0);
        assert!(l.block_sync_per_peer_attempts >= 1);
        assert!(l.block_sync_max_attempts >= l.block_sync_per_peer_attempts);
        assert!(l.block_sync_initial_backoff_views <= l.block_sync_max_backoff_views);
    }

    #[test]
    fn unbounded_for_tests_does_not_evict() {
        let l = CacheLimits::unbounded_for_tests();
        assert_eq!(l.vote_bucket_capacity, usize::MAX);
        assert_eq!(l.parked_proposals_capacity, usize::MAX);
        assert_eq!(l.pending_blocks_capacity, usize::MAX);
        assert_eq!(l.timeout_buckets_capacity, usize::MAX);
        // No backoff, no rotation, and no drop budget: every
        // PacemakerAdvance fires a retry to the original sender and
        // `block_sync_inflight` never auto-drops parked proposals —
        // preserves pre-#196 semantics for the property tests and
        // the wire-fuzz harness.
        assert_eq!(l.block_sync_initial_backoff_views, 0);
        assert_eq!(l.block_sync_max_backoff_views, 0);
        assert_eq!(l.block_sync_per_peer_attempts, u32::MAX);
        assert_eq!(l.block_sync_max_attempts, u32::MAX);
    }

    #[test]
    fn counters_default_to_zero_and_increment_independently() {
        let c = CacheEvictionCounters::default();
        assert_eq!(c.vote_bucket(), 0);
        assert_eq!(c.parked_proposals(), 0);
        assert_eq!(c.pending_blocks(), 0);
        assert_eq!(c.timeout_buckets(), 0);

        c.inc_vote_bucket(2);
        c.inc_parked_proposals(3);
        c.inc_pending_blocks(5);
        c.inc_timeout_buckets(7);
        c.inc_block_sync_dropped(11);
        assert_eq!(c.vote_bucket(), 2);
        assert_eq!(c.parked_proposals(), 3);
        assert_eq!(c.pending_blocks(), 5);
        assert_eq!(c.timeout_buckets(), 7);
        assert_eq!(c.block_sync_dropped(), 11);

        // Clone shares state — handing a counter handle to two
        // subsystems must aggregate, not split.
        let dup = c.clone();
        dup.inc_vote_bucket(1);
        assert_eq!(c.vote_bucket(), 3);
    }

    #[test]
    fn inc_zero_is_a_no_op() {
        let c = CacheEvictionCounters::default();
        c.inc_vote_bucket(0);
        c.inc_parked_proposals(0);
        c.inc_pending_blocks(0);
        c.inc_timeout_buckets(0);
        c.inc_block_sync_dropped(0);
        assert_eq!(c.vote_bucket(), 0);
        assert_eq!(c.parked_proposals(), 0);
        assert_eq!(c.pending_blocks(), 0);
        assert_eq!(c.timeout_buckets(), 0);
        assert_eq!(c.block_sync_dropped(), 0);
    }
}
