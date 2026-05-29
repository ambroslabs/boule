//! Bounded caches for the consensus layer: the [`CacheLimits`] caps and
//! the [`CacheEvictionCounters`] that record forced drops.
//!
//! Four in-memory maps in the HotStuff core and the integration layer are
//! keyed by attacker-chosen values, so without caps they grow with the
//! number of distinct messages a Byzantine peer — or an honest peer
//! recovering from a partition — can present. Each gets a capacity; on
//! overflow the lowest-priority entry is evicted and a counter is bumped.
//!
//! | Cache | Holds / why it's a flood vector | Cap | Eviction on overflow |
//! |---|---|---|---|
//! | `vote_bucket` | partial QCs keyed by `(view, block_hash)`; flipping one `block_hash` bit mints a fresh key | `vote_bucket_capacity` | drop lowest `view`; also drop all `view < gc_below` when `gc_below` advances |
//! | `parked_proposals` | proposals awaiting a not-yet-arrived parent, keyed by block hash | `parked_proposals_capacity` | drop lowest `view` |
//! | `pending_blocks` | uncommitted blocks; pruned on commit, but the proposal→commit gap is exploitable | `pending_blocks_capacity` | drop lowest `height`, never genesis nor a block within three parent links of `high_qc` |
//! | `timeout_buckets` | timeout votes keyed by `View`; dropped on TC formation, but far-future views pile up before any TC fires | `timeout_buckets_capacity` | drop lowest `view` |
//!
//! [`CacheLimits`] carries the caps; [`CacheEvictionCounters`] is shared
//! by every cache. Forced evictions log at INFO with a `cache=` field — under
//! load they are expected, not a warning, so operators grep for sustained
//! drops on a specific cache.

use std::sync::atomic::{AtomicU64, Ordering};

/// Per-cache caps and block-sync retry knobs the safety core and
/// integration layer take at construction.
///
/// Defaults ([`Self::production_defaults`]) sit 1–2 orders of magnitude
/// above a healthy four-validator cluster's steady-state usage, so
/// eviction only fires under flood; raise them for a larger cluster or
/// lower them for a tighter memory budget.
#[derive(Debug, Clone, Copy)]
pub struct CacheLimits {
    /// Max distinct `(view, block_hash)` partial-QC entries in the
    /// safety core's `vote_bucket`.
    pub vote_bucket_capacity: usize,
    /// Max parked proposals held while their parent blocks arrive via
    /// block-sync.
    pub parked_proposals_capacity: usize,
    /// Max uncommitted blocks in the safety core's `pending_blocks`.
    pub pending_blocks_capacity: usize,
    /// Max timeout-vote buckets in the integration layer. Independent
    /// of the on-TC-formation drop; guards against floods that never
    /// reach quorum.
    pub timeout_buckets_capacity: usize,
    /// Initial view gap between `RequestBlock` retries for the same
    /// parent hash; doubles each attempt up to
    /// [`Self::block_sync_max_backoff_views`]. `0` disables backoff —
    /// every `PacemakerAdvance` re-emits (the behaviour kept by
    /// [`Self::unbounded_for_tests`]).
    pub block_sync_initial_backoff_views: u64,
    /// Ceiling on the per-parent-hash retry gap; the exponential
    /// backoff saturates here so a long-stuck parent's next retry
    /// stays bounded.
    pub block_sync_max_backoff_views: u64,
    /// `RequestBlock` retries sent to one peer before rotating to the
    /// next validator in the ring. `0` is treated as `1`.
    pub block_sync_per_peer_attempts: u32,
    /// Total `RequestBlock` retries for one parent hash before every
    /// parked proposal depending on it is dropped. `u32::MAX` disables
    /// the budget, leaving only the [`Self::parked_proposals_capacity`]
    /// cap path.
    pub block_sync_max_attempts: u32,
}

impl CacheLimits {
    /// Permissive defaults that disable cap-based eviction, for tests
    /// whose assertions shouldn't be perturbed by it. Production callers
    /// use [`Self::production_defaults`].
    pub fn unbounded_for_tests() -> Self {
        Self {
            vote_bucket_capacity: usize::MAX,
            parked_proposals_capacity: usize::MAX,
            pending_blocks_capacity: usize::MAX,
            timeout_buckets_capacity: usize::MAX,
            // Backoff off, no rotation (per_peer = MAX), never give up
            // (max_attempts = MAX): "ask the same peer forever"
            // semantics the property tests and wire-fuzz harness
            // assume. The rotate-and-drop path is opt-in — only tests
            // with explicit bounded values hit it.
            block_sync_initial_backoff_views: 0,
            block_sync_max_backoff_views: 0,
            block_sync_per_peer_attempts: u32::MAX,
            block_sync_max_attempts: u32::MAX,
        }
    }

    /// Production defaults, taken from the `DEFAULT_*` constants in
    /// [`boule_core::config`] so they stay in sync with the defaults of
    /// [`boule_core::config::ConsensusLimits`].
    pub fn production_defaults() -> Self {
        Self {
            vote_bucket_capacity: boule_core::config::DEFAULT_VOTE_BUCKET_CAPACITY,
            parked_proposals_capacity: boule_core::config::DEFAULT_PARKED_PROPOSALS_CAPACITY,
            pending_blocks_capacity: boule_core::config::DEFAULT_PENDING_BLOCKS_CAPACITY,
            timeout_buckets_capacity: boule_core::config::DEFAULT_TIMEOUT_BUCKETS_CAPACITY,
            block_sync_initial_backoff_views:
                boule_core::config::DEFAULT_BLOCK_SYNC_INITIAL_BACKOFF_VIEWS,
            block_sync_max_backoff_views: boule_core::config::DEFAULT_BLOCK_SYNC_MAX_BACKOFF_VIEWS,
            block_sync_per_peer_attempts: boule_core::config::DEFAULT_BLOCK_SYNC_PER_PEER_ATTEMPTS,
            block_sync_max_attempts: boule_core::config::DEFAULT_BLOCK_SYNC_MAX_ATTEMPTS,
        }
    }

    /// Build these caps from [`boule_core::config::ConsensusLimits`], field
    /// for field. (The mempool cap lives on
    /// `boule_core::config::ConsensusConfig`, not here.)
    pub fn from_config(c: &boule_core::config::ConsensusLimits) -> Self {
        Self {
            vote_bucket_capacity: c.vote_bucket_capacity,
            parked_proposals_capacity: c.parked_proposals_capacity,
            pending_blocks_capacity: c.pending_blocks_capacity,
            timeout_buckets_capacity: c.timeout_buckets_capacity,
            block_sync_initial_backoff_views: c.block_sync_initial_backoff_views,
            block_sync_max_backoff_views: c.block_sync_max_backoff_views,
            block_sync_per_peer_attempts: c.block_sync_per_peer_attempts,
            block_sync_max_attempts: c.block_sync_max_attempts,
        }
    }
}

/// Atomic counters for forced evictions across the consensus caches.
/// Clone is a single `Arc` bump, so the integration layer can hand
/// independent handles to the safety core and the timeout-vote handler
/// without a shared `Mutex`.
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
    /// Cumulative `vote_bucket` entries dropped — both cap-based and
    /// `gc_below` evictions count. (Reads are `Relaxed`, as for every
    /// getter here, so a snapshot may lag a concurrent eviction by one;
    /// harmless for an observability counter.)
    pub fn vote_bucket(&self) -> u64 {
        self.inner.vote_bucket.load(Ordering::Relaxed)
    }
    /// Cumulative `parked_proposals` entries dropped under cap pressure.
    pub fn parked_proposals(&self) -> u64 {
        self.inner.parked_proposals.load(Ordering::Relaxed)
    }
    /// Cumulative `pending_blocks` entries dropped under cap pressure.
    /// The on-commit prune (`retain(height > committed)`) is expected
    /// steady-state and does not count — only forced cap evictions do.
    pub fn pending_blocks(&self) -> u64 {
        self.inner.pending_blocks.load(Ordering::Relaxed)
    }
    /// Cumulative timeout-vote buckets dropped under cap pressure. The
    /// on-TC-formation drop (`retain(|&v, _| v > view)`) does not count;
    /// only cap-based evictions do.
    pub fn timeout_buckets(&self) -> u64 {
        self.inner.timeout_buckets.load(Ordering::Relaxed)
    }
    /// Cumulative parked proposals dropped after the `RequestBlock`
    /// retry budget ran out (see
    /// [`CacheLimits::block_sync_max_attempts`]). Unlike
    /// [`Self::parked_proposals`] (cap-based drops), this counts
    /// stuck-block-sync drops.
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
    pub fn inc_timeout_buckets(&self, n: u64) {
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
    fn from_config_maps_every_field() {
        let cfg = boule_core::config::ConsensusLimits {
            vote_bucket_capacity: 11,
            parked_proposals_capacity: 22,
            pending_blocks_capacity: 33,
            timeout_buckets_capacity: 44,
            block_sync_initial_backoff_views: 5,
            block_sync_max_backoff_views: 6,
            block_sync_per_peer_attempts: 7,
            block_sync_max_attempts: 8,
        };
        // Destructure so a newly added `CacheLimits` field that
        // `from_config` forgets is a *compile* error here — that's what
        // makes the "maps every field" guarantee real.
        let CacheLimits {
            vote_bucket_capacity,
            parked_proposals_capacity,
            pending_blocks_capacity,
            timeout_buckets_capacity,
            block_sync_initial_backoff_views,
            block_sync_max_backoff_views,
            block_sync_per_peer_attempts,
            block_sync_max_attempts,
        } = CacheLimits::from_config(&cfg);
        assert_eq!(vote_bucket_capacity, 11);
        assert_eq!(parked_proposals_capacity, 22);
        assert_eq!(pending_blocks_capacity, 33);
        assert_eq!(timeout_buckets_capacity, 44);
        assert_eq!(block_sync_initial_backoff_views, 5);
        assert_eq!(block_sync_max_backoff_views, 6);
        assert_eq!(block_sync_per_peer_attempts, 7);
        assert_eq!(block_sync_max_attempts, 8);
    }

    #[test]
    fn defaults_are_sane() {
        let l = CacheLimits::production_defaults();
        // Caps must be > 0: a zero-cap cache rejects every insert and
        // deadlocks the safety core.
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
        // No backoff, no rotation, no drop budget: every
        // PacemakerAdvance retries the original sender and parked
        // proposals never auto-drop — semantics the property tests and
        // wire-fuzz harness rely on.
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
