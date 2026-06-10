use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Copy)]
pub struct CacheLimits {
    pub vote_bucket_capacity: usize,

    pub parked_proposals_capacity: usize,

    pub pending_blocks_capacity: usize,

    pub timeout_buckets_capacity: usize,

    pub block_sync_initial_backoff_views: u64,

    pub block_sync_max_backoff_views: u64,

    pub block_sync_per_peer_attempts: u32,

    pub block_sync_max_attempts: u32,
}

impl CacheLimits {
    pub fn unbounded_for_tests() -> Self {
        Self {
            vote_bucket_capacity: usize::MAX,
            parked_proposals_capacity: usize::MAX,
            pending_blocks_capacity: usize::MAX,
            timeout_buckets_capacity: usize::MAX,

            block_sync_initial_backoff_views: 0,
            block_sync_max_backoff_views: 0,
            block_sync_per_peer_attempts: u32::MAX,
            block_sync_max_attempts: u32::MAX,
        }
    }

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
    pub fn vote_bucket(&self) -> u64 {
        self.inner.vote_bucket.load(Ordering::Relaxed)
    }

    pub fn parked_proposals(&self) -> u64 {
        self.inner.parked_proposals.load(Ordering::Relaxed)
    }

    pub fn pending_blocks(&self) -> u64 {
        self.inner.pending_blocks.load(Ordering::Relaxed)
    }

    pub fn timeout_buckets(&self) -> u64 {
        self.inner.timeout_buckets.load(Ordering::Relaxed)
    }

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
