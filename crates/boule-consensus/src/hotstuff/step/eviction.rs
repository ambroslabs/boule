//! Bounded-cache eviction for vote buckets and parked proposals.
use super::*;

impl HotStuffCore {
    /// Drop every parked proposal whose `parent_hash` matches and tear down the
    /// in-flight tracker. Increments
    /// [`CacheEvictionCounters::block_sync_dropped`] and emits one WARN per drop
    /// to correlate it with the missing parent. WARN (not the INFO used for
    /// cap-based eviction) because giving up on an unfetchable parent is a real
    /// liveness signal, not expected steady-state behaviour.
    pub(super) fn drop_parked_for_parent(&mut self, parent_hash: BlockHash) {
        let victims: Vec<BlockHash> = self
            .parked_proposals
            .iter()
            .filter(|(_, signed)| signed.payload.block.header.parent_hash == parent_hash)
            .map(|(child_hash, _)| *child_hash)
            .collect();
        for child_hash in &victims {
            self.parked_proposals.remove(child_hash);
        }
        let dropped = victims.len() as u64;
        if dropped > 0 {
            self.eviction_counters.inc_block_sync_dropped(dropped);
            tracing::warn!(
                target: TRACE_TARGET,
                cache = "block_sync_inflight",
                policy = "max_attempts_exhausted",
                parent_hash = ?parent_hash,
                dropped,
                attempts = self.limits.block_sync_max_attempts,
                "block_sync_request_dropped",
            );
        }
        self.block_sync_inflight.remove(&parent_hash);
    }

    /// Drop every `vote_bucket` entry whose `view < gc_below`. Invoked on
    /// `PacemakerAdvance` so a stale-vote flood on long-past views cannot
    /// accumulate indefinitely.
    ///
    /// Sweeps `vote_dedupe` and `proposal_dedupe` under the same cutoff: both
    /// exist only to detect equivocation against still-actionable votes/
    /// proposals, and a record below `gc_below` is no longer actionable (its
    /// bucket is gone and no new bucket can form past the cutoff). Sharing the
    /// view-keyed life cycle keeps a Byzantine flood of low-view distinct-hash
    /// votes from pinning memory in the dedup maps.
    pub(super) fn evict_vote_buckets_below(&mut self, gc_below: View) {
        let before = self.vote_bucket.len();
        self.vote_bucket.retain(|(view, _), _| *view >= gc_below);
        let dropped = (before - self.vote_bucket.len()) as u64;
        if dropped > 0 {
            self.eviction_counters.inc_vote_bucket(dropped);
            tracing::info!(
                target: TRACE_TARGET,
                cache = "vote_bucket",
                policy = "gc_below",
                gc_below = gc_below.0,
                dropped,
                size_after = self.vote_bucket.len(),
                "consensus_cache_evicted",
            );
        }
        self.vote_dedupe.retain(|(view, _), _| *view >= gc_below);
        self.proposal_dedupe
            .retain(|(view, _), _| *view >= gc_below);
    }

    /// Drop the lowest-`view` `vote_bucket` entry if the map is at cap.
    /// No-op when the cap is `usize::MAX` (the test default) or when
    /// the map has free slots.
    pub(super) fn evict_vote_buckets_to_fit_one(&mut self) {
        if self.vote_bucket.len() < self.limits.vote_bucket_capacity {
            return;
        }
        // Evict the lowest `(view, block_hash)`: a low-view vote is least likely
        // to ever feed a fresher high_qc than the one we hold. Tie-break on
        // block_hash for determinism.
        let Some(victim_key) = self.vote_bucket.keys().min().copied() else {
            return;
        };
        let removed = self.vote_bucket.remove(&victim_key);
        if removed.is_some() {
            self.eviction_counters.inc_vote_bucket(1);
            tracing::info!(
                target: TRACE_TARGET,
                cache = "vote_bucket",
                policy = "cap",
                evicted_view = victim_key.0.0,
                cap = self.limits.vote_bucket_capacity,
                size_after = self.vote_bucket.len(),
                "consensus_cache_evicted",
            );
        }
    }

    /// Drop the lowest-`view` `parked_proposals` entry if the map is at cap. The
    /// eviction key is the parked proposal's own view (not its missing parent's),
    /// so an attacker minting forged proposals at distinct future views gets
    /// bounded memory while honest current-view proposals stay parked.
    pub(super) fn evict_parked_to_fit_one(&mut self) {
        if self.parked_proposals.len() < self.limits.parked_proposals_capacity {
            return;
        }
        let Some((victim_hash, victim_view)) = self
            .parked_proposals
            .iter()
            .map(|(hash, signed)| (*hash, signed.payload.block.header.view))
            .min_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)))
        else {
            return;
        };
        if self.parked_proposals.remove(&victim_hash).is_some() {
            self.eviction_counters.inc_parked_proposals(1);
            tracing::info!(
                target: TRACE_TARGET,
                cache = "parked_proposals",
                policy = "cap",
                evicted_view = victim_view.0,
                cap = self.limits.parked_proposals_capacity,
                size_after = self.parked_proposals.len(),
                "consensus_cache_evicted",
            );
        }
    }
}
