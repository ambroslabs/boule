use super::*;

impl HotStuffCore {
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

    pub(super) fn evict_vote_buckets_to_fit_one(&mut self) {
        if self.vote_bucket.len() < self.limits.vote_bucket_capacity {
            return;
        }

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
