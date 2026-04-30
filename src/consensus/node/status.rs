//! Status snapshot construction for the consensus integration layer.
//!
//! [`super::ConsensusNode::build_status`] composes a fresh
//! [`ConsensusStatus`] from the safety-core, pacemaker, mempool, and
//! peer-tracking state. Cheap enough to run at the end of every event-
//! loop iteration.

use std::sync::atomic::Ordering;

use crate::consensus::hotstuff::qc::quorum_size;
use crate::consensus::status::{
    BUCKET_VIEW_WINDOW, CacheEvictionStatus, ConsensusStatus, LockedStatus, ParkedProposalStatus,
    QcStatus, TimeoutBucketStatus, VoteBucketStatus,
};
use crate::consensus::validator_set::ValidatorSet;
use crate::consensus::{Height, View};
use crate::p2p::NodeId;

use super::ConsensusNode;

/// Compute the `self_role` string for a [`ConsensusStatus`]: either
/// `"leader(view=N)"` when `self_id` is the round-robin proposer for
/// `view`, or `"replica"` otherwise.
///
/// Kept module-private and free-standing so
/// [`ConsensusNode::build_status`] doesn't have to hold a
/// [`crate::consensus::pacemaker::leader::RoundRobinSelector`]: the
/// round-robin rule (`validators[view % len]`) is the selector the
/// rest of the integration layer uses, and duplicating that one-liner
/// here keeps `ConsensusNode` from threading the selector through every
/// call. See
/// [`crate::consensus::pacemaker::leader::RoundRobinSelector`] for the
/// authoritative implementation.
pub(super) fn self_role_string(
    validator_set: &ValidatorSet,
    self_id: &NodeId,
    view: View,
) -> String {
    if validator_set.is_empty() {
        return "replica".to_string();
    }
    let idx = (view.0 % validator_set.len() as u64) as usize;
    match validator_set.get(idx) {
        Some(leader) if leader.as_node_id() == self_id => format!("leader(view={view})"),
        _ => "replica".to_string(),
    }
}

impl ConsensusNode {
    /// Build a fresh [`ConsensusStatus`] snapshot from the current
    /// safety-core, pacemaker, mempool, and peer-tracking state.
    ///
    /// Cheap — shallow-copies a handful of fields, clones a small
    /// handful of bounded-size vectors. Safe to call from the event
    /// loop after each state-mutating tick without affecting
    /// throughput.
    pub fn build_status(&self) -> ConsensusStatus {
        let current_view = self.pacemaker.current_view();
        let state = self.core.state();
        let vs_len = self.validator_set.len();
        let quorum = quorum_size(vs_len);

        let self_role = self_role_string(&self.validator_set, &self.self_id, current_view);

        let locked = state.locked.as_ref().map(|l| LockedStatus {
            view: l.view,
            height: l.height,
            block_hash: hex::encode(l.block_hash),
        });

        let high_qc = state.high_qc.as_ref().map(|qc| {
            let height = state
                .pending_blocks
                .get(&qc.block_hash())
                .map(|b| b.header.height);
            QcStatus {
                view: qc.view(),
                height,
                block_hash: hex::encode(qc.block_hash()),
            }
        });

        let min_view = current_view.saturating_sub(View(BUCKET_VIEW_WINDOW));
        let max_view = current_view.saturating_add(View(BUCKET_VIEW_WINDOW));

        let mut vote_buckets: Vec<VoteBucketStatus> = self
            .core
            .vote_buckets()
            .filter(|((view, _), _)| *view >= min_view && *view <= max_view)
            .map(|((view, block_hash), qc)| VoteBucketStatus {
                view: *view,
                block_hash: hex::encode(block_hash),
                signers: qc.signer_count(),
                quorum,
            })
            .collect();
        // Stable ordering keeps the JSON shape deterministic across
        // calls, which makes logs and diff-based debugging workable.
        vote_buckets.sort_by(|a, b| a.view.cmp(&b.view).then(a.block_hash.cmp(&b.block_hash)));

        let mut timeout_buckets: Vec<TimeoutBucketStatus> = self
            .timeout_buckets
            .iter()
            .filter(|(view, _)| **view >= min_view && **view <= max_view)
            .map(|(view, bucket)| TimeoutBucketStatus {
                view: *view,
                signers: bucket.signers.len(),
                quorum,
            })
            .collect();
        timeout_buckets.sort_by_key(|b| b.view);

        let mut parked_proposals: Vec<ParkedProposalStatus> = self
            .core
            .parked_proposals()
            .map(|signed| ParkedProposalStatus {
                block_hash: hex::encode(signed.payload.block.hash()),
                parent_hash: hex::encode(signed.payload.block.header.parent_hash),
                view: signed.payload.block.header.view,
            })
            .collect();
        parked_proposals.sort_by(|a, b| a.view.cmp(&b.view).then(a.block_hash.cmp(&b.block_hash)));

        let mut peers_connected: Vec<String> = self
            .peers_connected
            .iter()
            .map(crate::p2p::tls::node_id_to_base58)
            .collect();
        peers_connected.sort();

        let validator_set: Vec<String> = self
            .validator_set
            .iter()
            .map(|v| crate::p2p::tls::node_id_to_base58(v.as_node_id()))
            .collect();

        ConsensusStatus {
            node_id: crate::p2p::tls::node_id_to_base58(&self.self_id),
            self_role,
            current_view,
            last_voted_view: state.last_voted_view,
            last_committed_height: Height(self.last_committed_height.load(Ordering::Relaxed)),
            last_committed_view: self.last_committed_view,
            locked,
            high_qc,
            vote_buckets,
            timeout_buckets,
            parked_proposals,
            pending_blocks_count: state.pending_blocks.len(),
            peers_connected,
            validator_set,
            mempool_size: self.mempool.len(),
            cache_evictions: CacheEvictionStatus {
                vote_buckets: self.eviction_counters.vote_bucket(),
                parked_proposals: self.eviction_counters.parked_proposals(),
                pending_blocks: self.eviction_counters.pending_blocks(),
                timeout_buckets: self.eviction_counters.timeout_buckets(),
            },
            dropped_commands: self.dropped_commands.load(Ordering::Relaxed),
            equivocations_detected: self.equivocations_detected.load(Ordering::Relaxed),
        }
    }
}
