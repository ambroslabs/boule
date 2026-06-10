use std::sync::atomic::Ordering;

use boule_consensus::hotstuff::qc::{quorum_size, quorum_weight_threshold};
use boule_consensus::pacemaker::Pacemaker;
use boule_consensus::status::{
    BUCKET_VIEW_WINDOW, BackpressureStatus, CacheEvictionStatus, ConsensusStatus, LockedStatus,
    ParkedProposalStatus, QcStatus, RotationEntry, TimeoutBucketStatus, ValidatorKeyStatus,
    VoteBucketStatus,
};
use boule_consensus::validator_set::ValidatorSet;
use boule_consensus::{Height, View};
use boule_core::identity::NodeId;

use super::ConsensusNode;

pub(super) fn self_role_string(
    pacemaker: &Pacemaker,
    validator_set: &ValidatorSet,
    self_id: &NodeId,
    view: View,
) -> String {
    if validator_set.is_empty() {
        return "replica".to_string();
    }
    let leader = pacemaker.leader_for_view(view);
    if &leader == self_id {
        format!("leader(view={view})")
    } else {
        "replica".to_string()
    }
}

impl ConsensusNode {
    pub fn build_status(&self) -> ConsensusStatus {
        let current_view = self.pacemaker.current_view();
        let state = self.core.state();
        let vs_len = self.validator_set.len();
        let quorum = quorum_size(vs_len);

        let self_role = self_role_string(
            &self.pacemaker,
            &self.validator_set,
            &self.self_id,
            current_view,
        );

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
            .map(|((view, block_hash), qc)| {
                let set_at = self.validator_history.set_at(*view);
                let vs = set_at.for_view(*view);
                VoteBucketStatus {
                    view: *view,
                    block_hash: hex::encode(block_hash),
                    signers: qc.signer_count(),
                    quorum,
                    signer_weight: qc.signer_weight(vs),
                    quorum_weight: quorum_weight_threshold(vs),
                }
            })
            .collect();

        vote_buckets.sort_by(|a, b| a.view.cmp(&b.view).then(a.block_hash.cmp(&b.block_hash)));

        let mut timeout_buckets: Vec<TimeoutBucketStatus> = self
            .timeout_buckets
            .iter()
            .filter(|(view, _)| **view >= min_view && **view <= max_view)
            .map(|(view, bucket)| {
                let set_at = self.validator_history.set_at(*view);
                let vs = set_at.for_view(*view);
                TimeoutBucketStatus {
                    view: *view,
                    signers: bucket.signers.len(),
                    quorum,

                    signer_weight: bucket.signer_weight,
                    quorum_weight: quorum_weight_threshold(vs),
                }
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
            .map(boule_core::identity::node_id_to_base58)
            .collect();
        peers_connected.sort();

        let active_set = self.validator_history.set_at(current_view);
        let validator_set: Vec<String> = active_set
            .for_view(current_view)
            .iter()
            .map(|v| boule_core::identity::node_id_to_base58(v.as_node_id()))
            .collect();

        let validator_keys: Vec<ValidatorKeyStatus> = self
            .validator_key_history
            .iter()
            .map(|(stable_id, entries)| {
                let entries: Vec<RotationEntry> = entries
                    .map(|(v_eff, pubkey)| RotationEntry {
                        v_eff,
                        pubkey: boule_core::identity::node_id_to_base58(&pubkey),
                    })
                    .collect();
                let active_pubkey = entries.last().map(|e| e.pubkey.clone()).unwrap_or_default();
                ValidatorKeyStatus {
                    stable_id: boule_core::identity::node_id_to_base58(stable_id.as_node_id()),
                    active_pubkey,
                    entries,
                }
            })
            .collect();

        ConsensusStatus {
            node_id: boule_core::identity::node_id_to_base58(&self.self_id),
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
            validator_keys,
            mempool_size: self.mempool.len(),
            cache_evictions: CacheEvictionStatus {
                vote_buckets: self.eviction_counters.vote_bucket(),
                parked_proposals: self.eviction_counters.parked_proposals(),
                pending_blocks: self.eviction_counters.pending_blocks(),
                timeout_buckets: self.eviction_counters.timeout_buckets(),
            },
            dropped_commands: self.dropped_commands.load(Ordering::Relaxed),
            equivocations_detected: self.equivocations_detected.load(Ordering::Relaxed),
            proposal_equivocations_detected: self
                .proposal_equivocations_detected
                .load(Ordering::Relaxed),
            equivocation_proofs_built: self.equivocation_proofs_built,
            equivocation_evidence_committed: self.committed_evidence.len() as u64,
            state_divergence_detected: self.state_divergence_detected.load(Ordering::Relaxed),
            proposal_command_rejections: self.proposal_command_rejections.load(Ordering::Relaxed),
            backpressure: BackpressureStatus {
                gossip_sink_overflow_total: self
                    .gossip_sink_overflows
                    .as_ref()
                    .map(|c| c.load(Ordering::Relaxed))
                    .unwrap_or(0),
                peer_outbound_overflow_total: self
                    .peer_outbound_overflows
                    .as_ref()
                    .map(|c| c.load(Ordering::Relaxed))
                    .unwrap_or(0),
                block_sync_serve_drops_total: self
                    .block_sync_credit
                    .drops_counter()
                    .load(Ordering::Relaxed),
                p2p_egress_byte_drops_total: self
                    .rate_limiter
                    .as_ref()
                    .map(|l| l.counters().outbound_drops_total())
                    .unwrap_or(0),
            },

            delinquent_validators: self
                .liveness_tracker
                .delinquents()
                .iter()
                .map(|v| boule_core::identity::node_id_to_base58(v.as_node_id()))
                .collect(),
            cluster_participation_permille: self.liveness_tracker.cluster_participation_permille(),

            el_behind: self.el_behind,
            el_behind_height_gap: self.el_behind_height_gap,
        }
    }
}
