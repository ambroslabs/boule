use boule_consensus::dispatch::verify_equivocation_proof;
use boule_consensus::equivocation_evidence::{decode_evidence, is_evidence_payload};
use boule_consensus::hotstuff::QuorumCertificate;
use boule_consensus::replication::application::{AppContext, Evidence, VoteInfo};
use boule_consensus::replication::block::Block;

use super::ConsensusNode;

impl ConsensusNode {
    pub(super) fn build_app_context(&self, high_qc: &QuorumCertificate) -> AppContext {
        let vs_at = self.validator_history.set_at(high_qc.view);
        let vs = vs_at.for_view(high_qc.view);
        let last_commit = high_qc
            .signer_indices()
            .filter_map(|idx| {
                vs.get(idx).map(|id| VoteInfo {
                    validator: *id.as_node_id(),
                    weight: vs.weight_at(idx),
                })
            })
            .collect();
        AppContext {
            proposer: self.self_id,
            last_commit,
            evidence: Vec::new(),
        }
    }

    pub(super) fn commit_app_context(&self, block: &Block) -> AppContext {
        let evidence = block
            .commands
            .iter()
            .filter(|c| is_evidence_payload(c))
            .filter_map(|c| decode_evidence(c).ok())
            .filter_map(|proof| {
                verify_equivocation_proof(
                    &proof,
                    &self.validator_history,
                    &self.validator_key_history,
                    &self.chain_id,
                )
                .ok()
                .map(|who| Evidence {
                    offender: who.into_node_id(),
                    view: proof.view(),
                })
            })
            .collect();
        AppContext {
            proposer: block.header.proposer,
            last_commit: Vec::new(),
            evidence,
        }
    }
}
