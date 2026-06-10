use std::collections::HashMap;

use boule_consensus::View;
use boule_consensus::dispatch::{EquivocationProof, verify_equivocation_proof};
use boule_consensus::hotstuff::qc::{Proposal, Vote};
use boule_consensus::hotstuff::step::Event as SafetyEvent;
use boule_consensus::replication::block::BlockHash;
use boule_consensus::validator_set::ValidatorId;
use boule_core::crypto::signed::Signed;

use super::{ConsensusNode, TRACE_TARGET};

pub(super) type SeenVotes = HashMap<(View, ValidatorId, BlockHash), Signed<Vote>>;

pub(super) type SeenProposals = HashMap<(View, ValidatorId, BlockHash), Signed<Proposal>>;

const EVIDENCE_RETENTION_VIEWS: u64 = 256;

const EVIDENCE_MAP_CAP: usize = 4096;

impl ConsensusNode {
    pub(super) fn retain_for_equivocation_evidence(&mut self, ev: &SafetyEvent) {
        match ev {
            SafetyEvent::VoteReceived(variant) => {
                let v = variant.verified();
                let signed = v.inner();
                let key = (
                    signed.payload.view,
                    v.signer_validator_id(),
                    signed.payload.block_hash,
                );
                insert_capped(&mut self.seen_votes, key, signed.clone());
            }
            SafetyEvent::ProposalReceived(v) => {
                let signed = v.inner();
                let key = (
                    signed.payload.block.header.view,
                    v.signer_validator_id(),
                    signed.payload.block.hash(),
                );
                insert_capped(&mut self.seen_proposals, key, signed.clone());
            }
            _ => {}
        }
    }

    pub(super) fn gc_equivocation_evidence(&mut self, current: View) {
        let floor = current.0.saturating_sub(EVIDENCE_RETENTION_VIEWS);
        self.seen_votes.retain(|(view, _, _), _| view.0 >= floor);
        self.seen_proposals
            .retain(|(view, _, _), _| view.0 >= floor);
    }

    pub(super) fn build_vote_equivocation_proof(
        &mut self,
        voter: ValidatorId,
        view: View,
        block_a: BlockHash,
        block_b: BlockHash,
    ) -> Option<EquivocationProof> {
        let (Some(a), Some(b)) = (
            self.seen_votes.get(&(view, voter, block_a)).cloned(),
            self.seen_votes.get(&(view, voter, block_b)).cloned(),
        ) else {
            return None;
        };
        let proof = EquivocationProof::DoubleVote(Box::new(a), Box::new(b));
        self.record_equivocation_proof(proof, voter, view, "vote")
    }

    pub(super) fn build_proposal_equivocation_proof(
        &mut self,
        leader: ValidatorId,
        view: View,
        block_a: BlockHash,
        block_b: BlockHash,
    ) -> Option<EquivocationProof> {
        let (Some(a), Some(b)) = (
            self.seen_proposals.get(&(view, leader, block_a)).cloned(),
            self.seen_proposals.get(&(view, leader, block_b)).cloned(),
        ) else {
            return None;
        };
        let proof = EquivocationProof::DoubleProposal(Box::new(a), Box::new(b));
        self.record_equivocation_proof(proof, leader, view, "proposal")
    }

    pub(super) fn mint_equivocation_evidence(
        &mut self,
        proof: &EquivocationProof,
        who: ValidatorId,
    ) -> bool {
        if self.evidence_minted.contains(&who) || self.committed_evidence.contains_key(&who) {
            return false;
        }
        let payload = boule_consensus::equivocation_evidence::encode_evidence(proof);
        match self.mempool.insert(payload) {
            Ok(_) => {
                self.evidence_minted.insert(who);
                true
            }
            Err(e) => {
                tracing::warn!(
                    target: TRACE_TARGET,
                    error = %e,
                    "evidence_mempool_insert_failed",
                );
                false
            }
        }
    }

    fn record_equivocation_proof(
        &mut self,
        proof: EquivocationProof,
        who: ValidatorId,
        view: View,
        kind: &str,
    ) -> Option<EquivocationProof> {
        match verify_equivocation_proof(
            &proof,
            &self.validator_history,
            &self.validator_key_history,
            &self.chain_id,
        ) {
            Ok(id) if id == who => {
                self.equivocation_proofs_built += 1;
                tracing::warn!(
                    target: TRACE_TARGET,
                    kind,
                    validator = %boule_core::identity::node_id_to_base58(who.as_node_id()),
                    view = view.0,
                    "consensus_equivocation_proof_built",
                );

                if self.mint_equivocation_evidence(&proof, who) {
                    Some(proof)
                } else {
                    None
                }
            }
            other => {
                tracing::error!(
                    target: TRACE_TARGET,
                    kind,
                    view = view.0,
                    matched = ?other.map(|id| id == who),
                    "consensus_equivocation_proof_self_verify_failed",
                );
                None
            }
        }
    }
}

fn insert_capped<K, V>(map: &mut HashMap<K, V>, key: K, value: V)
where
    K: std::hash::Hash + Eq,
{
    if map.len() >= EVIDENCE_MAP_CAP && !map.contains_key(&key) {
        return;
    }
    map.insert(key, value);
}
