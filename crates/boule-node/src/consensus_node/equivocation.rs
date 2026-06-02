//! Building non-repudiable equivocation proofs (#656b).
//!
//! The safety core *detects* equivocation and emits
//! [`Action::EquivocationEvidence`](boule_consensus::hotstuff::step::Action::EquivocationEvidence)
//! / `ProposalEquivocationEvidence` — but those carry only block hashes. This
//! module retains the verified `Signed<Vote>`/`Signed<Proposal>` envelopes the
//! integration layer sees at ingress, so when the core fires that action it
//! can pair the two conflicting *signed* messages into an
//! [`EquivocationProof`] and confirm it with the independent verifier
//! [`verify_equivocation_proof`] (#656a) — producing evidence a future slash
//! (#658) can trust.
//!
//! Persisting / gossiping / block-inclusion of the proof is #657; here it is
//! built, self-verified, counted, and logged.

use std::collections::HashMap;

use boule_consensus::View;
use boule_consensus::dispatch::{EquivocationProof, verify_equivocation_proof};
use boule_consensus::hotstuff::qc::{Proposal, Vote};
use boule_consensus::hotstuff::step::Event as SafetyEvent;
use boule_consensus::replication::block::BlockHash;
use boule_consensus::validator_set::ValidatorId;
use boule_core::crypto::signed::Signed;

use super::{ConsensusNode, TRACE_TARGET};

/// Verified vote envelopes retained for evidence, keyed by
/// `(view, validator, block)`: one per honest validator per view, a few for a
/// Byzantine double-signer.
pub(super) type SeenVotes = HashMap<(View, ValidatorId, BlockHash), Signed<Vote>>;
/// Verified proposal envelopes retained for evidence (proposal equivocation).
pub(super) type SeenProposals = HashMap<(View, ValidatorId, BlockHash), Signed<Proposal>>;

/// Retain envelopes only for views within this window behind the current view;
/// older ones are GC'd. An equivocation fires at an active (uncommitted) view,
/// well inside the window.
const EVIDENCE_RETENTION_VIEWS: u64 = 256;
/// Hard cap on each retention map so a Byzantine flood of distinct blocks
/// across many future views cannot pin unbounded memory between GC sweeps.
const EVIDENCE_MAP_CAP: usize = 4096;

impl ConsensusNode {
    /// Retain the verified signed envelope in `ev` (a Vote or Proposal) so a
    /// later equivocation action can pair it into a proof. Called from
    /// `step_safety` *before* the event is consumed by the core.
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

    /// Drop retained envelopes older than the retention window. Called on
    /// `PacemakerAdvance(current)`.
    pub(super) fn gc_equivocation_evidence(&mut self, current: View) {
        let floor = current.0.saturating_sub(EVIDENCE_RETENTION_VIEWS);
        self.seen_votes.retain(|(view, _, _), _| view.0 >= floor);
        self.seen_proposals
            .retain(|(view, _, _), _| view.0 >= floor);
    }

    /// Pair the two conflicting signed votes the core just flagged into a
    /// verified [`EquivocationProof`]. A no-op if either envelope was not
    /// retained (GC'd, or a 3rd+ fork beyond the cap — the first conflict
    /// already produced a proof).
    pub(super) fn build_vote_equivocation_proof(
        &mut self,
        voter: ValidatorId,
        view: View,
        block_a: BlockHash,
        block_b: BlockHash,
    ) {
        let (Some(a), Some(b)) = (
            self.seen_votes.get(&(view, voter, block_a)).cloned(),
            self.seen_votes.get(&(view, voter, block_b)).cloned(),
        ) else {
            return;
        };
        let proof = EquivocationProof::DoubleVote(Box::new(a), Box::new(b));
        self.record_equivocation_proof(proof, voter, view, "vote");
    }

    /// Proposal-equivocation analogue of [`Self::build_vote_equivocation_proof`].
    pub(super) fn build_proposal_equivocation_proof(
        &mut self,
        leader: ValidatorId,
        view: View,
        block_a: BlockHash,
        block_b: BlockHash,
    ) {
        let (Some(a), Some(b)) = (
            self.seen_proposals.get(&(view, leader, block_a)).cloned(),
            self.seen_proposals.get(&(view, leader, block_b)).cloned(),
        ) else {
            return;
        };
        let proof = EquivocationProof::DoubleProposal(Box::new(a), Box::new(b));
        self.record_equivocation_proof(proof, leader, view, "proposal");
    }

    /// Self-verify the built proof and record it (count + WARN). The
    /// verification is a safety self-check: a proof built from our own
    /// retained, ingress-verified envelopes *must* pass the independent
    /// verifier (#656a); if it ever doesn't, that's a bug, not evidence.
    fn record_equivocation_proof(
        &mut self,
        proof: EquivocationProof,
        who: ValidatorId,
        view: View,
        kind: &str,
    ) {
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
                    validator = %boule_transport_tcp::tls::node_id_to_base58(who.as_node_id()),
                    view = view.0,
                    "consensus_equivocation_proof_built",
                );
                // #657 will persist / gossip / include the proof; for now it
                // is built, verified, and counted.
            }
            other => {
                tracing::error!(
                    target: TRACE_TARGET,
                    kind,
                    view = view.0,
                    matched = ?other.map(|id| id == who),
                    "consensus_equivocation_proof_self_verify_failed",
                );
            }
        }
    }
}

/// Insert into a retention map, dropping new *distinct* keys once at the cap
/// (existing keys are still refreshed) so the map stays bounded until GC.
fn insert_capped<K, V>(map: &mut HashMap<K, V>, key: K, value: V)
where
    K: std::hash::Hash + Eq,
{
    if map.len() >= EVIDENCE_MAP_CAP && !map.contains_key(&key) {
        return;
    }
    map.insert(key, value);
}
