//! Builders for the per-block [`AppContext`](boule_consensus::replication::application::AppContext)
//! consensus surfaces to the [`Application`](boule_consensus::replication::application::Application)
//! at proposal-build and commit time (#653).
//!
//! The context is an opaque escape hatch the application *reads* — proposer
//! identity, the justifying QC's commit-info (who signed, with what weight),
//! and any committed misbehaviour evidence with offenders resolved. Consensus
//! does not interpret what the application does with it. The reth EL ignores
//! it; a staking application reads `last_commit` to apportion rewards and
//! `evidence` to drive slashing; a Cosmos adapter maps it onto
//! `RequestPrepareProposal` / `RequestFinalizeBlock`.

use boule_consensus::dispatch::verify_equivocation_proof;
use boule_consensus::equivocation_evidence::{decode_evidence, is_evidence_payload};
use boule_consensus::hotstuff::QuorumCertificate;
use boule_consensus::replication::application::{AppContext, Evidence, VoteInfo};
use boule_consensus::replication::block::Block;

use super::ConsensusNode;

impl ConsensusNode {
    /// The [`AppContext`] for a proposal this node is constructing, justified
    /// by `high_qc`. `proposer` is this node; `last_commit` resolves the QC's
    /// signers to `(validator, weight)` against the set authoritative at the
    /// QC's view. `evidence` is empty on the build path — the leader's
    /// evidence-embedding decision lands separately in the block's commands.
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

    /// The [`AppContext`] for committing `block`: its `header.proposer` plus the
    /// equivocation evidence the block carries, each offender resolved to its
    /// stable id via the key active at the equivocation view. `last_commit` is
    /// empty here — the QC that justified a committed block is not threaded into
    /// the commit path today, and no commit-time consumer needs it yet.
    ///
    /// Evidence is re-verified here independently of the slashing pass
    /// ([`Self::apply_committed_evidence`]); the two are decoupled so this PR
    /// does not rewire the slash path. Evidence-carrying blocks are rare, so the
    /// duplicate verification is negligible.
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
