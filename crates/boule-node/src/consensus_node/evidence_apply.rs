//! Commit-time application of equivocation-evidence system txs (#657).
//!
//! See [`super::ConsensusNode::apply_committed_evidence`] for the validation
//! and exactly-once recording discipline. The committed-evidence registry this
//! builds is the input a later slashing pass (#658) consumes.

use std::collections::BTreeMap;

use boule_consensus::View;
use boule_consensus::dispatch::verify_equivocation_proof;
use boule_consensus::equivocation_evidence::{
    MAX_EVIDENCE_AGE_VIEWS, decode_evidence, is_evidence_payload,
};
use boule_consensus::replication::block::Block;
use boule_consensus::validator_set::ValidatorId;
use boule_core::storage::Storage;

use super::{ConsensusNode, STORAGE_KEY_COMMITTED_EVIDENCE, TRACE_TARGET};

impl ConsensusNode {
    /// Scan `block.commands` for tagged equivocation-evidence payloads (#657)
    /// and record each valid, fresh, not-yet-seen one in the committed-evidence
    /// registry — **exactly once per equivocator**.
    ///
    /// Each payload is independently re-verified (defence in depth against a
    /// malicious proposer embedding garbage — the leader-side build drop is the
    /// first gate, this is the second), checked against the staleness window,
    /// and deduped by the equivocator's stable `ValidatorId`. Invalid, stale,
    /// future, or duplicate evidence is logged and dropped; the block itself
    /// stays committed since the safety core is independent of payload validity.
    ///
    /// Called from the commit path after reconfigs and rotations, so the key
    /// history the verifier consults reflects any membership/key change
    /// committed in the same block.
    pub(super) fn apply_committed_evidence(&mut self, block: &Block) {
        let block_view = block.header.view;
        let mut recorded_any = false;

        for cmd_bytes in &block.commands {
            if !is_evidence_payload(cmd_bytes) {
                continue;
            }
            let proof = match decode_evidence(cmd_bytes) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(
                        target: TRACE_TARGET,
                        height = block.header.height.0,
                        view = block_view.0,
                        error = %e,
                        "evidence_payload_malformed",
                    );
                    continue;
                }
            };

            // Re-verify: resolves the slashing-correct stable `ValidatorId` via
            // the key active at the equivocation view. Garbage / forged /
            // mis-attributed evidence fails here and is a no-op.
            let who = match verify_equivocation_proof(
                &proof,
                &self.validator_history,
                &self.validator_key_history,
                &self.chain_id,
            ) {
                Ok(id) => id,
                Err(e) => {
                    tracing::warn!(
                        target: TRACE_TARGET,
                        view = block_view.0,
                        error = %e,
                        "evidence_verification_failed",
                    );
                    continue;
                }
            };

            let evidence_view = proof.view();
            // An equivocation can only be committed after it happened.
            if evidence_view > block_view {
                tracing::warn!(
                    target: TRACE_TARGET,
                    block_view = block_view.0,
                    evidence_view = evidence_view.0,
                    "evidence_view_in_future",
                );
                continue;
            }
            // Staleness window: don't act on ancient equivocations.
            if block_view.0.saturating_sub(evidence_view.0) > MAX_EVIDENCE_AGE_VIEWS {
                tracing::warn!(
                    target: TRACE_TARGET,
                    block_view = block_view.0,
                    evidence_view = evidence_view.0,
                    max_age = MAX_EVIDENCE_AGE_VIEWS,
                    "evidence_stale",
                );
                continue;
            }

            // Exactly-once: a validator with already-committed evidence is a
            // no-op (it is recorded, and a later slash acts on it once).
            if self.committed_evidence.contains_key(&who) {
                continue;
            }
            self.committed_evidence.insert(who, evidence_view);
            recorded_any = true;
            tracing::warn!(
                target: TRACE_TARGET,
                validator = %boule_transport_tcp::tls::node_id_to_base58(who.as_node_id()),
                evidence_view = evidence_view.0,
                committed_view = block_view.0,
                "consensus_equivocation_evidence_committed",
            );
        }

        if recorded_any {
            self.persist_committed_evidence();
        }
    }

    /// Persist the committed-evidence registry. Logged-and-dropped on error
    /// (the in-memory registry stays authoritative for this session; the next
    /// commit that records evidence re-attempts the flush).
    fn persist_committed_evidence(&self) {
        match postcard::to_stdvec(&self.committed_evidence) {
            Ok(bytes) => {
                if let Err(e) = self.storage.put(STORAGE_KEY_COMMITTED_EVIDENCE, &bytes) {
                    tracing::error!(
                        target: TRACE_TARGET,
                        error = %e,
                        "committed_evidence_persist_failed",
                    );
                }
            }
            Err(e) => {
                tracing::error!(
                    target: TRACE_TARGET,
                    error = %e,
                    "committed_evidence_encode_failed",
                );
            }
        }
    }

    /// Load the committed-evidence registry from storage at recovery. Absent
    /// key → empty; a malformed blob → empty + error log (a corrupt
    /// economic-tracking blob must not refuse the node a boot).
    pub(super) fn load_committed_evidence(storage: &dyn Storage) -> BTreeMap<ValidatorId, View> {
        match storage.get(STORAGE_KEY_COMMITTED_EVIDENCE) {
            Ok(Some(raw)) => match postcard::from_bytes(&raw) {
                Ok(map) => map,
                Err(e) => {
                    tracing::error!(
                        target: TRACE_TARGET,
                        error = %e,
                        "committed_evidence_decode_failed",
                    );
                    BTreeMap::new()
                }
            },
            Ok(None) => BTreeMap::new(),
            Err(e) => {
                tracing::error!(
                    target: TRACE_TARGET,
                    error = %e,
                    "committed_evidence_read_failed",
                );
                BTreeMap::new()
            }
        }
    }
}
