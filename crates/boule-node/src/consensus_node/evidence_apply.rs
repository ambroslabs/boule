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

            if evidence_view > block_view {
                tracing::warn!(
                    target: TRACE_TARGET,
                    block_view = block_view.0,
                    evidence_view = evidence_view.0,
                    "evidence_view_in_future",
                );
                continue;
            }

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

            if self.committed_evidence.contains_key(&who) {
                continue;
            }
            self.committed_evidence.insert(who, evidence_view);
            recorded_any = true;
            tracing::warn!(
                target: TRACE_TARGET,
                validator = %boule_core::identity::node_id_to_base58(who.as_node_id()),
                evidence_view = evidence_view.0,
                committed_view = block_view.0,
                "consensus_equivocation_evidence_committed",
            );

            self.app.slash(who.into_node_id());
        }

        if recorded_any {
            self.persist_committed_evidence();
        }
    }

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
