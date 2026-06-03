//! Commit-time application of validator endpoint-advertisement system txs
//! (#546).
//!
//! See [`super::ConsensusNode::apply_committed_endpoints`] for the
//! validation discipline. The [`EndpointRegistry`] this maintains is a
//! discovery hint (which `(network_id, address)` pairs reach a validator),
//! not safety-critical state — so, unlike the validator/key histories, it
//! is **not** folded into the #325 anti-rollback commitment. It is
//! persisted after each applying commit and reloaded at recovery (never
//! re-derived against the chain), which is what lets it survive block
//! pruning.

use boule_consensus::endpoint_registry::{EndpointRegistry, SignedEndpointCommand};
use boule_consensus::replication::block::Block;
use boule_consensus::validator_set::{Pubkey, ValidatorId};
use boule_core::storage::Storage;

use super::{ConsensusNode, STORAGE_KEY_ENDPOINT_REGISTRY, TRACE_TARGET};

impl ConsensusNode {
    /// Scan `block.commands` for tagged [`SignedEndpointCommand`] payloads
    /// (#546) and apply each one that is well-formed, signed by the
    /// publishing validator's active key, and accepted by the registry
    /// (monotone `seq`, cap, no-dup invariant).
    ///
    /// Each command is independently re-verified: the signature must verify
    /// under the key the validator was signing with at this block's view
    /// (resolved from the key history), and the validator must be a current
    /// member. Malformed / mis-signed / non-member / registry-rejected
    /// commands are logged and dropped — the block stays committed since the
    /// safety core is independent of payload validity.
    ///
    /// Called from the commit path after reconfigs and rotations, so the key
    /// history + membership reflect any change committed in the same block.
    pub(super) fn apply_committed_endpoints(&mut self, block: &Block) {
        let block_view = block.header.view;
        let mut applied_any = false;

        for cmd_bytes in &block.commands {
            if !SignedEndpointCommand::is_endpoint_payload(cmd_bytes) {
                continue;
            }
            let signed = match SignedEndpointCommand::decode_command(cmd_bytes) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        target: TRACE_TARGET,
                        height = block.header.height.0,
                        view = block_view.0,
                        error = %e,
                        "endpoint_payload_malformed",
                    );
                    continue;
                }
            };

            // The publishing validator's stable id. It must be a current
            // member, and the command must be signed by the key active for
            // it at this view (the same trusted-source discipline as a
            // rotation's `sig_old`).
            let vid = ValidatorId::from_genesis_pubkey(signed.payload.validator);
            if self
                .validator_history
                .set_at(block_view)
                .for_view(block_view)
                .index_of(&vid)
                .is_none()
            {
                tracing::warn!(
                    target: TRACE_TARGET,
                    view = block_view.0,
                    validator = ?signed.payload.validator,
                    "endpoint_command_from_non_member",
                );
                continue;
            }
            let active_key: Pubkey = match self.validator_key_history.key_at(&vid, block_view) {
                Some(k) => k,
                None => {
                    tracing::warn!(
                        target: TRACE_TARGET,
                        view = block_view.0,
                        validator = ?signed.payload.validator,
                        "endpoint_command_validator_has_no_active_key",
                    );
                    continue;
                }
            };
            if let Err(e) = signed.verify(active_key.as_node_id(), &self.chain_id) {
                tracing::warn!(
                    target: TRACE_TARGET,
                    view = block_view.0,
                    validator = ?signed.payload.validator,
                    error = %e,
                    "endpoint_command_signature_invalid",
                );
                continue;
            }

            match self.endpoint_registry.apply(&signed.payload) {
                Ok(()) => {
                    applied_any = true;
                    tracing::debug!(
                        target: TRACE_TARGET,
                        height = block.header.height.0,
                        view = block_view.0,
                        validator = ?signed.payload.validator,
                        seq = signed.payload.seq,
                        "endpoint_command_applied",
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        target: TRACE_TARGET,
                        view = block_view.0,
                        validator = ?signed.payload.validator,
                        error = %e,
                        "endpoint_command_rejected",
                    );
                }
            }
        }

        if applied_any {
            self.persist_endpoint_registry();
        }
    }

    /// Persist the endpoint registry. Logged-and-dropped on error (the
    /// in-memory registry stays authoritative for this session; the next
    /// applying commit re-attempts the flush). `pub(super)` so the reconfig
    /// apply path can re-persist after GC'ing a removed validator's entries.
    pub(super) fn persist_endpoint_registry(&self) {
        match postcard::to_stdvec(&self.endpoint_registry) {
            Ok(bytes) => {
                if let Err(e) = self.storage.put(STORAGE_KEY_ENDPOINT_REGISTRY, &bytes) {
                    tracing::error!(
                        target: TRACE_TARGET,
                        error = %e,
                        "endpoint_registry_persist_failed",
                    );
                }
            }
            Err(e) => {
                tracing::error!(
                    target: TRACE_TARGET,
                    error = %e,
                    "endpoint_registry_encode_failed",
                );
            }
        }
    }

    /// Load the endpoint registry from storage at recovery, applying the
    /// deployment's current `max_endpoint_list_length`. Absent key → empty;
    /// a malformed blob → empty + error log (a corrupt discovery-hint blob
    /// must not refuse the node a boot).
    pub(super) fn load_endpoint_registry(
        storage: &dyn Storage,
        max_endpoint_list_length: usize,
    ) -> EndpointRegistry {
        let mut registry = match storage.get(STORAGE_KEY_ENDPOINT_REGISTRY) {
            Ok(Some(raw)) => match postcard::from_bytes::<EndpointRegistry>(&raw) {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(
                        target: TRACE_TARGET,
                        error = %e,
                        "endpoint_registry_decode_failed",
                    );
                    EndpointRegistry::new(max_endpoint_list_length)
                }
            },
            Ok(None) => EndpointRegistry::new(max_endpoint_list_length),
            Err(e) => {
                tracing::error!(
                    target: TRACE_TARGET,
                    error = %e,
                    "endpoint_registry_read_failed",
                );
                EndpointRegistry::new(max_endpoint_list_length)
            }
        };
        // The persisted blob carries whatever cap was in force when it was
        // written; re-apply the deployment's current cap so a config change
        // governs subsequent applies.
        registry.set_max_len(max_endpoint_list_length);
        registry
    }
}
