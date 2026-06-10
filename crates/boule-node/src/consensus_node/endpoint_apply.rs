use boule_consensus::endpoint_registry::{EndpointRegistry, SignedEndpointCommand};
use boule_consensus::replication::block::Block;
use boule_consensus::validator_set::{Pubkey, ValidatorId};
use boule_core::storage::Storage;

use super::{ConsensusNode, STORAGE_KEY_ENDPOINT_REGISTRY, TRACE_TARGET};

impl ConsensusNode {
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

        registry.set_max_len(max_endpoint_list_length);
        registry
    }
}
