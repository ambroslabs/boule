use boule_consensus::consensus_params::ConsensusParamUpdate;
use boule_consensus::replication::block::Block;

use super::{ConsensusNode, STORAGE_KEY_PARAM_HISTORY, TRACE_TARGET};

impl ConsensusNode {
    pub(super) fn apply_committed_param_updates(&mut self, block: &Block) {
        let mut inserted_any = false;
        for cmd_bytes in &block.commands {
            if !ConsensusParamUpdate::is_param_update_payload(cmd_bytes) {
                continue;
            }
            let cmd = match ConsensusParamUpdate::decode(cmd_bytes) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(
                        target: TRACE_TARGET,
                        height = block.header.height.0,
                        view = block.header.view.0,
                        error = %e,
                        "param_update_payload_malformed",
                    );
                    continue;
                }
            };
            if let Err(e) = cmd.validate_against(block.header.view) {
                tracing::warn!(
                    target: TRACE_TARGET,
                    height = block.header.height.0,
                    view = block.header.view.0,
                    error = %e,
                    "param_update_validation_failed",
                );
                continue;
            }
            let new_params = cmd.apply_to(self.param_history.latest());
            match self.param_history.insert_boundary(cmd.v_eff, new_params) {
                Ok(()) => {
                    inserted_any = true;
                    tracing::info!(
                        target: TRACE_TARGET,
                        height = block.header.height.0,
                        view = block.header.view.0,
                        v_eff = cmd.v_eff.0,
                        min_block_interval_ms = new_params.min_block_interval_ms,
                        "consensus_param_update_boundary_inserted",
                    );
                }
                Err(e) => tracing::warn!(
                    target: TRACE_TARGET,
                    view = block.header.view.0,
                    error = %e,
                    "param_update_insert_boundary_failed",
                ),
            }
        }

        if inserted_any {
            self.persist_param_history();
        }

        let active = self.param_history.at(block.header.view);
        self.min_block_interval = active.min_block_interval();
    }

    fn persist_param_history(&self) {
        match postcard::to_stdvec(&self.param_history.to_persisted()) {
            Ok(bytes) => {
                if let Err(e) = self.storage.put(STORAGE_KEY_PARAM_HISTORY, &bytes) {
                    tracing::error!(
                        target: TRACE_TARGET,
                        error = %e,
                        "param_history_persist_failed",
                    );
                }
            }
            Err(e) => tracing::error!(
                target: TRACE_TARGET,
                error = %e,
                "param_history_encode_failed",
            ),
        }
    }
}
