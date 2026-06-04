//! Commit-time application of
//! [`ConsensusParamUpdate`](boule_consensus::consensus_params::ConsensusParamUpdate)
//! payloads (#542). See [`super::ConsensusNode::apply_committed_param_updates`].

use boule_consensus::consensus_params::ConsensusParamUpdate;
use boule_consensus::replication::block::Block;

use super::{ConsensusNode, STORAGE_KEY_PARAM_HISTORY, TRACE_TARGET};

impl ConsensusNode {
    /// Scan `block.commands` for tagged [`ConsensusParamUpdate`] payloads,
    /// validate each against the block's view, insert the resulting `v_eff`
    /// boundary into [`ConsensusNode::param_history`], then refresh the cached
    /// active parameter values (currently [`ConsensusNode::min_block_interval`])
    /// for the committed view — so a boundary the chain has now reached becomes
    /// active.
    ///
    /// Validation failures (an update that changes nothing, a `v_eff` sooner
    /// than the delay floor, or a `v_eff` that does not exceed the last
    /// boundary) are logged and dropped: the block itself stays committed, the
    /// safety core being independent of payload validity — exactly the
    /// discipline [`Self::apply_committed_reconfigs`] uses.
    ///
    /// Each accepted update layers its set fields onto the most recently
    /// scheduled params ([`ConsensusParamHistory::latest`]), so sequential
    /// updates compose; `insert_boundary` enforces strictly increasing `v_eff`.
    ///
    /// [`ConsensusParamHistory::latest`]: boule_consensus::consensus_params::ConsensusParamHistory::latest
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
        // #746: durably persist the schedule once a boundary has landed, the
        // same persist-on-apply discipline `apply_committed_reconfigs` uses for
        // the validator history. A single postcard blob over the full history
        // (not a journal) so recovery is one read + decode and survives block
        // pruning. Failures log + drop: the in-memory schedule is authoritative
        // for the running process and the next committed update re-flushes.
        if inserted_any {
            self.persist_param_history();
        }
        // Refresh the cached active params for the committed view: a boundary
        // whose v_eff the chain has now reached takes effect here.
        let active = self.param_history.at(block.header.view);
        self.min_block_interval = active.min_block_interval();
    }

    /// Encode and write the current
    /// [`ConsensusParamHistory`](boule_consensus::consensus_params::ConsensusParamHistory)
    /// to durable storage under [`STORAGE_KEY_PARAM_HISTORY`]. See that key's
    /// docs for the recovery contract (#746).
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
