use std::sync::Arc;

use boule_consensus::View;
use boule_consensus::pacemaker::leader::WeightedAccumulatorSelector;
use boule_consensus::replication::block::Block;
use boule_consensus::validator_set::ValidatorSet;

use super::{
    ConsensusNode, STORAGE_KEY_BLS_KEY_HISTORY, STORAGE_KEY_OPERATOR_KEY_HISTORY,
    STORAGE_KEY_VALIDATOR_HISTORY, TRACE_TARGET,
};

impl ConsensusNode {
    pub(super) fn apply_committed_reconfigs(&mut self, block: &Block) {
        use boule_consensus::reconfig::ReconfigCommand;

        #[cfg(debug_assertions)]
        let pre_state_for_parity = (
            self.validator_history.clone(),
            self.operator_key_history.clone(),
        );

        let mut applied_any = false;

        let mut operator_history_changed = false;

        let mut bls_history_changed = false;

        let mut endpoint_registry_changed = false;
        for cmd_bytes in &block.commands {
            if !ReconfigCommand::is_reconfig_payload(cmd_bytes) {
                continue;
            }
            let cmd = match ReconfigCommand::decode(cmd_bytes) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(
                        target: TRACE_TARGET,
                        height = block.header.height.0,
                        view = block.header.view.0,
                        error = %e,
                        "reconfig_payload_malformed",
                    );
                    continue;
                }
            };

            let block_view = block.header.view;
            let current_set_at = self.validator_history.set_at(block_view);
            let next_members = match cmd.validate_against_with_delay_and_chain(
                current_set_at.for_view(block_view),
                block_view,
                self.min_v_eff_delay,
                &self.chain_id,
            ) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!(
                        target: TRACE_TARGET,
                        height = block.header.height.0,
                        view = block_view.0,
                        v_eff = cmd.v_eff.0,
                        error = %e,
                        "reconfig_validation_failed",
                    );
                    continue;
                }
            };

            let conflict = self
                .validator_history
                .iter()
                .any(|(v_eff, _)| v_eff != View::ZERO && v_eff > block_view);
            if conflict {
                tracing::warn!(
                    target: TRACE_TARGET,
                    height = block.header.height.0,
                    view = block_view.0,
                    v_eff = cmd.v_eff.0,
                    "reconfig_conflicts_with_pending_or_committed_boundary",
                );
                continue;
            }

            let next_entries: Vec<(boule_consensus::validator_set::ValidatorId, u64)> =
                next_members
                    .into_iter()
                    .map(|(n, w)| {
                        (
                            boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(n),
                            w,
                        )
                    })
                    .collect();
            let new_set = match ValidatorSet::with_weights(next_entries) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(
                        target: TRACE_TARGET,
                        error = %e,
                        "reconfig_with_weights_construct_failed",
                    );
                    continue;
                }
            };

            if let Err(e) = self
                .validator_history
                .insert_boundary(cmd.v_eff, new_set.clone())
            {
                tracing::error!(
                    target: TRACE_TARGET,
                    error = %e,
                    "reconfig_insert_boundary_into_node_history_failed",
                );
                continue;
            }

            if let Err(e) = self
                .core
                .insert_validator_boundary(cmd.v_eff, new_set.clone())
            {
                tracing::error!(
                    target: TRACE_TARGET,
                    error = %e,
                    "reconfig_insert_boundary_into_safety_core_failed",
                );
                continue;
            }

            let snapshot = Arc::new(self.validator_history.clone());
            self.pacemaker
                .set_selector(Arc::new(WeightedAccumulatorSelector::new(snapshot)));

            tracing::info!(
                target: TRACE_TARGET,
                height = block.header.height.0,
                view = block_view.0,
                v_eff = cmd.v_eff.0,
                next_size = new_set.len(),
                "reconfig_applied",
            );
            applied_any = true;

            if self.staged_governance_reconfig.as_ref() == Some(&cmd) {
                self.staged_governance_reconfig = None;
                tracing::info!(
                    target: TRACE_TARGET,
                    v_eff = cmd.v_eff.0,
                    "governance_reconfig_landed_stage_cleared",
                );
            }

            for entry in &cmd.adds {
                let Some(operator_pubkey) = entry.operator_pubkey else {
                    continue;
                };
                let v_id =
                    boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(entry.node_id);
                if new_set.contains(&v_id)
                    && !self.operator_key_history.contains(&v_id)
                    && self
                        .operator_key_history
                        .register(&v_id, cmd.v_eff, operator_pubkey)
                        .is_ok()
                {
                    operator_history_changed = true;
                }
            }

            if let Some(bls_history) = self.bls_key_history.as_mut() {
                for entry in &cmd.adds {
                    let Some(bls_pop) = &entry.bls_pop else {
                        continue;
                    };
                    let v_id = boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(
                        entry.node_id,
                    );
                    if new_set.contains(&v_id)
                        && !bls_history.contains(&entry.node_id)
                        && bls_history
                            .register(entry.node_id, cmd.v_eff, bls_pop.pubkey)
                            .is_ok()
                    {
                        bls_history_changed = true;
                    }
                }
            }

            for entry in &cmd.adds {
                if entry.initial_endpoints.is_empty() {
                    continue;
                }
                let v_id =
                    boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(entry.node_id);
                if !new_set.contains(&v_id) {
                    continue;
                }
                match self
                    .endpoint_registry
                    .seed(entry.node_id, entry.initial_endpoints.clone())
                {
                    Ok(()) => endpoint_registry_changed = true,
                    Err(e) => tracing::warn!(
                        target: TRACE_TARGET,
                        validator = ?entry.node_id,
                        error = %e,
                        "initial_endpoint_seed_rejected",
                    ),
                }
            }

            for removed in &cmd.removes {
                if self.endpoint_registry.forget(removed) {
                    endpoint_registry_changed = true;
                }
            }
        }

        if operator_history_changed {
            match postcard::to_stdvec(&self.operator_key_history.to_persisted()) {
                Ok(bytes) => {
                    if let Err(e) = self.storage.put(STORAGE_KEY_OPERATOR_KEY_HISTORY, &bytes) {
                        tracing::error!(
                            target: TRACE_TARGET,
                            error = %e,
                            "operator_key_history_persist_failed",
                        );
                    }
                }
                Err(e) => tracing::error!(
                    target: TRACE_TARGET,
                    error = %e,
                    "operator_key_history_encode_failed",
                ),
            }
        }

        if bls_history_changed {
            if let Some(bls) = self.bls_key_history.as_ref() {
                match postcard::to_stdvec(&bls.to_persisted()) {
                    Ok(bytes) => {
                        if let Err(e) = self.storage.put(STORAGE_KEY_BLS_KEY_HISTORY, &bytes) {
                            tracing::error!(
                                target: TRACE_TARGET,
                                error = %e,
                                "bls_key_history_persist_failed",
                            );
                        }
                    }
                    Err(e) => tracing::error!(
                        target: TRACE_TARGET,
                        error = %e,
                        "bls_key_history_encode_failed",
                    ),
                }
            }
        }

        if endpoint_registry_changed {
            self.persist_endpoint_registry();
        }

        if applied_any {
            self.staged_validator_updates.clear();

            let persisted = self.validator_history.to_persisted();
            match postcard::to_stdvec(&persisted) {
                Ok(bytes) => {
                    if let Err(e) = self.storage.put(STORAGE_KEY_VALIDATOR_HISTORY, &bytes) {
                        tracing::error!(
                            target: TRACE_TARGET,
                            error = %e,
                            "validator_history_persist_failed",
                        );
                    }
                }
                Err(e) => {
                    tracing::error!(
                        target: TRACE_TARGET,
                        error = %e,
                        "validator_history_encode_failed",
                    );
                }
            }
        }

        #[cfg(debug_assertions)]
        {
            let (mut rebuilt, mut rebuilt_operator) = pre_state_for_parity;
            let mut throwaway_key =
                boule_consensus::validator_key_history::ValidatorKeyHistory::new(
                    self.validator_set.iter().copied(),
                );
            boule_consensus::history_commitment::apply_reconfig_commands_to_set_history(
                block,
                &mut rebuilt,
                &mut throwaway_key,
                Some(&mut rebuilt_operator),
                None,
                self.min_v_eff_delay,
                &self.chain_id,
            );
            debug_assert_eq!(
                rebuilt.to_persisted(),
                self.validator_history.to_persisted(),
                "pure-rebuild reconfig path diverged from wrapper at height={} view={}",
                block.header.height,
                block.header.view,
            );

            debug_assert_eq!(
                rebuilt_operator.to_persisted(),
                self.operator_key_history.to_persisted(),
                "pure-rebuild reconfig operator-key path diverged from wrapper at height={} view={}",
                block.header.height,
                block.header.view,
            );
        }
    }
}
