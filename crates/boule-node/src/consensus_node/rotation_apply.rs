use boule_consensus::replication::block::Block;

use super::{
    ConsensusNode, STORAGE_KEY_BLS_KEY_HISTORY, STORAGE_KEY_OPERATOR_KEY_HISTORY,
    STORAGE_KEY_VALIDATOR_KEY_HISTORY, TRACE_TARGET,
};

impl ConsensusNode {
    pub(super) fn apply_committed_rotations(&mut self, block: &Block) {
        use boule_consensus::validator_rotation::DualSignedRotation;

        #[cfg(debug_assertions)]
        let pre_state_for_parity = (
            self.validator_key_history.clone(),
            self.bls_key_history.clone(),
            self.operator_key_history.clone(),
        );

        let block_view = block.header.view;
        let mut applied_any = false;
        for cmd_bytes in &block.commands {
            if !DualSignedRotation::is_rotation_payload(cmd_bytes) {
                continue;
            }
            let envelope = match DualSignedRotation::decode_command(cmd_bytes) {
                Ok(env) => env,
                Err(e) => {
                    tracing::warn!(
                        target: TRACE_TARGET,
                        height = block.header.height.0,
                        view = block_view.0,
                        error = %e,
                        "rotation_payload_malformed",
                    );
                    continue;
                }
            };

            let validator_pk =
                boule_consensus::validator_set::Pubkey::from_node_id(envelope.payload.validator);
            let current_key = match self.validator_key_history.current_key(&validator_pk) {
                Some(k) => k,
                None => {
                    tracing::warn!(
                        target: TRACE_TARGET,
                        height = block.header.height.0,
                        view = block_view.0,
                        validator = ?envelope.payload.validator,
                        "rotation_validator_not_in_key_history",
                    );
                    continue;
                }
            };

            if let Err(e) = envelope.verify(current_key.as_node_id(), &self.chain_id) {
                tracing::warn!(
                    target: TRACE_TARGET,
                    height = block.header.height.0,
                    view = block_view.0,
                    validator = ?envelope.payload.validator,
                    error = %e,
                    "rotation_signature_verification_failed",
                );
                continue;
            }

            if let Err(e) = envelope.payload.validate_scheme_consistency(&self.chain_id) {
                tracing::warn!(
                    target: TRACE_TARGET,
                    height = block.header.height.0,
                    view = block_view.0,
                    validator = ?envelope.payload.validator,
                    error = %e,
                    "rotation_scheme_consistency_failed",
                );
                continue;
            }

            let stable_id = self.validator_key_history.validator_for(&validator_pk);

            if let Err(e) = self
                .validator_key_history
                .apply_rotation(&envelope.payload, block_view)
            {
                tracing::warn!(
                    target: TRACE_TARGET,
                    height = block.header.height.0,
                    view = block_view.0,
                    validator = ?envelope.payload.validator,
                    new_pubkey = ?envelope.payload.new_pubkey,
                    v_eff = envelope.payload.v_eff.0,
                    error = %e,
                    "rotation_history_apply_failed",
                );
                continue;
            }

            {
                let new_bls_pk = envelope.payload.new_bls_pubkey.expect(
                    "BLS chain rotation passed scheme consistency must carry new_bls_pubkey",
                );
                let bls_history = self
                    .bls_key_history
                    .as_mut()
                    .expect("BLS chain must have a BlsKeyHistory at apply_committed_rotations");
                let stable_id =
                    stable_id.expect("validator_for resolved before apply_rotation succeeded");
                if let Err(e) = bls_history.apply_rotation(
                    stable_id.into_node_id(),
                    envelope.payload.v_eff,
                    new_bls_pk,
                ) {
                    tracing::error!(
                        target: TRACE_TARGET,
                        height = block.header.height.0,
                        view = block_view.0,
                        validator = ?envelope.payload.validator,
                        stable_id = ?stable_id,
                        new_bls_pubkey = ?new_bls_pk,
                        v_eff = envelope.payload.v_eff.0,
                        error = %e,
                        "bls_rotation_history_apply_failed_after_ed25519_apply_succeeded",
                    );
                }
            }

            tracing::info!(
                target: TRACE_TARGET,
                height = block.header.height.0,
                view = block_view.0,
                validator = ?envelope.payload.validator,
                new_pubkey = ?envelope.payload.new_pubkey,
                v_eff = envelope.payload.v_eff.0,
                "rotation_applied",
            );
            applied_any = true;
        }

        for cmd_bytes in &block.commands {
            match boule_consensus::history_commitment::apply_rotation_cancel_command(
                &mut self.validator_key_history,
                self.bls_key_history.as_mut(),
                cmd_bytes,
                &self.chain_id,
                block_view,
            ) {
                Ok(false) => {}
                Ok(true) => {
                    applied_any = true;
                    tracing::info!(
                        target: TRACE_TARGET,
                        height = block.header.height.0,
                        view = block_view.0,
                        "rotation_cancel_applied",
                    );
                }
                Err(e) => tracing::warn!(
                    target: TRACE_TARGET,
                    height = block.header.height.0,
                    view = block_view.0,
                    error = %e,
                    "rotation_cancel_apply_failed",
                ),
            }
        }

        for cmd_bytes in &block.commands {
            match boule_consensus::history_commitment::apply_operator_rotation_command(
                &mut self.validator_key_history,
                self.bls_key_history.as_mut(),
                &self.operator_key_history,
                cmd_bytes,
                &self.chain_id,
                block_view,
            ) {
                Ok(false) => {}
                Ok(true) => {
                    applied_any = true;
                    tracing::info!(
                        target: TRACE_TARGET,
                        height = block.header.height.0,
                        view = block_view.0,
                        "operator_rotation_applied",
                    );
                }
                Err(e) => tracing::warn!(
                    target: TRACE_TARGET,
                    height = block.header.height.0,
                    view = block_view.0,
                    error = %e,
                    "operator_rotation_apply_failed",
                ),
            }
        }

        let mut operator_history_changed = false;
        for cmd_bytes in &block.commands {
            match boule_consensus::history_commitment::apply_operator_key_rotation_command(
                &mut self.operator_key_history,
                cmd_bytes,
                &self.chain_id,
                block_view,
            ) {
                Ok(false) => {}
                Ok(true) => {
                    operator_history_changed = true;
                    tracing::info!(
                        target: TRACE_TARGET,
                        height = block.header.height.0,
                        view = block_view.0,
                        "operator_key_rotation_applied",
                    );
                }
                Err(e) => tracing::warn!(
                    target: TRACE_TARGET,
                    height = block.header.height.0,
                    view = block_view.0,
                    error = %e,
                    "operator_key_rotation_apply_failed",
                ),
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

        if applied_any {
            let persisted = self.validator_key_history.to_persisted();
            match postcard::to_stdvec(&persisted) {
                Ok(bytes) => {
                    if let Err(e) = self.storage.put(STORAGE_KEY_VALIDATOR_KEY_HISTORY, &bytes) {
                        tracing::error!(
                            target: TRACE_TARGET,
                            error = %e,
                            "validator_key_history_persist_failed",
                        );
                    }
                }
                Err(e) => {
                    tracing::error!(
                        target: TRACE_TARGET,
                        error = %e,
                        "validator_key_history_encode_failed",
                    );
                }
            }

            if let Some(bls) = self.bls_key_history.as_ref() {
                let persisted = bls.to_persisted();
                match postcard::to_stdvec(&persisted) {
                    Ok(bytes) => {
                        if let Err(e) = self.storage.put(STORAGE_KEY_BLS_KEY_HISTORY, &bytes) {
                            tracing::error!(
                                target: TRACE_TARGET,
                                error = %e,
                                "bls_key_history_persist_failed",
                            );
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            target: TRACE_TARGET,
                            error = %e,
                            "bls_key_history_encode_failed",
                        );
                    }
                }
            }
        }

        #[cfg(debug_assertions)]
        {
            let (mut rebuilt_keys, mut rebuilt_bls, mut rebuilt_operator) = pre_state_for_parity;
            boule_consensus::history_commitment::apply_rotation_commands_to_histories(
                block,
                &self.validator_history,
                &mut rebuilt_keys,
                rebuilt_bls.as_mut(),
                Some(&mut rebuilt_operator),
                &self.chain_id,
            );
            debug_assert_eq!(
                rebuilt_keys.to_persisted(),
                self.validator_key_history.to_persisted(),
                "pure-rebuild rotation path diverged from wrapper at height={} view={}",
                block.header.height,
                block.header.view,
            );
            debug_assert_eq!(
                rebuilt_bls.as_ref().map(|h| h.to_persisted()),
                self.bls_key_history.as_ref().map(|h| h.to_persisted()),
                "pure-rebuild BLS rotation path diverged from wrapper at height={} view={}",
                block.header.height,
                block.header.view,
            );

            debug_assert_eq!(
                rebuilt_operator.to_persisted(),
                self.operator_key_history.to_persisted(),
                "pure-rebuild operator-key path diverged from wrapper at height={} view={}",
                block.header.height,
                block.header.view,
            );
        }
    }
}
