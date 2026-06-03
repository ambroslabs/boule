//! Commit-time application of [`DualSignedRotation`](boule_consensus::validator_rotation::DualSignedRotation)
//! payloads. See [`super::ConsensusNode::apply_committed_rotations`] for
//! the validation discipline.

use boule_consensus::replication::block::Block;

use super::{
    ConsensusNode, STORAGE_KEY_BLS_KEY_HISTORY, STORAGE_KEY_VALIDATOR_KEY_HISTORY, TRACE_TARGET,
};

impl ConsensusNode {
    /// Scan `block.commands` for tagged [`DualSignedRotation`](boule_consensus::validator_rotation::DualSignedRotation)
    /// payloads (#260) and, for each one that passes structural and
    /// cryptographic validation, apply it to `validator_key_history`.
    /// Persisting the updated history happens once per commit if any
    /// rotation applied — same shape as `apply_committed_reconfigs`.
    ///
    /// Validation failures (structural, signature, history-invariant)
    /// are logged and dropped — they do not roll the block back. The
    /// safety core has already committed; an invalid rotation in the
    /// payload is treated as a no-op so all replicas agree on which
    /// rotations took effect (which is none, when the rotation is
    /// invalid).
    pub(super) fn apply_committed_rotations(&mut self, block: &Block) {
        use boule_consensus::validator_rotation::DualSignedRotation;

        // #325 PR B: parity snapshot — see the matching block in
        // apply_committed_reconfigs for the rationale.
        #[cfg(debug_assertions)]
        let pre_state_for_parity = (
            self.validator_key_history.clone(),
            self.bls_key_history.clone(),
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

            // The validator's currently-active signing key, looked up
            // through the reverse index. If the field doesn't resolve,
            // `apply_rotation` below will produce the same error — but
            // resolving here gives us the pubkey for the cryptographic
            // dual-signature check first, which is the more informative
            // failure to log when both would fire.
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

            // Cryptographic self-attestation: both signatures must
            // verify. Done at commit time so a malicious leader who
            // smuggled in a single-signed rotation can't make it
            // take effect — every replica re-runs this check
            // independently before mutating the history.
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

            // Scheme-consistency check (#358): on BLS chains the
            // rotation must atomically rotate both keys (with a
            // verified PoP for the new BLS pubkey); on Ed25519 chains
            // the BLS fields must be absent. Splitting the two halves
            // would leave the histories transiently disagreeing.
            if let Err(e) = envelope
                .payload
                .validate_scheme_consistency(self.signature_scheme, &self.chain_id)
            {
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

            // Snapshot the stable id BEFORE mutating
            // `validator_key_history` — `validator_for` resolves any
            // historical key (including the soon-to-be-stale
            // pre-rotation key) to the validator's stable id, but
            // computing it before the mutation is the simpler proof
            // of correctness.
            let stable_id = self.validator_key_history.validator_for(&validator_pk);

            // History-invariant check (structural + monotone v_eff +
            // no cross-validator key collision). Logs and drops on
            // failure — the in-memory state is unchanged.
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

            // BLS half (#358): mirror the rotation into
            // `bls_key_history`. The Ed25519 apply just succeeded and
            // `validate_scheme_consistency` already verified the PoP,
            // so `apply_rotation` here can only fail on the
            // monotone-`v_eff` invariant — same failure mode the
            // Ed25519 path already covers, but in the parallel BLS
            // history. Log + roll back if it does.
            if self.signature_scheme
                == boule_core::crypto::sig_scheme::SignatureSchemeChoice::BlsAggregated
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
                    // Rare but bounded: the validator_key_history
                    // accepted the rotation but the BLS history
                    // rejected it. The likeliest cause is a manual
                    // mis-seeding where `bls_key_history` lacks the
                    // validator's genesis entry. Drop the rotation
                    // and continue — the cluster is now in an
                    // inconsistent state for this validator (Ed25519
                    // rotated, BLS not), so loud-warn so an operator
                    // notices.
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
                    // Don't continue — the Ed25519 mutation already
                    // happened and we still want to flush + log.
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

        // #317: process any rotation-cancel commands after the rotations, via
        // the shared apply helper so the result is byte-identical to the
        // recovery rebuild (the parity assert below depends on it). A cancel
        // always targets a rotation from an earlier block, so this block's
        // rotations and cancels never alias. Logs + drops on failure.
        for cmd_bytes in &block.commands {
            match boule_consensus::history_commitment::apply_rotation_cancel_command(
                &mut self.validator_key_history,
                self.bls_key_history.as_mut(),
                cmd_bytes,
                &self.chain_id,
                self.signature_scheme,
                block_view,
            ) {
                Ok(false) => {} // not a cancel payload
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

        // #549: process operator-signed signing-key recovery rotations, via the
        // shared helper so the result is byte-identical to the recovery rebuild
        // (the parity assert below depends on it). Authorised by the operator
        // key active at the commit view, not the old signing key — so a
        // validator whose signing key was destroyed can rotate to a fresh one.
        // Logs + drops on failure.
        for cmd_bytes in &block.commands {
            match boule_consensus::history_commitment::apply_operator_rotation_command(
                &mut self.validator_key_history,
                self.bls_key_history.as_mut(),
                &self.operator_key_history,
                cmd_bytes,
                &self.chain_id,
                self.signature_scheme,
                block_view,
            ) {
                Ok(false) => {} // not an operator-rotation payload
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

        // Same persistence pattern as the reconfig path: write once
        // per commit if any rotation applied, encoded as a single
        // full-history blob (not a journal). Failures log + drop —
        // the in-memory history is authoritative; a subsequent
        // rotation will get another chance to flush, and recovery
        // resets to whatever was durably written before the last
        // successful flush.
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
            // Mirror the persist for the parallel BLS history (#339).
            // No-op on Ed25519 chains where bls_key_history is None.
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

        // #325 PR B: confirm the pure-rebuild rotation function lands
        // in the same place this wrapper did. See the matching block
        // in apply_committed_reconfigs for the rationale.
        #[cfg(debug_assertions)]
        {
            let (mut rebuilt_keys, mut rebuilt_bls) = pre_state_for_parity;
            boule_consensus::history_commitment::apply_rotation_commands_to_histories(
                block,
                &self.validator_history,
                &mut rebuilt_keys,
                rebuilt_bls.as_mut(),
                Some(&self.operator_key_history),
                &self.chain_id,
                self.signature_scheme,
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
        }
    }
}
