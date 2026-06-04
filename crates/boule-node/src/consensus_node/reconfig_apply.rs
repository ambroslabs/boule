//! Commit-time application of [`ReconfigCommand`](boule_consensus::reconfig::ReconfigCommand)
//! payloads. See [`super::ConsensusNode::apply_committed_reconfigs`] for
//! the validation and history-mirror discipline.

use std::sync::Arc;

use boule_consensus::View;
use boule_consensus::pacemaker::leader::WeightedAccumulatorSelector;
use boule_consensus::replication::block::Block;
use boule_consensus::validator_set::ValidatorSet;

use super::{
    ConsensusNode, STORAGE_KEY_OPERATOR_KEY_HISTORY, STORAGE_KEY_VALIDATOR_HISTORY, TRACE_TARGET,
};

impl ConsensusNode {
    /// Scan `block.commands` for tagged `ReconfigCommand` payloads
    /// (#247) and, for each one that validates against the active set
    /// at the block's view, insert a new boundary into
    /// `validator_history`, mirror it into the safety core, and
    /// re-install the leader selector so the pacemaker rotation
    /// observes the new committee at and after `v_eff`.
    ///
    /// Validation failures (floor, overlap, v_eff delay, conflict
    /// with an unsettled pending reconfig) are logged and dropped —
    /// they do not roll the block back. A reconfig that conflicts
    /// with a pending one is dropped silently so a single block
    /// can't sneak two contradictory boundaries past validation.
    pub(super) fn apply_committed_reconfigs(&mut self, block: &Block) {
        use boule_consensus::reconfig::ReconfigCommand;

        // #325 PR B: snapshot the pre-state so a debug_assert can
        // confirm that the pure rebuild path (used by recovery-time
        // validation) produces the same final history this wrapper
        // does. Any divergence is a bug — the rebuild would otherwise
        // produce a different history than what's persisted, and the
        // recovery check would falsely flag healthy storage. The
        // snapshot is `cfg(debug_assertions)`-gated so release builds
        // don't pay the clone.
        #[cfg(debug_assertions)]
        let pre_state_for_parity = (
            self.validator_history.clone(),
            self.operator_key_history.clone(),
        );

        let mut applied_any = false;
        // #549: track operator-key registrations from reconfig adds separately
        // — the operator-key history persists under its own key (and, unlike
        // signing keys, is NOT re-derivable from the set, so it must be saved).
        let mut operator_history_changed = false;
        // #546: track endpoint-registry GC (a removed validator's entries
        // dropped) so we re-persist the registry once if anything changed.
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

            // Validate against the set authoritative at the block's
            // view — the cluster's view of "now" at commit time. The
            // pacemaker may have advanced past this by the time the
            // commit drains, but the rule must use the block's view
            // so all replicas accept or reject identically.
            let block_view = block.header.view;
            let current_set_at = self.validator_history.set_at(block_view);
            let next_members = match cmd.validate_against_with_delay_and_scheme(
                current_set_at.for_view(block_view),
                block_view,
                self.min_v_eff_delay,
                self.signature_scheme,
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

            // Conflict guard: only one reconfig may be pending at a
            // time. If the history already carries a non-genesis
            // boundary whose `v_eff` is strictly after the committing
            // block's view, a previously committed reconfig has not
            // yet taken effect — drop the second so the two cannot
            // compose unsoundly (cmd_b's validation baseline would
            // need to be cmd_a's post-boundary set, not the current
            // set, which we'd have to thread through). Future PRs can
            // relax this rule once compositional validation lands.
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
                    // validate_against_with_delay_and_scheme already
                    // rejects weight 0; this path is unreachable in
                    // practice. If it fires, drop the reconfig — the
                    // post-#460 ValidatorSet invariant is load-bearing
                    // for has_quorum, so a malformed boundary must
                    // never land in the history.
                    tracing::error!(
                        target: TRACE_TARGET,
                        error = %e,
                        "reconfig_with_weights_construct_failed",
                    );
                    continue;
                }
            };

            // Insert the boundary into the integration-layer history
            // (used by `dispatch::ingress`).
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
            // Mirror into the safety core's history so vote tally,
            // QC sizing, and proposal-time leader pick all see the
            // boundary at and after `v_eff`.
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
            // Re-install the pacemaker selector against a fresh
            // snapshot of the now-extended history so leader rotation
            // past `v_eff` lands on the post-boundary set. The
            // post-boundary regime starts with a fresh accumulator
            // (priorities = [0; n]) — see
            // `WeightedAccumulatorSelector` for the per-regime
            // independence guarantee.
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

            // #729: if the reconfig that just landed *is* this node's staged
            // governance reconfig, clear the stage so the next proposal does not
            // re-mint it. Match by command equality (its `v_eff`-bound consent
            // makes the committed bytes identical to the staged ones) so that a
            // *staking* reconfig landing does not clear a still-pending
            // governance one.
            if self.staged_governance_reconfig.as_ref() == Some(&cmd) {
                self.staged_governance_reconfig = None;
                tracing::info!(
                    target: TRACE_TARGET,
                    v_eff = cmd.v_eff.0,
                    "governance_reconfig_landed_stage_cleared",
                );
            }

            // #549: register operator keys for newly-seated validators whose
            // `adds` entry declared one — the operator-key analogue of the
            // signing-key mirror, but applied *live* (and persisted below)
            // because operator keys aren't re-derivable from the set. Mirrors
            // the same logic in `apply_reconfig_commands_to_set_history` so the
            // live history matches the commitment/recovery rebuild.
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

            // #547: seed the initial endpoint list of newly-seated
            // validators (authenticated by the inbound-consent signature
            // when an operator key is present, #548). Best-effort: a list
            // that violates the `max_endpoint_list_length` cap or carries a
            // duplicate `network_id` is logged and skipped — the validator
            // is still seated, it just starts with no published endpoints.
            // An empty list is a no-op.
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

            // #546: GC the endpoint entries of validators this reconfig
            // removes, so the registry doesn't grow without bound across
            // membership churn. Done at the reconfig's commit (slightly
            // ahead of the removal's `v_eff`): endpoint entries are
            // non-binding discovery hints, so dropping a soon-to-leave
            // validator's hints a few views early just falls its peers back
            // to the gossip overlay — harmless. (Precise `v_eff + k` timing
            // remains the #546 refinement.) `forget` is a no-op for a
            // validator with no published entries.
            for removed in &cmd.removes {
                if self.endpoint_registry.forget(removed) {
                    endpoint_registry_changed = true;
                }
            }
        }

        // #549: persist the operator-key history if a reconfig add registered
        // an operator key (it cannot be rebuilt from genesis once mutated).
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

        // #546: re-persist the endpoint registry if a removed validator's
        // entries were GC'd. The registry lives outside the #325
        // anti-rollback commitment, so this is a plain persist (no
        // commitment/rebuild interaction).
        if endpoint_registry_changed {
            self.persist_endpoint_registry();
        }

        // #254: durably persist the updated history once any boundary
        // has landed. Write a single blob over the full history (rather
        // than a journal of diffs) so recovery is a single read +
        // decode. Failures log + drop — the in-memory state is
        // authoritative for the running process; on the next reconfig
        // we'll get another chance to flush, and the recovery path will
        // just reset to whatever state was durably written before the
        // last successful flush.
        if applied_any {
            // A reconfig boundary landed, so any app-driven (staking) validator
            // updates this node had staged are now materialised (this is where a
            // minted ReconfigCommand takes effect). Clear the stage so the next
            // proposal does not re-mint them. (A staged *governance* reconfig
            // #729 is cleared separately, above, only when its own command lands
            // — so a staking reconfig landing does not drop a still-pending
            // governance one, and the two serialise across boundaries.)
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

        // #325 PR B: confirm the pure-rebuild function lands in the
        // same place the wrapper did for the set_history surface.
        // The pure function additionally mirrors new validators into
        // key_history (matching the from_set_history fallback that
        // recover() applies when no key_history blob is persisted),
        // but the wrapper deliberately leaves key_history untouched
        // — that mirror happens implicitly at the next recover. So
        // this debug_assert only checks set_history parity. See the
        // snapshot at the top of this method for context.
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
                self.signature_scheme,
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
            // #549: unlike key_history, the live wrapper *does* register
            // operator keys from reconfig adds (they aren't re-derivable), so
            // the rebuild's operator history must match the live one.
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
