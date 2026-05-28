//! Commit-time application of [`ReconfigCommand`](crate::consensus::reconfig::ReconfigCommand)
//! payloads. See [`super::ConsensusNode::apply_committed_reconfigs`] for
//! the validation and history-mirror discipline.

use std::sync::Arc;

use crate::consensus::View;
use crate::consensus::pacemaker::leader::WeightedAccumulatorSelector;
use crate::consensus::validator_set::ValidatorSet;
use crate::replication::block::Block;

use super::{ConsensusNode, STORAGE_KEY_VALIDATOR_HISTORY, TRACE_TARGET};

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
        use crate::consensus::reconfig::ReconfigCommand;

        // #325 PR B: snapshot the pre-state so a debug_assert can
        // confirm that the pure rebuild path (used by recovery-time
        // validation) produces the same final history this wrapper
        // does. Any divergence is a bug — the rebuild would otherwise
        // produce a different history than what's persisted, and the
        // recovery check would falsely flag healthy storage. The
        // snapshot is `cfg(debug_assertions)`-gated so release builds
        // don't pay the clone.
        #[cfg(debug_assertions)]
        let pre_state_for_parity = self.validator_history.clone();

        let mut applied_any = false;
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

            let next_entries: Vec<(crate::consensus::validator_set::ValidatorId, u64)> =
                next_members
                    .into_iter()
                    .map(|(n, w)| {
                        (
                            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(n),
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
            let mut rebuilt = pre_state_for_parity;
            let mut throwaway_key =
                crate::consensus::validator_key_history::ValidatorKeyHistory::new(
                    self.validator_set.iter().copied(),
                );
            crate::consensus::history_commitment::apply_reconfig_commands_to_set_history(
                block,
                &mut rebuilt,
                &mut throwaway_key,
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
        }
    }
}
