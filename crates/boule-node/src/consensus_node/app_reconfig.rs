use std::collections::BTreeMap;

use boule_consensus::View;
use boule_consensus::consensus_params::ConsensusParamUpdate;
use boule_consensus::endpoint_registry::SignedEndpointCommand;
use boule_consensus::reconfig::{
    MIN_V_EFF_DELAY, MIN_VALIDATOR_FLOOR, ReconfigCommand, WeightChange,
};
use boule_consensus::replication::application::{ValidatorEffect, ValidatorUpdate};
use boule_consensus::validator_rotation::{
    DualSignedOperatorRotation, DualSignedRotation, DualSignedRotationCancel,
    OperatorSignedRotation,
};
use boule_consensus::validator_set::{ValidatorId, ValidatorSet};
use boule_core::identity::NodeId;

use super::{ConsensusNode, TRACE_TARGET};

fn is_rotation_command(bytes: &[u8]) -> bool {
    DualSignedRotation::is_rotation_payload(bytes)
        || DualSignedRotationCancel::is_cancel_payload(bytes)
        || OperatorSignedRotation::is_operator_rotation_payload(bytes)
        || DualSignedOperatorRotation::is_operator_key_rotation_payload(bytes)
}

const APP_RECONFIG_SETTLE_VIEWS: View = View::new(8);

impl ConsensusNode {
    pub(super) fn mint_staged_reconfig(&mut self, view: View) {
        let set_at = self.validator_history.set_at(view);
        let current = set_at.for_view(view).clone();
        let jail = self.jail_removes(&current);

        if self.staged_validator_updates.is_empty() && jail.is_empty() {
            return;
        }

        let pending = self
            .validator_history
            .iter()
            .any(|(v_eff, _)| v_eff != View::ZERO && v_eff > view);
        if pending {
            return;
        }

        let effective_delay = std::cmp::max(
            std::cmp::max(self.min_v_eff_delay, MIN_V_EFF_DELAY),
            APP_RECONFIG_SETTLE_VIEWS,
        );
        let Some(v_eff) = view.checked_add(effective_delay) else {
            tracing::error!(target: TRACE_TARGET, view = view.0, "mint_staged_reconfig_v_eff_overflow");
            return;
        };

        let mut updates = self.staged_validator_updates.clone();
        updates.extend(jail);
        let Some(cmd) = staged_updates_to_reconfig(&updates, &current, v_eff) else {
            tracing::warn!(
                target: TRACE_TARGET,
                view = view.0,
                "mint_staged_reconfig_no_actionable_updates",
            );
            self.staged_validator_updates.clear();
            return;
        };

        match self.mempool.insert(cmd.encode()) {
            Ok(_) => tracing::info!(
                target: TRACE_TARGET,
                view = view.0,
                v_eff = v_eff.0,
                removes = cmd.removes.len(),
                changes = cmd.changes.len(),
                "app_validator_updates_minted_reconfig",
            ),
            Err(e) => tracing::error!(
                target: TRACE_TARGET,
                error = %e,
                "mint_staged_reconfig_mempool_insert_failed",
            ),
        }
    }

    pub(super) fn mint_staged_governance_reconfig(&mut self, view: View) {
        let Some(cmd) = self.staged_governance_reconfig.clone() else {
            return;
        };

        let floor = std::cmp::max(self.min_v_eff_delay, MIN_V_EFF_DELAY);
        let too_soon = view
            .checked_add(floor)
            .is_none_or(|earliest| cmd.v_eff < earliest);
        if too_soon {
            tracing::warn!(
                target: TRACE_TARGET,
                view = view.0,
                v_eff = cmd.v_eff.0,
                "governance_reconfig_dropped_stale_v_eff",
            );
            self.staged_governance_reconfig = None;
            return;
        }

        let pending = self
            .validator_history
            .iter()
            .any(|(v_eff, _)| v_eff != View::ZERO && v_eff > view);
        if pending {
            return;
        }

        match self.mempool.insert(cmd.encode()) {
            Ok(_) => tracing::info!(
                target: TRACE_TARGET,
                view = view.0,
                v_eff = cmd.v_eff.0,
                adds = cmd.adds.len(),
                removes = cmd.removes.len(),
                changes = cmd.changes.len(),
                "governance_reconfig_minted",
            ),
            Err(e) => tracing::error!(
                target: TRACE_TARGET,
                error = %e,
                "mint_staged_governance_reconfig_mempool_insert_failed",
            ),
        }
    }

    pub(super) fn mint_staged_effects(&mut self, view: View) {
        if self.staged_effects.is_empty() {
            return;
        }
        for effect in std::mem::take(&mut self.staged_effects) {
            match effect {
                ValidatorEffect::KeyRotation(bytes) => {
                    if !is_rotation_command(&bytes) {
                        tracing::error!(
                            target: TRACE_TARGET,
                            view = view.0,
                            "mint_staged_effects_key_rotation_payload_not_a_rotation",
                        );
                        continue;
                    }
                    match self.mempool.insert(bytes) {
                        Ok(_) => tracing::info!(
                            target: TRACE_TARGET,
                            view = view.0,
                            "app_effect_minted_key_rotation",
                        ),
                        Err(e) => tracing::error!(
                            target: TRACE_TARGET,
                            error = %e,
                            "mint_staged_effects_mempool_insert_failed",
                        ),
                    }
                }
                ValidatorEffect::EndpointUpdate(bytes) => {
                    if !SignedEndpointCommand::is_endpoint_payload(&bytes) {
                        tracing::error!(
                            target: TRACE_TARGET,
                            view = view.0,
                            "mint_staged_effects_endpoint_update_payload_not_an_endpoint",
                        );
                        continue;
                    }
                    match self.mempool.insert(bytes) {
                        Ok(_) => tracing::info!(
                            target: TRACE_TARGET,
                            view = view.0,
                            "app_effect_minted_endpoint_update",
                        ),
                        Err(e) => tracing::error!(
                            target: TRACE_TARGET,
                            error = %e,
                            "mint_staged_effects_mempool_insert_failed",
                        ),
                    }
                }
                ValidatorEffect::ParamUpdate(bytes) => {
                    if !ConsensusParamUpdate::is_param_update_payload(&bytes) {
                        tracing::error!(
                            target: TRACE_TARGET,
                            view = view.0,
                            "mint_staged_effects_param_update_payload_not_a_param_update",
                        );
                        continue;
                    }
                    match self.mempool.insert(bytes) {
                        Ok(_) => tracing::info!(
                            target: TRACE_TARGET,
                            view = view.0,
                            "app_effect_minted_param_update",
                        ),
                        Err(e) => tracing::error!(
                            target: TRACE_TARGET,
                            error = %e,
                            "mint_staged_effects_mempool_insert_failed",
                        ),
                    }
                }
                ValidatorEffect::Reconfig(bytes) => match ReconfigCommand::decode(&bytes) {
                    Ok(cmd) => {
                        tracing::info!(
                            target: TRACE_TARGET,
                            view = view.0,
                            v_eff = cmd.v_eff.0,
                            "governance_reconfig_staged",
                        );
                        self.staged_governance_reconfig = Some(cmd);
                    }
                    Err(e) => tracing::error!(
                        target: TRACE_TARGET,
                        view = view.0,
                        error = %e,
                        "mint_staged_effects_reconfig_payload_not_a_reconfig",
                    ),
                },

                _ => tracing::warn!(
                    target: TRACE_TARGET,
                    view = view.0,
                    "app_effect_unknown_category_dropped",
                ),
            }
        }
    }

    fn jail_removes(&self, current: &ValidatorSet) -> Vec<ValidatorUpdate> {
        let mut seated: Vec<ValidatorId> = self
            .committed_evidence
            .keys()
            .copied()
            .filter(|v| current.contains(v))
            .collect();
        if seated.is_empty() {
            return Vec::new();
        }
        seated.sort();

        let app_removes = self
            .staged_validator_updates
            .iter()
            .filter(|u| {
                u.weight == 0 && current.contains(&ValidatorId::from_genesis_pubkey(u.node_id))
            })
            .count();
        let budget = current
            .len()
            .saturating_sub(MIN_VALIDATOR_FLOOR)
            .saturating_sub(app_removes);
        if budget == 0 {
            tracing::warn!(
                target: TRACE_TARGET,
                seated_equivocators = seated.len(),
                set_size = current.len(),
                floor = MIN_VALIDATOR_FLOOR,
                "jail_blocked_by_validator_floor",
            );
            return Vec::new();
        }
        seated.truncate(budget);
        seated
            .iter()
            .map(|v| ValidatorUpdate {
                node_id: *v.as_node_id(),
                weight: 0,
            })
            .collect()
    }
}

pub(super) fn staged_updates_to_reconfig(
    updates: &[ValidatorUpdate],
    current: &ValidatorSet,
    v_eff: View,
) -> Option<ReconfigCommand> {
    let mut target: BTreeMap<NodeId, u64> = BTreeMap::new();
    for u in updates {
        target.insert(u.node_id, u.weight);
    }

    let mut removes = Vec::new();
    let mut changes = Vec::new();
    for (node_id, weight) in target {
        let seated = current.contains(&ValidatorId::from_genesis_pubkey(node_id));
        match (weight, seated) {
            (0, true) => removes.push(node_id),
            (0, false) => {}
            (_, true) => changes.push(WeightChange { node_id, weight }),
            (_, false) => {}
        }
    }

    if removes.is_empty() && changes.is_empty() {
        return None;
    }
    Some(ReconfigCommand {
        adds: Vec::new(),
        removes,
        changes,
        v_eff,
    })
}
