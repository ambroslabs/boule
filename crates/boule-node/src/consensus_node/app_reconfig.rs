//! Deferred materialisation of application-driven validator-set changes.
//!
//! When an [`Application`](boule_consensus::replication::application::Application)
//! returns validator updates
//! ([`CommitResult`](boule_consensus::replication::application::CommitResult))
//! from `commit`, they are staged on the node (see
//! [`ConsensusNode::staged_validator_updates`](super::ConsensusNode#structfield.staged_validator_updates)).
//! The next time this node builds a proposal as leader,
//! [`ConsensusNode::mint_staged_reconfig`] turns the staged batch into a real
//! [`ReconfigCommand`] on the block it is about to build, so an app-driven
//! membership change flows through exactly the same validated /
//! header-committed / recoverable path as a governance reconfig (#225 M5).
//!
//! Materialising as a block command — rather than mutating the validator
//! history directly at commit — is what keeps recovery sound: the startup
//! integrity check re-derives the validator history from committed block
//! *commands*, so a boundary that never appeared in any block's commands
//! could not be reproduced and the node would refuse to start. A minted
//! `ReconfigCommand` *is* a command, so the existing rebuild reproduces it.
//!
//! The same pattern carries the richer execution-layer transaction effects
//! ([`ValidatorEffect`], #727): an EL that has already authorized a key
//! rotation, endpoint update, or parameter change returns it from `commit`,
//! and [`ConsensusNode::mint_staged_effects`] re-materialises it as the
//! corresponding consensus system command at the next proposal — same
//! recovery-sound, command-in-a-block path.

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

/// Whether `bytes` is one of the consensus key-rotation system commands — the
/// canonical 4-way predicate the block builder uses to recognise a rotation
/// payload (dual-signed key rotation, its cancel, operator-signed recovery
/// rotation, operator-key self-rotation). Used by
/// [`ConsensusNode::mint_staged_effects`] to confirm a
/// [`ValidatorEffect::KeyRotation`] payload's declared category before minting.
fn is_rotation_command(bytes: &[u8]) -> bool {
    DualSignedRotation::is_rotation_payload(bytes)
        || DualSignedRotationCancel::is_cancel_payload(bytes)
        || OperatorSignedRotation::is_operator_rotation_payload(bytes)
        || DualSignedOperatorRotation::is_operator_key_rotation_payload(bytes)
}

/// Views to defer an app-driven reconfig's `v_eff` beyond the proposing
/// block's view, on top of the validation floor. The reconfig is minted
/// into the block this node proposes; that block only commits a few views
/// later (HotStuff's three-chain), so `v_eff` must sit comfortably past the
/// commit depth or the boundary would already be in the past when applied —
/// leaving replicas disagreeing on the committee around the boundary view.
const APP_RECONFIG_SETTLE_VIEWS: View = View::new(8);

impl ConsensusNode {
    /// If this node has staged application-driven validator updates and no
    /// reconfig boundary is already pending, mint them into a single
    /// [`ReconfigCommand`] and insert it into the mempool so the proposal
    /// this node is about to build at `view` (as leader) carries it.
    ///
    /// A no-op when nothing is staged — which is the only case for an
    /// application that does not drive membership (the reth EL), so the
    /// common path costs one `is_empty` check. The staged batch is left in
    /// place after a successful mint and cleared only when the reconfig
    /// boundary actually lands (see `apply_committed_reconfigs`), so a block
    /// that never commits is re-minted rather than lost; a batch with nothing
    /// actionable is dropped here so it does not re-attempt on every build.
    pub(super) fn mint_staged_reconfig(&mut self, view: View) {
        // #658a: an equivocator with committed evidence is jailed by removing
        // it from the active set. Derive the removes from the persisted
        // `committed_evidence` registry every proposal (rather than staging
        // once at record time) so the jail is idempotent and survives a
        // restart in the propose→commit window, and fold them into the same
        // reconfig as any app-driven updates — the apply path allows only one
        // boundary at a time, so they cannot ride separate commands.
        let set_at = self.validator_history.set_at(view);
        let current = set_at.for_view(view).clone();
        let jail = self.jail_removes(&current);

        if self.staged_validator_updates.is_empty() && jail.is_empty() {
            return;
        }
        // Respect the one-reconfig-at-a-time rule the apply path enforces:
        // if a boundary is already pending (a non-genesis boundary whose
        // v_eff is still in the future relative to this view),
        // `apply_committed_reconfigs` would drop a second one as a conflict,
        // so don't mint it.
        let pending = self
            .validator_history
            .iter()
            .any(|(v_eff, _)| v_eff != View::ZERO && v_eff > view);
        if pending {
            return;
        }

        // v_eff must clear not just the apply-time validation floor
        // (`block_view + min_v_eff_delay`) but the commit latency — see
        // APP_RECONFIG_SETTLE_VIEWS — so the boundary is still in the future
        // when the reconfig block lands.
        let effective_delay = std::cmp::max(
            std::cmp::max(self.min_v_eff_delay, MIN_V_EFF_DELAY),
            APP_RECONFIG_SETTLE_VIEWS,
        );
        let Some(v_eff) = view.checked_add(effective_delay) else {
            tracing::error!(target: TRACE_TARGET, view = view.0, "mint_staged_reconfig_v_eff_overflow");
            return;
        };

        // Merge app-staged updates with the jail removes into one batch.
        let mut updates = self.staged_validator_updates.clone();
        updates.extend(jail);
        let Some(cmd) = staged_updates_to_reconfig(&updates, &current, v_eff) else {
            // Nothing actionable (e.g. only adds, which need an endpoint, or
            // updates targeting non-members). Drop the dead batch so it does
            // not re-attempt on every build; the application re-requests on a
            // future commit if it still wants the change.
            tracing::warn!(
                target: TRACE_TARGET,
                view = view.0,
                "mint_staged_reconfig_no_actionable_updates",
            );
            self.staged_validator_updates.clear();
            return;
        };
        // Leave the stage in place: it is cleared when the reconfig boundary
        // actually lands (see `apply_committed_reconfigs`), so if this block
        // never commits a later proposal re-mints the change rather than
        // silently losing it. (Jail removes are re-derived from the persisted
        // registry, so they need no staging.)

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

    /// If this node has a staged governance reconfig (#729) and no reconfig
    /// boundary is already pending, mint it **verbatim** into the mempool so the
    /// proposal this node builds at `view` carries it. Called next to
    /// [`Self::mint_staged_reconfig`] on the build path.
    ///
    /// A governance reconfig is minted whole and unchanged — unlike the staking
    /// path, its `v_eff` is *not* recomputed, because an add's `consent_sig`
    /// (#548) pre-image is bound to that exact `v_eff`. It rides the same
    /// one-reconfig-boundary-at-a-time discipline as the staking path: the same
    /// pending guard here, and the apply path's "first reconfig per block wins"
    /// rule, mean a governance and a staking reconfig minted into the same round
    /// never both land — the loser is retained and re-minted next round, so the
    /// two serialise rather than conflict.
    ///
    /// The stage is left in place after a mint and cleared only when *this*
    /// reconfig's boundary lands (see [`Self::apply_committed_reconfigs`]), so a
    /// block that never commits re-mints rather than losing it. A governance
    /// reconfig whose `v_eff` has gone stale (it can no longer clear the
    /// apply-time floor, and `view` only advances) is dropped here — its consent
    /// is dead, so governance must re-approve with a later `v_eff`.
    pub(super) fn mint_staged_governance_reconfig(&mut self, view: View) {
        let Some(cmd) = self.staged_governance_reconfig.clone() else {
            return;
        };

        // Stale: `v_eff` can no longer clear the apply-time validation floor,
        // and it never will (views only advance). Drop it — the bound consent
        // is dead; governance re-approves with a later `v_eff`.
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

        // One-reconfig-at-a-time: skip if a boundary is already pending (the
        // apply path would drop a second one), and re-mint next round.
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

    /// Drain the staged execution-layer transaction effects (#727) and
    /// materialise each into its consensus system command on the proposal this
    /// node is about to build as leader. Called next to
    /// [`Self::mint_staged_reconfig`] on the build path.
    ///
    /// A no-op when nothing is staged — the only case for a backend that drives
    /// no effects (PoA, the reth EL default), so the common path costs one
    /// `is_empty` check.
    ///
    /// Unlike `staged_validator_updates`, staged effects are **drained** (minted
    /// once) rather than retained-until-landed. If the proposal that carries a
    /// minted command never commits, re-emission is the producing execution
    /// layer's responsibility: the EL holds the authorization in its own state
    /// and re-emits the effect on a later commit until it observes the change
    /// applied (#730). Retaining here would instead risk minting duplicate
    /// rotation commands, which have no one-boundary-at-a-time guard to dedupe
    /// them the way [`Self::mint_staged_reconfig`] does for reconfigs.
    ///
    /// Every [`ValidatorEffect`] category now has a live apply path:
    /// [`ValidatorEffect::KeyRotation`] (#730),
    /// [`ValidatorEffect::EndpointUpdate`] (#731), and
    /// [`ValidatorEffect::ParamUpdate`] (#542) are minted here directly as their
    /// consensus system commands; [`ValidatorEffect::Reconfig`] (#729) is
    /// instead *staged* for [`Self::mint_staged_governance_reconfig`] (it can't
    /// be drained-and-minted here — its `v_eff`-bound consent must be preserved
    /// and it must serialise with the staking reconfig path). Each mint/stage
    /// first confirms the payload's declared category (defense against the
    /// effect channel smuggling a mismatched command in). A future
    /// `#[non_exhaustive]` category with no materialiser is surfaced rather than
    /// silently dropped (cf. #728).
    pub(super) fn mint_staged_effects(&mut self, view: View) {
        if self.staged_effects.is_empty() {
            return;
        }
        for effect in std::mem::take(&mut self.staged_effects) {
            match effect {
                ValidatorEffect::KeyRotation(bytes) => {
                    // The EL already authorized this rotation (e.g. a precompile
                    // verified the dual signature, #730); re-materialise it as a
                    // block command so it flows through the existing rotation
                    // validate/apply path, where the embedded signatures are
                    // re-verified. Confirm the declared category matches the
                    // payload before minting (defense-in-depth: the effect
                    // channel must not smuggle a non-rotation command in).
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
                    // #731: the EL recorded a validator endpoint advertisement
                    // (#546); re-materialise it as a SignedEndpointCommand so it
                    // flows through `apply_committed_endpoints` at commit, where
                    // the validator's signature + monotone seq are verified.
                    // Confirm the declared category matches the payload first.
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
                    // #542: the EL drove a live consensus-parameter change;
                    // re-materialise it as a ConsensusParamUpdate command so it
                    // flows through `apply_committed_param_updates` at commit
                    // (validated + scheduled at its v_eff). Confirm the declared
                    // category matches the payload before minting.
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
                ValidatorEffect::Reconfig(bytes) => {
                    // #729: the EL's governance mechanism approved a membership
                    // reconfig. Stage it (last-wins) for
                    // `mint_staged_governance_reconfig`, which mints it verbatim
                    // under the one-boundary discipline — it is NOT minted here,
                    // because its `v_eff`-bound consent forbids recomputation and
                    // it must serialise with the staking reconfig path rather
                    // than race it. Confirm the declared category first.
                    match ReconfigCommand::decode(&bytes) {
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
                    }
                }
                // `ValidatorEffect` is `#[non_exhaustive]`: a category added by
                // a future milestone-#4 issue without a materialiser here is
                // surfaced rather than silently dropped.
                _ => tracing::warn!(
                    target: TRACE_TARGET,
                    view = view.0,
                    "app_effect_unknown_category_dropped",
                ),
            }
        }
    }

    /// Jail removes (#658a): one weight-0 [`ValidatorUpdate`] per committed-
    /// evidence equivocator that is still seated in `current`, capped so the
    /// removals keep the active set at or above [`MIN_VALIDATOR_FLOOR`].
    ///
    /// The floor cap is essential: commit-time validation rejects the *entire*
    /// reconfig if the result drops below the floor, which would take any
    /// legit app updates down with it — so we never propose more removes than
    /// the floor allows, accounting for app-staged removes already in flight.
    /// When the floor blocks every jail, the equivocator stays seated and the
    /// evidence record stands as off-chain accountability (the #457 caveat).
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
        seated.sort(); // deterministic order across nodes

        // Removals already implied by app-staged weight-0 updates for seated
        // validators reduce how many more the floor permits.
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

/// Translate a staged batch of [`ValidatorUpdate`]s into a single
/// [`ReconfigCommand`] against `current`, or `None` if nothing is
/// actionable.
///
/// - `weight == 0` removes a seated validator.
/// - `weight >= 1` for a seated validator changes its weight.
/// - `weight >= 1` for a non-member would be an *add* — skipped, because
///   adding a validator needs a network endpoint that a weight-keyed update
///   does not carry (endpoint advertisement is a separate concern).
/// - a remove of a non-member is skipped (nothing to remove).
///
/// Within the batch the last update for a given validator wins. The result
/// is ordered by `node_id` for a stable command encoding.
pub(super) fn staged_updates_to_reconfig(
    updates: &[ValidatorUpdate],
    current: &ValidatorSet,
    v_eff: View,
) -> Option<ReconfigCommand> {
    // Last-write-wins per validator, ordered by node_id.
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
            (0, false) => { /* nothing to remove */ }
            (_, true) => changes.push(WeightChange { node_id, weight }),
            (_, false) => { /* add needs an endpoint — skip */ }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn vid(b: u8) -> ValidatorId {
        ValidatorId::from_genesis_pubkey([b; 32])
    }
    fn set(entries: &[(u8, u64)]) -> ValidatorSet {
        ValidatorSet::with_weights(entries.iter().map(|(b, w)| (vid(*b), *w)).collect()).unwrap()
    }
    fn upd(b: u8, weight: u64) -> ValidatorUpdate {
        ValidatorUpdate {
            node_id: [b; 32],
            weight,
        }
    }

    #[test]
    fn classifies_change_and_remove_skips_add_and_absent_remove() {
        let current = set(&[(1, 10), (2, 10), (3, 10)]);
        let updates = vec![
            upd(1, 25), // seated, weight > 0 -> weight change
            upd(2, 0),  // seated, weight 0 -> remove
            upd(9, 7),  // not seated, weight > 0 -> add -> skipped (needs endpoint)
            upd(8, 0),  // not seated, weight 0 -> nothing to remove -> skipped
        ];
        let cmd =
            staged_updates_to_reconfig(&updates, &current, View::new(42)).expect("actionable");
        assert_eq!(cmd.v_eff, View::new(42));
        assert!(
            cmd.adds.is_empty(),
            "adds are never minted (need an endpoint)"
        );
        assert_eq!(cmd.removes, vec![[2u8; 32]]);
        assert_eq!(cmd.changes.len(), 1);
        assert_eq!(cmd.changes[0].node_id, [1u8; 32]);
        assert_eq!(cmd.changes[0].weight, 25);
    }

    #[test]
    fn last_write_wins_within_batch() {
        let current = set(&[(1, 10), (2, 10)]);
        let updates = vec![upd(1, 5), upd(1, 30)];
        let cmd = staged_updates_to_reconfig(&updates, &current, View::new(5)).unwrap();
        assert_eq!(cmd.changes.len(), 1);
        assert_eq!(
            cmd.changes[0].weight, 30,
            "the later update for node 1 wins"
        );
    }

    #[test]
    fn nothing_actionable_returns_none() {
        let current = set(&[(1, 10), (2, 10)]);
        // An add of a non-member and a remove of a non-member: neither is
        // expressible, so there is nothing to mint.
        let only_non_members = vec![upd(9, 5), upd(8, 0)];
        assert!(staged_updates_to_reconfig(&only_non_members, &current, View::new(5)).is_none());
        assert!(staged_updates_to_reconfig(&[], &current, View::new(5)).is_none());
    }
}
