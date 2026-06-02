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

use std::collections::BTreeMap;

use boule_consensus::View;
use boule_consensus::reconfig::{MIN_V_EFF_DELAY, ReconfigCommand, WeightChange};
use boule_consensus::replication::application::ValidatorUpdate;
use boule_consensus::validator_set::{ValidatorId, ValidatorSet};
use boule_core::identity::NodeId;

use super::{ConsensusNode, TRACE_TARGET};

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
        if self.staged_validator_updates.is_empty() {
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

        let set_at = self.validator_history.set_at(view);
        let current = set_at.for_view(view);
        let Some(cmd) = staged_updates_to_reconfig(&self.staged_validator_updates, current, v_eff)
        else {
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
        // silently losing it.

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
