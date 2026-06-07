//! Leader-side proposal building.
use super::*;

impl HotStuffCore {
    /// Leader entry point for `view`, invoked on `Action::BecomeLeader(view)`.
    ///
    /// The pacemaker only emits that action for the rotation leader, so the
    /// leader-rotation check is the caller's; this path enforces only the
    /// per-view double-propose guard, `high_qc` presence, and parent lookup.
    /// Delegates to [`Self::build_proposal_at_view`]; see it for when an empty
    /// `Vec` is returned.
    pub fn become_leader(&mut self, view: impl Into<View>) -> Vec<Action> {
        let view = view.into();
        self.build_proposal_at_view(view)
    }

    /// Emit a `BuildProposal` action for `view`, or empty `Vec` if any guard
    /// fails: already proposed at `view` (the `proposed_in_view` double-propose
    /// guard), no `high_qc` yet, or the QC's parent block is absent from
    /// `pending_blocks` (block-sync incomplete; a later `PacemakerAdvance`
    /// retries).
    ///
    /// No leader-rotation check — callers needing it use
    /// [`Self::try_propose_as_leader`]. The `proposed_in_view` guard ensures
    /// the several call sites targeting one view emit at most one proposal,
    /// keeping an honest leader distinguishable from a Byzantine equivocator.
    pub(super) fn build_proposal_at_view(&mut self, view: View) -> Vec<Action> {
        if view <= self.proposed_in_view {
            return Vec::new();
        }
        let Some(high_qc) = self.state.high_qc.clone() else {
            return Vec::new();
        };
        let high_qc = high_qc.into_inner();
        let Some(parent) = self.state.pending_blocks.get(&high_qc.block_hash).cloned() else {
            return Vec::new();
        };
        // The integration layer runs the (async-capable) builder and calls
        // `proposal_built` with the result. A build failure there leaves
        // `proposed_in_view` unset, so the view stays retriable.
        vec![Action::BuildProposal {
            view,
            high_qc,
            parent,
        }]
    }

    /// Test-only stand-in for the integration layer's block builder, so tests
    /// can fabricate a proposal from a `BuildProposal` action without owning a
    /// builder. Produces the same deterministic empty-commands child as
    /// `TestBlockBuilder` (proposer = `self_id`). Production builds in the
    /// integration layer (`ConsensusNode`), which holds the real builder.
    #[cfg(test)]
    pub fn build_proposal(
        &self,
        view: View,
        high_qc: &QuorumCertificate,
        parent: &Block,
    ) -> anyhow::Result<Block> {
        tests::TestBlockBuilder {
            proposer: self.self_id,
        }
        .build(parent, view, high_qc, &self.state.pending_blocks, 0)
    }

    /// Finalize a proposal the integration layer just built for `view`: set the
    /// `proposed_in_view` double-propose guard and return the
    /// `Persist(ProposedInView)` then `Broadcast(Proposal)` actions (persist
    /// before broadcast). Called only after a successful build, so a failed
    /// build leaves `proposed_in_view` unset and the view retriable.
    pub fn proposal_built(
        &mut self,
        view: View,
        block: Block,
        high_qc: QuorumCertificate,
    ) -> Vec<Action> {
        self.proposed_in_view = view;
        vec![
            Action::Persist(StateUpdate::ProposedInView { view }),
            Action::Broadcast(ConsensusMsg::Proposal(Proposal {
                block,
                justify: high_qc,
            })),
        ]
    }

    /// Leader-rotation-aware variant of [`Self::build_proposal_at_view`].
    /// Returns empty unless this replica is the round-robin leader of `view`;
    /// otherwise delegates to the build path. Used from re-entrant entry points
    /// that fire regardless of whether self is the leader.
    pub(super) fn try_propose_as_leader(&mut self, view: View) -> Vec<Action> {
        // Leader rotation is keyed by the validator set authoritative at `view`.
        let vs_at = self.state.validator_history.set_at(view);
        if round_robin_leader(vs_at.for_view(view), view) != self.self_id {
            return Vec::new();
        }
        self.build_proposal_at_view(view)
    }
}
