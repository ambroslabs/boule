use super::*;

impl HotStuffCore {
    pub fn become_leader(&mut self, view: impl Into<View>) -> Vec<Action> {
        let view = view.into();
        self.build_proposal_at_view(view)
    }

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

        vec![Action::BuildProposal {
            view,
            high_qc,
            parent,
        }]
    }

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

    pub(super) fn try_propose_as_leader(&mut self, view: View) -> Vec<Action> {
        let vs_at = self.state.validator_history.set_at(view);
        if round_robin_leader(vs_at.for_view(view), view) != self.self_id {
            return Vec::new();
        }
        self.build_proposal_at_view(view)
    }
}
