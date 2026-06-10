use super::*;

impl HotStuffCore {
    pub(super) fn check_proposal_dedupe(
        &mut self,
        view: View,
        leader: ValidatorId,
        block_hash: BlockHash,
    ) -> Option<Action> {
        match self.proposal_dedupe.entry((view, leader)) {
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(block_hash);
                None
            }
            std::collections::hash_map::Entry::Occupied(e) if *e.get() == block_hash => None,
            std::collections::hash_map::Entry::Occupied(e) => {
                let block_a = *e.get();
                Some(Action::ProposalEquivocationEvidence {
                    leader,
                    view,
                    block_a,
                    block_b: block_hash,
                })
            }
        }
    }

    pub(super) fn on_proposal_received(&mut self, signed: Signed<Proposal>) -> Vec<Action> {
        let parent_hash = signed.payload.block.header.parent_hash;

        if !self.state.pending_blocks.contains_key(&parent_hash) {
            let child_hash = signed.payload.block.hash();
            let sender = signed.signer;

            let expected_height = signed.payload.block.header.height.saturating_sub(Height(1));

            if !self.parked_proposals.contains_key(&child_hash) {
                self.evict_parked_to_fit_one();
            }
            self.parked_proposals.insert(child_hash, signed);

            return self.try_emit_block_sync_retry(
                parent_hash,
                sender,
                expected_height,
                BlockSyncReason::UnknownParentOnProposal,
            );
        }

        self.block_sync_inflight
            .remove(&signed.payload.block.hash());
        self.state.insert_pending(signed.payload.block.clone());

        let mut actions = Vec::new();

        let vote_to_broadcast = if safe_to_vote(&signed.payload, &self.state) {
            let view = signed.payload.block.header.view;
            let block_hash = signed.payload.block.hash();

            self.state.last_voted_view = view;
            actions.push(Action::Persist(StateUpdate::VotedInView { view }));

            if should_update_high_qc(&signed.payload.justify, &self.state) {
                let qc = signed.payload.justify.clone();

                self.state.high_qc = Some(VerifiedQc::unchecked(qc.clone()));
                actions.push(Action::Persist(StateUpdate::HighQc(qc)));
            }

            Some(Vote { view, block_hash })
        } else {
            None
        };

        let two_chain_candidate: Option<Locked> = self
            .state
            .pending_blocks
            .get(&parent_hash)
            .and_then(|b_prime_prime| {
                let grandparent_hash = b_prime_prime.header.parent_hash;
                self.state
                    .pending_blocks
                    .get(&grandparent_hash)
                    .map(|b_prime| Locked {
                        view: b_prime.header.view,
                        height: b_prime.header.height,
                        block_hash: grandparent_hash,
                    })
            });
        if let Some(candidate) = two_chain_candidate {
            let current_height = self.state.locked.map(|l| l.height).unwrap_or(Height::ZERO);
            if candidate.height > current_height {
                self.state.locked = Some(candidate);
                actions.push(Action::Persist(StateUpdate::Locked(candidate)));
            }
        }

        if let Some(vote) = vote_to_broadcast {
            actions.push(Action::Broadcast(ConsensusMsg::Vote(vote)));
        }

        if let Some(committed) = three_chain_commit(&signed.payload.justify, &self.state) {
            let commit_height = committed.header.height;
            actions.push(Action::Commit(committed));
            self.state
                .pending_blocks
                .retain(|_, b| b.header.height > commit_height);
        }

        actions
    }

    pub(super) fn on_vote_received(&mut self, variant: VoteVariant) -> Vec<Action> {
        let (verified, partial) = variant.into_parts();
        let (signed, voter_id) = verified.into_parts();
        let vote = &signed.payload;
        let next_view = vote.view + 1;

        let vs_at_vote = self.state.validator_history.set_at(vote.view);

        let Some(voter_idx) = vs_at_vote.for_view(vote.view).index_of(&voter_id) else {
            return Vec::new();
        };

        match self.vote_dedupe.entry((vote.view, voter_id)) {
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(vote.block_hash);
            }
            std::collections::hash_map::Entry::Occupied(e) if *e.get() == vote.block_hash => {}
            std::collections::hash_map::Entry::Occupied(e) => {
                let block_a = *e.get();
                return vec![Action::EquivocationEvidence {
                    voter: voter_id,
                    view: vote.view,
                    block_a,
                    block_b: vote.block_hash,
                }];
            }
        }

        let key = (vote.view, vote.block_hash);
        let vs_at_vote_set = vs_at_vote.for_view(vote.view);
        let validator_set_len = vs_at_vote_set.len();

        if !self.vote_bucket.contains_key(&key) {
            self.evict_vote_buckets_to_fit_one();
        }
        let qc = self.vote_bucket.entry(key).or_insert_with(|| {
            QuorumCertificate::new(vote.view, vote.block_hash, validator_set_len)
        });
        let had_quorum = qc.has_quorum(vs_at_vote_set);
        qc.add_bls_partial(voter_idx, partial);
        let has_quorum_now = qc.has_quorum(vs_at_vote_set);

        if had_quorum || !has_quorum_now {
            return Vec::new();
        }

        let formed = qc.clone();
        let mut actions = Vec::new();

        if should_update_high_qc(&formed, &self.state) {
            self.state.high_qc = Some(VerifiedQc::unchecked(formed.clone()));
            actions.push(Action::Persist(StateUpdate::HighQc(formed.clone())));
        }

        actions.extend(self.try_propose_as_leader(next_view));

        actions
    }

    pub(super) fn on_new_view_received(&mut self, signed: Signed<NewView>) -> Vec<Action> {
        let qc = signed.payload.high_qc;
        if !should_update_high_qc(&qc, &self.state) {
            return Vec::new();
        }
        let block_hash = qc.block_hash;
        let sender = signed.signer;

        self.state.high_qc = Some(VerifiedQc::unchecked(qc.clone()));
        let mut actions = vec![Action::Persist(StateUpdate::HighQc(qc))];
        if !self.state.pending_blocks.contains_key(&block_hash) {
            actions.extend(self.try_emit_block_sync_retry(
                block_hash,
                sender,
                Height::ZERO,
                BlockSyncReason::UnknownHighQcOnNewView,
            ));
        }
        actions
    }

    pub(super) fn on_pacemaker_advance(&mut self, v: View) -> Vec<Action> {
        self.state.current_view = v;

        let active_at = self.state.validator_history.set_at(v);
        let active = active_at.for_view(v);
        if *active != self.state.validator_set {
            self.state.validator_set = active.clone();
        }

        self.evict_vote_buckets_below(v);

        let mut actions = Vec::new();

        let ready: Vec<BlockHash> = self
            .parked_proposals
            .iter()
            .filter_map(|(child_hash, signed)| {
                let parent_hash = signed.payload.block.header.parent_hash;
                if self.state.pending_blocks.contains_key(&parent_hash) {
                    Some(*child_hash)
                } else {
                    None
                }
            })
            .collect();
        for child_hash in ready {
            if let Some(signed) = self.parked_proposals.remove(&child_hash) {
                let parent_hash = signed.payload.block.header.parent_hash;
                self.block_sync_inflight.remove(&parent_hash);
                let retry_actions = self.on_proposal_received(signed);
                actions.extend(retry_actions);
            }
        }

        let mut parent_hashes_to_retry: std::collections::BTreeSet<BlockHash> =
            std::collections::BTreeSet::new();
        for signed in self.parked_proposals.values() {
            parent_hashes_to_retry.insert(signed.payload.block.header.parent_hash);
        }
        if let Some(high_qc_hash) = self
            .state
            .high_qc
            .as_ref()
            .map(|qc| qc.block_hash())
            .filter(|h| !self.state.pending_blocks.contains_key(h))
        {
            parent_hashes_to_retry.insert(high_qc_hash);
        }
        for parent_hash in &parent_hashes_to_retry {
            actions.extend(self.run_block_sync_retry_for_parent(*parent_hash));
        }

        if let Some(high_qc) = self.state.high_qc.clone() {
            actions.push(Action::Broadcast(ConsensusMsg::NewView(NewView {
                high_qc: high_qc.into_inner(),
            })));
        }

        actions.extend(self.try_propose_as_leader(v));

        actions
    }
}
