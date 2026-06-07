//! Wire-event handlers: proposals, votes, new-views, pacemaker advance.
use super::*;

impl HotStuffCore {
    /// Dedupe a proposal against [`Self::proposal_dedupe`] keyed on `(view, leader)`.
    ///
    /// - Vacant: record the first sighting, return `None`.
    /// - Same `block_hash`: idempotent re-delivery, return `None`.
    /// - Different `block_hash`: leader equivocation. Return
    ///   [`Action::ProposalEquivocationEvidence`]. The recorded hash is
    ///   never overwritten, so further forks are always compared against
    ///   the first sighting.
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

    /// Handle an inbound [`Proposal`].
    pub(super) fn on_proposal_received(&mut self, signed: Signed<Proposal>) -> Vec<Action> {
        let parent_hash = signed.payload.block.header.parent_hash;
        // Unknown parent: without it we can't walk the extension against
        // our lock. Park the child and request the parent.
        if !self.state.pending_blocks.contains_key(&parent_hash) {
            let child_hash = signed.payload.block.hash();
            let sender = signed.signer;
            // saturating_sub guards the (unreachable) genesis-child case
            // against a malformed proposal claiming height 0.
            let expected_height = signed.payload.block.header.height.saturating_sub(Height(1));
            // Evict only when inserting a genuinely new child; an
            // idempotent re-park doesn't grow the map.
            if !self.parked_proposals.contains_key(&child_hash) {
                self.evict_parked_to_fit_one();
            }
            self.parked_proposals.insert(child_hash, signed);

            // First sighting of this parent starts the in-flight tracker
            // and probes; re-deliveries are gated by per-parent backoff.
            return self.try_emit_block_sync_retry(
                parent_hash,
                sender,
                expected_height,
                BlockSyncReason::UnknownParentOnProposal,
            );
        }

        // Parent has arrived: insert the block so `safe_to_vote` can walk
        // the extension, and clear the in-flight tracker for this hash.
        self.block_sync_inflight
            .remove(&signed.payload.block.hash());
        self.state.insert_pending(signed.payload.block.clone());

        let mut actions = Vec::new();
        // The vote's `Broadcast` is deferred until after the lock
        // promotion is pushed onto `actions`. The integration layer
        // flushes any leading `Persist` items before a non-`Persist`
        // action, so persisting the new lock before the vote reaches the
        // wire closes the Tendermint amnesia hole: a crash between
        // vote-broadcast and lock-persist would leave the on-disk lock
        // stale while `last_voted_view` had advanced.
        let vote_to_broadcast = if safe_to_vote(&signed.payload, &self.state) {
            let view = signed.payload.block.header.view;
            let block_hash = signed.payload.block.hash();

            // Persist the vote-view before any wire action: safety rests
            // on a restarted replica never voting twice at the same view.
            self.state.last_voted_view = view;
            actions.push(Action::Persist(StateUpdate::VotedInView { view }));

            // Adopt the proposal's justify as `high_qc` if strictly
            // fresher. Gated on `safe_to_vote`: if we rejected the
            // proposal we don't trust its justify either. The NewView
            // path adopts independently when we have no proposal.
            if should_update_high_qc(&signed.payload.justify, &self.state) {
                let qc = signed.payload.justify.clone();
                // The dispatch verifier ran `verify_qc_if_requested` on
                // `qc` against the validator set at `qc.view` before
                // building the `Verified` envelope, so unchecked is sound.
                self.state.high_qc = Some(VerifiedQc::unchecked(qc.clone()));
                actions.push(Action::Persist(StateUpdate::HighQc(qc)));
            }

            Some(Vote { view, block_hash })
        } else {
            None
        };

        // Two-chain lock promotion. Walk `b* → b'' (parent) → b'
        // (grandparent, present only if we saw its proposal)`. If `b'`
        // exists at a strictly greater height than our lock, promote and
        // emit `Persist(Locked)`.
        //
        // Runs unconditionally (independent of `safe_to_vote`), per
        // Algorithm 4's `update(bnew)`; the safety proof covers
        // unconditional lock updates, and refusing would only wedge us on
        // a staler lock. Comparison is by height, not view: view would let
        // a Byzantine proposer wedge us with a short chain at a huge view.
        //
        // Pushed before the deferred `Broadcast(Vote)` so the lock is
        // flushed to disk before the vote hits the wire.
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
            // A missing lock is treated as height 0 (genesis): promoting
            // to a positive-height `b'` proceeds, locking on genesis is a
            // no-op.
            let current_height = self.state.locked.map(|l| l.height).unwrap_or(Height::ZERO);
            if candidate.height > current_height {
                self.state.locked = Some(candidate);
                actions.push(Action::Persist(StateUpdate::Locked(candidate)));
            }
        }

        // Deferred vote broadcast: sent to every replica, not just the
        // next-view leader, so QC formation survives a crashed leader.
        // Under deterministic round-robin a single crash would otherwise
        // permanently kill every fourth view's vote-target, so no QC
        // forms there and the 3-chain commit rule starves forever.
        if let Some(vote) = vote_to_broadcast {
            actions.push(Action::Broadcast(ConsensusMsg::Vote(vote)));
        }

        // Three-chain commit. Feeding the justify (a QC over `b''`) to
        // `three_chain_commit` commits the great-grandparent `b` when it
        // fires. The predicate strictly requires consecutive views
        // (`b1.view+1 == b2.view`, `b2.view+1 == b3.view`) — the
        // direct-parent chain; relaxing it breaks safety, not just
        // liveness.
        //
        // On commit, prune every `pending_blocks` entry at or below the
        // committed height. Nothing walks past a decided block (extension
        // walks stop at the lock, which sits above the commit; chain
        // walks reach back at most three blocks), so retaining them would
        // leak memory unboundedly.
        if let Some(committed) = three_chain_commit(&signed.payload.justify, &self.state) {
            let commit_height = committed.header.height;
            actions.push(Action::Commit(committed));
            self.state
                .pending_blocks
                .retain(|_, b| b.header.height > commit_height);
        }

        actions
    }

    /// Handle an inbound [`Vote`]. Every replica aggregates, not just the
    /// leader of `vote.view + 1`, so QC formation survives a crashed
    /// next-view leader.
    ///
    /// When a partial signature takes a bucket across quorum for the
    /// first time:
    /// 1. Adopt the freshly-formed QC as `high_qc` (emitting
    ///    `Persist(HighQc)`) if it's fresher.
    /// 2. If this replica is the leader of `vote.view + 1`, broadcast a
    ///    new [`Proposal`] carrying the QC as its justify. Non-leaders
    ///    keep the QC locally and let the next leader propose.
    ///
    /// Mirrors Algorithm 4's `onReceiveVote`, widened to every-replica
    /// aggregation so a permanently-down validator under round-robin
    /// doesn't starve every fourth view's QC.
    pub(super) fn on_vote_received(&mut self, variant: VoteVariant) -> Vec<Action> {
        // `voter_id` is the stable `ValidatorId` ingress resolved via
        // `ValidatorKeyHistory::validator_for` and stamped on the
        // envelope. `bls_partial` is `Some` iff the variant is `Bls`; the
        // type makes "BLS chain + missing partial" unrepresentable.
        let (signed, voter_id, bls_partial): (Signed<Vote>, _, Option<BlsPartialSig>) =
            match variant {
                VoteVariant::Ed25519(verified) => {
                    let (signed, voter_id) = verified.into_parts();
                    (signed, voter_id, None)
                }
                VoteVariant::Bls { signed, partial } => {
                    let (signed, voter_id) = signed.into_parts();
                    (signed, voter_id, Some(partial))
                }
            };
        let vote = &signed.payload;
        let next_view = vote.view + 1;

        // The voter must be a known validator at `vote.view`, else there
        // is no `SignerBitmap` index. Defence-in-depth against replay or
        // test-wiring bugs; ingress normally filters these. The lookup is
        // against the historical set so cross-reconfig votes match the
        // right committee.
        let vs_at_vote = self.state.validator_history.set_at(vote.view);
        // Use the stamped `voter_id`, not `signed.signer`: after a key
        // rotation the wire pubkey no longer equals the stable id, but the
        // bitmap is indexed by stable id.
        let Some(voter_idx) = vs_at_vote.for_view(vote.view).index_of(&voter_id) else {
            return Vec::new();
        };

        // Equivocation detection: a stable voter signs at most one block
        // per view. A second vote at `vote.view` for a different
        // `block_hash` emits `Action::EquivocationEvidence` and drops the
        // partial; folding it into a second bucket would help a Byzantine
        // voter form QCs on conflicting blocks. A duplicate (same
        // `block_hash`) falls through to the idempotent re-fold below.
        match self.vote_dedupe.entry((vote.view, voter_id)) {
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(vote.block_hash);
            }
            std::collections::hash_map::Entry::Occupied(e) if *e.get() == vote.block_hash => {
                // Duplicate: idempotent re-fold below.
            }
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

        // Accumulate into the bucket for this `(view, block_hash)`.
        // `add_signature` / `add_bls_partial` are idempotent on set bits.
        // The bucket is sized to the set authoritative at `vote.view` so
        // the bitmap and quorum threshold match later QC verification.
        let key = (vote.view, vote.block_hash);
        let vs_at_vote_set = vs_at_vote.for_view(vote.view);
        let validator_set_len = vs_at_vote_set.len();
        // Evict only when inserting a genuinely new `(view, block_hash)`
        // tuple — the shape a Byzantine flood of distinct hashes takes.
        if !self.vote_bucket.contains_key(&key) {
            self.evict_vote_buckets_to_fit_one();
        }
        let qc = self
            .vote_bucket
            .entry(key)
            .or_insert_with(|| match bls_partial {
                None => QuorumCertificate::new(vote.view, vote.block_hash, validator_set_len),
                Some(_) => {
                    QuorumCertificate::new_bls(vote.view, vote.block_hash, validator_set_len)
                }
            });
        let had_quorum = qc.has_quorum(vs_at_vote_set);
        match bls_partial {
            None => qc.add_signature(voter_idx, signed.sig),
            Some(partial) => qc.add_bls_partial(voter_idx, partial),
        }
        let has_quorum_now = qc.has_quorum(vs_at_vote_set);

        // Fire only on the sub-quorum to quorum transition. Late votes
        // after the QC formed are absorbed silently.
        if had_quorum || !has_quorum_now {
            return Vec::new();
        }

        let formed = qc.clone();
        let mut actions = Vec::new();

        // Adopt as `high_qc` if strictly fresher (Algorithm 4's
        // `updateQCHigh`).
        if should_update_high_qc(&formed, &self.state) {
            // Assembled locally from ingress-verified partials (each
            // checked against the signer's per-view pubkey before reaching
            // the core), so the aggregate is valid by construction and
            // unchecked is sound.
            self.state.high_qc = Some(VerifiedQc::unchecked(formed.clone()));
            actions.push(Action::Persist(StateUpdate::HighQc(formed.clone())));
        }

        // Propose the next block if we lead `next_view` and hold the
        // parent. Missing the parent (e.g. leader restart) safely skips
        // the broadcast; the pacemaker handles the stall via timeout. The
        // helper's per-view double-propose guard lets a later
        // `PacemakerAdvance` on `next_view` re-attempt exactly once.
        actions.extend(self.try_propose_as_leader(next_view));

        actions
    }

    /// Handle an inbound [`NewView`] advertising a sender's highest QC.
    /// If it beats our `high_qc`, adopt and emit `Persist(HighQc)`;
    /// otherwise ignore.
    ///
    /// Unlike the proposal path, adoption here is not gated on
    /// `safe_to_vote`: the QC carries its own quorum proof, and
    /// `should_update_high_qc`'s strict view comparison prevents
    /// stalest-writes-win.
    ///
    /// If the adopted QC's `block_hash` is absent from `pending_blocks`,
    /// seed a `RequestBlock`. Otherwise a replica whose mesh missed the
    /// originating proposal would lift its view via NewView traffic but
    /// never see the block, parking `last_committed_height` while the
    /// cluster advances. The probe shares the per-parent
    /// `block_sync_inflight` tracker, so backoff/rotation/budget apply.
    pub(super) fn on_new_view_received(&mut self, signed: Signed<NewView>) -> Vec<Action> {
        let qc = signed.payload.high_qc;
        if !should_update_high_qc(&qc, &self.state) {
            return Vec::new();
        }
        let block_hash = qc.block_hash;
        let sender = signed.signer;
        // The dispatch verifier ran `verify_qc_if_requested` on `qc`
        // against the validator set at `qc.view` before building the
        // `Verified` envelope, so unchecked is sound.
        self.state.high_qc = Some(VerifiedQc::unchecked(qc.clone()));
        let mut actions = vec![Action::Persist(StateUpdate::HighQc(qc))];
        if !self.state.pending_blocks.contains_key(&block_hash) {
            // `expected_height` is informational; the QC has no height
            // field and we lack the block, so emit `0` (same convention
            // as genesis-rooted orphans on the proposal path).
            actions.extend(self.try_emit_block_sync_retry(
                block_hash,
                sender,
                Height::ZERO,
                BlockSyncReason::UnknownHighQcOnNewView,
            ));
        }
        actions
    }

    /// Handle a [`crate::hotstuff::step::Event::PacemakerAdvance`] from
    /// the driver. In order:
    ///
    /// 1. Write the new view to `state.current_view`. This is the only
    ///    path that advances the view, keeping the pacemaker
    ///    authoritative over liveness.
    /// 2. Re-dispatch any `parked_proposals` whose parent has arrived
    ///    through `on_proposal_received` (which re-parks nested misses).
    /// 3. For still-parked proposals, re-emit `RequestBlock` to retry the
    ///    fetch. The peer follows [`HotStuffCore::block_sync_inflight`]'s
    ///    rotation, throttled by per-parent backoff and capped by
    ///    [`CacheLimits::block_sync_max_attempts`]; on exhaustion the
    ///    dependent parked proposals are dropped and
    ///    [`CacheEvictionCounters::block_sync_dropped`] ticks.
    /// 4. If `high_qc` is set, broadcast `NewView { high_qc }`. Before any
    ///    proposal lands `high_qc` is `None` and the broadcast is skipped
    ///    ([`NewView`] has no optional QC, and a zero QC would mislead).
    ///
    /// Emission order: un-park retry actions, then `RequestBlock` retries
    /// for still-parked proposals, then the `Broadcast(NewView)` last.
    pub(super) fn on_pacemaker_advance(&mut self, v: View) -> Vec<Action> {
        self.state.current_view = v;

        // Refresh `state.validator_set` to the committee at the new view,
        // so view-less downstream readers (e.g. `pick_block_sync_peer`)
        // see the post-boundary set after a reconfig.
        let active_at = self.state.validator_history.set_at(v);
        let active = active_at.for_view(v);
        if *active != self.state.validator_set {
            self.state.validator_set = active.clone();
        }

        // Drop vote buckets below the new view: a QC formed at
        // `view < v` can never beat what we'd adopt next, so retaining
        // them only lets a Byzantine peer pin memory with low-view votes
        // for distinct block_hash values.
        self.evict_vote_buckets_below(v);

        let mut actions = Vec::new();

        // Un-park retries. Collect child hashes whose parent has arrived,
        // then remove-and-re-dispatch one at a time; the two-step avoids
        // borrowing `parked_proposals` while `on_proposal_received`
        // mutates `self`.
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
                // Parent has arrived, so its in-flight tracker is stale:
                // clear it before re-dispatch so a re-parked grandchild
                // starts with a fresh attempt counter, not the resolved
                // parent's exhausted budget.
                let parent_hash = signed.payload.block.header.parent_hash;
                self.block_sync_inflight.remove(&parent_hash);
                let retry_actions = self.on_proposal_received(signed);
                actions.extend(retry_actions);
            }
        }

        // Block-sync retry. Group still-parked proposals by parent_hash so
        // one in-flight tracker drives one retry (or drop) per missing
        // parent regardless of child count. The `BTreeSet` makes iteration
        // sorted-by-parent, keeping replay/property tests deterministic.
        //
        // Also retry `high_qc.block_hash` when it's absent from
        // `pending_blocks`: the NewView-driven seed has no parked children,
        // so the walk alone wouldn't reach it. Folding it in gives it the
        // standard backoff/rotation/budget and lets the exhaustion path
        // tear down its `block_sync_inflight` entry.
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

        // Leader recovery: if we lead `v` but never proposed at this view
        // (typically the high_qc parent was missing when we became
        // leader), re-attempt now. Block-sync relies on this — it inserts
        // the arrived block into `pending_blocks` and feeds
        // `PacemakerAdvance(current_view)` back, expecting the leader's
        // pending proposal to fire rather than wait out the timeout.
        actions.extend(self.try_propose_as_leader(v));

        actions
    }
}
