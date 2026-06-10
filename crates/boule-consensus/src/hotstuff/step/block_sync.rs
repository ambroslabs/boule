use super::*;

impl HotStuffCore {
    pub fn has_inflight_block_request(&self, hash: &BlockHash) -> bool {
        self.block_sync_inflight.contains_key(hash)
    }

    pub fn has_any_block_sync_inflight(&self) -> bool {
        !self.block_sync_inflight.is_empty()
    }

    pub fn block_sync_max_attempts(&self) -> u32 {
        self.limits.block_sync_max_attempts
    }

    pub fn step_block_sync_retry_tick(&mut self) -> Vec<Action> {
        let parents: std::collections::BTreeSet<BlockHash> =
            self.block_sync_inflight.keys().copied().collect();
        let mut actions = Vec::with_capacity(parents.len());
        for parent_hash in parents {
            actions.extend(self.run_block_sync_retry_tick_for_parent(parent_hash));
        }
        actions
    }

    pub(super) fn try_emit_block_sync_retry(
        &mut self,
        parent_hash: BlockHash,
        original_sender: NodeId,
        expected_height: Height,
        reason: BlockSyncReason,
    ) -> Vec<Action> {
        if !self.block_sync_inflight.contains_key(&parent_hash) {
            self.block_sync_inflight.insert(
                parent_hash,
                BlockSyncInflight {
                    original_sender,
                    attempts: 1,
                    last_asked_view: self.state.current_view,
                    expected_height,
                },
            );
            return vec![Action::RequestBlock {
                hash: parent_hash,
                peer: original_sender,
                expected_height,
                reason,
            }];
        }

        let snapshot = *self.block_sync_inflight.get(&parent_hash).unwrap();
        if snapshot.attempts >= self.limits.block_sync_max_attempts {
            return Vec::new();
        }
        let backoff = block_sync_backoff_views(
            snapshot.attempts,
            self.limits.block_sync_initial_backoff_views,
            self.limits.block_sync_max_backoff_views,
        );
        let elapsed = self
            .state
            .current_view
            .saturating_sub(snapshot.last_asked_view);
        if elapsed.0 < backoff {
            return Vec::new();
        }
        let peer = pick_block_sync_peer(
            snapshot.original_sender,
            snapshot.attempts,
            self.limits.block_sync_per_peer_attempts,
            &self.state.validator_set,
            self.self_id,
        );
        let entry = self.block_sync_inflight.get_mut(&parent_hash).unwrap();
        entry.attempts = entry.attempts.saturating_add(1);
        entry.last_asked_view = self.state.current_view;
        vec![Action::RequestBlock {
            hash: parent_hash,
            peer,
            expected_height: snapshot.expected_height,
            reason,
        }]
    }

    pub(super) fn run_block_sync_retry_tick_for_parent(
        &mut self,
        parent_hash: BlockHash,
    ) -> Vec<Action> {
        let snapshot = match self.block_sync_inflight.get(&parent_hash) {
            Some(e) => *e,
            None => return Vec::new(),
        };
        if snapshot.attempts >= self.limits.block_sync_max_attempts {
            self.drop_parked_for_parent(parent_hash);
            return Vec::new();
        }
        let peer = pick_block_sync_peer(
            snapshot.original_sender,
            snapshot.attempts,
            self.limits.block_sync_per_peer_attempts,
            &self.state.validator_set,
            self.self_id,
        );
        let entry = self.block_sync_inflight.get_mut(&parent_hash).unwrap();
        entry.attempts = entry.attempts.saturating_add(1);
        entry.last_asked_view = self.state.current_view;
        vec![Action::RequestBlock {
            hash: parent_hash,
            peer,
            expected_height: snapshot.expected_height,
            reason: BlockSyncReason::RetryTimerTick,
        }]
    }

    pub(super) fn run_block_sync_retry_for_parent(
        &mut self,
        parent_hash: BlockHash,
    ) -> Vec<Action> {
        let snapshot = match self.block_sync_inflight.get(&parent_hash) {
            Some(e) => *e,

            None => return Vec::new(),
        };
        if snapshot.attempts >= self.limits.block_sync_max_attempts {
            self.drop_parked_for_parent(parent_hash);
            return Vec::new();
        }

        self.try_emit_block_sync_retry(
            parent_hash,
            snapshot.original_sender,
            snapshot.expected_height,
            BlockSyncReason::StillParkedOnPacemakerAdvance,
        )
    }
}
