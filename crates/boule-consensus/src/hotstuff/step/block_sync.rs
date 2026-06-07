//! Missing-ancestor block-sync: request emission, retry/backoff, peer pick.
use super::*;

impl HotStuffCore {
    /// Whether a `RequestBlock` retry entry is still tracked for `hash`.
    /// The `BlockResponse` handler gates `insert_pending_block` on this to
    /// drop unsolicited or duplicate responses before they reach
    /// `pending_blocks`.
    pub fn has_inflight_block_request(&self, hash: &BlockHash) -> bool {
        self.block_sync_inflight.contains_key(hash)
    }

    /// Whether any `RequestBlock` is in flight for any parent hash. Read
    /// after each safety-core step to (re-)arm or cancel the block-sync
    /// retry timer; when false the timer is cancelled so an idle node
    /// never wakes up just to find nothing to retry.
    pub fn has_any_block_sync_inflight(&self) -> bool {
        !self.block_sync_inflight.is_empty()
    }

    /// Per-parent retry budget for `RequestBlock`; read-only mirror of
    /// [`CacheLimits::block_sync_max_attempts`]. The range-keyed retry
    /// walk reads this so the bulk-range path enforces the same per-entry
    /// budget as the hash-keyed path without duplicating the constant.
    pub fn block_sync_max_attempts(&self) -> u32 {
        self.limits.block_sync_max_attempts
    }

    /// Wall-clock-driven retry tick. Walks every tracked
    /// `block_sync_inflight` entry and emits at most one
    /// `Action::RequestBlock` per parent. The view-elapsed backoff of
    /// `try_emit_block_sync_retry` is bypassed here: cadence is set by the
    /// [`BlockSyncRetryTimer`], so applying both would delay the first
    /// retry past the next pacemaker tick. The per-parent attempt budget
    /// (`block_sync_max_attempts`) and per-peer rotation budget
    /// (`block_sync_per_peer_attempts`) still apply: a parent whose budget
    /// is exhausted has its parked proposals dropped here.
    ///
    /// Returns the actions to feed through `apply_safety_actions`. The
    /// caller (re-)arms the retry timer afterwards iff
    /// [`Self::has_any_block_sync_inflight`] is still true.
    ///
    /// [`BlockSyncRetryTimer`]: crate::block_sync_retry_timer::BlockSyncRetryTimer
    pub fn step_block_sync_retry_tick(&mut self) -> Vec<Action> {
        // Sorted iteration so replay/property tests stay byte-identical
        // regardless of `HashMap` ordering.
        let parents: std::collections::BTreeSet<BlockHash> =
            self.block_sync_inflight.keys().copied().collect();
        let mut actions = Vec::with_capacity(parents.len());
        for parent_hash in parents {
            actions.extend(self.run_block_sync_retry_tick_for_parent(parent_hash));
        }
        actions
    }

    /// Test-only: install a `block_sync_inflight` entry for `hash` as if a
    /// `RequestBlock` had just been emitted to `original_sender` for a
    /// parent at `expected_height`, to exercise the `BlockResponse`
    /// hash-check gates without a full parked-proposal flow.
    #[cfg(any(test, feature = "testing"))]
    pub fn install_block_sync_inflight_for_test(
        &mut self,
        hash: BlockHash,
        original_sender: NodeId,
        expected_height: Height,
    ) {
        self.block_sync_inflight.insert(
            hash,
            BlockSyncInflight {
                original_sender,
                attempts: 1,
                last_asked_view: self.state.current_view,
                expected_height,
            },
        );
    }

    /// Decide whether to emit a `RequestBlock` for `parent_hash` now and
    /// update the in-flight tracker. Returns zero or one `Action`; empty
    /// when suppressed by backoff or when the per-parent attempt budget is
    /// exhausted (caller then drops the parked proposals).
    ///
    /// `original_sender` and `expected_height` are recorded on first
    /// sighting and ignored on later re-deliveries, so peer rotation stays
    /// anchored to the first seen sender.
    pub(super) fn try_emit_block_sync_retry(
        &mut self,
        parent_hash: BlockHash,
        original_sender: NodeId,
        expected_height: Height,
        reason: BlockSyncReason,
    ) -> Vec<Action> {
        // First sighting: install the tracker (attempts = 1 for the one
        // ask) and emit the initial probe to the sender.
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

        // Re-delivery or retry of a tracked parent. Snapshot, decide
        // outside the borrow, then mutate.
        let snapshot = *self.block_sync_inflight.get(&parent_hash).unwrap();
        if snapshot.attempts >= self.limits.block_sync_max_attempts {
            // Budget exhausted: leave the entry; the pacemaker-advance
            // loop drops the parked proposals on its next pass.
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

    /// Retry-timer-driven retry path: like
    /// [`Self::run_block_sync_retry_for_parent`] but without the
    /// view-elapsed backoff gate, since the
    /// [`BlockSyncRetryTimer`](crate::block_sync_retry_timer::BlockSyncRetryTimer)
    /// already enforces a wall-clock schedule. Still drops parked
    /// proposals on attempt-budget exhaustion and rotates peers via
    /// `pick_block_sync_peer`.
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

    /// Pacemaker-driven retry path: emit one `RequestBlock` for
    /// `parent_hash` if the in-flight tracker says it is time, or drop
    /// every parked proposal depending on this parent once the retry
    /// budget is exhausted. Returns the actions to append to the pacemaker
    /// step output.
    pub(super) fn run_block_sync_retry_for_parent(
        &mut self,
        parent_hash: BlockHash,
    ) -> Vec<Action> {
        let snapshot = match self.block_sync_inflight.get(&parent_hash) {
            Some(e) => *e,
            // Every parked proposal should have an in-flight entry; a
            // missing one means the parent landed between iterations of
            // `parked_proposals`. No action.
            None => return Vec::new(),
        };
        if snapshot.attempts >= self.limits.block_sync_max_attempts {
            self.drop_parked_for_parent(parent_hash);
            return Vec::new();
        }
        // Reuse the on-proposal throttle-and-rotate logic; the
        // original_sender lookup comes from the in-flight entry, so the
        // call is idempotent w.r.t. parked_proposals state.
        self.try_emit_block_sync_retry(
            parent_hash,
            snapshot.original_sender,
            snapshot.expected_height,
            BlockSyncReason::StillParkedOnPacemakerAdvance,
        )
    }
}
