//! Interpreter for safety-core / pacemaker / dispatch actions.
//!
//! Owns the persist-before-send discipline that translates HotStuff
//! safety-core actions into wire sends, durable writes, and local
//! self-feeds. Also routes inbound dispatch items to the right handler
//! and steps the pacemaker / safety core with structured tracing at
//! the event boundary.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::consensus::crashpoint::crashpoint;
use crate::consensus::dispatch::{self, Dispatch, Outbound};
use crate::consensus::hotstuff::ConsensusMsg;
use crate::consensus::hotstuff::step::{Action as SafetyAction, Event as SafetyEvent, StateUpdate};
use crate::consensus::pacemaker::Action as PacemakerAction;
use crate::consensus::pacemaker::Event as PacemakerEvent;
use crate::consensus::view_timer::ViewTimer;
use crate::consensus::{Height, View};
use crate::crypto::signed::Signer;
use crate::p2p::NodeId;
use crate::p2p::limits::{Decision, MessageKind};
use crate::p2p::overlay::Broadcaster;
use crate::p2p::tls::node_id_to_base58;

use super::{
    ConsensusNode, TRACE_TARGET, load_block_from_storage, msg_kind, pacemaker_event_kind,
    send_outbound, update_kind,
};

/// Snapshot of the tracing fields we want to log around a safety-core
/// step. Captured *before* the step consumes the event so we still
/// have access to the signer / view / height after the event is moved.
enum SafetyLogCtx {
    Proposal {
        proposer: NodeId,
        view: View,
        height: Height,
    },
    Vote {
        voter: NodeId,
        view: View,
    },
    NewView {
        sender: NodeId,
        high_qc_view: View,
    },
}

impl ConsensusNode {
    // ── Rate limiting (issue #134) ──────────────────────────────────────────

    /// Classify `payload` and consult the rate limiter (if any).
    /// Returns `true` if the frame should be dispatched, `false` if
    /// the limiter dropped it. On a Disconnect decision, fires a
    /// best-effort [`crate::p2p::PeerCommand::Disconnect`] for `from`.
    pub(super) async fn admit_inbound(&self, from: NodeId, payload: &[u8]) -> bool {
        let Some(limiter) = self.rate_limiter.as_ref() else {
            return true;
        };
        // Empty frames will fall through to `dispatch::ingress` which
        // returns IngressError::Decode — let the existing path handle
        // that consistently rather than silently dropping here.
        let Some(&first) = payload.first() else {
            return true;
        };
        let Some(kind) = MessageKind::from_wire_tag(first) else {
            // Unknown tag: pass through so the postcard decode error
            // surfaces in the existing log path. Treating it as a
            // rate-limited drop would mask malformed-frame bugs.
            return true;
        };
        match limiter.admit(from, kind, payload.len()) {
            Decision::Allow => true,
            Decision::Drop => {
                tracing::warn!(
                    target: TRACE_TARGET,
                    peer = %node_id_to_base58(&from),
                    msg_type = kind.label(),
                    bytes = payload.len(),
                    "rate_limit_drop",
                );
                false
            }
            Decision::Disconnect => {
                tracing::warn!(
                    target: TRACE_TARGET,
                    peer = %node_id_to_base58(&from),
                    msg_type = kind.label(),
                    "rate_limit_disconnect",
                );
                if let Some(cmd_tx) = self.peer_cmd_tx.as_ref() {
                    // Fire-and-forget: if the channel is full or
                    // closed (manager shut down), the limiter has
                    // already recorded the disconnect-decision.
                    let _ = cmd_tx.try_send(crate::p2p::PeerCommand::Disconnect { node_id: from });
                }
                // Don't `forget_peer` here: the peer state's
                // `disconnect_dispatched` latch silences any frames
                // already queued from this peer before the manager
                // tears the connection down. The `PeerDisconnected`
                // arm below clears the state when the connection
                // actually goes away, so a future reconnect starts
                // fresh — matching the "no cross-reconnect
                // reputation" non-goal in #134.
                false
            }
        }
    }

    // ── Internal action dispatchers ──────────────────────────────────────────

    pub(super) async fn apply_dispatch(
        &mut self,
        d: Dispatch,
        broadcaster: &dyn Broadcaster,
        view_timer: &mut ViewTimer,
        signer: &Arc<dyn Signer>,
    ) -> anyhow::Result<()> {
        match d {
            Dispatch::Safety(ev) => {
                // Joiner-side lag detection (#229): peek at the
                // proposal's height before consuming the event, so
                // the snapshot-fetch state machine can decide
                // whether to fast-path the joiner past block-sync.
                let mut multi_block_gap_proposer: Option<(NodeId, crate::consensus::Height)> = None;
                if let SafetyEvent::ProposalReceived(signed) = &ev {
                    let signed = signed.inner();
                    let proposer = signed.signer;
                    let proposal_height = signed.payload.block.header.height;
                    let actions = self.snapshot_sync.observe_proposal(
                        self.last_committed_height.load(Ordering::Relaxed),
                        proposal_height,
                        proposer,
                        &self.validator_set,
                    );
                    self.apply_snapshot_sync_actions(actions, broadcaster, view_timer, signer)
                        .await?;
                    // Bulk-range gap detection (#515): if the
                    // incoming proposal sits well above our commit
                    // frontier, the safety core's single-block
                    // RequestBlock is going to walk the chain
                    // backwards one parent at a time. Stash the
                    // proposer and proposal_height so we can fire a
                    // BlockRangeRequest in addition to the
                    // single-block path — only when the safety
                    // core's response actually emits a RequestBlock
                    // (i.e. the parent is missing).
                    multi_block_gap_proposer = Some((proposer, proposal_height));
                }
                let actions = self.step_safety(ev);
                let safety_emitted_request_block = actions
                    .iter()
                    .any(|a| matches!(a, SafetyAction::RequestBlock { .. }));
                self.apply_safety_actions(actions, broadcaster, view_timer, signer)
                    .await?;
                if safety_emitted_request_block
                    && let Some((proposer, proposal_height)) = multi_block_gap_proposer
                {
                    self.maybe_emit_block_range_request(
                        proposer,
                        proposal_height,
                        broadcaster,
                        signer,
                    )
                    .await?;
                }
            }

            Dispatch::Pacemaker(ev) => {
                let pm_actions = self.step_pacemaker(ev);
                self.apply_pacemaker_actions(pm_actions, broadcaster, view_timer, signer)
                    .await?;
            }

            Dispatch::ServeBlock { hash, to } => {
                // Per-peer credit window (#498). Acquires one
                // outstanding-serve credit; if `to` is already at
                // [`block_sync::BLOCK_SYNC_OUTSTANDING_PER_PEER`],
                // drop the request silently (with counter increment)
                // rather than queueing it. The synchronous serving
                // path that ships today never reaches the cap (one
                // serve at a time), but a future async responder
                // would; the gate is here so a refactor cannot leak
                // unbounded concurrent serves into the storage layer.
                let _credit = match self.block_sync_credit.try_acquire(to) {
                    Some(guard) => guard,
                    None => {
                        tracing::warn!(
                            target: TRACE_TARGET,
                            from = %node_id_to_base58(&to),
                            hash = ?hash,
                            "block_sync_serve_dropped_at_credit_window",
                        );
                        return Ok(());
                    }
                };
                // Look in the in-memory `pending_blocks` cache first;
                // fall back to durable storage for blocks that were
                // committed before this replica restarted (where the
                // cache is rebuilt empty save for genesis) or in any
                // future world where pending_blocks gets pruned.
                // Issue #178: without the storage fallback, a restarted
                // node could not serve any pre-restart block, leaving
                // its peers' block-sync stuck.
                let mut found_in_pending = false;
                let mut found_in_storage = false;
                let block = self
                    .core
                    .state()
                    .pending_blocks
                    .get(&hash)
                    .cloned()
                    .inspect(|_| {
                        found_in_pending = true;
                    })
                    .or_else(|| {
                        load_block_from_storage(self.storage.as_ref(), &hash)
                            .inspect(|got| {
                                found_in_storage = got.is_some();
                            })
                            .unwrap_or_else(|e| {
                                tracing::error!(
                                    target: TRACE_TARGET,
                                    hash = ?hash,
                                    error = %e,
                                    "block_storage_lookup_failed",
                                );
                                None
                            })
                    });
                tracing::info!(
                    target: TRACE_TARGET,
                    from = %node_id_to_base58(&to),
                    hash = ?hash,
                    found_in_pending,
                    found_in_storage,
                    found = block.is_some(),
                    "block_sync_request_received",
                );
                if block.is_none() {
                    tracing::warn!(
                        target: TRACE_TARGET,
                        from = %node_id_to_base58(&to),
                        hash = ?hash,
                        pending_blocks_size = self.core.state().pending_blocks.len(),
                        "block_sync_request_unfindable",
                    );
                }
                let out = dispatch::egress_block_response(
                    hash,
                    block,
                    to,
                    signer.as_ref(),
                    &self.chain_id,
                )?;
                send_outbound(broadcaster, out).await;
            }

            // Block arrived in response to an earlier RequestBlock;
            // insert it and re-drive parked proposals via
            // PacemakerAdvance. Drop the response if it does not match
            // the hash we asked for (or if we never asked for that
            // hash) — without this gate a Byzantine responder could
            // pollute `pending_blocks` with arbitrary blocks (#434,
            // audit finding 10-2).
            Dispatch::ReceiveBlock {
                requested_hash,
                block: Some(block),
                from,
            } => {
                let block_hash = block.hash();
                let block_view = block.header.view;
                let block_height = block.header.height;
                if block_hash != requested_hash {
                    tracing::warn!(
                        target: TRACE_TARGET,
                        from = %node_id_to_base58(&from),
                        requested_hash = ?requested_hash,
                        received_hash = ?block_hash,
                        view = block_view.0,
                        height = block_height.0,
                        "block_sync_response_hash_mismatch",
                    );
                    return Ok(());
                }
                if !self.core.has_inflight_block_request(&requested_hash) {
                    tracing::warn!(
                        target: TRACE_TARGET,
                        from = %node_id_to_base58(&from),
                        requested_hash = ?requested_hash,
                        view = block_view.0,
                        height = block_height.0,
                        "block_sync_response_unrequested",
                    );
                    return Ok(());
                }
                tracing::info!(
                    target: TRACE_TARGET,
                    from = %node_id_to_base58(&from),
                    hash = ?block_hash,
                    view = block_view.0,
                    height = block_height.0,
                    "block_sync_response_received",
                );
                self.core.insert_pending_block(block);
                let current = self.pacemaker.current_view();
                let actions = self.step_safety(SafetyEvent::PacemakerAdvance(current));
                self.apply_safety_actions(actions, broadcaster, view_timer, signer)
                    .await?;
            }

            Dispatch::ReceiveBlock {
                requested_hash,
                block: None,
                from,
            } => {
                tracing::warn!(
                    target: TRACE_TARGET,
                    from = %node_id_to_base58(&from),
                    requested_hash = ?requested_hash,
                    "block_sync_response_not_found",
                );
            }

            Dispatch::TimeoutVote {
                signed,
                high_qc_trusted,
            } => {
                self.on_timeout_vote(signed, high_qc_trusted, broadcaster, view_timer, signer)
                    .await?;
            }

            Dispatch::ServeSnapshotManifest { height, to } => {
                self.serve_snapshot_manifest(height, to, broadcaster).await;
            }

            Dispatch::ServeSnapshotChunk {
                height,
                chunk_idx,
                to,
            } => {
                self.serve_snapshot_chunk(height, chunk_idx, to, broadcaster)
                    .await;
            }

            Dispatch::ReceiveSnapshotManifest { manifest, from } => {
                if self.snapshot_sync.is_manifest_pending_from(&from) {
                    tracing::debug!(
                        target: TRACE_TARGET,
                        from = %node_id_to_base58(&from),
                        has_manifest = manifest.is_some(),
                        height = manifest.as_ref().map(|m| m.height.0),
                        "snapshot_manifest_response_received",
                    );
                } else {
                    // Manifest arrived without an outstanding request to
                    // this peer (no active joiner-mode session, response
                    // landed after we already aborted, or peer wasn't the
                    // one we asked). The state machine drops it, but
                    // surfacing it at warn level keeps it from being a
                    // silent footgun in production.
                    tracing::warn!(
                        target: TRACE_TARGET,
                        from = %node_id_to_base58(&from),
                        has_manifest = manifest.is_some(),
                        height = manifest.as_ref().map(|m| m.height.0),
                        "snapshot_manifest_response_unexpected",
                    );
                }
                let actions =
                    self.snapshot_sync
                        .on_manifest_response(from, manifest, &self.validator_set);
                self.apply_snapshot_sync_actions(actions, broadcaster, view_timer, signer)
                    .await?;
            }

            Dispatch::ReceiveSnapshotChunk {
                height,
                chunk_idx,
                payload,
                from,
            } => {
                tracing::debug!(
                    target: TRACE_TARGET,
                    from = %node_id_to_base58(&from),
                    height = height.0,
                    chunk_idx,
                    has_payload = payload.is_some(),
                    payload_len = payload.as_ref().map(|p| p.len()),
                    "snapshot_chunk_response_received",
                );
                let actions = self
                    .snapshot_sync
                    .on_chunk_response(from, height.0, chunk_idx, payload);
                self.apply_snapshot_sync_actions(actions, broadcaster, view_timer, signer)
                    .await?;
            }

            // Bulk-range serve (#514). Same per-peer credit window
            // (#498) as the single-block ServeBlock arm — a flood of
            // range requests from one peer is bounded by the same
            // outstanding-serve cap.
            Dispatch::ServeBlockRange {
                from_height,
                to_height,
                to,
            } => {
                let _credit = match self.block_sync_credit.try_acquire(to) {
                    Some(guard) => guard,
                    None => {
                        tracing::warn!(
                            target: TRACE_TARGET,
                            from = %node_id_to_base58(&to),
                            from_height = from_height.0,
                            to_height = to_height.0,
                            "block_sync_range_serve_dropped_at_credit_window",
                        );
                        return Ok(());
                    }
                };
                let blocks = self.collect_block_range(from_height, to_height);
                let block_count = blocks.len();
                tracing::info!(
                    target: TRACE_TARGET,
                    from = %node_id_to_base58(&to),
                    from_height = from_height.0,
                    to_height = to_height.0,
                    block_count,
                    "block_sync_range_request_received",
                );
                let out = dispatch::egress_block_range_response(
                    from_height,
                    to_height,
                    blocks,
                    to,
                    signer.as_ref(),
                    &self.chain_id,
                )?;
                send_outbound(broadcaster, out).await;
            }

            // Bulk-range receive (#514). The per-block insert and the
            // `parked_proposals` re-drive land here. The requester-
            // side state machine that pipelines further range
            // requests is wired by #515 — this PR only does the
            // basic insert so an out-of-order range response cannot
            // pollute the safety state.
            Dispatch::ReceiveBlockRange {
                from_height,
                to_height,
                blocks,
                from,
            } => {
                self.handle_block_range_response(
                    from_height,
                    to_height,
                    blocks,
                    from,
                    broadcaster,
                    view_timer,
                    signer,
                )
                .await?;
            }
        }
        Ok(())
    }

    /// Collect blocks whose `header.height` falls inside
    /// `[from_height, to_height]` (inclusive) for the bulk-range RPC
    /// (#514). Looks in `pending_blocks` first (in-memory fast path
    /// for blocks above the commit frontier) and walks durable
    /// storage from the recorded chain tip backwards for committed
    /// blocks below.
    ///
    /// Returns blocks in ascending-height order. Truncates to
    /// [`crate::consensus::node::BLOCK_RANGE_RESPONSE_MAX_BLOCKS`].
    fn collect_block_range(
        &self,
        from_height: crate::consensus::Height,
        to_height: crate::consensus::Height,
    ) -> Vec<crate::replication::block::Block> {
        if from_height > to_height {
            return Vec::new();
        }
        let cap = crate::consensus::node::BLOCK_RANGE_RESPONSE_MAX_BLOCKS;

        // Pending-blocks fast path: collect uncommitted blocks in the
        // requested span. These dominate the catch-up case where the
        // recovering node is asking about heights at or just above
        // the cluster's current commit frontier.
        let mut out: Vec<crate::replication::block::Block> = self
            .core
            .state()
            .pending_blocks
            .values()
            .filter(|b| b.header.height >= from_height && b.header.height <= to_height)
            .cloned()
            .collect();

        // Storage walk: pick up committed blocks below the pending-
        // blocks frontier. The lookup is gated on `last_committed`
        // being present; on a fresh node the storage walk is a
        // no-op and `out` carries whatever pending_blocks held.
        let last_committed_raw = match self
            .storage
            .get(crate::consensus::node::STORAGE_KEY_LAST_COMMITTED)
        {
            Ok(raw) => raw,
            Err(e) => {
                tracing::error!(
                    target: TRACE_TARGET,
                    error = %e,
                    "block_range_serve_last_committed_lookup_failed",
                );
                None
            }
        };
        if let Some(raw) = last_committed_raw {
            match crate::consensus::node::decode_last_committed(&raw) {
                Ok(lc) => {
                    let storage_blocks = match crate::consensus::node::load_block_range_from_storage(
                        self.storage.as_ref(),
                        lc.last_committed_hash,
                        from_height,
                        to_height,
                        cap,
                    ) {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::error!(
                                target: TRACE_TARGET,
                                error = %e,
                                "block_range_serve_storage_walk_failed",
                            );
                            Vec::new()
                        }
                    };
                    out.extend(storage_blocks);
                }
                Err(e) => {
                    tracing::error!(
                        target: TRACE_TARGET,
                        error = %e,
                        "block_range_serve_last_committed_decode_failed",
                    );
                }
            }
        }

        // Dedup by hash (a committed pending entry may also appear in
        // storage), sort ascending by height, truncate at the cap.
        let mut seen: std::collections::HashSet<crate::replication::block::BlockHash> =
            std::collections::HashSet::new();
        out.retain(|b| seen.insert(b.hash()));
        out.sort_by_key(|b| b.header.height);
        out.truncate(cap);
        out
    }

    /// Bulk-range gap detection (#515): when a proposal arrives
    /// whose parent is not in `pending_blocks` and whose height sits
    /// more than two blocks above the commit frontier, fire a
    /// [`WireMessage::BlockRangeRequest`] to the proposer in addition
    /// to the safety core's single-block `RequestBlock` for the
    /// immediate parent. The single-block path keeps working as a
    /// fallback for the unknown-parent-but-only-one-block-away case
    /// the existing tests cover; the range request collapses
    /// multi-block catch-up into one round trip.
    ///
    /// Dedup: re-emissions for the same `(from_height, to_height)`
    /// pair while a previous request is still in flight are
    /// suppressed. The matching [`Dispatch::ReceiveBlockRange`]
    /// handler clears the inflight entry on arrival.
    async fn maybe_emit_block_range_request(
        &mut self,
        proposer: NodeId,
        proposal_height: crate::consensus::Height,
        broadcaster: &dyn Broadcaster,
        _signer: &Arc<dyn Signer>,
    ) -> anyhow::Result<()> {
        // Asking ourselves for blocks is a no-op the safety core
        // already drops on the RequestBlock side; mirror that here.
        if proposer == self.self_id {
            return Ok(());
        }
        let last_committed = self.last_committed_height.load(Ordering::Relaxed);
        let parent_height = proposal_height.0.saturating_sub(1);
        // Only fire when the gap is more than one block — the
        // single-block path covers the trailing case.
        if parent_height <= last_committed.saturating_add(1) {
            return Ok(());
        }
        let from_height = crate::consensus::Height(last_committed.saturating_add(1));
        let cap = crate::consensus::node::BLOCK_RANGE_RESPONSE_MAX_BLOCKS as u64;
        // Cap the upper bound to from_height + cap - 1 so the
        // requested span never exceeds the responder's per-response
        // budget. Larger gaps pipeline naturally as subsequent
        // proposals arrive (each ProposalReceived event re-evaluates
        // the gap from the new commit frontier).
        let to_height = crate::consensus::Height(parent_height.min(from_height.0 + cap - 1));
        let key = (from_height, to_height);
        if self.block_sync_range_inflight.contains_key(&key) {
            tracing::debug!(
                target: TRACE_TARGET,
                from_height = from_height.0,
                to_height = to_height.0,
                proposer = %node_id_to_base58(&proposer),
                "block_sync_range_request_suppressed_already_inflight",
            );
            return Ok(());
        }
        self.block_sync_range_inflight.insert(key, proposer);
        tracing::info!(
            target: TRACE_TARGET,
            from_height = from_height.0,
            to_height = to_height.0,
            proposer = %node_id_to_base58(&proposer),
            "block_sync_range_request_emitted",
        );
        let out = dispatch::egress_block_range_request(from_height, to_height, proposer);
        send_outbound(broadcaster, out).await;
        Ok(())
    }

    /// Apply a bulk-range response: validate each block's height
    /// against the echoed `[from_height, to_height]`, insert the
    /// well-formed blocks into the safety core's `pending_blocks`,
    /// and re-drive the parked-proposals walk via a single
    /// `PacemakerAdvance(current_view)` after all inserts have
    /// landed. The requester-side pipelining state machine (#515)
    /// hooks in on top of this.
    #[allow(clippy::too_many_arguments)]
    async fn handle_block_range_response(
        &mut self,
        from_height: crate::consensus::Height,
        to_height: crate::consensus::Height,
        blocks: Vec<crate::replication::block::Block>,
        from: NodeId,
        broadcaster: &dyn Broadcaster,
        view_timer: &mut ViewTimer,
        signer: &Arc<dyn Signer>,
    ) -> anyhow::Result<()> {
        let block_count = blocks.len();
        tracing::info!(
            target: TRACE_TARGET,
            from = %node_id_to_base58(&from),
            from_height = from_height.0,
            to_height = to_height.0,
            block_count,
            "block_sync_range_response_received",
        );
        // Drop the matching range-inflight entry (#515). Done
        // *before* the inserts so a follow-up proposal arriving
        // mid-iteration can re-emit a fresh range request — the
        // dedup guard in [`Self::maybe_emit_block_range_request`]
        // would otherwise suppress the next emission.
        self.block_sync_range_inflight
            .remove(&(from_height, to_height));
        let mut inserted = 0u64;
        let mut last_height: Option<crate::consensus::Height> = None;
        for block in blocks {
            let h = block.header.height;
            if h < from_height || h > to_height {
                tracing::warn!(
                    target: TRACE_TARGET,
                    from = %node_id_to_base58(&from),
                    from_height = from_height.0,
                    to_height = to_height.0,
                    block_height = h.0,
                    "block_sync_range_block_out_of_range",
                );
                continue;
            }
            if let Some(prev) = last_height
                && h <= prev
            {
                tracing::warn!(
                    target: TRACE_TARGET,
                    from = %node_id_to_base58(&from),
                    prev_height = prev.0,
                    block_height = h.0,
                    "block_sync_range_blocks_not_strictly_ascending",
                );
                continue;
            }
            last_height = Some(h);
            self.core.insert_pending_block(block);
            inserted += 1;
        }
        if inserted > 0 {
            let current = self.pacemaker.current_view();
            let actions = self.step_safety(SafetyEvent::PacemakerAdvance(current));
            self.apply_safety_actions(actions, broadcaster, view_timer, signer)
                .await?;
        }
        Ok(())
    }

    /// Apply a slice of safety-core actions with the persist-before-send
    /// discipline: any `Persist` updates are written atomically to storage
    /// before the next non-`Persist` action is executed.
    ///
    /// # Self-loopback for `Broadcast` / `SendTo`
    ///
    /// Production p2p broadcasts exclude the sender and `SendTo(self)`
    /// is dropped by the p2p manager (see `src/p2p/manager.rs`). Without
    /// help from this layer the proposing leader would never receive its
    /// own `Broadcast(Proposal)` and the next-view leader would never
    /// count the `SendTo(self_id, Vote)` it emits when it votes on the
    /// current leader's proposal. Both losses combine to keep quorum one
    /// signer short of threshold and deadlock the cluster (#118).
    ///
    /// For every `Broadcast(msg)` we both ship the signed frame on the
    /// wire AND feed the same signed envelope through the local
    /// dispatcher, mirroring what a peer would do on receipt. For
    /// `SendTo(target, msg)` where `target == self.self_id` we skip the
    /// wire and only feed locally; for any other target we wire-send
    /// without a local feed. `RequestBlock { peer, .. }` where
    /// `peer == self.self_id` is degenerate (we would be asking
    /// ourselves for a block we just asked about) and is dropped.
    pub(super) async fn apply_safety_actions(
        &mut self,
        actions: Vec<SafetyAction>,
        broadcaster: &dyn Broadcaster,
        view_timer: &mut ViewTimer,
        signer: &Arc<dyn Signer>,
    ) -> anyhow::Result<()> {
        let mut persist_buf: Vec<StateUpdate> = Vec::new();

        for action in actions {
            if let SafetyAction::Persist(u) = &action {
                persist_buf.push(u.clone());
                continue;
            }
            // Non-persist action: flush persists first.
            if !persist_buf.is_empty() {
                let kinds: Vec<_> = persist_buf.iter().map(update_kind).collect();
                self.persist_updates(&persist_buf)?;
                persist_buf.clear();
                // Crashpoints fire AFTER the persist batch durably
                // landed but BEFORE the dependent send leaves. Audit
                // findings #1 / #11 / #406 hinge on this exact gap:
                // the buffer kinds tell the harness which durability
                // boundary the integration layer just crossed.
                for kind in kinds {
                    match kind {
                        "VotedInView" => crashpoint!("after_persist_voted_view"),
                        "Locked" => crashpoint!("after_persist_locked"),
                        "HighQc" => crashpoint!("after_persist_high_qc"),
                        "ProposedInView" => {
                            crashpoint!("after_persist_proposed_in_view")
                        }
                        _ => {}
                    }
                }
            }

            match action {
                SafetyAction::Persist(_) => unreachable!(),

                SafetyAction::Broadcast(mut msg) => {
                    tracing::debug!(
                        target: TRACE_TARGET,
                        msg = msg_kind(&msg),
                        "outbound_broadcast",
                    );
                    // #325 PR A/C: stamp the validator-history
                    // commitment into outgoing proposals before the
                    // envelope is signed. The block builder leaves the
                    // field at [0; 32]; here we replace it with the
                    // v1 hash over the **post-block** histories: fork
                    // our current `(validator_history,
                    // validator_key_history, bls_key_history?)`, apply
                    // this block's reconfig/rotation commands to the
                    // fork, and hash the result. Post-block hashing
                    // (PR C) makes the commitment a deterministic
                    // function of the chain content rather than the
                    // producer's commit position, so a follower at a
                    // less-advanced commit position can still verify
                    // the leader's stamp by running the same fork on
                    // its own histories — see
                    // [`crate::consensus::history_commitment::compute_post_block_commitment`]
                    // and the proposal-receive verifier in `dispatch`.
                    if let ConsensusMsg::Proposal(ref mut p) = msg {
                        p.block.header.validator_history_commitment =
                            crate::consensus::history_commitment::compute_post_block_commitment(
                                &p.block,
                                &self.validator_history,
                                &self.validator_key_history,
                                self.bls_key_history.as_ref(),
                                &self.chain_id,
                                self.signature_scheme,
                                self.min_v_eff_delay,
                            );
                    }
                    let bls_signer = self.bls_signer.as_deref();
                    let (payload, loopback) = dispatch::egress_consensus_msg_with_loopback(
                        &msg,
                        signer.as_ref(),
                        bls_signer,
                        &self.validator_key_history,
                        &self.chain_id,
                    )?;
                    let msg_is_proposal = matches!(msg, ConsensusMsg::Proposal(_));
                    let msg_is_vote = matches!(msg, ConsensusMsg::Vote(_));
                    send_outbound(broadcaster, Outbound::Broadcast(payload)).await;
                    // After a Proposal hits the wire the leader has a
                    // de-facto commitment to view N — but
                    // `proposed_in_view` is in-memory only (audit
                    // finding 4-3 / issue #407). After a Vote hits the
                    // wire the replica has a de-facto commitment to
                    // last_voted_view = view, which `persist_voted_view`
                    // either has or has not flushed depending on
                    // discipline (audit finding 4-1 / issue #405).
                    if msg_is_proposal {
                        crashpoint!("after_send_outbound_for_proposal");
                    }
                    if msg_is_vote {
                        crashpoint!("after_broadcast_vote");
                    }
                    self.deliver_loopback(loopback, broadcaster, view_timer, signer)
                        .await?;
                }

                SafetyAction::SendTo(target, msg) => {
                    let bls_signer = self.bls_signer.as_deref();
                    let (payload, loopback) = dispatch::egress_consensus_msg_with_loopback(
                        &msg,
                        signer.as_ref(),
                        bls_signer,
                        &self.validator_key_history,
                        &self.chain_id,
                    )?;
                    let msg_is_vote = matches!(msg, ConsensusMsg::Vote(_));
                    if target == self.self_id {
                        tracing::debug!(
                            target: TRACE_TARGET,
                            msg = msg_kind(&msg),
                            "outbound_loopback",
                        );
                        // Self-addressed: deliver locally; do not put bytes
                        // on the wire (the p2p layer would drop them).
                        self.deliver_loopback(loopback, broadcaster, view_timer, signer)
                            .await?;
                    } else {
                        tracing::debug!(
                            target: TRACE_TARGET,
                            dest = %node_id_to_base58(&target),
                            msg = msg_kind(&msg),
                            "outbound_send_to",
                        );
                        send_outbound(
                            broadcaster,
                            Outbound::SendTo {
                                to: target,
                                payload,
                            },
                        )
                        .await;
                        // Vote frames are unicast `SendTo(next_leader)`
                        // by default. After the bytes are on the wire
                        // the replica has committed to that vote — so a
                        // crash here exercises audit finding #1 (the
                        // peer accepts the vote, the local replica
                        // restarts, and if `last_voted_view` was not
                        // already durable the restart equivocates).
                        if msg_is_vote {
                            crashpoint!("after_broadcast_vote");
                        }
                    }
                }

                SafetyAction::RequestBlock {
                    hash,
                    peer,
                    expected_height,
                    reason,
                } => {
                    if peer == self.self_id {
                        // Asking ourselves for a block is a no-op: if we
                        // don't already have it, the p2p layer can't
                        // fetch it from us. Log at debug and move on.
                        tracing::debug!(
                            target: TRACE_TARGET,
                            hash = ?hash,
                            requesting_height = expected_height.0,
                            triggered_by = reason.as_str(),
                            "block_sync_request_self_dropped",
                        );
                    } else {
                        tracing::info!(
                            target: TRACE_TARGET,
                            dest = %node_id_to_base58(&peer),
                            hash = ?hash,
                            requesting_height = expected_height.0,
                            triggered_by = reason.as_str(),
                            our_view = self.pacemaker.current_view().0,
                            our_high_qc_view = ?self.core.state().high_qc.as_ref().map(|q| q.view().0),
                            "block_sync_request_emitted",
                        );
                        let out = dispatch::egress_block_request(hash, peer);
                        send_outbound(broadcaster, out).await;
                    }
                }

                SafetyAction::Commit(block) => {
                    self.apply_commit(block);
                }

                SafetyAction::EquivocationEvidence {
                    voter,
                    view,
                    block_a,
                    block_b,
                } => {
                    // Audit finding 3-1 (#409): the safety core just
                    // observed a stable validator voting for two
                    // distinct block_hash values at the same view.
                    // Surface as a WARN with structured fields so
                    // operators can grep for evidence and a future
                    // slashing pipeline can attach without further
                    // safety-core changes.
                    self.equivocations_detected.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        target: TRACE_TARGET,
                        voter = %node_id_to_base58(voter.as_node_id()),
                        view = view.0,
                        block_a = ?block_a,
                        block_b = ?block_b,
                        "consensus_equivocation_detected",
                    );
                }

                SafetyAction::ProposalEquivocationEvidence {
                    leader,
                    view,
                    block_a,
                    block_b,
                } => {
                    // Audit finding L5-1: the safety core just
                    // observed a stable leader proposing two distinct
                    // block_hash values at the same view. Sibling
                    // handler of `EquivocationEvidence` above —
                    // separate counter and event name so operator
                    // dashboards can attribute proposer-side vs.
                    // voter-side Byzantine activity independently.
                    self.proposal_equivocations_detected
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        target: TRACE_TARGET,
                        leader = %node_id_to_base58(leader.as_node_id()),
                        view = view.0,
                        block_a = ?block_a,
                        block_b = ?block_b,
                        "consensus_proposal_equivocation_detected",
                    );
                }
            }
        }

        // Flush any trailing Persist actions (e.g. a proposal that only
        // emits Persist + SendTo; the SendTo flushes, but a final-only
        // Persist batch needs explicit flush here).
        if !persist_buf.is_empty() {
            let kinds: Vec<_> = persist_buf.iter().map(update_kind).collect();
            self.persist_updates(&persist_buf)?;
            for kind in kinds {
                match kind {
                    "VotedInView" => crashpoint!("after_persist_voted_view"),
                    "Locked" => crashpoint!("after_persist_locked"),
                    "HighQc" => crashpoint!("after_persist_high_qc"),
                    "ProposedInView" => crashpoint!("after_persist_proposed_in_view"),
                    _ => {}
                }
            }
        }

        Ok(())
    }

    /// Feed self-addressed dispatch items back through the same entry
    /// point a peer message would take.
    ///
    /// Boxed so the mutual recursion with [`Self::apply_safety_actions`]
    /// and [`Self::apply_pacemaker_actions`] compiles as an async fn.
    pub(super) async fn deliver_loopback(
        &mut self,
        loopback: Vec<Dispatch>,
        broadcaster: &dyn Broadcaster,
        view_timer: &mut ViewTimer,
        signer: &Arc<dyn Signer>,
    ) -> anyhow::Result<()> {
        for d in loopback {
            Box::pin(self.apply_dispatch(d, broadcaster, view_timer, signer)).await?;
        }
        Ok(())
    }

    /// Apply pacemaker actions: advance the safety core, arm timers, build
    /// proposals when we become leader.
    pub(super) async fn apply_pacemaker_actions(
        &mut self,
        actions: Vec<PacemakerAction>,
        broadcaster: &dyn Broadcaster,
        view_timer: &mut ViewTimer,
        signer: &Arc<dyn Signer>,
    ) -> anyhow::Result<()> {
        for action in actions {
            tracing::debug!(
                target: TRACE_TARGET,
                view = self.pacemaker.current_view().0,
                self_id = %node_id_to_base58(&self.self_id),
                action = ?action,
                "pacemaker_action",
            );
            match action {
                PacemakerAction::AdvanceToView { view: v, cause } => {
                    tracing::debug!(
                        target: TRACE_TARGET,
                        new_view = v.0,
                        cause = cause.as_str(),
                        "view_advanced",
                    );
                    // Feed PacemakerAdvance into the safety core so it updates
                    // current_view and un-parks pending proposals.
                    let safety_actions = self.step_safety(SafetyEvent::PacemakerAdvance(v));
                    self.apply_safety_actions(safety_actions, broadcaster, view_timer, signer)
                        .await?;
                }

                PacemakerAction::BecomeLeader(v) => {
                    let safety_actions = self.core.become_leader(v);
                    self.apply_safety_actions(safety_actions, broadcaster, view_timer, signer)
                        .await?;
                }

                PacemakerAction::ResetTimer(d) => {
                    let view = self.pacemaker.current_view();
                    view_timer.reset(view, d);
                }

                PacemakerAction::SendTimeout(v) => {
                    self.send_timeout(v, broadcaster, view_timer, signer)
                        .await?;
                }
            }
        }
        Ok(())
    }

    /// Step the pacemaker, emitting a structured trace at the event
    /// boundary so operators can correlate inbound causes (timer fires,
    /// QCs, TCs, proposals) with the resulting view-change decisions.
    pub(super) fn step_pacemaker(&mut self, ev: PacemakerEvent) -> Vec<PacemakerAction> {
        tracing::debug!(
            target: TRACE_TARGET,
            view = self.pacemaker.current_view().0,
            self_id = %node_id_to_base58(&self.self_id),
            event = pacemaker_event_kind(&ev),
            "pacemaker_event",
        );
        self.pacemaker.step(ev)
    }

    /// Step the safety core, emitting a structured trace after the step
    /// for `ProposalReceived` / `VoteReceived` / `NewViewReceived` so the
    /// "did it vote?", "did it form a QC?", "was it parked?" information
    /// is visible from the debug logs. The trace lives at the integration
    /// layer specifically to keep the safety core I/O-free.
    pub(super) fn step_safety(&mut self, ev: SafetyEvent) -> Vec<SafetyAction> {
        // Snapshot the fields we want to log *before* moving `ev` into
        // the core — the event is consumed by `core.step` so we can't
        // re-borrow after.
        let log_ctx = match &ev {
            SafetyEvent::ProposalReceived(signed) => Some(SafetyLogCtx::Proposal {
                proposer: signed.inner().signer,
                view: signed.inner().payload.block.header.view,
                height: signed.inner().payload.block.header.height,
            }),
            SafetyEvent::VoteReceived(variant) => {
                let signed = variant.verified().inner();
                Some(SafetyLogCtx::Vote {
                    voter: signed.signer,
                    view: signed.payload.view,
                })
            }
            SafetyEvent::NewViewReceived(signed) => Some(SafetyLogCtx::NewView {
                sender: signed.inner().signer,
                high_qc_view: signed.inner().payload.high_qc.view,
            }),
            SafetyEvent::PacemakerAdvance(_) => None,
        };

        let actions = self.core.step(ev);

        match log_ctx {
            Some(SafetyLogCtx::Proposal {
                proposer,
                view,
                height,
            }) => {
                let voted = actions
                    .iter()
                    .any(|a| matches!(a, SafetyAction::Broadcast(ConsensusMsg::Vote(_))));
                let parked = actions
                    .iter()
                    .any(|a| matches!(a, SafetyAction::RequestBlock { .. }));
                tracing::debug!(
                    target: TRACE_TARGET,
                    proposer = %node_id_to_base58(&proposer),
                    view = view.0,
                    height = height.0,
                    voted,
                    parked,
                    "proposal_received",
                );
                // Surface the missing-parent path at WARN so operators
                // can see block-sync triggered without having to enable
                // DEBUG-level logging on `ambros_p2p::consensus`. The
                // matching `block_sync_request_emitted` event is logged
                // at INFO from `apply_safety_actions` when the request
                // actually leaves the node.
                if parked {
                    tracing::warn!(
                        target: TRACE_TARGET,
                        proposer = %node_id_to_base58(&proposer),
                        view = view.0,
                        height = height.0,
                        request_block_emitted = true,
                        "proposal_rejected_unknown_parent",
                    );
                }
            }
            Some(SafetyLogCtx::Vote { voter, view }) => {
                let formed_qc = actions
                    .iter()
                    .any(|a| matches!(a, SafetyAction::Broadcast(ConsensusMsg::Proposal(_))));
                tracing::debug!(
                    target: TRACE_TARGET,
                    voter = %node_id_to_base58(&voter),
                    view = view.0,
                    formed_qc,
                    "vote_received",
                );
            }
            Some(SafetyLogCtx::NewView {
                sender,
                high_qc_view,
            }) => {
                tracing::debug!(
                    target: TRACE_TARGET,
                    sender = %node_id_to_base58(&sender),
                    high_qc_view = high_qc_view.0,
                    "new_view_received",
                );
            }
            None => {}
        }

        actions
    }

    /// Surface a [`PacemakerEvent::OnRoundSync`] hint to the pacemaker,
    /// then apply the resulting actions. Called from
    /// [`Self::on_timeout_vote`] when a per-view bucket reaches the
    /// honesty threshold (`f + 1` distinct signers — see issue #218
    /// for the wedge this prevents and the Byzantine-bound rationale
    /// for the threshold choice). The `evidence` parameter is the
    /// sealed token minted at the threshold check (audit finding 2-3 /
    /// issue #419), forwarded into the typed `OnRoundSync` payload.
    pub(super) async fn fire_round_sync(
        &mut self,
        view: View,
        evidence: crate::consensus::pacemaker::HonestyThresholdEvidence,
        broadcaster: &dyn Broadcaster,
        view_timer: &mut ViewTimer,
        signer: &Arc<dyn Signer>,
    ) -> anyhow::Result<()> {
        tracing::debug!(
            target: TRACE_TARGET,
            view = view.0,
            current = self.pacemaker.current_view().0,
            "round_sync_fired",
        );
        let pm_actions = self.step_pacemaker(PacemakerEvent::OnRoundSync { view, evidence });
        Box::pin(self.apply_pacemaker_actions(pm_actions, broadcaster, view_timer, signer)).await
    }
}
