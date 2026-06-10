use std::sync::Arc;
use std::sync::atomic::Ordering;

use boule_consensus::dispatch::{self, Dispatch, Outbound};
use boule_consensus::hotstuff::ConsensusMsg;
use boule_consensus::hotstuff::step::{Action as SafetyAction, Event as SafetyEvent, StateUpdate};
use boule_consensus::pacemaker::Action as PacemakerAction;
use boule_consensus::pacemaker::Event as PacemakerEvent;
use boule_consensus::rate_limit::MessageKind;
use boule_consensus::view_timer::ViewTimer;
use boule_consensus::{Height, View};
use boule_core::crypto::signed::Signer;
use boule_core::identity::NodeId;
use boule_core::identity::node_id_to_base58;
use boule_core::transport::limits::{Decision, RateLimitKind};
use boule_core::transport::overlay::Broadcaster;

use super::{
    BlockSyncRangeInflight, ConsensusNode, TRACE_TARGET, load_block_from_storage, msg_kind,
    pacemaker_event_kind, send_outbound,
};

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
    pub(super) async fn admit_inbound(&self, from: NodeId, payload: &[u8]) -> bool {
        let Some(limiter) = self.rate_limiter.as_ref() else {
            return true;
        };

        let Some(&first) = payload.first() else {
            return true;
        };
        let Some(kind) = MessageKind::from_wire_tag(first) else {
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
                if let Some(disc) = self.disconnect_via.as_ref() {
                    disc.disconnect(from);
                }

                false
            }
        }
    }

    pub(super) async fn apply_dispatch(
        &mut self,
        d: Dispatch,
        broadcaster: &dyn Broadcaster,
        view_timer: &mut ViewTimer,
        signer: &Arc<dyn Signer>,
    ) -> anyhow::Result<()> {
        match d {
            Dispatch::Safety(ev) => {
                let mut multi_block_gap_proposer: Option<(NodeId, boule_consensus::Height)> = None;
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

                    multi_block_gap_proposer = Some((proposer, proposal_height));
                }

                if let SafetyEvent::ProposalReceived(signed) = &ev {
                    let block = &signed.inner().payload.block;

                    let recent = RecentBlockResolver {
                        pending: self.core.state().pending_blocks.clone(),
                        storage: self.storage.clone(),
                    };
                    if let Err(e) = self.app.validate_proposal(block, &recent).await {
                        tracing::warn!(
                            target: TRACE_TARGET,
                            view = block.header.view.0,
                            height = block.header.height.0,
                            proposer = %hex::encode(block.header.proposer),
                            error = %e,
                            "rejecting proposal: application could not validate its \
                             proposer-authored write set; not voting (#797)",
                        );
                        return Ok(());
                    }
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

            Dispatch::PeerStatus { from, height } => {
                self.peer_heights.insert(from, height);
            }

            Dispatch::ServeBlock { hash, to } => {
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

                    let last_committed = self
                        .last_committed_height
                        .load(std::sync::atomic::Ordering::Relaxed);
                    if self.block_retention_window > 0
                        && last_committed >= self.block_retention_window
                    {
                        tracing::warn!(
                            target: TRACE_TARGET,
                            from = %node_id_to_base58(&to),
                            hash = ?hash,
                            last_committed_height = last_committed,
                            retention_window = self.block_retention_window,
                            "block_sync_responder_pruned_miss",
                        );
                    }
                }
                let out = dispatch::egress_block_response(
                    hash,
                    block,
                    to,
                    signer.as_ref(),
                    &self.chain_id,
                )?;
                send_outbound(
                    broadcaster,
                    self.rate_limiter.as_deref(),
                    &self.peers_connected,
                    out,
                )
                .await;
            }

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
                send_outbound(
                    broadcaster,
                    self.rate_limiter.as_deref(),
                    &self.peers_connected,
                    out,
                )
                .await;
            }

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
            Dispatch::ReceiveEquivocationEvidence {
                proof,
                validator_id,
            } => {
                self.mint_equivocation_evidence(&proof, validator_id);
            }
        }
        Ok(())
    }

    fn collect_block_range(
        &self,
        from_height: boule_consensus::Height,
        to_height: boule_consensus::Height,
    ) -> Vec<boule_consensus::replication::block::Block> {
        if from_height > to_height {
            return Vec::new();
        }
        let cap = boule_consensus::wire::BLOCK_RANGE_RESPONSE_MAX_BLOCKS;

        let mut out: Vec<boule_consensus::replication::block::Block> = self
            .core
            .state()
            .pending_blocks
            .values()
            .filter(|b| b.header.height >= from_height && b.header.height <= to_height)
            .cloned()
            .collect();

        let last_committed_raw = match self
            .storage
            .get(crate::consensus_node::STORAGE_KEY_LAST_COMMITTED)
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
            match crate::consensus_node::decode_last_committed(&raw) {
                Ok(lc) => {
                    let storage_blocks = match crate::consensus_node::load_block_range_from_storage(
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

        let mut seen: std::collections::HashSet<boule_consensus::replication::block::BlockHash> =
            std::collections::HashSet::new();
        out.retain(|b| seen.insert(b.hash()));
        out.sort_by_key(|b| b.header.height);
        out.truncate(cap);
        out
    }

    async fn maybe_emit_block_range_request(
        &mut self,
        proposer: NodeId,
        proposal_height: boule_consensus::Height,
        broadcaster: &dyn Broadcaster,
        _signer: &Arc<dyn Signer>,
    ) -> anyhow::Result<()> {
        if proposer == self.self_id {
            return Ok(());
        }
        let last_committed = self.last_committed_height.load(Ordering::Relaxed);
        let parent_height = proposal_height.0.saturating_sub(1);

        if parent_height <= last_committed.saturating_add(1) {
            return Ok(());
        }
        let from_height = boule_consensus::Height(last_committed.saturating_add(1));
        let cap = boule_consensus::wire::BLOCK_RANGE_RESPONSE_MAX_BLOCKS as u64;

        let to_height = boule_consensus::Height(parent_height.min(from_height.0 + cap - 1));
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
        self.block_sync_range_inflight.insert(
            key,
            BlockSyncRangeInflight {
                peer: proposer,
                attempts: 1,
                last_asked_at: tokio::time::Instant::now(),
            },
        );
        tracing::info!(
            target: TRACE_TARGET,
            from_height = from_height.0,
            to_height = to_height.0,
            proposer = %node_id_to_base58(&proposer),
            "block_sync_range_request_emitted",
        );
        let out = dispatch::egress_block_range_request(from_height, to_height, proposer);
        send_outbound(
            broadcaster,
            self.rate_limiter.as_deref(),
            &self.peers_connected,
            out,
        )
        .await;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_block_range_response(
        &mut self,
        from_height: boule_consensus::Height,
        to_height: boule_consensus::Height,
        blocks: Vec<boule_consensus::replication::block::Block>,
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

        if self
            .block_sync_range_inflight
            .remove(&(from_height, to_height))
            .is_none()
        {
            tracing::warn!(
                target: TRACE_TARGET,
                from = %node_id_to_base58(&from),
                from_height = from_height.0,
                to_height = to_height.0,
                block_count,
                "block_sync_range_response_unrequested",
            );
            return Ok(());
        }
        let mut inserted = 0u64;
        let mut last_height: Option<boule_consensus::Height> = None;
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

        let frontier = self.last_committed_height.load(Ordering::Relaxed);
        if frontier >= from_height.0
            && let Some((proposer, proposal_height)) = self
                .core
                .parked_proposals()
                .map(|s| (s.signer, s.payload.block.header.height))
                .max_by_key(|(_, height)| height.0)
        {
            self.maybe_emit_block_range_request(proposer, proposal_height, broadcaster, signer)
                .await?;
        }
        Ok(())
    }

    pub(super) async fn maintain_block_sync_range_retry(
        &mut self,
        broadcaster: &dyn Broadcaster,
        retry_threshold: std::time::Duration,
    ) -> anyhow::Result<()> {
        if self.block_sync_range_inflight.is_empty() {
            return Ok(());
        }
        let now = tokio::time::Instant::now();
        let max_attempts = self.core.block_sync_max_attempts();

        let keys: std::collections::BTreeSet<(Height, Height)> =
            self.block_sync_range_inflight.keys().copied().collect();
        let mut to_drop: Vec<(Height, Height)> = Vec::new();
        let mut to_emit: Vec<(Height, Height, NodeId)> = Vec::new();
        for key in keys {
            let entry = self
                .block_sync_range_inflight
                .get_mut(&key)
                .expect("key just enumerated must still be present");
            if entry.attempts >= max_attempts {
                to_drop.push(key);
                continue;
            }
            if now.duration_since(entry.last_asked_at) < retry_threshold {
                continue;
            }
            entry.attempts = entry.attempts.saturating_add(1);
            entry.last_asked_at = now;
            to_emit.push((key.0, key.1, entry.peer));
        }
        for key in to_drop {
            if let Some(entry) = self.block_sync_range_inflight.remove(&key) {
                tracing::warn!(
                    target: TRACE_TARGET,
                    from_height = key.0.0,
                    to_height = key.1.0,
                    peer = %node_id_to_base58(&entry.peer),
                    attempts = entry.attempts,
                    max_attempts,
                    "block_sync_range_request_dropped_attempts_exhausted",
                );
            }
        }
        for (from_height, to_height, peer) in to_emit {
            tracing::info!(
                target: TRACE_TARGET,
                from_height = from_height.0,
                to_height = to_height.0,
                peer = %node_id_to_base58(&peer),
                "block_sync_range_request_retry_emitted",
            );
            let out = dispatch::egress_block_range_request(from_height, to_height, peer);
            send_outbound(
                broadcaster,
                self.rate_limiter.as_deref(),
                &self.peers_connected,
                out,
            )
            .await;
        }
        Ok(())
    }

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

            if !persist_buf.is_empty() {
                self.persist_updates(&persist_buf)?;
                persist_buf.clear();
            }

            match action {
                SafetyAction::Persist(_) => unreachable!(),

                SafetyAction::Broadcast(mut msg) => {
                    if self.role.is_full() {
                        tracing::trace!(
                            target: TRACE_TARGET,
                            msg = msg_kind(&msg),
                            "follow_only_suppressed_outbound",
                        );
                        continue;
                    }
                    tracing::debug!(
                        target: TRACE_TARGET,
                        msg = msg_kind(&msg),
                        "outbound_broadcast",
                    );

                    if let ConsensusMsg::Proposal(ref mut p) = msg {
                        p.block.header.validator_history_commitment =
                            boule_consensus::history_commitment::compute_post_block_commitment(
                                &p.block,
                                &self.validator_history,
                                &self.validator_key_history,
                                self.bls_key_history.as_ref(),
                                Some(&self.operator_key_history),
                                &self.chain_id,
                                self.min_v_eff_delay,
                            );
                    }

                    if self.vote_divergence_check_enabled
                        && let ConsensusMsg::Vote(vote) = &msg
                        && let Some(block) = self.core.state().pending_blocks.get(&vote.block_hash)
                        && block.header.committed_height.0
                            == self.last_committed_height.load(Ordering::Relaxed)
                    {
                        let local_root = self.app.state_commitment();
                        if local_root != block.header.committed_state_root {
                            tracing::warn!(
                                target: TRACE_TARGET,
                                view = vote.view.0,
                                committed_height = block.header.committed_height.0,
                                claimed = %hex::encode(block.header.committed_state_root),
                                local = %hex::encode(local_root),
                                "consensus_state_divergence_detected",
                            );
                            self.state_divergence_detected
                                .fetch_add(1, Ordering::Relaxed);

                            continue;
                        }
                    }

                    if let ConsensusMsg::Vote(vote) = &msg
                        && let Some(block) = self.core.state().pending_blocks.get(&vote.block_hash)
                    {
                        let rejected = block.commands.iter().find_map(|cmd| {
                            if boule_consensus::validator_rotation::DualSignedRotation::is_rotation_payload(cmd)
                                || boule_consensus::validator_rotation::DualSignedRotationCancel::is_cancel_payload(cmd)
                                || boule_consensus::validator_rotation::OperatorSignedRotation::is_operator_rotation_payload(cmd)
                                || boule_consensus::validator_rotation::DualSignedOperatorRotation::is_operator_key_rotation_payload(cmd)
                                || boule_consensus::reconfig::ReconfigCommand::is_reconfig_payload(cmd)

                                || boule_consensus::equivocation_evidence::is_evidence_payload(cmd)

                                || boule_consensus::consensus_params::ConsensusParamUpdate::is_param_update_payload(cmd)

                                || boule_consensus::endpoint_registry::SignedEndpointCommand::is_endpoint_payload(cmd)
                            {
                                return None;
                            }
                            self.app.check(cmd).err()
                        });
                        if let Some(e) = rejected {
                            tracing::warn!(
                                target: TRACE_TARGET,
                                view = vote.view.0,
                                error = %e,
                                "consensus_proposal_command_not_includable",
                            );
                            self.proposal_command_rejections
                                .fetch_add(1, Ordering::Relaxed);

                            continue;
                        }
                    }

                    if matches!(msg, ConsensusMsg::Proposal(_))
                        && !self.min_block_interval.is_zero()
                        && self
                            .last_proposal_at
                            .is_some_and(|last| last.elapsed() < self.min_block_interval)
                    {
                        self.stashed_proposal = Some(msg);
                        continue;
                    }
                    self.broadcast_consensus_msg(msg, broadcaster, view_timer, signer)
                        .await?;
                }

                SafetyAction::RequestBlock {
                    hash,
                    peer,
                    expected_height,
                    reason,
                } => {
                    if peer == self.self_id {
                        tracing::debug!(
                            target: TRACE_TARGET,
                            hash = ?hash,
                            requesting_height = expected_height.0,
                            triggered_by = reason.as_str(),
                            "block_sync_request_self_dropped",
                        );
                    } else {
                        let dest = if self.peers_connected.contains(&peer)
                            || self.peers_connected.is_empty()
                        {
                            peer
                        } else {
                            let mut pool: Vec<NodeId> = self
                                .peers_connected
                                .iter()
                                .copied()
                                .filter(|p| {
                                    self.peer_heights
                                        .get(p)
                                        .is_some_and(|h| *h >= expected_height)
                                })
                                .collect();
                            if pool.is_empty() {
                                pool = self.peers_connected.iter().copied().collect();
                            }
                            pool.sort_unstable();
                            let idx = (self.block_sync_neighbour_rr as usize) % pool.len();
                            self.block_sync_neighbour_rr =
                                self.block_sync_neighbour_rr.wrapping_add(1);
                            pool[idx]
                        };
                        tracing::info!(
                            target: TRACE_TARGET,
                            dest = %node_id_to_base58(&dest),
                            block_holder = %node_id_to_base58(&peer),
                            hash = ?hash,
                            requesting_height = expected_height.0,
                            triggered_by = reason.as_str(),
                            our_view = self.pacemaker.current_view().0,
                            our_high_qc_view = ?self.core.state().high_qc.as_ref().map(|q| q.view().0),
                            "block_sync_request_emitted",
                        );
                        let out = dispatch::egress_block_request(hash, dest);
                        send_outbound(
                            broadcaster,
                            self.rate_limiter.as_deref(),
                            &self.peers_connected,
                            out,
                        )
                        .await;
                    }
                }

                SafetyAction::Commit(block) => {
                    let committed_height = block.header.height;
                    self.commit_block(block).await;

                    send_outbound(
                        broadcaster,
                        self.rate_limiter.as_deref(),
                        &self.peers_connected,
                        dispatch::egress_status(committed_height),
                    )
                    .await;
                }

                SafetyAction::EquivocationEvidence {
                    voter,
                    view,
                    block_a,
                    block_b,
                } => {
                    self.equivocations_detected.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        target: TRACE_TARGET,
                        voter = %node_id_to_base58(voter.as_node_id()),
                        view = view.0,
                        block_a = ?block_a,
                        block_b = ?block_b,
                        "consensus_equivocation_detected",
                    );

                    if let Some(proof) =
                        self.build_vote_equivocation_proof(voter, view, block_a, block_b)
                    {
                        let out = dispatch::egress_equivocation_evidence(proof);
                        send_outbound(
                            broadcaster,
                            self.rate_limiter.as_deref(),
                            &self.peers_connected,
                            out,
                        )
                        .await;
                    }
                }

                SafetyAction::ProposalEquivocationEvidence {
                    leader,
                    view,
                    block_a,
                    block_b,
                } => {
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
                    if let Some(proof) =
                        self.build_proposal_equivocation_proof(leader, view, block_a, block_b)
                    {
                        let out = dispatch::egress_equivocation_evidence(proof);
                        send_outbound(
                            broadcaster,
                            self.rate_limiter.as_deref(),
                            &self.peers_connected,
                            out,
                        )
                        .await;
                    }
                }

                SafetyAction::BuildProposal {
                    view,
                    high_qc,
                    parent,
                } => {
                    if self.role.is_full() {
                        continue;
                    }

                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0);

                    self.mint_staged_reconfig(view);

                    self.mint_staged_effects(view);

                    self.mint_staged_governance_reconfig(view);

                    let ctx = self.build_app_context(&high_qc);
                    match self
                        .app
                        .build_proposal(
                            &ctx,
                            &parent,
                            view,
                            &high_qc,
                            &self.core.state().pending_blocks,
                            timestamp,
                        )
                        .await
                    {
                        Ok(block) => {
                            let built = self.core.proposal_built(view, block, high_qc);
                            Box::pin(self.apply_safety_actions(
                                built,
                                broadcaster,
                                view_timer,
                                signer,
                            ))
                            .await?;
                        }
                        Err(e) => {
                            tracing::warn!(
                                target: TRACE_TARGET,
                                view = view.0,
                                parent_height = parent.header.height.0,
                                error = %e,
                                "block_builder_build_failed",
                            );
                        }
                    }
                }
            }
        }

        if !persist_buf.is_empty() {
            self.persist_updates(&persist_buf)?;
        }

        Ok(())
    }

    pub(super) async fn broadcast_consensus_msg(
        &mut self,
        msg: ConsensusMsg,
        broadcaster: &dyn Broadcaster,
        view_timer: &mut ViewTimer,
        signer: &Arc<dyn Signer>,
    ) -> anyhow::Result<()> {
        let bls_signer = self.bls_signer.as_deref();
        let (payload, loopback) = dispatch::egress_consensus_msg_with_loopback(
            &msg,
            signer.as_ref(),
            bls_signer,
            &self.validator_key_history,
            &self.chain_id,
        )?;
        let msg_is_proposal = matches!(msg, ConsensusMsg::Proposal(_));
        send_outbound(
            broadcaster,
            self.rate_limiter.as_deref(),
            &self.peers_connected,
            Outbound::Broadcast(payload),
        )
        .await;

        if msg_is_proposal {
            self.last_proposal_at = Some(tokio::time::Instant::now());
        }

        self.enqueue_loopback(loopback);
        Box::pin(self.drain_loopback(broadcaster, view_timer, signer)).await?;
        Ok(())
    }

    fn enqueue_loopback(&mut self, loopback: Vec<Dispatch>) {
        for d in loopback.into_iter().rev() {
            self.loopback_stack.push(d);
        }
    }

    pub(super) async fn drain_loopback(
        &mut self,
        broadcaster: &dyn Broadcaster,
        view_timer: &mut ViewTimer,
        signer: &Arc<dyn Signer>,
    ) -> anyhow::Result<()> {
        if self.draining_loopback {
            return Ok(());
        }
        self.draining_loopback = true;
        while let Some(d) = self.loopback_stack.pop() {
            if let Err(e) = self
                .apply_dispatch(d, broadcaster, view_timer, signer)
                .await
            {
                self.draining_loopback = false;
                self.loopback_stack.clear();
                return Err(e);
            }
        }
        self.draining_loopback = false;
        Ok(())
    }

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

                    self.signing_view
                        .store(v.0, std::sync::atomic::Ordering::Relaxed);

                    let safety_actions = self.step_safety(SafetyEvent::PacemakerAdvance(v));
                    self.apply_safety_actions(safety_actions, broadcaster, view_timer, signer)
                        .await?;
                }

                PacemakerAction::BecomeLeader(v) => {
                    if self.role.is_full() {
                        continue;
                    }
                    let safety_actions = self.core.become_leader(v);
                    self.apply_safety_actions(safety_actions, broadcaster, view_timer, signer)
                        .await?;
                }

                PacemakerAction::ResetTimer(d) => {
                    let view = self.pacemaker.current_view();
                    view_timer.reset(view, d);
                }

                PacemakerAction::SendTimeout(v) => {
                    if self.role.is_full() {
                        tracing::trace!(
                            target: TRACE_TARGET,
                            view = v.0,
                            "follow_only_suppressed_timeout",
                        );
                        continue;
                    }
                    self.send_timeout(v, broadcaster, view_timer, signer)
                        .await?;
                }
            }
        }
        Ok(())
    }

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

    pub(super) fn step_safety(&mut self, ev: SafetyEvent) -> Vec<SafetyAction> {
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

        self.retain_for_equivocation_evidence(&ev);
        if let SafetyEvent::PacemakerAdvance(current) = &ev {
            let current = *current;
            self.gc_equivocation_evidence(current);
        }

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

    pub(super) async fn fire_round_sync(
        &mut self,
        view: View,
        evidence: boule_consensus::pacemaker::HonestyThresholdEvidence,
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

struct RecentBlockResolver {
    pending: std::collections::HashMap<
        boule_consensus::replication::block::BlockHash,
        boule_consensus::replication::block::Block,
    >,
    storage: Arc<dyn boule_core::storage::Storage>,
}

impl boule_consensus::replication::application::RecentBlocks for RecentBlockResolver {
    fn get(
        &self,
        hash: &boule_consensus::replication::block::BlockHash,
    ) -> Option<boule_consensus::replication::block::Block> {
        if let Some(b) = self.pending.get(hash) {
            return Some(b.clone());
        }

        load_block_from_storage(self.storage.as_ref(), hash)
            .ok()
            .flatten()
    }
}
