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
                }
                let actions = self.step_safety(ev);
                self.apply_safety_actions(actions, broadcaster, view_timer, signer)
                    .await?;
            }

            Dispatch::Pacemaker(ev) => {
                let pm_actions = self.step_pacemaker(ev);
                self.apply_pacemaker_actions(pm_actions, broadcaster, view_timer, signer)
                    .await?;
            }

            Dispatch::ServeBlock { hash, to } => {
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
