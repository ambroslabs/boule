//! Snapshot serving and joiner-side restore.
//!
//! Three responsibilities:
//!
//! - [`super::ConsensusNode::try_take_snapshot`] writes a manifest+chunks
//!   to the local [`boule_consensus::replication::SnapshotStore`] when the
//!   configured policy fires at commit time.
//! - [`super::ConsensusNode::serve_snapshot_manifest`] /
//!   [`super::ConsensusNode::serve_snapshot_chunk`] handle inbound
//!   manifest/chunk requests by reading from the local store.
//! - [`super::ConsensusNode::apply_snapshot_sync_actions`] interprets
//!   the joiner-side state machine's actions (request next chunk,
//!   restore, abort), and [`super::ConsensusNode::restore_from_snapshot`]
//!   adopts a verified snapshot as the joiner's new baseline.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::Context;
use bytes::Bytes;

use boule_consensus::Height;
use boule_consensus::View;
use boule_consensus::crashpoint::crashpoint;
use boule_consensus::dispatch;
use boule_consensus::hotstuff::qc::VerifiedQc;
use boule_consensus::hotstuff::step::{Action as SafetyAction, Event as SafetyEvent, StateUpdate};
use boule_consensus::pacemaker::leader::WeightedAccumulatorSelector;
use boule_consensus::view_timer::ViewTimer;
use boule::crypto::signed::Signer;
use boule_transport_tcp::NodeId;
use boule_transport_tcp::overlay::Broadcaster;
use boule_transport_tcp::tls::node_id_to_base58;
use boule::storage::StorageExt;

use super::{
    ConsensusNode, LastCommitted, RECENT_QC_CACHE_CAPACITY, STORAGE_KEY_BLS_KEY_HISTORY,
    STORAGE_KEY_HIGH_QC, STORAGE_KEY_LAST_COMMITTED, STORAGE_KEY_LAST_VOTED_VIEW,
    STORAGE_KEY_LOCKED, STORAGE_KEY_VALIDATOR_HISTORY, STORAGE_KEY_VALIDATOR_KEY_HISTORY,
    TRACE_TARGET, block_storage_key, encode_block, encode_high_qc, encode_last_committed,
    encode_locked, encode_voted_view, send_outbound,
};

impl ConsensusNode {
    /// Execute a slice of [`SnapshotSyncAction`]s emitted by the
    /// joiner-side state machine. Each action is mapped to either a
    /// wire send (`SendManifestRequest`, `SendChunkRequest`), a
    /// state-restore call ([`Self::restore_from_snapshot`]), or a
    /// log-and-drop on `Abort`. The state machine has already
    /// transitioned by the time we see the actions, so any error
    /// here is treated as a soft failure: we log and let
    /// block-sync take over.
    pub(super) async fn apply_snapshot_sync_actions(
        &mut self,
        actions: Vec<boule_consensus::snapshot_sync::SnapshotSyncAction>,
        broadcaster: &dyn Broadcaster,
        view_timer: &mut ViewTimer,
        signer: &Arc<dyn Signer>,
    ) -> anyhow::Result<()> {
        use boule_consensus::snapshot_sync::SnapshotSyncAction;
        for action in actions {
            match action {
                SnapshotSyncAction::SendManifestRequest { peer } => {
                    tracing::info!(
                        target: TRACE_TARGET,
                        peer = %node_id_to_base58(&peer),
                        "snapshot_manifest_request_sent",
                    );
                    let out = dispatch::egress_snapshot_manifest_request(None, peer);
                    send_outbound(
                        broadcaster,
                        self.rate_limiter.as_deref(),
                        &self.peers_connected,
                        out,
                    )
                    .await;
                }
                SnapshotSyncAction::SendChunkRequest {
                    peer,
                    height,
                    chunk_idx,
                } => {
                    tracing::info!(
                        target: TRACE_TARGET,
                        peer = %node_id_to_base58(&peer),
                        height,
                        chunk_idx,
                        "snapshot_chunk_request_sent",
                    );
                    let out = dispatch::egress_snapshot_chunk_request(height, chunk_idx, peer);
                    send_outbound(
                        broadcaster,
                        self.rate_limiter.as_deref(),
                        &self.peers_connected,
                        out,
                    )
                    .await;
                }
                SnapshotSyncAction::Restore { manifest, payload } => {
                    let height = manifest.height;
                    let view = manifest.view;
                    if let Err(e) = self.restore_from_snapshot(*manifest, payload) {
                        tracing::error!(
                            target: TRACE_TARGET,
                            height = height.0,
                            view = view.0,
                            error = %e,
                            "snapshot_restore_failed",
                        );
                    } else {
                        tracing::info!(
                            target: TRACE_TARGET,
                            height = height.0,
                            view = view.0,
                            "snapshot_restored",
                        );
                        // Re-drive any parked proposals through the
                        // safety core: the post-restore lock at the
                        // snapshot's `(view, height)` may have just
                        // unblocked previously-parked proposals.
                        let current_view = self.pacemaker.current_view();
                        let pa_actions =
                            self.step_safety(SafetyEvent::PacemakerAdvance(current_view));
                        self.apply_safety_actions(pa_actions, broadcaster, view_timer, signer)
                            .await?;
                    }
                }
                SnapshotSyncAction::Abort { reason } => {
                    tracing::warn!(
                        target: TRACE_TARGET,
                        reason = ?reason,
                        "snapshot_fetch_aborted",
                    );
                }
            }
        }
        Ok(())
    }

    /// Adopt a verified snapshot as the joiner's new starting
    /// point. Called from [`Self::apply_snapshot_sync_actions`] when
    /// the snapshot-fetch state machine emits
    /// [`boule_consensus::snapshot_sync::SnapshotSyncAction::Restore`].
    ///
    /// Steps:
    /// 1. `state_machine.restore(&payload)` — rehydrate application
    ///    state. On failure, the SM is left implementation-defined;
    ///    we abort the restore.
    /// 2. Verify the SM's post-restore commitment matches the
    ///    manifest's claimed `state_commitment`. A mismatch means
    ///    the producer published a snapshot that doesn't agree with
    ///    its own block header — defensively reject.
    /// 3. Adopt the snapshot in the safety core: insert the block
    ///    into `pending_blocks`, set `locked`, `high_qc`, and
    ///    `last_voted_view` to the snapshot's values. Lock and
    ///    high-QC views are monotonically forward (joiner's prior
    ///    values are at most genesis), so safety invariants are
    ///    preserved. The safety core returns the [`StateUpdate`]s
    ///    its in-memory mutations must be paired with on disk.
    /// 4. Persist the snapshot block under
    ///    [`super::STORAGE_KEY_BLOCK_PREFIX`], the new `last_committed`,
    ///    and every safety-core [`StateUpdate`] from step 3
    ///    (`VotedInView`, `Locked`, `HighQc`) in one atomic batch.
    ///    Folding the safety-core writes into the same batch is the
    ///    audit-finding-4-3 (#406) requirement: a crash between an
    ///    in-memory adoption and a follow-up persist would let
    ///    [`super::recover_state`] rehydrate stale `locked` /
    ///    `last_voted_view` and the joiner could vote on a fork below
    ///    the snapshot height. Survives crash recovery: a subsequent
    ///    boot's [`super::recover_state`] rebuilds the safety state
    ///    from these keys.
    /// 5. Update the in-memory `last_committed_*` so subsequent
    ///    `apply_commit`s don't regress.
    pub(super) fn restore_from_snapshot(
        &mut self,
        manifest: boule_consensus::replication::snapshot::SnapshotManifest,
        payload: Bytes,
    ) -> anyhow::Result<()> {
        // Step 1: restore the application state machine.
        self.state_machine
            .lock()
            .restore(&payload)
            .map_err(|e| anyhow::anyhow!("state_machine.restore failed: {e}"))?;
        // Step 2: confirm the post-restore commitment matches the
        // manifest. A mismatch indicates a buggy or malicious
        // producer; bail before touching durable state.
        let post_restore = self.state_machine.lock().state_commitment();
        if post_restore != manifest.state_commitment {
            anyhow::bail!(
                "post-restore state_commitment {} does not match manifest {}",
                hex::encode(post_restore),
                hex::encode(manifest.state_commitment),
            );
        }
        // Step 3: adopt in the safety core (in-memory) and capture
        // the safety-state Persist actions the core requires us to
        // flush. Doing the in-memory mutation first lets us pre-encode
        // every key the snapshot must persist before opening the
        // batch, so a single atomic write covers both the
        // integration-layer keys (block, last_committed) and the
        // safety-core keys (voted_in_view, locked, high_qc). Audit
        // finding 4-3 (#406): without folding the safety-core writes
        // into the same batch, a crash between an in-memory adoption
        // and a follow-up persist would let `recover_state` rehydrate
        // a stale `locked` / `last_voted_view` and the joiner could
        // vote on a fork below the snapshot height.
        let block = manifest.block.clone();
        let block_hash = manifest.block_hash;
        let last_committed = LastCommitted {
            height: manifest.height,
            view: manifest.view,
            last_committed_hash: block_hash,
        };
        // `manifest.commit_qc` survived `SnapshotManifest::verify`
        // upstream of `restore_from_snapshot` (well-formedness, quorum,
        // and `commit_qc.block_hash == manifest.block_hash`), so wrap
        // unchecked here is the audited-by-name snapshot trust path.
        // Audit finding 5-1 / issue #408.
        let safety_persist_actions = self.core.adopt_snapshot(
            block.clone(),
            VerifiedQc::unchecked(manifest.commit_qc.clone()),
            manifest.view,
        );
        let mut safety_persist_writes: Vec<(&'static [u8], Vec<u8>)> = Vec::new();
        for action in &safety_persist_actions {
            match action {
                SafetyAction::Persist(StateUpdate::VotedInView { view }) => {
                    safety_persist_writes
                        .push((STORAGE_KEY_LAST_VOTED_VIEW, encode_voted_view(*view)?));
                }
                SafetyAction::Persist(StateUpdate::Locked(locked)) => {
                    safety_persist_writes.push((STORAGE_KEY_LOCKED, encode_locked(locked)?));
                }
                SafetyAction::Persist(StateUpdate::HighQc(qc)) => {
                    safety_persist_writes.push((STORAGE_KEY_HIGH_QC, encode_high_qc(qc)?));
                }
                other => anyhow::bail!(
                    "adopt_snapshot must only emit Persist actions, got {:?}",
                    other,
                ),
            }
        }
        let block_bytes = encode_block(&block)?;
        let last_committed_bytes = encode_last_committed(&last_committed)?;
        let block_key = block_storage_key(&block_hash);
        self.storage.batch(|b| {
            b.put(&block_key, &block_bytes);
            b.put(STORAGE_KEY_LAST_COMMITTED, &last_committed_bytes);
            for (key, bytes) in &safety_persist_writes {
                b.put(key, bytes);
            }
            Ok(())
        })?;
        // Audit finding 4-3 / issue #406: marks the all-safety-state-durable
        // boundary for snapshot restore. The batch above landed
        // (block, last_committed, voted_in_view, locked, high_qc)
        // atomically, so a crash here is the regression-test target:
        // `recover_state` must rebuild the snapshot's `locked`,
        // `high_qc`, and `last_voted_view` exactly as the in-memory
        // mutation in `core.adopt_snapshot` set them, with no view
        // regression that would let `safe_to_vote` accept a fork
        // below the snapshot height.
        crashpoint!("after_adopt_snapshot_persist");
        // Step 5: update in-memory last-committed counters. The
        // safety core emits `Action::Commit` in height order, so
        // future commits will increment from this baseline.
        if manifest.height.0 > self.last_committed_height.load(Ordering::Relaxed) {
            self.last_committed_height
                .store(manifest.height.0, Ordering::Relaxed);
            self.last_committed_view = manifest.view;
        }
        // Step 5b (#325 PR D): install the producer's validator
        // history triple from the manifest. `SnapshotManifest::verify`
        // has already cross-checked the embedded persisted forms
        // against the snapshot block's stamped
        // `validator_history_commitment` (called from
        // `snapshot_sync::on_manifest_response`), so by the time we
        // reach this point the histories are known to match the
        // chain's claim. Without installing them here, the joiner's
        // `validator_history` would remain genesis-only after
        // restore — wrong on any chain that committed a reconfig
        // before snapshot height — and a subsequent
        // `verify_persisted_history_consistency` would reject every
        // restart.
        let installed_set =
            boule_consensus::validator_history::ValidatorSetHistory::from_persisted(
                manifest.validator_history.clone(),
            )
            .map_err(|e| anyhow::anyhow!("decode validator_history from manifest: {e}"))?;
        let installed_key =
            boule_consensus::validator_key_history::ValidatorKeyHistory::from_persisted(
                manifest.validator_key_history.clone(),
            )
            .map_err(|e| anyhow::anyhow!("decode validator_key_history from manifest: {e}"))?;
        let installed_bls = match &manifest.bls_key_history {
            Some(p) => Some(
                boule_consensus::bls_key_history::BlsKeyHistory::from_persisted(p.clone())
                    .map_err(|e| anyhow::anyhow!("decode bls_key_history from manifest: {e}"))?,
            ),
            None => None,
        };
        // Mirror every post-genesis boundary into the safety core's
        // history so vote tally / QC sizing / proposal-time leader
        // pick all see the snapshot-time committee. Genesis is
        // already seeded; only later boundaries need replay.
        for (v_eff, set) in installed_set.iter() {
            if v_eff == View::ZERO {
                continue;
            }
            self.core
                .insert_validator_boundary(v_eff, (**set).clone())
                .with_context(|| {
                    format!("replay validator boundary at v_eff = {v_eff} from snapshot manifest")
                })?;
        }
        // Re-install the pacemaker selector against the snapshot's
        // history so leader rotation past `snapshot.view` honors the
        // post-boundary committees.
        let snapshot_set = (*installed_set.current_set()).clone();
        self.validator_set = snapshot_set;
        self.validator_history = installed_set;
        self.validator_key_history = installed_key;
        self.bls_key_history = installed_bls;
        self.pacemaker
            .set_selector(Arc::new(WeightedAccumulatorSelector::new(Arc::new(
                self.validator_history.clone(),
            ))));
        // Persist the installed histories so a subsequent restart
        // reads them back and the recovery-time consistency check
        // (#325 PR B) finds them matching the chain. Failures log
        // and drop — the in-memory state is authoritative for the
        // running process.
        if let Ok(bytes) = postcard::to_stdvec(&self.validator_history.to_persisted()) {
            let _ = self.storage.put(STORAGE_KEY_VALIDATOR_HISTORY, &bytes);
        }
        if let Ok(bytes) = postcard::to_stdvec(&self.validator_key_history.to_persisted()) {
            let _ = self.storage.put(STORAGE_KEY_VALIDATOR_KEY_HISTORY, &bytes);
        }
        if let Some(bls) = self.bls_key_history.as_ref() {
            if let Ok(bytes) = postcard::to_stdvec(&bls.to_persisted()) {
                let _ = self.storage.put(STORAGE_KEY_BLS_KEY_HISTORY, &bytes);
            }
        }
        // Mirror the recent_qcs cache update that
        // `persist_updates` would do for a normally-adopted high_qc;
        // keeps the snapshot-creation hook in `apply_commit`
        // consistent if the joiner later commits a block whose
        // hash equals the snapshot's (degenerate but cheap).
        self.recent_qcs
            .lock()
            .insert(block_hash, manifest.commit_qc, RECENT_QC_CACHE_CAPACITY);
        Ok(())
    }

    /// Serve a [`boule_consensus::dispatch::Dispatch::ServeSnapshotManifest`]
    /// by looking up the requested manifest in the local
    /// [`boule_consensus::replication::SnapshotStore`] and replying.
    ///
    /// `height = None` requests the latest available manifest;
    /// `Some(h)` requests the exact-match manifest. Misses (no
    /// snapshots, height not found) reply with
    /// `SnapshotManifestResponse(None)` so the joiner can fall through
    /// to another peer or to plain block-sync.
    pub(super) async fn serve_snapshot_manifest(
        &self,
        height: Option<u64>,
        to: NodeId,
        broadcaster: &dyn Broadcaster,
    ) {
        let store = boule_consensus::replication::snapshot::SnapshotStore::new(Arc::clone(&self.storage));
        let manifest = match height {
            Some(h) => match store.load_manifest(h) {
                Ok(m) => m,
                Err(e) => {
                    tracing::error!(
                        target: TRACE_TARGET,
                        height = h,
                        error = %e,
                        "snapshot_manifest_lookup_failed",
                    );
                    None
                }
            },
            None => match store.latest_height() {
                Ok(Some(h)) => match store.load_manifest(h) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::error!(
                            target: TRACE_TARGET,
                            height = h,
                            error = %e,
                            "snapshot_latest_manifest_lookup_failed",
                        );
                        None
                    }
                },
                Ok(None) => None,
                Err(e) => {
                    tracing::error!(
                        target: TRACE_TARGET,
                        error = %e,
                        "snapshot_latest_height_lookup_failed",
                    );
                    None
                }
            },
        };
        tracing::info!(
            target: TRACE_TARGET,
            from = %node_id_to_base58(&to),
            requested_height = ?height,
            served_height = manifest.as_ref().map(|m| m.height.0),
            "snapshot_manifest_request_received",
        );
        let out = dispatch::egress_snapshot_manifest_response(manifest, to);
        send_outbound(
            broadcaster,
            self.rate_limiter.as_deref(),
            &self.peers_connected,
            out,
        )
        .await;
    }

    /// Serve a [`boule_consensus::dispatch::Dispatch::ServeSnapshotChunk`]
    /// by looking up the chunk in the local snapshot store. Misses
    /// reply with `payload = None`.
    pub(super) async fn serve_snapshot_chunk(
        &self,
        height: Height,
        chunk_idx: u32,
        to: NodeId,
        broadcaster: &dyn Broadcaster,
    ) {
        let store = boule_consensus::replication::snapshot::SnapshotStore::new(Arc::clone(&self.storage));
        let payload = match store.load_chunk(height.0, chunk_idx) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(
                    target: TRACE_TARGET,
                    height = height.0,
                    chunk_idx,
                    error = %e,
                    "snapshot_chunk_lookup_failed",
                );
                None
            }
        };
        tracing::info!(
            target: TRACE_TARGET,
            from = %node_id_to_base58(&to),
            height = height.0,
            chunk_idx,
            served = payload.is_some(),
            "snapshot_chunk_request_received",
        );
        let out = dispatch::egress_snapshot_chunk_response(height.0, chunk_idx, payload, to);
        send_outbound(
            broadcaster,
            self.rate_limiter.as_deref(),
            &self.peers_connected,
            out,
        )
        .await;
    }

    /// Build and persist a snapshot of the state machine at `block`'s
    /// height, then prune older snapshots per the configured retention.
    ///
    /// Caller must check
    /// [`boule_consensus::replication::snapshot::SnapshotPolicy::should_snapshot_at`]
    /// before invoking — this routine assumes the policy is enabled and
    /// the height is appropriate.
    pub(super) fn try_take_snapshot(
        &self,
        block: &boule_consensus::replication::block::Block,
    ) -> anyhow::Result<()> {
        use boule_consensus::replication::snapshot::{SnapshotManifest, SnapshotStore, chunk_snapshot};
        let block_hash = block.hash();
        // Find a QC over this block. The cache is populated whenever
        // the safety core adopts a new high_qc; by the time block
        // commits, its QC must have been adopted (it sat in high_qc
        // when the proposal at the next height arrived). If the cache
        // has been evicted, skip the snapshot rather than synthesizing
        // a placeholder QC — the joiner-side verifier will reject
        // unsigned manifests. Subsequent snapshots at later heights
        // will succeed once a fresh QC populates the cache.
        let commit_qc = match self.recent_qcs.lock().get(&block_hash) {
            Some(qc) => qc.clone(),
            None => {
                tracing::warn!(
                    target: TRACE_TARGET,
                    height = block.header.height.0,
                    view = block.header.view.0,
                    "snapshot_skipped_no_qc_cached",
                );
                return Ok(());
            }
        };
        // Capture the state-machine bytes and its commitment under one
        // lock so the snapshot is internally consistent.
        let snapshot_bytes = self.state_machine.lock().snapshot();
        let chunks_with_hashes =
            chunk_snapshot(&snapshot_bytes, self.snapshot_policy.chunk_size_bytes);
        let chunk_hashes: Vec<[u8; 32]> = chunks_with_hashes.iter().map(|(_, h)| *h).collect();
        let chunks: Vec<Bytes> = chunks_with_hashes.into_iter().map(|(c, _)| c).collect();
        let created_unix_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // The block's `state_commitment` is what consensus committed
        // and what `manifest.verify` cross-checks against the
        // standalone `state_commitment` field in the manifest.
        // #254: pick the validator set authoritative *at the snapshot
        // block's view* rather than `self.validator_set` (which is
        // the boot-time genesis set). After a reconfig, the snapshot
        // must embed the post-boundary committee so a fresh joiner's
        // QC verification picks the right set.
        let active_set_at = self.validator_history.set_at(block.header.view);
        let active_set = active_set_at.for_view(block.header.view);
        // #325 PR D: embed the producer's full `(validator_history,
        // validator_key_history, bls_key_history?)` triple in the
        // manifest's persisted forms. The joiner installs these
        // verbatim during restore, and `SnapshotManifest::verify`
        // cross-checks their v1 hash against the snapshot block's
        // stamped `validator_history_commitment` so a tampered or
        // rolled-back triple is rejected before any durable state on
        // the joiner is touched.
        let validator_history_persisted = self.validator_history.to_persisted();
        let validator_key_history_persisted = self.validator_key_history.to_persisted();
        let bls_key_history_persisted = self.bls_key_history.as_ref().map(|h| h.to_persisted());
        let manifest = SnapshotManifest::build(
            block.clone(), // `block` is `&Block` here; clone for the manifest's owned field.
            active_set,
            self.snapshot_policy.chunk_size_bytes,
            chunk_hashes,
            commit_qc,
            created_unix_secs,
            validator_history_persisted,
            validator_key_history_persisted,
            bls_key_history_persisted,
        );
        let store = SnapshotStore::new(Arc::clone(&self.storage));
        store.save(&manifest, &chunks)?;
        // Prune older snapshots. `0` retention disables pruning so a
        // test (or operator) accumulating snapshots for forensic
        // reasons retains everything; the default keeps three.
        let pruned = store.prune_older_than(self.snapshot_policy.retention_count)?;
        tracing::info!(
            target: TRACE_TARGET,
            height = manifest.height.0,
            view = manifest.view.0,
            chunk_count = manifest.chunk_count,
            chunk_size = manifest.chunk_size,
            pruned = ?pruned,
            "snapshot_created",
        );
        Ok(())
    }
}
