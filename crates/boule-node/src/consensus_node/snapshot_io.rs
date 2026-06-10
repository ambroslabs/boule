use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::Context;
use bytes::Bytes;

use boule_consensus::Height;
use boule_consensus::View;
use boule_consensus::dispatch;
use boule_consensus::hotstuff::qc::VerifiedQc;
use boule_consensus::hotstuff::step::{Action as SafetyAction, Event as SafetyEvent, StateUpdate};
use boule_consensus::pacemaker::leader::WeightedAccumulatorSelector;
use boule_consensus::view_timer::ViewTimer;
use boule_core::crypto::signed::Signer;
use boule_core::identity::NodeId;
use boule_core::identity::node_id_to_base58;
use boule_core::storage::StorageExt;
use boule_core::transport::overlay::Broadcaster;

use super::{
    ConsensusNode, LastCommitted, RECENT_QC_CACHE_CAPACITY, STORAGE_KEY_BLS_KEY_HISTORY,
    STORAGE_KEY_HIGH_QC, STORAGE_KEY_LAST_COMMITTED, STORAGE_KEY_LAST_VOTED_VIEW,
    STORAGE_KEY_LOCKED, STORAGE_KEY_VALIDATOR_HISTORY, STORAGE_KEY_VALIDATOR_KEY_HISTORY,
    TRACE_TARGET, block_storage_key, encode_block, encode_high_qc, encode_last_committed,
    encode_locked, encode_voted_view, send_outbound,
};

impl ConsensusNode {
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

    pub(super) fn restore_from_snapshot(
        &mut self,
        manifest: boule_consensus::replication::snapshot::SnapshotManifest,
        payload: Bytes,
    ) -> anyhow::Result<()> {
        self.app
            .restore(&payload)
            .map_err(|e| anyhow::anyhow!("application restore failed: {e}"))?;

        let post_restore = self.app.state_commitment();
        if post_restore != manifest.state_commitment {
            anyhow::bail!(
                "post-restore state_commitment {} does not match manifest {}",
                hex::encode(post_restore),
                hex::encode(manifest.state_commitment),
            );
        }

        let block = manifest.block.clone();
        let block_hash = manifest.block_hash;
        let last_committed = LastCommitted {
            height: manifest.height,
            view: manifest.view,
            last_committed_hash: block_hash,
        };

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

        if manifest.height.0 > self.last_committed_height.load(Ordering::Relaxed) {
            self.last_committed_height
                .store(manifest.height.0, Ordering::Relaxed);
            self.last_committed_view = manifest.view;
        }

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

        let snapshot_set = (*installed_set.current_set()).clone();
        self.validator_set = snapshot_set;
        self.validator_history = installed_set;
        self.validator_key_history = installed_key;
        self.bls_key_history = installed_bls;
        self.pacemaker
            .set_selector(Arc::new(WeightedAccumulatorSelector::new(Arc::new(
                self.validator_history.clone(),
            ))));

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

        self.recent_qcs
            .lock()
            .insert(block_hash, manifest.commit_qc, RECENT_QC_CACHE_CAPACITY);
        Ok(())
    }

    pub(super) async fn serve_snapshot_manifest(
        &self,
        height: Option<u64>,
        to: NodeId,
        broadcaster: &dyn Broadcaster,
    ) {
        let store =
            boule_consensus::replication::snapshot::SnapshotStore::new(Arc::clone(&self.storage));
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

    pub(super) async fn serve_snapshot_chunk(
        &self,
        height: Height,
        chunk_idx: u32,
        to: NodeId,
        broadcaster: &dyn Broadcaster,
    ) {
        let store =
            boule_consensus::replication::snapshot::SnapshotStore::new(Arc::clone(&self.storage));
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

    pub(super) fn try_take_snapshot(
        &self,
        block: &boule_consensus::replication::block::Block,
    ) -> anyhow::Result<()> {
        use boule_consensus::replication::snapshot::{
            SnapshotManifest, SnapshotStore, chunk_snapshot,
        };
        let block_hash = block.hash();

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

        let snapshot_bytes = self.app.snapshot();
        let chunks_with_hashes =
            chunk_snapshot(&snapshot_bytes, self.snapshot_policy.chunk_size_bytes);
        let chunk_hashes: Vec<[u8; 32]> = chunks_with_hashes.iter().map(|(_, h)| *h).collect();
        let chunks: Vec<Bytes> = chunks_with_hashes.into_iter().map(|(c, _)| c).collect();
        let created_unix_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let active_set_at = self.validator_history.set_at(block.header.view);
        let active_set = active_set_at.for_view(block.header.view);

        let validator_history_persisted = self.validator_history.to_persisted();
        let validator_key_history_persisted = self.validator_key_history.to_persisted();
        let bls_key_history_persisted = self.bls_key_history.as_ref().map(|h| h.to_persisted());

        let operator_key_history_persisted = Some(self.operator_key_history.to_persisted());
        let manifest = SnapshotManifest::build(
            block.clone(),
            active_set,
            self.snapshot_policy.chunk_size_bytes,
            chunk_hashes,
            commit_qc,
            created_unix_secs,
            validator_history_persisted,
            validator_key_history_persisted,
            bls_key_history_persisted,
            operator_key_history_persisted,
        );
        let store = SnapshotStore::new(Arc::clone(&self.storage));
        store.save(&manifest, &chunks)?;

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
