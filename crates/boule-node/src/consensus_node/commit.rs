use std::sync::atomic::Ordering;

use boule_consensus::Height;
use boule_consensus::replication::application::CommitResult;
use boule_consensus::replication::block::{Block, BlockHash};
use boule_core::storage::{Storage, StorageExt};

use super::{
    ConsensusNode, LastCommitted, STORAGE_KEY_HEIGHT_PREFIX, STORAGE_KEY_LAST_COMMITTED,
    TRACE_TARGET, block_storage_key, decode_height_storage_key, encode_block,
    encode_last_committed, height_storage_key,
};

impl ConsensusNode {
    pub(super) async fn commit_block(&mut self, block: Block) {
        let ctx = self.commit_app_context(&block);
        match self.app.commit(&ctx, &block).await {
            Ok(result) => self.stage_app_validator_updates(result, &block),
            Err(e) => {
                tracing::error!(
                    target: TRACE_TARGET,
                    height = block.header.height.0,
                    view = block.header.view.0,
                    error = %e,
                    "application_commit_failed",
                );
            }
        }
        self.apply_commit(block);
    }

    fn stage_app_validator_updates(&mut self, result: CommitResult, block: &Block) {
        if !result.validator_updates.is_empty() {
            tracing::info!(
                target: TRACE_TARGET,
                height = block.header.height.0,
                view = block.header.view.0,
                count = result.validator_updates.len(),
                "app_validator_updates_staged",
            );
            self.staged_validator_updates
                .extend(result.validator_updates);
        }
        if !result.effects.is_empty() {
            tracing::info!(
                target: TRACE_TARGET,
                height = block.header.height.0,
                view = block.header.view.0,
                count = result.effects.len(),
                "app_validator_effects_staged",
            );
            self.staged_effects.extend(result.effects);
        }
    }

    pub(super) fn apply_commit(&mut self, block: Block) {
        self.mempool.remove_committed(&block.commands);

        if block.header.height.0 > self.last_committed_height.load(Ordering::Relaxed) {
            self.last_committed_height
                .store(block.header.height.0, Ordering::Relaxed);
            self.last_committed_view = block.header.view;
        }

        let block_hash = block.hash();

        if let Some(msg) = super::weak_subjectivity_violation(
            self.weak_subjectivity_checkpoint,
            block.header.height,
            block_hash,
        ) {
            panic!("consensus: {msg}; halting (#642)");
        }
        let key = block_storage_key(&block_hash);
        let height_key = height_storage_key(block.header.height);
        let last_committed = LastCommitted {
            height: Height(self.last_committed_height.load(Ordering::Relaxed)),
            view: self.last_committed_view,
            last_committed_hash: block_hash,
        };

        let prune_targets = match prune_targets_for_commit(
            self.storage.as_ref(),
            last_committed.height,
            self.block_retention_window,
        ) {
            Ok(targets) => targets,
            Err(e) => {
                tracing::error!(
                    target: TRACE_TARGET,
                    height = block.header.height.0,
                    view = block.header.view.0,
                    error = %e,
                    "block_prune_scan_failed",
                );
                Vec::new()
            }
        };
        let put_result = (|| -> anyhow::Result<()> {
            let block_bytes = encode_block(&block)?;
            let last_committed_bytes = encode_last_committed(&last_committed)?;
            self.storage.batch(|b| {
                b.put(&key, &block_bytes);
                b.put(&height_key, &block_hash);
                b.put(STORAGE_KEY_LAST_COMMITTED, &last_committed_bytes);
                for target in &prune_targets {
                    b.delete(&target.height_key);
                    if let Some(block_key) = &target.block_key {
                        b.delete(block_key);
                    }
                }
                Ok(())
            })
        })();
        if let Err(e) = put_result {
            tracing::error!(
                target: TRACE_TARGET,
                height = block.header.height.0,
                view = block.header.view.0,
                hash = ?block_hash,
                error = %e,
                "block_persist_failed",
            );

            panic!(
                "consensus: durable persist of committed block failed (height={}, view={}, hash={:?}): {e}; halting to prevent SM/last_committed divergence",
                block.header.height, block.header.view, block_hash,
            );
        }

        tracing::info!(
            "consensus: committed block height={} view={}",
            block.header.height,
            block.header.view,
        );

        if self.snapshot_policy.should_snapshot_at(block.header.height) {
            if let Err(e) = self.try_take_snapshot(&block) {
                tracing::error!(
                    target: TRACE_TARGET,
                    height = block.header.height.0,
                    view = block.header.view.0,
                    error = %e,
                    "snapshot_create_failed",
                );
            }
        }

        self.apply_committed_reconfigs(&block);

        self.apply_committed_rotations(&block);

        self.apply_committed_evidence(&block);

        self.apply_committed_endpoints(&block);

        self.apply_committed_param_updates(&block);

        {
            let view = block.header.view;
            let qc = self.recent_qcs.lock().get(&block_hash).cloned();
            if let Some(qc) = qc {
                let set_at = self.validator_history.set_at(view);
                let set = set_at.for_view(view);
                let members: Vec<boule_consensus::validator_set::ValidatorId> =
                    set.iter().copied().collect();
                let credited: Vec<boule_consensus::validator_set::ValidatorId> = qc
                    .signer_indices()
                    .filter_map(|i| members.get(i).copied())
                    .collect();
                self.liveness_tracker.observe(&members, &credited);
            }
        }

        if let Some(notifier) = &self.commit_notifier {
            notifier.on_commit(&block, &block.header.state_commitment, block.header.view);
        }

        for target in &prune_targets {
            tracing::debug!(
                target: TRACE_TARGET,
                pruned_height = target.height.map(|h| h.0),
                malformed_index = target.block_key.is_none(),
                last_committed_height = last_committed.height.0,
                retention_window = self.block_retention_window,
                "block_pruned",
            );
        }
    }
}

#[derive(Debug)]
struct PruneTarget {
    height: Option<Height>,
    height_key: Vec<u8>,
    block_key: Option<Vec<u8>>,
}

fn prune_targets_for_commit(
    storage: &dyn Storage,
    last_committed_height: Height,
    retention_window: u64,
) -> anyhow::Result<Vec<PruneTarget>> {
    if retention_window == 0 {
        return Ok(Vec::new());
    }
    let prune_below = match last_committed_height.0.checked_sub(retention_window) {
        Some(floor) => floor,
        None => return Ok(Vec::new()),
    };
    let mut out = Vec::new();
    for (key, hash_bytes) in storage.scan_prefix(STORAGE_KEY_HEIGHT_PREFIX)? {
        let height = decode_height_storage_key(&key);
        if let Some(h) = height
            && h.0 >= prune_below
        {
            break;
        }
        let block_key: Option<Vec<u8>> = (*hash_bytes)
            .try_into()
            .ok()
            .map(|hash: BlockHash| block_storage_key(&hash));
        out.push(PruneTarget {
            height,
            height_key: key.to_vec(),
            block_key,
        });
    }
    Ok(out)
}
