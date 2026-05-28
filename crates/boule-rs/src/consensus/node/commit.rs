//! Block-commit handler. Applies committed commands to the state
//! machine, drains the mempool, persists the committed block and the
//! `last_committed` checkpoint, then delegates to the
//! reconfig/rotation/snapshot siblings.

use std::sync::atomic::Ordering;

use crate::consensus::Height;
use crate::consensus::crashpoint::crashpoint;
use crate::replication::block::{Block, BlockHash};
use crate::storage::{Storage, StorageExt};

use super::{
    ConsensusNode, LastCommitted, STORAGE_KEY_HEIGHT_PREFIX, STORAGE_KEY_LAST_COMMITTED,
    TRACE_TARGET, block_storage_key, decode_height_storage_key, encode_block,
    encode_last_committed, height_storage_key,
};

impl ConsensusNode {
    /// Commit `block` to the state machine and drain the committed commands
    /// from the mempool.
    ///
    /// # Durability
    ///
    /// Every committed block is also written to durable storage under
    /// `consensus/block/<hash>` together with an updated
    /// `consensus/last_committed` checkpoint, applied as a single atomic
    /// batch. Two reasons:
    ///
    /// 1. **Block-sync responder fallback.** A peer that requests a
    ///    block we have already evicted from `pending_blocks` (or that
    ///    we have not yet re-inserted post-restart, since the in-memory
    ///    cache is rebuilt empty) must still be served. The
    ///    [`crate::consensus::dispatch::Dispatch::ServeBlock`] arm
    ///    consults storage when `pending_blocks` misses; without the
    ///    put here, the lookup would return `None` and our peer would
    ///    loop forever on its `RequestBlock` retries (#178 reopen).
    /// 2. **Status accuracy after restart.** `last_committed_height`
    ///    is otherwise an in-memory counter; `consensus_resumed` would
    ///    report `0` post-restart even when storage attests to a long
    ///    chain of commits. Persisting the checkpoint lets [`Self::recover`]
    ///    rebuild the counter at boot.
    ///
    /// Storage backend errors are logged at `error` and otherwise
    /// swallowed: the safety-core contract is satisfied as long as
    /// `last_voted_view` / `locked` / `high_qc` are flushed (which
    /// happens through [`Self::persist_updates`] before any outbound vote),
    /// so a transient block-store hiccup must not stop liveness.
    pub(super) fn apply_commit(&mut self, block: Block) {
        {
            let mut sm = self.state_machine.lock();
            for cmd in &block.commands {
                if let Err(e) = sm.apply(cmd) {
                    tracing::error!(
                        "consensus: SM apply failed for committed block (height={}, view={}): {e}",
                        block.header.height,
                        block.header.view,
                    );
                }
            }
        }
        self.mempool.remove_committed(&block.commands);
        // Track the most recent commit for the status snapshot. The
        // safety core emits `Action::Commit` in height order, so a
        // plain max-by-value assignment keeps this monotonic without
        // any extra bookkeeping.
        if block.header.height.0 > self.last_committed_height.load(Ordering::Relaxed) {
            self.last_committed_height
                .store(block.header.height.0, Ordering::Relaxed);
            self.last_committed_view = block.header.view;
        }
        // Persist (block, height-index, last_committed) atomically so
        // the responder path and the status snapshot agree on durable
        // state. The height index lets us cheaply find the oldest
        // committed blocks at prune time without scanning the full
        // hash-keyed table — see the doc-comment for the rest of the
        // why. Pruning runs in the same batch (#194) so a crash mid-
        // commit either leaves the chain unchanged or advances by one
        // commit; there's no intermediate "wrote new block but didn't
        // delete old one" state to recover from.
        let block_hash = block.hash();
        let key = block_storage_key(&block_hash);
        let height_key = height_storage_key(block.header.height);
        let last_committed = LastCommitted {
            height: Height(self.last_committed_height.load(Ordering::Relaxed)),
            view: self.last_committed_view,
            last_committed_hash: block_hash,
        };
        // Compute the prune set up front so the batch closure stays
        // pure (no `?` paths inside): a backend error during the
        // pre-scan should fail the whole commit-persist below, not
        // poison a partially-built batch.
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
            // Audit finding 4-2 / issue #411: the SM has already
            // applied above and the safety core has already retired
            // `pending_blocks` for this commit, but the durable
            // (block, last_committed) batch did not land. Returning
            // here would let the snapshot creation hook, reconfig /
            // rotation appliers, and the CommitNotifier fan-out fire
            // against a non-durable commit — on restart the durable
            // checkpoint would not reflect the commit, leaving SM
            // state and `last_committed` divergent. Halt the node so
            // an operator sees the failure and recovery starts from
            // the durable checkpoint as the single source of truth.
            panic!(
                "consensus: durable persist of committed block failed (height={}, view={}, hash={:?}): {e}; halting to prevent SM/last_committed divergence",
                block.header.height, block.header.view, block_hash,
            );
        }
        // After the committed block + last_committed batch is durable
        // but BEFORE any downstream side effect (snapshot creation,
        // reconfig/rotation application, commit-notifier fan-out)
        // runs. Audit finding 4-2 / issue #411 gates those downstream
        // actions on the durable block write — the panic above is
        // what enforces the gate; a regression that turned it back
        // into a logged-and-continue would let the snapshot creation
        // hook fire against a block that did not in fact reach disk.
        crashpoint!("after_apply_commit_block_persist");
        tracing::info!(
            "consensus: committed block height={} view={}",
            block.header.height,
            block.header.view,
        );
        // Take a snapshot when the configured policy fires. This runs
        // after the block is persisted (so an aborted snapshot leaves
        // the chain intact) and before the commit observer fires (so
        // tests subscribing to the commit channel can sequence on
        // snapshot creation completion). Errors are logged and swallowed
        // — snapshots are an optimization, not a correctness path.
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
        // #272: scan the committed block's commands for any tagged
        // ReconfigCommand payloads and apply them to the validator
        // history. Done after the block is durably persisted so a
        // crash mid-apply leaves the chain intact and recovery can
        // re-derive the boundary on next replay (#254). Errors log
        // and drop — the block itself stays committed since the
        // safety core is independent of payload validity.
        self.apply_committed_reconfigs(&block);
        // #260: same treatment for tagged DualSignedRotation
        // payloads. Reconfigs come first so that a rotation
        // committed in the same block as a reconfig sees the
        // post-reconfig key history (the rotation tx's `validator`
        // field must resolve via the reverse index, which a
        // reconfig-added validator will be present in only after
        // the reconfig has applied — though in practice committing
        // both in the same block is unusual).
        self.apply_committed_rotations(&block);
        if let Some(notifier) = &self.commit_notifier {
            notifier.on_commit(&block, &block.header.state_commitment, block.header.view);
        }
        // Emit one pruning trace per evicted block. Done after the
        // durable batch lands so the counter and the disk state agree.
        // Each event surfaces the height that was pruned and the
        // post-commit retention floor so an operator can read the log
        // and recompute the window without cross-referencing config.
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

/// One block to evict on the current commit. `block_key` is `None`
/// when the height-index row was structurally malformed (its value
/// was not a 32-byte hash); the index row is still scheduled for
/// deletion to stop it tripping every future commit.
#[derive(Debug)]
struct PruneTarget {
    height: Option<Height>,
    height_key: Vec<u8>,
    block_key: Option<Vec<u8>>,
}

/// Compute the blocks to evict from durable storage as part of the
/// current commit. Returns an empty vec when:
///
/// - `retention_window == 0` (archive mode),
/// - `last_committed_height < retention_window` (chain not yet long
///   enough to have anything past the floor),
/// - or the height index is empty.
///
/// Otherwise scans `consensus/height/*` in ascending order and
/// collects every `(h, hash)` pair with `h < last_committed_height -
/// retention_window`. The scan is bounded: redb returns the index in
/// numeric order (because the keys are big-endian u64), and on a
/// healthy node only a single entry is below the floor on each
/// commit. Operators flipping retention on after a long archive run
/// may see a one-time burst here — that's intentional. See #194.
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
            // Heights are stored big-endian and scan_prefix yields in
            // ascending lex order, so once we cross the floor every
            // remaining entry is in-window.
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
