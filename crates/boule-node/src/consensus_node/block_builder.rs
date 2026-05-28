//! [`BlockBuilder`] that assembles a child block from the local mempool
//! and the current committed state machine.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;

use boule_consensus::hotstuff::QuorumCertificate;
use boule_consensus::hotstuff::step::BlockBuilder;
use boule_consensus::replication::block::{Block, BlockHash, BlockHeader};
use boule_consensus::replication::mempool::Mempool;
use boule_consensus::replication::state_machine::StateMachine;
use boule_consensus::{Height, View};
use boule_transport_tcp::NodeId;

use super::TRACE_TARGET;

/// [`BlockBuilder`] that assembles a child block from the local mempool
/// and the current committed state machine.
///
/// `state_commitment` is computed by forking the committed SM state:
/// snapshot → walk uncommitted ancestors of `parent` and apply their
/// commands → apply candidate commands → read commitment → restore.
/// In the steady-state pipelined path (leader at view `v` proposes
/// while views `v − 1`, `v − 2` are still uncommitted), the
/// uncommitted-ancestor walk is what makes the leader's stamped
/// commitment match what every replica computes from its own
/// SM-after-uncommitted-ancestors. See [`MempoolBlockBuilder::build`]
/// for the walk algorithm.
pub struct MempoolBlockBuilder {
    self_id: NodeId,
    mempool: Arc<dyn Mempool>,
    /// Shared with the event loop's `Commit` handler, which advances
    /// this SM forward when blocks commit.
    state_machine: Arc<Mutex<Box<dyn StateMachine>>>,
    /// Shared height of the most-recently-committed block. The
    /// integration layer ([`super::ConsensusNode::apply_commit`] and
    /// [`super::ConsensusNode::restore_from_snapshot`]) writes; the builder
    /// reads to bound the uncommitted-ancestor walk so genesis
    /// (height 0, pre-seeded into `pending_blocks`) and any
    /// recovery-seeded block at-or-below the committed boundary
    /// are not re-applied to the SM.
    last_committed_height: Arc<AtomicU64>,
    /// Cumulative count of commands the builder dropped because
    /// `StateMachine::apply` returned `Err` (issue #376). Read by
    /// [`super::ConsensusNode::build_status`] and surfaced under
    /// `ConsensusStatus::dropped_commands` so an operator can spot
    /// a flood of rejected commands without grepping logs.
    dropped_commands: Arc<AtomicU64>,
    propose_limit: usize,
}

impl MempoolBlockBuilder {
    pub fn new(
        self_id: NodeId,
        mempool: Arc<dyn Mempool>,
        state_machine: Arc<Mutex<Box<dyn StateMachine>>>,
        last_committed_height: Arc<AtomicU64>,
        dropped_commands: Arc<AtomicU64>,
        propose_limit: usize,
    ) -> Self {
        Self {
            self_id,
            mempool,
            state_machine,
            last_committed_height,
            dropped_commands,
            propose_limit,
        }
    }
}

impl BlockBuilder for MempoolBlockBuilder {
    /// Compute `state_commitment` for the new block over the chain
    /// `last_committed → … → parent → candidate`:
    ///
    /// 1. Walk `parent`'s ancestors backwards via `pending_blocks`,
    ///    keeping every block whose `header.height` is strictly
    ///    above the integration layer's `last_committed_height`. The
    ///    walk terminates either when the next `parent_hash` is
    ///    absent from `pending_blocks` (the boundary is the
    ///    last-committed block, pruned by `step::on_proposal_received`
    ///    after each three-chain commit) or when the walk reaches a
    ///    block at or below the committed boundary (genesis pre-seed
    ///    or a recovery-seeded block).
    /// 2. Snapshot the SM, apply the collected ancestors' commands
    ///    in oldest-first order, then apply the mempool-pulled
    ///    candidate commands. Read `state_commitment` after each
    ///    successful `apply` per the [`StateMachine`] contract that a
    ///    failed command is a no-op.
    /// 3. Restore the SM to the snapshot.
    ///
    /// Determinism: `pending_blocks` is read by hash-only `.get()`
    /// during the parent-pointer walk (see
    /// [`uncommitted_ancestor_chain`]) — never iterated. The chain is
    /// then applied in `Vec` order. Two honest replicas computing
    /// `state_commitment` for the same `(parent, candidate-commands)`
    /// will produce byte-equal `Block`s, regardless of the underlying
    /// `HashMap` iteration order. Audit Finding 5-3 / issue #426.
    fn build(
        &self,
        parent: &Block,
        view: View,
        _high_qc: &QuorumCertificate,
        pending_blocks: &HashMap<BlockHash, Block>,
    ) -> anyhow::Result<Block> {
        let commands = self.mempool.propose(self.propose_limit);

        // Walk parent's uncommitted ancestor chain. The result is
        // newest-first; reversing gives the apply order.
        let committed_height = Height(self.last_committed_height.load(Ordering::Relaxed));
        let ancestor_chain = uncommitted_ancestor_chain(parent, pending_blocks, committed_height);

        // Fork the committed SM state: snapshot, apply ancestor commands
        // and candidate commands, read commitment, then restore so the
        // SM is left unchanged.
        let state_commitment = {
            let mut sm = self.state_machine.lock();
            let snap = sm.snapshot();

            let mut commitment = sm.state_commitment();
            // Apply each in-flight ancestor's commands in chain order,
            // oldest first, then the candidate commands on top. A
            // failed `apply` leaves state unchanged per the
            // [`StateMachine`] contract, so the commitment is
            // consistent with "skip bad cmds" — which is exactly what
            // every replica's own apply will produce on the same
            // input. The silent drop hid bugs from operators
            // (issue #376), so emit a warn-level event per failure
            // so a flood of rejected commands shows up in the logs.
            // Ancestor `cmd_idx` is reported as `(height, idx)` so
            // operators can disambiguate from candidate-command
            // failures (which carry only `cmd_idx`).
            for ancestor in ancestor_chain.iter().rev() {
                for (cmd_idx, cmd) in ancestor.commands.iter().enumerate() {
                    match sm.apply(cmd) {
                        Ok(_) => {
                            commitment = sm.state_commitment();
                        }
                        Err(e) => {
                            self.dropped_commands.fetch_add(1, Ordering::Relaxed);
                            tracing::warn!(
                                target: TRACE_TARGET,
                                view = view.0,
                                ancestor_height = ancestor.header.height.0,
                                cmd_idx,
                                error = %e,
                                "block_builder_ancestor_command_apply_failed",
                            );
                        }
                    }
                }
            }
            for (cmd_idx, cmd) in commands.iter().enumerate() {
                match sm.apply(cmd) {
                    Ok(_) => {
                        commitment = sm.state_commitment();
                    }
                    Err(e) => {
                        self.dropped_commands.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(
                            target: TRACE_TARGET,
                            view = view.0,
                            cmd_idx,
                            error = %e,
                            "block_builder_command_apply_failed",
                        );
                    }
                }
            }

            // Restore SM to committed state regardless of outcome. On
            // the happy path this is the inverse of `sm.snapshot()`
            // captured a few lines above and never fails; in the
            // pathological case (corrupt redb table, half-finished
            // migration, version skew across an upgrade, on-disk
            // bit-flip) the round trip can fail. Surface the error
            // to the safety core so it skips this view's proposal —
            // the next-view leader takes over — rather than
            // panicking. Audit finding 4-F3, issue #326.
            let snap_len = snap.len();
            if let Err(e) = sm.restore(&snap) {
                tracing::error!(
                    target: TRACE_TARGET,
                    view = view.0,
                    parent_height = parent.header.height.0,
                    ancestor_chain_len = ancestor_chain.len(),
                    snap_bytes = snap_len,
                    error = %e,
                    "block_builder_restore_failed",
                );
                anyhow::bail!(
                    "MempoolBlockBuilder: state-machine restore from own snapshot failed: {e}",
                );
            }
            commitment
        };

        let commands_commitment = Block::commands_commitment(&commands);
        Ok(Block {
            header: BlockHeader {
                parent_hash: parent.hash(),
                height: parent.header.height + 1,
                view,
                proposer: self.self_id,
                state_commitment,
                commands_commitment,
                validator_history_commitment: [0; 32],
            },
            commands,
        })
    }
}

/// Walk `parent`'s ancestors backwards through `pending_blocks`,
/// returning every block whose height is strictly above
/// `committed_height` — i.e. the uncommitted-ancestor chain that the
/// builder must fold into its `state_commitment`.
///
/// The result is newest-first (`parent` is element 0 if it is
/// uncommitted); callers iterating in apply order should reverse it.
///
/// The walk stops when:
/// - the cursor's height drops to or below `committed_height` (the
///   committed boundary; genesis pre-seed or recovery-seeded blocks
///   live below this line), or
/// - the cursor's `parent_hash` is missing from `pending_blocks`
///   (post-commit prune has removed the last-committed block).
///
/// `pending_blocks` is read **by hash-only `.get()`** — never iterated.
/// The walk's order comes from the parent-pointer chain itself, so the
/// underlying `HashMap`'s non-deterministic iteration order is not
/// observable in the result. This is the determinism property the
/// builder relies on for cross-replica equality of `state_commitment`
/// (audit Finding 5-3 / issue #426).
fn uncommitted_ancestor_chain(
    parent: &Block,
    pending_blocks: &HashMap<BlockHash, Block>,
    committed_height: Height,
) -> Vec<Block> {
    let mut chain = Vec::new();
    let mut cursor = parent.clone();
    loop {
        if cursor.header.height <= committed_height {
            // cursor is committed (genesis pre-seed or a
            // recovery-seeded committed block); not part of the
            // uncommitted chain.
            break;
        }
        let parent_hash = cursor.header.parent_hash;
        chain.push(cursor);
        match pending_blocks.get(&parent_hash) {
            Some(next) => cursor = next.clone(),
            None => break,
        }
    }
    chain
}
