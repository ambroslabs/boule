//! [`BlockBuilder`] that assembles a child block from the local mempool
//! and the current committed state machine.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;

use boule_consensus::hotstuff::QuorumCertificate;
use boule_consensus::hotstuff::step::BlockBuilder;
use boule_consensus::replication::application::{AppContext, Application, CommitResult};
use boule_consensus::replication::block::{Block, BlockHash, BlockHeader};
use boule_consensus::replication::mempool::Mempool;
use boule_consensus::replication::reward_ledger::{RewardConfig, RewardLedger};
use boule_consensus::replication::stake_source::StakeSource;
use boule_consensus::replication::state_machine::{CommandValidator, StateMachine};
use boule_consensus::{Height, View};
use boule_core::clock::BoxFuture;
use boule_core::identity::NodeId;

use super::TRACE_TARGET;
use crate::demo_staking::StakeCommand;

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
    /// Pluggable source of the weighted validator set (#654). The demo
    /// backend routes tagged [`StakeCommand`]s into this CL-native ledger at
    /// `commit` and returns the resulting validator-set deltas. Behind a
    /// `Box<dyn StakeSource>` so an EVM/Cosmos source (#655) can replace it
    /// without touching the builder. `Mutex` because `commit` is `&self`.
    stake_source: Mutex<Box<dyn StakeSource>>,
    /// Lazy validator-reward accrual (#659a). Inert unless `reward_config` is
    /// enabled — rewards are optional, so the default backend rewards nothing.
    reward_ledger: Mutex<RewardLedger>,
    /// Reward policy: per-block issuance + proposer bonus. All-zero disables.
    reward_config: RewardConfig,
    /// Stateless includability predicate (#607), captured from the state
    /// machine once at construction. Used by the build *and* vote paths so
    /// the includability check never locks the mutable `state_machine`
    /// (`check` is stateless by contract, so a one-time snapshot is exact).
    validator: Arc<dyn CommandValidator>,
}

impl MempoolBlockBuilder {
    pub fn new(
        self_id: NodeId,
        mempool: Arc<dyn Mempool>,
        state_machine: Arc<Mutex<Box<dyn StateMachine>>>,
        last_committed_height: Arc<AtomicU64>,
        dropped_commands: Arc<AtomicU64>,
        propose_limit: usize,
        stake_source: Box<dyn StakeSource>,
    ) -> Self {
        // Capture the stateless includability validator once (#607); the
        // check paths then never lock `state_machine`.
        let validator = state_machine.lock().validator();
        Self {
            self_id,
            mempool,
            state_machine,
            last_committed_height,
            dropped_commands,
            propose_limit,
            stake_source: Mutex::new(stake_source),
            reward_ledger: Mutex::new(RewardLedger::new()),
            reward_config: RewardConfig::default(),
            validator,
        }
    }

    /// Enable implicit protocol rewards with `config` (#659a). Off by default.
    pub fn with_reward_config(mut self, config: RewardConfig) -> Self {
        self.reward_config = config;
        self
    }

    /// Total claimable reward of `node_id` (settled + unsettled), reading the
    /// validator's current stake from the source. For status / tests.
    pub fn reward_balance_of(&self, node_id: &NodeId) -> u64 {
        let stake = self.stake_source.lock().stake_of(node_id);
        self.reward_ledger.lock().claimable(node_id, stake)
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
        timestamp: u64,
    ) -> anyhow::Result<Block> {
        // Clamp to the parent so block time is non-decreasing even if the
        // wall clock jumped backward since the parent was built (NTP,
        // suspend/resume); a strictly correct `validate_structural` then
        // never rejects an honest proposal on time alone.
        let timestamp = timestamp.max(parent.header.timestamp);
        let mut commands = self.mempool.propose(self.propose_limit);

        // Walk parent's uncommitted ancestor chain. The result is
        // newest-first; reversing gives the apply order.
        let committed_height = Height(self.last_committed_height.load(Ordering::Relaxed));
        let ancestor_chain = uncommitted_ancestor_chain(parent, pending_blocks, committed_height);

        // Fork the committed SM state: snapshot, apply ancestor commands
        // and candidate commands, read commitment, then restore so the
        // SM is left unchanged.
        //
        // `committed_state_root` is the SM commitment over our committed
        // frontier (`committed_height`) *before* applying any uncommitted
        // ancestor or candidate commands — the deferred (lagged) root a
        // voter reproduces from its own committed execution before voting.
        // It is read here, inside the lock, while the SM is still at the
        // committed state.
        let (state_commitment, committed_state_root) = {
            let mut sm = self.state_machine.lock();
            let snap = sm.snapshot();

            let mut commitment = sm.state_commitment();
            let committed_state_root = commitment;
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
                    // App-level stake commands (the demo backend) are not
                    // counter-SM commands — skip them here so they neither
                    // fail `apply` nor affect the counter commitment.
                    if StakeCommand::is_stake_payload(cmd) {
                        continue;
                    }
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
            // Leader-side includability filter (#598). Drop candidate
            // application commands the state machine declares not
            // well-formed enough to include, so this leader never proposes
            // a block carrying them. System txs (rotation/reconfig) are
            // consensus-layer commands, not the SM's domain — their
            // validity is checked at commit — so they pass through
            // untouched. Order-preserving via `retain`.
            commands.retain(|cmd| {
                if boule_consensus::validator_rotation::DualSignedRotation::is_rotation_payload(cmd)
                    // Rotation-cancel system txs (#317): validated + applied at
                    // commit, like the rotation they retract.
                    || boule_consensus::validator_rotation::DualSignedRotationCancel::is_cancel_payload(cmd)
                    // Operator-signed recovery rotations (#549): authorised by
                    // the operator key, validated + applied at commit.
                    || boule_consensus::validator_rotation::OperatorSignedRotation::is_operator_rotation_payload(cmd)
                    // Operator-key self-rotations (#549): validated + applied at commit.
                    || boule_consensus::validator_rotation::DualSignedOperatorRotation::is_operator_key_rotation_payload(cmd)
                    || boule_consensus::reconfig::ReconfigCommand::is_reconfig_payload(cmd)
                    // Equivocation-evidence system txs (#657): self-authenticating
                    // proofs validated + recorded at commit, like reconfig/rotation.
                    || boule_consensus::equivocation_evidence::is_evidence_payload(cmd)
                    // Consensus-parameter-update system txs (#542): validated +
                    // scheduled at commit, like reconfig/rotation.
                    || boule_consensus::consensus_params::ConsensusParamUpdate::is_param_update_payload(cmd)
                    // Endpoint-advertisement system txs (#546/#731): validated +
                    // applied at commit, like reconfig/rotation.
                    || boule_consensus::endpoint_registry::SignedEndpointCommand::is_endpoint_payload(cmd)
                    // App-level stake commands (the demo backend) are
                    // includable by the application even though the counter
                    // SM doesn't decode them; `commit` turns them into
                    // validator updates.
                    || StakeCommand::is_stake_payload(cmd)
                {
                    return true;
                }
                // Includability via the stateless validator handle (#607),
                // not the locked `sm` — the predicate doesn't touch apply
                // state.
                match self.validator.check(cmd) {
                    Ok(()) => true,
                    Err(e) => {
                        self.dropped_commands.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(
                            target: TRACE_TARGET,
                            view = view.0,
                            error = %e,
                            "block_builder_command_check_rejected",
                        );
                        false
                    }
                }
            });
            for (cmd_idx, cmd) in commands.iter().enumerate() {
                if StakeCommand::is_stake_payload(cmd) {
                    continue;
                }
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
            (commitment, committed_state_root)
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
                committed_height,
                committed_state_root,
                timestamp,
            },
            commands,
        })
    }
}

impl Application for MempoolBlockBuilder {
    /// The counter application's build path is genuine in-process work
    /// (mempool pull + SM fork), so there is nothing to `await`: it runs
    /// the synchronous [`BlockBuilder::build`] and returns an
    /// already-resolved future. The async signature exists for the
    /// out-of-process case (a reth execution layer building a payload
    /// over the Engine API), where this future would not resolve until
    /// the remote round trip completes.
    fn build_proposal<'a>(
        &'a self,
        _ctx: &'a AppContext,
        parent: &'a Block,
        view: View,
        high_qc: &'a QuorumCertificate,
        pending_blocks: &'a HashMap<BlockHash, Block>,
        timestamp: u64,
    ) -> BoxFuture<'a, anyhow::Result<Block>> {
        let built = BlockBuilder::build(self, parent, view, high_qc, pending_blocks, timestamp);
        Box::pin(async move { built })
    }

    /// #658b: zero the equivocator's bonded stake in the CL-native ledger.
    /// The resulting `weight 0` delta is drained by the next `commit`'s
    /// `take_updates`, merging with the jail-remove (#658a) in the reconfig.
    fn slash(&self, node_id: NodeId) {
        self.stake_source.lock().slash(node_id);
    }

    /// The counter application's commit is in-process: lock the shared
    /// state machine and apply the committed block's commands. A failed
    /// `apply` is a no-op per the [`StateMachine`] contract — it is logged
    /// and skipped, never propagated, because consensus commits the block
    /// regardless of execution outcome. There is no real I/O, so the
    /// future is already resolved; a reth EL would instead `await` the
    /// Engine-API round trip here.
    ///
    /// As the demo app-driven-validator backend (#225 M6), it also
    /// recognises tagged [`StakeCommand`]s: these are not counter-SM
    /// commands, so they are surfaced as `validator_updates` rather than
    /// applied to the state machine, driving an app-driven validator-set
    /// change through the deferred-materialisation path (#225 M5).
    fn commit<'a>(
        &'a self,
        _ctx: &'a AppContext,
        block: &'a Block,
    ) -> BoxFuture<'a, anyhow::Result<CommitResult>> {
        Box::pin(async move {
            let mut stake = self.stake_source.lock();
            // Advance the stake clock first so this block's unbondings schedule
            // against the right height and matured ones release (#660).
            stake.advance_to_height(block.header.height);
            // #659a: accrue this block's reward over the active set + credit the
            // proposer bonus (O(1); validators settle lazily on staking events).
            if self.reward_config.is_enabled() {
                self.reward_ledger.lock().accrue_block(
                    block.header.proposer,
                    self.reward_config.issuance_per_block,
                    self.reward_config.proposer_bonus,
                    stake.total_stake(),
                );
            }
            let mut sm = self.state_machine.lock();
            for cmd in &block.commands {
                if StakeCommand::is_stake_payload(cmd) {
                    match StakeCommand::decode(cmd) {
                        // Route the stake op into the CL-native source; the
                        // resulting validator-set deltas are drained below.
                        Ok(c) => {
                            // Settle the validator's accrued reward at its
                            // current stake *before* the stake changes (#659a).
                            if self.reward_config.is_enabled() {
                                self.reward_ledger
                                    .lock()
                                    .settle(c.node_id, stake.stake_of(&c.node_id));
                            }
                            stake.apply(c.node_id, c.op);
                        }
                        Err(e) => tracing::warn!(
                            target: TRACE_TARGET,
                            height = block.header.height.0,
                            error = %e,
                            "demo_stake_command_malformed",
                        ),
                    }
                    continue;
                }
                if let Err(e) = sm.apply(cmd) {
                    tracing::error!(
                        "consensus: SM apply failed for committed block (height={}, view={}): {e}",
                        block.header.height,
                        block.header.view,
                    );
                }
            }
            Ok(CommitResult {
                validator_updates: stake.take_updates(),
                ..Default::default()
            })
        })
    }

    // The counter application's state queries delegate to the shared
    // in-process state machine under its lock.

    fn check(&self, cmd: &[u8]) -> anyhow::Result<()> {
        // App-level stake commands (the demo backend) are includable even
        // though the counter SM doesn't decode them — `commit` turns them
        // into validator updates. This is what lets the vote-time
        // includability check (which calls `app.check`) accept a block
        // carrying a stake command.
        if StakeCommand::is_stake_payload(cmd) {
            return Ok(());
        }
        // #607: the includability predicate runs on the stateless validator
        // handle, so the vote path never locks the mutable state machine.
        self.validator.check(cmd)
    }

    fn state_commitment(&self) -> [u8; 32] {
        self.state_machine.lock().state_commitment()
    }

    fn snapshot(&self) -> bytes::Bytes {
        self.state_machine.lock().snapshot()
    }

    fn restore(&self, snap: &[u8]) -> anyhow::Result<()> {
        self.state_machine.lock().restore(snap)
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

#[cfg(test)]
mod tests {
    use super::*;
    use boule_consensus::replication::impls::counter_sm::CounterCommand;
    use boule_consensus::replication::impls::{CounterStateMachine, InMemoryMempool};
    use bytes::Bytes;

    /// The leader-side includability filter (#598) drops candidate
    /// application commands the state machine rejects via `check`, keeps
    /// well-formed ones, and passes system txs (rotation/reconfig) through
    /// untouched.
    #[test]
    fn build_drops_non_includable_app_commands_and_keeps_system_txs() {
        let mempool: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(64));
        let valid = CounterCommand::Increment.encode();
        // An undecodable application command — rejected at `check`.
        let garbage = Bytes::from_static(&[0x07]);
        // A system tx (rotation-tagged). `check` is never consulted for it;
        // it passes through and is applied at commit by the rotation path.
        let mut system = Vec::from(*boule_consensus::validator_rotation::ROTATION_TAG);
        system.push(0xAA);
        let system = Bytes::from(system);

        mempool.insert(valid.clone()).unwrap();
        mempool.insert(garbage.clone()).unwrap();
        mempool.insert(system.clone()).unwrap();

        let dropped = Arc::new(AtomicU64::new(0));
        let builder = MempoolBlockBuilder::new(
            [1u8; 32],
            Arc::clone(&mempool),
            Arc::new(Mutex::new(
                Box::new(CounterStateMachine::new()) as Box<dyn StateMachine>
            )),
            Arc::new(AtomicU64::new(0)),
            Arc::clone(&dropped),
            64,
            Box::new(boule_consensus::replication::stake_source::BondedStakeLedger::empty()),
        );

        let genesis = Block::genesis([0; 32], [0; 32]);
        let qc = QuorumCertificate::new(0, genesis.hash(), 4);
        let block = builder
            .build(&genesis, View(1), &qc, &HashMap::new(), 0)
            .expect("build must succeed");

        assert!(
            block.commands.contains(&valid),
            "the well-formed application command must be included",
        );
        assert!(
            block.commands.contains(&system),
            "the system tx must pass through and be included",
        );
        assert!(
            !block.commands.contains(&garbage),
            "the non-includable application command must be dropped",
        );
        assert_eq!(block.commands.len(), 2);
        // At least the garbage rejection bumped the counter (the system tx
        // also fails `apply` since it isn't a CounterCommand, which is the
        // pre-existing behaviour).
        assert!(dropped.load(Ordering::Relaxed) >= 1);
    }

    /// #659a: with rewards enabled, a committed block credits the proposer's
    /// bonus and accrues issuance stake-proportionally across the active set.
    #[tokio::test]
    async fn reward_accrual_credits_proposer_bonus_and_stake_proportional_issuance() {
        use boule_consensus::replication::reward_ledger::RewardConfig;
        use boule_consensus::replication::stake_source::BondedStakeLedger;

        let v1 = [1u8; 32]; // proposer + staker
        let v2 = [2u8; 32]; // staker, never proposes here
        let builder = MempoolBlockBuilder::new(
            v1,
            Arc::new(InMemoryMempool::new(64)),
            Arc::new(Mutex::new(
                Box::new(CounterStateMachine::new()) as Box<dyn StateMachine>
            )),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
            64,
            Box::new(BondedStakeLedger::seeded_from([(v1, 10), (v2, 10)])),
        )
        .with_reward_config(RewardConfig {
            issuance_per_block: 100,
            proposer_bonus: 5,
        });

        // One block, proposed by v1 (build stamps proposer = self_id).
        let genesis = Block::genesis([0; 32], [0; 32]);
        let qc = QuorumCertificate::new(0, genesis.hash(), 4);
        let block = builder
            .build(&genesis, View(1), &qc, &HashMap::new(), 0)
            .expect("build");
        assert_eq!(block.header.proposer, v1);
        builder
            .commit(&AppContext::default(), &block)
            .await
            .expect("commit");

        // Issuance 100 over total stake 20 → 50 each by share; v1 also gets the
        // proposer bonus of 5.
        assert_eq!(builder.reward_balance_of(&v1), 55);
        assert_eq!(builder.reward_balance_of(&v2), 50);
    }
}
