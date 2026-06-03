//! `RethApplication` — the consensus [`Application`] backed by reth.
//!
//! One boule block carries exactly one command: the opaque EVM execution
//! payload reth built. The mapping, under the deferred-execution model:
//!
//! - [`Application::build_proposal`] (leader) asks reth to build a payload on
//!   the parent block's EVM head and registers it so later builds can chain
//!   on it before it commits (HotStuff pipelining). The boule header's
//!   `state_commitment` is the payload's post-state root; the lagged
//!   `committed_state_root` is reth's committed-frontier root, which every
//!   honest replica reproduces and the QC therefore attests to.
//! - [`Application::commit`] (every node) executes and finalizes the payload
//!   (`newPayloadV3` + `forkchoiceUpdatedV3`), then advances the committed
//!   frontier.
//! - [`Application::check`] is stateless: the command must decode to a
//!   payload carrying a block hash.
//! - [`Application::state_commitment`] is the committed-frontier EVM root.
//! - [`Application::snapshot`]/[`Application::restore`] carry the committed
//!   `(height, root)` only. reth owns the world state in its own database, so
//!   a joiner needs reth's state-sync to execute — a consensus snapshot
//!   cannot reconstruct it. This is a deliberate stub for the single-node
//!   path; full reth state-sync is out of scope.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use boule_consensus::hotstuff::QuorumCertificate;
use boule_consensus::reconfig::ReconfigCommand;
use boule_consensus::replication::application::{
    AppContext, Application, CommitResult, IntegrationCapability, ValidatorUpdate,
};
use boule_consensus::replication::block::{Block, BlockHash, BlockHeader};
use boule_consensus::replication::mempool::Mempool;
use boule_consensus::replication::stake_source::StakeSource;
use boule_consensus::validator_rotation::DualSignedRotation;
use boule_consensus::{Height, View};
use boule_core::clock::BoxFuture;
use boule_core::identity::NodeId;
use bytes::Bytes;
use parking_lot::Mutex;
use serde_json::Value;

use crate::engine::{ElStatus, RethEngine, root_from_hex};
use crate::staking;
use crate::transport::EngineTransport;

/// Max boule system txs to pull from the mempool into one proposal. Only a
/// single reconfig is ever pending (the one-reconfig-at-a-time rule), so this
/// just bounds the scan.
const SYSTEM_TX_LIMIT: usize = 16;

/// The committed frontier reth has executed and finalized: the height of the
/// last committed boule block and its EVM post-state root.
struct Committed {
    height: Height,
    state_root: [u8; 32],
}

/// A consensus [`Application`] that orders and executes EVM payloads via reth.
pub struct RethApplication {
    transport: Box<dyn EngineTransport>,
    self_id: NodeId,
    fee_recipient: String,
    /// reth's genesis block hash — the EVM parent of the first built block.
    reth_genesis_hash: String,
    /// Pause between `forkchoiceUpdatedV3(attrs)` and `getPayloadV3` so reth's
    /// async build can pull pool transactions in before the payload is sealed.
    build_wait: Duration,
    committed: Mutex<Committed>,
    /// Validator-set source-of-truth (#654/#655). The CL-native ledger fed by
    /// the staking predeploy's `Deposit`/`Withdraw` events, which `commit`
    /// reads from each executed block. Seeded from the genesis validator set.
    stake_source: Mutex<Box<dyn StakeSource>>,
    /// boule's mempool, shared with the integration layer. `build_proposal`
    /// pulls pending consensus-layer system txs (reconfig/rotation) from it
    /// into the block — the only path for them onto the reth backend.
    mempool: Arc<dyn Mempool>,
}

impl RethApplication {
    /// `genesis_root` is reth's genesis state root, which must equal the
    /// consensus genesis block's `state_commitment` — the caller verifies that
    /// bridge at startup. `reth_genesis_hash` is reth's genesis block hash, the
    /// EVM parent of the first proposed block.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transport: Box<dyn EngineTransport>,
        self_id: NodeId,
        fee_recipient: impl Into<String>,
        reth_genesis_hash: impl Into<String>,
        genesis_root: [u8; 32],
        build_wait: Duration,
        stake_source: Box<dyn StakeSource>,
        mempool: Arc<dyn Mempool>,
    ) -> Self {
        Self {
            transport,
            self_id,
            fee_recipient: fee_recipient.into(),
            reth_genesis_hash: reth_genesis_hash.into(),
            build_wait,
            committed: Mutex::new(Committed {
                height: Height::ZERO,
                state_root: genesis_root,
            }),
            stake_source: Mutex::new(stake_source),
            mempool,
        }
    }

    fn engine(&self) -> RethEngine<'_> {
        RethEngine::new(&*self.transport, self.fee_recipient.clone())
    }

    /// Read the staking predeploy's `Deposit`/`Withdraw` events for the
    /// just-executed `payload`, apply them to the CL-native stake ledger,
    /// and return the validator-set deltas (#655). Only called once the EL
    /// reports the payload `VALID`, so its logs are available. A failed
    /// `eth_getLogs` is logged and yields no updates — a transient RPC error
    /// must not fail the commit (consensus commits regardless of the EL).
    async fn derive_validator_updates(
        &self,
        payload: &Value,
        height: Height,
    ) -> Vec<ValidatorUpdate> {
        // Read this block's staking events (empty on any failure — the height
        // still advances so unbondings mature, #660).
        let ops = match payload["blockHash"].as_str() {
            Some(block_hash) => match self
                .transport
                .eth_rpc("eth_getLogs", staking::logs_filter(block_hash))
                .await
            {
                Ok(logs) => staking::parse_stake_logs(&logs),
                Err(e) => {
                    tracing::warn!(
                        target: "boule::reth",
                        error = %e,
                        "eth_getLogs for staking events failed; no staking ops this block",
                    );
                    Vec::new()
                }
            },
            None => Vec::new(),
        };
        let mut src = self.stake_source.lock();
        // Advance the ledger clock first (releases matured unbondings, #660),
        // then apply this block's ops so their unbonding release is scheduled
        // relative to this height.
        src.advance_to_height(height);
        for (node_id, op) in ops {
            src.apply(node_id, op);
        }
        src.take_updates()
    }

    /// Backfill the staking events of blocks the EL executed via background
    /// self-sync (snap/full, #631) that `commit` skipped while the EL was
    /// `SYNCING` (#674).
    ///
    /// When the EL reports `VALID` for a block whose height is more than one
    /// past the committed frontier, every block in the gap
    /// `(prev_height, height)` was executed by the EL out-of-band — not through
    /// `commit`, which returned early while `SYNCING` — so its predeploy
    /// staking events were never read and the CL stake ledger would silently
    /// drift from EL state (the root self-heals via `recover_frontier`, but the
    /// ledger has no such re-anchor).
    ///
    /// Each skipped block's events are read *by canonical EVM number* — its
    /// hash is unknown on this path — and applied **at the block's own height**,
    /// exactly as the normal per-block path would, so a node that caught up via
    /// self-sync reaches the byte-identical ledger of one that committed every
    /// block in order (unbonding maturity is height-relative, #660). This
    /// relies on the one-EVM-block-per-committed-boule-block invariant: EVM
    /// block number advances 1:1 with boule height, so the block at boule
    /// height `h` has EVM number `current_number - (height - h)`.
    ///
    /// Applies ops to the ledger but does not drain updates — the caller's
    /// [`Self::derive_validator_updates`] for the current block drains the gap's
    /// and the current block's deltas together.
    async fn backfill_self_synced_gap(&self, payload: &Value, prev_height: Height, height: Height) {
        // No gap: the frontier advanced by exactly one block (the common path).
        if height.0 <= prev_height.0 + 1 {
            return;
        }
        let Some(current_number) = payload["blockNumber"]
            .as_str()
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        else {
            tracing::warn!(
                target: "boule::reth",
                "self-sync backfill: current payload has no parseable blockNumber; \
                 skipping staking reconcile over the gap",
            );
            return;
        };
        tracing::info!(
            target: "boule::reth",
            from = prev_height.0 + 1,
            to = height.0 - 1,
            "self-sync backfill: reconciling staking over EL self-synced gap",
        );
        // Skipped boule heights, oldest first, applied at their own height.
        for h in (prev_height.0 + 1)..height.0 {
            let evm_number = current_number - (height.0 - h);
            let ops = match self
                .transport
                .eth_rpc("eth_getLogs", staking::logs_filter_by_number(evm_number))
                .await
            {
                Ok(logs) => staking::parse_stake_logs(&logs),
                Err(e) => {
                    tracing::warn!(
                        target: "boule::reth",
                        height = h,
                        evm_number,
                        error = %e,
                        "self-sync backfill: eth_getLogs failed; staking events for \
                         this skipped block are lost",
                    );
                    Vec::new()
                }
            };
            let mut src = self.stake_source.lock();
            src.advance_to_height(Height(h));
            for (node_id, op) in ops {
                src.apply(node_id, op);
            }
        }
    }

    /// Reconcile the committed frontier with reality on restart. `new` starts at
    /// `(0, genesis_root)`, but on a restart reth (its own persistent DB) is
    /// already at the finalized head while consensus recovers its committed
    /// height from storage — so without this the first post-restart proposal
    /// would stamp a genesis lagged `committed_state_root` and fail the
    /// deferred-root vote check. The caller passes reth's finalized
    /// `(height, state_root)` (see [`crate::fetch_finalized_head`]).
    pub fn recover_frontier(&self, height: Height, state_root: [u8; 32]) {
        let mut c = self.committed.lock();
        c.height = height;
        c.state_root = state_root;
    }

    /// The EVM `(block hash, timestamp-seconds)` to build the next block on.
    /// For the boule genesis parent (no commands) that's reth's genesis;
    /// otherwise it is read from the parent boule block's payload command.
    fn parent_evm_anchor(&self, parent: &Block) -> Result<(String, u64)> {
        match parent.commands.first() {
            None => Ok((self.reth_genesis_hash.clone(), 0)),
            Some(cmd) => {
                let payload: Value = serde_json::from_slice(cmd)
                    .context("parent block command is not a JSON execution payload")?;
                let hash = payload["blockHash"]
                    .as_str()
                    .context("parent payload blockHash")?
                    .to_string();
                let ts = payload["timestamp"]
                    .as_str()
                    .context("parent payload timestamp")?;
                let ts = u64::from_str_radix(ts.trim_start_matches("0x"), 16)
                    .context("parent payload timestamp not hex")?;
                Ok((hash, ts))
            }
        }
    }
}

/// Extract the 32-byte post-state root from an execution payload.
fn state_root_of(payload: &Value) -> Result<[u8; 32]> {
    root_from_hex(payload["stateRoot"].as_str().context("payload stateRoot")?)
}

/// `parent` plus its uncommitted ancestors (strictly above the committed
/// frontier), walked through `pending_blocks` and returned **oldest-first**.
///
/// This is the chain a leader must make sure reth knows before it can build
/// on `parent`. The committed frontier and everything below it are already in
/// reth (commit runs `newPayloadV3`), but under HotStuff pipelining `parent`
/// and its recent ancestors may still be uncommitted — and a *rotated* leader
/// only ever **voted** on them (deferred execution: it never executed them),
/// so its reth has not seen those payloads. Registering this chain oldest-
/// first, on top of the known committed frontier, lets the build chain on
/// `parent`. The walk stops at the first block at/below `committed_height` or
/// the first parent missing from `pending_blocks` (the committed boundary).
fn uncommitted_chain<'b>(
    parent: &'b Block,
    pending_blocks: &'b HashMap<BlockHash, Block>,
    committed_height: Height,
) -> Vec<&'b Block> {
    let mut chain = Vec::new();
    let mut cursor = parent;
    while cursor.header.height.0 > committed_height.0 {
        chain.push(cursor);
        match pending_blocks.get(&cursor.header.parent_hash) {
            Some(p) => cursor = p,
            None => break,
        }
    }
    chain.reverse();
    chain
}

impl Application for RethApplication {
    fn build_proposal<'a>(
        &'a self,
        _ctx: &'a AppContext,
        parent: &'a Block,
        view: View,
        _high_qc: &'a QuorumCertificate,
        pending_blocks: &'a HashMap<BlockHash, Block>,
        timestamp: u64,
    ) -> BoxFuture<'a, Result<Block>> {
        Box::pin(async move {
            // Snapshot the committed frontier; do not hold the lock across the
            // engine round-trips below.
            let (committed_height, committed_state_root) = {
                let c = self.committed.lock();
                (c.height, c.state_root)
            };

            let (parent_evm_hash, parent_evm_ts) = self.parent_evm_anchor(parent)?;
            // EVM block time: strictly greater than the parent (EVM rule),
            // honoring the agreed consensus time (millis -> seconds).
            let evm_ts = (parent_evm_ts + 1).max(timestamp / 1000);

            let engine = self.engine();
            // Make sure reth knows the uncommitted chain we're about to build
            // on. A rotated leader may have only voted on `parent` and its
            // recent ancestors (never executed them), so register each payload
            // (`newPayloadV3`, no finalize) oldest-first before building.
            // Idempotent for blocks reth already knows; the genesis parent has
            // an empty chain. This is what makes the reth backend work across
            // leader rotation under pipelining.
            for ancestor in uncommitted_chain(parent, pending_blocks, committed_height) {
                if let Some(cmd) = ancestor.commands.first() {
                    let payload: Value = serde_json::from_slice(cmd)
                        .context("uncommitted ancestor command is not a JSON execution payload")?;
                    if engine.register_payload(&payload).await? == ElStatus::Syncing {
                        // Our EL is still syncing the uncommitted chain — it
                        // can't build on a head it doesn't have. Skip proposing
                        // this view; the EL catches up via the commit path, and
                        // a later leader (or this node once caught up) builds.
                        // Retriable: the safety core treats a build Err as a
                        // skipped proposal (#326), not a fault.
                        anyhow::bail!(
                            "reth EL still syncing the uncommitted ancestor chain (height {}); \
                             skipping proposal for view {}",
                            ancestor.header.height.0,
                            view.0,
                        );
                    }
                }
            }
            let built = engine
                .build_block(&parent_evm_hash, evm_ts, self.build_wait)
                .await?;
            // Register immediately so a later build can chain on this block
            // before it commits (HotStuff pipelining).
            engine.register_payload(&built.execution_payload).await?;

            // The block's first command is always the EVM execution payload.
            let mut commands = vec![Bytes::from(
                serde_json::to_vec(&built.execution_payload)
                    .context("serializing the EVM execution payload")?,
            )];
            // Carry pending boule *system* txs (reconfig/rotation) from the
            // mempool too. Application transactions live in reth's own pool
            // and ride the EVM payload, but consensus-layer system txs — e.g.
            // the ReconfigCommand the staking read path mints (#655) — have no
            // other way into a block on the reth backend, since this builder
            // does not draw application commands from boule's mempool. Without
            // this, a minted reconfig would never commit. Their validity is
            // checked at commit (apply_committed_reconfigs); app commands in
            // the pool are ignored here.
            for cmd in self.mempool.propose(SYSTEM_TX_LIMIT) {
                if ReconfigCommand::is_reconfig_payload(&cmd)
                    || DualSignedRotation::is_rotation_payload(&cmd)
                    || boule_consensus::validator_rotation::DualSignedRotationCancel::is_cancel_payload(&cmd)
                    || boule_consensus::validator_rotation::OperatorSignedRotation::is_operator_rotation_payload(&cmd)
                    || boule_consensus::validator_rotation::DualSignedOperatorRotation::is_operator_key_rotation_payload(&cmd)
                    // Equivocation-evidence system txs (#657): same rationale —
                    // no other path onto the reth backend; validated at commit.
                    || boule_consensus::equivocation_evidence::is_evidence_payload(&cmd)
                {
                    commands.push(cmd);
                }
            }
            let commands_commitment = Block::commands_commitment(&commands);

            Ok(Block {
                header: BlockHeader {
                    parent_hash: parent.hash(),
                    height: parent.header.height + 1,
                    view,
                    proposer: self.self_id,
                    state_commitment: built.state_root_bytes()?,
                    commands_commitment,
                    validator_history_commitment: [0; 32],
                    committed_height,
                    committed_state_root,
                    // Clamp to the parent so block time is non-decreasing.
                    timestamp: timestamp.max(parent.header.timestamp),
                },
                commands,
            })
        })
    }

    fn commit<'a>(
        &'a self,
        _ctx: &'a AppContext,
        block: &'a Block,
    ) -> BoxFuture<'a, Result<CommitResult>> {
        Box::pin(async move {
            let Some(cmd) = block.commands.first() else {
                // Genesis / empty block: nothing to execute.
                return Ok(CommitResult::default());
            };
            let payload: Value = serde_json::from_slice(cmd)
                .context("committed block command is not a JSON execution payload")?;
            let new_root = state_root_of(&payload)?;
            let (_, status) = self.engine().commit_block(&payload).await?;
            match status {
                ElStatus::Valid => {
                    // The EL executed it — advance the committed frontier,
                    // capturing the previous frontier height first so we can
                    // tell whether the EL just self-synced past a gap (#674).
                    let prev_height = {
                        let mut c = self.committed.lock();
                        let prev = c.height;
                        c.height = block.header.height;
                        c.state_root = new_root;
                        prev
                    };
                    // #674: if the frontier jumped by more than one block, the
                    // EL executed the in-between blocks via background self-sync
                    // (not through `commit`); read their staking events now so
                    // the CL stake ledger doesn't drift from EL state.
                    self.backfill_self_synced_gap(&payload, prev_height, block.header.height)
                        .await;
                }
                ElStatus::Syncing => {
                    // The EL doesn't have this block's parent yet; commit_block
                    // pointed it at the head via forkchoiceUpdated and it is
                    // syncing in the background. Hold the committed frontier at
                    // the last executed block until the EL reports VALID — don't
                    // claim a state the EL hasn't reached. Not an error:
                    // consensus commits regardless of EL execution outcome.
                    //
                    // Staking events are read only once the EL reports VALID
                    // (below) — its logs aren't available while syncing — so
                    // membership changes from this block are deferred until the
                    // EL catches up and the block is re-committed (#635).
                    tracing::info!(
                        target: "boule::reth",
                        height = block.header.height.0,
                        "reth EL syncing toward committed block; frontier + staking held until VALID",
                    );
                    return Ok(CommitResult::default());
                }
            }
            // The EL executed this block, so the staking predeploy's events for
            // it are now readable. Read them (#655) and feed the CL-native
            // stake ledger; the resulting deltas become validator_updates the
            // integration layer materialises into a reconfig (#652).
            let validator_updates = self
                .derive_validator_updates(&payload, block.header.height)
                .await;
            Ok(CommitResult {
                validator_updates,
                ..Default::default()
            })
        })
    }

    fn check(&self, cmd: &[u8]) -> Result<()> {
        // Tier-1 includability: the command must decode to an execution
        // payload carrying a block hash. Stateless — no reth round-trip.
        let payload: Value =
            serde_json::from_slice(cmd).context("command is not a JSON execution payload")?;
        payload
            .get("blockHash")
            .and_then(|v| v.as_str())
            .context("execution payload is missing blockHash")?;
        Ok(())
    }

    /// #658b: zero the equivocator's bonded stake in the CL-native ledger
    /// (the authoritative balance; `Staking.sol` is a pure event emitter).
    /// The `weight 0` delta is drained by the next `commit`'s `take_updates`
    /// and merges with the jail-remove (#658a) through the reconfig path.
    fn slash(&self, node_id: NodeId) {
        self.stake_source.lock().slash(node_id);
    }

    fn capabilities(&self) -> Vec<IntegrationCapability> {
        // The reth backend drives the validator set from on-chain staking logs
        // (#655) and burns bonded stake on committed evidence (#658b); it does
        // not (yet) drive key rotation, endpoint advertisement, parameter
        // updates, or rewards through the seam (those are milestone-#4
        // follow-ups — #730/#731/#542).
        vec![
            IntegrationCapability::Membership,
            IntegrationCapability::Slashing,
        ]
    }

    fn executed_height(&self) -> Option<Height> {
        // reth's executed frontier: the last committed block whose payload the
        // EL reported VALID. Lags the consensus committed height while the EL
        // is SYNCING, which is what the startup EL-catch-up (#635) keys off.
        Some(self.committed.lock().height)
    }

    fn state_commitment(&self) -> [u8; 32] {
        self.committed.lock().state_root
    }

    fn snapshot(&self) -> Bytes {
        let c = self.committed.lock();
        let mut out = Vec::with_capacity(40);
        out.extend_from_slice(&c.height.0.to_le_bytes());
        out.extend_from_slice(&c.state_root);
        Bytes::from(out)
    }

    fn restore(&self, snap: &[u8]) -> Result<()> {
        if snap.len() != 40 {
            anyhow::bail!(
                "reth snapshot must be 40 bytes (u64 height + 32-byte root), got {}",
                snap.len()
            );
        }
        let height = u64::from_le_bytes(snap[..8].try_into().unwrap());
        let root: [u8; 32] = snap[8..].try_into().unwrap();
        let mut c = self.committed.lock();
        c.height = Height(height);
        c.state_root = root;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::FixtureTransport;

    const RETH_GENESIS: &str = "0x48d8efff29130c4b1149a8cb877448dc06421f6617b92dc0f817ef96d8973767";
    const BLOCK1: &str = "0x24df01d105151ebf3d2a6c33530c4d3078d632fb7be477e4ce038ec645a61e91";
    const BLOCK1_STATE_ROOT: &str =
        "351714af72d74259f45cd7eab0b04527cd40e74836a45abcae50f92d919d988f";
    const FEE: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

    fn make_app(genesis_root: [u8; 32]) -> RethApplication {
        RethApplication::new(
            Box::new(FixtureTransport),
            [1u8; 32],
            FEE,
            RETH_GENESIS,
            genesis_root,
            Duration::ZERO,
            Box::new(boule_consensus::replication::stake_source::BondedStakeLedger::empty()),
            std::sync::Arc::new(boule_consensus::replication::impls::InMemoryMempool::new(
                64,
            )),
        )
    }

    fn genesis() -> Block {
        Block::genesis([0; 32], [0; 32])
    }

    fn sample_qc(block: &Block) -> QuorumCertificate {
        QuorumCertificate::new(0, block.hash(), 4)
    }

    #[tokio::test]
    async fn build_from_genesis_maps_payload_into_a_boule_block() {
        let app = make_app([0u8; 32]);
        let g = genesis();
        let block = app
            .build_proposal(
                &AppContext::default(),
                &g,
                View(1),
                &sample_qc(&g),
                &HashMap::new(),
                0,
            )
            .await
            .expect("build");

        assert_eq!(block.header.height, Height(1));
        assert_eq!(block.header.view, View(1));
        assert_eq!(block.header.parent_hash, g.hash());
        assert_eq!(block.header.proposer, [1u8; 32]);
        // Immediate post-state root from reth's getPayload.
        assert_eq!(
            hex::encode(block.header.state_commitment),
            BLOCK1_STATE_ROOT
        );
        // Lagged frontier is genesis until the first commit.
        assert_eq!(block.header.committed_height, Height(0));
        assert_eq!(block.header.committed_state_root, [0u8; 32]);

        // One command == the EVM payload for block 1.
        assert_eq!(block.commands.len(), 1);
        let payload: Value = serde_json::from_slice(&block.commands[0]).unwrap();
        assert_eq!(payload["blockHash"], BLOCK1);
    }

    #[test]
    fn declares_membership_and_slashing_capabilities() {
        // #728: the reth backend drives the validator set (#655) and slashing
        // (#658b), and declares exactly those — nothing it doesn't drive.
        let app = make_app([0u8; 32]);
        let caps = app.capabilities();
        assert!(caps.contains(&IntegrationCapability::Membership));
        assert!(caps.contains(&IntegrationCapability::Slashing));
        assert!(!caps.contains(&IntegrationCapability::Rewards));
        assert!(!caps.contains(&IntegrationCapability::KeyRotation));
        assert_eq!(caps.len(), 2);
    }

    #[tokio::test]
    async fn commit_executes_and_advances_the_committed_frontier() {
        let app = make_app([0u8; 32]);
        assert_eq!(app.state_commitment(), [0u8; 32], "starts at genesis root");

        let g = genesis();
        let block = app
            .build_proposal(
                &AppContext::default(),
                &g,
                View(1),
                &sample_qc(&g),
                &HashMap::new(),
                0,
            )
            .await
            .expect("build");
        let result = app
            .commit(&AppContext::default(), &block)
            .await
            .expect("commit");
        // The reth EL drives no membership changes — Ethereum keeps the
        // validator set in the consensus layer.
        assert!(result.validator_updates.is_empty());

        assert_eq!(hex::encode(app.state_commitment()), BLOCK1_STATE_ROOT);
    }

    /// Test transport: engine_* via the golden fixtures (so `commit` reaches
    /// VALID), plus a canned `eth_getLogs` result so the staking read path
    /// can be exercised without a live reth.
    struct StakingTransport {
        inner: FixtureTransport,
        logs: Value,
    }
    impl EngineTransport for StakingTransport {
        fn call(&self, method: &str, params: Value, tag: &str) -> BoxFuture<'_, Result<Value>> {
            self.inner.call(method, params, tag)
        }
        fn eth_rpc(&self, _method: &str, _params: Value) -> BoxFuture<'_, Result<Value>> {
            let logs = self.logs.clone();
            Box::pin(async move { Ok(logs) })
        }
    }

    #[tokio::test]
    async fn commit_reads_staking_logs_into_validator_updates() {
        use boule_consensus::replication::stake_source::BondedStakeLedger;

        // A validator seeded with genesis stake 1; a Withdraw of 1 fully
        // unbonds it, which the ledger reports as a removal (weight 0).
        let node = [2u8; 32];
        let logs = serde_json::json!([{
            "topics": [staking::WITHDRAW_TOPIC, format!("0x{}", "02".repeat(32))],
            "data": format!("0x{:064x}", 1u64),
        }]);
        let app = RethApplication::new(
            Box::new(StakingTransport {
                inner: FixtureTransport,
                logs,
            }),
            [1u8; 32],
            FEE,
            RETH_GENESIS,
            [0u8; 32],
            Duration::ZERO,
            Box::new(BondedStakeLedger::seeded_from([(node, 1u64)])),
            std::sync::Arc::new(boule_consensus::replication::impls::InMemoryMempool::new(
                64,
            )),
        );

        let g = genesis();
        let block = app
            .build_proposal(
                &AppContext::default(),
                &g,
                View(1),
                &sample_qc(&g),
                &HashMap::new(),
                0,
            )
            .await
            .expect("build");
        let result = app
            .commit(&AppContext::default(), &block)
            .await
            .expect("commit");
        assert_eq!(
            result.validator_updates,
            vec![ValidatorUpdate {
                node_id: node,
                weight: 0,
            }],
            "a Withdraw of the full stake removes the validator (weight 0)",
        );
    }

    /// The reth builder must carry a pending boule system tx (a minted
    /// reconfig) from the mempool into the block alongside the EVM payload —
    /// otherwise a staking-driven reconfig never commits (the gap the
    /// multi-process reth e2e caught). App-level pool txs are *not* included
    /// (they ride reth's payload).
    #[tokio::test]
    async fn build_proposal_carries_a_pending_reconfig_from_the_mempool() {
        use boule_consensus::replication::impls::InMemoryMempool;
        use boule_consensus::replication::stake_source::BondedStakeLedger;

        let mempool: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(16));
        let reconfig = ReconfigCommand {
            adds: vec![],
            removes: vec![[9u8; 32]],
            changes: vec![],
            v_eff: View(10),
        }
        .encode();
        mempool.insert(reconfig).unwrap();
        // A plain app command must be ignored (it belongs to reth's pool).
        mempool.insert(Bytes::from_static(b"an-app-tx")).unwrap();

        let app = RethApplication::new(
            Box::new(FixtureTransport),
            [1u8; 32],
            FEE,
            RETH_GENESIS,
            [0u8; 32],
            Duration::ZERO,
            Box::new(BondedStakeLedger::empty()),
            Arc::clone(&mempool),
        );
        let g = genesis();
        let block = app
            .build_proposal(
                &AppContext::default(),
                &g,
                View(1),
                &sample_qc(&g),
                &HashMap::new(),
                0,
            )
            .await
            .expect("build");
        assert_eq!(
            block.commands.len(),
            2,
            "the EVM payload plus the one pending reconfig (the app tx is excluded)",
        );
        assert!(
            ReconfigCommand::is_reconfig_payload(&block.commands[1]),
            "the second command is the carried reconfig",
        );
    }

    #[tokio::test]
    async fn commit_of_genesis_is_a_noop() {
        let app = make_app([9u8; 32]);
        app.commit(&AppContext::default(), &genesis())
            .await
            .expect("genesis commit");
        assert_eq!(app.state_commitment(), [9u8; 32]);
    }

    #[test]
    fn check_accepts_a_payload_and_rejects_garbage() {
        let app = make_app([0u8; 32]);
        let payload = serde_json::json!({ "blockHash": BLOCK1 });
        let cmd = serde_json::to_vec(&payload).unwrap();
        assert!(app.check(&cmd).is_ok());
        assert!(app.check(b"not a payload").is_err());
        // Decodes as JSON but missing blockHash.
        assert!(app.check(b"{}").is_err());
    }

    #[test]
    fn snapshot_round_trips_height_and_root() {
        let app = make_app([0u8; 32]);
        {
            let mut c = app.committed.lock();
            c.height = Height(7);
            c.state_root = [0xAB; 32];
        }
        let snap = app.snapshot();

        let restored = make_app([0u8; 32]);
        restored.restore(&snap).unwrap();
        assert_eq!(restored.state_commitment(), [0xAB; 32]);
        assert_eq!(restored.committed.lock().height, Height(7));
    }

    #[test]
    fn restore_rejects_a_wrong_length_blob() {
        let app = make_app([0u8; 32]);
        assert!(app.restore(&[0u8; 16]).is_err());
    }

    #[test]
    fn executed_height_tracks_the_committed_frontier() {
        // The EL's executed height is the committed frontier — what the startup
        // EL-catch-up (#635) compares against the consensus committed height.
        let app = make_app([0u8; 32]);
        assert_eq!(app.executed_height(), Some(Height(0)), "starts at genesis");
        app.recover_frontier(Height(42), [0xAB; 32]);
        assert_eq!(app.executed_height(), Some(Height(42)));
    }

    #[test]
    fn recover_frontier_seeds_height_and_root_on_restart() {
        // Fresh construction starts at the genesis frontier...
        let app = make_app([7u8; 32]);
        assert_eq!(app.committed.lock().height, Height(0));
        assert_eq!(app.state_commitment(), [7u8; 32]);
        // ...and restart recovery reconciles it to reth's finalized head.
        app.recover_frontier(Height(99), [0xCD; 32]);
        assert_eq!(app.committed.lock().height, Height(99));
        assert_eq!(app.state_commitment(), [0xCD; 32]);
    }

    // ── #629: uncommitted-ancestor registration on the build path ──────────

    fn evm_payload(block_hash: &str) -> Bytes {
        Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "blockHash": block_hash,
                "stateRoot": format!("0x{}", "11".repeat(32)),
                "timestamp": "0x1",
            }))
            .unwrap(),
        )
    }

    fn block_with_payload(parent_hash: [u8; 32], height: u64, block_hash: &str) -> Block {
        let commands = vec![evm_payload(block_hash)];
        Block {
            header: BlockHeader {
                parent_hash,
                height: Height(height),
                view: View(height),
                proposer: [1u8; 32],
                state_commitment: [0u8; 32],
                commands_commitment: Block::commands_commitment(&commands),
                validator_history_commitment: [0u8; 32],
                committed_height: Height(0),
                committed_state_root: [0u8; 32],
                timestamp: 1,
            },
            commands,
        }
    }

    #[test]
    fn uncommitted_chain_returns_parent_and_ancestors_oldest_first() {
        // genesis(0) <- a(1) <- b(2) <- c(3); committed frontier at height 1.
        let g = genesis();
        let a = block_with_payload(g.hash(), 1, "0xaa");
        let b = block_with_payload(a.hash(), 2, "0xbb");
        let c = block_with_payload(b.hash(), 3, "0xcc");
        let pending: HashMap<BlockHash, Block> =
            [(a.hash(), a), (b.hash(), b), (c.hash(), c.clone())]
                .into_iter()
                .collect();

        // a is at the committed frontier (excluded); b, c are uncommitted, so
        // the chain is oldest-first [b, c].
        let chain = uncommitted_chain(&c, &pending, Height(1));
        let heights: Vec<u64> = chain.iter().map(|blk| blk.header.height.0).collect();
        assert_eq!(heights, vec![2, 3]);
    }

    #[test]
    fn uncommitted_chain_is_empty_for_the_genesis_parent() {
        let g = genesis();
        assert!(uncommitted_chain(&g, &HashMap::new(), Height(0)).is_empty());
    }

    #[test]
    fn uncommitted_chain_stops_at_a_missing_parent() {
        // Only c is in pending (its ancestors absent); the walk stops at c.
        let g = genesis();
        let a = block_with_payload(g.hash(), 1, "0xaa");
        let b = block_with_payload(a.hash(), 2, "0xbb");
        let c = block_with_payload(b.hash(), 3, "0xcc");
        let pending: HashMap<BlockHash, Block> = [(c.hash(), c.clone())].into_iter().collect();
        let chain = uncommitted_chain(&c, &pending, Height(0));
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].header.height.0, 3);
    }

    /// Transport that records the engine methods called while replaying the
    /// golden fixtures, so the driver runs and the call sequence is observable.
    struct RecordingTransport {
        methods: std::sync::Arc<Mutex<Vec<String>>>,
    }

    impl EngineTransport for RecordingTransport {
        fn call(
            &self,
            method: &str,
            params: Value,
            _tag: &str,
        ) -> BoxFuture<'_, anyhow::Result<Value>> {
            self.methods.lock().push(method.to_string());
            let raw = match method {
                "engine_forkchoiceUpdatedV3" => {
                    if params.get(1).is_some_and(|v| !v.is_null()) {
                        include_str!("../fixtures/01-fcu-attrs.json")
                    } else {
                        include_str!("../fixtures/04-fcu-final.json")
                    }
                }
                "engine_getPayloadV3" => include_str!("../fixtures/02-getpayload.json"),
                "engine_newPayloadV3" => include_str!("../fixtures/03-newpayload.json"),
                other => panic!("unexpected engine method {other}"),
            };
            let v = serde_json::from_str::<Value>(raw).unwrap()["result"].clone();
            Box::pin(async move { Ok(v) })
        }
    }

    #[tokio::test]
    async fn build_registers_the_uncommitted_ancestor_chain_before_building() {
        let methods = std::sync::Arc::new(Mutex::new(Vec::<String>::new()));
        let app = RethApplication::new(
            Box::new(RecordingTransport {
                methods: methods.clone(),
            }),
            [1u8; 32],
            FEE,
            RETH_GENESIS,
            [0u8; 32],
            Duration::ZERO,
            Box::new(boule_consensus::replication::stake_source::BondedStakeLedger::empty()),
            std::sync::Arc::new(boule_consensus::replication::impls::InMemoryMempool::new(
                64,
            )),
        );

        // Two uncommitted blocks above the (genesis) committed frontier; build
        // on the tip `b`.
        let g = genesis();
        let a = block_with_payload(g.hash(), 1, "0xaa");
        let b = block_with_payload(a.hash(), 2, "0xbb");
        let pending: HashMap<BlockHash, Block> =
            [(a.hash(), a), (b.hash(), b.clone())].into_iter().collect();

        app.build_proposal(
            &AppContext::default(),
            &b,
            View(3),
            &sample_qc(&b),
            &pending,
            1_000,
        )
        .await
        .expect("build");

        let m = methods.lock();
        let new_payloads = m.iter().filter(|x| *x == "engine_newPayloadV3").count();
        assert_eq!(new_payloads, 3, "two ancestors (a, b) + the built block");
        // Both ancestors are registered before the build's forkchoiceUpdatedV3.
        let first_fcu = m
            .iter()
            .position(|x| x == "engine_forkchoiceUpdatedV3")
            .expect("build issues a forkchoiceUpdatedV3");
        let registered_before_build = m[..first_fcu]
            .iter()
            .filter(|x| *x == "engine_newPayloadV3")
            .count();
        assert_eq!(
            registered_before_build, 2,
            "ancestors registered before building"
        );
    }

    // ── #636: tolerate Engine-API SYNCING (EL catch-up) ────────────────────

    /// Transport whose newPayload/fcU return `SYNCING` (EL is behind).
    struct SyncingTransport;
    impl EngineTransport for SyncingTransport {
        fn call(
            &self,
            method: &str,
            _params: Value,
            _tag: &str,
        ) -> BoxFuture<'_, anyhow::Result<Value>> {
            let v = match method {
                "engine_newPayloadV3" => serde_json::json!({ "status": "SYNCING" }),
                "engine_forkchoiceUpdatedV3" => {
                    serde_json::json!({ "payloadStatus": { "status": "SYNCING" } })
                }
                other => panic!("unexpected method {other}"),
            };
            Box::pin(async move { Ok(v) })
        }
    }

    #[tokio::test]
    async fn commit_holds_the_frontier_when_the_el_is_syncing() {
        let app = RethApplication::new(
            Box::new(SyncingTransport),
            [1u8; 32],
            FEE,
            RETH_GENESIS,
            [0u8; 32],
            Duration::ZERO,
            Box::new(boule_consensus::replication::stake_source::BondedStakeLedger::empty()),
            std::sync::Arc::new(boule_consensus::replication::impls::InMemoryMempool::new(
                64,
            )),
        );
        {
            let mut c = app.committed.lock();
            c.height = Height(5);
            c.state_root = [0x55; 32];
        }
        // A committed block the EL can't execute yet (SYNCING).
        let block = block_with_payload([0u8; 32], 10, BLOCK1);
        app.commit(&AppContext::default(), &block)
            .await
            .expect("SYNCING commit is not an error");
        // Frontier held at the last executed block, not advanced to 10.
        assert_eq!(app.committed.lock().height, Height(5));
        assert_eq!(app.state_commitment(), [0x55; 32]);
    }

    /// #674: when the EL reports VALID for a block whose height jumps past the
    /// committed frontier by more than one (it self-synced the in-between
    /// blocks via snap/full sync, never replaying them through `commit`), the
    /// staking events of those skipped blocks are backfilled — read by EVM
    /// number and applied at their own height — so the CL stake ledger does not
    /// silently drift from EL state.
    #[tokio::test]
    async fn commit_backfills_staking_over_an_el_self_synced_gap() {
        use boule_consensus::replication::stake_source::BondedStakeLedger;

        fn payload_with_number(block_hash: &str, number: u64) -> Bytes {
            Bytes::from(
                serde_json::to_vec(&serde_json::json!({
                    "blockHash": block_hash,
                    "blockNumber": format!("0x{number:x}"),
                    "stateRoot": format!("0x{}", "11".repeat(32)),
                    "timestamp": "0x1",
                }))
                .unwrap(),
            )
        }

        const VALIDATOR_A: [u8; 32] = [0x0a; 32]; // genesis-staked, withdraws in block 3
        const VALIDATOR_C: [u8; 32] = [0x0c; 32]; // deposits in skipped block 1
        const BLOCK3_HASH: &str = "0x3c";

        // Transport: engine_* report VALID so `commit` advances the frontier;
        // `eth_getLogs` serves per-block staking events — by EVM number for the
        // self-synced gap blocks, by hash for the current block.
        struct GapStakingTransport;
        impl EngineTransport for GapStakingTransport {
            fn call(
                &self,
                method: &str,
                _params: Value,
                _tag: &str,
            ) -> BoxFuture<'_, Result<Value>> {
                let v = match method {
                    "engine_newPayloadV3" => serde_json::json!({ "status": "VALID" }),
                    "engine_forkchoiceUpdatedV3" => {
                        serde_json::json!({ "payloadStatus": { "status": "VALID" } })
                    }
                    other => panic!("unexpected engine method {other}"),
                };
                Box::pin(async move { Ok(v) })
            }
            fn eth_rpc(&self, _method: &str, params: Value) -> BoxFuture<'_, Result<Value>> {
                let filter = &params[0];
                let logs = if filter["fromBlock"] == serde_json::json!("0x1") {
                    // Skipped block 1: validator C deposits 7.
                    serde_json::json!([{
                        "topics": [staking::DEPOSIT_TOPIC, format!("0x{}", "0c".repeat(32))],
                        "data": format!("0x{:064x}", 7u64),
                    }])
                } else if filter["blockHash"] == serde_json::json!(BLOCK3_HASH) {
                    // Current block 3: validator A withdraws its full stake.
                    serde_json::json!([{
                        "topics": [staking::WITHDRAW_TOPIC, format!("0x{}", "0a".repeat(32))],
                        "data": format!("0x{:064x}", 1u64),
                    }])
                } else {
                    // Skipped block 2 (fromBlock 0x2) and anything else: no events.
                    serde_json::json!([])
                };
                Box::pin(async move { Ok(logs) })
            }
        }

        let app = RethApplication::new(
            Box::new(GapStakingTransport),
            [1u8; 32],
            FEE,
            RETH_GENESIS,
            [0u8; 32],
            Duration::ZERO,
            Box::new(BondedStakeLedger::seeded_from([(VALIDATOR_A, 1u64)])),
            std::sync::Arc::new(boule_consensus::replication::impls::InMemoryMempool::new(
                64,
            )),
        );

        // Frontier starts at genesis (0). The EL self-synced blocks 1 and 2 in
        // the background; now it executes block 3 (height jumps 0 → 3).
        let block3 = {
            let commands = vec![payload_with_number(BLOCK3_HASH, 3)];
            Block {
                header: BlockHeader {
                    parent_hash: [0u8; 32],
                    height: Height(3),
                    view: View(3),
                    proposer: [1u8; 32],
                    state_commitment: [0u8; 32],
                    commands_commitment: Block::commands_commitment(&commands),
                    validator_history_commitment: [0u8; 32],
                    committed_height: Height(0),
                    committed_state_root: [0u8; 32],
                    timestamp: 1,
                },
                commands,
            }
        };

        let result = app
            .commit(&AppContext::default(), &block3)
            .await
            .expect("commit");

        // Frontier advanced to 3.
        assert_eq!(app.committed.lock().height, Height(3));
        // The gap block 1's deposit (C, weight 7) is NOT lost, and the current
        // block 3's withdraw (A → weight 0) also rides this commit.
        let mut got = result.validator_updates.clone();
        got.sort_by_key(|u| u.node_id);
        assert_eq!(
            got,
            vec![
                ValidatorUpdate {
                    node_id: VALIDATOR_A,
                    weight: 0,
                },
                ValidatorUpdate {
                    node_id: VALIDATOR_C,
                    weight: 7,
                },
            ],
            "the self-synced gap's staking event (C +7) is backfilled alongside \
             the current block's (A removed)",
        );
    }

    #[tokio::test]
    async fn build_skips_when_the_el_is_syncing() {
        let app = RethApplication::new(
            Box::new(SyncingTransport),
            [1u8; 32],
            FEE,
            RETH_GENESIS,
            [0u8; 32],
            Duration::ZERO,
            Box::new(boule_consensus::replication::stake_source::BondedStakeLedger::empty()),
            std::sync::Arc::new(boule_consensus::replication::impls::InMemoryMempool::new(
                64,
            )),
        );
        let g = genesis();
        let a = block_with_payload(g.hash(), 1, "0xaa");
        let pending: HashMap<BlockHash, Block> = [(a.hash(), a.clone())].into_iter().collect();
        // The leader's EL can't register the uncommitted ancestor (SYNCING) →
        // build is skipped (retriable), not a forged proposal.
        let err = app
            .build_proposal(
                &AppContext::default(),
                &a,
                View(2),
                &sample_qc(&a),
                &pending,
                1_000,
            )
            .await
            .expect_err("build must skip while the EL is syncing");
        assert!(err.to_string().contains("still syncing"));
    }
}
