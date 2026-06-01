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
use std::time::Duration;

use anyhow::{Context, Result};
use boule_consensus::hotstuff::QuorumCertificate;
use boule_consensus::replication::application::Application;
use boule_consensus::replication::block::{Block, BlockHash, BlockHeader};
use boule_consensus::{Height, View};
use boule_core::clock::BoxFuture;
use boule_core::identity::NodeId;
use bytes::Bytes;
use parking_lot::Mutex;
use serde_json::Value;

use crate::engine::{RethEngine, root_from_hex};
use crate::transport::EngineTransport;

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
}

impl RethApplication {
    /// `genesis_root` is reth's genesis state root, which must equal the
    /// consensus genesis block's `state_commitment` — the caller verifies that
    /// bridge at startup. `reth_genesis_hash` is reth's genesis block hash, the
    /// EVM parent of the first proposed block.
    pub fn new(
        transport: Box<dyn EngineTransport>,
        self_id: NodeId,
        fee_recipient: impl Into<String>,
        reth_genesis_hash: impl Into<String>,
        genesis_root: [u8; 32],
        build_wait: Duration,
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
        }
    }

    fn engine(&self) -> RethEngine<'_> {
        RethEngine::new(&*self.transport, self.fee_recipient.clone())
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
                    engine.register_payload(&payload).await?;
                }
            }
            let built = engine
                .build_block(&parent_evm_hash, evm_ts, self.build_wait)
                .await?;
            // Register immediately so a later build can chain on this block
            // before it commits (HotStuff pipelining).
            engine.register_payload(&built.execution_payload).await?;

            let commands = vec![Bytes::from(
                serde_json::to_vec(&built.execution_payload)
                    .context("serializing the EVM execution payload")?,
            )];
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

    fn commit<'a>(&'a self, block: &'a Block) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let Some(cmd) = block.commands.first() else {
                // Genesis / empty block: nothing to execute.
                return Ok(());
            };
            let payload: Value = serde_json::from_slice(cmd)
                .context("committed block command is not a JSON execution payload")?;
            let new_root = state_root_of(&payload)?;
            self.engine().commit_block(&payload).await?;
            // Advance the committed frontier only after reth confirms.
            let mut c = self.committed.lock();
            c.height = block.header.height;
            c.state_root = new_root;
            Ok(())
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
            .build_proposal(&g, View(1), &sample_qc(&g), &HashMap::new(), 0)
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

    #[tokio::test]
    async fn commit_executes_and_advances_the_committed_frontier() {
        let app = make_app([0u8; 32]);
        assert_eq!(app.state_commitment(), [0u8; 32], "starts at genesis root");

        let g = genesis();
        let block = app
            .build_proposal(&g, View(1), &sample_qc(&g), &HashMap::new(), 0)
            .await
            .expect("build");
        app.commit(&block).await.expect("commit");

        assert_eq!(hex::encode(app.state_commitment()), BLOCK1_STATE_ROOT);
    }

    #[tokio::test]
    async fn commit_of_genesis_is_a_noop() {
        let app = make_app([9u8; 32]);
        app.commit(&genesis()).await.expect("genesis commit");
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
        );

        // Two uncommitted blocks above the (genesis) committed frontier; build
        // on the tip `b`.
        let g = genesis();
        let a = block_with_payload(g.hash(), 1, "0xaa");
        let b = block_with_payload(a.hash(), 2, "0xbb");
        let pending: HashMap<BlockHash, Block> =
            [(a.hash(), a), (b.hash(), b.clone())].into_iter().collect();

        app.build_proposal(&b, View(3), &sample_qc(&b), &pending, 1_000)
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
}
