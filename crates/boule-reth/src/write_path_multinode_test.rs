//! Multi-node simulation of the proposer EVM-write path (#766).
//!
//! The boule→EVM registry write path (`recordKey` / `recordWeight` /
//! `recordSettled` in [`RethApplication::commit`]) was previously validated
//! only against a single live `reth --dev`. Its *distributed* behaviour —
//! proposer rotation, the shared system-account nonce, and restart
//! replay/idempotency — cannot be surfaced single-node. A full N-node reth
//! cluster is too heavy to run here (and the testnet driver does not wire reth
//! at all), so this module exercises the distributed risk where it actually
//! lives: **boule's submission logic**, driven through a deterministic
//! recording mock [`EngineTransport`].
//!
//! # Model
//!
//! A [`SharedEvm`] (behind `Arc<Mutex>`) stands in for the one reth every
//! validator's `RethApplication` writes the *one* system account to:
//!
//! - `eth_getTransactionCount(system, "pending")` returns the shared pending
//!   nonce (the count of accepted system txs) — exactly what a rotating set of
//!   proposers, each independently fetching the pending nonce, would read.
//! - `eth_sendRawTransaction(raw)` decodes + recovers the tx, **rejects** a
//!   stale nonce (`< pending`, modelling reth dropping a colliding/duplicate
//!   nonce), otherwise accepts it, bumps the pending nonce, and applies the
//!   call to the simulated `Registry` storage with the contract's real
//!   semantics: `recordKey` requires a strictly increasing `vEff` per
//!   validator (a duplicate reverts), `recordWeight` overwrites, and
//!   `recordSettled` clamps monotonically.
//! - Each submission is recorded as `(sender, nonce, call, outcome)` so the
//!   tests can assert *who* submitted *what* and whether it landed or reverted.
//!
//! Each [`RethApplication`] node shares the same `SharedEvm`, so committing the
//! same block at N nodes — only one of which is the proposer — directly tests
//! the `ctx.proposer == self_id` gate, the shared nonce, and idempotency across
//! a simulated restart.
//!
//! # Coverage (see #766)
//!
//! - **(a) proposer-only:** non-proposer commits submit nothing; exactly one
//!   write per state change. Covered.
//! - **(b) rotation across views:** a different node proposes each view; writes
//!   stay exactly-once with monotone, gap-free nonces. Covered.
//! - **(c) restart replay / idempotency:** re-committing already-committed
//!   blocks re-submits, but the monotone `vEff` guard reverts the duplicate
//!   `recordKey` and `recordSettled` clamps — no corruption. Covered.
//! - **(d) reorg:** a write for a block later reorged out. **Not covered** —
//!   BFT finality means committed boule blocks never reorg, so this is a
//!   live-reth-only EVM-reorg concern outside the consensus model; it remains
//!   for a real-cluster test.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use alloy_consensus::TxEnvelope;
use alloy_consensus::transaction::SignerRecoverable;
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::Address;
use boule_consensus::replication::application::{AppContext, Application, ValidatorEffect};
use boule_consensus::replication::block::{Block, BlockHash, BlockHeader};
use boule_consensus::replication::impls::InMemoryMempool;
use boule_consensus::replication::stake_source::BondedStakeLedger;
use boule_consensus::validator_rotation::{DualSignedRotation, ValidatorKeyRotation};
use boule_consensus::{Height, View};
use boule_core::clock::BoxFuture;
use boule_core::crypto::sig_scheme::{BlsAggregated, BlsPublicKey};
use boule_core::identity::NodeId;
use bytes::Bytes;
use parking_lot::Mutex;
use serde_json::{Value, json};

use crate::testing::FixtureTransport;
use crate::transport::EngineTransport;
use crate::{RethApplication, registry, rotation, staking, system_account};

const RETH_GENESIS: &str = "0x48d8efff29130c4b1149a8cb877448dc06421f6617b92dc0f817ef96d8973767";
const FEE: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

/// A decoded system-registry call (what the proposer authored).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    RecordKey { validator: [u8; 32], v_eff: u64 },
    RecordWeight { validator: [u8; 32], weight: u64 },
    RecordSettled { view: u64 },
    Other,
}

/// One recorded system-tx submission against the shared EVM.
#[derive(Debug, Clone)]
struct Submission {
    /// Recovered tx sender — must always be the one system account.
    sender: Address,
    /// The nonce the proposer signed the tx with.
    nonce: u64,
    call: Call,
    /// `true` if the tx landed (state-changing), `false` if it reverted as a
    /// no-op (stale nonce, or the contract's monotone guard rejected it).
    applied: bool,
}

/// The shared on-chain state every node's `RethApplication` writes: the one
/// system account's pending nonce, the `Registry`'s per-validator key-history
/// frontier (`vEff`) + current weights + settled view, and the full
/// submission log. Mirrors only what the contract guards enforce.
#[derive(Default)]
struct EvmState {
    /// System-account pending nonce: the count of accepted system txs.
    pending_nonce: u64,
    /// Greatest `vEff` recorded per validator (`recordKey` requires strictly
    /// increasing — a duplicate/older reverts).
    key_frontier: HashMap<[u8; 32], u64>,
    /// Current on-chain weight per validator (`recordWeight` overwrites).
    weight: HashMap<[u8; 32], u64>,
    /// The settled-view frontier (`recordSettled` clamps monotonically).
    settled_view: u64,
    submissions: Vec<Submission>,
}

#[derive(Clone)]
struct SharedEvm(Arc<Mutex<EvmState>>);

impl SharedEvm {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(EvmState::default())))
    }

    /// All recorded submissions, in submission order.
    fn submissions(&self) -> Vec<Submission> {
        self.0.lock().submissions.clone()
    }

    /// Submissions that actually changed state (landed, not reverted).
    fn applied(&self) -> Vec<Submission> {
        self.0
            .lock()
            .submissions
            .iter()
            .filter(|s| s.applied)
            .cloned()
            .collect()
    }

    fn settled_view(&self) -> u64 {
        self.0.lock().settled_view
    }

    fn weight_of(&self, v: &[u8; 32]) -> u64 {
        self.0.lock().weight.get(v).copied().unwrap_or(0)
    }

    /// Decode + apply one submitted raw tx with the contract's guard
    /// semantics, recording the outcome. Returns the tx hash (a dummy here).
    fn accept_raw(&self, raw: &[u8]) -> anyhow::Result<String> {
        let envelope = TxEnvelope::decode_2718(&mut &*raw)?;
        let sender = envelope.recover_signer()?;
        let (nonce, input) = match &envelope {
            TxEnvelope::Eip1559(signed) => (signed.tx().nonce, signed.tx().input.clone()),
            other => anyhow::bail!("unexpected tx type: {other:?}"),
        };
        let call = decode_call(&input);

        let mut st = self.0.lock();
        // reth's pool rejects a tx whose nonce is below the account's pending
        // nonce (a colliding/duplicate nonce from a racing proposer or a
        // restart re-submit). Model that as a non-applied submission.
        if nonce < st.pending_nonce {
            st.submissions.push(Submission {
                sender,
                nonce,
                call,
                applied: false,
            });
            return Ok(stale_hash());
        }
        // Accepted into the pool: the nonce advances (so the next independent
        // pending-nonce fetch is fresh) regardless of whether the call's body
        // reverts in the EVM — a reverted tx still consumes its nonce.
        st.pending_nonce = nonce + 1;
        let applied = match &call {
            Call::RecordKey { validator, v_eff } => {
                let prev = st.key_frontier.get(validator).copied();
                // `recordKey` requires strictly increasing vEff.
                let ok = prev.is_none_or(|p| *v_eff > p);
                if ok {
                    st.key_frontier.insert(*validator, *v_eff);
                }
                ok
            }
            Call::RecordWeight { validator, weight } => {
                st.weight.insert(*validator, *weight);
                true
            }
            Call::RecordSettled { view } => {
                // Monotone clamp: a stale/replayed view is a no-op.
                if *view > st.settled_view {
                    st.settled_view = *view;
                    true
                } else {
                    false
                }
            }
            Call::Other => true,
        };
        st.submissions.push(Submission {
            sender,
            nonce,
            call,
            applied,
        });
        Ok(applied_hash())
    }
}

fn stale_hash() -> String {
    format!("0x{}", "11".repeat(32))
}
fn applied_hash() -> String {
    format!("0x{}", "22".repeat(32))
}

/// Decode a registry calldata blob into the [`Call`] it represents, by its
/// 4-byte selector and ABI head words. Only the fields the tests assert on are
/// pulled out.
fn decode_call(input: &[u8]) -> Call {
    if input.len() < 4 {
        return Call::Other;
    }
    let selector: [u8; 4] = input[0..4].try_into().unwrap();
    let word = |i: usize| -> Option<&[u8]> { input.get(4 + i * 32..4 + (i + 1) * 32) };
    let u64_tail = |w: &[u8]| -> u64 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&w[24..32]);
        u64::from_be_bytes(b)
    };
    match selector {
        registry::RECORD_KEY_SELECTOR => {
            let (Some(v), Some(e)) = (word(0), word(1)) else {
                return Call::Other;
            };
            let mut validator = [0u8; 32];
            validator.copy_from_slice(v);
            Call::RecordKey {
                validator,
                v_eff: u64_tail(e),
            }
        }
        registry::RECORD_WEIGHT_SELECTOR => {
            let (Some(v), Some(w)) = (word(0), word(1)) else {
                return Call::Other;
            };
            let mut validator = [0u8; 32];
            validator.copy_from_slice(v);
            Call::RecordWeight {
                validator,
                weight: u64_tail(w),
            }
        }
        registry::RECORD_SETTLED_SELECTOR => {
            let Some(v) = word(0) else {
                return Call::Other;
            };
            Call::RecordSettled { view: u64_tail(v) }
        }
        _ => Call::Other,
    }
}

/// Per-block canned `eth_getLogs` results, shared so a test can swap the
/// rotation/staking logs *between* commits while persistent node apps keep
/// committing in sequence (each node reads whatever logs the current block
/// emits). Cloned into every node's transport so they all see the same block.
#[derive(Clone, Default)]
struct BlockLogs {
    /// Staking logs (drives `recordWeight`), served for the staking filter.
    staking: Arc<Mutex<Value>>,
    /// Rotation logs (drives `recordKey`), served for the rotation filter.
    rotation: Arc<Mutex<Value>>,
}

impl BlockLogs {
    fn with(staking: Value, rotation: Value) -> Self {
        Self {
            staking: Arc::new(Mutex::new(staking)),
            rotation: Arc::new(Mutex::new(rotation)),
        }
    }
    fn set_rotation(&self, logs: Value) {
        *self.rotation.lock() = logs;
    }
}

/// The recording mock transport one node writes through. `engine_*` replays
/// the golden fixtures (so `commit` reaches `VALID`); `eth_getLogs` is served
/// per the filter's predeploy address (staking → weight changes, rotation →
/// key rotations, everything else empty); the write primitives record against
/// the [`SharedEvm`].
struct RecordingTransport {
    evm: SharedEvm,
    logs: BlockLogs,
}

impl EngineTransport for RecordingTransport {
    fn call(&self, method: &str, params: Value, tag: &str) -> BoxFuture<'_, anyhow::Result<Value>> {
        FixtureTransport.call(method, params, tag)
    }

    fn eth_rpc(&self, method: &str, params: Value) -> BoxFuture<'_, anyhow::Result<Value>> {
        // chain id, queried by the system-tx builder.
        if method == "eth_chainId" {
            return Box::pin(async move { Ok(json!("0x539")) });
        }
        // eth_getLogs, dispatched by the filter's predeploy address.
        let addr = params[0]["address"].as_str().unwrap_or_default();
        let logs = if addr.eq_ignore_ascii_case(staking::STAKING_ADDRESS) {
            self.logs.staking.lock().clone()
        } else if addr.eq_ignore_ascii_case(rotation::ROTATION_ADDRESS) {
            self.logs.rotation.lock().clone()
        } else {
            Value::Array(Vec::new())
        };
        Box::pin(async move { Ok(logs) })
    }

    fn eth_get_transaction_count(&self, _address: &str) -> BoxFuture<'_, anyhow::Result<u64>> {
        let nonce = self.evm.0.lock().pending_nonce;
        Box::pin(async move { Ok(nonce) })
    }

    fn send_raw_transaction(&self, raw: Bytes) -> BoxFuture<'_, anyhow::Result<Value>> {
        let hash = self.evm.accept_raw(&raw);
        Box::pin(async move { Ok(Value::String(hash?)) })
    }
}

/// Build one validator node's `RethApplication`, writing through the shared
/// EVM and reading the shared per-block logs.
fn make_node(
    self_id: NodeId,
    evm: SharedEvm,
    logs: BlockLogs,
    genesis_stake: &[(NodeId, u64)],
) -> RethApplication {
    RethApplication::new(
        Box::new(RecordingTransport { evm, logs }),
        self_id,
        FEE,
        RETH_GENESIS,
        [0u8; 32],
        Duration::ZERO,
        Box::new(BondedStakeLedger::seeded_from(
            genesis_stake.iter().copied(),
        )),
        Arc::new(InMemoryMempool::new(64)),
    )
}

/// A committed block at `(height, view)` proposed by `proposer`, carrying the
/// fixture's EVM payload as its one command (so `commit` reaches `VALID`). The
/// payload's `blockHash` is fixed by the fixture; that is fine — the write path
/// keys off the committed `(view, proposer)` and the per-block logs, not the
/// EVM block identity.
fn committed_block(height: u64, view: u64, proposer: NodeId) -> Block {
    // The fixture's block-1 execution payload, as `build_proposal` would embed.
    let payload: Value =
        serde_json::from_str(include_str!("../fixtures/02-getpayload.json")).unwrap();
    let payload = payload["result"]["executionPayload"].clone();
    let command = Bytes::from(serde_json::to_vec(&payload).unwrap());
    let commands = vec![command];
    Block {
        header: BlockHeader {
            parent_hash: BlockHash::default(),
            height: Height(height),
            view: View(view),
            proposer,
            state_commitment: [0u8; 32],
            commands_commitment: Block::commands_commitment(&commands),
            validator_history_commitment: [0u8; 32],
            committed_height: Height(height.saturating_sub(1)),
            committed_state_root: [0u8; 32],
            timestamp: 0,
        },
        commands,
    }
}

/// `eth_getLogs`-shaped staking logs: a `Withdraw` of `amount` for `node`,
/// which the stake ledger turns into a weight change (→ `recordWeight`).
fn withdraw_log(node: [u8; 32], amount: u64) -> Value {
    json!([{
        "topics": [staking::WITHDRAW_TOPIC, format!("0x{}", hex::encode(node))],
        "data": format!("0x{amount:064x}"),
    }])
}

fn bls_pk(seed: u8) -> BlsPublicKey {
    let mut ikm = [0u8; 32];
    ikm[0] = seed;
    BlsAggregated::keygen(&ikm).expect("test BLS keygen").1
}

/// ABI-encode a dynamic `bytes` value as EVM log data lays it out (offset,
/// length, right-padded payload). Mirrors the helper in `application.rs`'s tests.
fn abi_log_bytes(payload: &[u8]) -> String {
    let mut data = Vec::new();
    let mut off = [0u8; 32];
    off[31] = 0x20;
    data.extend_from_slice(&off);
    let mut len = [0u8; 32];
    len[24..32].copy_from_slice(&(payload.len() as u64).to_be_bytes());
    data.extend_from_slice(&len);
    data.extend_from_slice(payload);
    data.extend(std::iter::repeat_n(0u8, (32 - payload.len() % 32) % 32));
    format!("0x{}", hex::encode(data))
}

/// `eth_getLogs`-shaped rotation logs: a BLS-key rotation for `validator`
/// effective at `v_eff` (→ `recordKey`).
fn rotation_log(validator: [u8; 32], v_eff: u64, bls_seed: u8) -> Value {
    let payload = ValidatorKeyRotation {
        validator,
        new_pubkey: [0xCC; 32],
        v_eff: View::new(v_eff),
        new_bls_pubkey: Some(bls_pk(bls_seed)),
        new_bls_pop: None,
    };
    let cmd = DualSignedRotation {
        payload,
        sig_old: [0u8; 64],
        sig_new: [0u8; 64],
    }
    .encode_command();
    json!([{
        "topics": [rotation::ROTATION_TOPIC, format!("0x{}", hex::encode(validator))],
        "data": abi_log_bytes(&cmd),
    }])
}

fn ctx(proposer: NodeId) -> AppContext {
    AppContext {
        proposer,
        ..Default::default()
    }
}

/// The system account's address, as recovered from every submitted tx.
fn system_addr() -> Address {
    system_account::SYSTEM_ACCOUNT_ADDRESS.parse().unwrap()
}

// ---------------------------------------------------------------------------
// (a) proposer-only: non-proposers submit nothing; exactly one node writes.
// ---------------------------------------------------------------------------

/// A 4-node set commits the same block; only the block's proposer writes the
/// `recordWeight` + `recordSettled` system txs. The other three submit nothing,
/// so the EVM sees exactly one node's writes (no N-fold redundant pool spam).
#[tokio::test]
async fn only_the_proposer_submits_writes() {
    let nodes: Vec<NodeId> = (1u8..=4).map(|i| [i; 32]).collect();
    let leaving = [9u8; 32];
    let evm = SharedEvm::new();
    // This block carries a Withdraw that removes `leaving` (weight 0 → one
    // recordWeight). Every node reads the same per-block logs.
    let logs = BlockLogs::with(withdraw_log(leaving, 5), Value::Array(Vec::new()));

    let apps: Vec<RethApplication> = nodes
        .iter()
        .map(|&id| make_node(id, evm.clone(), logs.clone(), &[(leaving, 5)]))
        .collect();

    let proposer = nodes[2];
    let block = committed_block(1, 1, proposer);
    for app in &apps {
        app.commit(&ctx(proposer), &block).await.expect("commit");
    }

    let subs = evm.submissions();
    // Exactly: one recordWeight (leaving → 0) + one recordSettled(view 1).
    assert_eq!(
        subs.len(),
        2,
        "only the proposer submits; non-proposers write nothing: {subs:?}"
    );
    assert!(subs.iter().all(|s| s.sender == system_addr()));
    assert_eq!(
        subs[0].call,
        Call::RecordWeight {
            validator: leaving,
            weight: 0
        }
    );
    assert_eq!(subs[1].call, Call::RecordSettled { view: 1 });
    assert!(subs.iter().all(|s| s.applied), "both writes land");
    assert_eq!(evm.settled_view(), 1);
    assert_eq!(evm.weight_of(&leaving), 0, "removed validator drained");
}

// ---------------------------------------------------------------------------
// (b) proposer rotation: a different node proposes each view; exactly-once
//     writes with monotone, gap-free system-account nonces.
// ---------------------------------------------------------------------------

/// Across three views with a *rotating* proposer (node1, node2, node3), each
/// commit advances the settled frontier and (where a rotation log is present)
/// records a key. Every node commits every block, but only the per-view
/// proposer writes — so the shared system account's nonces are monotone and
/// gap-free (0,1,2,…), never colliding despite three different signers.
///
/// The node apps are *persistent* across the three blocks (heights advance
/// 1→2→3, frontier by one each commit, as on the real path), and the shared
/// [`BlockLogs`] is swapped before each block so every node reads that block's
/// own rotation logs.
#[tokio::test]
async fn rotating_proposer_writes_exactly_once_with_sane_nonces() {
    let nodes: Vec<NodeId> = (1u8..=3).map(|i| [i; 32]).collect();
    let rotating = [0x42u8; 32];
    let evm = SharedEvm::new();
    let logs = BlockLogs::default();

    // Persistent apps, one per validator, all sharing the one EVM + logs.
    let apps: Vec<RethApplication> = nodes
        .iter()
        .map(|&id| make_node(id, evm.clone(), logs.clone(), &[(rotating, 1)]))
        .collect();

    // Per-block rotation logs: blocks 1 & 3 carry a key rotation (strictly
    // increasing vEff), block 2 carries none. The proposer rotates each block.
    let per_block_rotation = [
        Some((5u64, 0x9au8)), // block 1 → recordKey vEff 5
        None,                 // block 2 → none
        Some((9u64, 0x33u8)), // block 3 → recordKey vEff 9
    ];
    for (i, rot) in per_block_rotation.iter().enumerate() {
        let height = (i + 1) as u64;
        let proposer = nodes[i]; // rotate the proposer each block
        match rot {
            Some((v_eff, seed)) => logs.set_rotation(rotation_log(rotating, *v_eff, *seed)),
            None => logs.set_rotation(Value::Array(Vec::new())),
        }
        let block = committed_block(height, height, proposer);
        for app in &apps {
            app.commit(&ctx(proposer), &block).await.expect("commit");
        }
    }

    let applied = evm.applied();
    // Two recordKeys (views 1 & 3) + three recordSettled (one per view) = 5.
    let keys: Vec<_> = applied
        .iter()
        .filter(|s| matches!(s.call, Call::RecordKey { .. }))
        .collect();
    let settled: Vec<_> = applied
        .iter()
        .filter(|s| matches!(s.call, Call::RecordSettled { .. }))
        .collect();
    assert_eq!(keys.len(), 2, "exactly two key writes across the rotation");
    assert_eq!(settled.len(), 3, "settled advances once per committed view");

    // Every write is the one system account, authored by whichever node was the
    // proposer that view.
    assert!(applied.iter().all(|s| s.sender == system_addr()));

    // The shared account's accepted-tx nonces are a dense, gap-free, monotone
    // sequence 0..n — no collision despite three rotating signers.
    let nonces: Vec<u64> = applied.iter().map(|s| s.nonce).collect();
    let expected: Vec<u64> = (0..applied.len() as u64).collect();
    assert_eq!(nonces, expected, "monotone gap-free nonces: {nonces:?}");

    assert_eq!(evm.settled_view(), 3, "settled frontier reached view 3");
}

// ---------------------------------------------------------------------------
// (c) restart replay / idempotency: re-committing already-committed blocks
//     re-submits, but the monotone guards revert the duplicates — no corruption.
// ---------------------------------------------------------------------------

/// Simulate a node restart that re-derives from the *same* committed state and
/// re-commits the same blocks. The duplicate `recordKey` (same `vEff`) and
/// `recordSettled` (same/older view) submissions are *accepted into the pool*
/// (consuming nonces) but **revert as no-ops** in the EVM — the monotone `vEff`
/// guard and the settled-view clamp hold, so the on-chain frontier is exactly
/// what it was before the replay. No double-write, no corruption.
#[tokio::test]
async fn restart_replay_is_idempotent_no_corruption() {
    let proposer = [1u8; 32];
    let rotating = [0x42u8; 32];
    let evm = SharedEvm::new();
    let logs = BlockLogs::with(Value::Array(Vec::new()), rotation_log(rotating, 5, 0x9a));

    // A node restart re-derives a fresh `RethApplication` over reth's already
    // persisted state (the same `SharedEvm`) and re-commits the identical block.
    let commit_block_1 = || {
        let evm = evm.clone();
        let logs = logs.clone();
        async move {
            let app = make_node(proposer, evm, logs, &[(rotating, 1)]);
            let block = committed_block(1, 7, proposer);
            app.commit(&ctx(proposer), &block).await.expect("commit");
        }
    };

    // First commit: records key(vEff 5) + settled(view 7).
    commit_block_1().await;
    let after_first = evm.applied().len();
    assert_eq!(
        after_first, 2,
        "first commit lands recordKey + recordSettled"
    );
    let frontier_key = evm.0.lock().key_frontier.get(&rotating).copied();
    assert_eq!(frontier_key, Some(5));
    assert_eq!(evm.settled_view(), 7);

    // Restart: a fresh app over the *same* EVM re-derives and re-commits the
    // identical block (same vEff 5, same view 7).
    commit_block_1().await;

    // The replay submitted two more txs, but neither changed state.
    let total = evm.submissions().len();
    assert_eq!(total, 4, "replay re-submits both writes");
    let applied_after = evm.applied().len();
    assert_eq!(
        applied_after, after_first,
        "the replayed writes revert (monotone guard + clamp); no new state change"
    );
    // The frontier is untouched: no corruption, no double-advance.
    assert_eq!(
        evm.0.lock().key_frontier.get(&rotating).copied(),
        Some(5),
        "recordKey vEff frontier unchanged by the duplicate"
    );
    assert_eq!(
        evm.settled_view(),
        7,
        "settled view unchanged by the replayed recordSettled"
    );

    // And the replayed txs reverted because the contract guards rejected them,
    // not because reth dropped the nonce: they were accepted with fresh nonces.
    let replayed: Vec<_> = evm.submissions().into_iter().skip(2).collect();
    assert!(
        replayed.iter().all(|s| !s.applied),
        "both replayed writes are no-ops"
    );
    assert!(
        replayed
            .iter()
            .any(|s| matches!(s.call, Call::RecordKey { v_eff: 5, .. })),
        "the duplicate recordKey was re-submitted and reverted"
    );
}

// ---------------------------------------------------------------------------
// A guard test: a non-proposer commit never reads/writes the registry, even
// when this block carries rotation + staking logs.
// ---------------------------------------------------------------------------

/// A node that is *not* the committed block's proposer submits nothing, even
/// when the block carries a rotation (recordKey) and a weight change
/// (recordWeight) — the `ctx.proposer == self_id` gate fully suppresses the
/// write path on every non-proposing replica.
#[tokio::test]
async fn non_proposer_with_write_triggering_logs_submits_nothing() {
    let me = [1u8; 32];
    let proposer = [2u8; 32]; // someone else proposed this block
    let rotating = [0x42u8; 32];
    let evm = SharedEvm::new();

    let logs = BlockLogs::with(withdraw_log(rotating, 1), rotation_log(rotating, 5, 0x9a));
    let app = make_node(me, evm.clone(), logs, &[(rotating, 1)]);
    let block = committed_block(1, 1, proposer);
    let result = app.commit(&ctx(proposer), &block).await.expect("commit");

    // The commit still *derives* effects/updates (every node does that) …
    assert!(
        result
            .effects
            .iter()
            .any(|e| matches!(e, ValidatorEffect::KeyRotation(_))),
        "the non-proposer still surfaces the rotation effect to consensus"
    );
    // … but submits zero system txs.
    assert!(
        evm.submissions().is_empty(),
        "a non-proposer writes nothing: {:?}",
        evm.submissions()
    );
}
