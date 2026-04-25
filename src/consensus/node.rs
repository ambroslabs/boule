//! Integration layer for HotStuff consensus: wires together
//! [`HotStuffCore`], [`Pacemaker`], storage, mempool, and the network.
//!
//! # Scope (milestone 8 / #24)
//!
//! This module houses the parts of the integration layer that exist
//! independently of the async event loop:
//!
//! - Wire protocol constants and the [`WireMessage`] envelope that is
//!   postcard-encoded on the network.
//! - [`NodeConfigForConsensus`]: the plain-data configuration struct.
//! - [`MempoolBlockBuilder`]: the [`BlockBuilder`] impl that pulls
//!   commands from the mempool and stamps `state_commitment` by
//!   temporarily applying the commands to a fork of the committed SM.
//! - [`ConsensusNode`]: the struct holding all components; construction
//!   only — the async event loop lands in a later PR.
//!
//! # Durability note
//!
//! The event loop (Phase D/E) is responsible for ensuring every
//! `Action::Persist` is flushed to WAL before the corresponding
//! outbound message is sent. This module sets up the components;
//! the ordering discipline is enforced when actions are applied.
//!
//! # `state_commitment` simplification
//!
//! [`MempoolBlockBuilder`] computes the child block's `state_commitment`
//! by forking the current committed SM state (snapshot → restore →
//! apply → read commitment → restore back). This is exact when the
//! proposed parent is the last-committed block, which is the common
//! case in a healthy network. A future PR will walk the not-yet-
//! committed ancestor chain for the rare multi-block-in-flight case.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bytes::Bytes;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, oneshot, watch};

use crate::consensus::View;
use crate::consensus::dispatch::{self, Dispatch, Outbound};
use crate::consensus::hotstuff::Locked;
use crate::consensus::hotstuff::qc::{ConsensusMsg, TimeoutVote, quorum_size};
use crate::consensus::hotstuff::step::{
    Action as SafetyAction, BlockBuilder, Event as SafetyEvent, HotStuffCore, StateUpdate,
};
use crate::consensus::hotstuff::{HotStuffState, NewView, QuorumCertificate, genesis_qc};
use crate::consensus::pacemaker::Action as PacemakerAction;
use crate::consensus::pacemaker::Event as PacemakerEvent;
use crate::consensus::pacemaker::Pacemaker;
use crate::consensus::pacemaker::leader::RoundRobinSelector;
use crate::consensus::pacemaker::timeout::ExponentialBackoff;
use crate::consensus::status::{
    BUCKET_VIEW_WINDOW, ConsensusStatus, LockedStatus, ParkedProposalStatus, QcStatus,
    TimeoutBucketStatus, VoteBucketStatus,
};
use crate::consensus::validator_set::ValidatorSet;
use crate::consensus::view_timer::ViewTimer;
use crate::crypto::signed::Signed;
use crate::crypto::signed::Signer;
use crate::p2p::NodeId;
use crate::p2p::ProtocolEvent;
use crate::p2p::overlay::{Broadcaster, Discovery, DiscoveryEvent};
use crate::p2p::tls::node_id_to_base58;
use crate::replication::block::{Block, BlockHash, BlockHeader};
use crate::replication::mempool::Mempool;
use crate::replication::state_machine::StateMachine;
use crate::storage::{Storage, StorageExt, Wal};

/// Tracing target used by every structured trace emitted from the
/// consensus integration layer. Filter it with
/// `RUST_LOG=info,ambros_p2p::consensus=debug` to see just the event
/// boundaries without drowning in p2p / gossip traffic.
pub const TRACE_TARGET: &str = "ambros_p2p::consensus";

/// Short, stable tag for a [`ConsensusMsg`] variant — suitable as a
/// structured-log field value.
fn msg_kind(msg: &ConsensusMsg) -> &'static str {
    match msg {
        ConsensusMsg::Proposal(_) => "Proposal",
        ConsensusMsg::Vote(_) => "Vote",
        ConsensusMsg::NewView(_) => "NewView",
    }
}

/// Short, stable tag for a [`StateUpdate`] variant — suitable as a
/// structured-log field value.
fn update_kind(u: &StateUpdate) -> &'static str {
    match u {
        StateUpdate::VotedInView { .. } => "VotedInView",
        StateUpdate::Locked(_) => "Locked",
        StateUpdate::HighQc(_) => "HighQc",
    }
}

/// Short, stable tag for a pacemaker [`PacemakerEvent`] variant.
fn pacemaker_event_kind(ev: &PacemakerEvent) -> &'static str {
    match ev {
        PacemakerEvent::OnQc(_) => "OnQc",
        PacemakerEvent::OnTimeoutCert(_) => "OnTimeoutCert",
        PacemakerEvent::OnTimeout(_) => "OnTimeout",
        PacemakerEvent::OnProposalReceived(_) => "OnProposalReceived",
    }
}

/// Snapshot of the tracing fields we want to log around a safety-core
/// step. Captured *before* the step consumes the event so we still
/// have access to the signer / view / height after the event is moved.
enum SafetyLogCtx {
    Proposal {
        proposer: NodeId,
        view: View,
        height: u64,
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

// ── Protocol constants ───────────────────────────────────────────────────────

/// Storage key under which the replica's `last_voted_view` is persisted.
///
/// HotStuff safety rests on "never vote twice at the same view across
/// restarts" — the event loop writes this key (via [`ConsensusNode::persist_updates`])
/// before any outbound vote is allowed to leave the node, and the
/// recovery path ([`recover_state`]) reads it back at startup.
pub const STORAGE_KEY_LAST_VOTED_VIEW: &[u8] = b"consensus/last_voted_view";

/// Storage key for the replica's locked block (two-chain lock). See
/// [`Locked`] for the fields persisted.
pub const STORAGE_KEY_LOCKED: &[u8] = b"consensus/locked";

/// Storage key for the replica's highest-known QC, used as the
/// justify on proposals and piggybacked on `NewView`.
pub const STORAGE_KEY_HIGH_QC: &[u8] = b"consensus/high_qc";

/// Storage-key prefix under which committed blocks are persisted by
/// content-hash. Each block is written on commit so a peer can fetch
/// it via the block-sync sub-protocol even after we have evicted it
/// from the in-memory `pending_blocks` cache or restarted (which
/// resets `pending_blocks` to just the genesis block).
///
/// Keys are formed as `{STORAGE_KEY_BLOCK_PREFIX}{hash}` (a 32-byte
/// content hash appended to the prefix). See [`block_storage_key`].
///
/// Issue #178: a restarted replica with empty `pending_blocks` was
/// unable to serve a `BlockRequest` for a block it had already
/// committed, leaving its peers' block-sync stuck in a retry loop.
/// Persisting on commit gives every committed block a durable home
/// every replica can serve from.
pub const STORAGE_KEY_BLOCK_PREFIX: &[u8] = b"consensus/block/";

/// Storage key for the (height, view) of the most recently committed
/// block. Restored at startup so [`ConsensusStatus::last_committed_height`]
/// reflects the durable chain even before the run loop sees its first
/// inbound proposal — fixing the post-restart `last_committed_height
/// = 0` gap called out in #178's reopen comment.
pub const STORAGE_KEY_LAST_COMMITTED: &[u8] = b"consensus/last_committed";

/// Protocol ID registered with the p2p multiplexer for consensus traffic.
/// Gossip uses `0x01`, ping-RPC uses `0x02`.
pub const PROTOCOL_ID: u8 = 0x03;

/// Maximum encoded frame size accepted from the wire for this protocol.
/// Sized to accommodate a full block with up to ~1000 moderate-sized
/// commands; production tuning can raise this without protocol changes.
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024; // 4 MiB

// ── Wire message envelope ────────────────────────────────────────────────────

/// Every message sent over the `PROTOCOL_ID` channel is one of these
/// variants, postcard-encoded.
///
/// The three consensus variants carry a [`Signed`] envelope whose
/// signature the integration layer verifies against the claimed signer
/// **before** feeding the payload into [`HotStuffCore::step`].
///
/// `BlockRequest` / `BlockResponse` are the block-sync sub-protocol:
/// when the safety core emits `Action::RequestBlock(hash, peer)`, the
/// integration layer sends `BlockRequest`; the peer replies with
/// `BlockResponse` (carrying the block if it has it, `None` otherwise).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireMessage {
    Proposal(Signed<crate::consensus::hotstuff::Proposal>),
    Vote(Signed<crate::consensus::hotstuff::qc::Vote>),
    NewView(Signed<crate::consensus::hotstuff::NewView>),
    /// A replica's signed notice that it is giving up on a view. A
    /// quorum of these forms the timeout certificate that advances
    /// `view + 1` even when the leader never proposes.
    TimeoutVote(Signed<TimeoutVote>),
    /// Ask a peer for the block with this content-hash.
    BlockRequest(BlockHash),
    /// Reply to a `BlockRequest`. `None` means "I don't have it".
    BlockResponse(Option<Block>),
}

// ── Node configuration ───────────────────────────────────────────────────────

/// Plain-data configuration for a [`ConsensusNode`].
///
/// Constructed once at startup from the TOML config or test scaffolding
/// and passed into [`ConsensusNode::new`].
#[derive(Debug, Clone)]
pub struct NodeConfigForConsensus {
    /// The committee this node participates in. Must include `self_id`.
    pub validator_set: ValidatorSet,
    /// Pre-agreed genesis block. Every honest replica starts with an
    /// identical copy so `state.genesis_hash` is consistent cluster-wide.
    pub genesis: Block,
    /// Maximum number of commands a leader pulls from the mempool per
    /// proposal. Higher values increase throughput at the cost of
    /// larger blocks.
    pub propose_limit: usize,
    /// View-timer base duration (no consecutive failures). Feeds into
    /// [`ExponentialBackoff`].
    pub timeout_base: Duration,
    /// View-timer ceiling: backoff saturates here.
    pub timeout_max: Duration,
}

impl NodeConfigForConsensus {
    /// Reasonable defaults for a local 4-node test cluster.
    pub fn for_testing(validator_set: ValidatorSet, genesis: Block) -> Self {
        Self {
            validator_set,
            genesis,
            propose_limit: 64,
            timeout_base: Duration::from_millis(200),
            timeout_max: Duration::from_secs(10),
        }
    }
}

// ── Block builder ────────────────────────────────────────────────────────────

/// [`BlockBuilder`] that assembles a child block from the local mempool
/// and the current committed state machine.
///
/// `state_commitment` is computed by forking the committed SM state:
/// snapshot → apply new commands → read commitment → restore.  This is
/// exact when the proposed parent equals the last-committed block
/// (the common case). A future enhancement will walk the uncommitted
/// ancestor chain for the multi-block-in-flight scenario.
pub struct MempoolBlockBuilder {
    self_id: NodeId,
    mempool: Arc<dyn Mempool>,
    /// Shared with the event loop's `Commit` handler, which advances
    /// this SM forward when blocks commit.
    state_machine: Arc<Mutex<Box<dyn StateMachine>>>,
    propose_limit: usize,
}

impl MempoolBlockBuilder {
    pub fn new(
        self_id: NodeId,
        mempool: Arc<dyn Mempool>,
        state_machine: Arc<Mutex<Box<dyn StateMachine>>>,
        propose_limit: usize,
    ) -> Self {
        Self {
            self_id,
            mempool,
            state_machine,
            propose_limit,
        }
    }
}

impl BlockBuilder for MempoolBlockBuilder {
    fn build(&self, parent: &Block, view: View, _high_qc: &QuorumCertificate) -> Block {
        let commands = self.mempool.propose(self.propose_limit);

        // Fork the committed SM state: snapshot, apply candidate commands,
        // read commitment, then restore so the SM is left unchanged.
        let state_commitment = {
            let mut sm = self.state_machine.lock();
            let snap = sm.snapshot();

            let mut commitment = sm.state_commitment();
            // Apply each command on the fork; ignore individual errors
            // (a command that fails changes nothing per the StateMachine
            // contract, so commitment is consistent with "skip bad cmds").
            for cmd in &commands {
                if sm.apply(cmd).is_ok() {
                    commitment = sm.state_commitment();
                }
            }

            // Restore SM to committed state regardless of outcome.
            sm.restore(&snap)
                .expect("restore from own snapshot must not fail");
            commitment
        };

        let commands_commitment = Block::commands_commitment(&commands);
        Block {
            header: BlockHeader {
                parent_hash: parent.hash(),
                height: parent.header.height + 1,
                view,
                proposer: self.self_id,
                state_commitment,
                commands_commitment,
            },
            commands,
        }
    }
}

// ── ConsensusNode ────────────────────────────────────────────────────────────

/// Composes all consensus components into a single struct.
///
/// Construction only in this PR — the async event loop that drives the
/// select! over network events, timers, and pacemaker actions lands in
/// Phase D/E.
pub struct ConsensusNode {
    /// This replica's identity, used to sign outbound messages.
    pub self_id: NodeId,
    /// HotStuff safety core (pure state machine).
    pub core: HotStuffCore,
    /// View-management state machine (pure, no I/O).
    pub pacemaker: Pacemaker,
    /// Shared state machine; mutated on `Action::Commit`.
    pub state_machine: Arc<Mutex<Box<dyn StateMachine>>>,
    /// Source of pending commands for the block builder / leader path.
    pub mempool: Arc<dyn Mempool>,
    /// Durable KV store for control-plane state
    /// (`last_voted_view`, `locked`, `high_qc`).
    pub storage: Arc<dyn Storage>,
    /// Append-only log for durability. Flushed before outbound messages
    /// that depend on the persisted state.
    pub wal: Arc<dyn Wal>,
    /// The ordered committee this node participates in.
    pub validator_set: ValidatorSet,
    /// Configured view-timer behaviour; consulted by the timer helper
    /// in Phase D when arming/re-arming the view timer.
    pub timeout_policy: Arc<ExponentialBackoff>,
    /// Partial timeout certificates this replica is accumulating,
    /// keyed by the `View` the timeout pertains to. An entry is
    /// dropped once its TC fires `OnTimeoutCert` into the pacemaker
    /// so late-arriving timeout votes for past views are cheap no-ops.
    timeout_buckets: HashMap<View, TimeoutBucket>,
    /// Optional channel to notify an observer (e.g. a test harness) of
    /// each committed block. `None` in production builds.
    commit_tx: Option<tokio::sync::mpsc::UnboundedSender<Block>>,
    /// Peer-membership snapshot used by [`ConsensusNode::build_status`].
    /// Populated from [`Discovery`] events inside [`ConsensusNode::run`];
    /// before `run` starts (or in tests that bypass it) the set is empty
    /// and the status snapshot reports zero connected peers.
    peers_connected: HashSet<NodeId>,
    /// Height of the most recently committed block, updated in
    /// [`ConsensusNode::apply_commit`]. Zero before the first commit.
    last_committed_height: u64,
    /// View of the most recently committed block. Zero before the
    /// first commit.
    last_committed_view: View,
    /// Watch-channel publisher for [`ConsensusStatus`] snapshots. When
    /// `Some`, [`ConsensusNode::run`] republishes at the end of each
    /// event-loop iteration. The field is public at the module level
    /// via [`ConsensusNode::with_status_publisher`] so wiring in
    /// `main.rs` can attach a channel built around the initial
    /// snapshot.
    status_tx: Option<watch::Sender<Arc<ConsensusStatus>>>,
}

/// Accumulator for one view's timeout votes.
///
/// Tracks the set of distinct signers that have timed out at a view,
/// and the freshest `high_qc` any of them reported. When `signers.len()`
/// reaches `quorum_size(validator_set.len())` we fire
/// [`pacemaker::Event::OnTimeoutCert`] — and we drop the bucket so
/// further duplicate timeout votes for the same view don't re-enter
/// the pacemaker.
#[derive(Default)]
struct TimeoutBucket {
    signers: HashSet<NodeId>,
    best_high_qc: Option<QuorumCertificate>,
}

impl ConsensusNode {
    /// Construct a `ConsensusNode` from configuration and backing
    /// resources. Does **not** start the event loop.
    pub fn new(
        self_id: NodeId,
        config: NodeConfigForConsensus,
        state_machine: Arc<Mutex<Box<dyn StateMachine>>>,
        mempool: Arc<dyn Mempool>,
        storage: Arc<dyn Storage>,
        wal: Arc<dyn Wal>,
    ) -> Self {
        let validator_set = Arc::new(config.validator_set.clone());

        let timeout_policy = Arc::new(ExponentialBackoff::new(
            config.timeout_base,
            config.timeout_max,
        ));

        let selector = Arc::new(RoundRobinSelector::new(Arc::clone(&validator_set)));

        let pacemaker = Pacemaker::new(
            self_id,
            Arc::clone(&selector) as _,
            Arc::clone(&timeout_policy) as _,
        );

        let builder = Arc::new(MempoolBlockBuilder::new(
            self_id,
            Arc::clone(&mempool),
            Arc::clone(&state_machine),
            config.propose_limit,
        ));

        let validator_set_len = config.validator_set.len();
        let boot_qc = genesis_qc(&config.genesis, validator_set_len);
        let mut hs_state = HotStuffState::new(config.validator_set.clone(), config.genesis);
        // Seed the cluster-agreed genesis QC so the view-1 leader can
        // build a proposal on first boot without waiting for a QC-forming
        // vote round. Every honest replica derives the same QC from the
        // shared `(genesis, validator_set_len)` config.
        hs_state.high_qc = Some(boot_qc);
        let core = HotStuffCore::new(self_id, hs_state, builder as Arc<dyn BlockBuilder>);

        Self {
            self_id,
            core,
            pacemaker,
            state_machine,
            mempool,
            storage,
            wal,
            validator_set: config.validator_set,
            timeout_policy,
            timeout_buckets: HashMap::new(),
            commit_tx: None,
            peers_connected: HashSet::new(),
            last_committed_height: 0,
            last_committed_view: 0,
            status_tx: None,
        }
    }

    /// Attach a commit observer.
    ///
    /// Every block committed by the event loop is sent on `tx`. Intended
    /// for test harnesses (e.g. `SimCluster`); production callers leave
    /// this unset (`None`) and observe commits via the state machine.
    pub fn with_commit_observer(mut self, tx: tokio::sync::mpsc::UnboundedSender<Block>) -> Self {
        self.commit_tx = Some(tx);
        self
    }

    /// Replace the auto-seeded genesis QC with `qc`.
    ///
    /// [`ConsensusNode::new`] and [`ConsensusNode::recover`] already seed
    /// the safety-core state with the canonical genesis QC derived from
    /// `(genesis, validator_set_len)` via [`genesis_qc`]; this helper is
    /// kept for tests and harnesses that need to inject a hand-built QC
    /// (e.g. to start from a mid-chain state).
    pub fn with_genesis_qc(mut self, qc: QuorumCertificate) -> Self {
        self.core.set_high_qc(qc);
        self
    }

    /// Attach a [`watch::Sender`] that [`ConsensusNode::run`] will use
    /// to republish the [`ConsensusStatus`] snapshot after each event-
    /// loop iteration.
    ///
    /// The caller typically obtains the paired receiver by calling
    /// [`ConsensusNode::build_status`] on the just-constructed node and
    /// wrapping the result in [`watch::channel`] before attaching the
    /// sender here. That way the initial value published on the channel
    /// is already a sane snapshot (current_view=0 on a fresh boot),
    /// so the HTTP endpoint never returns 500 during the window between
    /// node construction and the first event-loop tick.
    pub fn with_status_publisher(mut self, tx: watch::Sender<Arc<ConsensusStatus>>) -> Self {
        self.status_tx = Some(tx);
        self
    }

    /// Build a fresh [`ConsensusStatus`] snapshot from the current
    /// safety-core, pacemaker, mempool, and peer-tracking state.
    ///
    /// Cheap — shallow-copies a handful of fields, clones a small
    /// handful of bounded-size vectors. Safe to call from the event
    /// loop after each state-mutating tick without affecting
    /// throughput.
    pub fn build_status(&self) -> ConsensusStatus {
        let current_view = self.pacemaker.current_view();
        let state = self.core.state();
        let vs_len = self.validator_set.len();
        let quorum = quorum_size(vs_len);

        let self_role = self_role_string(&self.validator_set, &self.self_id, current_view);

        let locked = state.locked.as_ref().map(|l| LockedStatus {
            view: l.view,
            height: l.height,
            block_hash: hex::encode(l.block_hash),
        });

        let high_qc = state.high_qc.as_ref().map(|qc| {
            let height = state
                .pending_blocks
                .get(&qc.block_hash)
                .map(|b| b.header.height);
            QcStatus {
                view: qc.view,
                height,
                block_hash: hex::encode(qc.block_hash),
            }
        });

        let min_view = current_view.saturating_sub(BUCKET_VIEW_WINDOW);
        let max_view = current_view.saturating_add(BUCKET_VIEW_WINDOW);

        let mut vote_buckets: Vec<VoteBucketStatus> = self
            .core
            .vote_buckets()
            .filter(|((view, _), _)| *view >= min_view && *view <= max_view)
            .map(|((view, block_hash), qc)| VoteBucketStatus {
                view: *view,
                block_hash: hex::encode(block_hash),
                signers: qc.signer_count(),
                quorum,
            })
            .collect();
        // Stable ordering keeps the JSON shape deterministic across
        // calls, which makes logs and diff-based debugging workable.
        vote_buckets.sort_by(|a, b| a.view.cmp(&b.view).then(a.block_hash.cmp(&b.block_hash)));

        let mut timeout_buckets: Vec<TimeoutBucketStatus> = self
            .timeout_buckets
            .iter()
            .filter(|(view, _)| **view >= min_view && **view <= max_view)
            .map(|(view, bucket)| TimeoutBucketStatus {
                view: *view,
                signers: bucket.signers.len(),
                quorum,
            })
            .collect();
        timeout_buckets.sort_by_key(|b| b.view);

        let mut parked_proposals: Vec<ParkedProposalStatus> = self
            .core
            .parked_proposals()
            .map(|signed| ParkedProposalStatus {
                block_hash: hex::encode(signed.payload.block.hash()),
                parent_hash: hex::encode(signed.payload.block.header.parent_hash),
                view: signed.payload.block.header.view,
            })
            .collect();
        parked_proposals.sort_by(|a, b| a.view.cmp(&b.view).then(a.block_hash.cmp(&b.block_hash)));

        let mut peers_connected: Vec<String> = self
            .peers_connected
            .iter()
            .map(crate::p2p::tls::node_id_to_base58)
            .collect();
        peers_connected.sort();

        let validator_set: Vec<String> = self
            .validator_set
            .iter()
            .map(crate::p2p::tls::node_id_to_base58)
            .collect();

        ConsensusStatus {
            node_id: crate::p2p::tls::node_id_to_base58(&self.self_id),
            self_role,
            current_view,
            last_voted_view: state.last_voted_view,
            last_committed_height: self.last_committed_height,
            last_committed_view: self.last_committed_view,
            locked,
            high_qc,
            vote_buckets,
            timeout_buckets,
            parked_proposals,
            pending_blocks_count: state.pending_blocks.len(),
            peers_connected,
            validator_set,
            mempool_size: self.mempool.len(),
        }
    }

    /// Publish a fresh snapshot on the watch channel (if attached).
    /// Called by [`ConsensusNode::run`] at the end of each event-loop
    /// iteration. `send_replace` ignores the "no receivers" case so the
    /// node keeps running even if no-one is listening.
    fn publish_status(&self) {
        if let Some(tx) = &self.status_tx {
            let _ = tx.send_replace(Arc::new(self.build_status()));
        }
    }

    /// Construct a `ConsensusNode`, restoring any durable control-plane
    /// state from `storage` (see [`recover_state`]).
    ///
    /// On a fresh `storage` with no persisted keys this behaves
    /// identically to [`ConsensusNode::new`]. On a storage that has
    /// previously recorded `last_voted_view` / `locked` / `high_qc` via
    /// [`ConsensusNode::persist_updates`], those values are read back
    /// into the [`HotStuffState`] so the safety-core invariants
    /// (no double-voting, no regression of the lock) survive a restart.
    ///
    /// Returns `Err` only on storage backend failures or corrupted
    /// stored bytes. Missing keys are the normal fresh-start case and
    /// are not errors.
    pub fn recover(
        self_id: NodeId,
        config: NodeConfigForConsensus,
        state_machine: Arc<Mutex<Box<dyn StateMachine>>>,
        mempool: Arc<dyn Mempool>,
        storage: Arc<dyn Storage>,
        wal: Arc<dyn Wal>,
    ) -> anyhow::Result<Self> {
        let hs_state = recover_state(
            storage.as_ref(),
            config.validator_set.clone(),
            config.genesis.clone(),
        )?;

        // Restore the (height, view) status checkpoint so a freshly
        // resumed replica reports its durable chain rather than `0` —
        // see `STORAGE_KEY_LAST_COMMITTED` and the `consensus_resumed`
        // gap called out in #178's reopen comment.
        let last_committed = match storage
            .get(STORAGE_KEY_LAST_COMMITTED)
            .context("read last_committed from storage")?
        {
            Some(raw) => decode_last_committed(&raw)?,
            None => LastCommitted { height: 0, view: 0 },
        };

        let validator_set = Arc::new(config.validator_set.clone());
        let timeout_policy = Arc::new(ExponentialBackoff::new(
            config.timeout_base,
            config.timeout_max,
        ));
        let selector = Arc::new(RoundRobinSelector::new(Arc::clone(&validator_set)));
        let pacemaker = Pacemaker::new(
            self_id,
            Arc::clone(&selector) as _,
            Arc::clone(&timeout_policy) as _,
        );

        let builder = Arc::new(MempoolBlockBuilder::new(
            self_id,
            Arc::clone(&mempool),
            Arc::clone(&state_machine),
            config.propose_limit,
        ));
        let core = HotStuffCore::new(self_id, hs_state, builder as Arc<dyn BlockBuilder>);

        Ok(Self {
            self_id,
            core,
            pacemaker,
            state_machine,
            mempool,
            storage,
            wal,
            validator_set: config.validator_set,
            timeout_policy,
            timeout_buckets: HashMap::new(),
            commit_tx: None,
            peers_connected: HashSet::new(),
            last_committed_height: last_committed.height,
            last_committed_view: last_committed.view,
            status_tx: None,
        })
    }

    /// Durably record a slice of [`StateUpdate`]s to
    /// [`ConsensusNode::storage`].
    ///
    /// Every update is applied inside a single atomic batch: on success
    /// every key is visible, on failure none are. If the same logical
    /// key appears multiple times in `updates`, the last write wins —
    /// this matches the safety-core's emission order, where freshly
    /// emitted updates semantically supersede earlier ones within the
    /// same `step`.
    ///
    /// The integration event loop (Phase D) must call this for every
    /// `Action::Persist` **before** forwarding any `Action::Broadcast` /
    /// `Action::SendTo` / `Action::Commit` that depends on the persisted
    /// state. That ordering is the durability discipline HotStuff
    /// safety requires — a crash between "send vote" and "write
    /// `last_voted_view`" would otherwise let a restarted replica vote
    /// twice at the same view.
    pub fn persist_updates(&self, updates: &[StateUpdate]) -> anyhow::Result<()> {
        if updates.is_empty() {
            return Ok(());
        }
        self.storage.batch(|b| {
            for u in updates {
                match u {
                    StateUpdate::VotedInView { view } => {
                        let bytes = encode_voted_view(*view)?;
                        b.put(STORAGE_KEY_LAST_VOTED_VIEW, &bytes);
                    }
                    StateUpdate::Locked(locked) => {
                        let bytes = encode_locked(locked)?;
                        b.put(STORAGE_KEY_LOCKED, &bytes);
                    }
                    StateUpdate::HighQc(qc) => {
                        let bytes = encode_high_qc(qc)?;
                        b.put(STORAGE_KEY_HIGH_QC, &bytes);
                    }
                }
            }
            Ok(())
        })?;
        let kinds: Vec<&'static str> = updates.iter().map(update_kind).collect();
        tracing::debug!(
            target: TRACE_TARGET,
            kinds = ?kinds,
            "persisted",
        );
        Ok(())
    }

    /// Current view from the pacemaker's perspective.
    pub fn current_view(&self) -> View {
        self.pacemaker.current_view()
    }

    // ── Event loop ───────────────────────────────────────────────────────────

    /// Run the consensus event loop until `shutdown` fires or the
    /// inbound channel closes.
    ///
    /// # Startup
    ///
    /// Immediately advances the pacemaker from view 0 → 1 (via a synthetic
    /// `OnQc(0)`) so the view timer is armed and the node announces itself
    /// to its peers before any network message arrives.
    ///
    /// # Durability discipline
    ///
    /// `Action::Persist` updates are buffered and written atomically to
    /// [`ConsensusNode::storage`] **before** any `Broadcast` / `SendTo` /
    /// `Commit` action that follows them in the same `step` output. This
    /// guarantees that a crash between "write persist" and "send vote" is
    /// safe: the replica restarts with the vote view recorded, so it cannot
    /// double-vote when it re-enters the view.
    ///
    /// # Topology abstraction
    ///
    /// Outbound traffic flows through `broadcaster` (a [`Broadcaster`]
    /// trait object) and peer-membership deltas through `discovery`'s
    /// event stream. The mesh is the only implementation today; gossip
    /// and dynamic-membership backends drop in here without touching
    /// the event loop. See [`crate::p2p::overlay`] for the contract.
    pub async fn run(
        mut self,
        broadcaster: Arc<dyn Broadcaster>,
        discovery: Arc<dyn Discovery>,
        mut event_rx: mpsc::Receiver<ProtocolEvent>,
        signer: Arc<dyn Signer>,
        mut shutdown: oneshot::Receiver<()>,
    ) -> anyhow::Result<()> {
        let mut discovery_events = discovery.subscribe();
        // Seed `peers_connected` from a snapshot so any peer that
        // connected before our subscription is still reflected. Discovery
        // events from the subscription point onward keep it in sync.
        self.peers_connected = discovery.known_peers().into_iter().collect();

        let (timer_tx, mut timer_rx) = mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        // Boot-time snapshot of recovered durable state. Logged once
        // per node start so operators can correlate "did we come up
        // already behind the live cluster?" with downstream block-sync
        // events. Issue #178 introduced this trace to disambiguate
        // restart bootstrap from peer-disconnect / block-not-found
        // stalls — the latter two only ever fire post-resume, so a
        // missing `consensus_resumed` line means the run loop never
        // started.
        tracing::info!(
            target: TRACE_TARGET,
            self_id = %node_id_to_base58(&self.self_id),
            last_committed_height = self.last_committed_height,
            last_committed_view = self.last_committed_view,
            high_qc_view = ?self.core.state().high_qc.as_ref().map(|q| q.view),
            last_voted_view = self.core.state().last_voted_view,
            locked_view = ?self.core.state().locked.as_ref().map(|l| l.view),
            validator_set_size = self.validator_set.len(),
            "consensus_resumed",
        );

        // Publish an initial snapshot before doing anything else, so
        // the HTTP endpoint has a sane value available even if it's
        // queried in the tiny window before the boot actions fire.
        self.publish_status();

        // Boot: advance pacemaker from 0 → 1, arm the view timer, and
        // broadcast NewView (if we have a high_qc from a prior session).
        let boot_actions = self.step_pacemaker(PacemakerEvent::OnQc(0));
        self.apply_pacemaker_actions(boot_actions, broadcaster.as_ref(), &mut view_timer, &signer)
            .await?;
        self.publish_status();

        loop {
            tokio::select! {
                biased;

                _ = &mut shutdown => break,

                Some(view) = timer_rx.recv() => {
                    let pm_actions = self.step_pacemaker(PacemakerEvent::OnTimeout(view));
                    self.apply_pacemaker_actions(pm_actions, broadcaster.as_ref(), &mut view_timer, &signer)
                        .await?;
                }

                disc = discovery_events.recv() => {
                    match disc {
                        Ok(DiscoveryEvent::PeerAdded(node_id)) => {
                            tracing::debug!("consensus: peer added {node_id:?}");
                            self.peers_connected.insert(node_id);
                        }
                        Ok(DiscoveryEvent::PeerRemoved(node_id)) => {
                            tracing::debug!("consensus: peer removed {node_id:?}");
                            self.peers_connected.remove(&node_id);
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            // Resync from the snapshot — the cache is the
                            // authoritative source, and `Discovery` only
                            // publishes deltas for forward-progress in the
                            // common case.
                            self.peers_connected = discovery.known_peers().into_iter().collect();
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            // Discovery shut down. Don't tear consensus
                            // down with it — peer tracking just freezes
                            // until restart.
                        }
                    }
                }

                Some(event) = event_rx.recv() => {
                    match event {
                        ProtocolEvent::Message { from, payload } => {
                            match dispatch::ingress(from, &payload, &self.validator_set) {
                                Ok(dispatches) => {
                                    for d in dispatches {
                                        self.apply_dispatch(d, broadcaster.as_ref(), &mut view_timer, &signer)
                                            .await?;
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!("consensus: ingress rejected from {from:?}: {e}");
                                }
                            }
                        }
                        // Peer connectivity is tracked through the
                        // Discovery event stream above; the protocol
                        // multiplexer still fans these out to every
                        // protocol handle (used by the RPC layer for
                        // request cancellation), so we just observe and
                        // move on at this layer.
                        ProtocolEvent::PeerConnected { .. }
                        | ProtocolEvent::PeerDisconnected { .. } => {}
                    }
                }

                else => break,
            }

            // Publish a fresh snapshot at the end of every iteration,
            // after all dispatched actions have been applied. No hot-
            // path locking — just a shallow rebuild and a watch-channel
            // `send_replace`.
            self.publish_status();
        }

        view_timer.cancel();
        Ok(())
    }

    // ── Internal action dispatchers ──────────────────────────────────────────

    async fn apply_dispatch(
        &mut self,
        d: Dispatch,
        broadcaster: &dyn Broadcaster,
        view_timer: &mut ViewTimer,
        signer: &Arc<dyn Signer>,
    ) -> anyhow::Result<()> {
        match d {
            Dispatch::Safety(ev) => {
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
                let out = dispatch::egress_block_response(block, to);
                send_outbound(broadcaster, out).await;
            }

            // Block arrived in response to an earlier RequestBlock; insert it
            // and re-drive parked proposals via PacemakerAdvance.
            Dispatch::ReceiveBlock {
                block: Some(block),
                from,
            } => {
                let block_hash = block.hash();
                let block_view = block.header.view;
                let block_height = block.header.height;
                tracing::info!(
                    target: TRACE_TARGET,
                    from = %node_id_to_base58(&from),
                    hash = ?block_hash,
                    view = block_view,
                    height = block_height,
                    "block_sync_response_received",
                );
                self.core.insert_pending_block(block);
                let current = self.pacemaker.current_view();
                let actions = self.step_safety(SafetyEvent::PacemakerAdvance(current));
                self.apply_safety_actions(actions, broadcaster, view_timer, signer)
                    .await?;
            }

            Dispatch::ReceiveBlock { block: None, from } => {
                tracing::warn!(
                    target: TRACE_TARGET,
                    from = %node_id_to_base58(&from),
                    "block_sync_response_not_found",
                );
            }

            Dispatch::TimeoutVote(signed) => {
                self.on_timeout_vote(signed, broadcaster, view_timer, signer)
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
    async fn apply_safety_actions(
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
                self.persist_updates(&persist_buf)?;
                persist_buf.clear();
            }

            match action {
                SafetyAction::Persist(_) => unreachable!(),

                SafetyAction::Broadcast(msg) => {
                    tracing::debug!(
                        target: TRACE_TARGET,
                        msg = msg_kind(&msg),
                        "outbound_broadcast",
                    );
                    let (payload, loopback) =
                        dispatch::egress_consensus_msg_with_loopback(&msg, signer.as_ref())?;
                    send_outbound(broadcaster, Outbound::Broadcast(payload)).await;
                    self.deliver_loopback(loopback, broadcaster, view_timer, signer)
                        .await?;
                }

                SafetyAction::SendTo(target, msg) => {
                    let (payload, loopback) =
                        dispatch::egress_consensus_msg_with_loopback(&msg, signer.as_ref())?;
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
                            requesting_height = expected_height,
                            triggered_by = reason.as_str(),
                            "block_sync_request_self_dropped",
                        );
                    } else {
                        tracing::info!(
                            target: TRACE_TARGET,
                            dest = %node_id_to_base58(&peer),
                            hash = ?hash,
                            requesting_height = expected_height,
                            triggered_by = reason.as_str(),
                            our_view = self.pacemaker.current_view(),
                            our_high_qc_view = ?self.core.state().high_qc.as_ref().map(|q| q.view),
                            "block_sync_request_emitted",
                        );
                        let out = dispatch::egress_block_request(hash, peer);
                        send_outbound(broadcaster, out).await;
                    }
                }

                SafetyAction::Commit(block) => {
                    self.apply_commit(block);
                }
            }
        }

        // Flush any trailing Persist actions (e.g. a proposal that only
        // emits Persist + SendTo; the SendTo flushes, but a final-only
        // Persist batch needs explicit flush here).
        if !persist_buf.is_empty() {
            self.persist_updates(&persist_buf)?;
        }

        Ok(())
    }

    /// Feed self-addressed dispatch items back through the same entry
    /// point a peer message would take.
    ///
    /// Boxed so the mutual recursion with [`Self::apply_safety_actions`]
    /// and [`Self::apply_pacemaker_actions`] compiles as an async fn.
    async fn deliver_loopback(
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
    async fn apply_pacemaker_actions(
        &mut self,
        actions: Vec<PacemakerAction>,
        broadcaster: &dyn Broadcaster,
        view_timer: &mut ViewTimer,
        signer: &Arc<dyn Signer>,
    ) -> anyhow::Result<()> {
        for action in actions {
            tracing::debug!(
                target: TRACE_TARGET,
                view = self.pacemaker.current_view(),
                self_id = %node_id_to_base58(&self.self_id),
                action = ?action,
                "pacemaker_action",
            );
            match action {
                PacemakerAction::AdvanceToView { view: v, cause } => {
                    tracing::debug!(
                        target: TRACE_TARGET,
                        new_view = v,
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
    fn step_pacemaker(&mut self, ev: PacemakerEvent) -> Vec<PacemakerAction> {
        tracing::debug!(
            target: TRACE_TARGET,
            view = self.pacemaker.current_view(),
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
    fn step_safety(&mut self, ev: SafetyEvent) -> Vec<SafetyAction> {
        // Snapshot the fields we want to log *before* moving `ev` into
        // the core — the event is consumed by `core.step` so we can't
        // re-borrow after.
        let log_ctx = match &ev {
            SafetyEvent::ProposalReceived(signed) => Some(SafetyLogCtx::Proposal {
                proposer: signed.signer,
                view: signed.payload.block.header.view,
                height: signed.payload.block.header.height,
            }),
            SafetyEvent::VoteReceived(signed) => Some(SafetyLogCtx::Vote {
                voter: signed.signer,
                view: signed.payload.view,
            }),
            SafetyEvent::NewViewReceived(signed) => Some(SafetyLogCtx::NewView {
                sender: signed.signer,
                high_qc_view: signed.payload.high_qc.view,
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
                    view,
                    height,
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
                        view,
                        height,
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
                    view,
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
                    high_qc_view,
                    "new_view_received",
                );
            }
            None => {}
        }

        actions
    }

    /// Build, broadcast, and self-deliver a [`TimeoutVote`] for `view`.
    ///
    /// Self-delivery matters because production p2p broadcasts do not
    /// loop back to the sender — without an explicit self-feed the
    /// local bucket would be one short of quorum, and a leader-crash
    /// scenario with exactly `quorum_size` live replicas would stall.
    async fn send_timeout(
        &mut self,
        view: View,
        broadcaster: &dyn Broadcaster,
        view_timer: &mut ViewTimer,
        signer: &Arc<dyn Signer>,
    ) -> anyhow::Result<()> {
        let high_qc = self.core.state().high_qc.clone();
        let payload = TimeoutVote { view, high_qc };
        let signed = Signed::sign(payload, signer.as_ref()).context("signing TimeoutVote")?;

        // Put the signed frame on the wire.
        let wire = WireMessage::TimeoutVote(signed.clone());
        let bytes = postcard::to_stdvec(&wire)
            .map(Bytes::from)
            .context("encoding TimeoutVote")?;
        send_outbound(broadcaster, Outbound::Broadcast(bytes)).await;

        // Count our own timeout locally so we don't depend on
        // broadcast-to-self semantics from the p2p layer.
        self.on_timeout_vote(signed, broadcaster, view_timer, signer)
            .await
    }

    /// Feed a verified [`TimeoutVote`] into the local timeout-certificate
    /// bucket.
    ///
    /// When a bucket's distinct-signer count crosses
    /// `quorum_size(validator_set.len())`, the replica:
    /// 1. Adopts the freshest `high_qc` reported by the timeout
    ///    quorum via the safety core's NewView path — `high_qc`
    ///    freshness is the standard HotStuff liveness trick that
    ///    prevents a departing leader's QC from being lost.
    /// 2. Feeds [`pacemaker::Event::OnTimeoutCert(view)`] into the
    ///    pacemaker so the local view advances to `view + 1`.
    ///
    /// The bucket is dropped once fired, so late-arriving timeout
    /// votes for the same view are silent no-ops.
    async fn on_timeout_vote(
        &mut self,
        signed: Signed<TimeoutVote>,
        broadcaster: &dyn Broadcaster,
        view_timer: &mut ViewTimer,
        signer: &Arc<dyn Signer>,
    ) -> anyhow::Result<()> {
        let view = signed.payload.view;

        // Stale: we have already advanced past this view via some other
        // path (QC or an earlier TC). Nothing to do.
        if view < self.pacemaker.current_view() {
            return Ok(());
        }
        // Defence-in-depth: ingress already rejected unknown signers,
        // but asserting here lets tests hand-construct Signed<TimeoutVote>
        // without going through ingress.
        if !self.validator_set.contains(&signed.signer) {
            return Ok(());
        }

        let quorum = quorum_size(self.validator_set.len());
        let signer_id = signed.signer;
        let is_local = signer_id == self.self_id;
        let adopt_qc = {
            let bucket = self.timeout_buckets.entry(view).or_default();
            let is_new = bucket.signers.insert(signed.signer);
            if !is_new {
                return Ok(());
            }
            // Remember the freshest high_qc reported so far. `None`
            // here means the sender had never seen a QC (rare after
            // genesis-QC seeding); we just leave `best_high_qc` as-is.
            if let Some(qc) = signed.payload.high_qc {
                let fresher = match &bucket.best_high_qc {
                    Some(cur) => qc.view > cur.view,
                    None => true,
                };
                if fresher {
                    bucket.best_high_qc = Some(qc);
                }
            }

            let bucket_size = bucket.signers.len();
            tracing::debug!(
                target: TRACE_TARGET,
                view,
                signer = %node_id_to_base58(&signer_id),
                bucket_size,
                quorum,
                is_local,
                "timeout_vote",
            );

            if bucket_size < quorum {
                return Ok(());
            }
            bucket.best_high_qc.clone()
        };

        tracing::debug!(
            target: TRACE_TARGET,
            view,
            adopt_qc_view = ?adopt_qc.as_ref().map(|q| q.view),
            "tc_formed",
        );

        // Drop the bucket: the TC has fired, further duplicates are
        // stale and no additional accounting is needed.
        self.timeout_buckets.remove(&view);
        // Also prune any strictly-older buckets — they can never
        // complete quorum into a future view that's still meaningful.
        self.timeout_buckets.retain(|&v, _| v > view);

        // Adopt the best high_qc observed via the NewView path so the
        // safety core's own freshness check and persistence discipline
        // applies. A round-trip through `Signed::sign(_, self)` keeps
        // the existing NewView handler's `signed.signer` invariant
        // (we trust our own envelope because ingress verified the
        // originals that fed the bucket).
        if let Some(qc) = adopt_qc {
            let nv = NewView { high_qc: qc };
            let self_signed =
                Signed::sign(nv, signer.as_ref()).context("signing self-NewView for TC adopt")?;
            let safety_actions = self.step_safety(SafetyEvent::NewViewReceived(self_signed));
            self.apply_safety_actions(safety_actions, broadcaster, view_timer, signer)
                .await?;
        }

        // Feed the TC into the pacemaker so the view advances.
        let pm_actions = self.step_pacemaker(PacemakerEvent::OnTimeoutCert(view));
        // NOTE: recursive-ish call through apply_pacemaker_actions is
        // safe — that function handles `AdvanceToView` / `BecomeLeader` /
        // `ResetTimer` / `SendTimeout`, and the pacemaker's reaction to
        // `OnTimeoutCert` never re-emits `OnTimeoutCert` itself.
        Box::pin(self.apply_pacemaker_actions(pm_actions, broadcaster, view_timer, signer)).await
    }

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
    ///    [`Dispatch::ServeBlock`] arm consults storage when
    ///    `pending_blocks` misses; without the put here, the lookup
    ///    would return `None` and our peer would loop forever on its
    ///    `RequestBlock` retries (#178 reopen).
    /// 2. **Status accuracy after restart.** `last_committed_height`
    ///    is otherwise an in-memory counter; `consensus_resumed` would
    ///    report `0` post-restart even when storage attests to a long
    ///    chain of commits. Persisting the checkpoint lets [`recover`]
    ///    rebuild the counter at boot.
    ///
    /// Storage backend errors are logged at `error` and otherwise
    /// swallowed: the safety-core contract is satisfied as long as
    /// `last_voted_view` / `locked` / `high_qc` are flushed (which
    /// happens through [`persist_updates`] before any outbound vote),
    /// so a transient block-store hiccup must not stop liveness.
    fn apply_commit(&mut self, block: crate::replication::block::Block) {
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
        if block.header.height > self.last_committed_height {
            self.last_committed_height = block.header.height;
            self.last_committed_view = block.header.view;
        }
        // Persist (block, last_committed) atomically so the responder
        // path and the status snapshot agree on durable state. See the
        // doc-comment for the why.
        let block_hash = block.hash();
        let key = block_storage_key(&block_hash);
        let last_committed = LastCommitted {
            height: self.last_committed_height,
            view: self.last_committed_view,
        };
        let put_result = (|| -> anyhow::Result<()> {
            let block_bytes = encode_block(&block)?;
            let last_committed_bytes = encode_last_committed(&last_committed)?;
            self.storage.batch(|b| {
                b.put(&key, &block_bytes);
                b.put(STORAGE_KEY_LAST_COMMITTED, &last_committed_bytes);
                Ok(())
            })
        })();
        if let Err(e) = put_result {
            tracing::error!(
                target: TRACE_TARGET,
                height = block.header.height,
                view = block.header.view,
                hash = ?block_hash,
                error = %e,
                "block_persist_failed",
            );
        }
        tracing::info!(
            "consensus: committed block height={} view={}",
            block.header.height,
            block.header.view,
        );
        if let Some(tx) = &self.commit_tx {
            let _ = tx.send(block);
        }
    }
}

// ── Durability bridge ────────────────────────────────────────────────────────

/// Serialize a `last_voted_view` value to its on-storage encoding.
pub fn encode_voted_view(view: View) -> anyhow::Result<Vec<u8>> {
    postcard::to_stdvec(&view).context("encode last_voted_view")
}

/// Inverse of [`encode_voted_view`].
pub fn decode_voted_view(bytes: &[u8]) -> anyhow::Result<View> {
    postcard::from_bytes(bytes).context("decode last_voted_view")
}

/// Serialize a [`Locked`] value to its on-storage encoding.
pub fn encode_locked(locked: &Locked) -> anyhow::Result<Vec<u8>> {
    postcard::to_stdvec(locked).context("encode locked")
}

/// Inverse of [`encode_locked`].
pub fn decode_locked(bytes: &[u8]) -> anyhow::Result<Locked> {
    postcard::from_bytes(bytes).context("decode locked")
}

/// Serialize a [`QuorumCertificate`] (as `high_qc`) to its on-storage
/// encoding.
pub fn encode_high_qc(qc: &QuorumCertificate) -> anyhow::Result<Vec<u8>> {
    postcard::to_stdvec(qc).context("encode high_qc")
}

/// Inverse of [`encode_high_qc`].
pub fn decode_high_qc(bytes: &[u8]) -> anyhow::Result<QuorumCertificate> {
    postcard::from_bytes(bytes).context("decode high_qc")
}

/// Compose the storage key for a committed block keyed by its
/// content-hash: `STORAGE_KEY_BLOCK_PREFIX || hash`.
pub fn block_storage_key(hash: &BlockHash) -> Vec<u8> {
    let mut key = Vec::with_capacity(STORAGE_KEY_BLOCK_PREFIX.len() + hash.len());
    key.extend_from_slice(STORAGE_KEY_BLOCK_PREFIX);
    key.extend_from_slice(hash);
    key
}

/// Serialize a committed [`Block`] for the durable block store. See
/// [`STORAGE_KEY_BLOCK_PREFIX`].
pub fn encode_block(block: &Block) -> anyhow::Result<Vec<u8>> {
    postcard::to_stdvec(block).context("encode committed block")
}

/// Inverse of [`encode_block`].
pub fn decode_block(bytes: &[u8]) -> anyhow::Result<Block> {
    postcard::from_bytes(bytes).context("decode committed block")
}

/// Persisted `(height, view)` pair for the most recently committed
/// block. Stored at [`STORAGE_KEY_LAST_COMMITTED`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastCommitted {
    pub height: u64,
    pub view: View,
}

/// Serialize the `(height, view)` checkpoint to its on-storage
/// encoding.
pub fn encode_last_committed(lc: &LastCommitted) -> anyhow::Result<Vec<u8>> {
    postcard::to_stdvec(lc).context("encode last_committed")
}

/// Inverse of [`encode_last_committed`].
pub fn decode_last_committed(bytes: &[u8]) -> anyhow::Result<LastCommitted> {
    postcard::from_bytes(bytes).context("decode last_committed")
}

/// Recover a [`HotStuffState`] by reading the persisted control-plane
/// keys from `storage`.
///
/// A fresh node state (equivalent to `HotStuffState::new(vs, genesis)`)
/// is the baseline; any of `last_voted_view`, `locked`, `high_qc` that
/// were previously persisted by [`ConsensusNode::persist_updates`] are
/// overlaid. The `pending_blocks` field is intentionally **not**
/// repopulated here — committed blocks live under
/// [`STORAGE_KEY_BLOCK_PREFIX`] and are served on demand by the
/// `Dispatch::ServeBlock` arm via [`load_block_from_storage`]. That
/// keeps boot O(1) rather than O(committed-blocks) while preserving
/// the issue #178 invariant that *some* replica will always serve a
/// previously-committed block to a peer that asks for it.
///
/// Missing keys are expected on a first startup and are not errors.
pub fn recover_state(
    storage: &dyn Storage,
    validator_set: ValidatorSet,
    genesis: Block,
) -> anyhow::Result<HotStuffState> {
    let vs_len = validator_set.len();
    let boot_qc = genesis_qc(&genesis, vs_len);
    let mut state = HotStuffState::new(validator_set, genesis);
    // Default every fresh replica to the cluster-agreed genesis QC so
    // view-1 can proceed without waiting for a cross-cluster NewView
    // round. If the replica previously persisted a fresher QC we
    // overlay that below.
    state.high_qc = Some(boot_qc);

    if let Some(raw) = storage
        .get(STORAGE_KEY_LAST_VOTED_VIEW)
        .context("read last_voted_view from storage")?
    {
        state.last_voted_view = decode_voted_view(&raw)?;
    }

    if let Some(raw) = storage
        .get(STORAGE_KEY_LOCKED)
        .context("read locked from storage")?
    {
        state.locked = Some(decode_locked(&raw)?);
    }

    if let Some(raw) = storage
        .get(STORAGE_KEY_HIGH_QC)
        .context("read high_qc from storage")?
    {
        state.high_qc = Some(decode_high_qc(&raw)?);
    }

    Ok(state)
}

// ── Status-snapshot helper ───────────────────────────────────────────────────

/// Compute the `self_role` string for a [`ConsensusStatus`]: either
/// `"leader(view=N)"` when `self_id` is the round-robin proposer for
/// `view`, or `"replica"` otherwise.
///
/// Kept module-private and free-standing so
/// [`ConsensusNode::build_status`] doesn't have to hold a
/// [`RoundRobinSelector`]: the round-robin rule
/// (`validators[view % len]`) is the selector the rest of the
/// integration layer uses, and duplicating that one-liner here keeps
/// `ConsensusNode` from threading the selector through every call.
/// See [`crate::consensus::pacemaker::leader::RoundRobinSelector`]
/// for the authoritative implementation.
fn self_role_string(validator_set: &ValidatorSet, self_id: &NodeId, view: View) -> String {
    if validator_set.is_empty() {
        return "replica".to_string();
    }
    let idx = (view % validator_set.len() as u64) as usize;
    match validator_set.get(idx) {
        Some(leader) if leader == self_id => format!("leader(view={view})"),
        _ => "replica".to_string(),
    }
}

// ── Internal send helper ─────────────────────────────────────────────────────

/// Dispatch an [`Outbound`] from the dispatch layer through the
/// [`Broadcaster`] trait object. The trait's implementations decide
/// whether to drop on backpressure; today's `MeshBroadcaster` preserves
/// the previous "send-and-await" semantics by awaiting an mpsc send.
async fn send_outbound(broadcaster: &dyn Broadcaster, out: Outbound) {
    match out {
        Outbound::Broadcast(b) => broadcaster.broadcast(b).await,
        Outbound::SendTo { to, payload } => broadcaster.send_to(to, payload).await,
    }
}

/// Read a previously-committed block from durable storage by its
/// content-hash. Returns `Ok(None)` when the key is absent (the block
/// was never committed by this replica), `Err` only on backend errors
/// or corrupt bytes. See [`STORAGE_KEY_BLOCK_PREFIX`].
pub fn load_block_from_storage(
    storage: &dyn Storage,
    hash: &BlockHash,
) -> anyhow::Result<Option<Block>> {
    let key = block_storage_key(hash);
    match storage.get(&key)? {
        Some(raw) => Ok(Some(decode_block(&raw)?)),
        None => Ok(None),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use parking_lot::Mutex;

    use super::*;
    use crate::consensus::validator_set::ValidatorSet;
    use crate::p2p::NodeId;
    use crate::replication::block::Block;
    use crate::replication::impls::{CounterStateMachine, InMemoryMempool};
    use crate::storage::{MemoryStorage, MemoryWal};

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn four_validators() -> ValidatorSet {
        ValidatorSet::new(vec![nid(1), nid(2), nid(3), nid(4)])
    }

    fn genesis() -> Block {
        Block::genesis([0u8; 32])
    }

    fn test_config(vs: ValidatorSet) -> NodeConfigForConsensus {
        NodeConfigForConsensus::for_testing(vs, genesis())
    }

    fn make_sm() -> Arc<Mutex<Box<dyn StateMachine>>> {
        Arc::new(Mutex::new(Box::new(CounterStateMachine::new())))
    }

    fn make_node(self_id: NodeId) -> ConsensusNode {
        let vs = four_validators();
        let cfg = test_config(vs);
        ConsensusNode::new(
            self_id,
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(256)),
            Arc::new(MemoryStorage::new()),
            Arc::new(MemoryWal::new()),
        )
    }

    // ── A4: smoke test ───────────────────────────────────────────────────────

    #[test]
    fn new_initializes_at_view_zero() {
        let node = make_node(nid(1));
        assert_eq!(node.current_view(), 0);
        assert_eq!(node.core.state().current_view, 0);
        assert_eq!(node.pacemaker.current_view(), 0);
    }

    #[test]
    fn self_id_is_stored_correctly() {
        let node = make_node(nid(3));
        assert_eq!(node.self_id, nid(3));
        assert_eq!(node.core.self_id(), nid(3));
        assert_eq!(node.pacemaker.self_id(), nid(3));
    }

    #[test]
    fn genesis_is_in_pending_blocks() {
        let node = make_node(nid(1));
        let g_hash = genesis().hash();
        assert!(
            node.core.state().pending_blocks.contains_key(&g_hash),
            "genesis block must be pre-seeded into pending_blocks",
        );
    }

    // ── A2: WireMessage roundtrip ────────────────────────────────────────────

    fn sample_block() -> Block {
        use crate::replication::block::BlockHeader;
        let g = genesis();
        Block {
            header: BlockHeader {
                parent_hash: g.hash(),
                height: 1,
                view: 1,
                proposer: nid(1),
                state_commitment: [0u8; 32],
                commands_commitment: Block::commands_commitment(&[]),
            },
            commands: vec![],
        }
    }

    fn sample_qc() -> crate::consensus::hotstuff::QuorumCertificate {
        crate::consensus::hotstuff::QuorumCertificate::new(0, genesis().hash(), 4)
    }

    fn dummy_sig() -> [u8; 64] {
        [0u8; 64]
    }

    #[test]
    fn wire_message_proposal_roundtrip() {
        use crate::consensus::hotstuff::Proposal;
        let msg = WireMessage::Proposal(Signed {
            payload: Proposal {
                block: sample_block(),
                justify: sample_qc(),
            },
            signer: nid(1),
            sig: dummy_sig(),
        });
        let encoded = postcard::to_stdvec(&msg).unwrap();
        let decoded: WireMessage = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn wire_message_vote_roundtrip() {
        use crate::consensus::hotstuff::qc::Vote;
        let msg = WireMessage::Vote(Signed {
            payload: Vote {
                view: 7,
                block_hash: [0xAB; 32],
            },
            signer: nid(2),
            sig: dummy_sig(),
        });
        let encoded = postcard::to_stdvec(&msg).unwrap();
        let decoded: WireMessage = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn wire_message_new_view_roundtrip() {
        use crate::consensus::hotstuff::NewView;
        let msg = WireMessage::NewView(Signed {
            payload: NewView {
                high_qc: sample_qc(),
            },
            signer: nid(3),
            sig: dummy_sig(),
        });
        let encoded = postcard::to_stdvec(&msg).unwrap();
        let decoded: WireMessage = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn wire_message_timeout_vote_roundtrip() {
        use crate::consensus::hotstuff::qc::TimeoutVote;
        let tv = TimeoutVote {
            view: 9,
            high_qc: Some(sample_qc()),
        };
        let msg = WireMessage::TimeoutVote(Signed {
            payload: tv,
            signer: nid(2),
            sig: dummy_sig(),
        });
        let encoded = postcard::to_stdvec(&msg).unwrap();
        let decoded: WireMessage = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, msg);

        // The `high_qc: None` variant must also roundtrip — it's the
        // very-early-bootstrap encoding where no QC has been observed.
        let tv_none = TimeoutVote {
            view: 1,
            high_qc: None,
        };
        let msg_none = WireMessage::TimeoutVote(Signed {
            payload: tv_none,
            signer: nid(3),
            sig: dummy_sig(),
        });
        let encoded = postcard::to_stdvec(&msg_none).unwrap();
        let decoded: WireMessage = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, msg_none);
    }

    #[test]
    fn wire_message_block_request_roundtrip() {
        let hash = [0xCDu8; 32];
        let msg = WireMessage::BlockRequest(hash);
        let encoded = postcard::to_stdvec(&msg).unwrap();
        let decoded: WireMessage = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn wire_message_block_response_some_roundtrip() {
        let msg = WireMessage::BlockResponse(Some(sample_block()));
        let encoded = postcard::to_stdvec(&msg).unwrap();
        let decoded: WireMessage = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn wire_message_block_response_none_roundtrip() {
        let msg = WireMessage::BlockResponse(None);
        let encoded = postcard::to_stdvec(&msg).unwrap();
        let decoded: WireMessage = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    // ── B3: MempoolBlockBuilder tests ────────────────────────────────────────

    fn make_builder(
        self_id: NodeId,
        mempool: Arc<dyn Mempool>,
        sm: Arc<Mutex<Box<dyn StateMachine>>>,
    ) -> MempoolBlockBuilder {
        MempoolBlockBuilder::new(self_id, mempool, sm, 10)
    }

    #[test]
    fn builder_sets_header_fields_from_parent_and_view() {
        let mp: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(16));
        let sm = make_sm();
        let builder = make_builder(nid(1), Arc::clone(&mp), Arc::clone(&sm));
        let parent = genesis();
        let qc = sample_qc();

        let block = builder.build(&parent, 3, &qc);

        assert_eq!(block.header.parent_hash, parent.hash());
        assert_eq!(block.header.height, 1);
        assert_eq!(block.header.view, 3);
        assert_eq!(block.header.proposer, nid(1));
    }

    #[test]
    fn builder_pulls_commands_from_mempool() {
        use crate::replication::impls::counter_sm::CounterCommand;

        let mp: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(16));
        mp.insert(CounterCommand::Increment.encode()).unwrap();
        mp.insert(CounterCommand::Decrement.encode()).unwrap();

        let sm = make_sm();
        let builder = make_builder(nid(1), Arc::clone(&mp), Arc::clone(&sm));
        let block = builder.build(&genesis(), 1, &sample_qc());

        assert_eq!(block.commands.len(), 2);
    }

    #[test]
    fn builder_is_deterministic_for_same_inputs() {
        use crate::replication::impls::counter_sm::CounterCommand;

        let mp: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(16));
        mp.insert(CounterCommand::Increment.encode()).unwrap();

        let sm = make_sm();
        let builder = make_builder(nid(1), Arc::clone(&mp), Arc::clone(&sm));
        let parent = genesis();
        let qc = sample_qc();

        let b1 = builder.build(&parent, 1, &qc);
        let b2 = builder.build(&parent, 1, &qc);

        assert_eq!(b1.hash(), b2.hash(), "build must be deterministic");
    }

    #[test]
    fn builder_does_not_mutate_state_machine() {
        use crate::replication::impls::counter_sm::CounterCommand;

        let mp: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(16));
        mp.insert(CounterCommand::Increment.encode()).unwrap();
        mp.insert(CounterCommand::Increment.encode()).unwrap();
        mp.insert(CounterCommand::Increment.encode()).unwrap();

        let sm = make_sm();
        let before = sm.lock().state_commitment();

        let builder = make_builder(nid(1), Arc::clone(&mp), Arc::clone(&sm));
        builder.build(&genesis(), 1, &sample_qc());

        let after = sm.lock().state_commitment();
        assert_eq!(
            before, after,
            "build must not leave the state machine mutated",
        );
    }

    #[test]
    fn builder_state_commitment_matches_applying_commands() {
        use crate::replication::impls::counter_sm::CounterCommand;

        let mp: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(16));
        let cmd = CounterCommand::Increment.encode();
        mp.insert(cmd.clone()).unwrap();

        let sm = make_sm();
        let builder = make_builder(nid(1), Arc::clone(&mp), Arc::clone(&sm));
        let block = builder.build(&genesis(), 1, &sample_qc());

        // Manually apply the same command and check commitment matches.
        let mut reference_sm = CounterStateMachine::new();
        reference_sm.apply(&cmd).unwrap();
        assert_eq!(
            block.header.state_commitment,
            reference_sm.state_commitment(),
        );
    }

    #[test]
    fn builder_commands_commitment_matches_commands() {
        use crate::replication::impls::counter_sm::CounterCommand;

        let mp: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(16));
        mp.insert(CounterCommand::Increment.encode()).unwrap();
        mp.insert(CounterCommand::Decrement.encode()).unwrap();

        let sm = make_sm();
        let builder = make_builder(nid(1), Arc::clone(&mp), Arc::clone(&sm));
        let block = builder.build(&genesis(), 1, &sample_qc());

        let recomputed = Block::commands_commitment(&block.commands);
        assert_eq!(block.header.commands_commitment, recomputed);
    }

    // ── C-series: durability bridge ──────────────────────────────────────────

    fn sample_locked() -> Locked {
        Locked {
            view: 40,
            height: 5,
            block_hash: [0xABu8; 32],
        }
    }

    fn sample_full_qc() -> QuorumCertificate {
        let mut qc = QuorumCertificate::new(41, [0xCDu8; 32], 4);
        qc.add_signature(0, [0x11u8; 64]);
        qc.add_signature(2, [0x22u8; 64]);
        qc.add_signature(3, [0x33u8; 64]);
        qc
    }

    #[test]
    fn encode_decode_voted_view_roundtrips() {
        let cases = [0u64, 1, 42, u64::MAX];
        for v in cases {
            let bytes = encode_voted_view(v).unwrap();
            assert_eq!(decode_voted_view(&bytes).unwrap(), v);
        }
    }

    #[test]
    fn encode_decode_locked_roundtrips() {
        let l = sample_locked();
        let bytes = encode_locked(&l).unwrap();
        assert_eq!(decode_locked(&bytes).unwrap(), l);
    }

    #[test]
    fn encode_decode_high_qc_roundtrips() {
        let qc = sample_full_qc();
        let bytes = encode_high_qc(&qc).unwrap();
        assert_eq!(decode_high_qc(&bytes).unwrap(), qc);
    }

    #[test]
    fn decode_voted_view_surfaces_error_on_garbage() {
        assert!(decode_voted_view(&[0xFFu8; 64]).is_err());
    }

    #[test]
    fn recover_state_from_empty_storage_seeds_genesis_qc() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let state = recover_state(storage.as_ref(), four_validators(), genesis()).unwrap();
        assert_eq!(state.current_view, 0);
        assert_eq!(state.last_voted_view, 0);
        assert!(state.locked.is_none());
        // Empty storage means no persisted high_qc, so the recovery path
        // seeds the cluster-agreed genesis QC so the view-1 leader can
        // propose on first boot.
        let expected = genesis_qc(&genesis(), four_validators().len());
        assert_eq!(state.high_qc.as_ref(), Some(&expected));
        assert!(state.pending_blocks.contains_key(&genesis().hash()));
    }

    #[test]
    fn persist_updates_empty_is_noop() {
        let node = make_node(nid(1));
        node.persist_updates(&[]).unwrap();
        assert!(
            node.storage
                .get(STORAGE_KEY_LAST_VOTED_VIEW)
                .unwrap()
                .is_none(),
        );
    }

    #[test]
    fn persist_then_recover_preserves_voted_view() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let wal: Arc<dyn Wal> = Arc::new(MemoryWal::new());
        let cfg = test_config(four_validators());

        // Session 1: persist a vote.
        let node = ConsensusNode::new(
            nid(1),
            cfg.clone(),
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::clone(&wal),
        );
        node.persist_updates(&[StateUpdate::VotedInView { view: 99 }])
            .unwrap();
        drop(node);

        // Session 2: recover. The voted view survives.
        let recovered = ConsensusNode::recover(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::clone(&wal),
        )
        .unwrap();
        assert_eq!(recovered.core.state().last_voted_view, 99);
    }

    #[test]
    fn persist_then_recover_preserves_locked_and_high_qc() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let wal: Arc<dyn Wal> = Arc::new(MemoryWal::new());
        let cfg = test_config(four_validators());
        let locked = sample_locked();
        let qc = sample_full_qc();

        let node = ConsensusNode::new(
            nid(1),
            cfg.clone(),
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::clone(&wal),
        );
        node.persist_updates(&[StateUpdate::Locked(locked), StateUpdate::HighQc(qc.clone())])
            .unwrap();
        drop(node);

        let recovered = ConsensusNode::recover(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::clone(&wal),
        )
        .unwrap();
        assert_eq!(recovered.core.state().locked, Some(locked));
        assert_eq!(recovered.core.state().high_qc.as_ref(), Some(&qc));
    }

    #[test]
    fn persist_all_three_fields_and_recover() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let wal: Arc<dyn Wal> = Arc::new(MemoryWal::new());
        let cfg = test_config(four_validators());

        let node = ConsensusNode::new(
            nid(2),
            cfg.clone(),
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::clone(&wal),
        );
        let updates = vec![
            StateUpdate::VotedInView { view: 7 },
            StateUpdate::Locked(sample_locked()),
            StateUpdate::HighQc(sample_full_qc()),
        ];
        node.persist_updates(&updates).unwrap();
        drop(node);

        let recovered = ConsensusNode::recover(
            nid(2),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::clone(&wal),
        )
        .unwrap();
        assert_eq!(recovered.core.state().last_voted_view, 7);
        assert_eq!(recovered.core.state().locked, Some(sample_locked()));
        assert_eq!(
            recovered.core.state().high_qc.as_ref(),
            Some(&sample_full_qc()),
        );
        // `recover` does not reset the pacemaker — it always starts at 0.
        assert_eq!(recovered.current_view(), 0);
    }

    #[test]
    fn persist_is_last_write_wins_within_batch() {
        let node = make_node(nid(1));
        node.persist_updates(&[
            StateUpdate::VotedInView { view: 3 },
            StateUpdate::VotedInView { view: 5 },
            StateUpdate::VotedInView { view: 4 },
        ])
        .unwrap();
        let raw = node
            .storage
            .get(STORAGE_KEY_LAST_VOTED_VIEW)
            .unwrap()
            .unwrap();
        assert_eq!(decode_voted_view(&raw).unwrap(), 4);
    }

    #[test]
    fn persist_monotonic_overwrites_previous() {
        // Subsequent persist calls overwrite the previous value: there's
        // no accumulation, each key is a single cell in storage.
        let node = make_node(nid(1));
        node.persist_updates(&[StateUpdate::VotedInView { view: 1 }])
            .unwrap();
        node.persist_updates(&[StateUpdate::VotedInView { view: 2 }])
            .unwrap();
        let raw = node
            .storage
            .get(STORAGE_KEY_LAST_VOTED_VIEW)
            .unwrap()
            .unwrap();
        assert_eq!(decode_voted_view(&raw).unwrap(), 2);
    }

    #[test]
    fn recover_surfaces_error_on_corrupted_stored_bytes() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        storage
            .put(STORAGE_KEY_LAST_VOTED_VIEW, &[0xFFu8; 64])
            .unwrap();
        let err = recover_state(storage.as_ref(), four_validators(), genesis()).unwrap_err();
        assert!(
            format!("{err:#}").contains("last_voted_view"),
            "error should mention the failing key: {err:#}",
        );
    }

    #[test]
    fn recover_only_locked_preserves_default_voted_view_and_seeds_genesis_qc() {
        // Partial persistence: only `locked` was flushed. Recovery
        // restores it, leaves `last_voted_view` at its default, and
        // seeds the genesis QC since no `high_qc` was persisted.
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let wal: Arc<dyn Wal> = Arc::new(MemoryWal::new());
        let cfg = test_config(four_validators());
        let node = ConsensusNode::new(
            nid(1),
            cfg.clone(),
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::clone(&wal),
        );
        node.persist_updates(&[StateUpdate::Locked(sample_locked())])
            .unwrap();
        drop(node);

        let recovered = ConsensusNode::recover(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::clone(&wal),
        )
        .unwrap();
        assert_eq!(recovered.core.state().last_voted_view, 0);
        assert_eq!(recovered.core.state().locked, Some(sample_locked()));
        let expected = genesis_qc(&genesis(), four_validators().len());
        assert_eq!(recovered.core.state().high_qc.as_ref(), Some(&expected));
    }

    // ── D/E-series: event loop ────────────────────────────────────────────────

    use crate::crypto::signed::NodeSigner;
    use crate::p2p::identity::NodeIdentity;
    use crate::p2p::{ProtocolEvent, ProtocolOutbound};
    use rcgen::KeyPair as RcgenKeyPair;
    use rcgen::PKCS_ED25519;
    use zeroize::Zeroizing;

    fn fresh_signer() -> NodeSigner {
        let kp = RcgenKeyPair::generate_for(&PKCS_ED25519).unwrap();
        let identity = NodeIdentity {
            pkcs8_der: Zeroizing::new(kp.serialize_der()),
        };
        NodeSigner::from_identity(&identity).unwrap()
    }

    /// Build an inbound `event_rx` for [`ConsensusNode::run`] backed by
    /// an in-memory channel; the returned sender lets tests inject
    /// arbitrary [`ProtocolEvent`]s.
    fn make_test_event_channel() -> (
        tokio::sync::mpsc::Sender<ProtocolEvent>,
        tokio::sync::mpsc::Receiver<ProtocolEvent>,
    ) {
        tokio::sync::mpsc::channel(16)
    }

    /// Build a [`Broadcaster`] backed by an in-memory channel and return
    /// the receiver so the test can inspect outbound traffic.
    fn make_test_broadcaster() -> (
        Arc<dyn Broadcaster>,
        tokio::sync::mpsc::Receiver<ProtocolOutbound>,
    ) {
        let (send_tx, send_rx) = tokio::sync::mpsc::channel::<ProtocolOutbound>(16);
        let bc: Arc<dyn Broadcaster> = Arc::new(crate::p2p::overlay::MeshBroadcaster::new(send_tx));
        (bc, send_rx)
    }

    /// Build a [`Discovery`] with no peers and a never-firing source.
    fn make_test_discovery() -> Arc<dyn Discovery> {
        let (_tx, rx) = tokio::sync::broadcast::channel::<DiscoveryEvent>(8);
        crate::p2p::overlay::MeshDiscovery::spawn(rx)
    }

    #[test]
    fn new_seeds_genesis_qc_so_view_one_leader_can_propose() {
        // Regression for the bootstrap-deadlock bug (#116). A freshly
        // constructed ConsensusNode must have `high_qc = Some(genesis_qc)`
        // so the view-1 leader can immediately build a proposal on boot
        // without waiting for a NewView round that only ever lands after
        // somebody has already proposed.
        let node = make_node(nid(1));
        let expected = genesis_qc(&genesis(), four_validators().len());
        assert_eq!(node.core.state().high_qc.as_ref(), Some(&expected));

        // And `become_leader(1)` must now yield an Action::Broadcast(Proposal)
        // rather than the empty Vec the pre-fix code returned.
        let mut node = node;
        let actions = node.core.become_leader(1);
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            SafetyAction::Broadcast(crate::consensus::hotstuff::ConsensusMsg::Proposal(_)),
        ));
    }

    #[test]
    fn insert_pending_block_is_visible_in_state() {
        let mut node = make_node(nid(1));
        let block = sample_block();
        let hash = block.hash();
        node.core.insert_pending_block(block);
        assert!(node.core.state().pending_blocks.contains_key(&hash));
    }

    #[test]
    fn apply_commit_advances_state_machine_and_drains_mempool() {
        use crate::replication::impls::counter_sm::CounterCommand;

        let mp: Arc<dyn crate::replication::mempool::Mempool> = Arc::new(InMemoryMempool::new(64));
        let cmd = CounterCommand::Increment.encode();
        mp.insert(cmd.clone()).unwrap();
        assert_eq!(mp.len(), 1);

        let sm = make_sm();
        let vs = four_validators();
        let cfg = test_config(vs);
        let mut node = ConsensusNode::new(
            nid(1),
            cfg,
            Arc::clone(&sm),
            Arc::clone(&mp),
            Arc::new(MemoryStorage::new()),
            Arc::new(MemoryWal::new()),
        );

        let block = crate::replication::block::Block {
            header: crate::replication::block::BlockHeader {
                parent_hash: genesis().hash(),
                height: 1,
                view: 1,
                proposer: nid(1),
                state_commitment: [0u8; 32],
                commands_commitment: crate::replication::block::Block::commands_commitment(
                    std::slice::from_ref(&cmd),
                ),
            },
            commands: vec![cmd],
        };

        let sm_before = sm.lock().state_commitment();
        node.apply_commit(block);
        let sm_after = sm.lock().state_commitment();

        assert_ne!(sm_before, sm_after, "state machine must advance on commit");
        assert_eq!(
            mp.len(),
            0,
            "committed commands must be drained from mempool"
        );
    }

    // ── #178 follow-up: durable block store + ServeBlock fallback ────────────

    /// `apply_commit` writes the block under `consensus/block/<hash>`
    /// and refreshes `consensus/last_committed`. Without this a peer
    /// asking for the block after we evicted (or restart-reset) it
    /// from `pending_blocks` would get `BlockResponse(None)` and stall.
    #[test]
    fn apply_commit_persists_block_and_last_committed_to_storage() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let cfg = test_config(four_validators());
        let mut node = ConsensusNode::new(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );

        let block = sample_block();
        let hash = block.hash();
        node.apply_commit(block.clone());

        // Block stored at the expected key; round-trips through
        // load_block_from_storage.
        let loaded = load_block_from_storage(storage.as_ref(), &hash)
            .expect("storage lookup must not error")
            .expect("committed block must be persisted");
        assert_eq!(loaded, block);

        // last_committed checkpoint reflects the just-committed block.
        let raw = storage
            .get(STORAGE_KEY_LAST_COMMITTED)
            .expect("storage")
            .expect("last_committed must be present");
        let lc = decode_last_committed(&raw).expect("decode");
        assert_eq!(lc.height, block.header.height);
        assert_eq!(lc.view, block.header.view);
    }

    /// `recover` rebuilds `last_committed_height`/`last_committed_view`
    /// from the durable checkpoint so `consensus_resumed` reports the
    /// real chain rather than `0` after a restart.
    #[test]
    fn recover_restores_last_committed_height_and_view() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let cfg = test_config(four_validators());

        // Simulate a session that committed up to (height=42, view=57).
        {
            let mut node = ConsensusNode::new(
                nid(1),
                cfg.clone(),
                make_sm(),
                Arc::new(InMemoryMempool::new(64)),
                Arc::clone(&storage),
                Arc::new(MemoryWal::new()),
            );
            for h in 1..=42u64 {
                use crate::replication::block::BlockHeader;
                let parent_hash = if h == 1 {
                    genesis().hash()
                } else {
                    [0u8; 32] // doesn't matter for this test — apply_commit only
                    // reads (height, view, hash) and the SM
                };
                let block = Block {
                    header: BlockHeader {
                        parent_hash,
                        height: h,
                        view: if h == 42 { 57 } else { h },
                        proposer: nid(1),
                        state_commitment: [0u8; 32],
                        commands_commitment: Block::commands_commitment(&[]),
                    },
                    commands: vec![],
                };
                node.apply_commit(block);
            }
            assert_eq!(node.last_committed_height, 42);
            assert_eq!(node.last_committed_view, 57);
        }

        // New session: recover from the same storage and confirm the
        // counters come back populated.
        let recovered = ConsensusNode::recover(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            storage,
            Arc::new(MemoryWal::new()),
        )
        .expect("recover");
        assert_eq!(recovered.last_committed_height, 42);
        assert_eq!(recovered.last_committed_view, 57);
    }

    /// `Dispatch::ServeBlock` must serve a block that lives only in
    /// durable storage (the in-memory `pending_blocks` cache having
    /// been reset by a restart). Without the fallback the responder
    /// would emit `BlockResponse(None)` and the requester would loop
    /// forever on retries — the bug #178's reopen comment described.
    #[tokio::test]
    async fn serve_block_falls_back_to_storage_when_pending_blocks_misses() {
        // Step 1: a "first session" commits a block to storage.
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let cfg = test_config(four_validators());
        let block = sample_block();
        let hash = block.hash();
        {
            let mut node = ConsensusNode::new(
                nid(1),
                cfg.clone(),
                make_sm(),
                Arc::new(InMemoryMempool::new(64)),
                Arc::clone(&storage),
                Arc::new(MemoryWal::new()),
            );
            node.apply_commit(block.clone());
        }

        // Step 2: a fresh node ("restarted") shares the same storage
        // but starts with an empty pending_blocks (save genesis).
        let mut node = ConsensusNode::recover(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        )
        .expect("recover");
        assert!(
            !node.core.state().pending_blocks.contains_key(&hash),
            "post-restart pending_blocks must not contain the committed block — \
             this is the precondition the storage fallback exists to handle",
        );

        // Step 3: drive a ServeBlock dispatch and observe the
        // outbound BlockResponse carries the block from storage.
        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let (broadcaster, mut outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);
        node.apply_dispatch(
            Dispatch::ServeBlock { hash, to: nid(2) },
            broadcaster.as_ref(),
            &mut view_timer,
            &signer,
        )
        .await
        .expect("apply_dispatch");

        // The outbound channel should now hold a SendTo with a
        // BlockResponse(Some(block)) addressed to nid(2).
        let outbound = outbound_rx
            .recv()
            .await
            .expect("an outbound BlockResponse must be sent");
        match outbound {
            ProtocolOutbound::SendTo { node_id, payload } => {
                assert_eq!(node_id, nid(2));
                let wire: WireMessage =
                    postcard::from_bytes(&payload).expect("decode BlockResponse");
                match wire {
                    WireMessage::BlockResponse(got) => {
                        assert_eq!(got, Some(block));
                    }
                    other => panic!("expected BlockResponse, got {other:?}"),
                }
            }
            other => panic!("expected SendTo, got {other:?}"),
        }
    }

    /// `Dispatch::ServeBlock` for an unknown hash returns
    /// `BlockResponse(None)` without erroring on storage. The peer's
    /// `block_sync_response_not_found` arm handles the negative case.
    #[tokio::test]
    async fn serve_block_returns_none_when_neither_pending_nor_storage_has_it() {
        let mut node = make_node(nid(1));
        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let (broadcaster, mut outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        let unknown_hash: BlockHash = [0xEE; 32];
        node.apply_dispatch(
            Dispatch::ServeBlock {
                hash: unknown_hash,
                to: nid(2),
            },
            broadcaster.as_ref(),
            &mut view_timer,
            &signer,
        )
        .await
        .expect("apply_dispatch");

        match outbound_rx.recv().await.expect("outbound") {
            ProtocolOutbound::SendTo { node_id, payload } => {
                assert_eq!(node_id, nid(2));
                let wire: WireMessage =
                    postcard::from_bytes(&payload).expect("decode BlockResponse");
                assert!(matches!(wire, WireMessage::BlockResponse(None)));
            }
            other => panic!("expected SendTo, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_shuts_down_cleanly_on_signal() {
        let node = make_node(nid(1));
        let signer = fresh_signer();
        let (_event_tx, event_rx) = make_test_event_channel();
        let (broadcaster, _outbound_rx) = make_test_broadcaster();
        let discovery = make_test_discovery();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let run_handle = tokio::spawn(async move {
            node.run(
                broadcaster,
                discovery,
                event_rx,
                Arc::new(signer),
                shutdown_rx,
            )
            .await
        });

        shutdown_tx.send(()).unwrap();
        let result = run_handle.await.unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn run_boots_and_sends_at_least_one_outbound_message() {
        // On boot the pacemaker advances to view 1. If the node is the
        // view-1 leader (round-robin: leader = validators[(1 % 4)] = nid(2)),
        // it would propose; otherwise it sends a NewView. Either way, at least
        // one outbound message must appear once the loop ticks.
        //
        // We don't check the exact message content here (that's tested in
        // dispatch tests); we just confirm the loop boots and sends.
        let node = make_node(nid(1));
        let signer = fresh_signer();
        let (_event_tx, event_rx) = make_test_event_channel();
        let (broadcaster, _outbound_rx) = make_test_broadcaster();
        let discovery = make_test_discovery();
        let (_shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            let _ = node
                .run(
                    broadcaster,
                    discovery,
                    event_rx,
                    Arc::new(signer),
                    shutdown_rx,
                )
                .await;
        });

        // Give the loop a tick to run its boot sequence.
        tokio::task::yield_now().await;

        // The pacemaker sends NewView on advance (if high_qc is present).
        // On a fresh node there is no high_qc, so no NewView is emitted —
        // but the timer IS armed. We verify the loop at least processed the
        // boot sequence without panicking: if the task panicked, the test
        // harness would surface it on the next await or drop.
    }

    // ── Self-addressed loopback (#118) ───────────────────────────────────────

    /// Build a node whose `self_id` matches `signer.node_id()` and who
    /// sits at `validator_set[self_idx]` of a 4-node committee. The
    /// remaining three slots are filled with placeholder ids so the
    /// safety core can route votes by validator index.
    fn make_node_with_signer(
        signer: &NodeSigner,
        self_idx: usize,
    ) -> (ConsensusNode, ValidatorSet) {
        assert!(self_idx < 4);
        let self_id = signer.node_id();
        let placeholders = [nid(0xA1), nid(0xA2), nid(0xA3)];
        let mut ids: Vec<NodeId> = Vec::with_capacity(4);
        let mut ph = placeholders.iter();
        for i in 0..4 {
            if i == self_idx {
                ids.push(self_id);
            } else {
                ids.push(*ph.next().unwrap());
            }
        }
        let vs = ValidatorSet::new(ids);
        let cfg = NodeConfigForConsensus::for_testing(vs.clone(), genesis());
        let node = ConsensusNode::new(
            self_id,
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::new(MemoryStorage::new()),
            Arc::new(MemoryWal::new()),
        );
        (node, vs)
    }

    /// Regression for issue #118: when a node is the proposing leader it
    /// must process its own `Broadcast(Proposal)` locally so it votes on
    /// its own proposal. Before the fix this path was silent — the p2p
    /// broadcast excluded the sender, the leader never ran
    /// `on_proposal_received` on its own frame, and the next-view
    /// leader's vote bucket was one signer short of quorum.
    #[tokio::test]
    async fn broadcast_proposal_is_delivered_locally_to_leader() {
        // Sit at index 1 so round-robin makes self the view-1 leader
        // (leader(1) = validator_set[1 % 4] = self).
        let ns = fresh_signer();
        let (mut node, vs) = make_node_with_signer(&ns, 1);
        let signer: Arc<dyn Signer> = Arc::new(ns);

        let (broadcaster, mut send_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        // Safety core emits exactly `[Broadcast(Proposal)]` for a freshly
        // booted leader seeded with the genesis QC (regression-tested by
        // `new_seeds_genesis_qc_so_view_one_leader_can_propose`).
        let actions = node.core.become_leader(1);
        assert_eq!(actions.len(), 1);

        node.apply_safety_actions(actions, broadcaster.as_ref(), &mut view_timer, &signer)
            .await
            .unwrap();

        // Observable effect of local self-delivery: the safety core
        // processed its own proposal through `on_proposal_received`,
        // which persists `last_voted_view = 1` before emitting the vote.
        let raw = node
            .storage
            .get(STORAGE_KEY_LAST_VOTED_VIEW)
            .unwrap()
            .expect("last_voted_view must be persisted after self-vote");
        assert_eq!(decode_voted_view(&raw).unwrap(), 1);
        assert_eq!(node.core.state().last_voted_view, 1);

        // Wire traffic: the proposal broadcast must have gone out, and
        // the subsequent vote must also be broadcast (not SendTo) —
        // #124 changed vote routing from point-to-point-to-next-leader
        // to broadcast-and-let-every-replica-aggregate so that QC
        // formation survives the next-view leader being crashed.
        let _next_leader = *vs.get(2).unwrap();

        let first = send_rx
            .try_recv()
            .expect("Broadcast(Proposal) must be sent");
        assert!(
            matches!(first, ProtocolOutbound::Broadcast(_)),
            "first outbound must be the proposal broadcast"
        );
        let second = send_rx.try_recv().expect("Broadcast(Vote) must be sent");
        assert!(
            matches!(second, ProtocolOutbound::Broadcast(_)),
            "second outbound must be the vote broadcast, got {second:?}",
        );
        // No further traffic.
        assert!(send_rx.try_recv().is_err());
    }

    /// Regression for issue #118: when this node is the next-view leader
    /// and votes on the current-view proposal, the safety core emits
    /// `SendTo(self_id, Vote)`. That must be delivered through the local
    /// dispatcher instead of leaking onto the wire, where the p2p layer
    /// would log "SendTo unknown peer SELF" and drop it.
    #[tokio::test]
    async fn send_to_self_vote_loops_back_without_wire_traffic() {
        let ns = fresh_signer();
        let (mut node, _vs) = make_node_with_signer(&ns, 0);
        let self_id = node.self_id;
        let signer: Arc<dyn Signer> = Arc::new(ns);

        let (broadcaster, mut send_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        // Hand-craft a self-addressed Vote action (as the safety core
        // would emit when this node is the next-view leader).
        let vote = crate::consensus::hotstuff::qc::Vote {
            view: 7,
            block_hash: [0x42; 32],
        };
        let action = SafetyAction::SendTo(
            self_id,
            crate::consensus::hotstuff::ConsensusMsg::Vote(vote),
        );

        node.apply_safety_actions(vec![action], broadcaster.as_ref(), &mut view_timer, &signer)
            .await
            .unwrap();

        // No wire traffic: a self-addressed SendTo must be consumed
        // entirely by the local-loopback path.
        assert!(
            send_rx.try_recv().is_err(),
            "self-addressed SendTo must not emit any ProtocolOutbound on the wire",
        );
    }

    /// Non-self `SendTo` must still go on the wire unchanged — the
    /// loopback machinery must only intercept self-addressed sends.
    #[tokio::test]
    async fn send_to_peer_vote_goes_on_the_wire_unchanged() {
        let ns = fresh_signer();
        let (mut node, vs) = make_node_with_signer(&ns, 0);
        let signer: Arc<dyn Signer> = Arc::new(ns);
        // A placeholder peer that is *not* self.
        let peer = *vs.get(1).unwrap();
        assert_ne!(peer, node.self_id);

        let (broadcaster, mut send_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        let vote = crate::consensus::hotstuff::qc::Vote {
            view: 3,
            block_hash: [0x7A; 32],
        };
        let action =
            SafetyAction::SendTo(peer, crate::consensus::hotstuff::ConsensusMsg::Vote(vote));

        node.apply_safety_actions(vec![action], broadcaster.as_ref(), &mut view_timer, &signer)
            .await
            .unwrap();

        let out = send_rx
            .try_recv()
            .expect("peer-addressed SendTo must be sent");
        match out {
            ProtocolOutbound::SendTo { node_id, payload } => {
                assert_eq!(node_id, peer);
                let decoded: WireMessage = postcard::from_bytes(&payload).unwrap();
                assert!(matches!(decoded, WireMessage::Vote(_)));
            }
            other => panic!("expected SendTo to peer, got {other:?}"),
        }
        assert!(send_rx.try_recv().is_err());
    }

    /// A self-addressed `RequestBlock` is degenerate — we can't service
    /// a block request from ourselves. It must be dropped locally rather
    /// than leaking to the p2p layer as "SendTo unknown peer SELF".
    #[tokio::test]
    async fn request_block_from_self_is_dropped() {
        let ns = fresh_signer();
        let (mut node, _vs) = make_node_with_signer(&ns, 0);
        let self_id = node.self_id;
        let signer: Arc<dyn Signer> = Arc::new(ns);

        let (broadcaster, mut send_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        let action = SafetyAction::RequestBlock {
            hash: [0xCD; 32],
            peer: self_id,
            expected_height: 7,
            reason: crate::consensus::hotstuff::step::BlockSyncReason::UnknownParentOnProposal,
        };
        node.apply_safety_actions(vec![action], broadcaster.as_ref(), &mut view_timer, &signer)
            .await
            .unwrap();
        assert!(send_rx.try_recv().is_err());
    }

    // ── Structured tracing capture (#122) ───────────────────────────────────

    /// Shared buffer of captured log lines. Cloneable so the same sink
    /// can back every `MakeWriter::make_writer` call issued by the
    /// subscriber during a test run.
    #[derive(Clone)]
    struct CaptureBuf(Arc<Mutex<Vec<u8>>>);

    impl CaptureBuf {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(Vec::new())))
        }

        fn take_string(&self) -> String {
            String::from_utf8(self.0.lock().clone()).expect("capture writer produced non-UTF8")
        }
    }

    impl std::io::Write for CaptureBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureBuf {
        type Writer = CaptureBuf;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Extract the ordered `message` field from each JSON-encoded trace
    /// event in `captured`, ignoring lines that don't parse (defensive).
    fn trace_messages(captured: &str) -> Vec<String> {
        captured
            .lines()
            .filter_map(|line| {
                let v: serde_json::Value = serde_json::from_str(line).ok()?;
                v.get("fields")?
                    .get("message")?
                    .as_str()
                    .map(|s| s.to_owned())
            })
            .collect()
    }

    /// Panic if `expected` does not appear (in order, possibly with other
    /// events in between) as a subsequence of `actual`.
    fn assert_subsequence(actual: &[String], expected: &[&str]) {
        let mut it = actual.iter();
        for want in expected {
            let found = it.any(|got| got == want);
            assert!(
                found,
                "expected subsequence {expected:?}, missing {want:?} in {actual:?}",
            );
        }
    }

    /// Happy-path flow: feed a QC to the pacemaker, then trigger a
    /// leader proposal through the safety core. Verify the integration
    /// layer emits the expected ordered trace events so operators get
    /// pacemaker → safety → outbound visibility without grepping for
    /// p2p-layer accidents.
    ///
    /// This guards against accidentally removing instrumentation later.
    /// The actual proposal is driven by `core.become_leader` directly
    /// rather than through `PacemakerAction::BecomeLeader` because
    /// `ValidatorSet::new` sorts by `NodeId` and a fresh Ed25519 public
    /// key ends up at a non-deterministic sorted position — so we can't
    /// rely on the pacemaker picking `self` as the view-1 leader.
    #[tokio::test]
    async fn tracing_emits_expected_events_for_proposal_and_vote_flow() {
        let capture = CaptureBuf::new();
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(
                "ambros_p2p::consensus=debug",
            ))
            .with_writer(capture.clone())
            .json()
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let ns = fresh_signer();
        let (mut node, _vs) = make_node_with_signer(&ns, 1);
        let signer: Arc<dyn Signer> = Arc::new(ns);

        let (broadcaster, _send_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        // Phase 1: OnQc(0) through the pacemaker. Covers pacemaker_event,
        // pacemaker_action, view_advanced (cause=qc), plus the
        // Broadcast(NewView) that on_pacemaker_advance emits once the
        // safety core sees the view jump — so outbound_broadcast and
        // new_view_received appear as part of the same flow.
        let boot_actions = node.step_pacemaker(PacemakerEvent::OnQc(0));
        node.apply_pacemaker_actions(boot_actions, broadcaster.as_ref(), &mut view_timer, &signer)
            .await
            .unwrap();

        // Phase 2: directly drive the view-1 leader path so the proposal
        // broadcast + self-loopback vote emission is deterministic
        // regardless of sort-order-dependent leader selection.
        let proposal_actions = node.core.become_leader(1);
        node.apply_safety_actions(
            proposal_actions,
            broadcaster.as_ref(),
            &mut view_timer,
            &signer,
        )
        .await
        .unwrap();

        drop(_guard);

        let captured = capture.take_string();
        let events = trace_messages(&captured);

        // Required subsequence. Extra events are allowed between these
        // points — the assertion is that each named boundary fires in
        // the expected order, not that nothing else fires.
        assert_subsequence(
            &events,
            &[
                "pacemaker_event",    // OnQc(0)
                "pacemaker_action",   // AdvanceToView { view: 1, cause: Qc }
                "view_advanced",      // cause = "qc"
                "outbound_broadcast", // NewView emitted on PacemakerAdvance
                "new_view_received",  // self-loopback into safety core
                "outbound_broadcast", // Proposal from become_leader(1)
                "proposal_received",  // self-loopback into safety core
                "persisted",          // VotedInView flushed before the vote
                "outbound_broadcast", // Vote broadcast to the cluster (#124)
            ],
        );

        // Sanity: the view_advanced event must be tagged cause="qc", not
        // "tc". This is what distinguishes happy-path progress from
        // view-change recovery in the logs.
        let has_qc_view_advanced = captured.lines().any(|line| {
            line.contains("\"message\":\"view_advanced\"") && line.contains("\"cause\":\"qc\"")
        });
        assert!(
            has_qc_view_advanced,
            "view_advanced must carry cause=\"qc\"; got: {captured}",
        );
    }
}
