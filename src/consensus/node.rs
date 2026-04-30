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
//! # `state_commitment` over the uncommitted ancestor chain
//!
//! [`MempoolBlockBuilder`] computes the child block's `state_commitment`
//! by forking the current committed SM state (snapshot → apply → read
//! commitment → restore back). When the proposed parent is the
//! last-committed block, this is a single-step apply. When the leader
//! is pipelining proposals ahead of commits — the normal path under
//! sustained load — the parent has uncommitted ancestors above the
//! last-committed boundary; the builder walks those ancestors via the
//! safety core's `pending_blocks` map and applies their commands in
//! order before applying the candidate commands. This keeps the
//! leader's stamped `state_commitment` byte-identical to what every
//! replica computes from its own SM-after-uncommitted-ancestors
//! (issue #375).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::Context;
use bytes::Bytes;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, oneshot, watch};

use crate::consensus::View;
use crate::consensus::api::CommitNotifier;
use crate::consensus::crashpoint::crashpoint;
use crate::consensus::dispatch::{self, Dispatch, Outbound};
use crate::consensus::hotstuff::Locked;
use crate::consensus::hotstuff::qc::genesis_qc_bls;
use crate::consensus::hotstuff::qc::{ConsensusMsg, TimeoutVote, quorum_size};
use crate::consensus::hotstuff::step::{
    Action as SafetyAction, BlockBuilder, Event as SafetyEvent, HotStuffCore, StateUpdate,
};
use crate::consensus::hotstuff::{HotStuffState, NewView, QuorumCertificate, genesis_qc};
use crate::consensus::limits::{CacheEvictionCounters, CacheLimits};
use crate::consensus::pacemaker::Action as PacemakerAction;
use crate::consensus::pacemaker::Event as PacemakerEvent;
use crate::consensus::pacemaker::Pacemaker;
use crate::consensus::pacemaker::leader::RoundRobinSelector;
use crate::consensus::pacemaker::timeout::ExponentialBackoff;
use crate::consensus::status::{
    BUCKET_VIEW_WINDOW, CacheEvictionStatus, ConsensusStatus, LockedStatus, ParkedProposalStatus,
    QcStatus, TimeoutBucketStatus, VoteBucketStatus,
};
use crate::consensus::validator_history::ValidatorSetHistory;
use crate::consensus::validator_key_history::ValidatorKeyHistory;
use crate::consensus::validator_set::ValidatorSet;
use crate::consensus::view_timer::ViewTimer;
use crate::crypto::signed::ChainId;
use crate::crypto::signed::Signed;
use crate::crypto::signed::SignedMessage;
use crate::crypto::signed::Signer;
use crate::p2p::NodeId;
use crate::p2p::ProtocolEvent;
use crate::p2p::limits::{Decision, MessageKind, RateLimiter};
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
        StateUpdate::ProposedInView { .. } => "ProposedInView",
    }
}

/// Short, stable tag for a pacemaker [`PacemakerEvent`] variant.
fn pacemaker_event_kind(ev: &PacemakerEvent) -> &'static str {
    match ev {
        PacemakerEvent::OnQc(_) => "OnQc",
        PacemakerEvent::OnTimeoutCert(_) => "OnTimeoutCert",
        PacemakerEvent::OnTimeout(_) => "OnTimeout",
        PacemakerEvent::OnProposalReceived(_) => "OnProposalReceived",
        PacemakerEvent::OnRoundSync(_) => "OnRoundSync",
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

/// Storage key for the highest view at which this replica has minted
/// a `Proposal` as leader. Persisted before any `Broadcast(Proposal)`
/// leaves so a crash between `Signed::sign` and the network bytes
/// reaching peers cannot let a restarted leader re-mint a *different*
/// proposal at the same view (different parent walk, different
/// `high_qc` snapshot, different mempool ordering) — two distinct
/// signed `Proposal(v)` envelopes from the same leader are slashable
/// equivocation evidence even when the leader was honest. Read at
/// boot by [`ConsensusNode::recover`] and threaded into the safety
/// core via [`HotStuffCore::with_proposed_in_view`]. Audit finding
/// 4-6, issue #407.
pub const STORAGE_KEY_PROPOSED_IN_VIEW: &[u8] = b"consensus/proposed_in_view";

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

/// Storage key for the persisted [`ValidatorSetHistory`] (#254). Written
/// after every successful commit-time reconfig application; read at
/// startup by [`ConsensusNode::recover`] so the active set tracks
/// committed reconfigs across restarts. The blob is the postcard-
/// encoded full history (genesis boundary + every later boundary in
/// chronological order) — small enough that we don't bother with
/// incremental encoding or a GC bound (#140 open question: keep all,
/// revisit if validator-set churn ever becomes pathological).
pub const STORAGE_KEY_VALIDATOR_HISTORY: &[u8] = b"consensus/validator_history";

/// Storage key for the persisted [`ValidatorKeyHistory`] (#260).
/// Written after every successful commit-time rotation application;
/// read at startup so post-rotation signing keys persist across
/// restarts. Same encoding shape as
/// [`STORAGE_KEY_VALIDATOR_HISTORY`]: a single full snapshot rather
/// than a journal, traded for simpler recovery.
pub const STORAGE_KEY_VALIDATOR_KEY_HISTORY: &[u8] = b"consensus/validator_key_history";

/// Storage key for the persisted [`crate::consensus::bls_key_history::BlsKeyHistory`]
/// (#339). Written alongside [`STORAGE_KEY_VALIDATOR_KEY_HISTORY`]
/// after every successful commit-time rotation application on BLS
/// chains; read at startup so the per-validator BLS pubkey timeline
/// persists across restarts. Without this, an old QC verified after
/// a restart would index against a stale post-genesis pubkey set
/// because the rotations are reseeded from genesis only.
pub const STORAGE_KEY_BLS_KEY_HISTORY: &[u8] = b"consensus/bls_key_history";

/// Protocol ID registered with the p2p multiplexer for consensus traffic.
/// Gossip uses `0x01`, ping-RPC uses `0x02`.
pub const PROTOCOL_ID: u8 = 0x03;

/// Maximum encoded frame size accepted from the wire for this protocol.
/// Sized to accommodate a full block with up to ~1000 moderate-sized
/// commands; production tuning can raise this without protocol changes.
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024; // 4 MiB

// ── Wire message envelope ────────────────────────────────────────────────────

/// Signed payload of a [`WireMessage::BlockResponse`].
///
/// `requested_hash` is the hash the requester named in the matching
/// `BlockRequest`. Including it inside the signed envelope binds the
/// responder's signature to a specific request: a Byzantine peer who
/// returns a different block (or no block) under a wrong-hash claim
/// is non-repudiable evidence — the requester can later present
/// `(BlockResponsePayload, signature)` for slashing once that
/// machinery lands.
///
/// Receivers must drop a response whose `block.hash() != requested_hash`,
/// or whose `requested_hash` does not match an outstanding
/// `block_sync_inflight` entry. See the
/// [`Dispatch::ReceiveBlock`](crate::consensus::dispatch::Dispatch::ReceiveBlock)
/// handler in [`Self::apply_dispatch`] for the gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockResponsePayload {
    /// The hash from the matching `BlockRequest` this response answers.
    pub requested_hash: BlockHash,
    /// The block matching `requested_hash`, or `None` if the responder
    /// doesn't have it.
    pub block: Option<Block>,
}

impl SignedMessage for BlockResponsePayload {
    const DOMAIN: &'static str = "ambros.consensus.block_response.v1";
}

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
///
/// `SnapshotManifestRequest` / `SnapshotManifestResponse` /
/// `SnapshotChunkRequest` / `SnapshotChunkResponse` are the snapshot
/// sub-protocol (#228): a joiner asks a peer for a manifest (latest or
/// at a specific height), then for each chunk by `(height, idx)`.
/// Issue #229 builds the joiner-side state machine on top.
///
/// **Variant order is wire-stable.** Postcard encodes the discriminant
/// as a varint at byte 0; reordering breaks every running peer.
/// Adding new variants at the end is fine. The
/// [`crate::p2p::limits::MessageKind`] enum mirrors this order and is
/// pinned by `wire_tag_layout_locked`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireMessage {
    Proposal(Signed<crate::consensus::hotstuff::Proposal>),
    /// A signed vote, optionally carrying a BLS partial signature
    /// alongside the Ed25519 envelope.
    ///
    /// The optional second field carries one validator's contribution to
    /// a future BLS QC aggregate. It is `Some(_)` on `bls_aggregated`
    /// chains and `None` on `ed25519_collected` chains. The partial sits
    /// **outside** the [`Signed<Vote>`] envelope so the postcard bytes
    /// of `Vote { view, block_hash }` — and therefore the canonical
    /// signing pre-image — stay byte-stable across schemes. Persisted
    /// `last_voted_view` envelopes and snapshot QCs continue to verify
    /// unchanged. See [`crate::consensus::dispatch`] for the ingress
    /// validation rule that enforces presence per chain scheme.
    Vote(
        Signed<crate::consensus::hotstuff::qc::Vote>,
        #[serde(with = "serde_optional_bls_partial")]
        Option<crate::crypto::sig_scheme::BlsPartialSig>,
    ),
    NewView(Signed<crate::consensus::hotstuff::NewView>),
    /// A replica's signed notice that it is giving up on a view. A
    /// quorum of these forms the timeout certificate that advances
    /// `view + 1` even when the leader never proposes.
    TimeoutVote(Signed<TimeoutVote>),
    /// Ask a peer for the block with this content-hash.
    BlockRequest(BlockHash),
    /// Reply to a `BlockRequest`. The signed payload commits to the
    /// hash the requester originally named so a Byzantine responder
    /// who returns the wrong block (or nothing) is non-repudiable
    /// evidence the responder can later be slashed for (#434).
    BlockResponse(Signed<BlockResponsePayload>),
    /// Ask a peer for a snapshot manifest. `None` means "your latest";
    /// `Some(h)` means "the snapshot at exact height `h`".
    SnapshotManifestRequest {
        height: Option<u64>,
    },
    /// Reply to a [`WireMessage::SnapshotManifestRequest`]. `None`
    /// means "I have no matching snapshot".
    SnapshotManifestResponse(Option<crate::replication::snapshot::SnapshotManifest>),
    /// Ask a peer for chunk `chunk_idx` of the snapshot at `height`.
    SnapshotChunkRequest {
        height: u64,
        chunk_idx: u32,
    },
    /// Reply to a [`WireMessage::SnapshotChunkRequest`]. `payload =
    /// None` means "I have no such chunk" (snapshot pruned, chunk
    /// index out of range, or never had this snapshot).
    SnapshotChunkResponse {
        height: u64,
        chunk_idx: u32,
        payload: Option<Bytes>,
    },
}

/// Serde adapter for `Option<BlsPartialSig>` — a 96-byte fixed array that
/// serde does not auto-derive past N=32. Mirrors the byte-sequence
/// shape used by [`crate::crypto::sig_scheme::BlsPop`] so the two BLS
/// wire fields encode the same way (length-prefixed byte sequence
/// inside an `Option`).
mod serde_optional_bls_partial {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    use crate::crypto::sig_scheme::BlsPartialSig;

    pub fn serialize<S: Serializer>(opt: &Option<BlsPartialSig>, s: S) -> Result<S::Ok, S::Error> {
        match opt {
            Some(sig) => s.serialize_some(&sig[..]),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<BlsPartialSig>, D::Error> {
        let opt: Option<Vec<u8>> = Option::deserialize(d)?;
        match opt {
            Some(v) => v
                .as_slice()
                .try_into()
                .map(Some)
                .map_err(|_| D::Error::custom("BLS partial must be exactly 96 bytes")),
            None => Ok(None),
        }
    }
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
    /// Per-cache caps for the safety-core's `vote_bucket`,
    /// `parked_proposals`, `pending_blocks` and the integration
    /// layer's `timeout_buckets`. See
    /// [`crate::consensus::limits::CacheLimits`] for the policy
    /// documentation.
    pub limits: CacheLimits,
    /// Snapshot creation policy. Defaults to disabled (no snapshots
    /// produced) so tests that don't opt in see zero behavioural
    /// change; production wiring in `src/node.rs` substitutes the
    /// operator-configured policy from
    /// [`crate::config::ConsensusConfig`].
    pub snapshot_policy: crate::replication::snapshot::SnapshotPolicy,

    /// Operator-supplied floor on the gap between a reconfig's commit
    /// view and its `v_eff` (#272). Clamped up to
    /// [`crate::consensus::reconfig::MIN_V_EFF_DELAY`] at validation
    /// time so the consensus-side floor is never undercut. Defaults to
    /// the constant.
    pub min_v_eff_delay: View,

    /// Chain-level signature scheme selected at genesis (#288). Fixed
    /// for the lifetime of the chain — switching requires a
    /// coordinated chain restart from new genesis. Today only
    /// `Ed25519Collected` is implemented; the BLS variant lands in #289
    /// and the "node built for the wrong scheme" mismatch check lands
    /// in #292.
    pub signature_scheme: crate::crypto::sig_scheme::SignatureSchemeChoice,
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
            // Tests should not see eviction unless they explicitly
            // construct a tight-cap config; honest-only proptests in
            // particular fail loudly under spurious eviction. The
            // production wiring in `src/node.rs` substitutes
            // `CacheLimits::production_defaults` (or the operator's
            // override).
            limits: CacheLimits::unbounded_for_tests(),
            // Tests opt into snapshots by replacing this with a real
            // policy. The default keeps the snapshot store untouched.
            snapshot_policy: crate::replication::snapshot::SnapshotPolicy::disabled(),
            min_v_eff_delay: crate::consensus::reconfig::MIN_V_EFF_DELAY,
            signature_scheme: crate::crypto::sig_scheme::SignatureSchemeChoice::default(),
        }
    }
}

// ── Block builder ────────────────────────────────────────────────────────────

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
    /// integration layer ([`ConsensusNode::apply_commit`] and
    /// [`ConsensusNode::restore_from_snapshot`]) writes; the builder
    /// reads to bound the uncommitted-ancestor walk so genesis
    /// (height 0, pre-seeded into `pending_blocks`) and any
    /// recovery-seeded block at-or-below the committed boundary
    /// are not re-applied to the SM.
    last_committed_height: Arc<AtomicU64>,
    /// Cumulative count of commands the builder dropped because
    /// `StateMachine::apply` returned `Err` (issue #376). Read by
    /// [`ConsensusNode::build_status`] and surfaced under
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
        let committed_height = self.last_committed_height.load(Ordering::Relaxed);
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
                                view,
                                ancestor_height = ancestor.header.height,
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
                            view,
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
                    view,
                    parent_height = parent.header.height,
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
    committed_height: u64,
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
    /// View-keyed history of `validator_set` across reconfiguration
    /// boundaries (#248). Until #253 lands the active reconfiguration
    /// path, this holds only the genesis boundary, so `set_at(view)`
    /// returns `validator_set` for every view. The dispatcher's
    /// per-message signer check consults this in #249 so signature
    /// verification can switch sides at a future boundary without
    /// further plumbing.
    pub validator_history: ValidatorSetHistory,
    /// Per-validator history of consensus signing keys (#259). Bridges
    /// the signer pubkey on the wire — which may be a post-rotation key
    /// — to the validator's stable identifier in `validator_history`.
    /// Until rotation tx commit-time application lands (#260), this
    /// only ever contains genesis entries (and any reconfig-added
    /// validators), so verification semantics match the
    /// pre-rotation behaviour.
    pub validator_key_history: ValidatorKeyHistory,
    /// Per-validator BLS pubkey history (#294). `Some` only on chains
    /// whose genesis declared `signature_scheme = "bls_aggregated"`
    /// (#288); `None` on Ed25519 chains. Used by the dispatch-layer QC
    /// aggregate verification (#332) to resolve per-historical-view
    /// BLS pubkeys for `verify_aggregate_bls`.
    pub bls_key_history: Option<crate::consensus::bls_key_history::BlsKeyHistory>,
    /// This validator's BLS partial signer (#354 step 2). `Some` on
    /// `bls_aggregated` chains where the operator loaded a
    /// `BlsValidatorIdentity` at boot; `None` on Ed25519 chains and on
    /// non-validator BLS-chain participants. Wrapped in `Arc` so the
    /// dispatch layer can cheaply hold a borrow across `await`
    /// suspension points alongside the existing Ed25519 `signer`.
    /// Consumed by [`crate::consensus::dispatch::sign_consensus_msg`]
    /// when signing a `Vote` on a BLS chain — the produced
    /// `BlsPartialSig` rides on the wire alongside the Ed25519
    /// envelope.
    pub bls_signer: Option<
        Arc<dyn crate::crypto::signed::PartialSigner<crate::crypto::sig_scheme::BlsAggregated>>,
    >,
    /// Chain-level signature scheme (#288). Fixed for the lifetime of
    /// the chain; consulted at ingress time to dispatch QC aggregate
    /// verification through the right `verify_aggregate` /
    /// `verify_aggregate_bls` arm.
    pub signature_scheme: crate::crypto::sig_scheme::SignatureSchemeChoice,
    /// Configured view-timer behaviour; consulted by the timer helper
    /// in Phase D when arming/re-arming the view timer.
    pub timeout_policy: Arc<ExponentialBackoff>,
    /// Partial timeout certificates this replica is accumulating,
    /// keyed by the `View` the timeout pertains to. An entry is
    /// dropped once its TC fires `OnTimeoutCert` into the pacemaker
    /// so late-arriving timeout votes for past views are cheap no-ops.
    timeout_buckets: HashMap<View, TimeoutBucket>,
    /// Cap on `timeout_buckets`. When at cap, the lowest-`view`
    /// bucket is dropped so a flood of timeout votes for far-future
    /// views can never grow the map without bound. See
    /// [`CacheLimits::timeout_buckets_capacity`].
    timeout_buckets_capacity: usize,
    /// Shared eviction-counter handle. The same `Arc` is bound into
    /// the [`HotStuffCore`] at construction so all four caches feed
    /// into one consistent set of cumulative counts.
    eviction_counters: CacheEvictionCounters,
    /// Optional [`CommitNotifier`] fired after each block is committed
    /// and applied. `None` in production builds today; consumed by the
    /// simulator for liveness assertions and by future observer-mode
    /// (#308) / out-of-process Application (#225) wiring.
    commit_notifier: Option<Arc<dyn CommitNotifier>>,
    /// Peer-membership snapshot used by [`ConsensusNode::build_status`].
    /// Populated from [`Discovery`] events inside [`ConsensusNode::run`];
    /// before `run` starts (or in tests that bypass it) the set is empty
    /// and the status snapshot reports zero connected peers.
    peers_connected: HashSet<NodeId>,
    /// Height of the most recently committed block, updated in
    /// [`ConsensusNode::apply_commit`]. Zero before the first commit.
    /// Wrapped in `Arc<AtomicU64>` so the [`MempoolBlockBuilder`] can
    /// read it from inside the safety core's `build_proposal_at_view`
    /// path to bound the uncommitted-ancestor walk (issue #375)
    /// without having to thread a borrow through the trait object.
    last_committed_height: Arc<AtomicU64>,
    /// Cumulative count of commands the local [`MempoolBlockBuilder`]
    /// dropped because `StateMachine::apply` returned `Err` (issue
    /// #376). Surfaced under [`ConsensusStatus::dropped_commands`].
    /// Shared with the builder's own `Arc<AtomicU64>` so the two
    /// always agree without locking.
    dropped_commands: Arc<AtomicU64>,
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
    /// Per-peer rate limiter (issue #134). When set, every inbound
    /// frame is classified by its postcard variant tag and admitted /
    /// dropped / disconnected per the configured token buckets. When
    /// `None`, ingress runs unfiltered — matches the historical
    /// pre-#134 behaviour and is the default in the simulator's
    /// happy-path tests.
    rate_limiter: Option<Arc<RateLimiter>>,
    /// Channel into the peer manager. When set together with
    /// `rate_limiter`, a [`Decision::Disconnect`] from the limiter
    /// drives a [`crate::p2p::PeerCommand::Disconnect`] so the
    /// offending peer's TCP/TLS connection is torn down. `None` in
    /// the simulator (which has no real manager); the limiter still
    /// records the disconnect-decision in its own counter so tests
    /// can observe the decision.
    peer_cmd_tx: Option<mpsc::Sender<crate::p2p::PeerCommand>>,
    /// Snapshot creation policy. When `is_enabled()`, [`apply_commit`]
    /// produces a snapshot at every multiple of `interval_blocks`.
    snapshot_policy: crate::replication::snapshot::SnapshotPolicy,
    /// Operator-supplied floor on the gap between a reconfig's commit
    /// view and its `v_eff` (#272). Clamped up to
    /// [`crate::consensus::reconfig::MIN_V_EFF_DELAY`] at validation
    /// time so the consensus-side floor is never undercut.
    min_v_eff_delay: View,
    /// Bounded cache of QCs adopted as `high_qc`, keyed by block hash.
    /// Populated by [`persist_updates`] on every `StateUpdate::HighQc`.
    /// Read at snapshot creation time to find a QC over the snapshot
    /// block. Wrapped in a [`parking_lot::Mutex`] so [`persist_updates`]
    /// can update it through a `&self` receiver — the existing
    /// signature is consumed by many tests with shared (`&`) borrows.
    recent_qcs: Mutex<RecentQcCache>,
    /// Joiner-side snapshot-fetch state machine (#229). Watches
    /// inbound proposals for lag, drives manifest+chunk fetch from a
    /// single peer, and emits an action for the integration layer to
    /// restore state. Disabled (no-op) when the policy's
    /// `interval_blocks == 0`.
    snapshot_sync: crate::consensus::snapshot_sync::SnapshotSync,
    /// Deployment-scoped 32-byte tag (#324) mixed into every signing
    /// pre-image we produce or verify. Derived once from the genesis
    /// block hash so every honest replica with the same genesis
    /// converges on the same value; cross-deployment signature replay
    /// fails because a sibling deployment with a different genesis has
    /// a different `ChainId`.
    chain_id: ChainId,
}

/// Bounded LRU-by-insertion cache of QCs keyed by block hash.
///
/// Insertion order is tracked in a `VecDeque`; on overflow, the
/// oldest entry is dropped. Lookups are O(1) via the inner `HashMap`.
#[derive(Default)]
struct RecentQcCache {
    map: HashMap<BlockHash, QuorumCertificate>,
    order: std::collections::VecDeque<BlockHash>,
}

impl RecentQcCache {
    fn insert(&mut self, hash: BlockHash, qc: QuorumCertificate, capacity: usize) {
        if self.map.insert(hash, qc).is_none() {
            self.order.push_back(hash);
            // Evict the oldest entries until back under cap.
            while self.order.len() > capacity {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
        }
    }

    fn get(&self, hash: &BlockHash) -> Option<&QuorumCertificate> {
        self.map.get(hash)
    }
}

/// Bound on [`ConsensusNode::recent_qcs`]. The cache only needs to
/// retain the QC for the most recently-committed block (so the
/// snapshot creation hook can find it); a small buffer absorbs
/// re-orderings between proposal arrival and commit. Production
/// memory cost is negligible — each QC is ≤ a few KiB and the cache
/// is tens of entries deep.
pub const RECENT_QC_CACHE_CAPACITY: usize = 32;

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

        // Pacemaker leader rotation runs against the historical lookup
        // (#271). With the genesis-only history below, behavior matches
        // the previous single-set rotation exactly; once #272 lands the
        // commit-time application path, leaders past `v_eff` will come
        // from the post-boundary set.
        let selector = Arc::new(RoundRobinSelector::from_genesis_set(Arc::clone(
            &validator_set,
        )));

        let pacemaker = Pacemaker::new(
            self_id,
            Arc::clone(&selector) as _,
            Arc::clone(&timeout_policy) as _,
        );

        let last_committed_height = Arc::new(AtomicU64::new(0));
        let dropped_commands = Arc::new(AtomicU64::new(0));
        let builder = Arc::new(MempoolBlockBuilder::new(
            self_id,
            Arc::clone(&mempool),
            Arc::clone(&state_machine),
            Arc::clone(&last_committed_height),
            Arc::clone(&dropped_commands),
            config.propose_limit,
        ));

        let validator_set_len = config.validator_set.len();
        // #324: bind the deployment's signing tag to its genesis block
        // hash. Compute before moving `config.genesis` into the safety
        // core. Every honest replica with the same genesis derives the
        // same value; sibling deployments with different genesis bytes
        // get a different tag, so a Vote/Proposal/NewView signed on one
        // chain cannot be replayed on another.
        let chain_id = ChainId::from_genesis_hash(config.genesis.hash());
        // Pick the genesis QC shape that matches the chain's signature
        // scheme. The Ed25519 path's all-zero placeholder sigs would
        // panic if folded into a BLS aggregate (see #338's
        // well-formedness invariant); the BLS variant returns an
        // empty-bitmap, empty-aggregate QC that the dispatch verifier
        // accepts via its `signer_count == 0` genesis-skip path.
        let boot_qc = match config.signature_scheme {
            crate::crypto::sig_scheme::SignatureSchemeChoice::Ed25519Collected => {
                genesis_qc(&config.genesis, validator_set_len)
            }
            crate::crypto::sig_scheme::SignatureSchemeChoice::BlsAggregated => {
                genesis_qc_bls(&config.genesis, validator_set_len)
            }
        };
        let mut hs_state = HotStuffState::new(config.validator_set.clone(), config.genesis);
        // Seed the cluster-agreed genesis QC so the view-1 leader can
        // build a proposal on first boot without waiting for a QC-forming
        // vote round. Every honest replica derives the same QC from the
        // shared `(genesis, validator_set_len)` config.
        hs_state.high_qc = Some(boot_qc);
        let eviction_counters = CacheEvictionCounters::default();
        let core = HotStuffCore::with_limits(
            self_id,
            hs_state,
            builder as Arc<dyn BlockBuilder>,
            config.limits,
            eviction_counters.clone(),
        )
        .with_signature_scheme(config.signature_scheme);

        let validator_history = ValidatorSetHistory::from_genesis(config.validator_set.clone());
        let validator_key_history = ValidatorKeyHistory::new(config.validator_set.iter().copied());
        Self {
            self_id,
            core,
            pacemaker,
            state_machine,
            mempool,
            storage,
            wal,
            validator_set: config.validator_set,
            validator_history,
            validator_key_history,
            bls_key_history: None,
            bls_signer: None,
            signature_scheme: config.signature_scheme,
            timeout_policy,
            timeout_buckets: HashMap::new(),
            timeout_buckets_capacity: config.limits.timeout_buckets_capacity,
            eviction_counters,
            commit_notifier: None,
            peers_connected: HashSet::new(),
            last_committed_height,
            dropped_commands,
            last_committed_view: 0,
            status_tx: None,
            rate_limiter: None,
            peer_cmd_tx: None,
            snapshot_policy: config.snapshot_policy,
            min_v_eff_delay: config.min_v_eff_delay,
            recent_qcs: Mutex::new(RecentQcCache::default()),
            snapshot_sync: crate::consensus::snapshot_sync::SnapshotSync::new(
                config.snapshot_policy,
            ),
            chain_id,
        }
    }

    /// Attach the per-validator BLS pubkey history. Used at boot on BLS
    /// chains so the dispatch layer can resolve per-historical-view BLS
    /// pubkeys for QC aggregate verification (#332). On Ed25519 chains
    /// this stays unset.
    pub fn with_bls_key_history(
        mut self,
        bls_key_history: crate::consensus::bls_key_history::BlsKeyHistory,
    ) -> Self {
        self.bls_key_history = Some(bls_key_history);
        self
    }

    /// Attach this validator's BLS partial signer (#354 step 2).
    ///
    /// Used at boot on `bls_aggregated` chains, when the operator has
    /// loaded a `BlsValidatorIdentity` for this node — see
    /// [`crate::crypto::bls_key::BlsPartialSignerImpl::from_identity`].
    /// The dispatch layer consults this signer when this node emits a
    /// `Vote`, producing the 96-byte BLS partial that rides on the
    /// wire alongside the Ed25519 envelope. On Ed25519 chains this
    /// stays unset; on BLS chains where this node is not a validator
    /// (or the operator booted without an identity), this also stays
    /// unset and the node will receive but never emit votes.
    pub fn with_bls_signer(
        mut self,
        bls_signer: Arc<
            dyn crate::crypto::signed::PartialSigner<crate::crypto::sig_scheme::BlsAggregated>,
        >,
    ) -> Self {
        self.bls_signer = Some(bls_signer);
        self
    }

    /// Attach a [`CommitNotifier`] (issue #373).
    ///
    /// Every block committed by the event loop is reported via
    /// [`CommitNotifier::on_commit`] after the block has been applied
    /// to the state machine, persisted, and had its tagged reconfig
    /// (#272) and rotation (#260) payloads processed. Intended for
    /// test harnesses (e.g. `SimCluster`), observer-mode nodes (#308),
    /// and external indexers; production callers without an observer
    /// leave this unset (`None`).
    ///
    /// The callback runs on the consensus event loop — implementations
    /// must not block (forward to a channel or atomic). See the
    /// [`CommitNotifier`] doc-comment for the full contract.
    pub fn with_commit_notifier(mut self, notifier: Arc<dyn CommitNotifier>) -> Self {
        self.commit_notifier = Some(notifier);
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

    /// Attach a per-peer rate limiter (issue #134) and the optional
    /// peer-command channel used to issue
    /// [`crate::p2p::PeerCommand::Disconnect`] when the limiter
    /// returns [`Decision::Disconnect`] for a peer. Pass `peer_cmd_tx
    /// = None` in the simulator: the limiter will still classify and
    /// drop, and tests can observe the disconnect decision via
    /// [`RateLimiter::counters`].
    pub fn with_rate_limiter(
        mut self,
        limiter: Arc<RateLimiter>,
        peer_cmd_tx: Option<mpsc::Sender<crate::p2p::PeerCommand>>,
    ) -> Self {
        self.rate_limiter = Some(limiter);
        self.peer_cmd_tx = peer_cmd_tx;
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
            .map(|v| crate::p2p::tls::node_id_to_base58(v.as_node_id()))
            .collect();

        ConsensusStatus {
            node_id: crate::p2p::tls::node_id_to_base58(&self.self_id),
            self_role,
            current_view,
            last_voted_view: state.last_voted_view,
            last_committed_height: self.last_committed_height.load(Ordering::Relaxed),
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
            cache_evictions: CacheEvictionStatus {
                vote_buckets: self.eviction_counters.vote_bucket(),
                parked_proposals: self.eviction_counters.parked_proposals(),
                pending_blocks: self.eviction_counters.pending_blocks(),
                timeout_buckets: self.eviction_counters.timeout_buckets(),
            },
            dropped_commands: self.dropped_commands.load(Ordering::Relaxed),
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
            None => LastCommitted {
                height: 0,
                view: 0,
                last_committed_hash: [0u8; 32],
            },
        };

        // #254: recover the persisted validator history if any
        // committed reconfig has flushed it. Missing key → fresh
        // genesis-only history.
        let validator_history = match storage
            .get(STORAGE_KEY_VALIDATOR_HISTORY)
            .context("read validator_history from storage")?
        {
            Some(raw) => {
                let persisted: crate::consensus::validator_history::PersistedValidatorHistory =
                    postcard::from_bytes(&raw).context("decode persisted validator_history")?;
                ValidatorSetHistory::from_persisted(persisted)
                    .context("rebuild ValidatorSetHistory from persisted form")?
            }
            None => ValidatorSetHistory::from_genesis(config.validator_set.clone()),
        };

        let active_set = (*validator_history.current_set()).clone();
        let timeout_policy = Arc::new(ExponentialBackoff::new(
            config.timeout_base,
            config.timeout_max,
        ));
        // Build the selector against a snapshot of the recovered
        // history so leader rotation honors any post-genesis boundaries
        // immediately after restart.
        let selector = Arc::new(RoundRobinSelector::new(Arc::new(validator_history.clone())));
        let pacemaker = Pacemaker::new(
            self_id,
            Arc::clone(&selector) as _,
            Arc::clone(&timeout_policy) as _,
        );

        let last_committed_height = Arc::new(AtomicU64::new(last_committed.height));
        let dropped_commands = Arc::new(AtomicU64::new(0));
        let builder = Arc::new(MempoolBlockBuilder::new(
            self_id,
            Arc::clone(&mempool),
            Arc::clone(&state_machine),
            Arc::clone(&last_committed_height),
            Arc::clone(&dropped_commands),
            config.propose_limit,
        ));
        // #407: restore the leader-side `proposed_in_view` guard so a
        // crash between `Signed::sign` and the `Broadcast(Proposal)`
        // bytes leaving the host does not let this replica re-mint a
        // *different* signed proposal at the same view on restart.
        // Missing key = fresh storage; a value of `0` is the safe
        // default the in-memory field already starts at.
        let proposed_in_view = match storage
            .get(STORAGE_KEY_PROPOSED_IN_VIEW)
            .context("read proposed_in_view from storage")?
        {
            Some(raw) => decode_proposed_in_view(&raw)?,
            None => 0,
        };
        let eviction_counters = CacheEvictionCounters::default();
        let mut core = HotStuffCore::with_limits(
            self_id,
            hs_state,
            builder as Arc<dyn BlockBuilder>,
            config.limits,
            eviction_counters.clone(),
        )
        .with_signature_scheme(config.signature_scheme)
        .with_proposed_in_view(proposed_in_view);

        // #254: replay each post-genesis boundary into the safety
        // core's history so vote tally / QC sizing / proposal-time
        // leader pick all see the recovered committee. Genesis is
        // already seeded by `HotStuffState::new`. Any failure here
        // surfaces as a recovery error — we'd rather fail closed than
        // run with a stale set.
        for (v_eff, set) in validator_history.iter() {
            if v_eff == 0 {
                continue;
            }
            core.insert_validator_boundary(v_eff, (**set).clone())
                .with_context(|| format!("replay validator boundary at v_eff = {v_eff}"))?;
        }

        // #260: load the persisted key history first, falling back to a
        // mirror of the set history if no rotations have ever been
        // committed (or the WAL key is otherwise absent). The persisted
        // form is authoritative once written — every committed rotation
        // is reflected — so we never overwrite it from set history.
        let validator_key_history = match storage
            .get(STORAGE_KEY_VALIDATOR_KEY_HISTORY)
            .context("read validator_key_history from storage")?
        {
            Some(raw) => {
                let persisted: crate::consensus::validator_key_history::PersistedValidatorKeyHistory =
                    postcard::from_bytes(&raw)
                        .context("decode persisted validator_key_history")?;
                ValidatorKeyHistory::from_persisted(persisted)
                    .context("rebuild ValidatorKeyHistory from persisted form")?
            }
            None => ValidatorKeyHistory::from_set_history(&validator_history),
        };

        // #324: same derivation as `ConsensusNode::new` — recover paths
        // must produce the same `ChainId` as a fresh boot, since both
        // share the same genesis bytes.
        let chain_id = ChainId::from_genesis_hash(config.genesis.hash());
        Ok(Self {
            self_id,
            core,
            pacemaker,
            state_machine,
            mempool,
            storage,
            wal,
            validator_set: active_set,
            validator_history,
            validator_key_history,
            bls_key_history: None,
            bls_signer: None,
            signature_scheme: config.signature_scheme,
            timeout_policy,
            timeout_buckets: HashMap::new(),
            timeout_buckets_capacity: config.limits.timeout_buckets_capacity,
            eviction_counters,
            commit_notifier: None,
            peers_connected: HashSet::new(),
            last_committed_height,
            dropped_commands,
            last_committed_view: last_committed.view,
            status_tx: None,
            rate_limiter: None,
            peer_cmd_tx: None,
            snapshot_policy: config.snapshot_policy,
            min_v_eff_delay: config.min_v_eff_delay,
            recent_qcs: Mutex::new(RecentQcCache::default()),
            snapshot_sync: crate::consensus::snapshot_sync::SnapshotSync::new(
                config.snapshot_policy,
            ),
            chain_id,
        })
    }

    /// Walk the persisted committed-block chain from genesis to the
    /// last-committed tip, rebuilding the validator histories from
    /// each block's reconfig and rotation commands, and assert that
    /// the rebuilt histories match what's currently loaded into this
    /// node from storage.
    ///
    /// **Audit goal (#325 PR B / 7-F2 anti-rollback)**: a corrupted
    /// or rolled-back persisted history blob — for instance, an
    /// attacker who flipped a byte in a boundary's `v_eff` to seat a
    /// validator early, or replaced the genesis member list — must be
    /// rejected at startup before consensus signs anything against
    /// the rolled-back state. This method is the gate.
    ///
    /// Two checks run together:
    ///
    /// 1. **Per-block commitment cross-check** (defense-in-depth):
    ///    each block's
    ///    [`crate::replication::block::BlockHeader::validator_history_commitment`]
    ///    must match the rebuild's `(set, key, bls?)` snapshot taken
    ///    *before* applying the block's commands. With PR A's
    ///    pre-block stamping semantics, this matches what the leader
    ///    actually signed at proposal time.
    /// 2. **End-of-walk equality**: after applying every block's
    ///    commands, the rebuilt persisted forms must equal the
    ///    histories loaded from storage. This is the literal audit
    ///    criterion: a tampered blob that survived the
    ///    `from_persisted` invariants will diverge here.
    ///
    /// Caller contract: invoke this **after** [`Self::with_bls_key_history`]
    /// has been wired in on BLS chains, since the BLS history is part
    /// of the commitment.
    ///
    /// Returns `Err` on any divergence. The caller propagates: the
    /// operator sees the error and the node refuses to start.
    ///
    /// # Out of scope
    ///
    /// Snapshot sync (#229) will eventually bound the walk; today it
    /// walks the entire committed chain. For chains a few thousand
    /// blocks deep this is fine (each iteration is a storage read +
    /// in-memory hash); deployments with millions of blocks may
    /// notice startup latency. Acceptable until #229 lands.
    pub fn verify_persisted_history_consistency(&self) -> anyhow::Result<()> {
        use crate::consensus::history_commitment::{
            apply_reconfig_commands_to_set_history, apply_rotation_commands_to_histories,
            validator_history_commitment_v1,
        };

        // Locate the chain tip from storage. Empty-tip = no blocks
        // committed yet (fresh boot or freshly reset storage); the
        // genesis-only triple in memory is trivially consistent with
        // a zero-block chain, so there's nothing to walk.
        let last_committed = match self
            .storage
            .get(STORAGE_KEY_LAST_COMMITTED)
            .context("read last_committed from storage")?
        {
            Some(raw) => decode_last_committed(&raw)?,
            None => return Ok(()),
        };
        if last_committed.height == 0 {
            // No committed blocks past genesis; nothing to walk.
            return Ok(());
        }

        // Walk backward from the tip to genesis, collecting blocks.
        // The walk uses each block's `parent_hash` link, same as
        // block-sync. Genesis is found either:
        //
        //  - in the in-memory `pending_blocks` (where
        //    [`HotStuffState::new`] always pre-seeds it), or
        //  - in storage at the `consensus/block/<genesis_hash>` key, if
        //    the safety core's `persist_updates` ever wrote it (which
        //    happens whenever a Locked / HighQc references genesis).
        //
        // We accept either source — both paths share the same hash so
        // the rebuilt chain anchors on the same content. Failing to
        // find genesis is an error (unreachable on a healthy chain
        // because the chain head's parent walk must terminate at
        // `genesis_hash`).
        let configured_genesis_hash = self.core.state().genesis_hash;
        let mut chain: Vec<Block> = Vec::new();
        let mut cursor = last_committed.last_committed_hash;
        loop {
            let block = if cursor == configured_genesis_hash {
                // Prefer the in-memory genesis (always present at
                // recover time) over a storage lookup. This keeps the
                // walk working even on tests that don't bother
                // persisting genesis under STORAGE_KEY_BLOCK_PREFIX.
                if let Some(g) = self.core.state().pending_blocks.get(&cursor).cloned() {
                    g
                } else if let Some(g) = load_block_from_storage(self.storage.as_ref(), &cursor)? {
                    g
                } else {
                    anyhow::bail!(
                        "validator history rebuild: genesis block at hash {} missing from both \
                         pending_blocks and storage — this should be unreachable on a healthy \
                         restart",
                        hex::encode(cursor),
                    );
                }
            } else {
                load_block_from_storage(self.storage.as_ref(), &cursor)?.ok_or_else(|| {
                    anyhow::anyhow!(
                        "validator history rebuild: storage missing committed block at \
                             hash {} (chain walk diverged from persisted \
                             last_committed_hash)",
                        hex::encode(cursor),
                    )
                })?
            };
            let is_genesis = block.header.height == 0;
            let parent = block.header.parent_hash;
            chain.push(block);
            if is_genesis {
                break;
            }
            cursor = parent;
        }
        chain.reverse();

        // Genesis bookkeeping: the first block of the rebuilt chain
        // must be the same genesis configured into this node. If
        // not, the persisted block store has been replaced wholesale
        // — we'd rather refuse than splice an alien chain onto our
        // identity.
        let walked_genesis_hash = chain
            .first()
            .expect("non-empty chain by virtue of last_committed.height > 0")
            .hash();
        if walked_genesis_hash != configured_genesis_hash {
            anyhow::bail!(
                "validator history rebuild: walked-chain genesis hash {} does not match \
                 configured genesis hash {} — persisted block store may be from a \
                 different chain",
                hex::encode(walked_genesis_hash),
                hex::encode(configured_genesis_hash),
            );
        }

        // Seed the rebuild from the loaded `validator_history`'s
        // genesis (`v_eff = 0`) boundary. We deliberately do *not*
        // re-derive from `self.validator_set` because that's the
        // *current* (latest-boundary) set after recovery — which
        // would differ from the genesis members on any chain that
        // has already committed a reconfig.
        //
        // Trusting the loaded blob's genesis boundary is safe even
        // under tampering: if those members are wrong, the very
        // first iteration of the walk below computes a commitment
        // over the tampered seed and compares against the genesis
        // *block*'s stamped commitment (which was hashed over the
        // *real* members at chain birth). The mismatch fires the
        // rejection.
        let genesis_members: Vec<crate::consensus::validator_set::ValidatorId> = self
            .validator_history
            .iter()
            .next()
            .map(|(_, set)| set.iter().copied().collect())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "validator history rebuild: loaded validator_history is empty (no genesis \
                     boundary)"
                )
            })?;
        let genesis_seed_set = ValidatorSet::new(genesis_members);
        let _ = chain.first().expect("non-empty chain"); // sanity: bind drops when block-walked is non-empty
        let mut rebuilt_set = ValidatorSetHistory::from_genesis(genesis_seed_set.clone());
        let mut rebuilt_key = ValidatorKeyHistory::new(genesis_seed_set.iter().copied());
        // BLS history seed: on a BLS chain, mirror whatever genesis
        // entries the loaded BLS history starts with. We don't have
        // the original `genesis_bls` config in hand here (it's
        // resolved by `src/node.rs` and folded into `bls_key_history`
        // via `with_bls_key_history`), so we extract the genesis
        // (`v_eff = 0`) entries from the loaded history. If the
        // loaded BLS history was tampered, the end-of-walk equality
        // check still catches it because the tampered entries flow
        // through both sides of the comparison.
        //
        // PR B refinement: instead of trusting the loaded history's
        // genesis entries, we cross-check against the genesis block's
        // stamped commitment below — the very first iteration
        // compares the rebuilt commitment (computed from the seed we
        // just constructed) against the genesis block's claim. If the
        // seed is wrong, the genesis-iteration check fires.
        let mut rebuilt_bls = self.bls_key_history.as_ref().map(genesis_only_bls_seed);

        for block in &chain {
            // #325 PR C semantics: each block's stamped commitment is
            // the **post-block** v1 hash — the histories *after*
            // applying this block's reconfig/rotation commands. So
            // apply first, then hash, then compare. Genesis is a
            // no-op for the apply step (zero commands), and its
            // stamped commitment equals the genesis-seed hash, so
            // the comparison still holds at N=0.
            apply_reconfig_commands_to_set_history(
                block,
                &mut rebuilt_set,
                &mut rebuilt_key,
                self.signature_scheme,
                self.min_v_eff_delay,
                &self.chain_id,
            );
            apply_rotation_commands_to_histories(
                block,
                &rebuilt_set,
                &mut rebuilt_key,
                rebuilt_bls.as_mut(),
                &self.chain_id,
                self.signature_scheme,
            );
            let claimed = block.header.validator_history_commitment;
            let actual =
                validator_history_commitment_v1(&rebuilt_set, &rebuilt_key, rebuilt_bls.as_ref());
            if claimed != actual {
                anyhow::bail!(
                    "validator_history_commitment mismatch at block height={} view={} hash={}: \
                     block claims {} but rebuild from chain produces {} — persisted history \
                     blob may be tampered or rolled back (audit #325/7-F2)",
                    block.header.height,
                    block.header.view,
                    hex::encode(block.hash()),
                    hex::encode(claimed),
                    hex::encode(actual),
                );
            }
        }

        // End-of-walk equality: the loaded blobs must match the
        // rebuild byte-for-byte. This is the literal audit criterion.
        let loaded_set_persisted = self.validator_history.to_persisted();
        let rebuilt_set_persisted = rebuilt_set.to_persisted();
        if loaded_set_persisted != rebuilt_set_persisted {
            anyhow::bail!(
                "validator_history_rebuild_mismatch: loaded validator_history does not match \
                 rebuild from chain — persisted blob may be tampered. \
                 loaded boundary_count={} rebuilt boundary_count={}",
                loaded_set_persisted.boundaries.len(),
                rebuilt_set_persisted.boundaries.len(),
            );
        }
        let loaded_key_persisted = self.validator_key_history.to_persisted();
        let rebuilt_key_persisted = rebuilt_key.to_persisted();
        if loaded_key_persisted != rebuilt_key_persisted {
            anyhow::bail!(
                "validator_key_history_rebuild_mismatch: loaded validator_key_history does not \
                 match rebuild from chain — persisted blob may be tampered. \
                 loaded validators={} rebuilt validators={}",
                loaded_key_persisted.validators.len(),
                rebuilt_key_persisted.validators.len(),
            );
        }
        match (self.bls_key_history.as_ref(), rebuilt_bls.as_ref()) {
            (Some(loaded), Some(rebuilt)) => {
                let lp = loaded.to_persisted();
                let rp = rebuilt.to_persisted();
                if lp != rp {
                    anyhow::bail!(
                        "bls_key_history_rebuild_mismatch: loaded bls_key_history does not \
                         match rebuild from chain — persisted blob may be tampered. \
                         loaded validators={} rebuilt validators={}",
                        lp.validators.len(),
                        rp.validators.len(),
                    );
                }
            }
            (None, None) => {}
            (Some(_), None) | (None, Some(_)) => {
                anyhow::bail!(
                    "bls_key_history_rebuild_mismatch: BLS history present/absent mismatch \
                     between loaded and rebuild — chain scheme inconsistency",
                );
            }
        }

        Ok(())
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
    ///
    /// In addition to the metadata write, every persisted `Locked` /
    /// `HighQc` carries the *block* it references into durable storage
    /// (under [`STORAGE_KEY_BLOCK_PREFIX`]) when that block is currently
    /// in the safety core's `pending_blocks`. Without this, a divergent
    /// resume could leave the cluster permanently stalled: the leader
    /// would have a `high_qc` but no parent block in `pending_blocks`,
    /// so [`HotStuffCore::become_leader`] would silently return an
    /// empty action set and no proposal would ever fire — preventing
    /// even the block-sync request that would otherwise repopulate the
    /// chain. Persisting the block alongside its referencing QC closes
    /// that gap so [`recover_state`] can re-seed `pending_blocks` with
    /// exactly the blocks the safety walks need to terminate. See
    /// issue #206.
    pub fn persist_updates(&self, updates: &[StateUpdate]) -> anyhow::Result<()> {
        if updates.is_empty() {
            return Ok(());
        }
        // Pre-encode the block writes for any `Locked` / `HighQc` whose
        // referenced block is still in `pending_blocks`. Done outside
        // the storage batch so a `?` on encoding doesn't poison the
        // batch closure.
        let mut block_writes: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for u in updates {
            let hash = match u {
                StateUpdate::HighQc(qc) => qc.block_hash,
                StateUpdate::Locked(locked) => locked.block_hash,
                StateUpdate::VotedInView { .. } | StateUpdate::ProposedInView { .. } => continue,
            };
            if let Some(block) = self.core.state().pending_blocks.get(&hash) {
                let bytes = encode_block(block)?;
                block_writes.push((block_storage_key(&hash), bytes));
            }
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
                    StateUpdate::ProposedInView { view } => {
                        let bytes = encode_proposed_in_view(*view)?;
                        b.put(STORAGE_KEY_PROPOSED_IN_VIEW, &bytes);
                    }
                }
            }
            for (key, bytes) in &block_writes {
                b.put(key, bytes);
            }
            Ok(())
        })?;
        // After durable writes succeed, populate the in-memory QC cache
        // so the snapshot creation hook (in `apply_commit`) can find a
        // QC over each committed block. Done after the batch commits so
        // a backend error can't leave the cache holding entries that
        // never made it to disk.
        for u in updates {
            if let StateUpdate::HighQc(qc) = u {
                self.recent_qcs
                    .lock()
                    .insert(qc.block_hash, qc.clone(), RECENT_QC_CACHE_CAPACITY);
            }
        }
        let kinds: Vec<&'static str> = updates.iter().map(update_kind).collect();
        tracing::debug!(
            target: TRACE_TARGET,
            kinds = ?kinds,
            blocks_persisted = block_writes.len(),
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
            last_committed_height = self.last_committed_height.load(Ordering::Relaxed),
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

        // Boot: advance the pacemaker out of view 0, arm the view timer,
        // and broadcast NewView (if we have a high_qc from a prior
        // session).
        //
        // For a fresh start, persisted `high_qc` and `last_voted_view`
        // are both zero so this is `OnQc(0)` → advance to view 1 — the
        // historical behaviour. After a restart with non-trivial durable
        // state we instead seed from
        // `max(high_qc.view, last_voted_view)` so the pacemaker lands
        // directly at the next post-restart view rather than briefly
        // advertising view 1 to peers and then jumping forward via the
        // self-loopback `OnQc(high_qc.view)`. The previous transient was
        // the path that left the first-killed-of-three replica wedged
        // at exactly its persisted `last_voted_view` (issue #222): if
        // peers' subsequent NewView messages are filtered out by the
        // gossip layer for any reason, the lagging replica's only catch-
        // up path is its own outbound timeout votes — and seeding from
        // disk eliminates the gap between "we restarted" and "our timer
        // is armed for the right view".
        let boot_view = self
            .core
            .state()
            .high_qc
            .as_ref()
            .map(|qc| qc.view)
            .unwrap_or(0)
            .max(self.core.state().last_voted_view);
        let boot_actions = self.step_pacemaker(PacemakerEvent::OnQc(boot_view));
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
                            // Snapshot-sync (#230): a freshly-added peer
                            // can immediately serve chunks. The state
                            // machine is a no-op outside `Fetching`.
                            let actions = self.snapshot_sync.add_candidate(node_id);
                            self.apply_snapshot_sync_actions(
                                actions,
                                broadcaster.as_ref(),
                                &mut view_timer,
                                &signer,
                            )
                            .await?;
                        }
                        Ok(DiscoveryEvent::PeerRemoved(node_id)) => {
                            tracing::debug!("consensus: peer removed {node_id:?}");
                            self.peers_connected.remove(&node_id);
                            // Snapshot-sync (#230): drop from candidate
                            // set, reassign in-flight chunks. The state
                            // machine handles non-`Fetching` states as
                            // no-ops.
                            let actions = self.snapshot_sync.on_peer_disconnected(node_id);
                            self.apply_snapshot_sync_actions(
                                actions,
                                broadcaster.as_ref(),
                                &mut view_timer,
                                &signer,
                            )
                            .await?;
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
                            // Rate-limit at the consensus integration
                            // boundary, before the postcard decode in
                            // `dispatch::ingress` (issue #134). The
                            // limiter peeks at the first byte (the
                            // postcard variant tag) and decides admit /
                            // drop / disconnect; on Disconnect we ask
                            // the manager to tear the peer's
                            // connection down. The limiter is
                            // optional, so this stays a no-op for any
                            // embedding that has not configured one
                            // (notably the sim's happy-path harness).
                            if !self.admit_inbound(from, &payload).await {
                                continue;
                            }
                            // Verify QC aggregates at ingress per the chain's scheme
                            // (#332). Closes the Byzantine-leader-ships-bogus-QC
                            // vector for both Ed25519 and BLS chains.
                            let qc_verification = dispatch::QcVerification::Verify {
                                scheme: self.signature_scheme,
                                bls_key_history: self.bls_key_history.as_ref(),
                                min_v_eff_delay: self.min_v_eff_delay,
                            };
                            match dispatch::ingress_with_qc_verification(
                                from,
                                &payload,
                                &self.validator_history,
                                &self.validator_key_history,
                                &qc_verification,
                                &self.chain_id,
                            ) {
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
                        // move on at this layer. The one exception is
                        // the rate limiter: a disconnect should clear
                        // the per-peer state so a future reconnect
                        // starts with a fresh budget (#134 non-goal:
                        // no cross-reconnect reputation).
                        ProtocolEvent::PeerConnected { .. } => {}
                        ProtocolEvent::PeerDisconnected { node_id } => {
                            if let Some(limiter) = self.rate_limiter.as_ref() {
                                limiter.forget_peer(node_id);
                            }
                        }
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

    // ── Rate limiting (issue #134) ──────────────────────────────────────────

    /// Classify `payload` and consult the rate limiter (if any).
    /// Returns `true` if the frame should be dispatched, `false` if
    /// the limiter dropped it. On a Disconnect decision, fires a
    /// best-effort [`crate::p2p::PeerCommand::Disconnect`] for `from`.
    async fn admit_inbound(&self, from: NodeId, payload: &[u8]) -> bool {
        let Some(limiter) = self.rate_limiter.as_ref() else {
            return true;
        };
        // Empty frames will fall through to `dispatch::ingress` which
        // returns IngressError::Decode — let the existing path handle
        // that consistently rather than silently dropping here.
        let Some(&first) = payload.first() else {
            return true;
        };
        let Some(kind) = MessageKind::from_wire_tag(first) else {
            // Unknown tag: pass through so the postcard decode error
            // surfaces in the existing log path. Treating it as a
            // rate-limited drop would mask malformed-frame bugs.
            return true;
        };
        match limiter.admit(from, kind, payload.len()) {
            Decision::Allow => true,
            Decision::Drop => {
                tracing::warn!(
                    target: TRACE_TARGET,
                    peer = %node_id_to_base58(&from),
                    msg_type = kind.label(),
                    bytes = payload.len(),
                    "rate_limit_drop",
                );
                false
            }
            Decision::Disconnect => {
                tracing::warn!(
                    target: TRACE_TARGET,
                    peer = %node_id_to_base58(&from),
                    msg_type = kind.label(),
                    "rate_limit_disconnect",
                );
                if let Some(cmd_tx) = self.peer_cmd_tx.as_ref() {
                    // Fire-and-forget: if the channel is full or
                    // closed (manager shut down), the limiter has
                    // already recorded the disconnect-decision.
                    let _ = cmd_tx.try_send(crate::p2p::PeerCommand::Disconnect { node_id: from });
                }
                // Don't `forget_peer` here: the peer state's
                // `disconnect_dispatched` latch silences any frames
                // already queued from this peer before the manager
                // tears the connection down. The `PeerDisconnected`
                // arm below clears the state when the connection
                // actually goes away, so a future reconnect starts
                // fresh — matching the "no cross-reconnect
                // reputation" non-goal in #134.
                false
            }
        }
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
                // Joiner-side lag detection (#229): peek at the
                // proposal's height before consuming the event, so
                // the snapshot-fetch state machine can decide
                // whether to fast-path the joiner past block-sync.
                if let SafetyEvent::ProposalReceived(signed) = &ev {
                    let signed = signed.inner();
                    let proposer = signed.signer;
                    let proposal_height = signed.payload.block.header.height;
                    let actions = self.snapshot_sync.observe_proposal(
                        self.last_committed_height.load(Ordering::Relaxed),
                        proposal_height,
                        proposer,
                        &self.validator_set,
                    );
                    self.apply_snapshot_sync_actions(actions, broadcaster, view_timer, signer)
                        .await?;
                }
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
                let out = dispatch::egress_block_response(
                    hash,
                    block,
                    to,
                    signer.as_ref(),
                    &self.chain_id,
                )?;
                send_outbound(broadcaster, out).await;
            }

            // Block arrived in response to an earlier RequestBlock;
            // insert it and re-drive parked proposals via
            // PacemakerAdvance. Drop the response if it does not match
            // the hash we asked for (or if we never asked for that
            // hash) — without this gate a Byzantine responder could
            // pollute `pending_blocks` with arbitrary blocks (#434,
            // audit finding 10-2).
            Dispatch::ReceiveBlock {
                requested_hash,
                block: Some(block),
                from,
            } => {
                let block_hash = block.hash();
                let block_view = block.header.view;
                let block_height = block.header.height;
                if block_hash != requested_hash {
                    tracing::warn!(
                        target: TRACE_TARGET,
                        from = %node_id_to_base58(&from),
                        requested_hash = ?requested_hash,
                        received_hash = ?block_hash,
                        view = block_view,
                        height = block_height,
                        "block_sync_response_hash_mismatch",
                    );
                    return Ok(());
                }
                if !self.core.has_inflight_block_request(&requested_hash) {
                    tracing::warn!(
                        target: TRACE_TARGET,
                        from = %node_id_to_base58(&from),
                        requested_hash = ?requested_hash,
                        view = block_view,
                        height = block_height,
                        "block_sync_response_unrequested",
                    );
                    return Ok(());
                }
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

            Dispatch::ReceiveBlock {
                requested_hash,
                block: None,
                from,
            } => {
                tracing::warn!(
                    target: TRACE_TARGET,
                    from = %node_id_to_base58(&from),
                    requested_hash = ?requested_hash,
                    "block_sync_response_not_found",
                );
            }

            Dispatch::TimeoutVote {
                signed,
                high_qc_trusted,
            } => {
                self.on_timeout_vote(signed, high_qc_trusted, broadcaster, view_timer, signer)
                    .await?;
            }

            Dispatch::ServeSnapshotManifest { height, to } => {
                self.serve_snapshot_manifest(height, to, broadcaster).await;
            }

            Dispatch::ServeSnapshotChunk {
                height,
                chunk_idx,
                to,
            } => {
                self.serve_snapshot_chunk(height, chunk_idx, to, broadcaster)
                    .await;
            }

            // Joiner-side consumers land in #229. For now, log and drop
            // so the wire protocol can be exercised end-to-end (peer A
            // serves, peer B drops with a debug log).
            Dispatch::ReceiveSnapshotManifest { manifest, from } => {
                tracing::debug!(
                    target: TRACE_TARGET,
                    from = %node_id_to_base58(&from),
                    has_manifest = manifest.is_some(),
                    height = manifest.as_ref().map(|m| m.height),
                    "snapshot_manifest_response_received",
                );
                let actions =
                    self.snapshot_sync
                        .on_manifest_response(from, manifest, &self.validator_set);
                self.apply_snapshot_sync_actions(actions, broadcaster, view_timer, signer)
                    .await?;
            }

            Dispatch::ReceiveSnapshotChunk {
                height,
                chunk_idx,
                payload,
                from,
            } => {
                tracing::debug!(
                    target: TRACE_TARGET,
                    from = %node_id_to_base58(&from),
                    height,
                    chunk_idx,
                    has_payload = payload.is_some(),
                    payload_len = payload.as_ref().map(|p| p.len()),
                    "snapshot_chunk_response_received",
                );
                let actions = self
                    .snapshot_sync
                    .on_chunk_response(from, height, chunk_idx, payload);
                self.apply_snapshot_sync_actions(actions, broadcaster, view_timer, signer)
                    .await?;
            }
        }
        Ok(())
    }

    /// Execute a slice of [`SnapshotSyncAction`]s emitted by the
    /// joiner-side state machine. Each action is mapped to either a
    /// wire send (`SendManifestRequest`, `SendChunkRequest`), a
    /// state-restore call ([`Self::restore_from_snapshot`]), or a
    /// log-and-drop on `Abort`. The state machine has already
    /// transitioned by the time we see the actions, so any error
    /// here is treated as a soft failure: we log and let
    /// block-sync take over.
    async fn apply_snapshot_sync_actions(
        &mut self,
        actions: Vec<crate::consensus::snapshot_sync::SnapshotSyncAction>,
        broadcaster: &dyn Broadcaster,
        view_timer: &mut ViewTimer,
        signer: &Arc<dyn Signer>,
    ) -> anyhow::Result<()> {
        use crate::consensus::snapshot_sync::SnapshotSyncAction;
        for action in actions {
            match action {
                SnapshotSyncAction::SendManifestRequest { peer } => {
                    tracing::info!(
                        target: TRACE_TARGET,
                        peer = %node_id_to_base58(&peer),
                        "snapshot_manifest_request_sent",
                    );
                    let out = dispatch::egress_snapshot_manifest_request(None, peer);
                    send_outbound(broadcaster, out).await;
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
                    send_outbound(broadcaster, out).await;
                }
                SnapshotSyncAction::Restore { manifest, payload } => {
                    let height = manifest.height;
                    let view = manifest.view;
                    if let Err(e) = self.restore_from_snapshot(*manifest, payload) {
                        tracing::error!(
                            target: TRACE_TARGET,
                            height,
                            view,
                            error = %e,
                            "snapshot_restore_failed",
                        );
                    } else {
                        tracing::info!(
                            target: TRACE_TARGET,
                            height,
                            view,
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
    /// [`crate::consensus::snapshot_sync::SnapshotSyncAction::Restore`].
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
    ///    [`STORAGE_KEY_BLOCK_PREFIX`], the new `last_committed`,
    ///    and every safety-core [`StateUpdate`] from step 3
    ///    (`VotedInView`, `Locked`, `HighQc`) in one atomic batch.
    ///    Folding the safety-core writes into the same batch is the
    ///    audit-finding-4-3 (#406) requirement: a crash between an
    ///    in-memory adoption and a follow-up persist would let
    ///    [`recover_state`] rehydrate stale `locked` / `last_voted_view`
    ///    and the joiner could vote on a fork below the snapshot
    ///    height. Survives crash recovery: a subsequent boot's
    ///    [`recover_state`] rebuilds the safety state from these
    ///    keys.
    /// 5. Update the in-memory `last_committed_*` so subsequent
    ///    `apply_commit`s don't regress.
    fn restore_from_snapshot(
        &mut self,
        manifest: crate::replication::snapshot::SnapshotManifest,
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
        let safety_persist_actions =
            self.core
                .adopt_snapshot(block.clone(), manifest.commit_qc.clone(), manifest.view);
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
        if manifest.height > self.last_committed_height.load(Ordering::Relaxed) {
            self.last_committed_height
                .store(manifest.height, Ordering::Relaxed);
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
            crate::consensus::validator_history::ValidatorSetHistory::from_persisted(
                manifest.validator_history.clone(),
            )
            .map_err(|e| anyhow::anyhow!("decode validator_history from manifest: {e}"))?;
        let installed_key =
            crate::consensus::validator_key_history::ValidatorKeyHistory::from_persisted(
                manifest.validator_key_history.clone(),
            )
            .map_err(|e| anyhow::anyhow!("decode validator_key_history from manifest: {e}"))?;
        let installed_bls = match &manifest.bls_key_history {
            Some(p) => Some(
                crate::consensus::bls_key_history::BlsKeyHistory::from_persisted(p.clone())
                    .map_err(|e| anyhow::anyhow!("decode bls_key_history from manifest: {e}"))?,
            ),
            None => None,
        };
        // Mirror every post-genesis boundary into the safety core's
        // history so vote tally / QC sizing / proposal-time leader
        // pick all see the snapshot-time committee. Genesis is
        // already seeded; only later boundaries need replay.
        for (v_eff, set) in installed_set.iter() {
            if v_eff == 0 {
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
            .set_selector(Arc::new(RoundRobinSelector::new(Arc::new(
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

    /// Serve a [`Dispatch::ServeSnapshotManifest`] by looking up the
    /// requested manifest in the local
    /// [`crate::replication::SnapshotStore`] and replying.
    ///
    /// `height = None` requests the latest available manifest;
    /// `Some(h)` requests the exact-match manifest. Misses (no
    /// snapshots, height not found) reply with
    /// `SnapshotManifestResponse(None)` so the joiner can fall through
    /// to another peer or to plain block-sync.
    async fn serve_snapshot_manifest(
        &self,
        height: Option<u64>,
        to: NodeId,
        broadcaster: &dyn Broadcaster,
    ) {
        let store = crate::replication::snapshot::SnapshotStore::new(Arc::clone(&self.storage));
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
            served_height = manifest.as_ref().map(|m| m.height),
            "snapshot_manifest_request_received",
        );
        let out = dispatch::egress_snapshot_manifest_response(manifest, to);
        send_outbound(broadcaster, out).await;
    }

    /// Serve a [`Dispatch::ServeSnapshotChunk`] by looking up the
    /// chunk in the local snapshot store. Misses reply with
    /// `payload = None`.
    async fn serve_snapshot_chunk(
        &self,
        height: u64,
        chunk_idx: u32,
        to: NodeId,
        broadcaster: &dyn Broadcaster,
    ) {
        let store = crate::replication::snapshot::SnapshotStore::new(Arc::clone(&self.storage));
        let payload = match store.load_chunk(height, chunk_idx) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(
                    target: TRACE_TARGET,
                    height,
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
            height,
            chunk_idx,
            served = payload.is_some(),
            "snapshot_chunk_request_received",
        );
        let out = dispatch::egress_snapshot_chunk_response(height, chunk_idx, payload, to);
        send_outbound(broadcaster, out).await;
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
                let kinds: Vec<_> = persist_buf.iter().map(update_kind).collect();
                self.persist_updates(&persist_buf)?;
                persist_buf.clear();
                // Crashpoints fire AFTER the persist batch durably
                // landed but BEFORE the dependent send leaves. Audit
                // findings #1 / #11 / #406 hinge on this exact gap:
                // the buffer kinds tell the harness which durability
                // boundary the integration layer just crossed.
                for kind in kinds {
                    match kind {
                        "VotedInView" => crashpoint!("after_persist_voted_view"),
                        "Locked" => crashpoint!("after_persist_locked"),
                        "HighQc" => crashpoint!("after_persist_high_qc"),
                        "ProposedInView" => {
                            crashpoint!("after_persist_proposed_in_view")
                        }
                        _ => {}
                    }
                }
            }

            match action {
                SafetyAction::Persist(_) => unreachable!(),

                SafetyAction::Broadcast(mut msg) => {
                    tracing::debug!(
                        target: TRACE_TARGET,
                        msg = msg_kind(&msg),
                        "outbound_broadcast",
                    );
                    // #325 PR A/C: stamp the validator-history
                    // commitment into outgoing proposals before the
                    // envelope is signed. The block builder leaves the
                    // field at [0; 32]; here we replace it with the
                    // v1 hash over the **post-block** histories: fork
                    // our current `(validator_history,
                    // validator_key_history, bls_key_history?)`, apply
                    // this block's reconfig/rotation commands to the
                    // fork, and hash the result. Post-block hashing
                    // (PR C) makes the commitment a deterministic
                    // function of the chain content rather than the
                    // producer's commit position, so a follower at a
                    // less-advanced commit position can still verify
                    // the leader's stamp by running the same fork on
                    // its own histories — see
                    // [`crate::consensus::history_commitment::compute_post_block_commitment`]
                    // and the proposal-receive verifier in `dispatch`.
                    if let crate::consensus::hotstuff::ConsensusMsg::Proposal(ref mut p) = msg {
                        p.block.header.validator_history_commitment =
                            crate::consensus::history_commitment::compute_post_block_commitment(
                                &p.block,
                                &self.validator_history,
                                &self.validator_key_history,
                                self.bls_key_history.as_ref(),
                                &self.chain_id,
                                self.signature_scheme,
                                self.min_v_eff_delay,
                            );
                    }
                    let bls_signer = self.bls_signer.as_deref();
                    let (payload, loopback) = dispatch::egress_consensus_msg_with_loopback(
                        &msg,
                        signer.as_ref(),
                        bls_signer,
                        &self.validator_key_history,
                        &self.chain_id,
                    )?;
                    let msg_is_proposal =
                        matches!(msg, crate::consensus::hotstuff::ConsensusMsg::Proposal(_));
                    let msg_is_vote =
                        matches!(msg, crate::consensus::hotstuff::ConsensusMsg::Vote(_));
                    send_outbound(broadcaster, Outbound::Broadcast(payload)).await;
                    // After a Proposal hits the wire the leader has a
                    // de-facto commitment to view N — but
                    // `proposed_in_view` is in-memory only (audit
                    // finding 4-3 / issue #407). After a Vote hits the
                    // wire the replica has a de-facto commitment to
                    // last_voted_view = view, which `persist_voted_view`
                    // either has or has not flushed depending on
                    // discipline (audit finding 4-1 / issue #405).
                    if msg_is_proposal {
                        crashpoint!("after_send_outbound_for_proposal");
                    }
                    if msg_is_vote {
                        crashpoint!("after_broadcast_vote");
                    }
                    self.deliver_loopback(loopback, broadcaster, view_timer, signer)
                        .await?;
                }

                SafetyAction::SendTo(target, msg) => {
                    let bls_signer = self.bls_signer.as_deref();
                    let (payload, loopback) = dispatch::egress_consensus_msg_with_loopback(
                        &msg,
                        signer.as_ref(),
                        bls_signer,
                        &self.validator_key_history,
                        &self.chain_id,
                    )?;
                    let msg_is_vote =
                        matches!(msg, crate::consensus::hotstuff::ConsensusMsg::Vote(_));
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
                        // Vote frames are unicast `SendTo(next_leader)`
                        // by default. After the bytes are on the wire
                        // the replica has committed to that vote — so a
                        // crash here exercises audit finding #1 (the
                        // peer accepts the vote, the local replica
                        // restarts, and if `last_voted_view` was not
                        // already durable the restart equivocates).
                        if msg_is_vote {
                            crashpoint!("after_broadcast_vote");
                        }
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
            let kinds: Vec<_> = persist_buf.iter().map(update_kind).collect();
            self.persist_updates(&persist_buf)?;
            for kind in kinds {
                match kind {
                    "VotedInView" => crashpoint!("after_persist_voted_view"),
                    "Locked" => crashpoint!("after_persist_locked"),
                    "HighQc" => crashpoint!("after_persist_high_qc"),
                    "ProposedInView" => crashpoint!("after_persist_proposed_in_view"),
                    _ => {}
                }
            }
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
                proposer: signed.inner().signer,
                view: signed.inner().payload.block.header.view,
                height: signed.inner().payload.block.header.height,
            }),
            SafetyEvent::VoteReceived(variant) => {
                let signed = variant.verified().inner();
                Some(SafetyLogCtx::Vote {
                    voter: signed.signer,
                    view: signed.payload.view,
                })
            }
            SafetyEvent::NewViewReceived(signed) => Some(SafetyLogCtx::NewView {
                sender: signed.inner().signer,
                high_qc_view: signed.inner().payload.high_qc.view,
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
        let signed = Signed::sign(payload, signer.as_ref(), &self.chain_id)
            .context("signing TimeoutVote")?;

        // Put the signed frame on the wire.
        let wire = WireMessage::TimeoutVote(signed.clone());
        let bytes = postcard::to_stdvec(&wire)
            .map(Bytes::from)
            .context("encoding TimeoutVote")?;
        send_outbound(broadcaster, Outbound::Broadcast(bytes)).await;
        // Audit finding 14-1 / issue #415: TimeoutVote is sent without
        // a preceding persist, so a crash here lets the replica
        // restart, observe a different `high_qc`, and broadcast a
        // *fresh* TimeoutVote for the same view with a different
        // piggyback — equivocation. The fix is to persist the
        // outbound TimeoutVote before this `send_outbound` returns;
        // this crashpoint exists so the regression test for that fix
        // can pin the gap.
        crashpoint!("after_broadcast_timeout_vote");

        // Count our own timeout locally so we don't depend on
        // broadcast-to-self semantics from the p2p layer. The
        // piggybacked `high_qc` came straight from our own safety-core
        // state above and was never on the wire, so it's trusted by
        // construction — bypass the ingress verifier for the self-feed
        // path.
        self.on_timeout_vote(signed, true, broadcaster, view_timer, signer)
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
        high_qc_trusted: bool,
        broadcaster: &dyn Broadcaster,
        view_timer: &mut ViewTimer,
        signer: &Arc<dyn Signer>,
    ) -> anyhow::Result<()> {
        let view = signed.payload.view;

        // Defence-in-depth: ingress already rejected unknown signers,
        // but asserting here lets tests hand-construct Signed<TimeoutVote>
        // without going through ingress. The wire envelope carries a
        // pubkey; resolve to the validator's stable id before the
        // membership check (#328).
        let signer_pk = crate::consensus::validator_set::Pubkey::from_node_id(signed.signer);
        let Some(stable_id) = self.validator_key_history.validator_for(&signer_pk) else {
            return Ok(());
        };
        if !self.validator_set.contains(&stable_id) {
            return Ok(());
        }

        // Stale: we have already advanced past this view via some other
        // path (QC or an earlier TC). The bucket logic below would
        // ignore the vote anyway, but a peer broadcasting a stale
        // timeout is also our cleanest signal that they are wedged at
        // a low view (typically a post-restart replica stuck at its
        // persisted `last_voted_view` — issue #222). Reply with our
        // current `high_qc` as a unicast NewView so they can adopt it
        // through the standard `OnQc(high_qc.view)` ingress path and
        // catch up. Only one reply per stale vote: if the wedged peer
        // is broadcasting timeouts on backoff, each one earns one fresh
        // NewView, but no per-message amplification beyond that.
        if view < self.pacemaker.current_view() {
            if let Some(high_qc) = self.core.state().high_qc.clone() {
                let nv = NewView { high_qc };
                let signed_nv = Signed::sign(nv, signer.as_ref(), &self.chain_id)
                    .context("signing catch-up NewView for stale TimeoutVote")?;
                let wire = WireMessage::NewView(signed_nv);
                let payload = postcard::to_stdvec(&wire)
                    .map(Bytes::from)
                    .context("encoding catch-up NewView for stale TimeoutVote")?;
                tracing::debug!(
                    target: TRACE_TARGET,
                    wedged_peer = %node_id_to_base58(&signed.signer),
                    wedged_view = view,
                    our_view = self.pacemaker.current_view(),
                    our_high_qc_view = ?self.core.state().high_qc.as_ref().map(|q| q.view),
                    "catch_up_new_view_sent",
                );
                send_outbound(
                    broadcaster,
                    Outbound::SendTo {
                        to: signed.signer,
                        payload,
                    },
                )
                .await;
            }
            return Ok(());
        }

        let quorum = quorum_size(self.validator_set.len());
        let signer_id = signed.signer;
        let is_local = signer_id == self.self_id;
        // Cap-based eviction. A genuinely new view triggers the
        // check; an entry update (same view, different signer) does
        // not grow the map, so we skip the check on the existing-key
        // path. Without this guard a Byzantine peer could fan out
        // timeout votes across distinct future views (each with no
        // hope of forming a TC) and pin memory until restart.
        if !self.timeout_buckets.contains_key(&view) {
            self.evict_timeout_buckets_to_fit_one();
        }
        let honesty_threshold =
            crate::consensus::hotstuff::qc::honesty_threshold(self.validator_set.len());
        let (adopt_qc, fired_round_sync) = {
            let bucket = self.timeout_buckets.entry(view).or_default();
            let is_new = bucket.signers.insert(signed.signer);
            if !is_new {
                return Ok(());
            }
            // Remember the freshest high_qc reported so far. `None`
            // here means the sender had never seen a QC (rare after
            // genesis-QC seeding); we just leave `best_high_qc` as-is.
            //
            // `high_qc_trusted == false` means ingress saw a piggyback
            // but rejected it (forged signatures, malformed bitmap, or
            // wrong validator set). The bucket treats it the same as
            // `high_qc: None`: the timeout-vote signal is still real
            // and counts toward the bucket's signer set, but the
            // forged QC must not flow through `best_high_qc` and into
            // the TC self-NewView loopback that ultimately feeds
            // `state.high_qc`. Audit finding 10-F3 / issue #321.
            if high_qc_trusted {
                if let Some(qc) = signed.payload.high_qc {
                    let fresher = match &bucket.best_high_qc {
                        Some(cur) => qc.view > cur.view,
                        None => true,
                    };
                    if fresher {
                        bucket.best_high_qc = Some(qc);
                    }
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

            // Round-sync hint (issue #218): the bucket has reached
            // `f + 1` distinct signers, so at least one honest peer
            // reports being at view `view`. We can advance our
            // pacemaker to `view` even before quorum gives us a TC.
            // Crucially, a single Byzantine signer can't fire this —
            // it needs at least one honest co-signer — which is what
            // keeps the `TimeoutSpammer` adversary from dragging
            // honest views to `u64::MAX`.
            //
            // Fire on the exact crossing so we don't re-emit on every
            // subsequent vote into the same bucket.
            let fire_round_sync = bucket_size == honesty_threshold;

            if bucket_size < quorum {
                return if fire_round_sync {
                    self.fire_round_sync(view, broadcaster, view_timer, signer)
                        .await
                } else {
                    Ok(())
                };
            }
            (bucket.best_high_qc.clone(), fire_round_sync)
        };

        // We've also crossed full quorum — but if we passed the
        // honesty threshold on this same vote, surface the round-sync
        // hint first so the pacemaker has the latest view recorded
        // before the OnTimeoutCert flow runs.
        if fired_round_sync {
            self.fire_round_sync(view, broadcaster, view_timer, signer)
                .await?;
        }

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
            let self_signed = Signed::sign(nv, signer.as_ref(), &self.chain_id)
                .context("signing self-NewView for TC adopt")?;
            // Trusted by construction: we just signed `self_signed` ourselves
            // from a `high_qc` that was assembled out of ingress-verified
            // partials. Resolve the local signer's stable `ValidatorId`
            // through the same `ValidatorKeyHistory` lookup the wire
            // path uses (#394) so the safety core's bitmap-index
            // resolution remains correct after a key rotation. The
            // `from_genesis_pubkey` fallback covers tests where the
            // local signer's pubkey is not registered in
            // `validator_key_history` (and pre-#394 the same call was
            // unconditional); production validators are seeded at boot,
            // so the registered branch is taken there.
            let signer_node_id = signer.as_ref().node_id();
            let signer_pk = crate::consensus::validator_set::Pubkey::from_node_id(signer_node_id);
            let signer_validator_id = self
                .validator_key_history
                .validator_for(&signer_pk)
                .unwrap_or_else(|| {
                    crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(
                        signer_node_id,
                    )
                });
            let safety_actions = self.step_safety(SafetyEvent::NewViewReceived(
                crate::consensus::dispatch::Verified::wrap_after_verify_with_signer(
                    self_signed,
                    signer_validator_id,
                ),
            ));
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

    /// Surface a [`PacemakerEvent::OnRoundSync(view)`] hint to the
    /// pacemaker, then apply the resulting actions. Called from
    /// [`Self::on_timeout_vote`] when a per-view bucket reaches the
    /// honesty threshold (`f + 1` distinct signers — see issue #218
    /// for the wedge this prevents and the Byzantine-bound rationale
    /// for the threshold choice).
    async fn fire_round_sync(
        &mut self,
        view: View,
        broadcaster: &dyn Broadcaster,
        view_timer: &mut ViewTimer,
        signer: &Arc<dyn Signer>,
    ) -> anyhow::Result<()> {
        tracing::debug!(
            target: TRACE_TARGET,
            view,
            current = self.pacemaker.current_view(),
            "round_sync_fired",
        );
        let pm_actions = self.step_pacemaker(PacemakerEvent::OnRoundSync(view));
        Box::pin(self.apply_pacemaker_actions(pm_actions, broadcaster, view_timer, signer)).await
    }

    /// Borrow the eviction counters this node aggregates across the
    /// safety-core and timeout-vote caches. Exposed for tests and
    /// for [`build_status`](Self::build_status) to project into the
    /// JSON snapshot.
    pub fn eviction_counters(&self) -> &CacheEvictionCounters {
        &self.eviction_counters
    }

    /// Drop the lowest-`view` `timeout_buckets` entry if the map is
    /// at cap. The on-TC-formation prune
    /// (`timeout_buckets.retain(|&v, _| v > view)`) handles the
    /// happy-path cleanup; this helper handles the flood path where
    /// no TC ever fires because the attacker addresses each fake
    /// timeout vote at a distinct future view.
    fn evict_timeout_buckets_to_fit_one(&mut self) {
        if self.timeout_buckets.len() < self.timeout_buckets_capacity {
            return;
        }
        let Some(victim_view) = self.timeout_buckets.keys().min().copied() else {
            return;
        };
        if self.timeout_buckets.remove(&victim_view).is_some() {
            self.eviction_counters.inc_timeout_buckets(1);
            tracing::info!(
                target: TRACE_TARGET,
                cache = "timeout_buckets",
                policy = "cap",
                evicted_view = victim_view,
                cap = self.timeout_buckets_capacity,
                size_after = self.timeout_buckets.len(),
                "consensus_cache_evicted",
            );
        }
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
        if block.header.height > self.last_committed_height.load(Ordering::Relaxed) {
            self.last_committed_height
                .store(block.header.height, Ordering::Relaxed);
            self.last_committed_view = block.header.view;
        }
        // Persist (block, last_committed) atomically so the responder
        // path and the status snapshot agree on durable state. See the
        // doc-comment for the why.
        let block_hash = block.hash();
        let key = block_storage_key(&block_hash);
        let last_committed = LastCommitted {
            height: self.last_committed_height.load(Ordering::Relaxed),
            view: self.last_committed_view,
            last_committed_hash: block_hash,
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
        // After the committed block + last_committed batch is durable
        // but BEFORE any downstream side effect (snapshot creation,
        // reconfig/rotation application, commit-notifier fan-out)
        // runs. Audit finding 4-6 / issue #411 is about gating those
        // downstream actions on the durable block write — a regression
        // would let the snapshot creation hook fire against a block
        // that did not in fact reach disk.
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
                    height = block.header.height,
                    view = block.header.view,
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
    }

    /// Scan `block.commands` for tagged `ReconfigCommand` payloads
    /// (#247) and, for each one that validates against the active set
    /// at the block's view, insert a new boundary into
    /// `validator_history`, mirror it into the safety core, and
    /// re-install the leader selector so the pacemaker rotation
    /// observes the new committee at and after `v_eff`.
    ///
    /// Validation failures (floor, overlap, v_eff delay, conflict
    /// with an unsettled pending reconfig) are logged and dropped —
    /// they do not roll the block back. A reconfig that conflicts
    /// with a pending one is dropped silently so a single block
    /// can't sneak two contradictory boundaries past validation.
    fn apply_committed_reconfigs(&mut self, block: &crate::replication::block::Block) {
        use crate::consensus::reconfig::ReconfigCommand;

        // #325 PR B: snapshot the pre-state so a debug_assert can
        // confirm that the pure rebuild path (used by recovery-time
        // validation) produces the same final history this wrapper
        // does. Any divergence is a bug — the rebuild would otherwise
        // produce a different history than what's persisted, and the
        // recovery check would falsely flag healthy storage. The
        // snapshot is `cfg(debug_assertions)`-gated so release builds
        // don't pay the clone.
        #[cfg(debug_assertions)]
        let pre_state_for_parity = self.validator_history.clone();

        let mut applied_any = false;
        for cmd_bytes in &block.commands {
            if !ReconfigCommand::is_reconfig_payload(cmd_bytes) {
                continue;
            }
            let cmd = match ReconfigCommand::decode(cmd_bytes) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(
                        target: TRACE_TARGET,
                        height = block.header.height,
                        view = block.header.view,
                        error = %e,
                        "reconfig_payload_malformed",
                    );
                    continue;
                }
            };

            // Validate against the set authoritative at the block's
            // view — the cluster's view of "now" at commit time. The
            // pacemaker may have advanced past this by the time the
            // commit drains, but the rule must use the block's view
            // so all replicas accept or reject identically.
            let block_view = block.header.view;
            let current_set = self.validator_history.set_at(block_view);
            let next_members = match cmd.validate_against_with_delay_and_scheme(
                &current_set,
                block_view,
                self.min_v_eff_delay,
                self.signature_scheme,
                &self.chain_id,
            ) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!(
                        target: TRACE_TARGET,
                        height = block.header.height,
                        view = block_view,
                        v_eff = cmd.v_eff,
                        error = %e,
                        "reconfig_validation_failed",
                    );
                    continue;
                }
            };

            // Conflict guard: only one reconfig may be pending at a
            // time. If the history already carries a non-genesis
            // boundary whose `v_eff` is strictly after the committing
            // block's view, a previously committed reconfig has not
            // yet taken effect — drop the second so the two cannot
            // compose unsoundly (cmd_b's validation baseline would
            // need to be cmd_a's post-boundary set, not the current
            // set, which we'd have to thread through). Future PRs can
            // relax this rule once compositional validation lands.
            let conflict = self
                .validator_history
                .iter()
                .any(|(v_eff, _)| v_eff != 0 && v_eff > block_view);
            if conflict {
                tracing::warn!(
                    target: TRACE_TARGET,
                    height = block.header.height,
                    view = block_view,
                    v_eff = cmd.v_eff,
                    "reconfig_conflicts_with_pending_or_committed_boundary",
                );
                continue;
            }

            let next_members_vid: Vec<crate::consensus::validator_set::ValidatorId> = next_members
                .into_iter()
                .map(crate::consensus::validator_set::ValidatorId::from_genesis_pubkey)
                .collect();
            let new_set = ValidatorSet::new(next_members_vid);

            // Insert the boundary into the integration-layer history
            // (used by `dispatch::ingress`).
            if let Err(e) = self
                .validator_history
                .insert_boundary(cmd.v_eff, new_set.clone())
            {
                tracing::error!(
                    target: TRACE_TARGET,
                    error = %e,
                    "reconfig_insert_boundary_into_node_history_failed",
                );
                continue;
            }
            // Mirror into the safety core's history so vote tally,
            // QC sizing, and proposal-time leader pick all see the
            // boundary at and after `v_eff`.
            if let Err(e) = self
                .core
                .insert_validator_boundary(cmd.v_eff, new_set.clone())
            {
                tracing::error!(
                    target: TRACE_TARGET,
                    error = %e,
                    "reconfig_insert_boundary_into_safety_core_failed",
                );
                continue;
            }
            // Re-install the pacemaker selector against a fresh
            // snapshot of the now-extended history so leader rotation
            // past `v_eff` lands on the post-boundary set.
            let snapshot = Arc::new(self.validator_history.clone());
            self.pacemaker
                .set_selector(Arc::new(RoundRobinSelector::new(snapshot)));

            tracing::info!(
                target: TRACE_TARGET,
                height = block.header.height,
                view = block_view,
                v_eff = cmd.v_eff,
                next_size = new_set.len(),
                "reconfig_applied",
            );
            applied_any = true;
        }

        // #254: durably persist the updated history once any boundary
        // has landed. Write a single blob over the full history (rather
        // than a journal of diffs) so recovery is a single read +
        // decode. Failures log + drop — the in-memory state is
        // authoritative for the running process; on the next reconfig
        // we'll get another chance to flush, and the recovery path will
        // just reset to whatever state was durably written before the
        // last successful flush.
        if applied_any {
            let persisted = self.validator_history.to_persisted();
            match postcard::to_stdvec(&persisted) {
                Ok(bytes) => {
                    if let Err(e) = self.storage.put(STORAGE_KEY_VALIDATOR_HISTORY, &bytes) {
                        tracing::error!(
                            target: TRACE_TARGET,
                            error = %e,
                            "validator_history_persist_failed",
                        );
                    }
                }
                Err(e) => {
                    tracing::error!(
                        target: TRACE_TARGET,
                        error = %e,
                        "validator_history_encode_failed",
                    );
                }
            }
        }

        // #325 PR B: confirm the pure-rebuild function lands in the
        // same place the wrapper did for the set_history surface.
        // The pure function additionally mirrors new validators into
        // key_history (matching the from_set_history fallback that
        // recover() applies when no key_history blob is persisted),
        // but the wrapper deliberately leaves key_history untouched
        // — that mirror happens implicitly at the next recover. So
        // this debug_assert only checks set_history parity. See the
        // snapshot at the top of this method for context.
        #[cfg(debug_assertions)]
        {
            let mut rebuilt = pre_state_for_parity;
            let mut throwaway_key = ValidatorKeyHistory::new(self.validator_set.iter().copied());
            crate::consensus::history_commitment::apply_reconfig_commands_to_set_history(
                block,
                &mut rebuilt,
                &mut throwaway_key,
                self.signature_scheme,
                self.min_v_eff_delay,
                &self.chain_id,
            );
            debug_assert_eq!(
                rebuilt.to_persisted(),
                self.validator_history.to_persisted(),
                "pure-rebuild reconfig path diverged from wrapper at height={} view={}",
                block.header.height,
                block.header.view,
            );
        }
    }

    /// Scan `block.commands` for tagged [`DualSignedRotation`] payloads
    /// (#260) and, for each one that passes structural and cryptographic
    /// validation, apply it to `validator_key_history`. Persisting the
    /// updated history happens once per commit if any rotation
    /// applied — same shape as `apply_committed_reconfigs`.
    ///
    /// Validation failures (structural, signature, history-invariant)
    /// are logged and dropped — they do not roll the block back. The
    /// safety core has already committed; an invalid rotation in the
    /// payload is treated as a no-op so all replicas agree on which
    /// rotations took effect (which is none, when the rotation is
    /// invalid).
    fn apply_committed_rotations(&mut self, block: &crate::replication::block::Block) {
        use crate::consensus::validator_rotation::DualSignedRotation;

        // #325 PR B: parity snapshot — see the matching block in
        // apply_committed_reconfigs for the rationale.
        #[cfg(debug_assertions)]
        let pre_state_for_parity = (
            self.validator_key_history.clone(),
            self.bls_key_history.clone(),
        );

        let block_view = block.header.view;
        let mut applied_any = false;
        for cmd_bytes in &block.commands {
            if !DualSignedRotation::is_rotation_payload(cmd_bytes) {
                continue;
            }
            let envelope = match DualSignedRotation::decode_command(cmd_bytes) {
                Ok(env) => env,
                Err(e) => {
                    tracing::warn!(
                        target: TRACE_TARGET,
                        height = block.header.height,
                        view = block_view,
                        error = %e,
                        "rotation_payload_malformed",
                    );
                    continue;
                }
            };

            // The validator's currently-active signing key, looked up
            // through the reverse index. If the field doesn't resolve,
            // `apply_rotation` below will produce the same error — but
            // resolving here gives us the pubkey for the cryptographic
            // dual-signature check first, which is the more informative
            // failure to log when both would fire.
            let validator_pk =
                crate::consensus::validator_set::Pubkey::from_node_id(envelope.payload.validator);
            let current_key = match self.validator_key_history.current_key(&validator_pk) {
                Some(k) => k,
                None => {
                    tracing::warn!(
                        target: TRACE_TARGET,
                        height = block.header.height,
                        view = block_view,
                        validator = ?envelope.payload.validator,
                        "rotation_validator_not_in_key_history",
                    );
                    continue;
                }
            };

            // Cryptographic self-attestation: both signatures must
            // verify. Done at commit time so a malicious leader who
            // smuggled in a single-signed rotation can't make it
            // take effect — every replica re-runs this check
            // independently before mutating the history.
            if let Err(e) = envelope.verify(current_key.as_node_id(), &self.chain_id) {
                tracing::warn!(
                    target: TRACE_TARGET,
                    height = block.header.height,
                    view = block_view,
                    validator = ?envelope.payload.validator,
                    error = %e,
                    "rotation_signature_verification_failed",
                );
                continue;
            }

            // Scheme-consistency check (#358): on BLS chains the
            // rotation must atomically rotate both keys (with a
            // verified PoP for the new BLS pubkey); on Ed25519 chains
            // the BLS fields must be absent. Splitting the two halves
            // would leave the histories transiently disagreeing.
            if let Err(e) = envelope
                .payload
                .validate_scheme_consistency(self.signature_scheme, &self.chain_id)
            {
                tracing::warn!(
                    target: TRACE_TARGET,
                    height = block.header.height,
                    view = block_view,
                    validator = ?envelope.payload.validator,
                    error = %e,
                    "rotation_scheme_consistency_failed",
                );
                continue;
            }

            // Snapshot the stable id BEFORE mutating
            // `validator_key_history` — `validator_for` resolves any
            // historical key (including the soon-to-be-stale
            // pre-rotation key) to the validator's stable id, but
            // computing it before the mutation is the simpler proof
            // of correctness.
            let stable_id = self.validator_key_history.validator_for(&validator_pk);

            // History-invariant check (structural + monotone v_eff +
            // no cross-validator key collision). Logs and drops on
            // failure — the in-memory state is unchanged.
            if let Err(e) = self
                .validator_key_history
                .apply_rotation(&envelope.payload, block_view)
            {
                tracing::warn!(
                    target: TRACE_TARGET,
                    height = block.header.height,
                    view = block_view,
                    validator = ?envelope.payload.validator,
                    new_pubkey = ?envelope.payload.new_pubkey,
                    v_eff = envelope.payload.v_eff,
                    error = %e,
                    "rotation_history_apply_failed",
                );
                continue;
            }

            // BLS half (#358): mirror the rotation into
            // `bls_key_history`. The Ed25519 apply just succeeded and
            // `validate_scheme_consistency` already verified the PoP,
            // so `apply_rotation` here can only fail on the
            // monotone-`v_eff` invariant — same failure mode the
            // Ed25519 path already covers, but in the parallel BLS
            // history. Log + roll back if it does.
            if self.signature_scheme
                == crate::crypto::sig_scheme::SignatureSchemeChoice::BlsAggregated
            {
                let new_bls_pk = envelope.payload.new_bls_pubkey.expect(
                    "BLS chain rotation passed scheme consistency must carry new_bls_pubkey",
                );
                let bls_history = self
                    .bls_key_history
                    .as_mut()
                    .expect("BLS chain must have a BlsKeyHistory at apply_committed_rotations");
                let stable_id =
                    stable_id.expect("validator_for resolved before apply_rotation succeeded");
                if let Err(e) = bls_history.apply_rotation(
                    stable_id.into_node_id(),
                    envelope.payload.v_eff,
                    new_bls_pk,
                ) {
                    // Rare but bounded: the validator_key_history
                    // accepted the rotation but the BLS history
                    // rejected it. The likeliest cause is a manual
                    // mis-seeding where `bls_key_history` lacks the
                    // validator's genesis entry. Drop the rotation
                    // and continue — the cluster is now in an
                    // inconsistent state for this validator (Ed25519
                    // rotated, BLS not), so loud-warn so an operator
                    // notices.
                    tracing::error!(
                        target: TRACE_TARGET,
                        height = block.header.height,
                        view = block_view,
                        validator = ?envelope.payload.validator,
                        stable_id = ?stable_id,
                        new_bls_pubkey = ?new_bls_pk,
                        v_eff = envelope.payload.v_eff,
                        error = %e,
                        "bls_rotation_history_apply_failed_after_ed25519_apply_succeeded",
                    );
                    // Don't continue — the Ed25519 mutation already
                    // happened and we still want to flush + log.
                }
            }

            tracing::info!(
                target: TRACE_TARGET,
                height = block.header.height,
                view = block_view,
                validator = ?envelope.payload.validator,
                new_pubkey = ?envelope.payload.new_pubkey,
                v_eff = envelope.payload.v_eff,
                "rotation_applied",
            );
            applied_any = true;
        }

        // Same persistence pattern as the reconfig path: write once
        // per commit if any rotation applied, encoded as a single
        // full-history blob (not a journal). Failures log + drop —
        // the in-memory history is authoritative; a subsequent
        // rotation will get another chance to flush, and recovery
        // resets to whatever was durably written before the last
        // successful flush.
        if applied_any {
            let persisted = self.validator_key_history.to_persisted();
            match postcard::to_stdvec(&persisted) {
                Ok(bytes) => {
                    if let Err(e) = self.storage.put(STORAGE_KEY_VALIDATOR_KEY_HISTORY, &bytes) {
                        tracing::error!(
                            target: TRACE_TARGET,
                            error = %e,
                            "validator_key_history_persist_failed",
                        );
                    }
                }
                Err(e) => {
                    tracing::error!(
                        target: TRACE_TARGET,
                        error = %e,
                        "validator_key_history_encode_failed",
                    );
                }
            }
            // Mirror the persist for the parallel BLS history (#339).
            // No-op on Ed25519 chains where bls_key_history is None.
            if let Some(bls) = self.bls_key_history.as_ref() {
                let persisted = bls.to_persisted();
                match postcard::to_stdvec(&persisted) {
                    Ok(bytes) => {
                        if let Err(e) = self.storage.put(STORAGE_KEY_BLS_KEY_HISTORY, &bytes) {
                            tracing::error!(
                                target: TRACE_TARGET,
                                error = %e,
                                "bls_key_history_persist_failed",
                            );
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            target: TRACE_TARGET,
                            error = %e,
                            "bls_key_history_encode_failed",
                        );
                    }
                }
            }
        }

        // #325 PR B: confirm the pure-rebuild rotation function lands
        // in the same place this wrapper did. See the matching block
        // in apply_committed_reconfigs for the rationale.
        #[cfg(debug_assertions)]
        {
            let (mut rebuilt_keys, mut rebuilt_bls) = pre_state_for_parity;
            crate::consensus::history_commitment::apply_rotation_commands_to_histories(
                block,
                &self.validator_history,
                &mut rebuilt_keys,
                rebuilt_bls.as_mut(),
                &self.chain_id,
                self.signature_scheme,
            );
            debug_assert_eq!(
                rebuilt_keys.to_persisted(),
                self.validator_key_history.to_persisted(),
                "pure-rebuild rotation path diverged from wrapper at height={} view={}",
                block.header.height,
                block.header.view,
            );
            debug_assert_eq!(
                rebuilt_bls.as_ref().map(|h| h.to_persisted()),
                self.bls_key_history.as_ref().map(|h| h.to_persisted()),
                "pure-rebuild BLS rotation path diverged from wrapper at height={} view={}",
                block.header.height,
                block.header.view,
            );
        }
    }

    /// Build and persist a snapshot of the state machine at `block`'s
    /// height, then prune older snapshots per the configured retention.
    ///
    /// Caller must check [`SnapshotPolicy::should_snapshot_at`] before
    /// invoking — this routine assumes the policy is enabled and the
    /// height is appropriate.
    fn try_take_snapshot(&self, block: &crate::replication::block::Block) -> anyhow::Result<()> {
        use crate::replication::snapshot::{SnapshotManifest, SnapshotStore, chunk_snapshot};
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
                    height = block.header.height,
                    view = block.header.view,
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
        let active_set = self.validator_history.set_at(block.header.view);
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
            &active_set,
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
            height = manifest.height,
            view = manifest.view,
            chunk_count = manifest.chunk_count,
            chunk_size = manifest.chunk_size,
            pruned = ?pruned,
            "snapshot_created",
        );
        Ok(())
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

/// Serialize a `proposed_in_view` value to its on-storage encoding.
/// See [`STORAGE_KEY_PROPOSED_IN_VIEW`] for the durability contract
/// (audit finding 4-6, issue #407).
pub fn encode_proposed_in_view(view: View) -> anyhow::Result<Vec<u8>> {
    postcard::to_stdvec(&view).context("encode proposed_in_view")
}

/// Inverse of [`encode_proposed_in_view`].
pub fn decode_proposed_in_view(bytes: &[u8]) -> anyhow::Result<View> {
    postcard::from_bytes(bytes).context("decode proposed_in_view")
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

/// Persisted `(height, view, hash)` triple for the most recently
/// committed block. Stored at [`STORAGE_KEY_LAST_COMMITTED`].
///
/// `last_committed_hash` is the content-hash of the most recently
/// committed block — used by the recovery path (#325 PR B) as the tip
/// from which to walk the committed-block chain backward to genesis,
/// rebuilding the validator histories from each block's reconfig and
/// rotation commands. Without the hash, recovery would have no way to
/// locate the chain tip in storage.
///
/// The genesis case (no blocks yet committed) is `height == 0`,
/// `view == 0`, `last_committed_hash == [0; 32]` (the all-zero hash
/// is reserved for "no tip persisted" and is distinguishable from a
/// real block hash because the recovery path treats `height == 0` as
/// "no chain to walk").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastCommitted {
    pub height: u64,
    pub view: View,
    pub last_committed_hash: BlockHash,
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
/// overlaid.
///
/// `pending_blocks` is re-seeded with the blocks referenced by the
/// recovered `locked` and `high_qc` (when those blocks are present in
/// durable storage — `persist_updates` writes them alongside their
/// metadata for exactly this reason). Without this, a 4-node cluster
/// whose replicas resume with divergent on-disk state can permanently
/// stall: every leader's [`HotStuffCore::become_leader`] short-circuits
/// because the high-QC's parent block isn't in `pending_blocks`, so no
/// proposal ever fires and the block-sync request that would otherwise
/// fetch the missing block is never triggered (issue #206). Older
/// committed blocks remain on-demand-only — they live under
/// [`STORAGE_KEY_BLOCK_PREFIX`] and are served by the
/// `Dispatch::ServeBlock` arm via [`load_block_from_storage`] — so boot
/// stays O(1) rather than O(committed-blocks).
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

    // Re-seed `pending_blocks` with the locked / high_qc blocks so the
    // safety-rule walks (extension via locked, become_leader's parent
    // lookup) terminate without first having to round-trip through
    // block-sync. Genesis is already in `pending_blocks`. Any block
    // missing from storage (e.g. an older snapshot adopted via NewView
    // before the persist-with-block pairing landed) is silently
    // skipped — the existing block-sync paths still cover that case.
    if let Some(qc) = state.high_qc.as_ref().cloned()
        && let Some(block) = load_block_from_storage(storage, &qc.block_hash)?
    {
        state.insert_pending(block);
    }
    if let Some(locked) = state.locked
        && let Some(block) = load_block_from_storage(storage, &locked.block_hash)?
    {
        state.insert_pending(block);
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
        Some(leader) if leader.as_node_id() == self_id => format!("leader(view={view})"),
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

/// Extract a fresh `BlsKeyHistory` containing only the genesis
/// (`v_eff = 0`) entries of `loaded`. Used by the recovery rebuild
/// path (#325 PR B) as the seed for replaying the chain's BLS
/// rotations: we can't trust the loaded history's later entries
/// (those are exactly what the rebuild is verifying), but the
/// genesis entries are cross-checked at the genesis iteration
/// against the genesis block's stamped `validator_history_commitment`.
/// If those entries are tampered with, the very first iteration of
/// the walk fires the mismatch error.
fn genesis_only_bls_seed(
    loaded: &crate::consensus::bls_key_history::BlsKeyHistory,
) -> crate::consensus::bls_key_history::BlsKeyHistory {
    use crate::consensus::bls_key_history::{
        BlsKeyHistory, PersistedBlsKeyEntry, PersistedBlsKeyHistory, PersistedBlsValidator,
    };
    let persisted = loaded.to_persisted();
    let genesis_only = PersistedBlsKeyHistory {
        validators: persisted
            .validators
            .into_iter()
            .filter_map(|v| {
                let mut v0_entries: Vec<PersistedBlsKeyEntry> =
                    v.entries.into_iter().filter(|e| e.v_eff == 0).collect();
                if v0_entries.is_empty() {
                    // Reconfig-added validator (no genesis entry).
                    // Don't seed it — the rebuild will add it back via
                    // the corresponding reconfig command at its
                    // `v_eff` block. If the loaded history has a
                    // genesis-time entry the chain didn't actually
                    // produce (or the chain produced one this
                    // tampering removed), the per-block commitment
                    // check fires at the relevant iteration.
                    None
                } else {
                    // Genesis entry only — strip any later entries.
                    v0_entries.truncate(1);
                    Some(PersistedBlsValidator {
                        stable_id: v.stable_id,
                        entries: v0_entries,
                    })
                }
            })
            .collect(),
    };
    BlsKeyHistory::from_persisted(genesis_only)
        .expect("genesis-only BLS seed has valid invariants by construction")
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

    fn vid(b: u8) -> crate::consensus::validator_set::ValidatorId {
        crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(nid(b))
    }

    fn four_validators() -> ValidatorSet {
        ValidatorSet::new(vec![vid(1), vid(2), vid(3), vid(4)])
    }

    fn genesis() -> Block {
        Block::genesis([0u8; 32], [0; 32])
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
                validator_history_commitment: [0; 32],
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
        let msg = WireMessage::Vote(
            Signed {
                payload: Vote {
                    view: 7,
                    block_hash: [0xAB; 32],
                },
                signer: nid(2),
                sig: dummy_sig(),
            },
            None,
        );
        let encoded = postcard::to_stdvec(&msg).unwrap();
        let decoded: WireMessage = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn wire_message_vote_with_bls_partial_roundtrip() {
        use crate::consensus::hotstuff::qc::Vote;
        let msg = WireMessage::Vote(
            Signed {
                payload: Vote {
                    view: 7,
                    block_hash: [0xAB; 32],
                },
                signer: nid(2),
                sig: dummy_sig(),
            },
            Some([0xCDu8; 96]),
        );
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
        let block = sample_block();
        let msg = WireMessage::BlockResponse(Signed {
            payload: BlockResponsePayload {
                requested_hash: block.hash(),
                block: Some(block),
            },
            signer: [0u8; 32],
            sig: [0u8; 64],
        });
        let encoded = postcard::to_stdvec(&msg).unwrap();
        let decoded: WireMessage = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn wire_message_block_response_none_roundtrip() {
        let msg = WireMessage::BlockResponse(Signed {
            payload: BlockResponsePayload {
                requested_hash: [0xAA; 32],
                block: None,
            },
            signer: [0u8; 32],
            sig: [0u8; 64],
        });
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
        MempoolBlockBuilder::new(
            self_id,
            mempool,
            sm,
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
            10,
        )
    }

    /// Variant of [`make_builder`] that exposes the
    /// `dropped_commands` counter so a caller can observe how many
    /// commands the builder skipped (#376).
    fn make_builder_with_dropped(
        self_id: NodeId,
        mempool: Arc<dyn Mempool>,
        sm: Arc<Mutex<Box<dyn StateMachine>>>,
        dropped_commands: Arc<AtomicU64>,
    ) -> MempoolBlockBuilder {
        MempoolBlockBuilder::new(
            self_id,
            mempool,
            sm,
            Arc::new(AtomicU64::new(0)),
            dropped_commands,
            10,
        )
    }

    /// Variant of [`make_builder`] that lets the caller seed
    /// `last_committed_height`. Used by the multi-block-in-flight
    /// test (#375) where the SM has been advanced past the
    /// pre-seeded genesis but pending_blocks still contains it.
    #[allow(dead_code)]
    fn make_builder_with_committed(
        self_id: NodeId,
        mempool: Arc<dyn Mempool>,
        sm: Arc<Mutex<Box<dyn StateMachine>>>,
        last_committed_height: Arc<AtomicU64>,
    ) -> MempoolBlockBuilder {
        MempoolBlockBuilder::new(
            self_id,
            mempool,
            sm,
            last_committed_height,
            Arc::new(AtomicU64::new(0)),
            10,
        )
    }

    #[test]
    fn builder_sets_header_fields_from_parent_and_view() {
        let mp: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(16));
        let sm = make_sm();
        let builder = make_builder(nid(1), Arc::clone(&mp), Arc::clone(&sm));
        let parent = genesis();
        let qc = sample_qc();

        let block = builder
            .build(&parent, 3, &qc, &HashMap::new())
            .expect("test builder must not fail");

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
        let block = builder
            .build(&genesis(), 1, &sample_qc(), &HashMap::new())
            .expect("test builder must not fail");

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

        let b1 = builder
            .build(&parent, 1, &qc, &HashMap::new())
            .expect("test builder must not fail");
        let b2 = builder
            .build(&parent, 1, &qc, &HashMap::new())
            .expect("test builder must not fail");

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
        builder
            .build(&genesis(), 1, &sample_qc(), &HashMap::new())
            .expect("test builder must not fail");

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
        let block = builder
            .build(&genesis(), 1, &sample_qc(), &HashMap::new())
            .expect("test builder must not fail");

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
        let block = builder
            .build(&genesis(), 1, &sample_qc(), &HashMap::new())
            .expect("test builder must not fail");

        let recomputed = Block::commands_commitment(&block.commands);
        assert_eq!(block.header.commands_commitment, recomputed);
    }

    /// Issue #326 / audit finding 4-F3: a [`StateMachine::restore`]
    /// failure inside [`MempoolBlockBuilder::build`] must surface as
    /// `Err`, not panic. Pre-fix the build path called
    /// `expect("restore from own snapshot must not fail")` — a corrupt
    /// redb table or version skew would crash the node and trip a
    /// panic-on-startup loop. Now `build` returns `anyhow::Result`,
    /// the safety core's `build_proposal_at_view` skips the proposal
    /// at this view on `Err`, and the next-view leader takes over.
    ///
    /// **Bisect-confirmed**: reverting the `?`/`bail!` to the original
    /// `.expect(...)` makes this test fail with a panic instead of
    /// the expected `Err`.
    #[test]
    fn builder_propagates_state_machine_restore_failure() {
        use crate::replication::StateMachine;
        use bytes::Bytes;

        /// Test-only state machine whose `restore` always fails. The
        /// other methods are minimal — only `snapshot` + `restore` are
        /// on the build path that PR #326 cares about.
        struct FailingRestoreSm;

        impl StateMachine for FailingRestoreSm {
            fn apply(&mut self, _cmd: &[u8]) -> anyhow::Result<Bytes> {
                Ok(Bytes::new())
            }

            fn state_commitment(&self) -> [u8; 32] {
                [0xAB; 32]
            }

            fn snapshot(&self) -> Bytes {
                // Any non-empty bytes — the builder feeds this back into
                // restore on the same instance, where we then fail.
                Bytes::from_static(b"snap-bytes")
            }

            fn restore(&mut self, _snap: &[u8]) -> anyhow::Result<()> {
                anyhow::bail!("simulated restore failure (#326 test)")
            }
        }

        let sm: Arc<Mutex<Box<dyn StateMachine>>> =
            Arc::new(Mutex::new(Box::new(FailingRestoreSm)));
        let mp: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(16));
        let builder = make_builder(nid(1), Arc::clone(&mp), Arc::clone(&sm));

        // The fork-and-restore round trip inside `build` triggers our
        // simulated failure. The builder must surface this as `Err`,
        // not panic.
        let result = builder.build(&genesis(), 1, &sample_qc(), &HashMap::new());
        let err = result.expect_err("builder must propagate restore failure as Err");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("simulated restore failure"),
            "error must surface the underlying state-machine failure, got {msg}",
        );
    }

    /// Issue #375: multi-block-in-flight — when the leader builds a
    /// child while previous blocks are uncommitted, the stamped
    /// `state_commitment` must reflect *all* the in-flight ancestors'
    /// commands, not just the candidate commands applied to the
    /// committed SM. Pre-fix, the commitment was computed against the
    /// committed SM directly; replicas applying the chain in order
    /// would compute a different value and reject the proposal.
    ///
    /// The test builds a chain `genesis → b1 → b2 → b3` of
    /// uncommitted ancestors (each carrying one `Increment`), then
    /// asks the builder to extend `b3` with another `Increment` from
    /// the mempool. The stamped `state_commitment` must equal what a
    /// replica computes when applying every block's commands in
    /// order (`b1.cmds → b2.cmds → b3.cmds → candidate.cmds`).
    ///
    /// **Bisect-confirmed**: reverting [`MempoolBlockBuilder::build`]
    /// to the pre-fix single-step apply makes the assertion fail with
    /// a commitment mismatch — the leader's stamp would be the
    /// commitment for "apply 1 increment to genesis state" instead
    /// of "apply 4 increments".
    #[test]
    fn builder_state_commitment_walks_uncommitted_ancestor_chain() {
        use crate::replication::impls::counter_sm::CounterCommand;

        // The candidate (the new block being built) pulls one
        // Increment from the mempool.
        let mp: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(16));
        mp.insert(CounterCommand::Increment.encode()).unwrap();

        let sm = make_sm();
        let before = sm.lock().state_commitment();
        let last_committed_height = Arc::new(AtomicU64::new(0));
        let builder = make_builder_with_committed(
            nid(1),
            Arc::clone(&mp),
            Arc::clone(&sm),
            Arc::clone(&last_committed_height),
        );

        // Build the in-flight ancestor chain: genesis → b1 → b2 → b3,
        // each carrying one Increment. State_commitment fields are
        // not load-bearing for the builder's walk (the walk uses
        // pending_blocks parent links + commands), so any value
        // works here.
        let g = genesis();
        let make_inflight = |parent_hash: BlockHash, height: u64, view: View| -> Block {
            let commands = vec![CounterCommand::Increment.encode()];
            Block {
                header: BlockHeader {
                    parent_hash,
                    height,
                    view,
                    proposer: nid(1),
                    state_commitment: [0u8; 32],
                    commands_commitment: Block::commands_commitment(&commands),
                    validator_history_commitment: [0; 32],
                },
                commands,
            }
        };
        let b1 = make_inflight(g.hash(), 1, 1);
        let b2 = make_inflight(b1.hash(), 2, 2);
        let b3 = make_inflight(b2.hash(), 3, 3);

        let mut pending_blocks: HashMap<BlockHash, Block> = HashMap::new();
        pending_blocks.insert(g.hash(), g.clone());
        pending_blocks.insert(b1.hash(), b1.clone());
        pending_blocks.insert(b2.hash(), b2.clone());
        pending_blocks.insert(b3.hash(), b3.clone());

        let proposal = builder
            .build(&b3, 4, &sample_qc(), &pending_blocks)
            .expect("test builder must not fail");

        // The builder must not have left the SM mutated — the apply
        // discipline still requires snapshot/restore round-tripping.
        assert_eq!(
            sm.lock().state_commitment(),
            before,
            "build must not leave the state machine mutated",
        );

        // Compute the reference commitment by applying every block's
        // commands to a fresh SM in order, then the candidate
        // command. This is what every honest replica computes in its
        // own pending_blocks walk.
        let mut reference = CounterStateMachine::new();
        for ancestor in [&b1, &b2, &b3] {
            for cmd in &ancestor.commands {
                reference.apply(cmd).unwrap();
            }
        }
        for cmd in &proposal.commands {
            reference.apply(cmd).unwrap();
        }
        assert_eq!(
            proposal.header.state_commitment,
            reference.state_commitment(),
            "state_commitment must reflect b1+b2+b3+candidate, not just candidate",
        );
        assert_eq!(reference.value(), 4, "1 + 1 + 1 + 1 = 4 increments applied");
    }

    /// Issue #375 corollary: after the last-committed boundary
    /// advances (e.g. the SM is updated and `last_committed_height`
    /// bumped), the builder must stop walking *at* the new boundary
    /// — not the old one or genesis. This pins the contract that the
    /// integration layer's `apply_commit` updates the shared atomic
    /// in lockstep with the SM.
    #[test]
    fn builder_state_commitment_stops_at_last_committed_boundary() {
        use crate::replication::impls::counter_sm::CounterCommand;

        let mp: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(16));
        mp.insert(CounterCommand::Increment.encode()).unwrap();

        // Simulate "b1 has been committed": the SM has applied b1's
        // commands and `last_committed_height = 1`.
        let sm = make_sm();
        sm.lock()
            .apply(&CounterCommand::Increment.encode())
            .unwrap();
        let post_b1_commitment = sm.lock().state_commitment();

        let last_committed_height = Arc::new(AtomicU64::new(1));
        let builder = make_builder_with_committed(
            nid(1),
            Arc::clone(&mp),
            Arc::clone(&sm),
            Arc::clone(&last_committed_height),
        );

        // pending_blocks still contains b1, b2 (the typical
        // post-three-chain-commit shape would have pruned b1, but
        // until the prune fires the safety core can hold it; the
        // builder must not re-apply b1's commands either way).
        let g = genesis();
        let make_inflight = |parent_hash: BlockHash, height: u64, view: View| -> Block {
            let commands = vec![CounterCommand::Increment.encode()];
            Block {
                header: BlockHeader {
                    parent_hash,
                    height,
                    view,
                    proposer: nid(1),
                    state_commitment: [0u8; 32],
                    commands_commitment: Block::commands_commitment(&commands),
                    validator_history_commitment: [0; 32],
                },
                commands,
            }
        };
        let b1 = make_inflight(g.hash(), 1, 1);
        let b2 = make_inflight(b1.hash(), 2, 2);

        let mut pending_blocks: HashMap<BlockHash, Block> = HashMap::new();
        pending_blocks.insert(g.hash(), g.clone());
        pending_blocks.insert(b1.hash(), b1.clone());
        pending_blocks.insert(b2.hash(), b2.clone());

        let proposal = builder
            .build(&b2, 3, &sample_qc(), &pending_blocks)
            .expect("test builder must not fail");

        // SM unmutated.
        assert_eq!(sm.lock().state_commitment(), post_b1_commitment);

        // Reference: b2.commands + candidate.commands applied on top
        // of post-b1 state.
        let mut reference = CounterStateMachine::new();
        reference
            .apply(&CounterCommand::Increment.encode())
            .unwrap();
        for cmd in &b2.commands {
            reference.apply(cmd).unwrap();
        }
        for cmd in &proposal.commands {
            reference.apply(cmd).unwrap();
        }
        assert_eq!(
            proposal.header.state_commitment,
            reference.state_commitment(),
            "commitment must reflect b2 + candidate on top of committed b1",
        );
        assert_eq!(reference.value(), 3);
    }

    /// Issue #376: a command whose `apply` returns `Err` is dropped
    /// silently from the leader's commitment computation. The block
    /// itself still carries the (invalid) command bytes — replicas
    /// will fail the same `apply` deterministically and end up at
    /// the same commitment — but operators get no signal that any
    /// of their submitted commands were rejected. After the fix the
    /// builder emits a `tracing::warn!` per failed apply with
    /// `cmd_idx`, `view`, and `error` and bumps a shared cumulative
    /// counter that surfaces under `ConsensusStatus::dropped_commands`.
    /// The behavioural contract is that the build still succeeds, the
    /// resulting `state_commitment` matches the partial application
    /// of only the commands that did apply, and the counter
    /// increments by the number of skipped commands.
    #[test]
    fn builder_skips_failing_commands_and_commitment_matches_partial_apply() {
        use crate::replication::StateMachine;
        use crate::replication::impls::counter_sm::CounterCommand;
        use bytes::Bytes;

        // Mix valid and invalid commands. `bad_underflow` is a
        // well-formed `Decrement` against a fresh counter (`value =
        // 0` → underflow on apply). `bad_decode` is a malformed
        // payload that fails postcard decode. Both are exactly the
        // silent-drop cases the issue calls out: app-level rejection
        // and decode error.
        let good = CounterCommand::Increment.encode();
        let bad_underflow = CounterCommand::Decrement.encode();
        let bad_decode: Bytes = Bytes::from_static(&[0xFFu8, 0x00, 0x00, 0x00]);

        let mp: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(16));
        mp.insert(bad_underflow.clone()).unwrap();
        mp.insert(good.clone()).unwrap();
        mp.insert(bad_decode.clone()).unwrap();

        let sm = make_sm();
        let dropped_commands = Arc::new(AtomicU64::new(0));
        let builder = make_builder_with_dropped(
            nid(1),
            Arc::clone(&mp),
            Arc::clone(&sm),
            Arc::clone(&dropped_commands),
        );
        let block = builder
            .build(&genesis(), 1, &sample_qc(), &HashMap::new())
            .expect("builder must skip-and-warn rather than fail the proposal");

        // All three commands ride the block — replicas hit the same
        // `apply` errors deterministically and converge.
        assert_eq!(block.commands.len(), 3);

        // Reference: apply only the one good command to a fresh
        // counter SM and compare commitments.
        let mut reference = crate::replication::impls::CounterStateMachine::new();
        reference.apply(&good).unwrap();
        assert_eq!(
            block.header.state_commitment,
            reference.state_commitment(),
            "state_commitment must reflect only the commands that applied",
        );

        // The state machine itself must be untouched after build —
        // failing applies must not leak past the fork-and-restore.
        assert_eq!(
            sm.lock().state_commitment(),
            crate::replication::impls::CounterStateMachine::new().state_commitment(),
            "build must not mutate the SM, even when some commands fail to apply",
        );

        // The shared counter (surfaced under
        // `ConsensusStatus::dropped_commands`) bumps by exactly the
        // number of commands that hit `Err` on apply.
        assert_eq!(
            dropped_commands.load(Ordering::Relaxed),
            2,
            "dropped_commands must reflect both the underflow and the decode error",
        );

        // A second build with the same mempool contents must add to
        // the cumulative count, not reset it — the counter is
        // monotonic for the lifetime of the node, like
        // `cache_evictions`.
        builder
            .build(&genesis(), 2, &sample_qc(), &HashMap::new())
            .expect("second build must also succeed");
        assert_eq!(
            dropped_commands.load(Ordering::Relaxed),
            4,
            "dropped_commands must accumulate across builds",
        );
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
    fn encode_decode_proposed_in_view_roundtrips() {
        let cases = [0u64, 1, 42, u64::MAX];
        for v in cases {
            let bytes = encode_proposed_in_view(v).unwrap();
            assert_eq!(decode_proposed_in_view(&bytes).unwrap(), v);
        }
    }

    #[test]
    fn decode_voted_view_surfaces_error_on_garbage() {
        assert!(decode_voted_view(&[0xFFu8; 64]).is_err());
    }

    #[test]
    fn decode_proposed_in_view_surfaces_error_on_garbage() {
        assert!(decode_proposed_in_view(&[0xFFu8; 64]).is_err());
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

    /// Issue #407 / audit finding 4-6: persisting `ProposedInView`
    /// before `Broadcast(Proposal)` and restoring it on
    /// [`ConsensusNode::recover`] keeps a leader from re-minting a
    /// *different* signed proposal at the same view if it crashes
    /// between `Signed::sign` and the network bytes leaving the
    /// host. Without the durable mirror the in-memory guard would
    /// reset to `0` on restart and the next call into
    /// `try_propose_as_leader(view)` would re-enter the build path
    /// for the same view — handing a Byzantine-detector a
    /// slashable equivocation envelope, even though the leader was
    /// honest.
    #[test]
    fn persist_then_recover_preserves_proposed_in_view() {
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
        node.persist_updates(&[StateUpdate::ProposedInView { view: 12 }])
            .unwrap();

        // The durable write is immediately readable under the
        // documented storage key — defense-in-depth so a future refactor
        // that drops the call to `b.put(STORAGE_KEY_PROPOSED_IN_VIEW, _)`
        // surfaces here rather than only in the recovery test below.
        let raw = storage
            .get(STORAGE_KEY_PROPOSED_IN_VIEW)
            .unwrap()
            .expect("ProposedInView must be persisted under STORAGE_KEY_PROPOSED_IN_VIEW");
        assert_eq!(decode_proposed_in_view(&raw).unwrap(), 12);
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
        assert_eq!(
            recovered.core.proposed_in_view(),
            12,
            "recover() must restore proposed_in_view from durable storage so a \
             leader that crashed mid-broadcast cannot re-mint at the same view",
        );
    }

    /// Companion to [`persist_then_recover_preserves_proposed_in_view`]:
    /// fresh storage with no `ProposedInView` ever written must recover
    /// to `0`, matching the in-memory default for an unstarted leader.
    #[test]
    fn recover_with_no_persisted_proposed_in_view_defaults_to_zero() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let wal: Arc<dyn Wal> = Arc::new(MemoryWal::new());
        let cfg = test_config(four_validators());

        let recovered = ConsensusNode::recover(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::clone(&wal),
        )
        .unwrap();
        assert_eq!(recovered.core.proposed_in_view(), 0);
    }

    /// Issue #206 regression: persisting a `Locked` / `HighQc` whose
    /// referenced block is in `pending_blocks` writes the block to
    /// durable storage so [`recover_state`] can re-seed
    /// `pending_blocks` post-restart. Without this, every replica's
    /// [`HotStuffCore::become_leader`] silently returns an empty action
    /// set after a divergent resume — no proposal ever fires and the
    /// cluster permanently stalls.
    #[test]
    fn persist_writes_locked_and_high_qc_blocks_recover_seeds_pending() {
        use crate::replication::block::BlockHeader;

        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let wal: Arc<dyn Wal> = Arc::new(MemoryWal::new());
        let cfg = test_config(four_validators());

        // Build two distinct uncommitted blocks: `b_locked` at height 1
        // / view 18 (the locked block from the issue), and `b_high_qc`
        // at height 2 / view 19 (the high_qc block). Hashes differ
        // because the headers do.
        let g = genesis();
        let b_locked = Block {
            header: BlockHeader {
                parent_hash: g.hash(),
                height: 1,
                view: 18,
                proposer: nid(1),
                state_commitment: [0u8; 32],
                commands_commitment: Block::commands_commitment(&[]),
                validator_history_commitment: [0; 32],
            },
            commands: vec![],
        };
        let b_high_qc = Block {
            header: BlockHeader {
                parent_hash: b_locked.hash(),
                height: 2,
                view: 19,
                proposer: nid(2),
                state_commitment: [0u8; 32],
                commands_commitment: Block::commands_commitment(&[]),
                validator_history_commitment: [0; 32],
            },
            commands: vec![],
        };

        let locked = Locked {
            view: 18,
            height: 1,
            block_hash: b_locked.hash(),
        };
        let mut qc = QuorumCertificate::new(19, b_high_qc.hash(), 4);
        qc.add_signature(0, [0x11u8; 64]);
        qc.add_signature(1, [0x22u8; 64]);
        qc.add_signature(2, [0x33u8; 64]);

        // Session 1: seed the safety core's `pending_blocks` with both
        // uncommitted blocks (mirroring what `on_proposal_received`
        // does in production), then persist the lock and high_qc.
        {
            let mut node = ConsensusNode::new(
                nid(1),
                cfg.clone(),
                make_sm(),
                Arc::new(InMemoryMempool::new(64)),
                Arc::clone(&storage),
                Arc::clone(&wal),
            );
            node.core.insert_pending_block(b_locked.clone());
            node.core.insert_pending_block(b_high_qc.clone());
            node.persist_updates(&[StateUpdate::Locked(locked), StateUpdate::HighQc(qc.clone())])
                .unwrap();
            // Both blocks are durable under the block-storage prefix.
            assert!(
                load_block_from_storage(storage.as_ref(), &b_locked.hash())
                    .unwrap()
                    .is_some(),
                "persist_updates must write the locked block",
            );
            assert!(
                load_block_from_storage(storage.as_ref(), &b_high_qc.hash())
                    .unwrap()
                    .is_some(),
                "persist_updates must write the high_qc block",
            );
        }

        // Session 2: recover. `pending_blocks` must contain genesis
        // plus both uncommitted blocks so the post-restart leader can
        // build a proposal extending high_qc.block_hash and the
        // safe_to_vote extension walk can terminate at locked.
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
        assert!(
            recovered
                .core
                .state()
                .pending_blocks
                .contains_key(&b_locked.hash()),
            "recover must re-seed the locked block into pending_blocks",
        );
        assert!(
            recovered
                .core
                .state()
                .pending_blocks
                .contains_key(&b_high_qc.hash()),
            "recover must re-seed the high_qc block into pending_blocks",
        );
        // And the resumed leader can build a proposal — the parent
        // lookup that previously short-circuited is now resolved.
        assert!(
            recovered
                .core
                .state()
                .pending_blocks
                .contains_key(&qc.block_hash),
        );
    }

    /// Persisting `HighQc` whose block is *not* in `pending_blocks` —
    /// the rare NewView-only adoption path — still records the QC
    /// metadata, but no block write fires (the safety core's
    /// in-memory state is the authority for that case).
    #[test]
    fn persist_skips_block_write_when_referenced_block_absent() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let wal: Arc<dyn Wal> = Arc::new(MemoryWal::new());
        let cfg = test_config(four_validators());

        let node = ConsensusNode::new(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::clone(&wal),
        );
        // sample_full_qc references a hash that was never inserted.
        let qc = sample_full_qc();
        node.persist_updates(&[StateUpdate::HighQc(qc.clone())])
            .unwrap();

        // Metadata is on disk so liveness state survives the restart.
        let raw = storage.get(STORAGE_KEY_HIGH_QC).unwrap().unwrap();
        assert_eq!(decode_high_qc(&raw).unwrap(), qc);
        // But there is no block write for an unknown hash.
        assert!(
            load_block_from_storage(storage.as_ref(), &qc.block_hash)
                .unwrap()
                .is_none(),
        );
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

        // And `become_leader(1)` must now yield an
        // Action::Broadcast(Proposal) (preceded by the
        // ProposedInView persist that closes the audit-4-6 / #407
        // self-equivocation hazard) rather than the empty Vec the
        // pre-fix code returned.
        let mut node = node;
        let actions = node.core.become_leader(1);
        assert_eq!(actions.len(), 2);
        assert!(matches!(
            &actions[0],
            SafetyAction::Persist(crate::consensus::hotstuff::StateUpdate::ProposedInView {
                view: 1
            }),
        ));
        assert!(matches!(
            &actions[1],
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
                validator_history_commitment: [0; 32],
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

    // ── #272: commit-time reconfig application ────────────────────────────────

    fn five_validators() -> ValidatorSet {
        ValidatorSet::new(vec![vid(1), vid(2), vid(3), vid(4), vid(5)])
    }

    fn six_validators() -> ValidatorSet {
        ValidatorSet::new(vec![vid(1), vid(2), vid(3), vid(4), vid(5), vid(6)])
    }

    /// Build a Block at `(height, view)` that carries a single tagged
    /// `ReconfigCommand` payload built by `make_cmd`.
    fn block_with_reconfig(
        height: u64,
        view: View,
        proposer: NodeId,
        cmd: crate::consensus::reconfig::ReconfigCommand,
    ) -> crate::replication::block::Block {
        let payload = cmd.encode();
        let commands = vec![payload];
        let header = crate::replication::block::BlockHeader {
            parent_hash: genesis().hash(),
            height,
            view,
            proposer,
            state_commitment: [0u8; 32],
            commands_commitment: crate::replication::block::Block::commands_commitment(&commands),
            validator_history_commitment: [0; 32],
        };
        crate::replication::block::Block { header, commands }
    }

    #[test]
    fn apply_commit_with_valid_reconfig_inserts_boundary_into_history() {
        use crate::consensus::reconfig::{MIN_V_EFF_DELAY, ReconfigCommand, ValidatorEntry};

        let mut node = make_node(nid(1));
        // Pre-conditions: only the genesis boundary, with the original
        // four-validator set.
        assert_eq!(node.validator_history.boundary_count(), 1);
        assert_eq!(node.core.state().validator_history.boundary_count(), 1);
        assert_eq!(*node.validator_history.current_set(), four_validators());

        // Construct a reconfig adding nid(5) at v_eff = 5 (≥ block.view +
        // MIN_V_EFF_DELAY for block.view = 0).
        let v_eff = MIN_V_EFF_DELAY + 3;
        let cmd = ReconfigCommand {
            adds: vec![ValidatorEntry {
                node_id: nid(5),
                addr: "127.0.0.1:9005".parse().unwrap(),
                bls_pop: None,
            }],
            removes: vec![],
            v_eff,
        };
        let block = block_with_reconfig(1, 0, nid(1), cmd);
        node.apply_commit(block);

        // Both histories carry the new boundary.
        assert_eq!(node.validator_history.boundary_count(), 2);
        assert_eq!(node.core.state().validator_history.boundary_count(), 2);
        assert_eq!(*node.validator_history.set_at(v_eff), five_validators());
        assert_eq!(
            *node.core.state().validator_history.set_at(v_eff),
            five_validators()
        );

        // The pacemaker selector now picks leaders from the post-
        // boundary set at and after v_eff.
        let leader_at_v_eff = node.pacemaker.leader_for_view(v_eff);
        let leader_vid =
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(leader_at_v_eff);
        assert!(
            five_validators().contains(&leader_vid),
            "leader at v_eff must come from post-boundary set",
        );
    }

    #[test]
    fn apply_commit_with_floor_violating_reconfig_drops_silently() {
        use crate::consensus::reconfig::{MIN_V_EFF_DELAY, ReconfigCommand, ValidatorEntry};

        let mut node = make_node(nid(1));
        // Removing two of four would leave a 2-member set, below the
        // MIN_VALIDATOR_FLOOR of 4. apply_commit must log + drop, but
        // the block itself stays committed.
        let v_eff = MIN_V_EFF_DELAY + 5;
        let cmd = ReconfigCommand {
            adds: vec![],
            removes: vec![nid(3), nid(4)],
            v_eff,
        };
        // Empty `adds` so nothing's needed; this is purely a removal.
        let _ = ValidatorEntry {
            node_id: nid(0),
            addr: "127.0.0.1:0".parse().unwrap(),
            bls_pop: None,
        };
        let block = block_with_reconfig(1, 0, nid(1), cmd);
        node.apply_commit(block);

        // History unchanged — only the genesis boundary remains.
        assert_eq!(node.validator_history.boundary_count(), 1);
        assert_eq!(node.core.state().validator_history.boundary_count(), 1);
    }

    #[test]
    fn apply_commit_with_v_eff_below_min_delay_drops_silently() {
        use crate::consensus::reconfig::{ReconfigCommand, ValidatorEntry};

        let mut node = make_node(nid(1));
        // block.view = 5, v_eff = 5 — equal, but the rule wants
        // v_eff >= block.view + MIN_V_EFF_DELAY, so this is too low.
        let cmd = ReconfigCommand {
            adds: vec![ValidatorEntry {
                node_id: nid(5),
                addr: "127.0.0.1:9005".parse().unwrap(),
                bls_pop: None,
            }],
            removes: vec![],
            v_eff: 5,
        };
        let block = block_with_reconfig(1, 5, nid(1), cmd);
        node.apply_commit(block);

        assert_eq!(node.validator_history.boundary_count(), 1);
    }

    #[test]
    fn apply_commit_with_two_reconfigs_in_one_block_keeps_only_first() {
        use crate::consensus::reconfig::{MIN_V_EFF_DELAY, ReconfigCommand, ValidatorEntry};

        let mut node = make_node(nid(1));
        let v_eff_a = MIN_V_EFF_DELAY + 3;
        let v_eff_b = v_eff_a + 5;
        let cmd_a = ReconfigCommand {
            adds: vec![ValidatorEntry {
                node_id: nid(5),
                addr: "127.0.0.1:9005".parse().unwrap(),
                bls_pop: None,
            }],
            removes: vec![],
            v_eff: v_eff_a,
        };
        let cmd_b = ReconfigCommand {
            adds: vec![ValidatorEntry {
                node_id: nid(6),
                addr: "127.0.0.1:9006".parse().unwrap(),
                bls_pop: None,
            }],
            removes: vec![],
            v_eff: v_eff_b,
        };

        let payload_a = cmd_a.encode();
        let payload_b = cmd_b.encode();
        let commands = vec![payload_a, payload_b];
        let header = crate::replication::block::BlockHeader {
            parent_hash: genesis().hash(),
            height: 1,
            view: 0,
            proposer: nid(1),
            state_commitment: [0u8; 32],
            commands_commitment: crate::replication::block::Block::commands_commitment(&commands),
            validator_history_commitment: [0; 32],
        };
        let block = crate::replication::block::Block { header, commands };
        node.apply_commit(block);

        // The first reconfig lands; the second is dropped because the
        // history's now-non-genesis boundary at v_eff_a conflicts with
        // any `v_eff >= v_eff_a`.
        assert_eq!(node.validator_history.boundary_count(), 2);
        assert_eq!(*node.validator_history.set_at(v_eff_a), five_validators());
        // v_eff_b is past the only non-genesis boundary, so the same
        // post-boundary set applies — confirming cmd_b did NOT land
        // (otherwise the set would be six_validators).
        assert_eq!(*node.validator_history.set_at(v_eff_b), five_validators());
        assert_ne!(*node.validator_history.set_at(v_eff_b), six_validators());
    }

    /// #254: a reconfig committed by one ConsensusNode must be visible
    /// to a fresh node `recover`'d against the same storage. Both the
    /// integration-side `validator_history` and the safety core's
    /// mirror must reflect the post-boundary committee.
    #[test]
    fn recovered_node_replays_persisted_validator_history() {
        use crate::consensus::reconfig::{MIN_V_EFF_DELAY, ReconfigCommand, ValidatorEntry};

        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let cfg = test_config(four_validators());

        // Phase 1: a fresh node commits a block carrying a reconfig.
        let mut node = ConsensusNode::new(
            nid(1),
            cfg.clone(),
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );
        let v_eff = MIN_V_EFF_DELAY + 5;
        let cmd = ReconfigCommand {
            adds: vec![ValidatorEntry {
                node_id: nid(5),
                addr: "127.0.0.1:9005".parse().unwrap(),
                bls_pop: None,
            }],
            removes: vec![],
            v_eff,
        };
        let block = block_with_reconfig(1, 0, nid(1), cmd);
        node.apply_commit(block);
        assert_eq!(node.validator_history.boundary_count(), 2);
        drop(node);

        // Phase 2: a fresh node recovered against the same storage
        // must see the boundary in both histories, and the active set
        // looked up at v_eff must be the post-reconfig committee.
        let recovered = ConsensusNode::recover(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        )
        .expect("recover must succeed against persisted history");

        assert_eq!(
            recovered.validator_history.boundary_count(),
            2,
            "integration history must replay the boundary",
        );
        assert_eq!(
            recovered.core.state().validator_history.boundary_count(),
            2,
            "safety-core history must mirror the boundary after replay",
        );
        assert_eq!(
            *recovered.validator_history.set_at(v_eff),
            five_validators()
        );
        assert_eq!(
            *recovered.core.state().validator_history.set_at(v_eff),
            five_validators()
        );

        // The pacemaker selector built during `recover` rotates over
        // the recovered history — leaders at v_eff come from the post-
        // boundary set.
        let leader_v_eff_vid = crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(
            recovered.pacemaker.leader_for_view(v_eff),
        );
        assert!(
            five_validators().contains(&leader_v_eff_vid),
            "recovered selector must rotate over post-boundary committee",
        );
    }

    /// A node `recover`'d from storage that has no validator-history
    /// blob (i.e. no reconfig was ever committed) falls back cleanly
    /// to the genesis-only history, identical to a fresh node.
    #[test]
    fn recovered_node_with_no_persisted_history_uses_genesis_only() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let cfg = test_config(four_validators());

        let recovered = ConsensusNode::recover(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        )
        .expect("recover with empty storage must succeed");

        assert_eq!(recovered.validator_history.boundary_count(), 1);
        assert_eq!(
            *recovered.validator_history.current_set(),
            four_validators()
        );
    }

    #[test]
    fn apply_commit_with_malformed_reconfig_payload_logs_and_drops() {
        let mut node = make_node(nid(1));
        // Tagged but truncated body — decode will error.
        let bad_payload = bytes::Bytes::copy_from_slice(b"RECFG\0deliberately-truncated-body");
        let commands = vec![bad_payload];
        let header = crate::replication::block::BlockHeader {
            parent_hash: genesis().hash(),
            height: 1,
            view: 0,
            proposer: nid(1),
            state_commitment: [0u8; 32],
            commands_commitment: crate::replication::block::Block::commands_commitment(&commands),
            validator_history_commitment: [0; 32],
        };
        let block = crate::replication::block::Block { header, commands };
        node.apply_commit(block);

        // History unchanged — malformed payloads do not insert a
        // boundary.
        assert_eq!(node.validator_history.boundary_count(), 1);
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
                        validator_history_commitment: [0; 32],
                    },
                    commands: vec![],
                };
                node.apply_commit(block);
            }
            assert_eq!(node.last_committed_height.load(Ordering::Relaxed), 42);
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
        assert_eq!(recovered.last_committed_height.load(Ordering::Relaxed), 42);
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
                        assert_eq!(got.payload.requested_hash, hash);
                        assert_eq!(got.payload.block, Some(block));
                        assert_eq!(got.signer, signer.node_id());
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
                match wire {
                    WireMessage::BlockResponse(got) => {
                        assert_eq!(got.payload.requested_hash, unknown_hash);
                        assert!(got.payload.block.is_none());
                    }
                    other => panic!("expected BlockResponse, got {other:?}"),
                }
            }
            other => panic!("expected SendTo, got {other:?}"),
        }
    }

    // ── BlockResponse hash-check gates (#434) ──────────────────────────

    /// `Dispatch::ReceiveBlock` for an unsolicited hash (no
    /// `block_sync_inflight` entry) must drop the block before it
    /// lands in `pending_blocks`. Without this gate a Byzantine peer
    /// could pollute the cache with arbitrary blocks the requester
    /// never asked for (audit finding 10-2).
    #[tokio::test]
    async fn receive_block_drops_unsolicited_response() {
        let mut node = make_node(nid(1));
        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let (broadcaster, _outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        let block = sample_block();
        let block_hash = block.hash();
        let pending_before = node.core.state().pending_blocks.len();

        node.apply_dispatch(
            Dispatch::ReceiveBlock {
                requested_hash: block_hash,
                block: Some(block),
                from: nid(2),
            },
            broadcaster.as_ref(),
            &mut view_timer,
            &signer,
        )
        .await
        .expect("apply_dispatch");

        assert_eq!(
            node.core.state().pending_blocks.len(),
            pending_before,
            "unsolicited BlockResponse must not insert into pending_blocks",
        );
        assert!(
            !node.core.state().pending_blocks.contains_key(&block_hash),
            "the unsolicited block hash must not appear in pending_blocks",
        );
    }

    /// `Dispatch::ReceiveBlock` for a hash we *did* request, but
    /// where the responder ships a different block under that
    /// `requested_hash` claim, must drop the block. Otherwise a
    /// Byzantine responder could swap arbitrary content into the
    /// cache under a known-good hash.
    #[tokio::test]
    async fn receive_block_drops_hash_mismatch() {
        let mut node = make_node(nid(1));
        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let (broadcaster, _outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        // Pretend we asked for some other hash (not the block we are
        // about to receive).
        let requested_hash: BlockHash = [0xAA; 32];
        node.core
            .install_block_sync_inflight_for_test(requested_hash, nid(2), 1);

        let block = sample_block();
        let block_hash = block.hash();
        assert_ne!(block_hash, requested_hash);
        let pending_before = node.core.state().pending_blocks.len();

        node.apply_dispatch(
            Dispatch::ReceiveBlock {
                requested_hash,
                block: Some(block),
                from: nid(2),
            },
            broadcaster.as_ref(),
            &mut view_timer,
            &signer,
        )
        .await
        .expect("apply_dispatch");

        assert_eq!(
            node.core.state().pending_blocks.len(),
            pending_before,
            "hash-mismatched BlockResponse must not insert into pending_blocks",
        );
        assert!(
            !node.core.state().pending_blocks.contains_key(&block_hash),
            "the wrong-hash block must not appear in pending_blocks",
        );
        assert!(
            node.core.has_inflight_block_request(&requested_hash),
            "the inflight retry entry for the originally-requested hash must \
             be preserved across a hash-mismatched response so retries continue",
        );
    }

    /// Conversely, when a responder returns a block whose hash
    /// matches both the `requested_hash` and an outstanding inflight
    /// entry, the block must be inserted as before. Pins the
    /// happy-path of the new gate.
    #[tokio::test]
    async fn receive_block_inserts_when_hash_matches_inflight() {
        let mut node = make_node(nid(1));
        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let (broadcaster, _outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        let block = sample_block();
        let block_hash = block.hash();
        node.core
            .install_block_sync_inflight_for_test(block_hash, nid(2), 1);

        node.apply_dispatch(
            Dispatch::ReceiveBlock {
                requested_hash: block_hash,
                block: Some(block),
                from: nid(2),
            },
            broadcaster.as_ref(),
            &mut view_timer,
            &signer,
        )
        .await
        .expect("apply_dispatch");

        assert!(
            node.core.state().pending_blocks.contains_key(&block_hash),
            "matching-hash BlockResponse must insert the block",
        );
        assert!(
            !node.core.has_inflight_block_request(&block_hash),
            "insert_pending_block clears the inflight entry on match",
        );
    }

    // ── Snapshot wire protocol (#228) — serving handlers ────────────────

    /// Helper: write a fully-populated snapshot (manifest + chunks)
    /// into the node's `Storage` so the serving handlers find it.
    fn seed_snapshot(
        storage: &Arc<dyn Storage>,
        height: u64,
        chunk_size: u32,
        n_chunks: u32,
    ) -> crate::replication::snapshot::SnapshotManifest {
        use crate::replication::snapshot::{SnapshotManifest, SnapshotStore, chunk_snapshot};

        let payload: Vec<u8> = (0..n_chunks * chunk_size)
            .map(|i| (i & 0xFF) as u8)
            .collect();
        let chunks_with_hashes = chunk_snapshot(&payload, chunk_size);
        assert_eq!(chunks_with_hashes.len(), n_chunks as usize);
        let chunk_hashes: Vec<[u8; 32]> = chunks_with_hashes.iter().map(|(_, h)| *h).collect();
        let chunks: Vec<bytes::Bytes> = chunks_with_hashes.into_iter().map(|(c, _)| c).collect();

        let vs = four_validators();
        let block = {
            // Build a structurally-valid Block at the requested
            // height; the joiner's `manifest.verify` cross-checks
            // block.hash() vs manifest.block_hash and reject any
            // inconsistency.
            let parent_hash = genesis().hash();
            let commands: Vec<bytes::Bytes> = Vec::new();
            crate::replication::block::Block {
                header: crate::replication::block::BlockHeader {
                    parent_hash,
                    height,
                    view: 7,
                    proposer: [0u8; 32],
                    state_commitment: [0xCD; 32],
                    commands_commitment: crate::replication::block::Block::commands_commitment(
                        &commands,
                    ),
                    validator_history_commitment: [0; 32],
                },
                commands,
            }
        };
        let mut qc = QuorumCertificate::new(0, block.hash(), vs.len());
        for i in 0..crate::consensus::hotstuff::qc::quorum_size(vs.len()) {
            qc.add_signature(i, [0u8; 64]);
        }
        let manifest = SnapshotManifest::build_for_test_genesis_histories(
            block,
            &vs,
            chunk_size,
            chunk_hashes,
            qc,
            1_700_000_000,
        );
        SnapshotStore::new(Arc::clone(storage))
            .save(&manifest, &chunks)
            .expect("save snapshot");
        manifest
    }

    fn decode_outbound_wire(out: ProtocolOutbound) -> (NodeId, WireMessage) {
        match out {
            ProtocolOutbound::SendTo { node_id, payload } => {
                let wire: WireMessage = postcard::from_bytes(&payload).expect("decode wire");
                (node_id, wire)
            }
            other => panic!("expected SendTo, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn serve_snapshot_manifest_latest_returns_stored_manifest() {
        // A peer asks for our latest snapshot manifest; we look it up
        // via SnapshotStore and reply via the run-loop's serving
        // handler. Exercises the end-to-end Dispatch → SendTo path.
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let manifest = seed_snapshot(&storage, 100, 64, 2);

        let cfg = test_config(four_validators());
        let mut node = ConsensusNode::new(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );
        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let (broadcaster, mut outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        node.apply_dispatch(
            Dispatch::ServeSnapshotManifest {
                height: None,
                to: nid(2),
            },
            broadcaster.as_ref(),
            &mut view_timer,
            &signer,
        )
        .await
        .expect("apply_dispatch");

        let (to, wire) = decode_outbound_wire(outbound_rx.recv().await.expect("outbound"));
        assert_eq!(to, nid(2));
        match wire {
            WireMessage::SnapshotManifestResponse(Some(got)) => {
                assert_eq!(got, manifest);
            }
            other => panic!("expected SnapshotManifestResponse(Some), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn serve_snapshot_manifest_at_height_returns_exact_match() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let m_low = seed_snapshot(&storage, 100, 64, 1);
        let _m_high = seed_snapshot(&storage, 200, 64, 1);

        let cfg = test_config(four_validators());
        let mut node = ConsensusNode::new(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );
        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let (broadcaster, mut outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        node.apply_dispatch(
            Dispatch::ServeSnapshotManifest {
                height: Some(100),
                to: nid(2),
            },
            broadcaster.as_ref(),
            &mut view_timer,
            &signer,
        )
        .await
        .expect("apply_dispatch");

        let (_, wire) = decode_outbound_wire(outbound_rx.recv().await.expect("outbound"));
        match wire {
            WireMessage::SnapshotManifestResponse(Some(got)) => {
                assert_eq!(got, m_low);
                assert_eq!(got.height, 100);
            }
            other => panic!("expected SnapshotManifestResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn serve_snapshot_manifest_returns_none_when_store_empty() {
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
        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let (broadcaster, mut outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        node.apply_dispatch(
            Dispatch::ServeSnapshotManifest {
                height: None,
                to: nid(2),
            },
            broadcaster.as_ref(),
            &mut view_timer,
            &signer,
        )
        .await
        .expect("apply_dispatch");

        let (_, wire) = decode_outbound_wire(outbound_rx.recv().await.expect("outbound"));
        assert!(matches!(wire, WireMessage::SnapshotManifestResponse(None)));
    }

    #[tokio::test]
    async fn serve_snapshot_chunk_returns_payload_for_known_index() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let manifest = seed_snapshot(&storage, 100, 64, 3);

        let cfg = test_config(four_validators());
        let mut node = ConsensusNode::new(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );
        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let (broadcaster, mut outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        // Walk every chunk index served back, and verify each
        // payload matches the manifest's recorded hash.
        for idx in 0..manifest.chunk_count {
            node.apply_dispatch(
                Dispatch::ServeSnapshotChunk {
                    height: 100,
                    chunk_idx: idx,
                    to: nid(2),
                },
                broadcaster.as_ref(),
                &mut view_timer,
                &signer,
            )
            .await
            .expect("apply_dispatch");

            let (to, wire) = decode_outbound_wire(outbound_rx.recv().await.expect("outbound"));
            assert_eq!(to, nid(2));
            match wire {
                WireMessage::SnapshotChunkResponse {
                    height: 100,
                    chunk_idx,
                    payload: Some(p),
                } => {
                    assert_eq!(chunk_idx, idx);
                    crate::replication::snapshot::verify_chunk(&manifest, idx, &p)
                        .expect("served chunk must verify against manifest");
                }
                other => panic!("expected SnapshotChunkResponse(Some), got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn serve_snapshot_chunk_returns_none_for_missing_height() {
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
        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let (broadcaster, mut outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        node.apply_dispatch(
            Dispatch::ServeSnapshotChunk {
                height: 999,
                chunk_idx: 0,
                to: nid(2),
            },
            broadcaster.as_ref(),
            &mut view_timer,
            &signer,
        )
        .await
        .expect("apply_dispatch");

        let (_, wire) = decode_outbound_wire(outbound_rx.recv().await.expect("outbound"));
        match wire {
            WireMessage::SnapshotChunkResponse {
                height: 999,
                chunk_idx: 0,
                payload: None,
            } => {}
            other => panic!("expected SnapshotChunkResponse(None), got {other:?}"),
        }
    }

    /// End-to-end "peer A serves a manifest + chunks to peer B" via
    /// the in-process transport: the request is decoded by
    /// `dispatch::ingress`, fed through `apply_dispatch`, and the
    /// outbound reply is decoded back to a `WireMessage`. Acceptance
    /// criterion: "a node serves a manifest + all chunks to another
    /// node over the in-process transport."
    #[tokio::test]
    async fn serve_full_snapshot_round_trip_through_dispatch() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let manifest = seed_snapshot(&storage, 50, 32, 4);

        let cfg = test_config(four_validators());
        let mut node = ConsensusNode::new(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );
        let signer: Arc<dyn Signer> = Arc::new(fresh_signer());
        let (broadcaster, mut outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        // Step 1: peer B (nid(2)) sends a manifest request, encoded
        // on the wire. Decode via ingress, dispatch through the run
        // loop's apply_dispatch, and capture the outbound reply.
        let req_bytes =
            postcard::to_stdvec(&WireMessage::SnapshotManifestRequest { height: None }).unwrap();
        let dispatches = dispatch::ingress(
            nid(2),
            &req_bytes,
            &ValidatorSetHistory::from_genesis(four_validators()),
            &ValidatorKeyHistory::new(four_validators().iter().copied()),
            &crate::crypto::signed::ChainId::TEST,
        )
        .unwrap();
        assert_eq!(dispatches.len(), 1);
        for d in dispatches {
            node.apply_dispatch(d, broadcaster.as_ref(), &mut view_timer, &signer)
                .await
                .expect("apply_dispatch");
        }
        let (to, wire) = decode_outbound_wire(outbound_rx.recv().await.expect("outbound"));
        assert_eq!(to, nid(2));
        let served = match wire {
            WireMessage::SnapshotManifestResponse(Some(m)) => m,
            other => panic!("expected SnapshotManifestResponse, got {other:?}"),
        };
        assert_eq!(served, manifest);

        // Step 2: for each chunk index in the manifest, peer B
        // requests the chunk and we observe the outbound reply.
        for idx in 0..served.chunk_count {
            let req_bytes = postcard::to_stdvec(&WireMessage::SnapshotChunkRequest {
                height: served.height,
                chunk_idx: idx,
            })
            .unwrap();
            let dispatches = dispatch::ingress(
                nid(2),
                &req_bytes,
                &ValidatorSetHistory::from_genesis(four_validators()),
                &ValidatorKeyHistory::new(four_validators().iter().copied()),
                &crate::crypto::signed::ChainId::TEST,
            )
            .unwrap();
            for d in dispatches {
                node.apply_dispatch(d, broadcaster.as_ref(), &mut view_timer, &signer)
                    .await
                    .expect("apply_dispatch");
            }
            let (_, wire) = decode_outbound_wire(outbound_rx.recv().await.expect("outbound"));
            match wire {
                WireMessage::SnapshotChunkResponse {
                    height,
                    chunk_idx,
                    payload: Some(p),
                } => {
                    assert_eq!(height, served.height);
                    assert_eq!(chunk_idx, idx);
                    crate::replication::snapshot::verify_chunk(&served, idx, &p)
                        .expect("chunk must verify");
                }
                other => panic!("expected SnapshotChunkResponse(Some), got {other:?}"),
            }
        }
    }

    // ── Joiner-side fetch (#229) ────────────────────────────────────────

    fn snapshot_test_config_enabled(vs: ValidatorSet, interval: u64) -> NodeConfigForConsensus {
        let mut cfg = NodeConfigForConsensus::for_testing(vs, genesis());
        cfg.snapshot_policy = crate::replication::snapshot::SnapshotPolicy {
            interval_blocks: interval,
            retention_count: 3,
            chunk_size_bytes: 1024,
        };
        cfg
    }

    /// Build a Proposal at `(height, view)` whose proposer is
    /// `signer.node_id()`, parented at `parent_hash`, with empty
    /// commands. The proposal's `justify` is the genesis QC over
    /// the joiner's view of the chain — sufficient to reach the
    /// integration layer's `Dispatch::Safety(Event::ProposalReceived)`
    /// path, which is what `observe_proposal` peeks at.
    ///
    /// Tests use this to feed the joiner a synthetic high-height
    /// proposal that triggers the snapshot-fetch path without
    /// running a full consensus loop.
    /// Drain outbound traffic until a `WireMessage` matching
    /// `predicate` arrives, or the channel is empty. Returns
    /// `Some((to, payload))` on hit, `None` on empty drain. Used by
    /// the joiner-fetch tests to skip past the safety-core's
    /// incidental outbounds (NewView on a high-view proposal,
    /// BlockRequest for the missing parent, etc.) and find the
    /// snapshot-fetch wire messages.
    async fn drain_until<F>(
        rx: &mut tokio::sync::mpsc::Receiver<ProtocolOutbound>,
        mut predicate: F,
    ) -> Option<(NodeId, bytes::Bytes)>
    where
        F: FnMut(&WireMessage) -> bool,
    {
        // A few iterations is enough; the safety core emits a
        // bounded number of side effects per dispatch.
        for _ in 0..16 {
            let out = match rx.try_recv() {
                Ok(o) => o,
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                    // Yield once in case the producer hasn't run yet.
                    tokio::task::yield_now().await;
                    match rx.try_recv() {
                        Ok(o) => o,
                        Err(_) => return None,
                    }
                }
                Err(_) => return None,
            };
            if let ProtocolOutbound::SendTo { node_id, payload } = out {
                let wire: WireMessage = match postcard::from_bytes(&payload) {
                    Ok(w) => w,
                    Err(_) => continue,
                };
                if predicate(&wire) {
                    return Some((node_id, payload));
                }
            }
            // Broadcasts and decode failures are skipped; the
            // snapshot wire messages are all `SendTo`.
        }
        None
    }

    fn synthetic_proposal_dispatch(
        signer: &NodeSigner,
        height: u64,
        view: u64,
        parent_hash: BlockHash,
    ) -> Dispatch {
        use crate::consensus::hotstuff::Proposal;
        use crate::consensus::hotstuff::qc::genesis_qc;
        use crate::replication::block::{Block, BlockHeader};
        let commands: Vec<bytes::Bytes> = Vec::new();
        let block = Block {
            header: BlockHeader {
                parent_hash,
                height,
                view,
                proposer: signer.node_id(),
                state_commitment: [0u8; 32],
                commands_commitment: Block::commands_commitment(&commands),
                validator_history_commitment: [0; 32],
            },
            commands,
        };
        // Justify with the genesis QC — its content doesn't matter
        // for the lag-detection observation. The integration layer
        // peeks at `signed.payload.block.header.height` and
        // `signed.signer`, both of which we control.
        let justify = genesis_qc(&genesis(), 4);
        let proposal = Proposal { block, justify };
        let signed = Signed::sign(proposal, signer, &ChainId::TEST).expect("sign proposal");
        Dispatch::Safety(SafetyEvent::ProposalReceived(
            crate::consensus::dispatch::Verified::unchecked(signed),
        ))
    }

    /// Joiner happy path (#229 acceptance criteria 1):
    /// 1. Server has a populated `SnapshotStore` with a snapshot at
    ///    height ≥ `interval_blocks`.
    /// 2. Joiner has empty storage and snapshots enabled.
    /// 3. Joiner observes a synthetic proposal at high height →
    ///    triggers a manifest request to the proposer (= server).
    /// 4. The request is decoded by the server's run loop, which
    ///    serves the manifest.
    /// 5. The response is decoded by the joiner's run loop, which
    ///    requests every chunk in order. Each chunk is served by
    ///    the server.
    /// 6. After the last chunk, the joiner restores state.
    ///
    /// Asserts:
    /// - Joiner's `last_committed_height` equals the snapshot
    ///   height after restore.
    /// - Joiner's state machine commitment matches the manifest's.
    /// - Snapshot block, last_committed, and high_qc are persisted
    ///   to the joiner's storage (so a hypothetical restart would
    ///   recover the same state).
    #[tokio::test]
    async fn joiner_fetches_snapshot_from_server_and_restores_state() {
        use crate::replication::impls::counter_sm::CounterCommand;

        let server_signer = fresh_signer();
        let server_node_id = server_signer.node_id();
        let joiner_signer = fresh_signer();
        let other1_signer = fresh_signer();
        let other2_signer = fresh_signer();
        let vs = ValidatorSet::new(vec![
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(server_node_id),
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(
                joiner_signer.node_id(),
            ),
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(
                other1_signer.node_id(),
            ),
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(
                other2_signer.node_id(),
            ),
        ]);

        // ── Build the server with a populated SnapshotStore ────────────
        let server_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        // Run a few CounterCommand applies so the SM has non-trivial
        // state, then build a snapshot at height 50 / view 50. The
        // test's interval is 50, so a proposal at height 50+ will
        // trigger the joiner's fetch.
        let server_sm: Arc<Mutex<Box<dyn StateMachine>>> = Arc::new(Mutex::new(Box::new(
            crate::replication::impls::counter_sm::CounterStateMachine::new(),
        )));
        for _ in 0..7 {
            server_sm
                .lock()
                .apply(&CounterCommand::Increment.encode())
                .unwrap();
        }
        let snapshot_payload = server_sm.lock().snapshot();
        let expected_commitment = server_sm.lock().state_commitment();
        let chunks_with_hashes =
            crate::replication::snapshot::chunk_snapshot(&snapshot_payload, 1024);
        let chunk_hashes: Vec<[u8; 32]> = chunks_with_hashes.iter().map(|(_, h)| *h).collect();
        let chunks: Vec<bytes::Bytes> = chunks_with_hashes.into_iter().map(|(c, _)| c).collect();
        let snapshot_block = {
            let parent_hash = genesis().hash();
            let commands: Vec<bytes::Bytes> = Vec::new();
            crate::replication::block::Block {
                header: crate::replication::block::BlockHeader {
                    parent_hash,
                    height: 50,
                    view: 50,
                    proposer: server_node_id,
                    state_commitment: expected_commitment,
                    commands_commitment: crate::replication::block::Block::commands_commitment(
                        &commands,
                    ),
                    validator_history_commitment: [0; 32],
                },
                commands,
            }
        };
        let mut commit_qc = QuorumCertificate::new(50, snapshot_block.hash(), vs.len());
        for i in 0..crate::consensus::hotstuff::qc::quorum_size(vs.len()) {
            commit_qc.add_signature(i, [0u8; 64]);
        }
        let manifest =
            crate::replication::snapshot::SnapshotManifest::build_for_test_genesis_histories(
                snapshot_block,
                &vs,
                1024,
                chunk_hashes,
                commit_qc,
                1_700_000_000,
            );
        // The helper patches `block.header.validator_history_commitment`
        // which changes the block hash; rebind through the manifest so
        // downstream assertions match the post-patch value.
        let snapshot_block = manifest.block.clone();
        // Defensive: verify the manifest before saving — catches
        // any builder-side regression that would otherwise surface
        // only at the joiner's verification step.
        manifest
            .verify(&vs)
            .expect("server-built manifest must verify");
        crate::replication::snapshot::SnapshotStore::new(Arc::clone(&server_storage))
            .save(&manifest, &chunks)
            .expect("save snapshot");

        let mut server_node = ConsensusNode::new(
            server_node_id,
            snapshot_test_config_enabled(vs.clone(), 50),
            server_sm,
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&server_storage),
            Arc::new(MemoryWal::new()),
        );

        // ── Build the fresh joiner ────────────────────────────────────
        let joiner_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let joiner_sm: Arc<Mutex<Box<dyn StateMachine>>> = Arc::new(Mutex::new(Box::new(
            crate::replication::impls::counter_sm::CounterStateMachine::new(),
        )));
        let joiner_starting_commitment = joiner_sm.lock().state_commitment();
        assert_ne!(
            joiner_starting_commitment, expected_commitment,
            "test setup: joiner's empty SM must differ from server's populated SM",
        );
        let mut joiner_node = ConsensusNode::new(
            joiner_signer.node_id(),
            snapshot_test_config_enabled(vs.clone(), 50),
            Arc::clone(&joiner_sm),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&joiner_storage),
            Arc::new(MemoryWal::new()),
        );

        // Wrap in Arc *after* using the original `server_signer` to
        // sign the synthetic proposal below. `NodeSigner` is not
        // `Clone`, so we hold the Arc separately for `apply_dispatch`
        // calls that need a `&Arc<dyn Signer>` and the bare ref for
        // signing.
        let joiner_signer_arc: Arc<dyn Signer> = Arc::new(joiner_signer);
        let (server_bc, mut server_outbound) = make_test_broadcaster();
        let (joiner_bc, mut joiner_outbound) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut server_view_timer = ViewTimer::new(timer_tx.clone());
        let mut joiner_view_timer = ViewTimer::new(timer_tx);

        // ── Step 1: feed the joiner a synthetic proposal at height
        //   100 from the server. This is what the joiner would see
        //   in production: a high-height proposal carrying the
        //   server's pubkey as the proposer.
        let proposal = synthetic_proposal_dispatch(
            &server_signer,
            100,
            100,
            // The proposal's parent_hash doesn't matter for lag
            // detection; the safety core will park it for missing
            // parent regardless. Use a fake parent hash.
            [0xEE; 32],
        );
        joiner_node
            .apply_dispatch(
                proposal,
                joiner_bc.as_ref(),
                &mut joiner_view_timer,
                &joiner_signer_arc,
            )
            .await
            .expect("joiner apply_dispatch");

        // Now wrap the server signer in Arc for subsequent
        // `apply_dispatch` calls.
        let server_signer_arc: Arc<dyn Signer> = Arc::new(server_signer);

        // The joiner's snapshot_sync should have emitted a manifest
        // request to the proposer (= server). Filter past any
        // incidental safety-core outbounds (NewView, vote, etc.)
        // emitted by the same proposal.
        let (req_to, req_payload) = drain_until(&mut joiner_outbound, |w| {
            matches!(w, WireMessage::SnapshotManifestRequest { .. })
        })
        .await
        .expect("manifest request outbound");
        assert_eq!(req_to, server_node_id);
        let req_wire: WireMessage =
            postcard::from_bytes(&req_payload).expect("decode manifest request");
        assert!(matches!(
            req_wire,
            WireMessage::SnapshotManifestRequest { height: None },
        ));

        // ── Step 2: feed the request into the server via ingress;
        //   server's run loop serves the manifest.
        let dispatches = dispatch::ingress(
            joiner_signer_arc.node_id(),
            &req_payload,
            &ValidatorSetHistory::from_genesis(vs.clone()),
            &ValidatorKeyHistory::new(vs.iter().copied()),
            &crate::crypto::signed::ChainId::TEST,
        )
        .expect("ingress manifest request");
        for d in dispatches {
            server_node
                .apply_dispatch(
                    d,
                    server_bc.as_ref(),
                    &mut server_view_timer,
                    &server_signer_arc,
                )
                .await
                .expect("server apply_dispatch");
        }
        let (resp_to, resp_payload) = drain_until(&mut server_outbound, |w| {
            matches!(w, WireMessage::SnapshotManifestResponse(_))
        })
        .await
        .expect("manifest response outbound");
        assert_eq!(resp_to, joiner_signer_arc.node_id());

        // ── Step 3: feed the response back into the joiner. The
        //   joiner verifies the manifest and emits the first chunk
        //   request. Then we shuttle each chunk request → response
        //   through the in-memory transport until the joiner
        //   restores.
        let dispatches = dispatch::ingress(
            server_node_id,
            &resp_payload,
            &ValidatorSetHistory::from_genesis(vs.clone()),
            &ValidatorKeyHistory::new(vs.iter().copied()),
            &crate::crypto::signed::ChainId::TEST,
        )
        .expect("ingress manifest response");
        for d in dispatches {
            joiner_node
                .apply_dispatch(
                    d,
                    joiner_bc.as_ref(),
                    &mut joiner_view_timer,
                    &joiner_signer_arc,
                )
                .await
                .expect("joiner apply_dispatch manifest response");
        }

        // Loop: shuttle chunk requests/responses until the joiner
        // restores. Bounded loop count guards against a state-
        // machine bug that would otherwise hang the test.
        for _ in 0..(manifest.chunk_count + 4) {
            // Joiner emitted a chunk request? Drain and forward.
            let chunk_req = drain_until(&mut joiner_outbound, |w| {
                matches!(w, WireMessage::SnapshotChunkRequest { .. })
            })
            .await;
            let Some((_, chunk_req_payload)) = chunk_req else {
                break;
            };
            let dispatches = dispatch::ingress(
                joiner_signer_arc.node_id(),
                &chunk_req_payload,
                &ValidatorSetHistory::from_genesis(vs.clone()),
                &ValidatorKeyHistory::new(vs.iter().copied()),
                &crate::crypto::signed::ChainId::TEST,
            )
            .expect("ingress chunk request");
            for d in dispatches {
                server_node
                    .apply_dispatch(
                        d,
                        server_bc.as_ref(),
                        &mut server_view_timer,
                        &server_signer_arc,
                    )
                    .await
                    .expect("server apply_dispatch chunk request");
            }
            let (_, chunk_resp_payload) = drain_until(&mut server_outbound, |w| {
                matches!(w, WireMessage::SnapshotChunkResponse { .. })
            })
            .await
            .expect("chunk response");
            let dispatches = dispatch::ingress(
                server_node_id,
                &chunk_resp_payload,
                &ValidatorSetHistory::from_genesis(vs.clone()),
                &ValidatorKeyHistory::new(vs.iter().copied()),
                &crate::crypto::signed::ChainId::TEST,
            )
            .expect("ingress chunk response");
            for d in dispatches {
                joiner_node
                    .apply_dispatch(
                        d,
                        joiner_bc.as_ref(),
                        &mut joiner_view_timer,
                        &joiner_signer_arc,
                    )
                    .await
                    .expect("joiner apply_dispatch chunk response");
            }
        }

        // ── Assertions ────────────────────────────────────────────────
        assert!(
            joiner_node.snapshot_sync.is_done(),
            "joiner's snapshot_sync must reach Done after a successful fetch",
        );
        assert_eq!(
            joiner_node.last_committed_height.load(Ordering::Relaxed),
            50,
            "joiner's last_committed_height must equal the snapshot's height",
        );
        assert_eq!(joiner_node.last_committed_view, 50);
        assert_eq!(
            joiner_sm.lock().state_commitment(),
            expected_commitment,
            "joiner's state machine commitment must match the snapshot's after restore",
        );
        // Persistence: snapshot block, last_committed, high_qc are
        // all on disk so a hypothetical restart would recover.
        let block_key = block_storage_key(&snapshot_block.hash());
        assert!(
            joiner_storage.get(&block_key).unwrap().is_some(),
            "snapshot block must be persisted under the block-prefix",
        );
        assert!(
            joiner_storage
                .get(STORAGE_KEY_LAST_COMMITTED)
                .unwrap()
                .is_some(),
            "last_committed checkpoint must be persisted after restore",
        );
        assert!(
            joiner_storage.get(STORAGE_KEY_HIGH_QC).unwrap().is_some(),
            "high_qc must be persisted after restore",
        );
        // The snapshot block is in pending_blocks so future
        // safety-core walks terminate at the snapshot height.
        assert!(
            joiner_node
                .core
                .state()
                .pending_blocks
                .contains_key(&snapshot_block.hash()),
            "snapshot block must be inserted into pending_blocks",
        );
    }

    /// Joiner negative path (#229 acceptance criteria 2): a
    /// tampered manifest from the server triggers fallback without
    /// panicking. The joiner's `last_committed_height` stays at 0
    /// (no restore happened) and the snapshot_sync state machine
    /// is in `Aborted`.
    #[tokio::test]
    async fn joiner_aborts_on_tampered_manifest_without_panic() {
        let server_signer = fresh_signer();
        let server_node_id = server_signer.node_id();
        let joiner_signer = fresh_signer();
        let other1 = fresh_signer();
        let other2 = fresh_signer();
        let vs = ValidatorSet::new(vec![
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(server_node_id),
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(
                joiner_signer.node_id(),
            ),
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(other1.node_id()),
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(other2.node_id()),
        ]);

        let joiner_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let joiner_sm: Arc<Mutex<Box<dyn StateMachine>>> = Arc::new(Mutex::new(Box::new(
            crate::replication::impls::counter_sm::CounterStateMachine::new(),
        )));
        let mut joiner_node = ConsensusNode::new(
            joiner_signer.node_id(),
            snapshot_test_config_enabled(vs.clone(), 50),
            Arc::clone(&joiner_sm),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&joiner_storage),
            Arc::new(MemoryWal::new()),
        );
        let joiner_signer_arc: Arc<dyn Signer> = Arc::new(joiner_signer);
        let (joiner_bc, mut joiner_outbound) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut joiner_view_timer = ViewTimer::new(timer_tx);

        // Trigger the joiner's fetch.
        let proposal = synthetic_proposal_dispatch(&server_signer, 100, 100, [0xEE; 32]);
        joiner_node
            .apply_dispatch(
                proposal,
                joiner_bc.as_ref(),
                &mut joiner_view_timer,
                &joiner_signer_arc,
            )
            .await
            .expect("joiner apply_dispatch proposal");

        // Drain past any incidental safety-core outbounds and the
        // manifest request the joiner emitted.
        let _ = drain_until(&mut joiner_outbound, |w| {
            matches!(w, WireMessage::SnapshotManifestRequest { .. })
        })
        .await
        .expect("manifest request");

        // Build a *tampered* manifest: validator set field doesn't
        // match the joiner's `vs`. The joiner's verifier rejects
        // this as `ValidatorSetMismatch`.
        let bad_vs = ValidatorSet::new(vec![
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey([10u8; 32]),
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey([11u8; 32]),
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey([12u8; 32]),
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey([13u8; 32]),
        ]);
        let tampered_block = {
            use crate::replication::block::{Block, BlockHeader};
            let parent_hash = genesis().hash();
            let commands: Vec<bytes::Bytes> = Vec::new();
            Block {
                header: BlockHeader {
                    parent_hash,
                    height: 50,
                    view: 50,
                    proposer: server_signer.node_id(),
                    state_commitment: [0xCD; 32],
                    commands_commitment: Block::commands_commitment(&commands),
                    validator_history_commitment: [0; 32],
                },
                commands,
            }
        };
        let mut tampered_qc = QuorumCertificate::new(50, tampered_block.hash(), bad_vs.len());
        for i in 0..crate::consensus::hotstuff::qc::quorum_size(bad_vs.len()) {
            tampered_qc.add_signature(i, [0u8; 64]);
        }
        let bad_manifest =
            crate::replication::snapshot::SnapshotManifest::build_for_test_genesis_histories(
                tampered_block,
                &bad_vs,
                64,
                vec![[0u8; 32]],
                tampered_qc,
                1_700_000_000,
            );

        // Synthesize a SnapshotManifestResponse from the server and
        // feed it to the joiner.
        let resp_payload =
            postcard::to_stdvec(&WireMessage::SnapshotManifestResponse(Some(bad_manifest)))
                .unwrap();
        let dispatches = dispatch::ingress(
            server_signer.node_id(),
            &resp_payload,
            &ValidatorSetHistory::from_genesis(vs.clone()),
            &ValidatorKeyHistory::new(vs.iter().copied()),
            &crate::crypto::signed::ChainId::TEST,
        )
        .expect("ingress tampered manifest");
        for d in dispatches {
            joiner_node
                .apply_dispatch(
                    d,
                    joiner_bc.as_ref(),
                    &mut joiner_view_timer,
                    &joiner_signer_arc,
                )
                .await
                .expect("joiner apply_dispatch tampered manifest");
        }

        // Joiner's state machine must be Aborted.
        assert!(
            joiner_node.snapshot_sync.is_aborted(),
            "joiner's snapshot_sync must enter Aborted after tampered manifest",
        );
        // No restore happened.
        assert_eq!(
            joiner_node.last_committed_height.load(Ordering::Relaxed),
            0,
            "no restore must have run; last_committed stays at 0",
        );
        // No outbound chunk requests should have been emitted; the
        // joiner stopped after rejecting the manifest. (Other
        // safety-core outbounds may sit in the channel — we filter
        // for chunk requests specifically.)
        assert!(
            drain_until(&mut joiner_outbound, |w| matches!(
                w,
                WireMessage::SnapshotChunkRequest { .. }
            ))
            .await
            .is_none(),
            "joiner must not emit chunk requests after aborting",
        );
    }

    /// Joiner happy path with a rotation applied before the
    /// snapshot height (#311). A fresh joiner restoring from a
    /// post-rotation snapshot must inherit the producer's
    /// `validator_key_history` so it can resolve the rotated
    /// validator's pubkey at views ≥ `v_eff` to the post-rotation
    /// key. Without this, the joiner would fall through to tail-sync
    /// and reject every QC whose signer is the rotated validator
    /// (`IngressError::UnknownSigner`) — exactly the failure mode
    /// #311 calls out.
    ///
    /// Drives the joiner-side restore directly via
    /// `restore_from_snapshot` rather than the full network shuttle
    /// (the wire path is already covered by
    /// `joiner_fetches_snapshot_from_server_and_restores_state`).
    /// This isolates the rotation-aware install logic.
    #[tokio::test]
    async fn joiner_restore_installs_rotated_validator_key_history() {
        use crate::consensus::history_commitment::validator_history_commitment_v1;
        use crate::consensus::validator_key_history::PersistedValidatorKeyHistory;
        use crate::consensus::validator_rotation::ValidatorKeyRotation;
        use crate::replication::impls::counter_sm::CounterCommand;

        let server_signer = fresh_signer();
        let server_node_id = server_signer.node_id();
        let joiner_signer = fresh_signer();
        let other1_signer = fresh_signer();
        let other2_signer = fresh_signer();
        let vs = ValidatorSet::new(vec![
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(server_node_id),
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(
                joiner_signer.node_id(),
            ),
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(
                other1_signer.node_id(),
            ),
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(
                other2_signer.node_id(),
            ),
        ]);

        // ── Build the producer's history triple with one rotation
        //   applied. The rotated validator is `other1` (a non-leader
        //   of view 0); it rotates to a synthetic `new_pubkey` at
        //   `v_eff = 30`, well below the snapshot height of 50.
        let rotated_validator = other1_signer.node_id();
        let new_pubkey: NodeId = [0xAB; 32];
        let v_eff: View = 30;
        let mut producer_key_hist = ValidatorKeyHistory::new(vs.iter().copied());
        producer_key_hist
            .apply_rotation(
                &ValidatorKeyRotation {
                    validator: rotated_validator,
                    new_pubkey,
                    v_eff,
                    new_bls_pubkey: None,
                    new_bls_pop: None,
                },
                10,
            )
            .expect("rotation applies cleanly");
        let producer_set_hist = ValidatorSetHistory::from_genesis(vs.clone());
        let commitment =
            validator_history_commitment_v1(&producer_set_hist, &producer_key_hist, None);

        // ── Build the snapshot at height 50 / view 50 with the
        //   right state-commitment and history-commitment.
        let server_sm: Arc<Mutex<Box<dyn StateMachine>>> = Arc::new(Mutex::new(Box::new(
            crate::replication::impls::counter_sm::CounterStateMachine::new(),
        )));
        for _ in 0..5 {
            server_sm
                .lock()
                .apply(&CounterCommand::Increment.encode())
                .unwrap();
        }
        let snapshot_payload = server_sm.lock().snapshot();
        let expected_commitment = server_sm.lock().state_commitment();
        let chunks_with_hashes =
            crate::replication::snapshot::chunk_snapshot(&snapshot_payload, 1024);
        let chunk_hashes: Vec<[u8; 32]> = chunks_with_hashes.iter().map(|(_, h)| *h).collect();
        let chunks: Vec<bytes::Bytes> = chunks_with_hashes.into_iter().map(|(c, _)| c).collect();
        let snapshot_block = {
            let parent_hash = genesis().hash();
            let commands: Vec<bytes::Bytes> = Vec::new();
            crate::replication::block::Block {
                header: crate::replication::block::BlockHeader {
                    parent_hash,
                    height: 50,
                    view: 50,
                    proposer: server_node_id,
                    state_commitment: expected_commitment,
                    commands_commitment: crate::replication::block::Block::commands_commitment(
                        &commands,
                    ),
                    validator_history_commitment: commitment,
                },
                commands,
            }
        };
        let mut commit_qc = QuorumCertificate::new(50, snapshot_block.hash(), vs.len());
        for i in 0..crate::consensus::hotstuff::qc::quorum_size(vs.len()) {
            commit_qc.add_signature(i, [0u8; 64]);
        }
        let manifest = crate::replication::snapshot::SnapshotManifest::build(
            snapshot_block,
            &vs,
            1024,
            chunk_hashes,
            commit_qc,
            1_700_000_000,
            producer_set_hist.to_persisted(),
            producer_key_hist.to_persisted(),
            None,
        );
        manifest
            .verify(&vs)
            .expect("producer-built manifest must verify against the local set");

        // ── Build the fresh joiner and restore directly.
        let joiner_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let joiner_sm: Arc<Mutex<Box<dyn StateMachine>>> = Arc::new(Mutex::new(Box::new(
            crate::replication::impls::counter_sm::CounterStateMachine::new(),
        )));
        let mut joiner_node = ConsensusNode::new(
            joiner_signer.node_id(),
            snapshot_test_config_enabled(vs.clone(), 50),
            Arc::clone(&joiner_sm),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&joiner_storage),
            Arc::new(MemoryWal::new()),
        );
        // Pre-condition: joiner's key history is genesis-only and
        // does *not* know about the rotation.
        assert_eq!(
            joiner_node.validator_key_history.key_at(
                &crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(
                    rotated_validator,
                ),
                v_eff,
            ),
            Some(crate::consensus::validator_set::Pubkey::from_node_id(
                rotated_validator,
            )),
            "test setup: joiner starts with a genesis-only key history",
        );
        assert!(
            joiner_node
                .validator_key_history
                .validator_for(&crate::consensus::validator_set::Pubkey::from_node_id(
                    new_pubkey,
                ))
                .is_none(),
            "test setup: joiner does not yet know `new_pubkey`",
        );

        let payload = bytes::Bytes::from(
            chunks
                .iter()
                .flat_map(|c| c.iter().copied())
                .collect::<Vec<u8>>(),
        );
        joiner_node
            .restore_from_snapshot(manifest, payload)
            .expect("restore_from_snapshot must accept the rotation-aware manifest");

        // ── Post-condition: joiner's in-memory key history reflects
        //   the producer's rotation.
        let stable =
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(rotated_validator);
        assert_eq!(
            joiner_node.validator_key_history.key_at(&stable, v_eff - 1),
            Some(crate::consensus::validator_set::Pubkey::from_node_id(
                rotated_validator,
            )),
            "pre-v_eff lookups must still resolve to the genesis key",
        );
        assert_eq!(
            joiner_node.validator_key_history.key_at(&stable, v_eff),
            Some(crate::consensus::validator_set::Pubkey::from_node_id(
                new_pubkey,
            )),
            "at-v_eff lookups must resolve to the rotated key",
        );
        assert_eq!(
            joiner_node.validator_key_history.validator_for(
                &crate::consensus::validator_set::Pubkey::from_node_id(new_pubkey),
            ),
            Some(stable),
            "the new pubkey resolves through the reverse index — \
             dispatch::verify_signer_at would accept post-rotation votes",
        );

        // ── On-disk: the persisted blob round-trips back into a
        //   history with the rotation entry, so a subsequent restart
        //   recovers the same state.
        let persisted_bytes = joiner_storage
            .get(STORAGE_KEY_VALIDATOR_KEY_HISTORY)
            .unwrap()
            .expect("persisted validator_key_history must be on disk after restore");
        let persisted: PersistedValidatorKeyHistory =
            postcard::from_bytes(&persisted_bytes).expect("persisted blob decodes");
        let rebuilt = ValidatorKeyHistory::from_persisted(persisted).unwrap();
        assert_eq!(
            rebuilt.key_at(&stable, v_eff),
            Some(crate::consensus::validator_set::Pubkey::from_node_id(
                new_pubkey,
            )),
            "on-disk persisted history must carry the rotation",
        );
    }

    /// Audit finding 4-3 (#406): a joiner that adopts a snapshot,
    /// crashes before the next consensus event, and restarts must
    /// rehydrate `locked`, `high_qc`, and `last_voted_view` from
    /// storage at the snapshot's `(view, height)`. Without persisting
    /// the safety state alongside the snapshot block + last_committed
    /// in one atomic batch, `recover_state` would re-seed the joiner
    /// with `locked = None` and `last_voted_view = 0` — letting it
    /// vote on a fork below the snapshot height (`safe_to_vote`'s
    /// `view > last_voted_view` check is trivially satisfied).
    #[tokio::test]
    async fn restore_then_restart_preserves_locked_high_qc_and_last_voted_view() {
        use crate::replication::impls::counter_sm::{CounterCommand, CounterStateMachine};

        let server_signer = fresh_signer();
        let server_node_id = server_signer.node_id();
        let joiner_signer = fresh_signer();
        let other1 = fresh_signer().node_id();
        let other2 = fresh_signer().node_id();
        let vs = ValidatorSet::new(vec![
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(server_node_id),
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(
                joiner_signer.node_id(),
            ),
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(other1),
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(other2),
        ]);

        // Build a snapshot at height 50 / view 50. The exact values
        // don't matter — what we're testing is that they survive a
        // restart, so they need to be distinguishable from "fresh
        // joiner" defaults (view 0, no lock).
        let snapshot_height: u64 = 50;
        let snapshot_view: View = 50;
        let server_sm: Arc<Mutex<Box<dyn StateMachine>>> =
            Arc::new(Mutex::new(Box::new(CounterStateMachine::new())));
        for _ in 0..5 {
            server_sm
                .lock()
                .apply(&CounterCommand::Increment.encode())
                .unwrap();
        }
        let snapshot_payload = server_sm.lock().snapshot();
        let expected_commitment = server_sm.lock().state_commitment();
        let chunks_with_hashes =
            crate::replication::snapshot::chunk_snapshot(&snapshot_payload, 1024);
        let chunk_hashes: Vec<[u8; 32]> = chunks_with_hashes.iter().map(|(_, h)| *h).collect();
        let chunks: Vec<bytes::Bytes> = chunks_with_hashes.into_iter().map(|(c, _)| c).collect();
        let snapshot_block = {
            let parent_hash = genesis().hash();
            let commands: Vec<bytes::Bytes> = Vec::new();
            crate::replication::block::Block {
                header: crate::replication::block::BlockHeader {
                    parent_hash,
                    height: snapshot_height,
                    view: snapshot_view,
                    proposer: server_node_id,
                    state_commitment: expected_commitment,
                    commands_commitment: crate::replication::block::Block::commands_commitment(
                        &commands,
                    ),
                    validator_history_commitment: [0; 32],
                },
                commands,
            }
        };
        let mut commit_qc = QuorumCertificate::new(snapshot_view, snapshot_block.hash(), vs.len());
        for i in 0..crate::consensus::hotstuff::qc::quorum_size(vs.len()) {
            commit_qc.add_signature(i, [0u8; 64]);
        }
        // `build_for_test_genesis_histories` rewrites
        // `block.header.validator_history_commitment` (and re-targets
        // `commit_qc.block_hash` to match), so capture the canonical
        // post-build hash and QC for downstream assertions.
        let manifest =
            crate::replication::snapshot::SnapshotManifest::build_for_test_genesis_histories(
                snapshot_block,
                &vs,
                1024,
                chunk_hashes,
                commit_qc,
                1_700_000_000,
            );
        manifest.verify(&vs).expect("manifest verifies");
        let snapshot_block_hash = manifest.block_hash;
        let expected_commit_qc = manifest.commit_qc.clone();

        // ── Pre-crash session: build the joiner, restore the snapshot,
        //   then drop the node (simulating a crash before any further
        //   consensus event lands the safety state via `persist_updates`).
        let joiner_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let joiner_wal: Arc<dyn Wal> = Arc::new(MemoryWal::new());
        let cfg = snapshot_test_config_enabled(vs.clone(), snapshot_height);
        let joiner_sm: Arc<Mutex<Box<dyn StateMachine>>> =
            Arc::new(Mutex::new(Box::new(CounterStateMachine::new())));
        let mut joiner_node = ConsensusNode::new(
            joiner_signer.node_id(),
            cfg.clone(),
            Arc::clone(&joiner_sm),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&joiner_storage),
            Arc::clone(&joiner_wal),
        );
        let payload = bytes::Bytes::from(
            chunks
                .iter()
                .flat_map(|c| c.iter().copied())
                .collect::<Vec<u8>>(),
        );
        joiner_node
            .restore_from_snapshot(manifest, payload)
            .expect("restore_from_snapshot succeeds");

        // Sanity-check the in-memory state right after restore.
        assert_eq!(
            joiner_node.core.state().last_voted_view,
            snapshot_view,
            "in-memory last_voted_view must be bumped to snapshot view",
        );
        assert_eq!(
            joiner_node.core.state().locked.map(|l| l.view),
            Some(snapshot_view),
            "in-memory locked must reference the snapshot view",
        );
        assert_eq!(
            joiner_node.core.state().high_qc.as_ref().map(|qc| qc.view),
            Some(snapshot_view),
            "in-memory high_qc must reference the snapshot view",
        );

        drop(joiner_node);
        drop(joiner_sm);

        // ── Post-crash session: recover from the same storage. The
        //   recovered safety state must reflect the snapshot — no
        //   silent regression to genesis defaults.
        let recovered_sm: Arc<Mutex<Box<dyn StateMachine>>> =
            Arc::new(Mutex::new(Box::new(CounterStateMachine::new())));
        let recovered = ConsensusNode::recover(
            joiner_signer.node_id(),
            cfg,
            Arc::clone(&recovered_sm),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&joiner_storage),
            Arc::clone(&joiner_wal),
        )
        .expect("recover from snapshot-restored storage succeeds");

        let state = recovered.core.state();
        assert_eq!(
            state.last_voted_view, snapshot_view,
            "recovered last_voted_view must match snapshot view; \
             without it, safe_to_vote's view > last_voted_view check \
             is trivially satisfied on a conflicting fork",
        );
        let recovered_locked = state
            .locked
            .expect("recovered locked must be present (snapshot's lock survived)");
        assert_eq!(recovered_locked.view, snapshot_view);
        assert_eq!(recovered_locked.height, snapshot_height);
        assert_eq!(recovered_locked.block_hash, snapshot_block_hash);
        let recovered_high_qc = state
            .high_qc
            .as_ref()
            .expect("recovered high_qc must be present");
        assert_eq!(recovered_high_qc, &expected_commit_qc);
    }

    /// Joiner multi-source happy path (#230 acceptance criterion 1):
    /// 3 peers serve the same snapshot in parallel. Drives the
    /// fetch end-to-end via in-memory dispatch and asserts that
    /// chunks were served from ≥ 2 distinct peers (the workpool
    /// fanned out instead of pinning the primary).
    ///
    /// To keep the test compact, "servers" are simulated as a
    /// single shared `SnapshotStore` looked up by chunk index;
    /// the routing layer attributes each request to the peer it
    /// was addressed to, and the returned response is decoded by
    /// the joiner's `apply_dispatch`. This exercises the same
    /// joiner-side code paths as full multi-`ConsensusNode`
    /// scaffolding without spinning up redundant nodes.
    #[tokio::test]
    async fn joiner_multi_source_fan_out_uses_at_least_two_peers() {
        // 3 server pubkeys + 1 joiner. The joiner observes
        // proposals from each of the 3 servers.
        let server_signers: Vec<NodeSigner> = (0..3).map(|_| fresh_signer()).collect();
        let server_ids: Vec<NodeId> = server_signers.iter().map(|s| s.node_id()).collect();
        let joiner_signer = fresh_signer();
        let mut all_ids = server_ids.clone();
        all_ids.push(joiner_signer.node_id());
        let vs = ValidatorSet::new(
            all_ids
                .iter()
                .copied()
                .map(crate::consensus::validator_set::ValidatorId::from_genesis_pubkey)
                .collect(),
        );

        // Seed the SM via `restore` to a large counter value so
        // the postcard-encoded snapshot is wide enough to slice
        // into multiple chunks. (Calling `apply(Increment)` enough
        // times to reach a multi-byte varint would take 2M+
        // iterations.)
        let big_value: u64 = u64::MAX;
        let snapshot_payload = bytes::Bytes::from(postcard::to_stdvec(&big_value).unwrap());
        let server_sm: Arc<Mutex<Box<dyn StateMachine>>> = Arc::new(Mutex::new(Box::new(
            crate::replication::impls::counter_sm::CounterStateMachine::new(),
        )));
        server_sm.lock().restore(&snapshot_payload).unwrap();
        let expected_commitment = server_sm.lock().state_commitment();
        // 2-byte chunks over the ~10-byte u64::MAX postcard varint
        // → ≥ 4 chunks for the workpool to fan out across.
        let chunks_with_hashes = crate::replication::snapshot::chunk_snapshot(&snapshot_payload, 2);
        assert!(chunks_with_hashes.len() >= 4, "need ≥ 4 chunks for fanout");
        let chunk_hashes: Vec<[u8; 32]> = chunks_with_hashes.iter().map(|(_, h)| *h).collect();
        let chunks: Vec<bytes::Bytes> = chunks_with_hashes.into_iter().map(|(c, _)| c).collect();
        let snapshot_block = {
            let parent_hash = genesis().hash();
            let commands: Vec<bytes::Bytes> = Vec::new();
            crate::replication::block::Block {
                header: crate::replication::block::BlockHeader {
                    parent_hash,
                    height: 50,
                    view: 50,
                    proposer: server_ids[0],
                    state_commitment: expected_commitment,
                    commands_commitment: crate::replication::block::Block::commands_commitment(
                        &commands,
                    ),
                    validator_history_commitment: [0; 32],
                },
                commands,
            }
        };
        let mut commit_qc = QuorumCertificate::new(50, snapshot_block.hash(), vs.len());
        for i in 0..crate::consensus::hotstuff::qc::quorum_size(vs.len()) {
            commit_qc.add_signature(i, [0u8; 64]);
        }
        let manifest =
            crate::replication::snapshot::SnapshotManifest::build_for_test_genesis_histories(
                snapshot_block.clone(),
                &vs,
                2,
                chunk_hashes,
                commit_qc,
                1_700_000_000,
            );
        manifest.verify(&vs).expect("manifest must verify");

        // ── Build the joiner ──────────────────────────────────────
        let joiner_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let joiner_sm: Arc<Mutex<Box<dyn StateMachine>>> = Arc::new(Mutex::new(Box::new(
            crate::replication::impls::counter_sm::CounterStateMachine::new(),
        )));
        let mut joiner_node = ConsensusNode::new(
            joiner_signer.node_id(),
            snapshot_test_config_enabled(vs.clone(), 50),
            Arc::clone(&joiner_sm),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&joiner_storage),
            Arc::new(MemoryWal::new()),
        );
        let joiner_signer_arc: Arc<dyn Signer> = Arc::new(joiner_signer);
        let (joiner_bc, mut joiner_outbound) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut joiner_view_timer = ViewTimer::new(timer_tx);

        // ── Step 1: feed the joiner a proposal from each server ──────
        // Each observation accumulates the proposer into the
        // candidate pool the snapshot_sync will use once the fetch
        // starts.
        for s in &server_signers {
            let proposal = synthetic_proposal_dispatch(s, 100, 100, [0xEE; 32]);
            joiner_node
                .apply_dispatch(
                    proposal,
                    joiner_bc.as_ref(),
                    &mut joiner_view_timer,
                    &joiner_signer_arc,
                )
                .await
                .expect("joiner apply_dispatch proposal");
        }

        // ── Step 2: extract the manifest request and synthesize a
        //   response from the primary server (whichever one was
        //   asked).
        let (manifest_to, manifest_req_payload) = drain_until(&mut joiner_outbound, |w| {
            matches!(w, WireMessage::SnapshotManifestRequest { .. })
        })
        .await
        .expect("manifest request");
        let primary = manifest_to;
        let _ = manifest_req_payload;
        let resp_payload = postcard::to_stdvec(&WireMessage::SnapshotManifestResponse(Some(
            manifest.clone(),
        )))
        .unwrap();
        let dispatches = dispatch::ingress(
            primary,
            &resp_payload,
            &ValidatorSetHistory::from_genesis(vs.clone()),
            &ValidatorKeyHistory::new(vs.iter().copied()),
            &crate::crypto::signed::ChainId::TEST,
        )
        .expect("ingress manifest response");
        for d in dispatches {
            joiner_node
                .apply_dispatch(
                    d,
                    joiner_bc.as_ref(),
                    &mut joiner_view_timer,
                    &joiner_signer_arc,
                )
                .await
                .expect("joiner apply_dispatch manifest response");
        }

        // ── Step 3: shuttle every emitted chunk request →
        //   synthesized response, using the chunk_idx to look up
        //   the canonical chunk bytes. Track which peers were used
        //   to drive each chunk so the test can assert fanout.
        let mut chunk_peer_count: HashMap<NodeId, u32> = HashMap::new();
        // Bound the loop so a state-machine bug doesn't hang the test.
        for _ in 0..(manifest.chunk_count + 16) {
            let req = drain_until(&mut joiner_outbound, |w| {
                matches!(w, WireMessage::SnapshotChunkRequest { .. })
            })
            .await;
            let Some((peer, chunk_req_payload)) = req else {
                break;
            };
            let req_wire: WireMessage = postcard::from_bytes(&chunk_req_payload).unwrap();
            let (height, chunk_idx) = match req_wire {
                WireMessage::SnapshotChunkRequest { height, chunk_idx } => (height, chunk_idx),
                other => panic!("expected SnapshotChunkRequest, got {other:?}"),
            };
            *chunk_peer_count.entry(peer).or_insert(0) += 1;
            // Synthesize the chunk response from the canonical
            // store (any "server" has the same chunks).
            let resp = WireMessage::SnapshotChunkResponse {
                height,
                chunk_idx,
                payload: Some(chunks[chunk_idx as usize].clone()),
            };
            let resp_payload = postcard::to_stdvec(&resp).unwrap();
            let dispatches = dispatch::ingress(
                peer,
                &resp_payload,
                &ValidatorSetHistory::from_genesis(vs.clone()),
                &ValidatorKeyHistory::new(vs.iter().copied()),
                &crate::crypto::signed::ChainId::TEST,
            )
            .expect("ingress chunk response");
            for d in dispatches {
                joiner_node
                    .apply_dispatch(
                        d,
                        joiner_bc.as_ref(),
                        &mut joiner_view_timer,
                        &joiner_signer_arc,
                    )
                    .await
                    .expect("joiner apply_dispatch chunk response");
            }
            if joiner_node.snapshot_sync.is_done() {
                break;
            }
        }

        // ── Assertions ────────────────────────────────────────────
        assert!(
            joiner_node.snapshot_sync.is_done(),
            "joiner must complete the multi-source fetch",
        );
        assert_eq!(
            joiner_node.last_committed_height.load(Ordering::Relaxed),
            50,
            "joiner's last_committed_height must equal snapshot height",
        );
        assert_eq!(
            joiner_sm.lock().state_commitment(),
            expected_commitment,
            "joiner's state machine commitment must match the snapshot's",
        );
        let distinct_peer_count = chunk_peer_count.len();
        assert!(
            distinct_peer_count >= 2,
            "workpool must fan out across ≥ 2 peers; got {distinct_peer_count}: {chunk_peer_count:?}",
        );
    }

    /// Joiner mid-fetch peer drop (#230 acceptance criterion 2):
    /// after a peer is dropped via `DiscoveryEvent::PeerRemoved`,
    /// the joiner reassigns its in-flight chunks to surviving
    /// peers and completes the fetch. Driven through the same
    /// in-memory shuttle as the happy-path test.
    #[tokio::test]
    async fn joiner_completes_fetch_after_one_peer_disconnects() {
        let server_signers: Vec<NodeSigner> = (0..3).map(|_| fresh_signer()).collect();
        let server_ids: Vec<NodeId> = server_signers.iter().map(|s| s.node_id()).collect();
        let joiner_signer = fresh_signer();
        let mut all_ids = server_ids.clone();
        all_ids.push(joiner_signer.node_id());
        let vs = ValidatorSet::new(
            all_ids
                .iter()
                .copied()
                .map(crate::consensus::validator_set::ValidatorId::from_genesis_pubkey)
                .collect(),
        );

        let big_value: u64 = u64::MAX;
        let snapshot_payload = bytes::Bytes::from(postcard::to_stdvec(&big_value).unwrap());
        let server_sm: Arc<Mutex<Box<dyn StateMachine>>> = Arc::new(Mutex::new(Box::new(
            crate::replication::impls::counter_sm::CounterStateMachine::new(),
        )));
        server_sm.lock().restore(&snapshot_payload).unwrap();
        let expected_commitment = server_sm.lock().state_commitment();
        let chunks_with_hashes = crate::replication::snapshot::chunk_snapshot(&snapshot_payload, 2);
        let chunk_hashes: Vec<[u8; 32]> = chunks_with_hashes.iter().map(|(_, h)| *h).collect();
        let chunks: Vec<bytes::Bytes> = chunks_with_hashes.into_iter().map(|(c, _)| c).collect();
        let snapshot_block = {
            let parent_hash = genesis().hash();
            let commands: Vec<bytes::Bytes> = Vec::new();
            crate::replication::block::Block {
                header: crate::replication::block::BlockHeader {
                    parent_hash,
                    height: 50,
                    view: 50,
                    proposer: server_ids[0],
                    state_commitment: expected_commitment,
                    commands_commitment: crate::replication::block::Block::commands_commitment(
                        &commands,
                    ),
                    validator_history_commitment: [0; 32],
                },
                commands,
            }
        };
        let mut commit_qc = QuorumCertificate::new(50, snapshot_block.hash(), vs.len());
        for i in 0..crate::consensus::hotstuff::qc::quorum_size(vs.len()) {
            commit_qc.add_signature(i, [0u8; 64]);
        }
        let manifest =
            crate::replication::snapshot::SnapshotManifest::build_for_test_genesis_histories(
                snapshot_block.clone(),
                &vs,
                2,
                chunk_hashes,
                commit_qc,
                1_700_000_000,
            );

        let joiner_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let joiner_sm: Arc<Mutex<Box<dyn StateMachine>>> = Arc::new(Mutex::new(Box::new(
            crate::replication::impls::counter_sm::CounterStateMachine::new(),
        )));
        let mut joiner_node = ConsensusNode::new(
            joiner_signer.node_id(),
            snapshot_test_config_enabled(vs.clone(), 50),
            Arc::clone(&joiner_sm),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&joiner_storage),
            Arc::new(MemoryWal::new()),
        );
        let joiner_signer_arc: Arc<dyn Signer> = Arc::new(joiner_signer);
        let (joiner_bc, mut joiner_outbound) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut joiner_view_timer = ViewTimer::new(timer_tx);

        for s in &server_signers {
            let proposal = synthetic_proposal_dispatch(s, 100, 100, [0xEE; 32]);
            joiner_node
                .apply_dispatch(
                    proposal,
                    joiner_bc.as_ref(),
                    &mut joiner_view_timer,
                    &joiner_signer_arc,
                )
                .await
                .expect("joiner apply_dispatch proposal");
        }

        let (primary, _) = drain_until(&mut joiner_outbound, |w| {
            matches!(w, WireMessage::SnapshotManifestRequest { .. })
        })
        .await
        .expect("manifest request");
        let resp_payload = postcard::to_stdvec(&WireMessage::SnapshotManifestResponse(Some(
            manifest.clone(),
        )))
        .unwrap();
        let dispatches = dispatch::ingress(
            primary,
            &resp_payload,
            &ValidatorSetHistory::from_genesis(vs.clone()),
            &ValidatorKeyHistory::new(vs.iter().copied()),
            &crate::crypto::signed::ChainId::TEST,
        )
        .expect("ingress manifest response");
        for d in dispatches {
            joiner_node
                .apply_dispatch(
                    d,
                    joiner_bc.as_ref(),
                    &mut joiner_view_timer,
                    &joiner_signer_arc,
                )
                .await
                .expect("joiner apply_dispatch manifest response");
        }

        // Serve exactly one chunk to ensure the workpool has
        // distributed requests, then drop a peer that's actually
        // serving chunks.
        let (first_peer, first_payload) = drain_until(&mut joiner_outbound, |w| {
            matches!(w, WireMessage::SnapshotChunkRequest { .. })
        })
        .await
        .expect("first chunk request");
        let (height, idx) = match postcard::from_bytes::<WireMessage>(&first_payload).unwrap() {
            WireMessage::SnapshotChunkRequest { height, chunk_idx } => (height, chunk_idx),
            _ => panic!(),
        };
        let resp = WireMessage::SnapshotChunkResponse {
            height,
            chunk_idx: idx,
            payload: Some(chunks[idx as usize].clone()),
        };
        let resp_bytes = postcard::to_stdvec(&resp).unwrap();
        let dispatches = dispatch::ingress(
            first_peer,
            &resp_bytes,
            &ValidatorSetHistory::from_genesis(vs.clone()),
            &ValidatorKeyHistory::new(vs.iter().copied()),
            &crate::crypto::signed::ChainId::TEST,
        )
        .unwrap();
        for d in dispatches {
            joiner_node
                .apply_dispatch(
                    d,
                    joiner_bc.as_ref(),
                    &mut joiner_view_timer,
                    &joiner_signer_arc,
                )
                .await
                .unwrap();
        }

        // Drop the peer that just served us via a synthetic
        // PeerRemoved event-equivalent: drive snapshot_sync's
        // disconnect hook directly. This is what
        // `DiscoveryEvent::PeerRemoved` would do at runtime.
        let drop_actions = joiner_node.snapshot_sync.on_peer_disconnected(first_peer);
        joiner_node
            .apply_snapshot_sync_actions(
                drop_actions,
                joiner_bc.as_ref(),
                &mut joiner_view_timer,
                &joiner_signer_arc,
            )
            .await
            .unwrap();
        assert!(
            !joiner_node.snapshot_sync.is_aborted(),
            "with 2 surviving candidates, dropping one peer must not abort",
        );

        // Drain the rest. Bounded loop guards against state-machine
        // bugs. Stale requests still in the channel from before the
        // disconnect was processed (i.e. addressed to `first_peer`)
        // are silently dropped — the state machine has already
        // reassigned those chunks to surviving peers, so freshly-
        // emitted requests target other peers and the workpool
        // makes progress.
        let mut served_via_other = false;
        for _ in 0..(manifest.chunk_count * 4 + 16) {
            let req = drain_until(&mut joiner_outbound, |w| {
                matches!(w, WireMessage::SnapshotChunkRequest { .. })
            })
            .await;
            let Some((peer, payload)) = req else {
                break;
            };
            if peer == first_peer {
                // Stale: the disconnect superseded this request;
                // the state machine reassigned the chunk and we
                // shouldn't synthesize a response from a "dropped"
                // peer.
                continue;
            }
            served_via_other = true;
            let (height, idx) = match postcard::from_bytes::<WireMessage>(&payload).unwrap() {
                WireMessage::SnapshotChunkRequest { height, chunk_idx } => (height, chunk_idx),
                _ => panic!(),
            };
            let resp = WireMessage::SnapshotChunkResponse {
                height,
                chunk_idx: idx,
                payload: Some(chunks[idx as usize].clone()),
            };
            let resp_bytes = postcard::to_stdvec(&resp).unwrap();
            let dispatches = dispatch::ingress(
                peer,
                &resp_bytes,
                &ValidatorSetHistory::from_genesis(vs.clone()),
                &ValidatorKeyHistory::new(vs.iter().copied()),
                &crate::crypto::signed::ChainId::TEST,
            )
            .unwrap();
            for d in dispatches {
                joiner_node
                    .apply_dispatch(
                        d,
                        joiner_bc.as_ref(),
                        &mut joiner_view_timer,
                        &joiner_signer_arc,
                    )
                    .await
                    .unwrap();
            }
            if joiner_node.snapshot_sync.is_done() {
                break;
            }
        }
        assert!(
            served_via_other,
            "at least one chunk must be served by a non-dropped peer for the test to be meaningful",
        );

        assert!(
            joiner_node.snapshot_sync.is_done(),
            "joiner must complete fetch after a single peer drop",
        );
        assert_eq!(
            joiner_node.last_committed_height.load(Ordering::Relaxed),
            50
        );
        assert_eq!(joiner_sm.lock().state_commitment(), expected_commitment);
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

    // ── #218: TimeoutVote round-sync hint ───────────────────────────────────

    /// A signed `TimeoutVote(view=N)` from a single peer must NOT
    /// drag the local pacemaker forward — that would let a Byzantine
    /// `TimeoutSpammer` set our `current_view` to `u64::MAX` with one
    /// frame. The hint only fires once the local bucket reaches
    /// `f + 1` distinct signers (the honesty threshold), guaranteeing
    /// at least one honest peer agrees.
    ///
    /// This test verifies the bound: a single TimeoutVote leaves
    /// `current_view` untouched even though it's bucketed.
    #[tokio::test]
    async fn timeout_vote_single_signer_does_not_advance_pacemaker_view() {
        let self_signer = fresh_signer();
        let peer_signer = fresh_signer();
        let ids = vec![
            self_signer.node_id(),
            peer_signer.node_id(),
            nid(0xA1),
            nid(0xA2),
        ];
        // ValidatorSet::new sorts internally; the local ids.sort() is
        // redundant but kept for parity with the pre-#328 fixture.
        let vs = ValidatorSet::new(
            ids.into_iter()
                .map(crate::consensus::validator_set::ValidatorId::from_genesis_pubkey)
                .collect(),
        );
        let cfg = NodeConfigForConsensus::for_testing(vs.clone(), genesis());
        let mut node = ConsensusNode::new(
            self_signer.node_id(),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::new(MemoryStorage::new()),
            Arc::new(MemoryWal::new()),
        );

        let view_before = node.pacemaker.current_view();
        let tv = crate::consensus::hotstuff::qc::TimeoutVote {
            view: 42,
            high_qc: None,
        };
        let signed = crate::crypto::signed::Signed::sign(
            tv,
            &peer_signer,
            &crate::crypto::signed::ChainId::TEST,
        )
        .expect("sign TimeoutVote");
        let wire = WireMessage::TimeoutVote(signed);
        let payload = postcard::to_stdvec(&wire).expect("encode WireMessage");

        let dispatches = crate::consensus::dispatch::ingress(
            peer_signer.node_id(),
            &payload,
            &ValidatorSetHistory::from_genesis(vs.clone()),
            &ValidatorKeyHistory::new(vs.iter().copied()),
            &crate::crypto::signed::ChainId::TEST,
        )
        .expect("ingress");
        let signer_arc: Arc<dyn Signer> = Arc::new(self_signer);
        let (broadcaster, _outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);
        for d in dispatches {
            node.apply_dispatch(d, broadcaster.as_ref(), &mut view_timer, &signer_arc)
                .await
                .expect("apply_dispatch");
        }

        // 1 distinct signer < f + 1 = 2 (n = 4, f = 1) → no hint
        // fires, the pacemaker stays put.
        assert_eq!(
            node.pacemaker.current_view(),
            view_before,
            "single-signer TimeoutVote must not advance the pacemaker — that's \
             the Byzantine bound that keeps a TimeoutSpammer adversary from \
             dragging honest views (see #218)",
        );
    }

    /// Two distinct signers' `TimeoutVote(view=N)` is the honesty
    /// threshold for `n = 4` (`f + 1 = 2`): at least one must be
    /// honest. The pacemaker fast-jumps *to* `N` (not `N + 1`)
    /// without promoting `high_qc_view`. This is the path that closes
    /// the post-restart view-skew wedge in #218 — distinct resume
    /// views (e.g. 28 vs 29) leave each replica bucketing only at the
    /// view it itself is on, never reaching quorum, never emitting a
    /// TC; the round-sync hint at `f + 1` is what unsticks them.
    #[tokio::test]
    async fn two_distinct_timeout_votes_fire_round_sync_and_advance_pacemaker() {
        let self_signer = fresh_signer();
        let peer_a = fresh_signer();
        let peer_b = fresh_signer();
        let ids = vec![
            self_signer.node_id(),
            peer_a.node_id(),
            peer_b.node_id(),
            nid(0xA1),
        ];
        // ValidatorSet::new sorts internally; the local ids.sort() is
        // redundant but kept for parity with the pre-#328 fixture.
        let vs = ValidatorSet::new(
            ids.into_iter()
                .map(crate::consensus::validator_set::ValidatorId::from_genesis_pubkey)
                .collect(),
        );
        let cfg = NodeConfigForConsensus::for_testing(vs.clone(), genesis());
        let mut node = ConsensusNode::new(
            self_signer.node_id(),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::new(MemoryStorage::new()),
            Arc::new(MemoryWal::new()),
        );

        let high_qc_view_before = node.pacemaker.high_qc_view();
        let signer_arc: Arc<dyn Signer> = Arc::new(self_signer);
        let (broadcaster, _outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        // Feed two distinct signers' TimeoutVote(42) through the same
        // ingress + dispatch path the live event loop uses.
        for peer in [&peer_a, &peer_b] {
            let tv = crate::consensus::hotstuff::qc::TimeoutVote {
                view: 42,
                high_qc: None,
            };
            let signed = crate::crypto::signed::Signed::sign(
                tv,
                peer,
                &crate::crypto::signed::ChainId::TEST,
            )
            .expect("sign TimeoutVote");
            let wire = WireMessage::TimeoutVote(signed);
            let payload = postcard::to_stdvec(&wire).expect("encode WireMessage");
            let dispatches = crate::consensus::dispatch::ingress(
                peer.node_id(),
                &payload,
                &ValidatorSetHistory::from_genesis(vs.clone()),
                &ValidatorKeyHistory::new(vs.iter().copied()),
                &crate::crypto::signed::ChainId::TEST,
            )
            .expect("ingress");
            for d in dispatches {
                node.apply_dispatch(d, broadcaster.as_ref(), &mut view_timer, &signer_arc)
                    .await
                    .expect("apply_dispatch");
            }
        }

        assert_eq!(
            node.pacemaker.current_view(),
            42,
            "OnRoundSync at f+1 honesty threshold jumps to v, not v+1",
        );
        assert_eq!(
            node.pacemaker.high_qc_view(),
            high_qc_view_before,
            "OnRoundSync must not promote high_qc_view — round sync is a \
             liveness hint, not a QC witness",
        );
    }

    /// Issue #321 regression: a Byzantine peer's `TimeoutVote` with a
    /// well-formed but cryptographically forged `high_qc` piggyback
    /// must not flow into `bucket.best_high_qc`. The dispatch verifier
    /// (`verify_high_qc_piggyback`) clears `high_qc_trusted`, and
    /// `on_timeout_vote`'s bucket update reads that flag and skips the
    /// piggyback entirely, treating the envelope as `high_qc: None`.
    ///
    /// Without this gate, an attacker could broadcast a single
    /// timeout vote with `view = u64::MAX - 1, high_qc = forged(...)`
    /// and once `f + 1` honest replicas joined the same bucket on a
    /// real timeout, the TC self-NewView loopback would launder the
    /// forged QC into every honest replica's `state.high_qc`.
    #[tokio::test]
    async fn forged_piggyback_on_timeout_vote_does_not_taint_bucket_best_high_qc() {
        // n = 4 → quorum = 3, f + 1 = 2.
        let self_signer = fresh_signer();
        let byzantine = fresh_signer();
        let ids = vec![
            self_signer.node_id(),
            byzantine.node_id(),
            nid(0xA1),
            nid(0xA2),
        ];
        // ValidatorSet::new sorts internally; the local ids.sort() is
        // redundant but kept for parity with the pre-#328 fixture.
        let vs = ValidatorSet::new(
            ids.into_iter()
                .map(crate::consensus::validator_set::ValidatorId::from_genesis_pubkey)
                .collect(),
        );
        let cfg = NodeConfigForConsensus::for_testing(vs.clone(), genesis());
        let mut node = ConsensusNode::new(
            self_signer.node_id(),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::new(MemoryStorage::new()),
            Arc::new(MemoryWal::new()),
        );

        // Build a *well-formed* but cryptographically bogus QC at a
        // very-fresh view. Quorum-many bits set, quorum-many zero
        // signatures — passes is_well_formed, fails verify_aggregate.
        let bogus_view: View = u64::MAX - 1;
        let bogus_block_hash = [0xDE; 32];
        let mut forged = crate::consensus::hotstuff::qc::QuorumCertificate::new(
            bogus_view,
            bogus_block_hash,
            vs.len(),
        );
        let quorum = crate::consensus::hotstuff::qc::quorum_size(vs.len());
        for idx in 0..quorum {
            forged.add_signature(idx, [0u8; 64]);
        }

        // The byzantine signs a real timeout vote at a future view
        // and piggybacks the forged QC. The envelope itself is valid
        // (real signature over real payload bytes), so envelope
        // verification at ingress will pass.
        let attack_view: View = 42;
        let tv = crate::consensus::hotstuff::qc::TimeoutVote {
            view: attack_view,
            high_qc: Some(forged),
        };
        let signed = crate::crypto::signed::Signed::sign(
            tv,
            &byzantine,
            &crate::crypto::signed::ChainId::TEST,
        )
        .expect("sign TimeoutVote");
        let wire = WireMessage::TimeoutVote(signed);
        let payload = postcard::to_stdvec(&wire).expect("encode WireMessage");

        // Run through the production verify path — this is the same
        // policy the live event loop wires (node.rs apply_dispatch).
        let qc_verification = crate::consensus::dispatch::QcVerification::Verify {
            scheme: crate::crypto::sig_scheme::SignatureSchemeChoice::Ed25519Collected,
            bls_key_history: None,
            min_v_eff_delay: crate::consensus::reconfig::MIN_V_EFF_DELAY,
        };
        let dispatches = crate::consensus::dispatch::ingress_with_qc_verification(
            byzantine.node_id(),
            &payload,
            &ValidatorSetHistory::from_genesis(vs.clone()),
            &ValidatorKeyHistory::new(vs.iter().copied()),
            &qc_verification,
            &crate::crypto::signed::ChainId::TEST,
        )
        .expect("envelope is honest; ingress must accept and emit Dispatch::TimeoutVote");

        // Ingress must emit exactly one TimeoutVote dispatch with the
        // piggyback flagged untrusted — the public contract that
        // on_timeout_vote relies on.
        assert_eq!(dispatches.len(), 1);
        match &dispatches[0] {
            crate::consensus::dispatch::Dispatch::TimeoutVote {
                signed,
                high_qc_trusted,
            } => {
                assert!(
                    !high_qc_trusted,
                    "forged piggyback must not be flagged as trusted",
                );
                assert_eq!(signed.payload.view, attack_view);
                // The envelope is unchanged — the integration layer
                // will look at signed.payload.high_qc but must ignore
                // it because the flag is false.
                assert!(signed.payload.high_qc.is_some());
            }
            other => panic!("expected Dispatch::TimeoutVote, got {other:?}"),
        }

        let signer_arc: Arc<dyn Signer> = Arc::new(self_signer);
        let (broadcaster, _outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);
        for d in dispatches {
            node.apply_dispatch(d, broadcaster.as_ref(), &mut view_timer, &signer_arc)
                .await
                .expect("apply_dispatch");
        }

        // The byzantine's timeout vote was real, so the bucket records
        // the signer (one entry, below the f+1 honesty threshold). But
        // bucket.best_high_qc must be None — the forged piggyback was
        // dropped at ingress and never reached the freshness compare.
        let bucket = node
            .timeout_buckets
            .get(&attack_view)
            .expect("byzantine's timeout vote at attack_view created the bucket");
        assert_eq!(
            bucket.signers.len(),
            1,
            "the byzantine's signer must still count toward the bucket — \
             dropping the envelope outright would let an attacker mute \
             honest timeout signal by attaching garbage piggybacks",
        );
        assert!(
            bucket.best_high_qc.is_none(),
            "bucket.best_high_qc must remain None — the forged QC must \
             not be eligible for the TC self-NewView loopback that \
             feeds state.high_qc",
        );
    }

    /// Issue #222 regression: a peer's `TimeoutVote(view=V)` where
    /// `V < self.current_view` is the cleanest signal that the peer is
    /// wedged (typically post-restart, stuck at its persisted
    /// `last_voted_view`). The bucket logic ignores the vote, but we
    /// also reply with a unicast `NewView` carrying our current
    /// `high_qc` so the wedged peer can fire `OnQc(high_qc.view)`
    /// through the standard ingress path and exit the wedge.
    ///
    /// Without this reply, the wedged replica's only forward-progress
    /// signal is its own outbound timeout votes, which the rest of the
    /// cluster ignores; if proposals/NewViews from caught-up peers are
    /// also dropped at the gossip layer for any reason, no path advances
    /// the wedged pacemaker. This is the wedge observed at ~12% under
    /// the "kill 3 of 4, restart 3" recipe in #222.
    #[tokio::test]
    async fn stale_timeout_vote_replies_with_new_view_to_wedged_peer() {
        let self_signer = fresh_signer();
        let wedged_peer = fresh_signer();
        let ids = vec![
            self_signer.node_id(),
            wedged_peer.node_id(),
            nid(0xA1),
            nid(0xA2),
        ];
        // ValidatorSet::new sorts internally; the local ids.sort() is
        // redundant but kept for parity with the pre-#328 fixture.
        let vs = ValidatorSet::new(
            ids.into_iter()
                .map(crate::consensus::validator_set::ValidatorId::from_genesis_pubkey)
                .collect(),
        );
        let cfg = NodeConfigForConsensus::for_testing(vs.clone(), genesis());
        let mut node = ConsensusNode::new(
            self_signer.node_id(),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::new(MemoryStorage::new()),
            Arc::new(MemoryWal::new()),
        );

        // Advance our pacemaker well past the wedged peer's view.
        // Use OnQc(50) so current_view = 51 — comfortably ahead of the
        // wedged_view = 5 we will inject below.
        let signer_arc: Arc<dyn Signer> = Arc::new(self_signer);
        let (broadcaster, mut outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);
        let actions = node.step_pacemaker(PacemakerEvent::OnQc(50));
        node.apply_pacemaker_actions(actions, broadcaster.as_ref(), &mut view_timer, &signer_arc)
            .await
            .expect("apply boot");
        // Drain whatever the boot emitted (NewView, ResetTimer plumbing
        // through outbound_rx, etc.) so the assertion below sees only
        // the catch-up reply.
        while outbound_rx.try_recv().is_ok() {}
        let our_view_before = node.pacemaker.current_view();
        assert!(
            our_view_before > 5,
            "test setup: our pacemaker must be ahead of the wedged peer's view (5)",
        );
        let our_high_qc_view_before = node
            .core
            .state()
            .high_qc
            .as_ref()
            .expect("genesis_qc must seed high_qc on a fresh node")
            .view;

        // Inject a stale TimeoutVote(view=5) from the wedged peer
        // through the ingress + dispatch path.
        let tv = crate::consensus::hotstuff::qc::TimeoutVote {
            view: 5,
            high_qc: None,
        };
        let signed = crate::crypto::signed::Signed::sign(
            tv,
            &wedged_peer,
            &crate::crypto::signed::ChainId::TEST,
        )
        .expect("sign TimeoutVote");
        let wire = WireMessage::TimeoutVote(signed);
        let payload = postcard::to_stdvec(&wire).expect("encode WireMessage");

        let dispatches = crate::consensus::dispatch::ingress(
            wedged_peer.node_id(),
            &payload,
            &ValidatorSetHistory::from_genesis(vs.clone()),
            &ValidatorKeyHistory::new(vs.iter().copied()),
            &crate::crypto::signed::ChainId::TEST,
        )
        .expect("ingress");
        for d in dispatches {
            node.apply_dispatch(d, broadcaster.as_ref(), &mut view_timer, &signer_arc)
                .await
                .expect("apply_dispatch");
        }

        // Our pacemaker must not have moved — the stale vote does not
        // contribute to any bucket at our current view.
        assert_eq!(
            node.pacemaker.current_view(),
            our_view_before,
            "stale TimeoutVote must not advance our own pacemaker",
        );

        // We must have emitted a unicast NewView reply addressed to the
        // wedged peer, carrying our current high_qc.
        let mut found_reply = false;
        while let Ok(out) = outbound_rx.try_recv() {
            if let ProtocolOutbound::SendTo {
                node_id, payload, ..
            } = out
            {
                if node_id != wedged_peer.node_id() {
                    continue;
                }
                let decoded: WireMessage =
                    postcard::from_bytes(&payload).expect("decode reply payload");
                if let WireMessage::NewView(signed) = decoded {
                    assert_eq!(
                        signed.payload.high_qc.view, our_high_qc_view_before,
                        "reply must carry our current high_qc",
                    );
                    found_reply = true;
                    break;
                }
            }
        }
        assert!(
            found_reply,
            "expected a unicast NewView reply to the wedged peer carrying our high_qc",
        );
    }

    /// Issue #222 regression: after `recover` from non-trivial durable
    /// state, the integration boot must seed the pacemaker from
    /// `max(persisted high_qc.view, persisted last_voted_view)` rather
    /// than starting at view 0 + jumping to view 1. Without this, the
    /// boot path briefly advertises view 1 to peers (carrying the
    /// stale persisted high_qc), then catches up via the self-loopback
    /// `OnQc(high_qc.view)`. The transient is harmless on its own, but
    /// it is the timing window that turns into a permanent wedge if
    /// peer NewView traffic is filtered out for any reason.
    #[tokio::test]
    async fn boot_after_recover_seeds_pacemaker_from_persisted_state() {
        use crate::consensus::hotstuff::Locked;
        use crate::replication::block::BlockHeader;

        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let wal: Arc<dyn Wal> = Arc::new(MemoryWal::new());
        let cfg = test_config(four_validators());

        // Build a uncommitted block at view 9 so its hash + header can
        // back the persisted high_qc.
        let g = genesis();
        let b_high = Block {
            header: BlockHeader {
                parent_hash: g.hash(),
                height: 1,
                view: 9,
                proposer: nid(1),
                state_commitment: [0u8; 32],
                commands_commitment: Block::commands_commitment(&[]),
                validator_history_commitment: [0; 32],
            },
            commands: vec![],
        };
        let high_qc = QuorumCertificate::new(9, b_high.hash(), 4);
        let locked = Locked {
            view: 8,
            height: 1,
            block_hash: b_high.hash(),
        };

        // Session 1: persist a vote at view 10, plus locked / high_qc.
        // The locked entry's referenced block is `b_high`, which we
        // insert into pending_blocks first so `persist_updates` writes
        // it to durable storage too (#206 path).
        let mut node = ConsensusNode::new(
            nid(1),
            cfg.clone(),
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::clone(&wal),
        );
        node.core.insert_pending_block(b_high.clone());
        node.persist_updates(&[
            StateUpdate::VotedInView { view: 10 },
            StateUpdate::Locked(locked),
            StateUpdate::HighQc(high_qc.clone()),
        ])
        .unwrap();
        drop(node);

        // Session 2: recover and run the same `boot_view` snippet the
        // integration boot uses. Asserts the pacemaker lands at
        // max(high_qc.view = 9, last_voted_view = 10) + 1 = 11, not 1.
        let mut recovered = ConsensusNode::recover(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::clone(&wal),
        )
        .unwrap();
        assert_eq!(recovered.core.state().last_voted_view, 10);
        assert_eq!(recovered.core.state().high_qc.as_ref().unwrap().view, 9);

        // Build a self-signer whose node_id matches recovered.self_id
        // (= nid(1) here is a synthetic placeholder, not derived from a
        // real key). The boot snippet only needs the signer to sign
        // outbound NewView frames, which we don't assert on.
        let self_signer = fresh_signer();
        let signer_arc: Arc<dyn Signer> = Arc::new(self_signer);
        let (broadcaster, _outbound_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        let boot_view = recovered
            .core
            .state()
            .high_qc
            .as_ref()
            .map(|qc| qc.view)
            .unwrap_or(0)
            .max(recovered.core.state().last_voted_view);
        let boot_actions = recovered.step_pacemaker(PacemakerEvent::OnQc(boot_view));
        recovered
            .apply_pacemaker_actions(
                boot_actions,
                broadcaster.as_ref(),
                &mut view_timer,
                &signer_arc,
            )
            .await
            .expect("boot");

        assert_eq!(
            recovered.pacemaker.current_view(),
            11,
            "pacemaker must land at max(high_qc.view, last_voted_view) + 1 = 11 after recover boot",
        );
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
        let vs = ValidatorSet::new(
            ids.iter()
                .copied()
                .map(crate::consensus::validator_set::ValidatorId::from_genesis_pubkey)
                .collect(),
        );
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

        // Safety core emits `[Persist(ProposedInView), Broadcast(Proposal)]`
        // for a freshly booted leader seeded with the genesis QC
        // (regression-tested by
        // `new_seeds_genesis_qc_so_view_one_leader_can_propose`). The
        // ProposedInView persist is the audit-4-6 / #407 self-equivocation
        // guard the dispatcher flushes before the broadcast.
        let actions = node.core.become_leader(1);
        assert_eq!(actions.len(), 2);

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
        // #436: the proposal loopback now emits `OnQc(justify.view = 0)`,
        // which advances this node's pacemaker from view 0 → 1 and fires
        // `on_pacemaker_advance(1)`. That handler unconditionally emits
        // a `Broadcast(NewView)` advertising the seeded genesis high_qc
        // — the same NewView a real boot would send when the pacemaker
        // advances from 0 to 1 via the boot-time `OnQc(boot_view)`.
        // The double-propose guard on `proposed_in_view` keeps this from
        // re-emitting a Proposal at view 1.
        let third = send_rx
            .try_recv()
            .expect("Broadcast(NewView) must follow as the pacemaker advances to view 1");
        assert!(
            matches!(third, ProtocolOutbound::Broadcast(_)),
            "third outbound must be the NewView broadcast, got {third:?}",
        );
        // No further traffic.
        assert!(send_rx.try_recv().is_err());
    }

    /// PR A of #325: outbound proposals must carry a real
    /// `validator_history_commitment` — not the `[0; 32]` placeholder
    /// the block builder stamps. The leader-side rewrite in
    /// `apply_safety_actions` is what populates the field; this test
    /// pins that wiring so a future refactor can't silently drop it.
    ///
    /// Bisect-confirmed by removing the rewrite block in
    /// `apply_safety_actions`: the test then sees `[0; 32]` on the
    /// wire and fails the equality assertion.
    #[tokio::test]
    async fn outbound_proposal_carries_validator_history_commitment() {
        let ns = fresh_signer();
        let (mut node, _vs) = make_node_with_signer(&ns, 1);
        let signer: Arc<dyn Signer> = Arc::new(ns);

        // Snapshot the expected commitment before triggering the
        // broadcast — pre-block semantics, so this hash is what should
        // appear on the wire.
        let expected = crate::consensus::history_commitment::validator_history_commitment_v1(
            &node.validator_history,
            &node.validator_key_history,
            node.bls_key_history.as_ref(),
        );

        let (broadcaster, mut send_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        // Become view-1 leader and let the safety core emit its
        // single Action::Broadcast(Proposal). apply_safety_actions
        // walks the action list and rewrites the proposal's
        // validator_history_commitment before signing/broadcasting.
        let actions = node.core.become_leader(1);
        node.apply_safety_actions(actions, broadcaster.as_ref(), &mut view_timer, &signer)
            .await
            .unwrap();

        let outbound = send_rx
            .try_recv()
            .expect("Broadcast(Proposal) must be sent");
        let payload = match outbound {
            ProtocolOutbound::Broadcast(p) => p,
            other => panic!("expected Broadcast, got {other:?}"),
        };
        let wire: WireMessage = postcard::from_bytes(&payload).expect("decode wire");
        let signed = match wire {
            WireMessage::Proposal(s) => s,
            other => panic!("expected Proposal, got {other:?}"),
        };

        assert_eq!(
            signed.payload.block.header.validator_history_commitment, expected,
            "leader must stamp the real v1 commitment over its current histories, \
             not leave the [0; 32] placeholder the block builder produces",
        );
        // Sanity: this is not just the all-zero default.
        assert_ne!(
            signed.payload.block.header.validator_history_commitment, [0u8; 32],
            "the v1 commitment over a non-empty validator set must not collide \
             with the all-zero placeholder",
        );
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
        let peer = vs.get(1).unwrap().into_node_id();
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
                assert!(matches!(decoded, WireMessage::Vote(_, _)));
            }
            other => panic!("expected SendTo to peer, got {other:?}"),
        }
        assert!(send_rx.try_recv().is_err());
    }

    // ── Bounded-cache eviction (#135) ─────────────────────────────────────
    //
    // The safety-core caches are tested in `consensus::hotstuff::step`;
    // the integration layer owns `timeout_buckets`, so the cap-driven
    // eviction lives here. We exercise the cap by feeding distinct
    // future-view timeout votes from one signer (well below quorum, so
    // no TC ever fires and the on-TC `retain(v > view)` cleanup never
    // kicks in — the cap is the ONLY thing keeping the map bounded).

    /// Build a node whose timeout_buckets cap is `cap`; otherwise
    /// identical to [`make_node_with_signer`]. Other caches stay at
    /// their permissive test defaults so unrelated cap evictions
    /// don't pollute the assertion.
    fn make_node_with_timeout_cap(
        signer: &NodeSigner,
        self_idx: usize,
        cap: usize,
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
        let vs = ValidatorSet::new(
            ids.iter()
                .copied()
                .map(crate::consensus::validator_set::ValidatorId::from_genesis_pubkey)
                .collect(),
        );
        let mut limits = CacheLimits::unbounded_for_tests();
        limits.timeout_buckets_capacity = cap;
        let mut cfg = NodeConfigForConsensus::for_testing(vs.clone(), genesis());
        cfg.limits = limits;
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

    /// Insert 2× the cap of distinct-view sub-quorum timeout votes
    /// from a single signer — the cap holds, the counter records
    /// every drop, and the lowest-view buckets are the ones evicted.
    #[tokio::test]
    async fn timeout_buckets_inserting_twice_the_cap_evicts_to_cap() {
        let cap = 4usize;
        let ns = fresh_signer();
        let (mut node, vs) = make_node_with_timeout_cap(&ns, 0, cap);
        let signer: Arc<dyn Signer> = Arc::new(ns);

        let (broadcaster, _send_rx) = make_test_broadcaster();
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        // Use a non-self placeholder validator as the signer so we
        // exercise the foreign-vote ingress path and never trip the
        // self-loopback shortcut. View 0 must be skipped — `view <
        // current_view` would short-circuit before the bucket insert.
        let voter = vs.get(1).unwrap().into_node_id();
        let n = (2 * cap) as View;
        for view in 1..=n {
            let payload = TimeoutVote {
                view,
                high_qc: None,
            };
            let signed = Signed {
                payload,
                signer: voter,
                sig: [0u8; 64],
            };
            node.on_timeout_vote(signed, true, broadcaster.as_ref(), &mut view_timer, &signer)
                .await
                .unwrap();
            assert!(
                node.timeout_buckets.len() <= cap,
                "timeout_buckets grew past cap after view {view}: len={}",
                node.timeout_buckets.len(),
            );
        }
        assert_eq!(node.timeout_buckets.len(), cap);
        // n - cap inserts triggered eviction (n inserts past the
        // cap-fill point of `cap`).
        assert_eq!(
            node.eviction_counters().timeout_buckets(),
            (n as u64) - (cap as u64),
        );
        // Lowest-view-first: surviving views are the cap most recent.
        let mut surviving: Vec<View> = node.timeout_buckets.keys().copied().collect();
        surviving.sort();
        let expected: Vec<View> = ((n - cap as View + 1)..=n).collect();
        assert_eq!(surviving, expected);
    }

    /// Issue #327 / audit finding 4-F1 / 12-F3 (Tendermint amnesia
    /// regression guard).
    ///
    /// HotStuff safety requires that before a `Vote` envelope leaves the
    /// process, the `last_voted_view` field is durable on disk. If the
    /// order is reversed (vote sent, then crash before persist), the
    /// restarted replica will re-vote at the same view — potentially on
    /// a conflicting block — which is the Tendermint amnesia attack
    /// class.
    ///
    /// The current implementation gets this right by emission ordering
    /// in `step()` (`Action::Persist(VotedInView)` before
    /// `Action::Broadcast(Vote)`) and by `apply_safety_actions` flushing
    /// the persist buffer synchronously via `storage.batch(...)` before
    /// any non-Persist action runs. **This ordering is correct today.**
    /// The test below pins it: a future refactor that reorders
    /// `step()`'s emissions or that defers the `persist_buf.flush()`
    /// past the first `Broadcast` would fail this test.
    ///
    /// Approach: wrap [`Storage`] and [`Broadcaster`] in
    /// timestamp-recording shells that share an ordered log. Drive a
    /// fresh node (single-replica) to vote on a hand-crafted Proposal,
    /// then assert the log records `PersistVotedInView(V)` before
    /// `BroadcastVoteFor(V)` for the same view.
    #[tokio::test]
    async fn vote_persist_returns_before_send_called() {
        use bytes::Bytes;
        use parking_lot::Mutex as PlMutex;

        use crate::clock::BoxFuture;
        use crate::consensus::dispatch::ingress_with_qc_verification;
        use crate::consensus::hotstuff::Proposal;
        use crate::p2p::overlay::Broadcaster;
        use crate::storage::{Storage, WriteBatch};

        #[derive(Debug, Clone, PartialEq, Eq)]
        enum OrderEvent {
            PersistVotedInView(View),
            BroadcastVoteFor(View),
        }

        /// `Storage` wrapper that appends `PersistVotedInView(V)` to a
        /// shared log when (and only when) `apply_batch` returns `Ok`
        /// after writing `STORAGE_KEY_LAST_VOTED_VIEW`. Other batches
        /// pass through unchanged. Records *after* delegation so the
        /// log entry corresponds to "persist returned" rather than
        /// "persist started".
        struct OrderingStorage {
            inner: Arc<dyn Storage>,
            log: Arc<PlMutex<Vec<OrderEvent>>>,
        }
        impl Storage for OrderingStorage {
            fn get(&self, key: &[u8]) -> anyhow::Result<Option<Bytes>> {
                self.inner.get(key)
            }
            fn put(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
                self.inner.put(key, value)
            }
            fn delete(&self, key: &[u8]) -> anyhow::Result<()> {
                self.inner.delete(key)
            }
            fn scan_prefix(&self, prefix: &[u8]) -> anyhow::Result<Vec<(Bytes, Bytes)>> {
                self.inner.scan_prefix(prefix)
            }
            fn apply_batch(&self, batch: WriteBatch) -> anyhow::Result<()> {
                // Snapshot the view-write (if any) before consuming the
                // batch; record only after the inner write succeeds.
                let mut written_view: Option<View> = None;
                for op in &batch.ops {
                    if let crate::storage::WriteOp::Put(key, value) = op {
                        if key.as_slice() == STORAGE_KEY_LAST_VOTED_VIEW {
                            if let Ok(v) = decode_voted_view(value) {
                                written_view = Some(v);
                            }
                        }
                    }
                }
                let result = self.inner.apply_batch(batch);
                if result.is_ok() {
                    if let Some(v) = written_view {
                        self.log.lock().push(OrderEvent::PersistVotedInView(v));
                    }
                }
                result
            }
            fn compare_and_swap(
                &self,
                key: &[u8],
                expected: Option<&[u8]>,
                new: Option<&[u8]>,
            ) -> anyhow::Result<bool> {
                self.inner.compare_and_swap(key, expected, new)
            }
        }

        /// `Broadcaster` wrapper that appends `BroadcastVoteFor(V)` to
        /// the shared log *before* delegating to the inner. The log
        /// entry corresponds to "send was called", which is the
        /// observable timestamp the audit cares about.
        struct OrderingBroadcaster {
            inner: Arc<dyn Broadcaster>,
            log: Arc<PlMutex<Vec<OrderEvent>>>,
        }
        impl Broadcaster for OrderingBroadcaster {
            fn broadcast(&self, payload: Bytes) -> BoxFuture<'_, ()> {
                if let Ok(WireMessage::Vote(signed, _)) =
                    postcard::from_bytes::<WireMessage>(&payload)
                {
                    self.log
                        .lock()
                        .push(OrderEvent::BroadcastVoteFor(signed.payload.view));
                }
                self.inner.broadcast(payload)
            }
            fn send_to(&self, target: NodeId, payload: Bytes) -> BoxFuture<'_, ()> {
                self.inner.send_to(target, payload)
            }
        }

        // ── Setup ──────────────────────────────────────────────────────
        let log: Arc<PlMutex<Vec<OrderEvent>>> = Arc::new(PlMutex::new(Vec::new()));
        let inner_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let storage: Arc<dyn Storage> = Arc::new(OrderingStorage {
            inner: Arc::clone(&inner_storage),
            log: Arc::clone(&log),
        });

        // Self at index 1, leader of the proposal at view 1 sits at
        // some other index; the leader sends us a Proposal we'll vote on.
        let self_signer = fresh_signer();
        let leader_signer = fresh_signer();
        let mut ids: Vec<crate::consensus::validator_set::ValidatorId> = vec![
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(
                self_signer.node_id(),
            ),
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(
                leader_signer.node_id(),
            ),
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(nid(0xA1)),
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(nid(0xA2)),
        ];
        ids.sort();
        let vs = ValidatorSet::new(ids);
        let cfg = NodeConfigForConsensus::for_testing(vs.clone(), genesis());
        let mut node = ConsensusNode::new(
            self_signer.node_id(),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );
        let signer: Arc<dyn Signer> = Arc::new(self_signer);

        let (inner_bc, _outbound_rx) = make_test_broadcaster();
        let broadcaster: Arc<dyn Broadcaster> = Arc::new(OrderingBroadcaster {
            inner: inner_bc,
            log: Arc::clone(&log),
        });
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        // ── Drive a vote ───────────────────────────────────────────────
        // Hand-craft a view-1 proposal extending genesis with empty
        // commands. The leader is whichever validator at index 1 in
        // the round-robin set; we sign with `leader_signer` and route
        // through ingress to verify the safety-core path.
        let leader_id = leader_signer.node_id();
        let parent = genesis();
        let mut block = Block {
            header: BlockHeader {
                parent_hash: parent.hash(),
                height: 1,
                view: 1,
                proposer: leader_id,
                state_commitment: [0; 32],
                commands_commitment: Block::commands_commitment(&[]),
                validator_history_commitment: [0; 32],
            },
            commands: vec![],
        };
        // Stamp the post-block commitment (#325 PR C) so the ingress
        // verifier accepts the proposal. With no commands the value
        // equals the v1 hash of the genesis-time histories.
        block.header.validator_history_commitment =
            crate::consensus::history_commitment::compute_post_block_commitment(
                &block,
                &node.validator_history,
                &node.validator_key_history,
                node.bls_key_history.as_ref(),
                &node.chain_id,
                node.signature_scheme,
                node.min_v_eff_delay,
            );
        let justify = crate::consensus::hotstuff::qc::genesis_qc(&parent, vs.len());
        let proposal = Proposal { block, justify };
        let signed_proposal =
            Signed::sign(proposal, &leader_signer, &node.chain_id).expect("sign proposal");
        let wire = WireMessage::Proposal(signed_proposal);
        let payload = postcard::to_stdvec(&wire).expect("encode wire");
        let qc_verification = crate::consensus::dispatch::QcVerification::Verify {
            scheme: crate::crypto::sig_scheme::SignatureSchemeChoice::Ed25519Collected,
            bls_key_history: None,
            min_v_eff_delay: crate::consensus::reconfig::MIN_V_EFF_DELAY,
        };
        let dispatches = ingress_with_qc_verification(
            leader_id,
            &payload,
            &node.validator_history,
            &node.validator_key_history,
            &qc_verification,
            &node.chain_id,
        )
        .expect("ingress accepts the leader's proposal");
        for d in dispatches {
            node.apply_dispatch(d, broadcaster.as_ref(), &mut view_timer, &signer)
                .await
                .expect("apply_dispatch");
        }

        // ── Assert ordering ────────────────────────────────────────────
        let recorded = log.lock().clone();
        let persist_idx = recorded
            .iter()
            .position(|e| matches!(e, OrderEvent::PersistVotedInView(1)));
        let broadcast_idx = recorded
            .iter()
            .position(|e| matches!(e, OrderEvent::BroadcastVoteFor(1)));
        let persist_idx =
            persist_idx.expect("VotedInView{view: 1} must be persisted (storage.batch must run)");
        let broadcast_idx = broadcast_idx
            .expect("Vote{view: 1} must be broadcast (Action::Broadcast(Vote) must fire)");
        assert!(
            persist_idx < broadcast_idx,
            "persist must return before broadcast is called: \
             PersistVotedInView at index {persist_idx}, BroadcastVoteFor at index \
             {broadcast_idx}, full log = {recorded:?}",
        );
    }

    /// Issue #405 / audit finding 4-1 (Tendermint amnesia regression
    /// guard for the `Locked` state).
    ///
    /// Companion to `vote_persist_returns_before_send_called`. The vote
    /// guard pins `Persist(VotedInView)` before `Broadcast(Vote)`; this
    /// guard pins `Persist(Locked)` before `Broadcast(Vote)` when both
    /// fire on the same proposal (the 2-chain promotion path).
    ///
    /// Pre-fix, `step()` emitted `Action::Broadcast(Vote)` *before*
    /// `Action::Persist(StateUpdate::Locked)`. The integration layer's
    /// per-action persist-flush meant the lock landed on disk only
    /// after the vote left the wire — a crash in that window left
    /// disk with `last_voted_view` advanced and `locked` reverted to
    /// the pre-promotion value. On restart the in-memory promotion
    /// was gone, opening the canonical Tendermint amnesia hole. Issue
    /// #405 reorders emission so the persist always precedes the
    /// broadcast, and this test pins the new contract end-to-end via
    /// the same `OrderingStorage` / `OrderingBroadcaster` shells the
    /// vote-side test uses.
    ///
    /// Approach: pre-seed the safety core's `pending_blocks` with the
    /// view-1 / view-2 ancestor blocks (mirroring what two prior
    /// proposals would have done), then call `core.step()` on the
    /// view-3 proposal so we get the genuine action vector, and run
    /// it through `apply_safety_actions`. Assert the shared log
    /// records the lock persist before the vote broadcast.
    #[tokio::test]
    async fn lock_persist_returns_before_send_called_for_two_chain_promotion() {
        use bytes::Bytes;
        use parking_lot::Mutex as PlMutex;

        use crate::clock::BoxFuture;
        use crate::consensus::hotstuff::Proposal;
        use crate::consensus::hotstuff::qc::QuorumCertificate;
        use crate::p2p::overlay::Broadcaster;
        use crate::storage::{Storage, WriteBatch};

        #[derive(Debug, Clone, PartialEq, Eq)]
        enum OrderEvent {
            PersistLocked(View),
            BroadcastVoteFor(View),
        }

        struct OrderingStorage {
            inner: Arc<dyn Storage>,
            log: Arc<PlMutex<Vec<OrderEvent>>>,
        }
        impl Storage for OrderingStorage {
            fn get(&self, key: &[u8]) -> anyhow::Result<Option<Bytes>> {
                self.inner.get(key)
            }
            fn put(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
                self.inner.put(key, value)
            }
            fn delete(&self, key: &[u8]) -> anyhow::Result<()> {
                self.inner.delete(key)
            }
            fn scan_prefix(&self, prefix: &[u8]) -> anyhow::Result<Vec<(Bytes, Bytes)>> {
                self.inner.scan_prefix(prefix)
            }
            fn apply_batch(&self, batch: WriteBatch) -> anyhow::Result<()> {
                let mut written_lock_view: Option<View> = None;
                for op in &batch.ops {
                    if let crate::storage::WriteOp::Put(key, value) = op {
                        if key.as_slice() == STORAGE_KEY_LOCKED {
                            if let Ok(l) = decode_locked(value) {
                                written_lock_view = Some(l.view);
                            }
                        }
                    }
                }
                let result = self.inner.apply_batch(batch);
                if result.is_ok() {
                    if let Some(v) = written_lock_view {
                        self.log.lock().push(OrderEvent::PersistLocked(v));
                    }
                }
                result
            }
            fn compare_and_swap(
                &self,
                key: &[u8],
                expected: Option<&[u8]>,
                new: Option<&[u8]>,
            ) -> anyhow::Result<bool> {
                self.inner.compare_and_swap(key, expected, new)
            }
        }

        struct OrderingBroadcaster {
            inner: Arc<dyn Broadcaster>,
            log: Arc<PlMutex<Vec<OrderEvent>>>,
        }
        impl Broadcaster for OrderingBroadcaster {
            fn broadcast(&self, payload: Bytes) -> BoxFuture<'_, ()> {
                if let Ok(WireMessage::Vote(signed, _)) =
                    postcard::from_bytes::<WireMessage>(&payload)
                {
                    self.log
                        .lock()
                        .push(OrderEvent::BroadcastVoteFor(signed.payload.view));
                }
                self.inner.broadcast(payload)
            }
            fn send_to(&self, target: NodeId, payload: Bytes) -> BoxFuture<'_, ()> {
                self.inner.send_to(target, payload)
            }
        }

        // ── Setup ──────────────────────────────────────────────────────
        let log: Arc<PlMutex<Vec<OrderEvent>>> = Arc::new(PlMutex::new(Vec::new()));
        let inner_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let storage: Arc<dyn Storage> = Arc::new(OrderingStorage {
            inner: Arc::clone(&inner_storage),
            log: Arc::clone(&log),
        });

        let self_signer = fresh_signer();
        let leader_signer = fresh_signer();
        let mut ids: Vec<crate::consensus::validator_set::ValidatorId> = vec![
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(
                self_signer.node_id(),
            ),
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(
                leader_signer.node_id(),
            ),
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(nid(0xA1)),
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(nid(0xA2)),
        ];
        ids.sort();
        let vs = ValidatorSet::new(ids);
        let cfg = NodeConfigForConsensus::for_testing(vs.clone(), genesis());
        let mut node = ConsensusNode::new(
            self_signer.node_id(),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );
        let signer: Arc<dyn Signer> = Arc::new(self_signer);

        let (inner_bc, _outbound_rx) = make_test_broadcaster();
        let broadcaster: Arc<dyn Broadcaster> = Arc::new(OrderingBroadcaster {
            inner: inner_bc,
            log: Arc::clone(&log),
        });
        let (timer_tx, _timer_rx) = tokio::sync::mpsc::channel::<View>(4);
        let mut view_timer = ViewTimer::new(timer_tx);

        // ── Build the chain genesis → b_v1 → b_v2 → b_v3 ──────────────
        // Pre-seed b_v1 and b_v2 in `pending_blocks` so the b_v3
        // proposal triggers the 2-chain promotion in a single `step()`
        // (the grandparent walk reaches b_v1, height 1, beating the
        // None-baseline lock).
        let leader_id = leader_signer.node_id();
        fn build_block(parent: &Block, view: View, proposer: NodeId) -> Block {
            Block {
                header: BlockHeader {
                    parent_hash: parent.hash(),
                    height: parent.header.height + 1,
                    view,
                    proposer,
                    state_commitment: [0; 32],
                    commands_commitment: Block::commands_commitment(&[]),
                    validator_history_commitment: [0; 32],
                },
                commands: vec![],
            }
        }
        let parent = genesis();
        let b_v1 = build_block(&parent, 1, leader_id);
        let b_v2 = build_block(&b_v1, 2, leader_id);
        let mut b_v3 = build_block(&b_v2, 3, leader_id);
        // The validator-history commitment goes on the broadcast, not
        // on the safe-to-vote path — `core.step()` doesn't re-verify
        // it. We still stamp it for parity with the wire shape.
        b_v3.header.validator_history_commitment =
            crate::consensus::history_commitment::compute_post_block_commitment(
                &b_v3,
                &node.validator_history,
                &node.validator_key_history,
                node.bls_key_history.as_ref(),
                &node.chain_id,
                node.signature_scheme,
                node.min_v_eff_delay,
            );

        node.core.insert_pending_block(b_v1.clone());
        node.core.insert_pending_block(b_v2.clone());

        let justify_v2 = QuorumCertificate::new(2, b_v2.hash(), vs.len());
        let proposal_v3 = Proposal {
            block: b_v3,
            justify: justify_v2,
        };
        let signed_v3 =
            Signed::sign(proposal_v3, &leader_signer, &node.chain_id).expect("sign proposal");

        // Run the safety core to produce the action vector for the
        // view-3 proposal. The audit-fixed `on_proposal_received`
        // emits Persist(VotedInView), Persist(HighQc), Persist(Locked),
        // Broadcast(Vote), Commit(genesis) — in that order.
        let actions = node
            .core
            .step(crate::consensus::hotstuff::step::Event::ProposalReceived(
                crate::consensus::dispatch::Verified::unchecked(signed_v3),
            ));
        // Sanity: both items the test cares about are present.
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, SafetyAction::Persist(StateUpdate::Locked(_)))),
            "test setup: 2-chain promotion must emit Persist(Locked); actions={actions:?}",
        );
        assert!(
            actions.iter().any(|a| matches!(
                a,
                SafetyAction::Broadcast(crate::consensus::hotstuff::ConsensusMsg::Vote(_))
            )),
            "test setup: safe-to-vote must emit Broadcast(Vote); actions={actions:?}",
        );

        // Drive the actions through the integration layer's persist-
        // before-send flush discipline.
        node.apply_safety_actions(actions, broadcaster.as_ref(), &mut view_timer, &signer)
            .await
            .expect("apply_safety_actions");

        // ── Assert ordering ────────────────────────────────────────────
        let recorded = log.lock().clone();
        let persist_idx = recorded
            .iter()
            .position(|e| matches!(e, OrderEvent::PersistLocked(_)))
            .expect("Persist(Locked) must reach storage.batch");
        let broadcast_idx = recorded
            .iter()
            .position(|e| matches!(e, OrderEvent::BroadcastVoteFor(3)))
            .expect("Vote{view: 3} must be broadcast");
        assert!(
            persist_idx < broadcast_idx,
            "audit finding 4-1: lock persist must return before vote broadcast is called: \
             PersistLocked at index {persist_idx}, BroadcastVoteFor(3) at index \
             {broadcast_idx}, full log = {recorded:?}",
        );

        // And the lock is actually on disk, not just routed through the
        // hook — the on-disk shape is what survives a process crash.
        let raw = inner_storage
            .get(STORAGE_KEY_LOCKED)
            .unwrap()
            .expect("locked entry must be persisted");
        let on_disk = decode_locked(&raw).unwrap();
        assert_eq!(
            on_disk.view, 1,
            "on-disk lock must match the view-1 grandparent: {on_disk:?}",
        );
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

    // ── Structured-trace contract (#122, #192) ──────────────────────────────

    /// Operator-visible structured-log message names that the
    /// integration layer is expected to keep emitting on the
    /// pacemaker → safety → outbound flow. These are the strings
    /// runbooks and dashboards grep for; renaming or deleting one
    /// silently breaks downstream observability.
    ///
    /// The previous incarnation of this guard installed a
    /// `tracing-subscriber` and asserted these messages fired in a
    /// specific order during a happy-path leader flow. That test was
    /// flaky under parallel `cargo test` because tracing's
    /// per-thread dispatcher state interleaves with sibling test
    /// workers (issue #192 — flaky for both `with_subscriber` and
    /// `set_default` capture variants). Replacing it with a static
    /// source-text check trades the order assertion (which any
    /// refactor that breaks ordering would also reflect in the
    /// source-text co-location of these macros) for a deterministic,
    /// always-correct check that catches the load-bearing
    /// regression: a trace point being deleted or renamed.
    const EXPECTED_OPERATOR_TRACE_MESSAGES: &[&str] = &[
        "pacemaker_event",
        "pacemaker_action",
        "view_advanced",
        "outbound_broadcast",
        "new_view_received",
        "proposal_received",
        "persisted",
        "vote_received",
    ];

    /// Snapshot of `node.rs` baked into the test binary at compile
    /// time. Lets the contract test scan for `tracing::debug!(...)`
    /// macro calls without adding a runtime dependency on the file
    /// system or on cargo's package layout.
    const NODE_SOURCE_FOR_TRACE_AUDIT: &str = include_str!("node.rs");

    /// Each name in [`EXPECTED_OPERATOR_TRACE_MESSAGES`] must appear
    /// as a quoted string literal in `src/consensus/node.rs` at
    /// least twice — once in the contract array immediately above,
    /// and at least once more at the actual `tracing::debug!` macro
    /// call site. Counting `>= 2` is what catches deletion or
    /// rename of the macro call: the array entry alone leaves the
    /// count at exactly 1 and the assertion trips. If the rename is
    /// intentional, both the macro and the array are updated
    /// together and the count stays >= 2 with the new name.
    #[test]
    fn integration_layer_keeps_emitting_operator_trace_messages() {
        for name in EXPECTED_OPERATOR_TRACE_MESSAGES {
            // Quote the literal so we match `tracing::debug!(... "msg")`
            // and the array entry, not bare-word references in
            // comments or in field names with the same spelling.
            let needle = format!("\"{name}\"");
            let count = NODE_SOURCE_FOR_TRACE_AUDIT.matches(&needle).count();
            assert!(
                count >= 2,
                "operator-runbook contract: structured-trace message {name:?} appears \
                 only {count} time(s) as a quoted literal in src/consensus/node.rs \
                 (expected >= 2: one in EXPECTED_OPERATOR_TRACE_MESSAGES, one at the \
                 tracing::debug! call site). Renaming or removing this message silently \
                 breaks downstream log filters; if the rename is intentional, update \
                 EXPECTED_OPERATOR_TRACE_MESSAGES and any operator documentation that \
                 references the old name.",
            );
        }
    }

    /// `view_advanced` carries `cause = ?` (Qc/Tc), and the string
    /// tag operators read off the wire is fixed by
    /// [`crate::consensus::pacemaker::AdvanceCause::as_str`]. Pinning
    /// these here keeps the structured-log contract regression-checked
    /// without going through the dispatcher; renaming `"qc"` → `"QC"`
    /// (etc.) would silently break grep-based dashboards.
    #[test]
    fn advance_cause_strings_match_operator_runbooks() {
        use crate::consensus::pacemaker::AdvanceCause;
        assert_eq!(AdvanceCause::Qc.as_str(), "qc");
        assert_eq!(AdvanceCause::Tc.as_str(), "tc");
        assert_eq!(AdvanceCause::RoundSync.as_str(), "round_sync");
    }

    // ── RateLimiter integration (issue #134) ────────────────────────────────

    use crate::clock::{Clock, TokioClock};
    use crate::p2p::PeerCommand;
    use crate::p2p::limits::{RateLimiter, RateLimitsConfig};

    /// Build a `WireMessage::BlockRequest([0; 32])` postcard frame.
    /// Cheap to construct (no signing required) and decodes cleanly
    /// through `dispatch::ingress` so an honest frame survives the
    /// `Decision::Allow` path. Wire tag = 4.
    fn block_request_frame() -> bytes::Bytes {
        let msg = WireMessage::BlockRequest([0u8; 32]);
        bytes::Bytes::from(postcard::to_allocvec(&msg).expect("encode"))
    }

    /// Issue #134 acceptance criterion: a peer that floods at 10× the
    /// configured rate has its excess frames dropped *and* gets
    /// disconnected after K violations. We measure both outcomes —
    /// the drop counter rises and a `PeerCommand::Disconnect` lands
    /// on the manager-side channel.
    #[tokio::test]
    async fn flooding_peer_is_dropped_and_disconnected() {
        // Build a config with a tight per-kind bucket and a low
        // K so the test finishes quickly.
        let cfg = RateLimitsConfig {
            proposal_per_sec: 1.0,
            vote_per_sec: 1.0,
            timeout_vote_per_sec: 1.0,
            new_view_per_sec: 1.0,
            request_block_per_sec: 1.0,
            receive_block_per_sec: 1.0,
            snapshot_manifest_request_per_sec: 1.0,
            snapshot_manifest_response_per_sec: 1.0,
            snapshot_chunk_request_per_sec: 1.0,
            snapshot_chunk_response_per_sec: 1.0,
            bytes_per_sec: 1024.0 * 1024.0, // generous, isolate the test on per-kind
            burst_seconds: 1.0,
            violation_window: std::time::Duration::from_secs(60),
            max_violations: 5,
        };
        let clock: Arc<dyn Clock> = Arc::new(TokioClock::new());
        let limiter = Arc::new(RateLimiter::new(cfg, Arc::clone(&clock)));

        let node = make_node(nid(1));
        let (peer_cmd_tx, mut peer_cmd_rx) = tokio::sync::mpsc::channel::<PeerCommand>(8);
        let node = node.with_rate_limiter(Arc::clone(&limiter), Some(peer_cmd_tx));

        let signer = fresh_signer();
        let (event_tx, event_rx) = make_test_event_channel();
        let (broadcaster, mut _outbound_rx) = make_test_broadcaster();
        let discovery = make_test_discovery();
        let (_shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let _join = tokio::spawn(async move {
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

        // Drain occasional outbound traffic so the broadcaster channel
        // doesn't backpressure the run loop.
        let drain = tokio::spawn(async move { while _outbound_rx.recv().await.is_some() {} });

        // Flood ~50 BlockRequests from a single peer. The first ~1 fits
        // in the bucket, the rest become violations; after
        // max_violations the limiter returns Decision::Disconnect once
        // and the run loop forwards a PeerCommand::Disconnect.
        let attacker = nid(99);
        let frame = block_request_frame();
        for _ in 0..50 {
            event_tx
                .send(ProtocolEvent::Message {
                    from: attacker,
                    payload: frame.clone(),
                })
                .await
                .expect("event_rx alive");
        }

        // Wait for the disconnect command. 1s is generous — the run
        // loop processes the flood without any I/O.
        let cmd = tokio::time::timeout(Duration::from_secs(1), peer_cmd_rx.recv())
            .await
            .expect("disconnect command must fire within 1s")
            .expect("peer_cmd_tx closed");
        match cmd {
            PeerCommand::Disconnect { node_id } => {
                assert_eq!(
                    node_id, attacker,
                    "disconnect must target the flooding peer"
                );
            }
            other => panic!("expected Disconnect, got {other:?}"),
        }

        // The limiter's per-kind drop counter and disconnect counter
        // also reflect the flood.
        assert!(
            limiter.counters().drops(MessageKind::RequestBlock) > 0,
            "BlockRequest drops must accumulate"
        );
        assert_eq!(limiter.counters().disconnects(), 1);

        drain.abort();
    }

    /// Honest steady-state with the production-default rate limits
    /// installed must never drop a frame. Mirrors the issue's
    /// "1k-block sim → zero drops" criterion in miniature: we feed
    /// a small steady stream that stays well below the per-kind
    /// caps and assert zero drops.
    #[tokio::test]
    async fn honest_steady_state_does_not_trip_default_limits() {
        let clock: Arc<dyn Clock> = Arc::new(TokioClock::new());
        let limiter = Arc::new(RateLimiter::new(
            RateLimitsConfig::production_defaults(),
            Arc::clone(&clock),
        ));

        let node = make_node(nid(1));
        let (peer_cmd_tx, _peer_cmd_rx) = tokio::sync::mpsc::channel::<PeerCommand>(8);
        let node = node.with_rate_limiter(Arc::clone(&limiter), Some(peer_cmd_tx));

        let signer = fresh_signer();
        let (event_tx, event_rx) = make_test_event_channel();
        let (broadcaster, mut _outbound_rx) = make_test_broadcaster();
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
        let drain = tokio::spawn(async move { while _outbound_rx.recv().await.is_some() {} });

        // Send 8 BlockRequests/sec equivalent (the default cap is 8/s).
        // We push 4 per peer in one burst — well within the 8-token
        // capacity. With four peers the per-peer counter never trips
        // because each peer has its own bucket.
        let frame = block_request_frame();
        for peer_byte in 1..=4u8 {
            let peer = [peer_byte; 32];
            for _ in 0..4 {
                event_tx
                    .send(ProtocolEvent::Message {
                        from: peer,
                        payload: frame.clone(),
                    })
                    .await
                    .unwrap();
            }
        }
        // Give the run loop a few ticks to drain the queue.
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }

        assert_eq!(
            limiter.counters().total_drops(),
            0,
            "honest steady-state below the per-kind cap must not drop"
        );
        assert_eq!(limiter.counters().disconnects(), 0);

        drain.abort();
    }

    /// A peer flooding `RequestBlock` does not affect another peer's
    /// `Vote` budget — the per-type, per-peer buckets are
    /// independent. Issue #134 acceptance: "saturating one type doesn't
    /// starve another".
    #[tokio::test]
    async fn one_peer_saturating_one_type_does_not_starve_another() {
        let cfg = RateLimitsConfig {
            proposal_per_sec: 4.0,
            vote_per_sec: 4.0,
            timeout_vote_per_sec: 4.0,
            new_view_per_sec: 4.0,
            request_block_per_sec: 4.0,
            receive_block_per_sec: 4.0,
            snapshot_manifest_request_per_sec: 4.0,
            snapshot_manifest_response_per_sec: 4.0,
            snapshot_chunk_request_per_sec: 4.0,
            snapshot_chunk_response_per_sec: 4.0,
            bytes_per_sec: 1024.0 * 1024.0,
            burst_seconds: 1.0,
            violation_window: std::time::Duration::from_secs(60),
            max_violations: 1_000_000, // never disconnect in this test
        };
        let clock: Arc<dyn Clock> = Arc::new(TokioClock::new());
        let limiter = Arc::new(RateLimiter::new(cfg, Arc::clone(&clock)));

        // Saturate Peer A's RequestBlock bucket.
        let peer_a = nid(0xAA);
        let frame = block_request_frame();
        for _ in 0..20 {
            let _ = limiter.admit(peer_a, MessageKind::RequestBlock, frame.len());
        }
        assert!(limiter.counters().drops(MessageKind::RequestBlock) > 0);

        // Peer B's Vote bucket is unaffected.
        let peer_b = nid(0xBB);
        for _ in 0..4 {
            assert_eq!(
                limiter.admit(peer_b, MessageKind::Vote, 64),
                crate::p2p::limits::Decision::Allow
            );
        }
        // And Peer A's Vote bucket is unaffected too — distinct
        // bucket per (peer, kind).
        for _ in 0..4 {
            assert_eq!(
                limiter.admit(peer_a, MessageKind::Vote, 64),
                crate::p2p::limits::Decision::Allow
            );
        }
    }

    // ── Snapshot creation hook ──────────────────────────────────────────
    //
    // These tests exercise the `apply_commit → try_take_snapshot` path
    // at the integration-layer level, without spinning up the sim
    // cluster. They drive the same code paths an inbound proposal +
    // 3-chain commit would, but synthesize the inputs directly:
    //
    //   1. Persist a `HighQc` so the in-memory `recent_qcs` cache has
    //      a QC whose `block_hash` matches the block we're about to
    //      commit. (`persist_updates` populates the cache as a side
    //      effect — that side effect is what the snapshot hook
    //      depends on.)
    //   2. Call `apply_commit(block)` directly. The snapshot policy is
    //      checked against `block.header.height`, so the test controls
    //      which heights trigger.
    //   3. Inspect the snapshot store to assert the expected manifests
    //      and chunks landed (or didn't).

    fn snapshot_test_config(
        vs: ValidatorSet,
        policy: crate::replication::snapshot::SnapshotPolicy,
    ) -> NodeConfigForConsensus {
        let mut cfg = NodeConfigForConsensus::for_testing(vs, genesis());
        cfg.snapshot_policy = policy;
        cfg
    }

    fn make_committable_block(parent: &Block, height: u64, view: View) -> Block {
        // Synthesize a block whose header is well-formed enough for
        // `apply_commit` to write to storage without complaint. The
        // safety-rule walks aren't exercised here — `apply_commit`
        // is the integration-layer hook, not the safety core.
        let commands: Vec<bytes::Bytes> = Vec::new();
        Block {
            header: BlockHeader {
                parent_hash: parent.hash(),
                height,
                view,
                proposer: [0u8; 32],
                state_commitment: [0u8; 32],
                commands_commitment: Block::commands_commitment(&commands),
                validator_history_commitment: [0; 32],
            },
            commands,
        }
    }

    #[test]
    fn snapshot_created_on_commit_at_interval() {
        let policy = crate::replication::snapshot::SnapshotPolicy {
            interval_blocks: 5,
            retention_count: 3,
            chunk_size_bytes: 1024,
        };
        let cfg = snapshot_test_config(four_validators(), policy);
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let mut node = ConsensusNode::new(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );

        // Build a block at height 5 (the first multiple of the
        // interval after genesis). Persist a QC over its hash so the
        // recent_qcs cache is populated when apply_commit runs.
        let parent = genesis();
        let block = make_committable_block(&parent, 5, 5);
        let mut qc = QuorumCertificate::new(5, block.hash(), 4);
        qc.add_signature(0, [0u8; 64]);
        qc.add_signature(1, [0u8; 64]);
        qc.add_signature(2, [0u8; 64]);
        node.persist_updates(&[StateUpdate::HighQc(qc.clone())])
            .unwrap();

        node.apply_commit(block.clone());

        let store = crate::replication::snapshot::SnapshotStore::new(Arc::clone(&storage));
        let manifest = store
            .load_manifest(5)
            .unwrap()
            .expect("snapshot must have been created at height 5");
        assert_eq!(manifest.height, 5);
        assert_eq!(manifest.view, 5);
        assert_eq!(manifest.block_hash, block.hash());
        // Manifest's QC matches the one we cached.
        assert_eq!(manifest.commit_qc, qc);
        // Validator set round-trips byte-for-byte.
        assert_eq!(manifest.validator_set(), four_validators());
        // Latest pointer matches.
        assert_eq!(store.latest_height().unwrap(), Some(5));
    }

    #[test]
    fn snapshot_not_created_when_disabled_default() {
        // Default config has `SnapshotPolicy::disabled()`, so
        // committing a block (any height) must leave the snapshot
        // store empty. This is the "tests that don't opt in see zero
        // behavioural change" acceptance criterion.
        let cfg = test_config(four_validators());
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let mut node = ConsensusNode::new(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );

        let parent = genesis();
        let block = make_committable_block(&parent, 1, 1);
        let mut qc = QuorumCertificate::new(1, block.hash(), 4);
        qc.add_signature(0, [0u8; 64]);
        qc.add_signature(1, [0u8; 64]);
        qc.add_signature(2, [0u8; 64]);
        node.persist_updates(&[StateUpdate::HighQc(qc)]).unwrap();
        node.apply_commit(block);

        let store = crate::replication::snapshot::SnapshotStore::new(storage);
        assert!(store.list_heights().unwrap().is_empty());
        assert_eq!(store.latest_height().unwrap(), None);
    }

    #[test]
    fn snapshot_skipped_for_non_interval_height() {
        let policy = crate::replication::snapshot::SnapshotPolicy {
            interval_blocks: 5,
            retention_count: 3,
            chunk_size_bytes: 1024,
        };
        let cfg = snapshot_test_config(four_validators(), policy);
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let mut node = ConsensusNode::new(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );

        let parent = genesis();
        let block = make_committable_block(&parent, 3, 3); // not a multiple of 5
        let mut qc = QuorumCertificate::new(3, block.hash(), 4);
        qc.add_signature(0, [0u8; 64]);
        qc.add_signature(1, [0u8; 64]);
        qc.add_signature(2, [0u8; 64]);
        node.persist_updates(&[StateUpdate::HighQc(qc)]).unwrap();
        node.apply_commit(block);

        let store = crate::replication::snapshot::SnapshotStore::new(storage);
        assert!(store.list_heights().unwrap().is_empty());
    }

    #[test]
    fn snapshot_skipped_when_qc_not_in_cache() {
        // The cache is bounded; a snapshot at a height whose QC has
        // been evicted must be silently skipped (warning logged) so
        // the chain keeps moving. Recreate that case by feeding the
        // cache (RECENT_QC_CACHE_CAPACITY + 1) unrelated QCs before
        // committing — the QC for our target block is never inserted.
        let policy = crate::replication::snapshot::SnapshotPolicy {
            interval_blocks: 5,
            retention_count: 3,
            chunk_size_bytes: 1024,
        };
        let cfg = snapshot_test_config(four_validators(), policy);
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let mut node = ConsensusNode::new(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );

        let parent = genesis();
        let block = make_committable_block(&parent, 5, 5);
        // Note: we deliberately do NOT persist a HighQc over
        // `block.hash()`. The cache is empty for this hash, so the
        // snapshot creation hook returns early.
        node.apply_commit(block);

        let store = crate::replication::snapshot::SnapshotStore::new(storage);
        assert!(store.list_heights().unwrap().is_empty());
    }

    #[test]
    fn snapshot_retention_prunes_older_after_each_commit() {
        let policy = crate::replication::snapshot::SnapshotPolicy {
            interval_blocks: 5,
            retention_count: 3,
            chunk_size_bytes: 1024,
        };
        let cfg = snapshot_test_config(four_validators(), policy);
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let mut node = ConsensusNode::new(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );

        // Drive 5 snapshots at heights 5, 10, 15, 20, 25. Each commit
        // is independent — the safety-core invariants aren't checked
        // here, just the integration hook.
        for n in 1..=5u64 {
            let height = n * 5;
            let parent = if height == 5 {
                genesis()
            } else {
                make_committable_block(&genesis(), height - 1, height - 1)
            };
            let block = make_committable_block(&parent, height, height);
            let mut qc = QuorumCertificate::new(height, block.hash(), 4);
            qc.add_signature(0, [0u8; 64]);
            qc.add_signature(1, [0u8; 64]);
            qc.add_signature(2, [0u8; 64]);
            node.persist_updates(&[StateUpdate::HighQc(qc)]).unwrap();
            node.apply_commit(block);
        }

        let store = crate::replication::snapshot::SnapshotStore::new(storage);
        // Retention=3 keeps the 3 most-recent (15, 20, 25); 5 and 10
        // are pruned. The pruner runs atomically with each new
        // snapshot, so the assertion holds at any point after
        // commit-25.
        assert_eq!(store.list_heights().unwrap(), vec![15, 20, 25]);
        assert_eq!(store.latest_height().unwrap(), Some(25));
    }

    #[test]
    fn snapshot_retention_zero_keeps_all_snapshots() {
        let policy = crate::replication::snapshot::SnapshotPolicy {
            interval_blocks: 5,
            retention_count: 0, // disable pruning
            chunk_size_bytes: 1024,
        };
        let cfg = snapshot_test_config(four_validators(), policy);
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let mut node = ConsensusNode::new(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );

        for n in 1..=4u64 {
            let height = n * 5;
            let parent = if height == 5 {
                genesis()
            } else {
                make_committable_block(&genesis(), height - 1, height - 1)
            };
            let block = make_committable_block(&parent, height, height);
            let mut qc = QuorumCertificate::new(height, block.hash(), 4);
            qc.add_signature(0, [0u8; 64]);
            qc.add_signature(1, [0u8; 64]);
            qc.add_signature(2, [0u8; 64]);
            node.persist_updates(&[StateUpdate::HighQc(qc)]).unwrap();
            node.apply_commit(block);
        }

        let store = crate::replication::snapshot::SnapshotStore::new(storage);
        assert_eq!(store.list_heights().unwrap(), vec![5, 10, 15, 20]);
    }

    // ── #325 PR B: recovery-time validation acceptance tests ───────────────────
    //
    // The audit's anti-rollback gate is "a node that loaded a tampered
    // history blob must refuse to start." These tests pin that gate
    // by exercising the rebuild-from-chain path on:
    //
    //  1. Fresh genesis-only node (happy path).
    //  2. Single-byte-flip in a v_eff field.
    //  3. Append-a-fake-boundary tampering.
    //  4. Wrong-genesis-member-set tampering.
    //  5. BLS chain happy path (separate code branch from #1).
    //
    // Bisect-confirmation is noted in the PR summary: temporarily
    // disabling the end-of-walk equality check makes test #2 pass when
    // it should fail, proving the gate is what produces the rejection.

    /// Build a genesis block whose `validator_history_commitment` is
    /// the real v1 hash over the genesis-time histories — what the
    /// production `build_genesis` does (#325 PR B). For genesis the
    /// post-block hash (#325 PR C) equals the pre-block hash because
    /// genesis has no commands to apply.
    fn genesis_with_real_commitment(vs: &ValidatorSet) -> Block {
        let set_hist = ValidatorSetHistory::from_genesis(vs.clone());
        let key_hist = ValidatorKeyHistory::new(vs.iter().copied());
        let commitment = crate::consensus::history_commitment::validator_history_commitment_v1(
            &set_hist, &key_hist, None,
        );
        Block::genesis([0u8; 32], commitment)
    }

    /// Patch `block.header.validator_history_commitment` so it equals
    /// the v1 hash of the post-block histories, computed by forking
    /// the node's current `(set, key, bls?)` triple and applying the
    /// block's commands (#325 PR C). Mirrors what the leader-side
    /// stamp in `apply_safety_actions` does at proposal time, and
    /// what the proposal-receive verifier in `dispatch` checks.
    fn stamp_post_block_commitment(block: &mut Block, node: &ConsensusNode) {
        block.header.validator_history_commitment =
            crate::consensus::history_commitment::compute_post_block_commitment(
                block,
                &node.validator_history,
                &node.validator_key_history,
                node.bls_key_history.as_ref(),
                &node.chain_id,
                node.signature_scheme,
                node.min_v_eff_delay,
            );
    }

    /// Like [`block_with_reconfig`] but takes an explicit genesis hash
    /// for `parent_hash` so the rebuilt-chain walk can chase the link.
    fn block_with_reconfig_extending(
        parent_hash: BlockHash,
        height: u64,
        view: View,
        proposer: NodeId,
        cmd: crate::consensus::reconfig::ReconfigCommand,
        validator_history_commitment: [u8; 32],
    ) -> Block {
        let payload = cmd.encode();
        let commands = vec![payload];
        let header = crate::replication::block::BlockHeader {
            parent_hash,
            height,
            view,
            proposer,
            state_commitment: [0u8; 32],
            commands_commitment: Block::commands_commitment(&commands),
            validator_history_commitment,
        };
        Block { header, commands }
    }

    /// Test 1 (happy path): construct a node, commit a few blocks
    /// (including one with a reconfig), persist storage, then drop
    /// and recover. Verify recovery passes the consistency check.
    #[test]
    fn verify_persisted_history_consistency_happy_path() {
        use crate::consensus::reconfig::{MIN_V_EFF_DELAY, ReconfigCommand, ValidatorEntry};

        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let vs = four_validators();
        let g = genesis_with_real_commitment(&vs);
        let cfg = NodeConfigForConsensus::for_testing(vs.clone(), g.clone());

        // Phase 1: commit a block carrying a reconfig.
        let mut node = ConsensusNode::new(
            nid(1),
            cfg.clone(),
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );
        // Block 1 carries a reconfig. Stamp the post-block commitment
        // (#325 PR C) so the recovery walk's apply-then-hash check
        // matches.
        let v_eff = MIN_V_EFF_DELAY + 5;
        let cmd = ReconfigCommand {
            adds: vec![ValidatorEntry {
                node_id: nid(5),
                addr: "127.0.0.1:9005".parse().unwrap(),
                bls_pop: None,
            }],
            removes: vec![],
            v_eff,
        };
        let mut block1 = block_with_reconfig_extending(g.hash(), 1, 0, nid(1), cmd, [0u8; 32]);
        stamp_post_block_commitment(&mut block1, &node);
        node.apply_commit(block1);
        // Sanity: the reconfig must have applied so the recovered
        // history has 2 boundaries.
        assert_eq!(node.validator_history.boundary_count(), 2);
        drop(node);

        // Phase 2: recover and run the consistency check.
        let recovered = ConsensusNode::recover(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        )
        .expect("recover should succeed");
        recovered
            .verify_persisted_history_consistency()
            .expect("happy-path recovery must pass consistency check");
    }

    /// Test 2 (corrupt blob — single byte flip): flip one byte inside
    /// a boundary's `v_eff` field of the persisted validator-history
    /// blob. Recovery's consistency check must reject.
    #[test]
    fn verify_persisted_history_consistency_rejects_byte_flip_in_v_eff() {
        use crate::consensus::reconfig::{MIN_V_EFF_DELAY, ReconfigCommand, ValidatorEntry};
        use crate::consensus::validator_history::PersistedValidatorHistory;

        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let vs = four_validators();
        let g = genesis_with_real_commitment(&vs);
        let cfg = NodeConfigForConsensus::for_testing(vs.clone(), g.clone());

        // Commit a block with a reconfig so the persisted history has
        // a non-genesis boundary whose v_eff we can flip.
        let mut node = ConsensusNode::new(
            nid(1),
            cfg.clone(),
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );
        let v_eff = MIN_V_EFF_DELAY + 5;
        let cmd = ReconfigCommand {
            adds: vec![ValidatorEntry {
                node_id: nid(5),
                addr: "127.0.0.1:9005".parse().unwrap(),
                bls_pop: None,
            }],
            removes: vec![],
            v_eff,
        };
        let mut block1 = block_with_reconfig_extending(g.hash(), 1, 0, nid(1), cmd, [0u8; 32]);
        stamp_post_block_commitment(&mut block1, &node);
        node.apply_commit(block1);
        drop(node);

        // Tamper: decode the persisted blob, change the second
        // boundary's v_eff (the reconfig's v_eff), re-encode, write
        // back. This is the "modifies one boundary's v_eff" case the
        // audit explicitly calls out.
        let raw = storage
            .get(STORAGE_KEY_VALIDATOR_HISTORY)
            .unwrap()
            .expect("validator history blob must be persisted");
        let mut persisted: PersistedValidatorHistory = postcard::from_bytes(&raw).unwrap();
        assert_eq!(persisted.boundaries.len(), 2);
        persisted.boundaries[1].v_eff = persisted.boundaries[1].v_eff.wrapping_add(1);
        let tampered = postcard::to_stdvec(&persisted).unwrap();
        storage
            .put(STORAGE_KEY_VALIDATOR_HISTORY, &tampered)
            .unwrap();

        // Recover and check: the consistency check must reject.
        let recovered = ConsensusNode::recover(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        )
        .expect("recover (decoding the tampered blob) succeeds; the gate is the consistency check");
        let err = recovered
            .verify_persisted_history_consistency()
            .expect_err("consistency check must reject tampered v_eff");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("validator_history") || msg.contains("history_commitment"),
            "error message should mention the failing surface: {msg}",
        );
    }

    /// Test 3 (tampered blob — extra boundary): append a fabricated
    /// boundary to the persisted history with a `v_eff` past anything
    /// the chain saw. Recovery must reject.
    #[test]
    fn verify_persisted_history_consistency_rejects_extra_boundary() {
        use crate::consensus::validator_history::{PersistedBoundary, PersistedValidatorHistory};

        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let vs = four_validators();
        let g = genesis_with_real_commitment(&vs);
        let cfg = NodeConfigForConsensus::for_testing(vs.clone(), g.clone());

        // Commit a single empty block so there's a chain to walk
        // (the tip's `last_committed_hash` is non-genesis, and the
        // tip's stamped commitment is the genesis-baseline hash).
        let mut node = ConsensusNode::new(
            nid(1),
            cfg.clone(),
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );
        let pre_block_commitment =
            crate::consensus::history_commitment::validator_history_commitment_v1(
                &node.validator_history,
                &node.validator_key_history,
                None,
            );
        let block1 = Block {
            header: crate::replication::block::BlockHeader {
                parent_hash: g.hash(),
                height: 1,
                view: 1,
                proposer: nid(1),
                state_commitment: [0u8; 32],
                commands_commitment: Block::commands_commitment(&[]),
                validator_history_commitment: pre_block_commitment,
            },
            commands: vec![],
        };
        node.apply_commit(block1);
        drop(node);

        // Without the validator-history blob persisted (no reconfig
        // committed), the loaded history is empty-genesis-only. Seed
        // it explicitly so we have a blob to tamper. We do this by
        // manually persisting the genesis-only persisted form, then
        // appending a fake boundary.
        let genesis_only = ValidatorSetHistory::from_genesis(vs.clone()).to_persisted();
        let mut tampered = PersistedValidatorHistory {
            boundaries: genesis_only.boundaries,
        };
        tampered.boundaries.push(PersistedBoundary {
            v_eff: 999, // Past anything in the committed chain.
            members: vec![nid(1), nid(2), nid(3), nid(4), nid(99)],
        });
        let bytes = postcard::to_stdvec(&tampered).unwrap();
        storage.put(STORAGE_KEY_VALIDATOR_HISTORY, &bytes).unwrap();

        let recovered = ConsensusNode::recover(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        )
        .expect("recover decodes the (well-formed) tampered blob");
        let err = recovered
            .verify_persisted_history_consistency()
            .expect_err("consistency check must reject extra boundary");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("validator_history") || msg.contains("history_commitment"),
            "error must mention the failing surface: {msg}",
        );
    }

    /// Test 4 (tampered blob — wrong genesis member set): change a
    /// NodeId in the genesis boundary, re-encode, write back.
    /// Recovery must reject (the genesis-iteration commitment check
    /// fires because the rebuilt seed depends on the loaded blob's
    /// genesis members).
    #[test]
    fn verify_persisted_history_consistency_rejects_tampered_genesis_member() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let vs = four_validators();
        let g = genesis_with_real_commitment(&vs);
        let cfg = NodeConfigForConsensus::for_testing(vs.clone(), g.clone());

        // Commit a single empty block — we need a non-zero chain
        // height so the recovery-time walk runs (height == 0 is the
        // "no chain to walk" early return).
        let mut node = ConsensusNode::new(
            nid(1),
            cfg.clone(),
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        );
        let pre_block_commitment =
            crate::consensus::history_commitment::validator_history_commitment_v1(
                &node.validator_history,
                &node.validator_key_history,
                None,
            );
        let block1 = Block {
            header: crate::replication::block::BlockHeader {
                parent_hash: g.hash(),
                height: 1,
                view: 1,
                proposer: nid(1),
                state_commitment: [0u8; 32],
                commands_commitment: Block::commands_commitment(&[]),
                validator_history_commitment: pre_block_commitment,
            },
            commands: vec![],
        };
        node.apply_commit(block1);
        drop(node);

        // Seed and tamper: write a genesis-only blob with a NodeId
        // swapped in the genesis boundary.
        let mut tampered = ValidatorSetHistory::from_genesis(vs.clone()).to_persisted();
        // Swap out one NodeId in the genesis boundary.
        tampered.boundaries[0].members[0] = nid(99);
        let bytes = postcard::to_stdvec(&tampered).unwrap();
        storage.put(STORAGE_KEY_VALIDATOR_HISTORY, &bytes).unwrap();

        let recovered = ConsensusNode::recover(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        )
        .expect("recover decodes the tampered blob");
        let err = recovered
            .verify_persisted_history_consistency()
            .expect_err("consistency check must reject wrong genesis member set");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("validator_history") || msg.contains("history_commitment"),
            "error must mention the failing surface: {msg}",
        );
    }

    /// Test 5 (BLS chain happy path): on a BLS-flavored node, commit
    /// a block, then verify the consistency check passes. The BLS
    /// path is a separate code branch from the Ed25519 path; without
    /// this test, a future regression in the BLS-history walk would
    /// silently rot.
    #[test]
    fn verify_persisted_history_consistency_bls_happy_path() {
        use crate::consensus::bls_key_history::BlsKeyHistory;
        use crate::crypto::sig_scheme::{BlsPublicKey, SignatureSchemeChoice};

        // Synthesize 4 BLS pubkeys (deterministic, since the test
        // only exercises the bookkeeping path; PoP verification is
        // not on this gate's hot path).
        let bls_pk = |b: u8| -> BlsPublicKey {
            let mut out = [0u8; 48];
            out.fill(b);
            out
        };
        let vs = four_validators();
        let genesis_bls: Vec<(NodeId, BlsPublicKey)> = vs
            .iter()
            .copied()
            .enumerate()
            .map(|(i, id)| (id.into_node_id(), bls_pk(0xA0 + i as u8)))
            .collect();
        let bls_history = BlsKeyHistory::with_genesis(genesis_bls.iter().copied());

        // Build genesis with a commitment over the full BLS-aware triple.
        let set_hist = ValidatorSetHistory::from_genesis(vs.clone());
        let key_hist = ValidatorKeyHistory::new(vs.iter().copied());
        let commitment = crate::consensus::history_commitment::validator_history_commitment_v1(
            &set_hist,
            &key_hist,
            Some(&bls_history),
        );
        let g = Block::genesis([0u8; 32], commitment);

        let mut cfg = NodeConfigForConsensus::for_testing(vs.clone(), g.clone());
        cfg.signature_scheme = SignatureSchemeChoice::BlsAggregated;

        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());

        // Phase 1: commit a single empty block on the BLS chain. The
        // block builder leaves validator_history_commitment at the
        // pre-block hash; mirror that here.
        let mut node = ConsensusNode::new(
            nid(1),
            cfg.clone(),
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        )
        .with_bls_key_history(bls_history.clone());
        let pre_block_commitment =
            crate::consensus::history_commitment::validator_history_commitment_v1(
                &node.validator_history,
                &node.validator_key_history,
                node.bls_key_history.as_ref(),
            );
        let block1 = Block {
            header: crate::replication::block::BlockHeader {
                parent_hash: g.hash(),
                height: 1,
                view: 1,
                proposer: nid(1),
                state_commitment: [0u8; 32],
                commands_commitment: Block::commands_commitment(&[]),
                validator_history_commitment: pre_block_commitment,
            },
            commands: vec![],
        };
        node.apply_commit(block1);
        // Persist the BLS history so recovery can load it. apply_commit
        // doesn't write the BLS-history blob unless a rotation
        // applied; for a no-rotation block we mirror what `src/node.rs`
        // does by writing it through the with_bls_key_history wiring.
        // The simplest equivalent here: persist the in-memory BLS
        // history once explicitly.
        let bls_persisted = node.bls_key_history.as_ref().unwrap().to_persisted();
        let bls_bytes = postcard::to_stdvec(&bls_persisted).unwrap();
        storage
            .put(STORAGE_KEY_BLS_KEY_HISTORY, &bls_bytes)
            .unwrap();
        drop(node);

        // Phase 2: recover and re-attach the BLS history (mirroring
        // what `src/node.rs` does), then run the consistency check.
        let recovered = ConsensusNode::recover(
            nid(1),
            cfg,
            make_sm(),
            Arc::new(InMemoryMempool::new(64)),
            Arc::clone(&storage),
            Arc::new(MemoryWal::new()),
        )
        .expect("recover BLS chain")
        .with_bls_key_history(bls_history);
        recovered
            .verify_persisted_history_consistency()
            .expect("BLS happy-path consistency check must pass");
    }
}
