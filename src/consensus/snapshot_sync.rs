//! Joiner-side snapshot-fetch state machine.
//!
//! Pure state machine with no I/O — the integration layer in
//! [`crate::consensus::node::ConsensusNode`] feeds it observations
//! (inbound proposals, manifest/chunk responses, peer disconnects)
//! and executes the [`SnapshotSyncAction`]s it returns (send wire
//! messages, restore state, log abort).
//!
//! # Lifecycle (#229 + #230)
//!
//! ```text
//! Idle  ──observe_proposal (lag ≥ interval)──► ManifestPending
//!     │                                              │
//!     │                                              │ on_manifest_response
//!     │                                              ▼
//!     │                                          Fetching
//!     │                                              │
//!     │     on_chunk_response (last chunk OK) ◄──────┤
//!     │                                              │
//!     ▼                                              ▼
//! Aborted ◄──── on_*_response (bad / exhausted) ──► Done
//! ```
//!
//! `Aborted` and `Done` are terminal — once entered, the state
//! machine ignores further events. The integration layer treats
//! `Aborted` as "snapshot path failed; rely on block-sync"
//! (matching the issue's stated failure mode: "Snapshot is an
//! optimization; tail-sync is the correctness path.").
//!
//! # Multi-source fetch (#230)
//!
//! Once the primary peer's manifest verifies, the state machine
//! transitions to [`State::Fetching`] with a **candidate set** of
//! peers it considers reasonable chunk sources. The candidate set
//! is seeded from:
//!
//! - the primary peer (the one whose manifest we accepted),
//! - every other proposer the joiner has observed since boot,
//! - additional peers added later via [`SnapshotSync::add_candidate`]
//!   (for example, the integration layer can plumb in
//!   `Discovery::known_peers()` once it's populated).
//!
//! Chunk fetch runs as a **workpool** with sticky chunk-to-peer
//! assignment. At most [`MAX_CONCURRENT_CHUNK_REQUESTS`] chunks are
//! in flight simultaneously, capped per peer at
//! [`PER_PEER_CHUNK_CONCURRENCY`] so a single fast peer doesn't get
//! saturated while others sit idle. On any per-chunk failure
//! (peer says "no chunk", verify fails, peer disconnects mid-fetch)
//! the chunk is reassigned to a different candidate. After
//! [`PER_CHUNK_RETRY_BUDGET`] failed attempts on distinct peers,
//! the entire fetch aborts — repeated verification failures across
//! multiple peers point at a corrupt manifest, not flaky peers.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};

use bytes::Bytes;

use crate::consensus::validator_set::ValidatorSet;
use crate::p2p::NodeId;
use crate::replication::snapshot::{ManifestError, SnapshotManifest, SnapshotPolicy, verify_chunk};

/// Cap on the number of chunk requests in flight at any moment
/// across the workpool. Picked to balance bandwidth utilization
/// against per-peer fairness; production-default 1 MiB chunks at
/// four-way concurrency consumes ~4 MiB of pending buffer.
pub const MAX_CONCURRENT_CHUNK_REQUESTS: u32 = 4;

/// Cap on the number of chunk requests in flight to any single
/// peer. Two means we keep one fast peer busy without letting it
/// monopolize the workpool — the issue's "per-peer concurrency cap
/// so one fast peer doesn't get saturated while others sit idle."
pub const PER_PEER_CHUNK_CONCURRENCY: u32 = 2;

/// Maximum number of distinct peers the workpool will try for a
/// single chunk before giving up. After this many tried peers, the
/// fetch aborts: repeated failure across different sources points at
/// a corrupt manifest rather than flaky peers.
pub const PER_CHUNK_RETRY_BUDGET: u32 = 3;

/// Per-chunk bookkeeping inside [`State::Fetching`].
///
/// `tried` accumulates peers we've attempted (and failed) for this
/// chunk so the scheduler doesn't re-pick them. `attempts` is the
/// running count; aborts when it crosses [`PER_CHUNK_RETRY_BUDGET`].
#[derive(Debug, Clone)]
struct ChunkSlot {
    status: ChunkStatus,
    tried: HashSet<NodeId>,
    attempts: u32,
}

#[derive(Debug, Clone)]
enum ChunkStatus {
    Pending,
    InFlight { peer: NodeId },
    Received(Bytes),
}

/// State the joiner-side fetch is currently in.
#[derive(Debug)]
enum State {
    /// No fetch in progress. `observed_peers` accumulates proposers
    /// the joiner has seen, so when lag is detected we can seed the
    /// candidate set with multiple peers right away.
    Idle {
        observed_peers: HashSet<NodeId>,
    },
    /// Manifest request sent to `primary_peer`; waiting for the
    /// response. `observed_peers` keeps accumulating so the
    /// candidate set grows even before the fetch starts.
    ManifestPending {
        primary_peer: NodeId,
        observed_peers: HashSet<NodeId>,
    },
    /// Manifest verified; chunks being fetched in parallel from
    /// `candidates` under workpool semantics.
    Fetching {
        /// Boxed because `SnapshotManifest` is several hundred
        /// bytes; clippy's `large_enum_variant` lint flags an
        /// unboxed inline.
        manifest: Box<SnapshotManifest>,
        /// Peers the workpool considers reasonable chunk sources.
        /// Entries are removed on disconnect or when a chunk fails
        /// verification.
        candidates: Vec<NodeId>,
        /// Per-peer in-flight count (capped at
        /// [`PER_PEER_CHUNK_CONCURRENCY`] each).
        in_flight_per_peer: HashMap<NodeId, u32>,
        /// Indexed by `chunk_idx` (0..manifest.chunk_count).
        chunks: Vec<ChunkSlot>,
    },
    Done,
    Aborted,
}

/// Outcome of feeding an event into [`SnapshotSync`].
///
/// The integration layer is responsible for executing each action:
/// - `SendManifestRequest` / `SendChunkRequest`: encode a wire
///   message and dispatch via the `Broadcaster`.
/// - `Restore`: pass the manifest + assembled payload to
///   `ConsensusNode::restore_from_snapshot`.
/// - `Abort`: log the reason (`warn` is appropriate; the snapshot
///   path is an optimization) and let block-sync take over.
#[derive(Debug, Clone)]
pub enum SnapshotSyncAction {
    SendManifestRequest {
        peer: NodeId,
    },
    SendChunkRequest {
        peer: NodeId,
        height: u64,
        chunk_idx: u32,
    },
    Restore {
        /// Boxed for the same reason as `State::Fetching::manifest`.
        manifest: Box<SnapshotManifest>,
        payload: Bytes,
    },
    Abort {
        reason: AbortReason,
    },
}

/// Why a fetch was aborted. Each variant is distinct so the
/// integration layer can log it precisely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbortReason {
    /// The peer replied with `SnapshotManifestResponse(None)` —
    /// they have no snapshot to serve. We're in single-source
    /// mode (#230's polling-fan-out is opportunistic, not blocking)
    /// so this aborts the fetch.
    PeerHasNoSnapshot,
    /// The manifest failed [`SnapshotManifest::verify`].
    ManifestVerifyFailed(ManifestError),
    /// A chunk's per-chunk retry budget was exhausted across all
    /// available candidates. The integration layer logs `chunk_idx`
    /// and `attempts`; the most likely cause is a corrupt manifest
    /// rather than flaky peers.
    ChunkRetryBudgetExhausted { chunk_idx: u32, attempts: u32 },
    /// The candidate set went empty (every peer was dropped via
    /// disconnect) before the fetch finished.
    CandidatesExhausted,
}

/// Pure state machine driving the joiner-side fetch. Owns no I/O;
/// every interaction with the outside world is mediated by the
/// caller executing the returned [`SnapshotSyncAction`]s.
#[derive(Debug)]
pub struct SnapshotSync {
    state: State,
    policy: SnapshotPolicy,
}

impl SnapshotSync {
    /// New state machine in `Idle` with the given policy. When
    /// `policy.is_enabled()` is false, every observation is a
    /// no-op — the state machine never leaves `Idle`.
    pub fn new(policy: SnapshotPolicy) -> Self {
        Self {
            state: State::Idle {
                observed_peers: HashSet::new(),
            },
            policy,
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(
            self.state,
            State::ManifestPending { .. } | State::Fetching { .. },
        )
    }

    pub fn is_idle(&self) -> bool {
        matches!(self.state, State::Idle { .. })
    }

    pub fn is_done(&self) -> bool {
        matches!(self.state, State::Done)
    }

    pub fn is_aborted(&self) -> bool {
        matches!(self.state, State::Aborted)
    }

    /// Observe an inbound proposal at `proposal_height` proposed by
    /// `proposer`. The proposer is added to the running set of
    /// observed peers; if the joiner is `Idle` and the height
    /// implies a lag of at least `interval_blocks`, transitions to
    /// `ManifestPending` and emits a manifest request to
    /// `proposer`.
    ///
    /// `validator_set` is consulted defensively — the proposer must
    /// be a member. Envelope ingress already enforces this, so the
    /// check guards against wire bugs that would otherwise let a
    /// non-validator inject themselves into the candidate set.
    pub fn observe_proposal(
        &mut self,
        last_committed_height: u64,
        proposal_height: impl Into<crate::consensus::Height>,
        proposer: NodeId,
        validator_set: &ValidatorSet,
    ) -> Vec<SnapshotSyncAction> {
        let proposal_height = proposal_height.into();
        if !self.policy.is_enabled() {
            return Vec::new();
        }
        // The proposer arrives over the wire as a `NodeId`. Today the
        // validator set's stable ids are byte-equal to the active
        // signing pubkey (no rotation has decoupled them yet); when
        // key rotation lookups land here (#328 follow-up) this should
        // resolve via `key_history.validator_for(...)` instead.
        let proposer_id =
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey(proposer);
        if !validator_set.contains(&proposer_id) {
            return Vec::new();
        }
        match &mut self.state {
            State::Idle { observed_peers } => {
                observed_peers.insert(proposer);
                if proposal_height.0 < last_committed_height {
                    return Vec::new();
                }
                let lag = proposal_height.0 - last_committed_height;
                if lag < self.policy.interval_blocks {
                    return Vec::new();
                }
                let mut peers = std::mem::take(observed_peers);
                peers.insert(proposer);
                self.state = State::ManifestPending {
                    primary_peer: proposer,
                    observed_peers: peers,
                };
                vec![SnapshotSyncAction::SendManifestRequest { peer: proposer }]
            }
            State::ManifestPending { observed_peers, .. } => {
                observed_peers.insert(proposer);
                Vec::new()
            }
            State::Fetching {
                candidates,
                in_flight_per_peer,
                chunks,
                manifest,
                ..
            } => {
                if !candidates.contains(&proposer) {
                    candidates.push(proposer);
                    in_flight_per_peer.entry(proposer).or_insert(0);
                }
                schedule(candidates, in_flight_per_peer, chunks, manifest.height.0)
            }
            State::Done | State::Aborted => Vec::new(),
        }
    }

    /// Add `peer` to the candidate set for chunk fetch. Used by
    /// integration layers that have additional peer-discovery
    /// sources beyond proposal observation (e.g. gossip's
    /// `Discovery::known_peers`).
    ///
    /// No-op outside of `Fetching`. Inside `Fetching`, may schedule
    /// additional chunk requests if the new peer unblocks any
    /// pending slots.
    pub fn add_candidate(&mut self, peer: NodeId) -> Vec<SnapshotSyncAction> {
        match &mut self.state {
            State::Fetching {
                candidates,
                in_flight_per_peer,
                chunks,
                manifest,
                ..
            } => {
                if !candidates.contains(&peer) {
                    candidates.push(peer);
                    in_flight_per_peer.entry(peer).or_insert(0);
                }
                schedule(candidates, in_flight_per_peer, chunks, manifest.height.0)
            }
            _ => Vec::new(),
        }
    }

    /// Process a [`crate::consensus::dispatch::Dispatch::ReceiveSnapshotManifest`].
    ///
    /// On a verified manifest from the primary peer, transitions
    /// to `Fetching` and emits chunk requests via the workpool.
    /// On any failure aborts.
    pub fn on_manifest_response(
        &mut self,
        from: NodeId,
        manifest: Option<SnapshotManifest>,
        validator_set: &ValidatorSet,
    ) -> Vec<SnapshotSyncAction> {
        let State::ManifestPending {
            primary_peer,
            observed_peers,
        } = &self.state
        else {
            return Vec::new();
        };
        if from != *primary_peer {
            return Vec::new();
        }
        let manifest = match manifest {
            Some(m) => m,
            None => {
                self.state = State::Aborted;
                return vec![SnapshotSyncAction::Abort {
                    reason: AbortReason::PeerHasNoSnapshot,
                }];
            }
        };
        if let Err(e) = manifest.verify(validator_set) {
            self.state = State::Aborted;
            return vec![SnapshotSyncAction::Abort {
                reason: AbortReason::ManifestVerifyFailed(e),
            }];
        }
        // Seed the candidate set with the primary peer plus every
        // other proposer we've observed. The set ordering is
        // deterministic (sorted) so test failures reproduce.
        let mut candidate_set: Vec<NodeId> = observed_peers.iter().copied().collect();
        if !candidate_set.contains(primary_peer) {
            candidate_set.push(*primary_peer);
        }
        candidate_set.sort();
        let in_flight_per_peer: HashMap<NodeId, u32> =
            candidate_set.iter().map(|p| (*p, 0)).collect();
        let chunk_count = manifest.chunk_count;
        let chunks: Vec<ChunkSlot> = (0..chunk_count)
            .map(|_| ChunkSlot {
                status: ChunkStatus::Pending,
                tried: HashSet::new(),
                attempts: 0,
            })
            .collect();
        self.state = State::Fetching {
            manifest: Box::new(manifest),
            candidates: candidate_set,
            in_flight_per_peer,
            chunks,
        };
        let State::Fetching {
            candidates,
            in_flight_per_peer,
            chunks,
            manifest,
            ..
        } = &mut self.state
        else {
            unreachable!("just transitioned to Fetching");
        };
        schedule(candidates, in_flight_per_peer, chunks, manifest.height.0)
    }

    /// Process a [`crate::consensus::dispatch::Dispatch::ReceiveSnapshotChunk`].
    pub fn on_chunk_response(
        &mut self,
        from: NodeId,
        height: u64,
        chunk_idx: u32,
        payload: Option<Bytes>,
    ) -> Vec<SnapshotSyncAction> {
        let State::Fetching {
            manifest,
            candidates,
            in_flight_per_peer,
            chunks,
        } = &mut self.state
        else {
            return Vec::new();
        };
        if height != manifest.height.0 {
            return Vec::new();
        }
        let Some(slot) = chunks.get_mut(chunk_idx as usize) else {
            return Vec::new();
        };
        // Drop responses we weren't expecting from this peer for
        // this chunk. Out-of-flight responses can land legitimately
        // when a peer disconnect causes a chunk to be reassigned —
        // a late response from the dropped peer should be ignored,
        // not aborted.
        match &slot.status {
            ChunkStatus::InFlight { peer } if *peer == from => {}
            _ => return Vec::new(),
        }
        // Decrement the per-peer in-flight counter regardless of
        // outcome — the slot is no longer occupied by this peer.
        if let Some(c) = in_flight_per_peer.get_mut(&from) {
            *c = c.saturating_sub(1);
        }
        match payload {
            Some(p) => {
                if let Err(_e) = verify_chunk(manifest, chunk_idx, &p) {
                    // Verification failure — peer is malicious or
                    // their snapshot is corrupt. Drop them from
                    // candidates entirely; the chunk itself goes
                    // back to Pending with this peer in `tried`,
                    // and the workpool will retry on someone else.
                    slot.tried.insert(from);
                    slot.attempts += 1;
                    slot.status = ChunkStatus::Pending;
                    candidates.retain(|p| *p != from);
                    in_flight_per_peer.remove(&from);
                    if let Some(reason) = self.check_abort_conditions(chunk_idx) {
                        self.state = State::Aborted;
                        return vec![SnapshotSyncAction::Abort { reason }];
                    }
                    return self.schedule_or_abort();
                }
                slot.status = ChunkStatus::Received(p);
                self.try_finish_or_schedule()
            }
            None => {
                // Peer didn't have this chunk (snapshot pruned, or
                // out of range on their side). Don't drop them —
                // they may still serve other chunks. Just retry
                // this chunk on someone else.
                slot.tried.insert(from);
                slot.attempts += 1;
                slot.status = ChunkStatus::Pending;
                if let Some(reason) = self.check_abort_conditions(chunk_idx) {
                    self.state = State::Aborted;
                    return vec![SnapshotSyncAction::Abort { reason }];
                }
                self.schedule_or_abort()
            }
        }
    }

    /// Notify the state machine that `peer` has disconnected.
    ///
    /// During `ManifestPending`, if the disconnected peer is the
    /// primary, abort. (Cross-source manifest agreement is opportunistic
    /// and lives on top of this primary-peer flow.)
    ///
    /// During `Fetching`, drop the peer from candidates and
    /// reassign every in-flight chunk that was on them. If the
    /// candidate set goes empty, abort.
    pub fn on_peer_disconnected(&mut self, peer: NodeId) -> Vec<SnapshotSyncAction> {
        match &mut self.state {
            State::ManifestPending { primary_peer, .. } if *primary_peer == peer => {
                self.state = State::Aborted;
                vec![SnapshotSyncAction::Abort {
                    reason: AbortReason::CandidatesExhausted,
                }]
            }
            State::ManifestPending { observed_peers, .. } => {
                observed_peers.remove(&peer);
                Vec::new()
            }
            State::Idle { observed_peers } => {
                observed_peers.remove(&peer);
                Vec::new()
            }
            State::Fetching {
                candidates,
                in_flight_per_peer,
                chunks,
                ..
            } => {
                if !candidates.contains(&peer) {
                    return Vec::new();
                }
                candidates.retain(|p| *p != peer);
                in_flight_per_peer.remove(&peer);
                // Reassign in-flight chunks that were on this peer.
                for (idx, slot) in chunks.iter_mut().enumerate() {
                    if let ChunkStatus::InFlight { peer: p } = &slot.status
                        && *p == peer
                    {
                        slot.tried.insert(peer);
                        slot.attempts += 1;
                        slot.status = ChunkStatus::Pending;
                        if let Some(reason) = check_chunk_abort(slot, idx as u32, candidates) {
                            self.state = State::Aborted;
                            return vec![SnapshotSyncAction::Abort { reason }];
                        }
                    }
                }
                self.schedule_or_abort()
            }
            State::Done | State::Aborted => Vec::new(),
        }
    }

    /// Sub-helper: after a chunk slot was just put back to
    /// `Pending`, decide whether to abort (per-chunk retry budget
    /// exhausted) and how to abort if so.
    fn check_abort_conditions(&self, chunk_idx: u32) -> Option<AbortReason> {
        let State::Fetching {
            chunks, candidates, ..
        } = &self.state
        else {
            return None;
        };
        let slot = &chunks[chunk_idx as usize];
        check_chunk_abort(slot, chunk_idx, candidates)
    }

    /// Run the scheduler. If it can't make progress (no peer
    /// eligible for any pending chunk), abort with
    /// `CandidatesExhausted` — leaving chunks in `Pending` with no
    /// way to drain them is a livelock, not a failure mode worth
    /// preserving.
    fn schedule_or_abort(&mut self) -> Vec<SnapshotSyncAction> {
        let State::Fetching {
            manifest,
            candidates,
            in_flight_per_peer,
            chunks,
        } = &mut self.state
        else {
            return Vec::new();
        };
        let height = manifest.height.0;
        let actions = schedule(candidates, in_flight_per_peer, chunks, height);
        // If no chunks are in flight AND we have pending slots
        // AND no actions were scheduled, the workpool is stuck.
        let any_in_flight = chunks
            .iter()
            .any(|c| matches!(c.status, ChunkStatus::InFlight { .. }));
        let any_pending = chunks
            .iter()
            .any(|c| matches!(c.status, ChunkStatus::Pending));
        if !any_in_flight && any_pending && actions.is_empty() {
            self.state = State::Aborted;
            return vec![SnapshotSyncAction::Abort {
                reason: AbortReason::CandidatesExhausted,
            }];
        }
        actions
    }

    /// After a chunk's payload was just stored, either schedule
    /// more requests (if any remain) or finalize and emit
    /// `Restore`.
    fn try_finish_or_schedule(&mut self) -> Vec<SnapshotSyncAction> {
        let State::Fetching { chunks, .. } = &self.state else {
            return Vec::new();
        };
        let all_done = chunks
            .iter()
            .all(|c| matches!(c.status, ChunkStatus::Received(_)));
        if !all_done {
            return self.schedule_or_abort();
        }
        // Assemble in chunk-index order.
        let State::Fetching {
            chunks, manifest, ..
        } = std::mem::replace(&mut self.state, State::Done)
        else {
            unreachable!("just matched Fetching above");
        };
        let parts: Vec<Bytes> = chunks
            .into_iter()
            .map(|c| match c.status {
                ChunkStatus::Received(b) => b,
                _ => unreachable!("all_done check above"),
            })
            .collect();
        let payload = crate::replication::snapshot::assemble_chunks(&parts);
        vec![SnapshotSyncAction::Restore { manifest, payload }]
    }
}

/// Inspect a chunk slot and decide whether the per-chunk retry
/// budget is exhausted. Returns `Some(AbortReason)` if so.
///
/// Two abort triggers:
/// - `attempts >= PER_CHUNK_RETRY_BUDGET`: tried enough peers, all
///   failed → corrupt manifest is the most likely cause.
/// - Every remaining candidate is in `tried` for this chunk, so
///   there's no peer left to retry on. Reported as
///   `CandidatesExhausted` when no candidates exist; otherwise
///   `ChunkRetryBudgetExhausted` (we have peers, just not for
///   this chunk).
fn check_chunk_abort(
    slot: &ChunkSlot,
    chunk_idx: u32,
    candidates: &[NodeId],
) -> Option<AbortReason> {
    if slot.attempts >= PER_CHUNK_RETRY_BUDGET {
        return Some(AbortReason::ChunkRetryBudgetExhausted {
            chunk_idx,
            attempts: slot.attempts,
        });
    }
    if candidates.is_empty() {
        return Some(AbortReason::CandidatesExhausted);
    }
    if candidates.iter().all(|c| slot.tried.contains(c)) {
        return Some(AbortReason::ChunkRetryBudgetExhausted {
            chunk_idx,
            attempts: slot.attempts,
        });
    }
    None
}

/// Workpool scheduler. Walks pending chunks in index order and
/// emits at most enough `SendChunkRequest`s to fill the
/// concurrency window.
///
/// Skips any chunk for which no eligible peer exists (every
/// candidate is in `tried` for this chunk, or every candidate is
/// at `PER_PEER_CHUNK_CONCURRENCY`). Skipped chunks are revisited
/// the next time the scheduler runs (after a response or peer
/// addition).
fn schedule(
    candidates: &[NodeId],
    in_flight_per_peer: &mut HashMap<NodeId, u32>,
    chunks: &mut [ChunkSlot],
    height: u64,
) -> Vec<SnapshotSyncAction> {
    let mut actions = Vec::new();
    loop {
        let total_in_flight: u32 = in_flight_per_peer.values().sum();
        if total_in_flight >= MAX_CONCURRENT_CHUNK_REQUESTS {
            break;
        }
        // Find the next pending chunk that has at least one eligible peer.
        let next = chunks.iter_mut().enumerate().find_map(|(idx, slot)| {
            if !matches!(slot.status, ChunkStatus::Pending) {
                return None;
            }
            // Pick any candidate not in `tried` and not at the
            // per-peer concurrency cap. Iteration order matches
            // candidates[]; deterministic for test reproducibility.
            for peer in candidates {
                if slot.tried.contains(peer) {
                    continue;
                }
                let in_flight = *in_flight_per_peer.get(peer).unwrap_or(&0);
                if in_flight >= PER_PEER_CHUNK_CONCURRENCY {
                    continue;
                }
                return Some((idx, *peer));
            }
            None
        });
        let Some((idx, peer)) = next else {
            break;
        };
        chunks[idx].status = ChunkStatus::InFlight { peer };
        *in_flight_per_peer.entry(peer).or_insert(0) += 1;
        actions.push(SnapshotSyncAction::SendChunkRequest {
            peer,
            height,
            chunk_idx: idx as u32,
        });
    }
    actions
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::consensus::hotstuff::QuorumCertificate;
    use crate::consensus::hotstuff::qc::quorum_size;
    use crate::replication::block::{Block, BlockHash, BlockHeader};
    use crate::replication::snapshot::{SnapshotManifest, chunk_snapshot};

    fn validator_set_4() -> ValidatorSet {
        ValidatorSet::new(vec![
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey([1u8; 32]),
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey([2u8; 32]),
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey([3u8; 32]),
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey([4u8; 32]),
        ])
    }

    fn enabled_policy(interval: u64) -> SnapshotPolicy {
        SnapshotPolicy {
            interval_blocks: interval,
            retention_count: 3,
            chunk_size_bytes: 64,
        }
    }

    fn quorum_qc(vs_len: usize, block_hash: BlockHash) -> QuorumCertificate {
        let mut qc = QuorumCertificate::new(0, block_hash, vs_len);
        for i in 0..quorum_size(vs_len) {
            qc.add_signature(i, [0u8; 64]);
        }
        qc
    }

    fn sample_block(height: u64, view: u64) -> Block {
        let parent_hash = Block::genesis([0u8; 32], [0; 32]).hash();
        let commands: Vec<Bytes> = Vec::new();
        Block {
            header: BlockHeader {
                parent_hash,
                height: crate::consensus::Height(height),
                view: crate::consensus::View(view),
                proposer: [0u8; 32],
                state_commitment: [0xCD; 32],
                commands_commitment: Block::commands_commitment(&commands),
                validator_history_commitment: [0; 32],
            },
            commands,
        }
    }

    fn build_snapshot(
        vs: &ValidatorSet,
        height: u64,
        view: u64,
        payload: &[u8],
        chunk_size: u32,
    ) -> (SnapshotManifest, Vec<Bytes>) {
        let chunks_with_hashes = chunk_snapshot(payload, chunk_size);
        let chunk_hashes: Vec<[u8; 32]> = chunks_with_hashes.iter().map(|(_, h)| *h).collect();
        let chunks: Vec<Bytes> = chunks_with_hashes.into_iter().map(|(c, _)| c).collect();
        let block = sample_block(height, view);
        let qc = quorum_qc(vs.len(), block.hash());
        let manifest = SnapshotManifest::build_for_test_genesis_histories(
            block,
            vs,
            chunk_size,
            chunk_hashes,
            qc,
            1_700_000_000,
        );
        (manifest, chunks)
    }

    fn proposer(vs: &ValidatorSet, idx: usize) -> NodeId {
        vs.get(idx).unwrap().into_node_id()
    }

    fn extract_chunk_request(action: &SnapshotSyncAction) -> (NodeId, u64, u32) {
        match action {
            SnapshotSyncAction::SendChunkRequest {
                peer,
                height,
                chunk_idx,
            } => (*peer, *height, *chunk_idx),
            other => panic!("expected SendChunkRequest, got {other:?}"),
        }
    }

    // ── Trigger / observation ──────────────────────────────────────

    #[test]
    fn disabled_policy_never_starts_fetch() {
        let mut s = SnapshotSync::new(SnapshotPolicy::disabled());
        let vs = validator_set_4();
        let actions = s.observe_proposal(0, 1_000_000, proposer(&vs, 0), &vs);
        assert!(actions.is_empty());
        assert!(s.is_idle());
    }

    #[test]
    fn observation_below_threshold_does_not_start_fetch() {
        let mut s = SnapshotSync::new(enabled_policy(50));
        let vs = validator_set_4();
        let actions = s.observe_proposal(0, 49, proposer(&vs, 0), &vs);
        assert!(actions.is_empty());
        assert!(s.is_idle());
    }

    #[test]
    fn observation_at_threshold_emits_manifest_request_to_proposer() {
        let mut s = SnapshotSync::new(enabled_policy(50));
        let vs = validator_set_4();
        let p = proposer(&vs, 0);
        let actions = s.observe_proposal(0, 50, p, &vs);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            SnapshotSyncAction::SendManifestRequest { peer } => assert_eq!(*peer, p),
            other => panic!("expected SendManifestRequest, got {other:?}"),
        }
        assert!(s.is_active());
    }

    #[test]
    fn proposer_outside_validator_set_does_not_trigger() {
        let mut s = SnapshotSync::new(enabled_policy(50));
        let vs = validator_set_4();
        let outsider: NodeId = [0x99; 32];
        let actions = s.observe_proposal(0, 100, outsider, &vs);
        assert!(actions.is_empty());
        assert!(s.is_idle());
    }

    #[test]
    fn additional_observations_during_manifest_pending_accumulate_candidates() {
        // Once a fetch is triggered, observing more proposers
        // accumulates them so the candidate set is broad once we
        // start chunk fetch.
        let mut s = SnapshotSync::new(enabled_policy(50));
        let vs = validator_set_4();
        let p0 = proposer(&vs, 0);
        let p1 = proposer(&vs, 1);
        let p2 = proposer(&vs, 2);
        let _ = s.observe_proposal(0, 100, p0, &vs);
        let _ = s.observe_proposal(0, 100, p1, &vs);
        let _ = s.observe_proposal(0, 100, p2, &vs);
        // Send the manifest. Candidate set should include p0, p1, p2.
        let payload: Vec<u8> = vec![0x55; 256];
        let (manifest, chunks) = build_snapshot(&vs, 50, 5, &payload, 64);
        let actions = s.on_manifest_response(p0, Some(manifest.clone()), &vs);
        // Workpool should issue requests across multiple peers.
        let mut peers_used: HashSet<NodeId> = HashSet::new();
        for a in &actions {
            if let SnapshotSyncAction::SendChunkRequest { peer, .. } = a {
                peers_used.insert(*peer);
            }
        }
        assert!(
            peers_used.len() >= 2,
            "with 3 candidates and 4 chunks, the workpool should fan out across ≥2 peers (got {})",
            peers_used.len(),
        );
        // At least one chunk should be in flight to a non-primary peer.
        assert!(
            peers_used.contains(&p1) || peers_used.contains(&p2),
            "non-primary peers must be utilized; peers_used={peers_used:?}",
        );
        let _ = chunks;
    }

    // ── Manifest verification ─────────────────────────────────────

    #[test]
    fn manifest_response_from_wrong_peer_is_dropped() {
        let mut s = SnapshotSync::new(enabled_policy(50));
        let vs = validator_set_4();
        let p0 = proposer(&vs, 0);
        let p1 = proposer(&vs, 1);
        let _ = s.observe_proposal(0, 100, p0, &vs);
        let payload: Vec<u8> = vec![0xAA; 32];
        let (manifest, _chunks) = build_snapshot(&vs, 50, 5, &payload, 32);
        let actions = s.on_manifest_response(p1, Some(manifest), &vs);
        assert!(actions.is_empty());
        assert!(s.is_active());
    }

    #[test]
    fn manifest_none_aborts_with_distinct_reason() {
        let mut s = SnapshotSync::new(enabled_policy(50));
        let vs = validator_set_4();
        let p0 = proposer(&vs, 0);
        let _ = s.observe_proposal(0, 100, p0, &vs);
        let actions = s.on_manifest_response(p0, None, &vs);
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            SnapshotSyncAction::Abort {
                reason: AbortReason::PeerHasNoSnapshot
            },
        ));
        assert!(s.is_aborted());
    }

    #[test]
    fn manifest_verify_failure_aborts_with_distinct_reason() {
        let mut s = SnapshotSync::new(enabled_policy(50));
        let vs = validator_set_4();
        let other_vs = ValidatorSet::new(vec![
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey([10u8; 32]),
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey([11u8; 32]),
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey([12u8; 32]),
            crate::consensus::validator_set::ValidatorId::from_genesis_pubkey([13u8; 32]),
        ]);
        let p0 = proposer(&vs, 0);
        let _ = s.observe_proposal(0, 100, p0, &vs);
        let payload: Vec<u8> = vec![0xAA; 16];
        let (manifest, _chunks) = build_snapshot(&other_vs, 50, 5, &payload, 32);
        let actions = s.on_manifest_response(p0, Some(manifest), &vs);
        assert!(matches!(
            actions.first(),
            Some(SnapshotSyncAction::Abort {
                reason: AbortReason::ManifestVerifyFailed(ManifestError::ValidatorSetMismatch),
            }),
        ));
        assert!(s.is_aborted());
    }

    // ── Workpool fetch ────────────────────────────────────────────

    #[test]
    fn happy_path_single_candidate_issues_concurrent_requests() {
        // With one candidate (PER_PEER cap = 2), the workpool
        // issues at most 2 concurrent requests to that single peer.
        let mut s = SnapshotSync::new(enabled_policy(50));
        let vs = validator_set_4();
        let p0 = proposer(&vs, 0);
        let _ = s.observe_proposal(0, 100, p0, &vs);
        let payload: Vec<u8> = vec![0x55; 256];
        let (manifest, chunks) = build_snapshot(&vs, 50, 5, &payload, 64);
        assert!(manifest.chunk_count >= 4);
        let actions = s.on_manifest_response(p0, Some(manifest.clone()), &vs);
        let chunk_reqs: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, SnapshotSyncAction::SendChunkRequest { .. }))
            .collect();
        assert_eq!(
            chunk_reqs.len() as u32,
            PER_PEER_CHUNK_CONCURRENCY,
            "single candidate must be capped at PER_PEER_CHUNK_CONCURRENCY",
        );
        // Walk every chunk through; the test must end in Restore.
        let mut next_idx_to_serve: Vec<u32> = chunk_reqs
            .iter()
            .map(|a| extract_chunk_request(a).2)
            .collect();
        for idx in 0..manifest.chunk_count {
            // Wait for the matching request to have been emitted.
            let request_idx = next_idx_to_serve.remove(0);
            assert_eq!(request_idx, idx);
            let actions = s.on_chunk_response(
                p0,
                manifest.height.0,
                idx,
                Some(chunks[idx as usize].clone()),
            );
            // Each completion may emit the next request, or Restore.
            for a in &actions {
                match a {
                    SnapshotSyncAction::SendChunkRequest { chunk_idx, .. } => {
                        next_idx_to_serve.push(*chunk_idx);
                    }
                    SnapshotSyncAction::Restore { .. } => {
                        assert!(s.is_done());
                    }
                    SnapshotSyncAction::Abort { reason } => {
                        panic!("unexpected abort: {reason:?}");
                    }
                    _ => {}
                }
            }
        }
        assert!(s.is_done());
    }

    #[test]
    fn multi_candidate_fanout_uses_distinct_peers_in_parallel() {
        // 3 candidates × 4 chunks: workpool fans 4 in flight,
        // distributed across at least 2 peers.
        let mut s = SnapshotSync::new(enabled_policy(50));
        let vs = validator_set_4();
        let p0 = proposer(&vs, 0);
        let p1 = proposer(&vs, 1);
        let p2 = proposer(&vs, 2);
        let _ = s.observe_proposal(0, 100, p0, &vs);
        let _ = s.observe_proposal(0, 100, p1, &vs);
        let _ = s.observe_proposal(0, 100, p2, &vs);
        let payload: Vec<u8> = vec![0xAA; 256];
        let (manifest, chunks) = build_snapshot(&vs, 50, 5, &payload, 64);
        let actions = s.on_manifest_response(p0, Some(manifest.clone()), &vs);
        let chunk_reqs: Vec<_> = actions
            .iter()
            .filter_map(|a| match a {
                SnapshotSyncAction::SendChunkRequest {
                    peer, chunk_idx, ..
                } => Some((*peer, *chunk_idx)),
                _ => None,
            })
            .collect();
        assert_eq!(
            chunk_reqs.len() as u32,
            MAX_CONCURRENT_CHUNK_REQUESTS,
            "multi-candidate workpool must fill the concurrency window",
        );
        let unique_peers: HashSet<NodeId> = chunk_reqs.iter().map(|(p, _)| *p).collect();
        assert!(
            unique_peers.len() >= 2,
            "fanout must touch ≥ 2 peers; got {unique_peers:?}",
        );

        // Drain the fetch by serving every chunk from whichever
        // peer was assigned. After every response, the workpool
        // may schedule additional requests; track them.
        let mut pending_requests: Vec<(NodeId, u32)> = chunk_reqs;
        while !pending_requests.is_empty() {
            let (peer, idx) = pending_requests.remove(0);
            let actions = s.on_chunk_response(
                peer,
                manifest.height.0,
                idx,
                Some(chunks[idx as usize].clone()),
            );
            for a in &actions {
                match a {
                    SnapshotSyncAction::SendChunkRequest {
                        peer, chunk_idx, ..
                    } => {
                        pending_requests.push((*peer, *chunk_idx));
                    }
                    SnapshotSyncAction::Restore { .. } => {
                        assert!(s.is_done());
                    }
                    SnapshotSyncAction::Abort { reason } => {
                        panic!("unexpected abort: {reason:?}");
                    }
                    _ => {}
                }
            }
        }
        assert!(s.is_done());
    }

    #[test]
    fn peer_disconnect_mid_fetch_reassigns_in_flight_chunks() {
        let mut s = SnapshotSync::new(enabled_policy(50));
        let vs = validator_set_4();
        let p0 = proposer(&vs, 0);
        let p1 = proposer(&vs, 1);
        let p2 = proposer(&vs, 2);
        let _ = s.observe_proposal(0, 100, p0, &vs);
        let _ = s.observe_proposal(0, 100, p1, &vs);
        let _ = s.observe_proposal(0, 100, p2, &vs);
        let payload: Vec<u8> = vec![0xBB; 256];
        let (manifest, chunks) = build_snapshot(&vs, 50, 5, &payload, 64);
        let actions = s.on_manifest_response(p0, Some(manifest.clone()), &vs);
        let initial_reqs: Vec<(NodeId, u32)> = actions
            .iter()
            .filter_map(|a| match a {
                SnapshotSyncAction::SendChunkRequest {
                    peer, chunk_idx, ..
                } => Some((*peer, *chunk_idx)),
                _ => None,
            })
            .collect();
        // Pick a peer that's actually being used and disconnect it.
        let used_peers: HashSet<NodeId> = initial_reqs.iter().map(|(p, _)| *p).collect();
        let to_drop = *used_peers.iter().next().unwrap();
        let drop_actions = s.on_peer_disconnected(to_drop);
        // Reassignment should schedule fresh requests for chunks
        // that were on the dropped peer; nothing aborts.
        assert!(
            !s.is_aborted(),
            "with 2 remaining candidates, single-peer disconnect must not abort",
        );
        // Anything that was in flight to `to_drop` should now have
        // a fresh request to a different peer.
        let dropped_chunk_indices: Vec<u32> = initial_reqs
            .iter()
            .filter(|(p, _)| *p == to_drop)
            .map(|(_, idx)| *idx)
            .collect();
        let reassigned: HashSet<u32> = drop_actions
            .iter()
            .filter_map(|a| match a {
                SnapshotSyncAction::SendChunkRequest { chunk_idx, .. } => Some(*chunk_idx),
                _ => None,
            })
            .collect();
        for idx in &dropped_chunk_indices {
            assert!(
                reassigned.contains(idx),
                "chunk {idx} was in flight on the dropped peer and must be reassigned",
            );
        }
        for a in &drop_actions {
            if let SnapshotSyncAction::SendChunkRequest { peer, .. } = a {
                assert_ne!(
                    *peer, to_drop,
                    "reassigned requests must avoid the dropped peer"
                );
            }
        }
        // Drain the rest, ignoring any responses from the dropped
        // peer that arrive late (which the state machine should
        // also ignore).
        let mut pending_requests: Vec<(NodeId, u32)> = initial_reqs
            .into_iter()
            .filter(|(p, _)| *p != to_drop)
            .collect();
        for a in drop_actions {
            if let SnapshotSyncAction::SendChunkRequest {
                peer, chunk_idx, ..
            } = a
            {
                pending_requests.push((peer, chunk_idx));
            }
        }
        while !pending_requests.is_empty() {
            let (peer, idx) = pending_requests.remove(0);
            let actions = s.on_chunk_response(
                peer,
                manifest.height.0,
                idx,
                Some(chunks[idx as usize].clone()),
            );
            for a in &actions {
                match a {
                    SnapshotSyncAction::SendChunkRequest {
                        peer, chunk_idx, ..
                    } => {
                        pending_requests.push((*peer, *chunk_idx));
                    }
                    SnapshotSyncAction::Restore { .. } => {}
                    SnapshotSyncAction::Abort { reason } => {
                        panic!("unexpected abort: {reason:?}");
                    }
                    _ => {}
                }
            }
        }
        assert!(s.is_done());
    }

    #[test]
    fn all_candidates_disconnected_aborts_cleanly() {
        let mut s = SnapshotSync::new(enabled_policy(50));
        let vs = validator_set_4();
        let p0 = proposer(&vs, 0);
        let p1 = proposer(&vs, 1);
        let _ = s.observe_proposal(0, 100, p0, &vs);
        let _ = s.observe_proposal(0, 100, p1, &vs);
        let payload: Vec<u8> = vec![0xCC; 256];
        let (manifest, _chunks) = build_snapshot(&vs, 50, 5, &payload, 64);
        let _ = s.on_manifest_response(p0, Some(manifest.clone()), &vs);
        // Drop both candidates without serving any chunk.
        let _ = s.on_peer_disconnected(p0);
        let actions = s.on_peer_disconnected(p1);
        assert!(
            matches!(actions.last(), Some(SnapshotSyncAction::Abort { .. })),
            "expected Abort, got {actions:?}",
        );
        assert!(s.is_aborted());
    }

    #[test]
    fn tampered_chunk_drops_peer_and_retries_on_another() {
        // With multi-source, a peer that serves a corrupt chunk is
        // dropped from candidates and the chunk is retried on a
        // different peer.
        let mut s = SnapshotSync::new(enabled_policy(50));
        let vs = validator_set_4();
        let p0 = proposer(&vs, 0);
        let p1 = proposer(&vs, 1);
        let _ = s.observe_proposal(0, 100, p0, &vs);
        let _ = s.observe_proposal(0, 100, p1, &vs);
        let payload: Vec<u8> = vec![0xAA; 64];
        let (manifest, chunks) = build_snapshot(&vs, 50, 5, &payload, 32);
        let actions = s.on_manifest_response(p0, Some(manifest.clone()), &vs);
        // Find a request that went to p0; serve a tampered payload.
        let (peer_for_chunk_0, chunk_idx_0) = actions
            .iter()
            .find_map(|a| match a {
                SnapshotSyncAction::SendChunkRequest {
                    peer, chunk_idx, ..
                } if *chunk_idx == 0 => Some((*peer, *chunk_idx)),
                _ => None,
            })
            .expect("chunk 0 must be requested");
        let mut tampered = chunks[chunk_idx_0 as usize].to_vec();
        tampered[0] ^= 0xFF;
        let actions = s.on_chunk_response(
            peer_for_chunk_0,
            manifest.height.0,
            chunk_idx_0,
            Some(Bytes::from(tampered)),
        );
        // No abort: the other candidate is still available.
        assert!(!s.is_aborted());
        // The chunk is reassigned to a different peer.
        let reassigned = actions.iter().find_map(|a| match a {
            SnapshotSyncAction::SendChunkRequest {
                peer, chunk_idx, ..
            } if *chunk_idx == chunk_idx_0 => Some(*peer),
            _ => None,
        });
        assert!(
            reassigned.is_some(),
            "chunk 0 must be retried after verification failure",
        );
        assert_ne!(
            reassigned.unwrap(),
            peer_for_chunk_0,
            "retry must go to a different peer",
        );
    }

    #[test]
    fn peer_has_no_chunk_retries_without_dropping_peer() {
        // PeerHasNoChunk doesn't drop the peer (it might still
        // serve other chunks); the chunk is added to its tried
        // set and the workpool retries on someone else.
        let mut s = SnapshotSync::new(enabled_policy(50));
        let vs = validator_set_4();
        let p0 = proposer(&vs, 0);
        let p1 = proposer(&vs, 1);
        let _ = s.observe_proposal(0, 100, p0, &vs);
        let _ = s.observe_proposal(0, 100, p1, &vs);
        let payload: Vec<u8> = vec![0x33; 64];
        let (manifest, _chunks) = build_snapshot(&vs, 50, 5, &payload, 32);
        let actions = s.on_manifest_response(p0, Some(manifest.clone()), &vs);
        let (peer_for_chunk_0, chunk_idx_0) = actions
            .iter()
            .find_map(|a| match a {
                SnapshotSyncAction::SendChunkRequest {
                    peer, chunk_idx, ..
                } if *chunk_idx == 0 => Some((*peer, *chunk_idx)),
                _ => None,
            })
            .expect("chunk 0 must be requested");
        let actions = s.on_chunk_response(peer_for_chunk_0, manifest.height.0, chunk_idx_0, None);
        assert!(
            !s.is_aborted(),
            "peer-has-no-chunk must not abort with another candidate available"
        );
        let reassigned = actions.iter().find_map(|a| match a {
            SnapshotSyncAction::SendChunkRequest {
                peer, chunk_idx, ..
            } if *chunk_idx == chunk_idx_0 => Some(*peer),
            _ => None,
        });
        assert!(
            reassigned.is_some_and(|p| p != peer_for_chunk_0),
            "chunk must be retried on a different peer",
        );
    }

    #[test]
    fn chunk_response_from_dropped_peer_is_silently_ignored() {
        // When a peer is dropped mid-fetch, an in-flight response
        // arriving after the disconnect must be ignored — the
        // chunk slot is already reassigned, and we don't want a
        // late frame from the dropped peer to corrupt state.
        let mut s = SnapshotSync::new(enabled_policy(50));
        let vs = validator_set_4();
        let p0 = proposer(&vs, 0);
        let p1 = proposer(&vs, 1);
        let _ = s.observe_proposal(0, 100, p0, &vs);
        let _ = s.observe_proposal(0, 100, p1, &vs);
        let payload: Vec<u8> = vec![0x44; 64];
        let (manifest, chunks) = build_snapshot(&vs, 50, 5, &payload, 32);
        let actions = s.on_manifest_response(p0, Some(manifest.clone()), &vs);
        let initial_in_flight: HashSet<u32> = actions
            .iter()
            .filter_map(|a| match a {
                SnapshotSyncAction::SendChunkRequest { chunk_idx, .. } => Some(*chunk_idx),
                _ => None,
            })
            .collect();
        // Drop p0 — chunks in flight to it should be reassigned.
        let _ = s.on_peer_disconnected(p0);
        // Now feed a "late" response from p0 for one of the
        // initially in-flight chunks. The state machine should
        // ignore it.
        if let Some(idx) = initial_in_flight.iter().next() {
            let before_active = s.is_active();
            let _ = s.on_chunk_response(
                p0,
                manifest.height.0,
                *idx,
                Some(chunks[*idx as usize].clone()),
            );
            assert_eq!(
                s.is_active(),
                before_active,
                "late response from dropped peer must not affect state",
            );
        }
    }

    #[test]
    fn chunk_response_from_irrelevant_peer_is_dropped() {
        let mut s = SnapshotSync::new(enabled_policy(50));
        let vs = validator_set_4();
        let p0 = proposer(&vs, 0);
        let _ = s.observe_proposal(0, 100, p0, &vs);
        let payload: Vec<u8> = vec![0x77; 32];
        let (manifest, chunks) = build_snapshot(&vs, 50, 5, &payload, 32);
        let _ = s.on_manifest_response(p0, Some(manifest.clone()), &vs);
        let other = proposer(&vs, 3); // not in the candidate set
        let actions = s.on_chunk_response(other, manifest.height.0, 0, Some(chunks[0].clone()));
        assert!(actions.is_empty());
        assert!(s.is_active());
    }

    #[test]
    fn observe_after_done_does_not_restart() {
        let mut s = SnapshotSync::new(enabled_policy(50));
        let vs = validator_set_4();
        let p0 = proposer(&vs, 0);
        let _ = s.observe_proposal(0, 100, p0, &vs);
        let payload: Vec<u8> = vec![0xAA; 32];
        let (manifest, chunks) = build_snapshot(&vs, 50, 5, &payload, 32);
        let _ = s.on_manifest_response(p0, Some(manifest.clone()), &vs);
        let _ = s.on_chunk_response(p0, manifest.height.0, 0, Some(chunks[0].clone()));
        assert!(s.is_done());
        let actions = s.observe_proposal(50, 200, p0, &vs);
        assert!(actions.is_empty());
        assert!(s.is_done());
    }

    #[test]
    fn peer_disconnect_during_manifest_pending_aborts_when_primary() {
        let mut s = SnapshotSync::new(enabled_policy(50));
        let vs = validator_set_4();
        let p0 = proposer(&vs, 0);
        let _ = s.observe_proposal(0, 100, p0, &vs);
        assert!(s.is_active());
        let actions = s.on_peer_disconnected(p0);
        assert!(matches!(
            actions.first(),
            Some(SnapshotSyncAction::Abort { .. }),
        ));
        assert!(s.is_aborted());
    }

    #[test]
    fn peer_disconnect_for_unrelated_peer_is_noop() {
        let mut s = SnapshotSync::new(enabled_policy(50));
        let vs = validator_set_4();
        let p0 = proposer(&vs, 0);
        let _ = s.observe_proposal(0, 100, p0, &vs);
        let actions = s.on_peer_disconnected(proposer(&vs, 1));
        assert!(actions.is_empty());
        assert!(s.is_active());
    }

    #[test]
    fn add_candidate_outside_fetching_is_noop() {
        let mut s = SnapshotSync::new(enabled_policy(50));
        let actions = s.add_candidate([0x99; 32]);
        assert!(actions.is_empty());
        assert!(s.is_idle());
    }
}
