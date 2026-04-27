//! Joiner-side snapshot-fetch state machine (#229).
//!
//! Pure state machine with no I/O — the integration layer in
//! [`crate::consensus::node::ConsensusNode`] feeds it observations
//! (inbound proposals, manifest/chunk responses) and executes the
//! [`SnapshotSyncAction`]s it returns (send wire messages, restore
//! state).
//!
//! # Lifecycle
//!
//! The fetch goes through three phases, gated by the configured
//! [`SnapshotPolicy`]:
//!
//! 1. **`Idle`** — no fetch in progress. Watches inbound proposals;
//!    when one arrives at a height ≥ `policy.interval_blocks` above
//!    our committed height, picks the proposer as the peer and emits
//!    [`SnapshotSyncAction::SendManifestRequest`].
//! 2. **`ManifestPending`** — manifest request sent; waiting for
//!    [`Self::on_manifest_response`]. On a verified manifest, moves
//!    to `ChunksPending` and emits the first
//!    [`SnapshotSyncAction::SendChunkRequest`].
//! 3. **`ChunksPending`** — chunks fetched sequentially; each
//!    verified payload is buffered in `chunks` and the next request
//!    is emitted. After the last chunk arrives and verifies, emits
//!    [`SnapshotSyncAction::Restore`] and moves to `Done`.
//!
//! Any failure (verification error, manifest mismatch, peer dropping
//! a chunk) emits [`SnapshotSyncAction::Abort`] and moves to
//! `Aborted` — a terminal state. The joiner falls through to the
//! existing `RequestBlock` tail-sync, matching the issue's stated
//! failure mode: "Snapshot is an optimization; tail-sync is the
//! correctness path."
//!
//! # Cross-source check
//!
//! Issue #229 mentions a "cross-source sanity check": fetch
//! manifests from multiple peers and require ≥ 2 to agree before
//! committing chunk fetch. This single-peer implementation skips
//! that — issue #230 (multi-source parallel fetch) is the natural
//! home for it. With < 2 reachable peers, the issue itself
//! recommends proceeding with a single manifest, which is what we
//! do here.

#![allow(dead_code)]

use bytes::Bytes;

use crate::consensus::validator_set::ValidatorSet;
use crate::p2p::NodeId;
use crate::replication::snapshot::{
    ChunkError, ManifestError, SnapshotManifest, SnapshotPolicy, verify_chunk,
};

/// State the joiner-side fetch is currently in.
///
/// `Aborted` and `Done` are terminal — once entered, the state
/// machine ignores further events. The integration layer relies on
/// [`SnapshotSync::is_active`] to decide whether to keep feeding
/// inbound observations.
#[derive(Debug)]
enum State {
    Idle,
    ManifestPending {
        peer: NodeId,
        /// Highest height we've observed across inbound proposals.
        /// Refreshed by every `observe_proposal` call so an even
        /// taller proposal mid-fetch does not reset the fetch.
        observed_high: u64,
    },
    ChunksPending {
        peer: NodeId,
        /// Boxed because `SnapshotManifest` is several hundred bytes
        /// (it embeds a `Block` and a `QuorumCertificate`); the
        /// `State` enum's other variants are tiny, and clippy's
        /// `large_enum_variant` lint flags an unboxed inline.
        manifest: Box<SnapshotManifest>,
        /// Buffered chunks, indexed by chunk_idx. `None` means "not
        /// yet received". Length equals `manifest.chunk_count`.
        chunks: Vec<Option<Bytes>>,
        /// Index of the next chunk to request. Equal to
        /// `manifest.chunk_count` once the last chunk has been
        /// requested.
        next_idx: u32,
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
/// - `Abort`: log the reason at `warn` (or `info` for benign
///   `PolicyDisabled`) and let the existing block-sync path take over.
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
        /// Boxed for the same reason as `State::ChunksPending::manifest`.
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
    /// they have no snapshot to serve.
    PeerHasNoSnapshot,
    /// The manifest failed [`SnapshotManifest::verify`].
    ManifestVerifyFailed(ManifestError),
    /// The peer replied with `SnapshotChunkResponse { payload:
    /// None, .. }` — they don't have this chunk (or the snapshot
    /// has been pruned).
    PeerHasNoChunk { chunk_idx: u32 },
    /// A chunk failed [`verify_chunk`].
    ChunkVerifyFailed { chunk_idx: u32, error: ChunkError },
    /// A response arrived from a peer we hadn't asked, or for a
    /// height/index we weren't waiting for. Indicates a wire bug
    /// or a malicious peer.
    UnexpectedResponse,
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
            state: State::Idle,
            policy,
        }
    }

    /// True iff the state machine is in a non-terminal state. The
    /// integration layer uses this to decide whether continuing to
    /// route `Receive…` dispatches is worthwhile.
    pub fn is_active(&self) -> bool {
        matches!(
            self.state,
            State::ManifestPending { .. } | State::ChunksPending { .. },
        )
    }

    /// True iff the state machine is in `Idle` and would consider
    /// starting a fetch.
    pub fn is_idle(&self) -> bool {
        matches!(self.state, State::Idle)
    }

    /// True iff the state machine has reached `Done`. Entered only
    /// after `Restore` has been emitted.
    pub fn is_done(&self) -> bool {
        matches!(self.state, State::Done)
    }

    /// True iff the state machine has reached `Aborted` — terminal
    /// and not retriable in this PR. The integration layer treats
    /// this as "snapshot path failed; rely on block-sync".
    pub fn is_aborted(&self) -> bool {
        matches!(self.state, State::Aborted)
    }

    /// Observe an inbound proposal at `proposal_height` proposed by
    /// `proposer`. If we're idle and the height implies we're
    /// behind by at least `interval_blocks`, kick off a manifest
    /// request to `proposer`.
    ///
    /// `last_committed_height` is the joiner's current
    /// last-committed height (zero on a fresh boot). `validator_set`
    /// is the local validator set; the proposer must be a member
    /// (envelope ingress already enforced this, but we re-check
    /// defensively so a wire bug never targets a non-validator).
    pub fn observe_proposal(
        &mut self,
        last_committed_height: u64,
        proposal_height: u64,
        proposer: NodeId,
        validator_set: &ValidatorSet,
    ) -> Vec<SnapshotSyncAction> {
        if !self.policy.is_enabled() {
            return Vec::new();
        }
        // Track the highest-seen height even while a fetch is
        // in flight, so a future iteration could decide to
        // reorder fetches (#230 territory). For now, only
        // `Idle` triggers anything.
        match &mut self.state {
            State::Idle => {
                if proposal_height < last_committed_height {
                    return Vec::new();
                }
                let lag = proposal_height - last_committed_height;
                if lag < self.policy.interval_blocks {
                    return Vec::new();
                }
                if !validator_set.contains(&proposer) {
                    return Vec::new();
                }
                self.state = State::ManifestPending {
                    peer: proposer,
                    observed_high: proposal_height,
                };
                vec![SnapshotSyncAction::SendManifestRequest { peer: proposer }]
            }
            State::ManifestPending { observed_high, .. } => {
                if proposal_height > *observed_high {
                    *observed_high = proposal_height;
                }
                Vec::new()
            }
            State::ChunksPending { .. } | State::Done | State::Aborted => Vec::new(),
        }
    }

    /// Process a [`crate::consensus::dispatch::Dispatch::ReceiveSnapshotManifest`].
    ///
    /// On a verified manifest, transitions to `ChunksPending` and
    /// emits the first chunk request. On any failure (peer has
    /// nothing, verification fails, response is from the wrong
    /// peer), aborts.
    pub fn on_manifest_response(
        &mut self,
        from: NodeId,
        manifest: Option<SnapshotManifest>,
        validator_set: &ValidatorSet,
    ) -> Vec<SnapshotSyncAction> {
        let State::ManifestPending { peer, .. } = &self.state else {
            // Late or unsolicited response — safe to drop. Don't
            // abort an unrelated fetch over a stray frame.
            return Vec::new();
        };
        if from != *peer {
            // We only trust the peer we asked. A surprise reply
            // from someone else is dropped without changing state.
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
        let peer = *peer;
        let chunk_count = manifest.chunk_count;
        let height = manifest.height;
        let chunks = vec![None; chunk_count as usize];
        let first_request = SnapshotSyncAction::SendChunkRequest {
            peer,
            height,
            chunk_idx: 0,
        };
        self.state = State::ChunksPending {
            peer,
            manifest: Box::new(manifest),
            chunks,
            next_idx: 1,
        };
        vec![first_request]
    }

    /// Process a [`crate::consensus::dispatch::Dispatch::ReceiveSnapshotChunk`].
    ///
    /// On a verified payload at the expected index, buffers it and
    /// either fires the next chunk request or — when the buffer is
    /// full — emits [`SnapshotSyncAction::Restore`] and moves to
    /// `Done`.
    pub fn on_chunk_response(
        &mut self,
        from: NodeId,
        height: u64,
        chunk_idx: u32,
        payload: Option<Bytes>,
    ) -> Vec<SnapshotSyncAction> {
        let State::ChunksPending {
            peer,
            manifest,
            chunks,
            next_idx,
        } = &mut self.state
        else {
            return Vec::new();
        };
        if from != *peer || height != manifest.height {
            return Vec::new();
        }
        // The integration layer requests chunks in strict order
        // (0, 1, … n-1). Anything we weren't expecting is treated
        // as a wire error and aborts; reordering a correct stream
        // would only happen under reordering attacks at our layer
        // (envelope ingress hands frames in arrival order).
        let expecting = next_idx.saturating_sub(1);
        if chunk_idx != expecting {
            self.state = State::Aborted;
            return vec![SnapshotSyncAction::Abort {
                reason: AbortReason::UnexpectedResponse,
            }];
        }
        let payload = match payload {
            Some(p) => p,
            None => {
                self.state = State::Aborted;
                return vec![SnapshotSyncAction::Abort {
                    reason: AbortReason::PeerHasNoChunk { chunk_idx },
                }];
            }
        };
        if let Err(e) = verify_chunk(manifest, chunk_idx, &payload) {
            self.state = State::Aborted;
            return vec![SnapshotSyncAction::Abort {
                reason: AbortReason::ChunkVerifyFailed {
                    chunk_idx,
                    error: e,
                },
            }];
        }
        chunks[chunk_idx as usize] = Some(payload);

        // Emit the next request (if any) or assemble the snapshot
        // and emit `Restore`. The completion path takes ownership
        // of `manifest` and the chunk vec, so we transition the
        // state machine to `Done` first to satisfy the borrow
        // checker.
        if (*next_idx) < manifest.chunk_count {
            let request = SnapshotSyncAction::SendChunkRequest {
                peer: *peer,
                height: manifest.height,
                chunk_idx: *next_idx,
            };
            *next_idx += 1;
            return vec![request];
        }
        // All chunks present: assemble and emit `Restore`.
        let State::ChunksPending {
            manifest, chunks, ..
        } = std::mem::replace(&mut self.state, State::Done)
        else {
            unreachable!("just matched ChunksPending above");
        };
        // Every slot is `Some(_)` because we only reach the
        // assembly path after the final chunk's `chunk_idx == n-1`
        // wrote to slot `n-1` and every prior slot was filled in
        // strict order.
        let parts: Vec<Bytes> = chunks
            .into_iter()
            .map(|c| c.expect("all chunks must be present at restore time"))
            .collect();
        let payload = crate::replication::snapshot::assemble_chunks(&parts);
        vec![SnapshotSyncAction::Restore { manifest, payload }]
    }

    /// Notify the state machine that the peer we were fetching
    /// from has disconnected. Aborts an in-flight fetch.
    pub fn on_peer_disconnected(&mut self, peer: NodeId) -> Vec<SnapshotSyncAction> {
        let waiting_on = match &self.state {
            State::ManifestPending { peer, .. } => Some(*peer),
            State::ChunksPending { peer, .. } => Some(*peer),
            _ => None,
        };
        match waiting_on {
            Some(p) if p == peer => {
                self.state = State::Aborted;
                vec![SnapshotSyncAction::Abort {
                    reason: AbortReason::UnexpectedResponse,
                }]
            }
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::consensus::hotstuff::QuorumCertificate;
    use crate::consensus::hotstuff::qc::quorum_size;
    use crate::replication::block::BlockHash;
    use crate::replication::snapshot::{SnapshotManifest, chunk_snapshot};

    fn validator_set_4() -> ValidatorSet {
        ValidatorSet::new(vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]])
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

    fn sample_block(height: u64, view: u64) -> crate::replication::block::Block {
        use crate::replication::block::{Block, BlockHeader};
        let parent_hash = Block::genesis([0u8; 32]).hash();
        let commands: Vec<Bytes> = Vec::new();
        Block {
            header: BlockHeader {
                parent_hash,
                height,
                view,
                proposer: [0u8; 32],
                state_commitment: [0xCD; 32],
                commands_commitment: Block::commands_commitment(&commands),
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
        let manifest =
            SnapshotManifest::build(block, vs, chunk_size, chunk_hashes, qc, 1_700_000_000);
        (manifest, chunks)
    }

    fn proposer_peer(vs: &ValidatorSet) -> NodeId {
        *vs.get(0).unwrap()
    }

    #[test]
    fn disabled_policy_never_starts_fetch() {
        let mut s = SnapshotSync::new(SnapshotPolicy::disabled());
        let vs = validator_set_4();
        let actions = s.observe_proposal(0, 1_000_000, proposer_peer(&vs), &vs);
        assert!(actions.is_empty());
        assert!(s.is_idle());
    }

    #[test]
    fn observation_below_threshold_does_not_start_fetch() {
        let mut s = SnapshotSync::new(enabled_policy(50));
        let vs = validator_set_4();
        // Lag of 49 — below the threshold.
        let actions = s.observe_proposal(0, 49, proposer_peer(&vs), &vs);
        assert!(actions.is_empty());
        assert!(s.is_idle());
    }

    #[test]
    fn observation_at_threshold_emits_manifest_request() {
        let mut s = SnapshotSync::new(enabled_policy(50));
        let vs = validator_set_4();
        let proposer = proposer_peer(&vs);
        let actions = s.observe_proposal(0, 50, proposer, &vs);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            SnapshotSyncAction::SendManifestRequest { peer } => assert_eq!(*peer, proposer),
            other => panic!("expected SendManifestRequest, got {other:?}"),
        }
        assert!(s.is_active());
    }

    #[test]
    fn observation_from_non_validator_does_not_trigger() {
        let mut s = SnapshotSync::new(enabled_policy(50));
        let vs = validator_set_4();
        let outsider: NodeId = [0x99; 32];
        let actions = s.observe_proposal(0, 100, outsider, &vs);
        assert!(actions.is_empty());
        assert!(s.is_idle());
    }

    #[test]
    fn second_observation_during_manifest_pending_is_noop() {
        let mut s = SnapshotSync::new(enabled_policy(50));
        let vs = validator_set_4();
        let proposer = proposer_peer(&vs);
        let _ = s.observe_proposal(0, 100, proposer, &vs);
        assert!(s.is_active());
        // Subsequent observations don't issue a second manifest
        // request; the state machine sticks with the first peer.
        let actions = s.observe_proposal(0, 200, *vs.get(1).unwrap(), &vs);
        assert!(actions.is_empty());
    }

    #[test]
    fn manifest_response_from_wrong_peer_is_dropped() {
        let mut s = SnapshotSync::new(enabled_policy(50));
        let vs = validator_set_4();
        let proposer = proposer_peer(&vs);
        let _ = s.observe_proposal(0, 100, proposer, &vs);

        let other = *vs.get(1).unwrap();
        let (manifest, _chunks) = build_snapshot(&vs, 50, 5, b"hello", 16);
        let actions = s.on_manifest_response(other, Some(manifest), &vs);
        assert!(actions.is_empty());
        // State unchanged — still waiting on the original peer.
        assert!(s.is_active());
    }

    #[test]
    fn manifest_none_from_peer_aborts() {
        let mut s = SnapshotSync::new(enabled_policy(50));
        let vs = validator_set_4();
        let proposer = proposer_peer(&vs);
        let _ = s.observe_proposal(0, 100, proposer, &vs);

        let actions = s.on_manifest_response(proposer, None, &vs);
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
        let other_vs = ValidatorSet::new(vec![[10u8; 32], [11u8; 32], [12u8; 32], [13u8; 32]]);
        let proposer = proposer_peer(&vs);
        let _ = s.observe_proposal(0, 100, proposer, &vs);

        // Manifest's embedded set is `other_vs`, not the joiner's
        // local `vs` — verify rejects with `ValidatorSetMismatch`.
        let (manifest, _chunks) = build_snapshot(&other_vs, 50, 5, b"hello", 16);
        let actions = s.on_manifest_response(proposer, Some(manifest), &vs);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            SnapshotSyncAction::Abort {
                reason: AbortReason::ManifestVerifyFailed(ManifestError::ValidatorSetMismatch),
            } => {}
            other => panic!("expected ManifestVerifyFailed(ValidatorSetMismatch), got {other:?}"),
        }
        assert!(s.is_aborted());
    }

    #[test]
    fn happy_path_walks_chunks_in_order_and_restores() {
        let mut s = SnapshotSync::new(enabled_policy(50));
        let vs = validator_set_4();
        let proposer = proposer_peer(&vs);
        let payload: Vec<u8> = (0..128u32).flat_map(|i| (i as u8).to_le_bytes()).collect();
        let (manifest, chunks) = build_snapshot(&vs, 50, 5, &payload, 32);
        assert_eq!(manifest.chunk_count, chunks.len() as u32);
        assert!(manifest.chunk_count >= 2, "test needs multiple chunks");

        // Trigger fetch via observation.
        let _ = s.observe_proposal(0, 100, proposer, &vs);

        // Manifest response moves us to ChunksPending and asks
        // for chunk 0.
        let actions = s.on_manifest_response(proposer, Some(manifest.clone()), &vs);
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            SnapshotSyncAction::SendChunkRequest {
                peer,
                height: 50,
                chunk_idx: 0,
            } if *peer == proposer,
        ));

        // Walk every chunk in order; each should yield exactly
        // one request for the next index, EXCEPT the last which
        // yields a `Restore`.
        let last_idx = manifest.chunk_count - 1;
        for idx in 0..manifest.chunk_count {
            let actions = s.on_chunk_response(
                proposer,
                manifest.height,
                idx,
                Some(chunks[idx as usize].clone()),
            );
            if idx < last_idx {
                assert_eq!(actions.len(), 1);
                match &actions[0] {
                    SnapshotSyncAction::SendChunkRequest {
                        peer,
                        height,
                        chunk_idx,
                    } => {
                        assert_eq!(*peer, proposer);
                        assert_eq!(*height, manifest.height);
                        assert_eq!(*chunk_idx, idx + 1);
                    }
                    other => panic!("expected SendChunkRequest, got {other:?}"),
                }
                assert!(s.is_active());
            } else {
                assert_eq!(actions.len(), 1);
                match &actions[0] {
                    SnapshotSyncAction::Restore {
                        manifest: m,
                        payload: p,
                    } => {
                        assert_eq!(m.as_ref(), &manifest);
                        assert_eq!(p.as_ref(), payload.as_slice());
                    }
                    other => panic!("expected Restore, got {other:?}"),
                }
                assert!(s.is_done());
            }
        }
    }

    #[test]
    fn chunk_none_from_peer_aborts() {
        let mut s = SnapshotSync::new(enabled_policy(50));
        let vs = validator_set_4();
        let proposer = proposer_peer(&vs);
        let payload: Vec<u8> = (0..32u32).flat_map(|i| (i as u8).to_le_bytes()).collect();
        let (manifest, _chunks) = build_snapshot(&vs, 50, 5, &payload, 16);

        let _ = s.observe_proposal(0, 100, proposer, &vs);
        let _ = s.on_manifest_response(proposer, Some(manifest.clone()), &vs);

        let actions = s.on_chunk_response(proposer, manifest.height, 0, None);
        match actions.first() {
            Some(SnapshotSyncAction::Abort {
                reason: AbortReason::PeerHasNoChunk { chunk_idx: 0 },
            }) => {}
            other => panic!("expected Abort(PeerHasNoChunk), got {other:?}"),
        }
        assert!(s.is_aborted());
    }

    #[test]
    fn tampered_chunk_aborts_with_chunk_error() {
        let mut s = SnapshotSync::new(enabled_policy(50));
        let vs = validator_set_4();
        let proposer = proposer_peer(&vs);
        let payload: Vec<u8> = vec![0xAA; 64];
        let (manifest, chunks) = build_snapshot(&vs, 50, 5, &payload, 32);

        let _ = s.observe_proposal(0, 100, proposer, &vs);
        let _ = s.on_manifest_response(proposer, Some(manifest.clone()), &vs);

        // Flip a byte in chunk 0's payload before delivering.
        let mut tampered = chunks[0].to_vec();
        tampered[0] ^= 0xFF;
        let actions =
            s.on_chunk_response(proposer, manifest.height, 0, Some(Bytes::from(tampered)));
        match actions.first() {
            Some(SnapshotSyncAction::Abort {
                reason: AbortReason::ChunkVerifyFailed { chunk_idx: 0, .. },
            }) => {}
            other => panic!("expected Abort(ChunkVerifyFailed), got {other:?}"),
        }
        assert!(s.is_aborted());
    }

    #[test]
    fn out_of_order_chunk_aborts() {
        let mut s = SnapshotSync::new(enabled_policy(50));
        let vs = validator_set_4();
        let proposer = proposer_peer(&vs);
        let payload: Vec<u8> = vec![0xAA; 64];
        let (manifest, chunks) = build_snapshot(&vs, 50, 5, &payload, 16);
        assert!(manifest.chunk_count >= 2);

        let _ = s.observe_proposal(0, 100, proposer, &vs);
        let _ = s.on_manifest_response(proposer, Some(manifest.clone()), &vs);

        // Skip chunk 0 — deliver chunk 1 first.
        let actions = s.on_chunk_response(proposer, manifest.height, 1, Some(chunks[1].clone()));
        match actions.first() {
            Some(SnapshotSyncAction::Abort {
                reason: AbortReason::UnexpectedResponse,
            }) => {}
            other => panic!("expected Abort(UnexpectedResponse), got {other:?}"),
        }
        assert!(s.is_aborted());
    }

    #[test]
    fn chunk_response_from_wrong_peer_is_dropped() {
        let mut s = SnapshotSync::new(enabled_policy(50));
        let vs = validator_set_4();
        let proposer = proposer_peer(&vs);
        let payload: Vec<u8> = vec![0xAA; 32];
        let (manifest, chunks) = build_snapshot(&vs, 50, 5, &payload, 16);

        let _ = s.observe_proposal(0, 100, proposer, &vs);
        let _ = s.on_manifest_response(proposer, Some(manifest.clone()), &vs);

        let other = *vs.get(1).unwrap();
        let actions = s.on_chunk_response(other, manifest.height, 0, Some(chunks[0].clone()));
        assert!(actions.is_empty());
        // Still active and waiting for the right peer's response.
        assert!(s.is_active());
    }

    #[test]
    fn peer_disconnect_aborts_pending_fetch() {
        let mut s = SnapshotSync::new(enabled_policy(50));
        let vs = validator_set_4();
        let proposer = proposer_peer(&vs);
        let _ = s.observe_proposal(0, 100, proposer, &vs);
        assert!(s.is_active());

        let actions = s.on_peer_disconnected(proposer);
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
        let proposer = proposer_peer(&vs);
        let _ = s.observe_proposal(0, 100, proposer, &vs);

        let actions = s.on_peer_disconnected(*vs.get(1).unwrap());
        assert!(actions.is_empty());
        assert!(s.is_active());
    }

    #[test]
    fn observe_after_done_does_not_restart() {
        let mut s = SnapshotSync::new(enabled_policy(50));
        let vs = validator_set_4();
        let proposer = proposer_peer(&vs);
        let payload: Vec<u8> = vec![0xAA; 32];
        let (manifest, chunks) = build_snapshot(&vs, 50, 5, &payload, 32);

        // Drive a successful single-chunk fetch.
        let _ = s.observe_proposal(0, 100, proposer, &vs);
        let _ = s.on_manifest_response(proposer, Some(manifest.clone()), &vs);
        let _ = s.on_chunk_response(proposer, manifest.height, 0, Some(chunks[0].clone()));
        assert!(s.is_done());

        // A subsequent observation must not flip us back to active.
        let actions = s.observe_proposal(50, 200, proposer, &vs);
        assert!(actions.is_empty());
        assert!(s.is_done());
    }
}
