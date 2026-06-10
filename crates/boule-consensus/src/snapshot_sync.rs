#![allow(dead_code)]
use std::collections::{HashMap, HashSet};

use bytes::Bytes;

use crate::replication::snapshot::{ManifestError, SnapshotManifest, SnapshotPolicy, verify_chunk};
use crate::validator_set::ValidatorSet;
use boule_core::identity::NodeId;

pub const MAX_CONCURRENT_CHUNK_REQUESTS: u32 = 4;

pub const PER_PEER_CHUNK_CONCURRENCY: u32 = 2;

pub const PER_CHUNK_RETRY_BUDGET: u32 = 3;

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

#[derive(Debug)]
enum State {
    Idle {
        observed_peers: HashSet<NodeId>,
    },

    ManifestPending {
        primary_peer: NodeId,
        observed_peers: HashSet<NodeId>,
    },

    Fetching {
        manifest: Box<SnapshotManifest>,

        candidates: Vec<NodeId>,

        in_flight_per_peer: HashMap<NodeId, u32>,

        chunks: Vec<ChunkSlot>,
    },
    Done,
    Aborted,
}

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
        manifest: Box<SnapshotManifest>,
        payload: Bytes,
    },
    Abort {
        reason: AbortReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbortReason {
    PeerHasNoSnapshot,

    ManifestVerifyFailed(ManifestError),

    ChunkRetryBudgetExhausted { chunk_idx: u32, attempts: u32 },

    CandidatesExhausted,
}

#[derive(Debug)]
pub struct SnapshotSync {
    state: State,
    policy: SnapshotPolicy,
}

impl SnapshotSync {
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

    pub fn is_manifest_pending_from(&self, peer: &NodeId) -> bool {
        matches!(
            &self.state,
            State::ManifestPending { primary_peer, .. } if primary_peer == peer,
        )
    }

    pub fn observe_proposal(
        &mut self,
        last_committed_height: u64,
        proposal_height: impl Into<crate::Height>,
        proposer: NodeId,
        validator_set: &ValidatorSet,
    ) -> Vec<SnapshotSyncAction> {
        let proposal_height = proposal_height.into();
        if !self.policy.is_enabled() {
            return Vec::new();
        }

        let proposer_id = crate::validator_set::ValidatorId::from_genesis_pubkey(proposer);
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

        match &slot.status {
            ChunkStatus::InFlight { peer } if *peer == from => {}
            _ => return Vec::new(),
        }

        if let Some(c) = in_flight_per_peer.get_mut(&from) {
            *c = c.saturating_sub(1);
        }
        match payload {
            Some(p) => {
                if let Err(_e) = verify_chunk(manifest, chunk_idx, &p) {
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

        let next = chunks.iter_mut().enumerate().find_map(|(idx, slot)| {
            if !matches!(slot.status, ChunkStatus::Pending) {
                return None;
            }

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
