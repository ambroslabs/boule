//! Protocol-level Byzantine adversaries for the consensus simulator (#132).
//!
//! This module sits at the [`boule_consensus::hotstuff::HotStuffCore`]
//! action boundary — adversaries intercept the stream of
//! [`boule_transport_tcp::ProtocolOutbound`] frames their node would emit, decode
//! each as a [`WireMessage`], and craft *valid signed envelopes* that
//! misbehave at the protocol level: equivocation, vote withholding,
//! stale replays, forged QCs, timeout-vote spam.
//!
//! The point is to verify that honest replicas reject malicious
//! *content* (and at minimum do not crash); cryptographic forgery is
//! out of scope and covered by [`boule_consensus::wire_fuzz`] / #198.
//!
//! # Why intercept on the outbound side
//!
//! Mutating a `ConsensusNode`'s internal state to make it deviate would
//! force the adversary to know the node's private state machine. The
//! cleaner seam is the network edge: every outbound frame the honest
//! core emits passes through the per-node routing task in
//! [`crate::sim::SimCluster`]'s spawn path, and the
//! [`Adversary`] hook taps into that exact stream. Adversaries get the
//! node's own [`boule_core::crypto::signed::Signer`] so any envelope they
//! craft passes recipient-side signature verification — testing
//! protocol-level rejection rather than crypto-level rejection.
//!
//! # Property scope (issue acceptance criteria)
//!
//! Each property runs `n = 4` validators with a single Byzantine slot
//! (`f = 1`) and asserts:
//!
//! - **Safety**: [`assert_no_conflicts`] across every committed block
//!   on every node, including the Byzantine itself (its safety core is
//!   unchanged; only its outbound is mutated).
//! - **Liveness**: every honest node commits at least a small floor of
//!   blocks within the simulated-time budget. Floors are deliberately
//!   conservative — the suite asserts "the cluster makes some progress
//!   under attack", not a specific throughput number — so timing
//!   variance across runs doesn't make the suite flaky.
//!
//! The mixed property cycles all five adversary kinds across 6
//! deterministic cases.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use parking_lot::Mutex;
use proptest::prelude::*;

use super::sim::{Adversary, AdversaryCtx, SimCluster, assert_no_conflicts};
use boule_consensus::View;
use boule_consensus::hotstuff::qc::{QuorumCertificate, TimeoutVote, Vote};
use boule_consensus::hotstuff::{NewView, Proposal};
use boule_consensus::replication::block::{Block, BlockHash};
use boule_consensus::wire::WireMessage;
use boule_core::crypto::signed::{ChainId, Signed};
use boule_transport_tcp::{NodeId, ProtocolOutbound};

// ── Wire helpers ─────────────────────────────────────────────────────────────

fn decode(payload: &Bytes) -> Option<WireMessage> {
    postcard::from_bytes::<WireMessage>(payload).ok()
}

fn encode(msg: &WireMessage) -> Bytes {
    Bytes::from(postcard::to_stdvec(msg).expect("WireMessage encoding cannot fail"))
}

fn outbound_payload(out: &ProtocolOutbound) -> Bytes {
    match out {
        ProtocolOutbound::Broadcast(p) => p.clone(),
        ProtocolOutbound::SendTo { payload, .. } => payload.clone(),
    }
}

// ── Equivocator ──────────────────────────────────────────────────────────────

/// Adversary 1 (issue text): when the node would broadcast a Proposal
/// (i.e. it is leading the current view), instead split the cluster:
/// half the validators receive proposal A (the original), the other
/// half receive proposal B (a fork crafted by toggling one byte of
/// `state_commitment` so the block hash diverges). Both are signed
/// with the adversary's own key.
///
/// Honest replicas vote at most once per view (`last_voted_view`
/// monotonic), so safety holds: at most one of the two proposals can
/// accumulate the `2f+1 = 3` quorum at view `v`. With the 4-node split
/// (1 byzantine + 3 honest), the typical outcome is "1 honest got A, 2
/// honest got B" → neither side reaches quorum, view stalls, pacemaker
/// times out, next-view honest leader recovers liveness.
///
/// All non-Proposal outbounds (Vote, NewView, TimeoutVote, BlockRequest
/// / BlockResponse) pass through unchanged.
pub struct EquivocatorAdversary;

impl Adversary for EquivocatorAdversary {
    fn intercept(&self, ctx: &AdversaryCtx, outbound: ProtocolOutbound) -> Vec<ProtocolOutbound> {
        let payload = match &outbound {
            ProtocolOutbound::Broadcast(p) => p.clone(),
            // Only Broadcast carries a Proposal in honest emit; SendTo
            // is reserved for unicast (BlockRequest, BlockResponse,
            // and the legacy point-to-point Vote pre-#124).
            _ => return vec![outbound],
        };
        let Some(WireMessage::Proposal(signed_a)) = decode(&payload) else {
            return vec![outbound];
        };

        // Build proposal B: same view / parent / height / commands,
        // different state_commitment so the block hash diverges.
        // Re-sign with our own key so the envelope verifies on the
        // recipient side — we want the *content* to test honest
        // rejection logic, not the signature.
        let block_a = signed_a.payload.block.clone();
        let mut header_b = block_a.header.clone();
        header_b.state_commitment[0] ^= 0x01;
        let block_b = Block {
            header: header_b,
            commands: block_a.commands.clone(),
        };
        let proposal_b = Proposal {
            block: block_b,
            justify: signed_a.payload.justify.clone(),
        };
        let signed_b = Signed::sign(proposal_b, ctx.signer.as_ref(), &ChainId::TEST)
            .expect("equivocator re-signing must not fail (own signer is healthy)");
        let payload_b = encode(&WireMessage::Proposal(signed_b));

        // Disjoint subsets across the non-self peer set. The split is
        // intentionally near-balanced (floor(peers/2) get A, the rest
        // get B), so under n=4 the lone byzantine carves the 3 honest
        // peers into 1 + 2 — neither subset alone reaches quorum.
        let peers: Vec<NodeId> = ctx
            .validators
            .iter()
            .copied()
            .filter(|id| *id != ctx.my_id)
            .collect();
        let half = peers.len() / 2;
        peers
            .into_iter()
            .enumerate()
            .map(|(i, peer)| ProtocolOutbound::SendTo {
                node_id: peer,
                payload: if i < half {
                    payload.clone()
                } else {
                    payload_b.clone()
                },
            })
            .collect()
    }
}

// ── Vote-withholder ──────────────────────────────────────────────────────────

/// Adversary 2: receives proposals normally but never emits a Vote.
/// All other outbounds (Proposal-as-leader, NewView, TimeoutVote,
/// BlockRequest / BlockResponse) pass through unchanged.
///
/// With `n = 4`, `quorum = 3`. The leader's own self-vote (via
/// loopback) plus two votes from the two non-Byzantine non-leader
/// honest replicas is exactly 3 → quorum holds even with the
/// Byzantine silent. Liveness preserved.
pub struct VoteWithholderAdversary;

impl Adversary for VoteWithholderAdversary {
    fn intercept(&self, _ctx: &AdversaryCtx, outbound: ProtocolOutbound) -> Vec<ProtocolOutbound> {
        let payload = outbound_payload(&outbound);
        match decode(&payload) {
            Some(WireMessage::Vote(_, _)) => Vec::new(),
            _ => vec![outbound],
        }
    }
}

// ── Stale-replayer ───────────────────────────────────────────────────────────

/// Adversary 3: buffers every signed Proposal/Vote/NewView envelope the
/// node emits, and on every K-th outbound additionally re-broadcasts
/// the OLDEST buffered envelope. The replay payload is byte-identical
/// to a past honest emit, so the signature verifies — honest replicas
/// must reject it via the safety-rule monotonic counters
/// (`last_voted_view`, `should_update_high_qc`'s strict-greater-view
/// check), not via crypto.
///
/// History capacity is bounded so a long-running sim doesn't grow the
/// adversary's heap unboundedly.
pub struct StaleReplayerAdversary {
    state: Mutex<StaleState>,
    every: u32,
}

#[derive(Default)]
struct StaleState {
    history: Vec<Bytes>,
    counter: u32,
}

impl StaleReplayerAdversary {
    /// `every_n_emissions` of 1 means "replay on every outbound";
    /// values ≥ 2 spread the spam out.
    pub fn new(every_n_emissions: u32) -> Self {
        Self {
            state: Mutex::new(StaleState::default()),
            every: every_n_emissions.max(1),
        }
    }
}

impl Adversary for StaleReplayerAdversary {
    fn intercept(&self, _ctx: &AdversaryCtx, outbound: ProtocolOutbound) -> Vec<ProtocolOutbound> {
        let payload = outbound_payload(&outbound);
        let mut s = self.state.lock();
        if matches!(
            decode(&payload),
            Some(WireMessage::Proposal(_) | WireMessage::Vote(_, _) | WireMessage::NewView(_),)
        ) && s.history.len() < 64
        {
            s.history.push(payload);
        }
        s.counter = s.counter.wrapping_add(1);
        let mut frames = vec![outbound];
        if s.counter % self.every == 0
            && let Some(stale) = s.history.first().cloned()
        {
            frames.push(ProtocolOutbound::Broadcast(stale));
        }
        frames
    }
}

// ── Forged-QC sender ─────────────────────────────────────────────────────────

/// Adversary 4: every K-th outbound additionally broadcasts a NewView
/// envelope whose `high_qc` is forged — view 0 (the same view as the
/// genesis QC), insufficient signers (one set bit), and an all-zero
/// signature that no real Ed25519 key produced. The envelope is signed
/// by the adversary's own key so it survives recipient-side envelope
/// verification.
///
/// Rejection path: [`boule_consensus::hotstuff::safety_rules::should_update_high_qc`]
/// requires *strictly greater* view than the recipient's existing
/// `high_qc`, so a view-0 forged QC is dropped against the cluster's
/// genesis QC (also view 0) on the very first arrival, and against
/// every later real QC at view ≥ 1. Liveness is preserved.
///
/// **Scope note**: this property covers the "no crash on decode +
/// stale-view rejection" half of the issue-#132 forged-QC requirement.
/// A more aggressive adversary that broadcast a *fresher-view* forged
/// QC would currently wedge the cluster — there is no quorum-count
/// check on `should_update_high_qc`'s adoption path. That gap is
/// orthogonal to this PR; once a QC-validation guard lands, this
/// adversary can be extended to forge fresher-view QCs and still
/// preserve liveness.
pub struct ForgedQcAdversary {
    counter: Mutex<u32>,
    every: u32,
}

impl ForgedQcAdversary {
    pub fn new(every_n_emissions: u32) -> Self {
        Self {
            counter: Mutex::new(0),
            every: every_n_emissions.max(1),
        }
    }

    fn forged_qc(validators_len: usize) -> QuorumCertificate {
        let mut qc = QuorumCertificate::new(0, [0xFE; 32], validators_len);
        // Insufficient signers: one set bit, one zero signature.
        qc.add_signature(0, [0u8; 64]);
        qc
    }
}

impl Adversary for ForgedQcAdversary {
    fn intercept(&self, ctx: &AdversaryCtx, outbound: ProtocolOutbound) -> Vec<ProtocolOutbound> {
        let mut counter = self.counter.lock();
        *counter = counter.wrapping_add(1);
        if *counter % self.every != 0 {
            return vec![outbound];
        }
        let nv = NewView {
            high_qc: Self::forged_qc(ctx.validators.len()),
        };
        let signed = Signed::sign(nv, ctx.signer.as_ref(), &ChainId::TEST)
            .expect("forged-QC adversary signing must not fail");
        let payload = encode(&WireMessage::NewView(signed));
        vec![outbound, ProtocolOutbound::Broadcast(payload)]
    }
}

// ── TimeoutVote spammer ──────────────────────────────────────────────────────

/// Adversary 5: every K-th outbound additionally broadcasts a
/// TimeoutVote for an arbitrary view (here: the linearly-increasing
/// outbound counter). With `quorum = 3` of `4` and only one signer,
/// the timeout-certificate bucket on the recipient never crosses
/// threshold off this adversary alone, so the spurious votes are
/// absorbed silently — no view jump, no commit unsafety.
pub struct TimeoutSpammerAdversary {
    counter: Mutex<u32>,
    every: u32,
}

impl TimeoutSpammerAdversary {
    pub fn new(every_n_emissions: u32) -> Self {
        Self {
            counter: Mutex::new(0),
            every: every_n_emissions.max(1),
        }
    }
}

impl Adversary for TimeoutSpammerAdversary {
    fn intercept(&self, ctx: &AdversaryCtx, outbound: ProtocolOutbound) -> Vec<ProtocolOutbound> {
        let mut counter = self.counter.lock();
        *counter = counter.wrapping_add(1);
        if *counter % self.every != 0 {
            return vec![outbound];
        }
        let tv = TimeoutVote {
            view: View(u64::from(*counter)),
            high_qc: None,
        };
        let signed = Signed::sign(tv, ctx.signer.as_ref(), &ChainId::TEST)
            .expect("timeout-spammer signing must not fail");
        let payload = encode(&WireMessage::TimeoutVote(signed));
        vec![outbound, ProtocolOutbound::Broadcast(payload)]
    }
}

// ── Forged-piggyback timeout-vote spammer ────────────────────────────────────

/// Adversary 6 (issue #321 acceptance): broadcasts an extra
/// [`TimeoutVote`] every K-th outbound, but unlike
/// [`TimeoutSpammerAdversary`] this one *attaches a forged
/// fresher-view `high_qc` piggyback*.
///
/// The threat model the verifier closes (audit finding 10-F3): without
/// ingress-side aggregate verification of the piggyback, the bucket
/// logic in [`crate::consensus_node::ConsensusNode::on_timeout_vote`]
/// folds the freshest piggybacked QC across all signers in the bucket
/// into `bucket.best_high_qc`, and on TC formation laundering it
/// through a self-signed NewView straight into the safety core's
/// `state.high_qc`. With `f + 1` honest replicas joining the same
/// bucket on a real timeout, the byzantine's `view = u64::MAX - 1`
/// piggyback is the freshest in the bucket, the TC fires, and every
/// honest replica's `state.high_qc.view` jumps to a fake view with no
/// real ancestor block. Safety breaks: subsequent proposals justify on
/// the fake QC, the three-chain commit walk runs over an unverified
/// ancestor, and liveness wedges (no real block hashes match what the
/// safety core thinks it has committed against).
///
/// With #321's verifier wired in, `verify_high_qc_piggyback` rejects
/// the forged aggregate before the envelope reaches `on_timeout_vote`,
/// the bucket sees the timeout signal but ignores the QC, and
/// `bucket.best_high_qc` only ever takes on values from honest
/// piggybacks. The cluster's safety + liveness invariants then hold
/// under the same `run_one_property` harness as the other adversaries.
///
/// The forged QC is *well-formed* (quorum-count bits set, matching
/// signature slot count, structurally consistent bitmap) so it slips
/// past `is_well_formed` — the only thing left to drop it is the
/// aggregate signature check, which is exactly the path #321 wires.
pub struct ForgedPiggybackAdversary {
    counter: Mutex<u32>,
    every: u32,
}

impl ForgedPiggybackAdversary {
    pub fn new(every_n_emissions: u32) -> Self {
        Self {
            counter: Mutex::new(0),
            every: every_n_emissions.max(1),
        }
    }

    /// Build a bitmap-quorum, zero-signature QC at a fresher view than
    /// honest replicas could plausibly hold, over a sentinel block hash
    /// no honest block ever produces. Well-formed under the cluster's
    /// validator set, so the structural gate passes; aggregate verify
    /// is what rejects it.
    fn forged_piggyback_qc(validators_len: usize) -> QuorumCertificate {
        // u64::MAX - 1 keeps the value distinguishable from genuine
        // `u64::MAX` should the constant ever appear elsewhere, while
        // staying strictly fresher than any view honest replicas reach.
        let mut qc = QuorumCertificate::new(u64::MAX - 1, [0xDE; 32], validators_len);
        let quorum = boule_consensus::hotstuff::qc::quorum_size(validators_len);
        for idx in 0..quorum {
            qc.add_signature(idx, [0u8; 64]);
        }
        qc
    }
}

impl Adversary for ForgedPiggybackAdversary {
    fn intercept(&self, ctx: &AdversaryCtx, outbound: ProtocolOutbound) -> Vec<ProtocolOutbound> {
        let mut counter = self.counter.lock();
        *counter = counter.wrapping_add(1);
        if *counter % self.every != 0 {
            return vec![outbound];
        }
        let tv = TimeoutVote {
            view: View(u64::from(*counter)),
            high_qc: Some(Self::forged_piggyback_qc(ctx.validators.len())),
        };
        let signed = Signed::sign(tv, ctx.signer.as_ref(), &ChainId::TEST)
            .expect("forged-piggyback adversary signing must not fail");
        let payload = encode(&WireMessage::TimeoutVote(signed));
        vec![outbound, ProtocolOutbound::Broadcast(payload)]
    }
}

// ── Forged-history-commitment leader ─────────────────────────────────────────

/// Adversary 7 (issue #325 PR C acceptance): when this node would
/// broadcast a Proposal as leader, mutate `block.header.
/// validator_history_commitment` to a sentinel `[0xDE; 32]` value
/// before re-signing.
///
/// Threat: without proposal-receive validation of the commitment, an
/// honest follower votes on the proposal, the QC forms, the block
/// commits, and the chain advances with a block whose stamped
/// commitment doesn't match the histories that produced it. PR B
/// catches this at the next restart (rebuild walk diverges); PR C
/// catches it at receive time and never lets the bogus block reach
/// the safety core. Honest leaders at the next view recover
/// liveness.
///
/// All non-Proposal outbounds (Vote, NewView, TimeoutVote,
/// BlockRequest / BlockResponse) pass through unchanged. The
/// envelope is re-signed with the byzantine's own key so envelope
/// verification at recipients still passes — the rejection comes
/// from the new commitment check, not from the signer.
pub struct ForgedHistoryCommitmentAdversary;

impl Adversary for ForgedHistoryCommitmentAdversary {
    fn intercept(&self, ctx: &AdversaryCtx, outbound: ProtocolOutbound) -> Vec<ProtocolOutbound> {
        let payload = match &outbound {
            ProtocolOutbound::Broadcast(p) => p.clone(),
            _ => return vec![outbound],
        };
        let Some(WireMessage::Proposal(signed)) = decode(&payload) else {
            return vec![outbound];
        };

        let mut block = signed.payload.block.clone();
        // Sentinel: a value no honest replica would compute over any
        // real history triple. The 0xDE byte is shared with the
        // ForgedPiggybackAdversary's forged-QC sentinel so adversary
        // outputs are easy to distinguish from honest values when
        // grepping logs.
        block.header.validator_history_commitment = [0xDE; 32];
        let proposal = Proposal {
            block,
            justify: signed.payload.justify.clone(),
        };
        let signed_b = Signed::sign(proposal, ctx.signer.as_ref(), &ChainId::TEST)
            .expect("forged-commitment adversary re-signing must not fail");
        vec![ProtocolOutbound::Broadcast(encode(&WireMessage::Proposal(
            signed_b,
        )))]
    }
}

/// A Byzantine leader that stamps a forged `committed_state_root` (the
/// deferred/lagged state root, #599) into every proposal it broadcasts,
/// leaving `committed_height` honest so the height-gate still passes on
/// every honest voter at that frontier. Honest voters reproduce the real
/// root from their own committed execution, see the mismatch, and abstain
/// — the block gets no honest votes and is rejected, while honest nodes
/// stay live. Models a leader trying to commit a state it cannot prove.
///
/// Re-signs with **`ctx.chain_id`** (the cluster's genesis-derived chain
/// id), not `ChainId::TEST`, so the envelope verifies at recipients and
/// the rejection comes specifically from the vote-time root check rather
/// than an envelope-signature failure.
pub struct ForgedCommittedRootAdversary;

impl Adversary for ForgedCommittedRootAdversary {
    fn intercept(&self, ctx: &AdversaryCtx, outbound: ProtocolOutbound) -> Vec<ProtocolOutbound> {
        let payload = match &outbound {
            ProtocolOutbound::Broadcast(p) => p.clone(),
            _ => return vec![outbound],
        };
        let Some(WireMessage::Proposal(signed)) = decode(&payload) else {
            return vec![outbound];
        };

        let mut block = signed.payload.block.clone();
        // Sentinel root no honest replica would compute. `committed_height`
        // is deliberately left untouched so the honest height-gate fires.
        block.header.committed_state_root = [0xDE; 32];
        let proposal = Proposal {
            block,
            justify: signed.payload.justify.clone(),
        };
        let signed_b = Signed::sign(proposal, ctx.signer.as_ref(), &ctx.chain_id)
            .expect("forged-committed-root adversary re-signing must not fail");
        vec![ProtocolOutbound::Broadcast(encode(&WireMessage::Proposal(
            signed_b,
        )))]
    }
}

/// A Byzantine leader that injects a non-includable *application* command
/// (one the `CounterStateMachine`'s `check` rejects — here a single byte
/// that is not a valid `CounterCommand` and carries no system-tx tag) into
/// every proposal it broadcasts (#598). It recomputes `commands_commitment`
/// so the block is otherwise structurally valid and reaches the honest
/// voters' vote-time includability check, which then abstains — the block
/// gets no honest votes and is rejected, while honest nodes stay live.
/// Models a leader trying to commit a command an honest leader would have
/// dropped at build.
///
/// Re-signs with `ctx.chain_id` so the rejection comes from the
/// includability check, not an envelope-signature failure.
pub struct NonIncludableCommandAdversary;

impl Adversary for NonIncludableCommandAdversary {
    fn intercept(&self, ctx: &AdversaryCtx, outbound: ProtocolOutbound) -> Vec<ProtocolOutbound> {
        let payload = match &outbound {
            ProtocolOutbound::Broadcast(p) => p.clone(),
            _ => return vec![outbound],
        };
        let Some(WireMessage::Proposal(signed)) = decode(&payload) else {
            return vec![outbound];
        };

        let mut block = signed.payload.block.clone();
        // 0x07 is not a valid CounterCommand discriminant and starts with
        // no system-tx tag, so the SM's `check` rejects it.
        block.commands.push(bytes::Bytes::from_static(&[0x07]));
        // Recompute the commands commitment so the block passes structural
        // validation and reaches the vote-time includability check.
        block.header.commands_commitment =
            boule_consensus::replication::block::Block::commands_commitment(&block.commands);
        let proposal = Proposal {
            block,
            justify: signed.payload.justify.clone(),
        };
        let signed_b = Signed::sign(proposal, ctx.signer.as_ref(), &ctx.chain_id)
            .expect("non-includable-command adversary re-signing must not fail");
        vec![ProtocolOutbound::Broadcast(encode(&WireMessage::Proposal(
            signed_b,
        )))]
    }
}

// ── Twin-mode adversary (issue #421) ─────────────────────────────────────────

/// Which honest emission [`TwinValidatorAdversary`] should equivocate
/// under the shared validator key. One variant per signed-envelope kind
/// HotStuff puts on the wire whose detection / safety / liveness story
/// differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwinKind {
    /// Twin Vote envelopes: pass the original through and additionally
    /// broadcast a forged Vote at the same view with a mutated
    /// `block_hash`, re-signed under the byzantine's own key. Honest
    /// recipients hit the `(view, voter_id)` dedupe map landed in
    /// #409 and emit `Action::EquivocationEvidence` on the second
    /// arrival; the integration layer increments
    /// [`boule_consensus::status::ConsensusStatus::equivocations_detected`]
    /// — which the proptest property reads via
    /// [`SimCluster::peek_equivocations_detected`] to confirm the
    /// evidence-emission path is exercised end-to-end.
    Vote,
    /// Twin Proposal envelopes: pass the original through and
    /// additionally broadcast a forged Proposal at the same view whose
    /// `block.header.state_commitment` is mutated and the resulting
    /// block is re-signed. Both proposals reach every honest replica
    /// (unlike [`EquivocatorAdversary`], which splits a 1+2 subset).
    /// Safety holds via the safety core's `last_voted_view` monotonic
    /// — each replica votes for at most one of the two proposals; the
    /// other is dropped on the floor at the receive-side safety check.
    /// Honest replicas hit the `(view, leader_id)` proposal-dedupe map
    /// landed in audit finding L5-1 on the second arrival and emit
    /// [`boule_consensus::hotstuff::step::Action::ProposalEquivocationEvidence`];
    /// the integration layer increments
    /// [`boule_consensus::status::ConsensusStatus::proposal_equivocations_detected`]
    /// — read via
    /// [`crate::sim::SimCluster::peek_proposal_equivocations_detected`]
    /// so the proptest property can confirm the proposer-side
    /// evidence-emission path is exercised end-to-end.
    Proposal,
    /// Twin TimeoutVote envelopes: pass the original through and
    /// additionally broadcast a forged TimeoutVote at the same view
    /// with a mutated `high_qc` piggyback (clears the field to `None`
    /// — distinct from any honest emission, which carries the
    /// genuine `high_qc`). The timeout-bucket folds at most one
    /// signature per `(view, signer)` so the byzantine's two
    /// envelopes contribute one vote, not two; safety + liveness hold
    /// the same way `TimeoutSpammerAdversary` does. No equivocation
    /// evidence is produced today (the dedupe map in #409 covers
    /// Vote only).
    TimeoutVote,
}

/// Adversary 8 (issue #421 / audit finding 14-2): twin-mode adversary
/// that simulates a single validator slot driving two independent
/// inputs to the network under one shared validator key.
///
/// The issue's `TwinValidator` proposal carved this as two real
/// safety-core instances behind a network router. We get the same
/// wire-level shape — and crucially the same recipient-side reactions
/// — by intercepting the honest core's outbound emission, decoding it,
/// and additionally broadcasting a forged twin envelope that conflicts
/// with the original under the same key. From the cluster's vantage
/// every byte that hits the wire is identical to what two cores
/// sharing a key would have emitted; the recipient-side dedupe in #409
/// fires on the Vote variant exactly as it would in the two-core
/// design, and safety + liveness assertions hold for the same reasons
/// (`last_voted_view` monotonic, single-signer-per-bucket folding).
///
/// Restricting to one of [`TwinKind::Vote`] / [`TwinKind::Proposal`] /
/// [`TwinKind::TimeoutVote`] per proptest property satisfies the
/// issue's "at least three property tests" acceptance criterion and
/// keeps the failure mode of any one assertion attributable to a
/// single twin direction.
pub struct TwinValidatorAdversary {
    kind: TwinKind,
}

impl TwinValidatorAdversary {
    pub fn new(kind: TwinKind) -> Self {
        Self { kind }
    }
}

impl Adversary for TwinValidatorAdversary {
    fn intercept(&self, ctx: &AdversaryCtx, outbound: ProtocolOutbound) -> Vec<ProtocolOutbound> {
        let payload = outbound_payload(&outbound);
        let Some(decoded) = decode(&payload) else {
            return vec![outbound];
        };
        match (self.kind, decoded) {
            (TwinKind::Vote, WireMessage::Vote(signed_a, bls_partial)) => {
                // Forge a twin Vote at the same view with a mutated
                // block_hash. The mutated hash points to no real block,
                // but the recipient-side equivocation detector in
                // [`boule_consensus::hotstuff::step::HotStuffCore::on_vote_received`]
                // keys on `(view, voter_id)` and only inspects the
                // stored vs. arriving `block_hash` — it does not
                // require either hash to resolve to a known block.
                //
                // Sign under `ctx.chain_id` (not `ChainId::TEST`) so the
                // honest receivers' `verify_sig` accepts the forgery —
                // the cluster's chain id is derived from the genesis
                // block hash (#324). A forgery under any other tag is
                // rejected at ingress before it can reach the dedupe.
                let mut block_hash_b = signed_a.payload.block_hash;
                block_hash_b[0] ^= 0x01;
                let vote_b = Vote {
                    view: signed_a.payload.view,
                    block_hash: block_hash_b,
                };
                let signed_b = Signed::sign(vote_b, ctx.signer.as_ref(), &ctx.chain_id)
                    .expect("twin vote re-signing must not fail (own signer is healthy)");
                // Carry the original Vote's BLS partial slot through —
                // on Ed25519 chains it is `None`; on BLS chains the
                // dispatch-layer ingress check rejects the forged twin
                // because the partial does not sign over the mutated
                // block_hash. The Ed25519 envelope still verifies, the
                // dedupe map still fires, so the test invariant holds
                // on either chain scheme.
                let payload_b = encode(&WireMessage::Vote(signed_b, bls_partial));
                vec![outbound, ProtocolOutbound::Broadcast(payload_b)]
            }
            (TwinKind::Proposal, WireMessage::Proposal(signed_a)) => {
                // Forge a twin Proposal at the same view whose
                // `state_commitment` is mutated so the block hash
                // diverges from the original. Both proposals are
                // broadcast to every peer (unlike the
                // [`EquivocatorAdversary`] split of 1+2): every honest
                // replica observes both forks at the same view, but
                // each only votes for one (the safety core's
                // `last_voted_view` monotonic check rejects the second
                // by view-equality).
                let block_a = signed_a.payload.block.clone();
                let mut header_b = block_a.header.clone();
                header_b.state_commitment[0] ^= 0x01;
                let block_b = Block {
                    header: header_b,
                    commands: block_a.commands.clone(),
                };
                let proposal_b = Proposal {
                    block: block_b,
                    justify: signed_a.payload.justify.clone(),
                };
                let signed_b = Signed::sign(proposal_b, ctx.signer.as_ref(), &ctx.chain_id)
                    .expect("twin proposal re-signing must not fail");
                let payload_b = encode(&WireMessage::Proposal(signed_b));
                vec![outbound, ProtocolOutbound::Broadcast(payload_b)]
            }
            (TwinKind::TimeoutVote, WireMessage::TimeoutVote(signed_a)) => {
                // Forge a twin TimeoutVote at the same view whose
                // `high_qc` piggyback is cleared (distinct from the
                // honest emission, which carries the genuine
                // `Some(high_qc)`). The timeout-bucket folds at most
                // one signature per `(view, signer)` pair so the
                // twin's envelope adds zero quorum weight; the bucket
                // ignores it the same way it would absorb a stale
                // [`TimeoutSpammerAdversary`] frame.
                let tv_b = TimeoutVote {
                    view: signed_a.payload.view,
                    high_qc: None,
                };
                let signed_b = Signed::sign(tv_b, ctx.signer.as_ref(), &ctx.chain_id)
                    .expect("twin timeout-vote re-signing must not fail");
                let payload_b = encode(&WireMessage::TimeoutVote(signed_b));
                vec![outbound, ProtocolOutbound::Broadcast(payload_b)]
            }
            _ => vec![outbound],
        }
    }
}

// ── Coordinated multi-Byzantine state (audit L3-1) ───────────────────────────

/// Joint state shared by the two coordinated equivocators in the
/// `f = 2` adjacent-view fork scenario.
///
/// Each Byzantine, when it leads, forges a twin proposal (same shape as
/// [`TwinKind::Proposal`]) and publishes its fork-block hash here; its
/// partner reads the other's fork before forging, so the two
/// adjacent-view forks are *causally linked* rather than independent —
/// the leader of view `v+1` chains its fork onto the one the leader of
/// view `v` opened. Without this channel the two equivocations are
/// uncoordinated and the second can't reference the first. This is the
/// "meaningful coordination" the L3-1 acceptance criteria call for.
#[derive(Default)]
struct CoordinationState {
    /// Latest forged fork-block hash published by each coordinated
    /// equivocator, keyed by the publisher's own [`NodeId`].
    forks: HashMap<NodeId, BlockHash>,
    /// How many times an equivocator read a *partner's* fork (a `NodeId`
    /// other than its own) out of `forks` before forging. A non-zero
    /// value proves the channel actually carried data across the two
    /// Byzantines — not just that each wrote its own slot in isolation.
    coordinated_reads: usize,
}

/// Coordinated equivocator (audit L3-1): the multi-Byzantine analogue of
/// [`TwinValidatorAdversary`] under [`TwinKind::Proposal`]. When leading,
/// it broadcasts the honest proposal plus a forged twin (mutated
/// `state_commitment`) to *every* peer, so each honest replica observes
/// both forks at the same view and the proposal-equivocation evidence
/// path fires. Two instances share a [`CoordinationState`]: the second
/// to act folds the partner's published fork hash into its own forged
/// block, linking the two adjacent-view forks.
///
/// Safety holds for the same reason the single equivocator's does — each
/// honest replica's `last_voted_view` monotonic check votes for at most
/// one fork per view, and neither fork reaches the `2f+1 = 5` quorum at
/// `n = 7`. Liveness holds because only the two adjacent Byzantine-led
/// views fork; the five consecutive honest-led views still form a
/// three-chain.
struct CoordinatedEquivocatorAdversary {
    coord: Arc<Mutex<CoordinationState>>,
}

impl CoordinatedEquivocatorAdversary {
    fn new(coord: Arc<Mutex<CoordinationState>>) -> Self {
        Self { coord }
    }
}

impl Adversary for CoordinatedEquivocatorAdversary {
    fn intercept(&self, ctx: &AdversaryCtx, outbound: ProtocolOutbound) -> Vec<ProtocolOutbound> {
        let payload = outbound_payload(&outbound);
        // Only equivocate our own proposals (i.e. when we lead). Every
        // other emission passes through honestly — so a coordinated
        // equivocator that is currently a follower still votes, which is
        // what makes the honest-led views reach quorum.
        let Some(WireMessage::Proposal(signed_a)) = decode(&payload) else {
            return vec![outbound];
        };

        // Read the partner's most-recent fork (any entry not our own)
        // out of the shared channel and fold it into our mutation, so
        // the two adjacent-view forks are causally linked. Record the
        // cross-read so the test can prove the channel carried data.
        let partner_fork: Option<BlockHash> = {
            let mut c = self.coord.lock();
            let partner = c
                .forks
                .iter()
                .find(|(id, _)| **id != ctx.my_id)
                .map(|(_, h)| *h);
            if partner.is_some() {
                c.coordinated_reads += 1;
            }
            partner
        };

        // Forge twin proposal B at the same view: mutate
        // `state_commitment` so the block hash diverges from the honest
        // proposal. If we saw a partner's fork, fold its first byte in
        // so B's identity depends on the partner's fork (the causal
        // link). Re-sign under `ctx.chain_id` so honest receivers accept
        // the envelope and reach the content-level safety check.
        let block_a = signed_a.payload.block.clone();
        let mut header_b = block_a.header.clone();
        header_b.state_commitment[0] ^= 0x01;
        if let Some(pf) = partner_fork {
            header_b.state_commitment[1] ^= pf[0];
        }
        let block_b = Block {
            header: header_b,
            commands: block_a.commands.clone(),
        };
        let proposal_b = Proposal {
            block: block_b,
            justify: signed_a.payload.justify.clone(),
        };
        let signed_b = Signed::sign(proposal_b, ctx.signer.as_ref(), &ctx.chain_id)
            .expect("coordinated equivocator re-signing must not fail (own signer is healthy)");

        // Publish our fork hash for the partner to extend on its turn.
        self.coord
            .lock()
            .forks
            .insert(ctx.my_id, signed_b.payload.block.hash());

        let payload_b = encode(&WireMessage::Proposal(signed_b));
        vec![outbound, ProtocolOutbound::Broadcast(payload_b)]
    }
}

// ── Tests / proptest properties ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Run an async sim scenario on a fresh `current_thread` Tokio
    /// runtime with virtual time paused. Mirrors the `run_paused`
    /// helper in [`crate::sim`]'s L-series proptests.
    fn run_paused<Fut, T>(fut: impl FnOnce() -> Fut) -> T
    where
        Fut: std::future::Future<Output = T>,
    {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap()
            .block_on(fut())
    }

    /// Adversary kind for the mixed-fuzz property below.
    #[derive(Debug, Clone, Copy)]
    enum AdvKind {
        Equivocator,
        VoteWithholder,
        StaleReplayer,
        ForgedQc,
        TimeoutSpammer,
        ForgedPiggyback,
        ForgedHistoryCommitment,
        TwinVote,
        TwinProposal,
        TwinTimeoutVote,
    }

    fn build_adversary(kind: AdvKind) -> Arc<dyn Adversary> {
        match kind {
            AdvKind::Equivocator => Arc::new(EquivocatorAdversary),
            AdvKind::VoteWithholder => Arc::new(VoteWithholderAdversary),
            // K=2 keeps the replay fraction high enough to exercise
            // the rejection path on every other outbound, while
            // still letting honest traffic dominate so the test
            // budget stays bounded.
            AdvKind::StaleReplayer => Arc::new(StaleReplayerAdversary::new(2)),
            AdvKind::ForgedQc => Arc::new(ForgedQcAdversary::new(2)),
            AdvKind::TimeoutSpammer => Arc::new(TimeoutSpammerAdversary::new(2)),
            AdvKind::ForgedPiggyback => Arc::new(ForgedPiggybackAdversary::new(2)),
            AdvKind::ForgedHistoryCommitment => Arc::new(ForgedHistoryCommitmentAdversary),
            AdvKind::TwinVote => Arc::new(TwinValidatorAdversary::new(TwinKind::Vote)),
            AdvKind::TwinProposal => Arc::new(TwinValidatorAdversary::new(TwinKind::Proposal)),
            AdvKind::TwinTimeoutVote => {
                Arc::new(TwinValidatorAdversary::new(TwinKind::TimeoutVote))
            }
        }
    }

    fn adv_label(kind: AdvKind) -> &'static str {
        match kind {
            AdvKind::Equivocator => "equivocator",
            AdvKind::VoteWithholder => "vote-withholder",
            AdvKind::StaleReplayer => "stale-replayer",
            AdvKind::ForgedQc => "forged-qc",
            AdvKind::TimeoutSpammer => "timeout-spammer",
            AdvKind::ForgedPiggyback => "forged-piggyback",
            AdvKind::ForgedHistoryCommitment => "forged-history-commitment",
            AdvKind::TwinVote => "twin-vote",
            AdvKind::TwinProposal => "twin-proposal",
            AdvKind::TwinTimeoutVote => "twin-timeout-vote",
        }
    }

    /// Honest commit floor used by every property below. Conservative
    /// — the suite asserts "the cluster keeps making progress under
    /// attack", not a specific throughput, so a small floor avoids
    /// flakiness from view-stall recovery latency.
    const HONEST_FLOOR: u64 = 3;

    /// Cap on simulated time per case. Each property's
    /// `advance_and_yield_until` call early-exits as soon as every
    /// honest node has cleared `HONEST_FLOOR`, so the cap is a safety
    /// net rather than the typical run length. The wider cap on the
    /// equivocator / mixed properties absorbs the extra view-stall
    /// recovery latency when the byzantine is currently leading.
    const SIM_CAP: Duration = Duration::from_secs(10);

    /// Spawn a 4-node cluster with one Byzantine adversary at sorted
    /// index `victim`. Returns the cluster and the list of honest
    /// indices for downstream assertion convenience.
    async fn spawn_with_one_adversary(
        victim: usize,
        adv: Arc<dyn Adversary>,
    ) -> (SimCluster, Vec<usize>) {
        let mut adversaries: Vec<Option<Arc<dyn Adversary>>> = (0..4).map(|_| None).collect();
        adversaries[victim] = Some(adv);
        let cluster = SimCluster::spawn_with_adversaries(
            4,
            // 50ms timeout base matches the rest of the consensus
            // sim suite; under tokio::time::pause this is virtual
            // time so the wall-clock cost is independent of the
            // base.
            Duration::from_millis(50),
            adversaries,
        )
        .await;
        let honest: Vec<usize> = (0..4).filter(|i| *i != victim).collect();
        (cluster, honest)
    }

    /// Drive simulated time until every honest node has gained at
    /// least `HONEST_FLOOR` commits past `baseline`, or the `SIM_CAP`
    /// budget is exhausted. Returns the post-run heights so the
    /// caller can include them in failure messages.
    async fn run_until_honest_floor_or_cap(
        cluster: &mut SimCluster,
        honest: &[usize],
        baseline: &[u64],
    ) -> (bool, Vec<u64>) {
        let baseline = baseline.to_vec();
        let honest_owned = honest.to_vec();
        let satisfied = cluster
            .advance_and_yield_until(SIM_CAP, |c| {
                let h = c.peek_commit_heights();
                honest_owned
                    .iter()
                    .all(|&i| h[i] >= baseline[i] + HONEST_FLOOR)
            })
            .await;
        let final_heights = cluster.peek_commit_heights();
        (satisfied, final_heights)
    }

    /// One property body, parameterised on the adversary kind. Spawns
    /// `4` validators with a single Byzantine at sorted index `victim`,
    /// runs until every honest node has gained `HONEST_FLOOR` new
    /// commits (capped by `SIM_CAP`), then asserts:
    ///
    /// 1. Safety: `assert_no_conflicts` across every committed block on
    ///    every node, byzantine included.
    /// 2. Liveness: the early-exit predicate fired (every honest node
    ///    cleared the floor).
    async fn run_one_property(victim: usize, kind: AdvKind) -> Result<(), TestCaseError> {
        let (mut cluster, honest) = spawn_with_one_adversary(victim, build_adversary(kind)).await;
        let baseline = cluster.peek_commit_heights();
        let (satisfied, final_heights) =
            run_until_honest_floor_or_cap(&mut cluster, &honest, &baseline).await;

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);

        prop_assert!(
            satisfied,
            "{} adversary at index {victim}: honest nodes did not all gain \
             ≥ {HONEST_FLOOR} commits within {SIM_CAP:?} simulated; \
             baseline = {baseline:?}, final = {final_heights:?}",
            adv_label(kind),
        );
        Ok(())
    }

    proptest! {
        // 6 cases per property keeps the per-property wall-clock
        // budget under ~3s (cluster setup dominates; each case
        // spawns 4 fresh Ed25519 keypairs at ~5–10ms each), so the
        // full 6-property suite stays well inside the issue's
        // ≤ 60s `cargo test --release` cap.
        #![proptest_config(ProptestConfig {
            cases: 6,
            failure_persistence: None,
            ..Default::default()
        })]

        /// **Equivocator** — leader broadcasts two distinct proposals
        /// at the same view to disjoint validator subsets. With n=4
        /// and a 1+2 split of the three honest peers, neither proposal
        /// reaches the 3-vote quorum during the equivocated view; the
        /// pacemaker times out and the next-view honest leader recovers
        /// liveness. Safety: `last_voted_view` monotonicity on every
        /// honest replica means each replica votes for at most one of
        /// the two proposals, so a conflicting block is never finalised.
        #[test]
        fn proptest_equivocator_preserves_safety_and_liveness(
            victim in 0usize..4,
        ) {
            run_paused(|| async move {
                run_one_property(victim, AdvKind::Equivocator).await
            })?;
        }

        /// **Vote-withholder** — Byzantine receives proposals normally
        /// but never emits a Vote. Cluster has quorum without the
        /// Byzantine's vote (leader's own self-vote + 2 honest = 3 of
        /// 4), so liveness is preserved on every view.
        #[test]
        fn proptest_vote_withholder_preserves_safety_and_liveness(
            victim in 0usize..4,
        ) {
            run_paused(|| async move {
                run_one_property(victim, AdvKind::VoteWithholder).await
            })?;
        }

        /// **Stale-replayer** — Byzantine replays past valid envelopes
        /// after their views have moved on. Honest replicas reject via
        /// `last_voted_view` (votes), the view-monotonic check on
        /// proposals, and `should_update_high_qc` (NewView) — all
        /// without crashing. Safety + liveness preserved.
        #[test]
        fn proptest_stale_replayer_preserves_safety_and_liveness(
            victim in 0usize..4,
        ) {
            run_paused(|| async move {
                run_one_property(victim, AdvKind::StaleReplayer).await
            })?;
        }

        /// **Forged-QC sender** — Byzantine broadcasts NewView envelopes
        /// carrying QCs with insufficient signers and zero-byte
        /// signatures, at view 0 (the genesis-QC view). Honest replicas
        /// reject via `should_update_high_qc`'s strict-greater-view
        /// rule without crashing on the malformed inner content.
        #[test]
        fn proptest_forged_qc_preserves_safety_and_liveness(
            victim in 0usize..4,
        ) {
            run_paused(|| async move {
                run_one_property(victim, AdvKind::ForgedQc).await
            })?;
        }

        /// **TimeoutVote spammer** — Byzantine broadcasts a TimeoutVote
        /// for arbitrary views on a regular schedule. The
        /// timeout-certificate bucket on each recipient absorbs a
        /// single signer silently (1 < 3 = quorum), so no spurious
        /// view jump fires. Safety + liveness preserved.
        #[test]
        fn proptest_timeout_spammer_preserves_safety_and_liveness(
            victim in 0usize..4,
        ) {
            run_paused(|| async move {
                run_one_property(victim, AdvKind::TimeoutSpammer).await
            })?;
        }

        /// **Forged-piggyback timeout-vote spammer** (issue #321) —
        /// Byzantine attaches a well-formed but cryptographically
        /// bogus `high_qc` at `view = u64::MAX - 1` to its timeout
        /// votes. Without ingress aggregate verification, the bucket
        /// would adopt this piggyback as `best_high_qc` once `f + 1`
        /// honest replicas timed out into the same view, and the TC
        /// self-NewView loopback would launder it into every honest
        /// replica's `state.high_qc`. Safety would then break: the
        /// safety core would commit on a chain whose ancestor QC is
        /// unauthenticated. With the verifier wired in, the forged
        /// piggyback is dropped at ingress (`high_qc_trusted == false`
        /// in the resulting `Dispatch::TimeoutVote`), the bucket
        /// ignores the QC, and the cluster's safety + liveness floors
        /// hold. The same `assert_no_conflicts` + honest-floor
        /// pattern as the other adversaries is sufficient: a forged
        /// QC adoption would either fork the committed chain or wedge
        /// liveness as honest replicas fail to converge to a fake
        /// future view.
        #[test]
        fn proptest_forged_piggyback_preserves_safety_and_liveness(
            victim in 0usize..4,
        ) {
            run_paused(|| async move {
                run_one_property(victim, AdvKind::ForgedPiggyback).await
            })?;
        }

        /// **Forged history-commitment leader** (issue #325 PR C) —
        /// when this byzantine is leader, every Proposal it
        /// broadcasts has its `block.header.validator_history_commitment`
        /// rewritten to a sentinel `[0xDE; 32]` value before being
        /// re-signed. Without proposal-receive validation in
        /// `dispatch::ingress`, honest followers vote on the
        /// proposal, the QC forms, and the chain commits a block
        /// whose stamped commitment doesn't match the histories
        /// that produced it. With the verifier wired in (PR C),
        /// every forged-commitment proposal is rejected with
        /// `IngressError::InvalidValidatorHistoryCommitment` before
        /// reaching the safety core; honest leaders at the next
        /// view recover liveness. Safety + the honest-floor liveness
        /// invariant hold under the same `run_one_property`
        /// harness.
        #[test]
        fn proptest_forged_history_commitment_preserves_safety_and_liveness(
            victim in 0usize..4,
        ) {
            run_paused(|| async move {
                run_one_property(victim, AdvKind::ForgedHistoryCommitment).await
            })?;
        }

        /// **Twin-mode vote** (issue #421 / audit finding 14-2) —
        /// byzantine emits an honest Vote and additionally broadcasts
        /// a forged twin Vote at the same view with a mutated
        /// `block_hash`, both signed under the shared validator key.
        /// Honest replicas hit the `(view, voter_id)` dedupe map
        /// landed in #409 on the second arrival and emit
        /// `Action::EquivocationEvidence`; the integration layer
        /// increments
        /// [`boule_consensus::status::ConsensusStatus::equivocations_detected`].
        /// Safety: the dedupe drops the second partial on the floor,
        /// so neither bucket inflates with conflicting signatures.
        /// Liveness: the byzantine's *first* Vote still folds into
        /// the bucket the proposed block hashes to, leaving honest
        /// quorum formation unaffected.
        ///
        /// In addition to the safety + liveness floors enforced by
        /// `run_one_property`, this property asserts the
        /// evidence-emission path is exercised end-to-end:
        /// `equivocations_detected` is `> 0` on at least
        /// `f + 1 = 2` honest replicas. Per-replica detection runs
        /// independently on each receiver, and the byzantine emits
        /// twin votes on every view it participates in, so a
        /// HONEST_FLOOR-of-3 commit run reliably accumulates
        /// detections everywhere.
        #[test]
        fn proptest_twin_vote_preserves_safety_and_emits_evidence(
            victim in 0usize..4,
        ) {
            run_paused(|| async move {
                let (mut cluster, honest) =
                    spawn_with_one_adversary(victim, build_adversary(AdvKind::TwinVote)).await;
                let baseline = cluster.peek_commit_heights();
                let (satisfied, final_heights) =
                    run_until_honest_floor_or_cap(&mut cluster, &honest, &baseline).await;

                let committed = cluster.drain_commits();
                assert_no_conflicts(&committed);

                prop_assert!(
                    satisfied,
                    "twin-vote adversary at index {victim}: honest nodes did not all gain \
                     ≥ {HONEST_FLOOR} commits within {SIM_CAP:?} simulated; \
                     baseline = {baseline:?}, final = {final_heights:?}",
                );

                let evidence_counts: Vec<u64> = honest
                    .iter()
                    .map(|&i| cluster.peek_equivocations_detected(i))
                    .collect();
                let detectors = evidence_counts.iter().filter(|&&c| c > 0).count();
                prop_assert!(
                    detectors >= 2,
                    "twin-vote adversary at index {victim}: expected the equivocation \
                     evidence path to fire on ≥ f+1 = 2 honest replicas, got {detectors} \
                     (per-honest counts = {evidence_counts:?})",
                );
                Ok::<(), TestCaseError>(())
            })?;
        }

        /// **Twin-mode proposal** (issue #421 / audit finding L5-1) —
        /// byzantine leader broadcasts an honest Proposal and
        /// additionally a forged twin Proposal at the same view whose
        /// `state_commitment` is mutated, both signed under the shared
        /// validator key. Both proposals reach every honest replica
        /// (unlike the existing [`EquivocatorAdversary`], which carves
        /// a 1+2 split). Safety: each honest replica's
        /// `last_voted_view` monotonic check ensures it votes for at
        /// most one of the two proposals at view V; the other is
        /// dropped. Liveness: when honest replicas converge on the
        /// same fork the QC forms normally; when they vote on
        /// different forks neither side reaches quorum, the pacemaker
        /// times out, and the next-view honest leader recovers — the
        /// same wedge the equivocator property already exercises.
        ///
        /// In addition to the safety + liveness floors enforced by
        /// `run_one_property`, this property asserts the proposer-side
        /// evidence-emission path is exercised end-to-end:
        /// `proposal_equivocations_detected` is `> 0` on at least
        /// `f + 1 = 2` honest replicas. The byzantine becomes leader
        /// once per `n` views in round-robin, and a HONEST_FLOOR-of-3
        /// commit run takes enough views that at least one of those
        /// leadership turns lands on the byzantine — both forks reach
        /// every honest replica via the broadcast, so each receiver
        /// trips its dedupe map independently.
        #[test]
        fn proptest_twin_proposal_preserves_safety_and_emits_evidence(
            victim in 0usize..4,
        ) {
            run_paused(|| async move {
                let (mut cluster, honest) =
                    spawn_with_one_adversary(victim, build_adversary(AdvKind::TwinProposal)).await;
                let baseline = cluster.peek_commit_heights();
                let (satisfied, final_heights) =
                    run_until_honest_floor_or_cap(&mut cluster, &honest, &baseline).await;

                let committed = cluster.drain_commits();
                assert_no_conflicts(&committed);

                prop_assert!(
                    satisfied,
                    "twin-proposal adversary at index {victim}: honest nodes did not all gain \
                     ≥ {HONEST_FLOOR} commits within {SIM_CAP:?} simulated; \
                     baseline = {baseline:?}, final = {final_heights:?}",
                );

                let evidence_counts: Vec<u64> = honest
                    .iter()
                    .map(|&i| cluster.peek_proposal_equivocations_detected(i))
                    .collect();
                let detectors = evidence_counts.iter().filter(|&&c| c > 0).count();
                prop_assert!(
                    detectors >= 2,
                    "twin-proposal adversary at index {victim}: expected the \
                     proposal-equivocation evidence path to fire on ≥ f+1 = 2 honest replicas, \
                     got {detectors} (per-honest counts = {evidence_counts:?})",
                );
                Ok::<(), TestCaseError>(())
            })?;
        }

        /// **Twin-mode timeout-vote** (issue #421) — byzantine emits
        /// an honest TimeoutVote and additionally broadcasts a forged
        /// twin TimeoutVote at the same view with the `high_qc`
        /// piggyback cleared, both signed under the shared validator
        /// key. The timeout-bucket folds at most one signature per
        /// `(view, signer)`, so the twin envelope adds zero quorum
        /// weight; the bucket absorbs it the same way it would
        /// absorb a stale [`TimeoutSpammerAdversary`] frame. Safety
        /// + liveness invariants hold under the standard harness.
        #[test]
        fn proptest_twin_timeout_vote_preserves_safety_and_liveness(
            victim in 0usize..4,
        ) {
            run_paused(|| async move {
                run_one_property(victim, AdvKind::TwinTimeoutVote).await
            })?;
        }

        /// **Mixed adversary** — randomly pick one of the ten
        /// adversary kinds for the single Byzantine slot. Verifies
        /// that property-1..10's invariants hold across the union of
        /// adversaries (no implicit interaction breaks safety or
        /// liveness when the adversary is selected uniformly).
        #[test]
        fn proptest_mixed_adversary_preserves_safety_and_liveness(
            victim in 0usize..4,
            kind_selector in 0usize..10,
        ) {
            run_paused(|| async move {
                let kind = match kind_selector {
                    0 => AdvKind::Equivocator,
                    1 => AdvKind::VoteWithholder,
                    2 => AdvKind::StaleReplayer,
                    3 => AdvKind::ForgedQc,
                    4 => AdvKind::TimeoutSpammer,
                    5 => AdvKind::ForgedPiggyback,
                    6 => AdvKind::ForgedHistoryCommitment,
                    7 => AdvKind::TwinVote,
                    8 => AdvKind::TwinProposal,
                    _ => AdvKind::TwinTimeoutVote,
                };
                run_one_property(victim, kind).await
            })?;
        }
    }

    // ── Multi-Byzantine (n = 7, f = 2) coordinated adversaries (L3-1) ─────────
    //
    // The single-Byzantine catalog above covers `n = 4, f = 1`. The
    // HotStuff safety theorem is parameterised by `f` Byzantine in
    // `n = 3f+1`; these properties lift coverage to `f = 2` with *two*
    // adversaries, including a genuinely coordinated pair sharing joint
    // state. Quorum is 5-of-7 (uniform weight), the honesty threshold is
    // `f+1 = 3`. The honest commit floor (`HONEST_FLOOR`) and time cap
    // (`SIM_CAP`) are reused from the f=1 suite.

    /// `n = 3f+1` for `f = 2`.
    const F2_N: usize = 7;

    /// Map a `0..10` selector to an [`AdvKind`]; shared by the mixed
    /// composition property so each Byzantine samples the catalog
    /// independently.
    fn adv_kind_from_index(i: usize) -> AdvKind {
        match i {
            0 => AdvKind::Equivocator,
            1 => AdvKind::VoteWithholder,
            2 => AdvKind::StaleReplayer,
            3 => AdvKind::ForgedQc,
            4 => AdvKind::TimeoutSpammer,
            5 => AdvKind::ForgedPiggyback,
            6 => AdvKind::ForgedHistoryCommitment,
            7 => AdvKind::TwinVote,
            8 => AdvKind::TwinProposal,
            _ => AdvKind::TwinTimeoutVote,
        }
    }

    /// Spawn an `n`-node cluster with a Byzantine adversary installed at
    /// each `(index, adversary)` slot; the rest run honest. Returns the
    /// cluster and the sorted list of honest indices.
    async fn spawn_with_adversaries_at(
        n: usize,
        slots: Vec<(usize, Arc<dyn Adversary>)>,
    ) -> (SimCluster, Vec<usize>) {
        let mut adversaries: Vec<Option<Arc<dyn Adversary>>> = (0..n).map(|_| None).collect();
        for (idx, adv) in &slots {
            adversaries[*idx] = Some(Arc::clone(adv));
        }
        let cluster =
            SimCluster::spawn_with_adversaries(n, Duration::from_millis(50), adversaries).await;
        let byz: Vec<usize> = slots.iter().map(|(i, _)| *i).collect();
        let honest: Vec<usize> = (0..n).filter(|i| !byz.contains(i)).collect();
        (cluster, honest)
    }

    proptest! {
        // 4 cases per property: an n=7 cluster spawns 7 fresh Ed25519
        // keypairs and routes ~2× the f=1 message volume, so each case
        // is heavier than the f=1 suite's. 4 keeps every property well
        // under the 15s-per-test ceiling while still sampling a range of
        // Byzantine placements.
        #![proptest_config(ProptestConfig {
            cases: 4,
            failure_persistence: None,
            ..Default::default()
        })]

        /// **Two coordinated equivocators at adjacent views.** Byzantines
        /// at sorted indices `b` and `b+1` lead views `b` and `b+1`
        /// (round-robin `leader_for_view(v) = node_ids[v % n]`, so
        /// adjacent indices ⇒ adjacent views), each twin-equivocating its
        /// proposal and chaining its fork onto the partner's via the
        /// shared [`CoordinationState`]. Asserts: no commit on either
        /// fork (`assert_no_conflicts`), the 5 honest replicas still meet
        /// the commit floor through the five honest-led views, both
        /// equivocations are evidenced on ≥ `f+1 = 3` honest replicas,
        /// and the coordination channel actually carried data across the
        /// two Byzantines.
        #[test]
        fn proptest_f2_two_coordinated_equivocators_preserve_safety_and_evidence(
            b in 0usize..7,
        ) {
            run_paused(|| async move {
                let coord = Arc::new(Mutex::new(CoordinationState::default()));
                let b1 = b;
                let b2 = (b + 1) % F2_N;
                let slots: Vec<(usize, Arc<dyn Adversary>)> = vec![
                    (
                        b1,
                        Arc::new(CoordinatedEquivocatorAdversary::new(Arc::clone(&coord))),
                    ),
                    (
                        b2,
                        Arc::new(CoordinatedEquivocatorAdversary::new(Arc::clone(&coord))),
                    ),
                ];
                let (mut cluster, honest) = spawn_with_adversaries_at(F2_N, slots).await;
                let baseline = cluster.peek_commit_heights();

                // Drive until the honest floor is met *and* the
                // coordination channel has been read across the two
                // Byzantines. The second condition matters because the
                // bare floor can be reached from the first few honest-led
                // views before the second Byzantine ever leads a view to
                // read its partner's fork; without it the run early-exits
                // and `coordinated_reads` is racily still 0.
                let coord_probe = Arc::clone(&coord);
                let honest_pred = honest.clone();
                let baseline_pred = baseline.clone();
                let satisfied = cluster
                    .advance_and_yield_until(SIM_CAP, |c| {
                        let h = c.peek_commit_heights();
                        let floor_met = honest_pred
                            .iter()
                            .all(|&i| h[i] >= baseline_pred[i] + HONEST_FLOOR);
                        floor_met && coord_probe.lock().coordinated_reads >= 1
                    })
                    .await;
                let final_heights = cluster.peek_commit_heights();

                let committed = cluster.drain_commits();
                assert_no_conflicts(&committed);

                prop_assert!(
                    satisfied,
                    "two coordinated equivocators at {b1},{b2}: honest floor (≥ {HONEST_FLOOR}) \
                     and a cross-Byzantine coordination read were not both reached within \
                     {SIM_CAP:?} simulated; baseline = {baseline:?}, final = {final_heights:?}, \
                     coordinated_reads = {}",
                    coord.lock().coordinated_reads,
                );

                let evidence: Vec<u64> = honest
                    .iter()
                    .map(|&i| cluster.peek_proposal_equivocations_detected(i))
                    .collect();
                let detectors = evidence.iter().filter(|&&c| c > 0).count();
                prop_assert!(
                    detectors >= 3,
                    "two coordinated equivocators at {b1},{b2}: expected the \
                     proposal-equivocation evidence path to fire on ≥ f+1 = 3 honest replicas, \
                     got {detectors} (per-honest counts = {evidence:?})",
                );

                let reads = coord.lock().coordinated_reads;
                prop_assert!(
                    reads >= 1,
                    "coordination channel was never read across the two Byzantines \
                     (coordinated_reads = {reads})",
                );
                Ok::<(), TestCaseError>(())
            })?;
        }

        /// **Equivocator + withholder.** Byzantine #1 equivocates as
        /// leader; Byzantine #2 withholds every vote. Tests that the
        /// 5-of-7 quorum survives losing both Byzantines' contribution
        /// (the withholder's vote and the equivocator's forked
        /// leader-views) — the five honest replicas still commit, safety
        /// preserved.
        #[test]
        fn proptest_f2_equivocator_plus_withholder_preserves_liveness(b in 0usize..7) {
            run_paused(|| async move {
                let b1 = b;
                // +3 (mod 7) keeps the two Byzantines distinct and
                // non-adjacent across the placement sweep.
                let b2 = (b + 3) % F2_N;
                let slots: Vec<(usize, Arc<dyn Adversary>)> = vec![
                    (b1, Arc::new(EquivocatorAdversary)),
                    (b2, Arc::new(VoteWithholderAdversary)),
                ];
                let (mut cluster, honest) = spawn_with_adversaries_at(F2_N, slots).await;
                let baseline = cluster.peek_commit_heights();
                let (satisfied, final_heights) =
                    run_until_honest_floor_or_cap(&mut cluster, &honest, &baseline).await;

                let committed = cluster.drain_commits();
                assert_no_conflicts(&committed);

                prop_assert!(
                    satisfied,
                    "equivocator@{b1} + withholder@{b2}: honest nodes did not all gain \
                     ≥ {HONEST_FLOOR} commits within {SIM_CAP:?} simulated; \
                     baseline = {baseline:?}, final = {final_heights:?}",
                );
                Ok::<(), TestCaseError>(())
            })?;
        }

        /// **Two TimeoutVote spammers.** Both Byzantines flood the
        /// timeout buckets at distinct leader views. Asserts: no spurious
        /// view advance wedges progress (the honesty-threshold gate holds
        /// — the per-bucket cap evicts under joint pressure without OOM),
        /// the honest replicas still meet the commit floor, and safety is
        /// preserved.
        #[test]
        fn proptest_f2_two_timeout_spammers_preserve_liveness(b in 0usize..7) {
            run_paused(|| async move {
                let b1 = b;
                let b2 = (b + 2) % F2_N;
                let slots: Vec<(usize, Arc<dyn Adversary>)> = vec![
                    (b1, Arc::new(TimeoutSpammerAdversary::new(2))),
                    (b2, Arc::new(TimeoutSpammerAdversary::new(2))),
                ];
                let (mut cluster, honest) = spawn_with_adversaries_at(F2_N, slots).await;
                let baseline = cluster.peek_commit_heights();
                let (satisfied, final_heights) =
                    run_until_honest_floor_or_cap(&mut cluster, &honest, &baseline).await;

                let committed = cluster.drain_commits();
                assert_no_conflicts(&committed);

                prop_assert!(
                    satisfied,
                    "two timeout spammers at {b1},{b2}: honest nodes did not all gain \
                     ≥ {HONEST_FLOOR} commits within {SIM_CAP:?} simulated; \
                     baseline = {baseline:?}, final = {final_heights:?}",
                );
                Ok::<(), TestCaseError>(())
            })?;
        }

        /// **Coordinated piggyback forge.** Both Byzantines attach forged
        /// high-view `high_qc` piggybacks to their TimeoutVotes. Asserts
        /// that piggyback verification (#321 / 10-F3) holds under joint
        /// pressure: neither forged QC can wedge the cluster or fork it —
        /// the honest replicas keep committing and safety is preserved.
        /// (A forged QC that slipped into `best_high_qc` would either
        /// stall a replica on a non-existent block or admit a conflicting
        /// commit; both surface here as a floor/safety failure.)
        #[test]
        fn proptest_f2_two_piggyback_forgers_preserve_safety_and_liveness(b in 0usize..7) {
            run_paused(|| async move {
                let b1 = b;
                let b2 = (b + 2) % F2_N;
                let slots: Vec<(usize, Arc<dyn Adversary>)> = vec![
                    (b1, Arc::new(ForgedPiggybackAdversary::new(2))),
                    (b2, Arc::new(ForgedPiggybackAdversary::new(2))),
                ];
                let (mut cluster, honest) = spawn_with_adversaries_at(F2_N, slots).await;
                let baseline = cluster.peek_commit_heights();
                let (satisfied, final_heights) =
                    run_until_honest_floor_or_cap(&mut cluster, &honest, &baseline).await;

                let committed = cluster.drain_commits();
                assert_no_conflicts(&committed);

                prop_assert!(
                    satisfied,
                    "two piggyback forgers at {b1},{b2}: honest nodes did not all gain \
                     ≥ {HONEST_FLOOR} commits within {SIM_CAP:?} simulated; \
                     baseline = {baseline:?}, final = {final_heights:?}",
                );
                Ok::<(), TestCaseError>(())
            })?;
        }

        /// **Mixed-class composition at f=2.** Each Byzantine
        /// independently samples the 10-class catalog (the f=1 mixed
        /// property lifted to two adversaries). `sep ∈ 1..7` guarantees
        /// the two placements are distinct. Asserts safety and the honest
        /// commit floor across every sampled composition.
        #[test]
        fn proptest_f2_mixed_composition_preserves_safety_and_liveness(
            b in 0usize..7,
            sep in 1usize..7,
            k1 in 0usize..10,
            k2 in 0usize..10,
        ) {
            run_paused(|| async move {
                let b1 = b;
                let b2 = (b + sep) % F2_N;
                let kind1 = adv_kind_from_index(k1);
                let kind2 = adv_kind_from_index(k2);
                let slots: Vec<(usize, Arc<dyn Adversary>)> = vec![
                    (b1, build_adversary(kind1)),
                    (b2, build_adversary(kind2)),
                ];
                let (mut cluster, honest) = spawn_with_adversaries_at(F2_N, slots).await;
                let baseline = cluster.peek_commit_heights();
                let (satisfied, final_heights) =
                    run_until_honest_floor_or_cap(&mut cluster, &honest, &baseline).await;

                let committed = cluster.drain_commits();
                assert_no_conflicts(&committed);

                prop_assert!(
                    satisfied,
                    "mixed f=2 [{}@{b1}, {}@{b2}]: honest nodes did not all gain \
                     ≥ {HONEST_FLOOR} commits within {SIM_CAP:?} simulated; \
                     baseline = {baseline:?}, final = {final_heights:?}",
                    adv_label(kind1),
                    adv_label(kind2),
                );
                Ok::<(), TestCaseError>(())
            })?;
        }
    }

    // ── Weighted-quorum re-validation of the adversary roster (#472) ──────────
    //
    // The catalog above (f=1 and f=2) ran at uniform weight = 1. The
    // weighted-quorum stack (#463/#467) ships a strict-`>` predicate
    // `3*signer_weight > 2*total_weight`; whether each adversary's
    // safety/liveness story survives a *stake-heavy* Byzantine subset was
    // unverified by automation (#470 covered only the silencing/kill
    // fault model). These properties pair a non-uniform weight vector
    // with each existing `Adversary` impl, picking the Byzantine subset
    // weight-descending up to `floor(total_weight / 3)`.

    /// Honest commit floor for the weighted properties. Deliberately a
    /// single commit (vs. the f=1/f=2 floor of 3): the Byzantine subset
    /// here sits right at the `floor(total/3)` weight boundary and `n` /
    /// weight ranges are wide, so a `≥ 1` floor is the robust liveness
    /// signal — "the honest survivors still make progress" — rather than
    /// a throughput claim.
    const WEIGHTED_FLOOR: u64 = 1;

    /// Greedily pick the Byzantine subset *weight-descending* until the
    /// next addition would push the running Byzantine weight past
    /// `floor(total_weight / 3)`. Returns the chosen indices sorted
    /// ascending (sorted-validator order, matching `cluster.node_ids`).
    ///
    /// Heaviest-first both maximises Byzantine influence within the bound
    /// (the strongest test of the strict-`>` quorum boundary) and
    /// *minimises the Byzantine node count* — reaching the weight cap in
    /// the fewest validators — which keeps the honest-led run long enough
    /// to form three-chains and is what makes liveness hold. Mirrors the
    /// generator #470 used for its silencing test.
    fn weight_descending_byzantine_subset(weights: &[u64]) -> Vec<usize> {
        let total: u128 = weights.iter().map(|w| u128::from(*w)).sum();
        let cap = total / 3;
        let mut indexed: Vec<(usize, u64)> = weights.iter().copied().enumerate().collect();
        indexed.sort_by_key(|(_, w)| std::cmp::Reverse(*w));
        let mut byz: Vec<usize> = Vec::new();
        let mut byz_weight: u128 = 0;
        for (idx, w) in indexed {
            if byz_weight + u128::from(w) <= cap {
                byz.push(idx);
                byz_weight += u128::from(w);
            }
        }
        byz.sort_unstable();
        byz
    }

    /// Pick the *single* heaviest validator whose weight is ≤
    /// `floor(total_weight / 3)` — one stake-heavy Byzantine carrying up
    /// to ~⅓ of total weight.
    ///
    /// Used for the *leader-faulty* adversaries (the equivocator and the
    /// forged-history-commitment leader) whose proposals produce **no QC
    /// at their own leader views** — the equivocator's disjoint split
    /// never reaches quorum on either fork, and the forged-history block
    /// is rejected as structurally invalid. Under the round-robin (count-
    /// based) leader rotation, a *multi*-validator Byzantine subset of
    /// such leaders can occupy ≥1 of every three consecutive leader slots
    /// and so deny chained HotStuff the three-consecutive-honest-leader
    /// window it needs to commit — a real interaction between count-based
    /// leadership and weighted quorums that this issue's *stake-weighted
    /// leader selection* non-goal leaves open. A single Byzantine leaves
    /// an `n-1`-length consecutive honest-leader run, so the three-chain
    /// always forms and liveness is robust, while still stressing the
    /// weighted-quorum boundary with a ~⅓-weight adversary. (Multi-
    /// Byzantine equivocation *safety* at uniform weight is covered by the
    /// f=2 coordinated-equivocator property above / #589.)
    ///
    /// Always returns exactly one index for `n ≥ 4`: the lowest-weight
    /// validator has weight ≤ `total/n ≤ total/4 ≤ cap`, so the
    /// candidate set is never empty.
    fn heaviest_byzantine_within_cap(weights: &[u64]) -> Vec<usize> {
        let total: u128 = weights.iter().map(|w| u128::from(*w)).sum();
        let cap = total / 3;
        weights
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, w)| u128::from(*w) <= cap)
            .max_by_key(|(_, w)| *w)
            .map(|(idx, _)| vec![idx])
            .unwrap_or_default()
    }

    /// Map a `0..8` selector to a *QC-preserving* [`AdvKind`] — the
    /// catalog minus the two leader-faulty kinds (`Equivocator`,
    /// `ForgedHistoryCommitment`). Every kind here still produces a QC at
    /// its own leader views (it proposes honestly, or — like
    /// `TwinProposal` — broadcasts both forks so honest replicas converge
    /// on the first), so a multi-Byzantine subset never denies the
    /// three-chain window. Used by the weighted mixed-composition
    /// property.
    fn adv_kind_qc_preserving(i: usize) -> AdvKind {
        match i % 8 {
            0 => AdvKind::VoteWithholder,
            1 => AdvKind::StaleReplayer,
            2 => AdvKind::ForgedQc,
            3 => AdvKind::TimeoutSpammer,
            4 => AdvKind::ForgedPiggyback,
            5 => AdvKind::TwinVote,
            6 => AdvKind::TwinProposal,
            _ => AdvKind::TwinTimeoutVote,
        }
    }

    /// Shared body for the weighted-adversary properties. `select_byz`
    /// picks the stake-heavy Byzantine subset from the weight vector
    /// (multi-subset for QC-preserving adversaries, single-heaviest for
    /// the leader-faulty ones); `make_adv(slot)` installs a fresh
    /// adversary at each chosen index (stateful adversaries get their own
    /// counters; `slot` lets the mixed variant vary the kind per
    /// Byzantine). Spawns the weighted cluster and asserts:
    ///
    /// 1. Safety: `assert_no_conflicts` across every committed block.
    /// 2. Liveness: every honest survivor gains ≥ `WEIGHTED_FLOOR`
    ///    commits within `SIM_CAP` simulated.
    async fn run_weighted_adversary_property<S, F>(
        n: usize,
        weights: Vec<u64>,
        label: &str,
        select_byz: S,
        make_adv: F,
    ) -> Result<(), TestCaseError>
    where
        S: Fn(&[u64]) -> Vec<usize>,
        F: Fn(usize) -> Arc<dyn Adversary>,
    {
        let byz = select_byz(&weights);
        let mut adversaries: Vec<Option<Arc<dyn Adversary>>> = (0..n).map(|_| None).collect();
        for (slot, &idx) in byz.iter().enumerate() {
            adversaries[idx] = Some(make_adv(slot));
        }
        let mut cluster = SimCluster::spawn_with_weights_and_adversaries(
            n,
            Duration::from_millis(50),
            weights.clone(),
            adversaries,
        )
        .await;

        let honest: Vec<usize> = (0..n).filter(|i| !byz.contains(i)).collect();
        let baseline = cluster.peek_commit_heights();
        let honest_pred = honest.clone();
        let baseline_pred = baseline.clone();
        let satisfied = cluster
            .advance_and_yield_until(SIM_CAP, |c| {
                let h = c.peek_commit_heights();
                honest_pred
                    .iter()
                    .all(|&i| h[i] >= baseline_pred[i] + WEIGHTED_FLOOR)
            })
            .await;
        let final_heights = cluster.peek_commit_heights();

        let committed = cluster.drain_commits();
        assert_no_conflicts(&committed);

        prop_assert!(
            satisfied,
            "{label}: honest survivors did not all gain ≥ {WEIGHTED_FLOOR} commit within \
             {SIM_CAP:?} simulated (n={n}, weights={weights:?}, byzantine={byz:?}, \
             baseline={baseline:?}, final={final_heights:?})",
        );
        Ok(())
    }

    proptest! {
        // 4 cases per property: each spawns an n∈[4,7] weighted cluster
        // and runs to a 1-commit floor, so the per-property wall-clock
        // stays well under the 15s-per-test ceiling. `n ∈ [4, 7]`,
        // weights ∈ `[1, 1000]` matches the spec the weighted-quorum
        // proptests (#469) settled on.
        #![proptest_config(ProptestConfig {
            cases: 4,
            failure_persistence: None,
            ..Default::default()
        })]

        /// **Weighted equivocator** (single stake-heavy Byzantine — see
        /// [`heaviest_byzantine_within_cap`] for why this adversary uses
        /// the single-Byzantine selection). A ~⅓-weight equivocating
        /// leader splits its proposal across disjoint subsets; two
        /// disjoint honest subsets cannot each carry quorum weight (each
        /// would need `> 2/3` of total, and `2·(2/3) > 1`), so at most one
        /// fork commits — safety holds. With one Byzantine the remaining
        /// `n-1` validators give a consecutive honest-leader run, so
        /// honest-led views reach the weighted quorum and liveness holds.
        #[test]
        fn proptest_weighted_equivocator_preserves_safety_and_liveness(
            n in 4usize..=7,
            weights7 in proptest::collection::vec(1u64..=1000, 7),
        ) {
            run_paused(|| async move {
                let weights: Vec<u64> = weights7.into_iter().take(n).collect();
                run_weighted_adversary_property(
                    n,
                    weights,
                    "weighted equivocator",
                    heaviest_byzantine_within_cap,
                    |_| build_adversary(AdvKind::Equivocator),
                )
                .await
            })?;
        }

        /// **Weighted timeout spammer.** A stake-heavy spammer floods
        /// spurious TimeoutVotes; the honesty-threshold gate (#218/#419)
        /// is weight-aware, so the spam can't force a view advance, and
        /// the honest super-majority keeps committing.
        #[test]
        fn proptest_weighted_timeout_spammer_preserves_safety_and_liveness(
            n in 4usize..=7,
            weights7 in proptest::collection::vec(1u64..=1000, 7),
        ) {
            run_paused(|| async move {
                let weights: Vec<u64> = weights7.into_iter().take(n).collect();
                run_weighted_adversary_property(
                    n,
                    weights,
                    "weighted timeout-spammer",
                    weight_descending_byzantine_subset,
                    |_| build_adversary(AdvKind::TimeoutSpammer),
                )
                .await
            })?;
        }

        /// **Weighted forged-piggyback spammer.** A stake-heavy adversary
        /// attaches forged high-view `high_qc` piggybacks to its
        /// TimeoutVotes; piggyback verification (#321 / 10-F3) must reject
        /// them regardless of the signer's weight, so no forged QC enters
        /// `best_high_qc` and the cluster keeps committing safely.
        #[test]
        fn proptest_weighted_forged_piggyback_preserves_safety_and_liveness(
            n in 4usize..=7,
            weights7 in proptest::collection::vec(1u64..=1000, 7),
        ) {
            run_paused(|| async move {
                let weights: Vec<u64> = weights7.into_iter().take(n).collect();
                run_weighted_adversary_property(
                    n,
                    weights,
                    "weighted forged-piggyback",
                    weight_descending_byzantine_subset,
                    |_| build_adversary(AdvKind::ForgedPiggyback),
                )
                .await
            })?;
        }

        /// **Weighted twin proposal.** A stake-heavy leader broadcasts a
        /// genuine and a forged twin proposal at the same view to every
        /// peer; each honest replica votes for at most one
        /// (`last_voted_view` monotonic) so safety holds, and the
        /// proposal-equivocation evidence path is exercised under weight.
        #[test]
        fn proptest_weighted_twin_proposal_preserves_safety_and_liveness(
            n in 4usize..=7,
            weights7 in proptest::collection::vec(1u64..=1000, 7),
        ) {
            run_paused(|| async move {
                let weights: Vec<u64> = weights7.into_iter().take(n).collect();
                run_weighted_adversary_property(
                    n,
                    weights,
                    "weighted twin-proposal",
                    weight_descending_byzantine_subset,
                    |_| build_adversary(AdvKind::TwinProposal),
                )
                .await
            })?;
        }

        /// **Weighted twin timeout-vote.** A stake-heavy adversary emits a
        /// genuine and a forged twin TimeoutVote at the same view; the
        /// timeout bucket folds at most one signature per `(view, signer)`
        /// so the twin adds zero quorum weight under the weighted
        /// predicate — safety and liveness hold.
        #[test]
        fn proptest_weighted_twin_timeout_vote_preserves_safety_and_liveness(
            n in 4usize..=7,
            weights7 in proptest::collection::vec(1u64..=1000, 7),
        ) {
            run_paused(|| async move {
                let weights: Vec<u64> = weights7.into_iter().take(n).collect();
                run_weighted_adversary_property(
                    n,
                    weights,
                    "weighted twin-timeout-vote",
                    weight_descending_byzantine_subset,
                    |_| build_adversary(AdvKind::TwinTimeoutVote),
                )
                .await
            })?;
        }

        /// **Weighted stale replayer.** A stake-heavy adversary replays
        /// past signed envelopes on a schedule; stale frames are rejected
        /// at ingress by view/round checks independent of signer weight,
        /// so the honest super-majority keeps committing safely.
        #[test]
        fn proptest_weighted_stale_replayer_preserves_safety_and_liveness(
            n in 4usize..=7,
            weights7 in proptest::collection::vec(1u64..=1000, 7),
        ) {
            run_paused(|| async move {
                let weights: Vec<u64> = weights7.into_iter().take(n).collect();
                run_weighted_adversary_property(
                    n,
                    weights,
                    "weighted stale-replayer",
                    weight_descending_byzantine_subset,
                    |_| build_adversary(AdvKind::StaleReplayer),
                )
                .await
            })?;
        }

        /// **Weighted forged-history-commitment leader** (single
        /// stake-heavy Byzantine — its rejected proposals produce no QC at
        /// its leader views, so it uses the single-Byzantine selection for
        /// the same reason as the equivocator; see
        /// [`heaviest_byzantine_within_cap`]). A ~⅓-weight leader mutates
        /// `block.header.validator_history_commitment`; honest replicas
        /// reject the structurally-invalid block on the receive-side check
        /// regardless of proposer weight, so no fork commits and liveness
        /// recovers on the next honest leader.
        #[test]
        fn proptest_weighted_forged_history_commitment_preserves_safety_and_liveness(
            n in 4usize..=7,
            weights7 in proptest::collection::vec(1u64..=1000, 7),
        ) {
            run_paused(|| async move {
                let weights: Vec<u64> = weights7.into_iter().take(n).collect();
                run_weighted_adversary_property(
                    n,
                    weights,
                    "weighted forged-history-commitment",
                    heaviest_byzantine_within_cap,
                    |_| build_adversary(AdvKind::ForgedHistoryCommitment),
                )
                .await
            })?;
        }

        /// **Weighted mixed composition.** Each Byzantine slot in the
        /// stake-heavy (multi-validator) subset independently runs a
        /// *different* QC-preserving adversary (round-robin from a
        /// proptest-chosen offset via [`adv_kind_qc_preserving`]) — the
        /// `proptest_mixed_adversary` shape paired with a weight-bounded
        /// Byzantine subset. The two leader-faulty kinds are excluded here
        /// (they'd break the three-chain window under a multi-Byzantine
        /// round-robin subset) and are covered by their own
        /// single-Byzantine weighted properties above. Safety and the
        /// honest commit floor must hold across every sampled composition.
        #[test]
        fn proptest_weighted_mixed_adversary_preserves_safety_and_liveness(
            n in 4usize..=7,
            weights7 in proptest::collection::vec(1u64..=1000, 7),
            k0 in 0usize..10,
        ) {
            run_paused(|| async move {
                let weights: Vec<u64> = weights7.into_iter().take(n).collect();
                run_weighted_adversary_property(
                    n,
                    weights,
                    "weighted mixed",
                    weight_descending_byzantine_subset,
                    move |slot| build_adversary(adv_kind_qc_preserving(k0 + slot)),
                )
                .await
            })?;
        }
    }
}
