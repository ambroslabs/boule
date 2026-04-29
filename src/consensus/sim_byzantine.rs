//! Protocol-level Byzantine adversaries for the consensus simulator (#132).
//!
//! Companion to [`crate::sim::sim_adversary`], which covers
//! network-layer byte-mutation hooks (`FlipFirstByte`, `ZeroPayload`).
//! This module sits at the [`crate::consensus::hotstuff::HotStuffCore`]
//! action boundary — adversaries intercept the stream of
//! [`crate::p2p::ProtocolOutbound`] frames their node would emit, decode
//! each as a [`WireMessage`], and craft *valid signed envelopes* that
//! misbehave at the protocol level: equivocation, vote withholding,
//! stale replays, forged QCs, timeout-vote spam.
//!
//! The point is to verify that honest replicas reject malicious
//! *content* (and at minimum do not crash); cryptographic forgery is
//! out of scope and covered by [`crate::consensus::wire_fuzz`] / #198.
//!
//! # Why intercept on the outbound side
//!
//! Mutating a `ConsensusNode`'s internal state to make it deviate would
//! force the adversary to know the node's private state machine. The
//! cleaner seam is the network edge: every outbound frame the honest
//! core emits passes through the per-node routing task in
//! [`crate::consensus::sim::SimCluster`]'s spawn path, and the
//! [`Adversary`] hook taps into that exact stream. Adversaries get the
//! node's own [`crate::crypto::signed::Signer`] so any envelope they
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

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use parking_lot::Mutex;
use proptest::prelude::*;

use super::sim::{Adversary, AdversaryCtx, SimCluster, assert_no_conflicts};
use crate::consensus::hotstuff::qc::{QuorumCertificate, TimeoutVote};
use crate::consensus::hotstuff::{NewView, Proposal};
use crate::consensus::node::WireMessage;
use crate::crypto::signed::{ChainId, Signed};
use crate::p2p::{NodeId, ProtocolOutbound};
use crate::replication::block::Block;

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
/// Rejection path: [`crate::consensus::hotstuff::safety_rules::should_update_high_qc`]
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
            view: u64::from(*counter),
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
/// logic in [`crate::consensus::node::ConsensusNode::on_timeout_vote`]
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
        let quorum = crate::consensus::hotstuff::qc::quorum_size(validators_len);
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
            view: u64::from(*counter),
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

// ── Tests / proptest properties ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Run an async sim scenario on a fresh `current_thread` Tokio
    /// runtime with virtual time paused. Mirrors the `run_paused`
    /// helper in [`crate::consensus::sim`]'s L-series proptests.
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

        /// **Mixed adversary** — randomly pick one of the seven
        /// adversary kinds for the single Byzantine slot. Verifies
        /// that property-1..7's invariants hold across the union of
        /// adversaries (no implicit interaction breaks safety or
        /// liveness when the adversary is selected uniformly).
        #[test]
        fn proptest_mixed_adversary_preserves_safety_and_liveness(
            victim in 0usize..4,
            kind_selector in 0usize..7,
        ) {
            run_paused(|| async move {
                let kind = match kind_selector {
                    0 => AdvKind::Equivocator,
                    1 => AdvKind::VoteWithholder,
                    2 => AdvKind::StaleReplayer,
                    3 => AdvKind::ForgedQc,
                    4 => AdvKind::TimeoutSpammer,
                    5 => AdvKind::ForgedPiggyback,
                    _ => AdvKind::ForgedHistoryCommitment,
                };
                run_one_property(victim, kind).await
            })?;
        }
    }
}
