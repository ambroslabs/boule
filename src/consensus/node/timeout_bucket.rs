//! Timeout-vote accumulator and the integration-layer paths that
//! produce, broadcast, and consume timeout votes.
//!
//! When a replica's view timer fires, [`super::ConsensusNode::send_timeout`]
//! mints (or replays) a [`TimeoutVote`] envelope, persists it under
//! [`super::STORAGE_KEY_LAST_TIMEOUT_VOTE`] for crash-safety, broadcasts
//! it, and self-feeds it. Inbound timeout votes flow through
//! [`super::ConsensusNode::on_timeout_vote`], which accumulates per-view
//! distinct signers in [`TimeoutBucket`] and fires
//! [`crate::consensus::pacemaker::Event::OnTimeoutCert`] once quorum is
//! reached.

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Context;
use bytes::Bytes;

use crate::consensus::View;
use crate::consensus::crashpoint::crashpoint;
use crate::consensus::dispatch::{self, Outbound};
use crate::consensus::hotstuff::NewView;
use crate::consensus::hotstuff::QuorumCertificate;
use crate::consensus::hotstuff::qc::{
    TimeoutVote, honesty_weight_threshold, quorum_weight_threshold,
};
use crate::consensus::hotstuff::step::Event as SafetyEvent;
use crate::consensus::pacemaker::Event as PacemakerEvent;
use crate::consensus::pacemaker::HonestyThresholdEvidence as PacemakerHonestyThresholdEvidence;
use crate::consensus::view_timer::ViewTimer;
use crate::crypto::signed::{Signed, Signer};
use crate::p2p::NodeId;
use crate::p2p::overlay::Broadcaster;
use crate::p2p::tls::node_id_to_base58;

use super::wire::WireMessage;
use super::{
    ConsensusNode, STORAGE_KEY_LAST_TIMEOUT_VOTE, TRACE_TARGET, decode_last_timeout_vote,
    encode_last_timeout_vote, send_outbound,
};

/// Accumulator for one view's timeout votes.
///
/// Tracks the set of distinct signers that have timed out at a view,
/// the running sum of those signers' voting weights (#461), and the
/// freshest `high_qc` any of them reported. When `signer_weight`
/// crosses the weighted-quorum threshold we fire
/// [`pacemaker::Event::OnTimeoutCert`] — and we drop the bucket so
/// further duplicate timeout votes for the same view don't re-enter
/// the pacemaker.
#[derive(Default)]
pub(super) struct TimeoutBucket {
    pub(super) signers: HashSet<NodeId>,
    /// Sum of voting weights for the signers in [`Self::signers`],
    /// looked up against the validator set authoritative at this
    /// bucket's view (#461). Tracked alongside `signers` so the
    /// quorum check is O(1) per insert rather than O(|signers|).
    pub(super) signer_weight: u128,
    pub(super) best_high_qc: Option<QuorumCertificate>,
}

impl ConsensusNode {
    /// Build a fresh [`TimeoutVote`] payload for `view` from the
    /// current `state.high_qc` and durably stamp it under
    /// [`STORAGE_KEY_LAST_TIMEOUT_VOTE`] before returning. The
    /// `crashpoint!("after_persist_timeout_vote")` between the put and
    /// the return lets a regression test pin the gap between
    /// "envelope is on disk" and "envelope is on the wire" — a crash
    /// in this gap leaves the durable record that [`Self::send_timeout`]
    /// replays after restart (audit finding 14-1, issue #415).
    fn persist_fresh_timeout_vote(&self, view: View) -> anyhow::Result<TimeoutVote> {
        let high_qc = self
            .core
            .state()
            .high_qc
            .as_ref()
            .map(|qc| qc.inner().clone());
        let payload = TimeoutVote { view, high_qc };
        let bytes = encode_last_timeout_vote(&payload)?;
        self.storage
            .put(STORAGE_KEY_LAST_TIMEOUT_VOTE, &bytes)
            .context("persist last_timeout_vote")?;
        crashpoint!("after_persist_timeout_vote");
        Ok(payload)
    }

    /// Build, broadcast, and self-deliver a [`TimeoutVote`] for `view`.
    ///
    /// Self-delivery matters because production p2p broadcasts do not
    /// loop back to the sender — without an explicit self-feed the
    /// local bucket would be one short of quorum, and a leader-crash
    /// scenario with exactly `quorum_size` live replicas would stall.
    ///
    /// # Persistence (audit finding 14-1, issue #415)
    ///
    /// The TimeoutVote envelope this replica commits to for `view` is
    /// persisted under [`STORAGE_KEY_LAST_TIMEOUT_VOTE`] *before* any
    /// byte hits the wire. On any subsequent attempt to time out at
    /// the same `view` — whether a timer re-fire in the same process
    /// (the policy's exponential backoff fires `OnTimeout(view)` again
    /// when the cluster has not yet formed a TC) or a `send_timeout`
    /// after a crash-and-restart — the persisted payload is replayed
    /// bit-identically. Without this, the second attempt would build
    /// from `state.high_qc`, which may have advanced between the
    /// original send and this attempt; a peer holding both signed
    /// envelopes could then present a contradiction (two distinct
    /// `high_qc` snapshots endorsed by the same signer at the same
    /// view).
    pub(super) async fn send_timeout(
        &mut self,
        view: View,
        broadcaster: &dyn Broadcaster,
        view_timer: &mut ViewTimer,
        signer: &Arc<dyn Signer>,
    ) -> anyhow::Result<()> {
        // Reuse a previously persisted envelope for this view if one
        // exists — that is the canonical payload this replica has
        // already committed to. Fresh views fall through to the build
        // path below and persist their envelope before broadcast.
        let payload = match self
            .storage
            .get(STORAGE_KEY_LAST_TIMEOUT_VOTE)
            .context("read last_timeout_vote from storage")?
        {
            Some(raw) => {
                let prev = decode_last_timeout_vote(&raw)?;
                if prev.view == view {
                    prev
                } else {
                    self.persist_fresh_timeout_vote(view)?
                }
            }
            None => self.persist_fresh_timeout_vote(view)?,
        };
        let signed = Signed::sign(payload, signer.as_ref(), &self.chain_id)
            .context("signing TimeoutVote")?;

        // Put the signed frame on the wire.
        let wire = WireMessage::TimeoutVote(signed.clone());
        let bytes = postcard::to_stdvec(&wire)
            .map(Bytes::from)
            .context("encoding TimeoutVote")?;
        send_outbound(broadcaster, Outbound::Broadcast(bytes)).await;
        // The envelope under STORAGE_KEY_LAST_TIMEOUT_VOTE is durable
        // before this send returns (see persist_fresh_timeout_vote);
        // a crash here therefore replays the same payload on restart
        // rather than minting a fresh one with a possibly-different
        // `high_qc` snapshot — closing audit finding 14-1 (#415).
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
    pub(super) async fn on_timeout_vote(
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
                let nv = NewView {
                    high_qc: high_qc.into_inner(),
                };
                let signed_nv = Signed::sign(nv, signer.as_ref(), &self.chain_id)
                    .context("signing catch-up NewView for stale TimeoutVote")?;
                let wire = WireMessage::NewView(signed_nv);
                let payload = postcard::to_stdvec(&wire)
                    .map(Bytes::from)
                    .context("encoding catch-up NewView for stale TimeoutVote")?;
                tracing::debug!(
                    target: TRACE_TARGET,
                    wedged_peer = %node_id_to_base58(&signed.signer),
                    wedged_view = view.0,
                    our_view = self.pacemaker.current_view().0,
                    our_high_qc_view = ?self.core.state().high_qc.as_ref().map(|q| q.view().0),
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

        let quorum_weight = quorum_weight_threshold(&self.validator_set);
        let signer_id = signed.signer;
        let is_local = signer_id == self.self_id;
        // Look up the signer's voting weight against the *current* set
        // (membership was already confirmed above). The weight is the
        // signer's contribution to this bucket's running tally; with
        // every weight defaulted to 1 (#460) the running tally and the
        // distinct-signer count are numerically identical, and the
        // weight-based quorum reduces exactly to the count-based
        // pre-#461 form.
        let signer_weight = u128::from(self.validator_set.weight_for(&stable_id).unwrap_or(0));
        // Cap-based eviction. A genuinely new view triggers the
        // check; an entry update (same view, different signer) does
        // not grow the map, so we skip the check on the existing-key
        // path. Without this guard a Byzantine peer could fan out
        // timeout votes across distinct future views (each with no
        // hope of forming a TC) and pin memory until restart.
        if !self.timeout_buckets.contains_key(&view) {
            self.evict_timeout_buckets_to_fit_one();
        }
        let honesty_threshold = honesty_weight_threshold(&self.validator_set);
        let (adopt_qc, fired_round_sync) = {
            let bucket = self.timeout_buckets.entry(view).or_default();
            let is_new = bucket.signers.insert(signed.signer);
            if !is_new {
                return Ok(());
            }
            // Maintain the running weight sum in lockstep with the
            // signer set; `is_new` above guarantees we don't double-
            // count.
            let prev_weight = bucket.signer_weight;
            bucket.signer_weight = bucket.signer_weight.saturating_add(signer_weight);

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

            let bucket_signers = bucket.signers.len();
            let bucket_weight = bucket.signer_weight;
            tracing::debug!(
                target: TRACE_TARGET,
                view = view.0,
                signer = %node_id_to_base58(&signer_id),
                bucket_signers,
                bucket_weight = bucket_weight as u64, // tracing prefers u64
                quorum_weight = quorum_weight as u64,
                is_local,
                "timeout_vote",
            );

            // Round-sync hint (issue #218): the bucket has accumulated
            // enough signer-weight to guarantee at least one honest
            // peer reports being at view `view`. We can advance our
            // pacemaker to `view` even before quorum gives us a TC.
            // Crucially, a Byzantine subset whose total weight is at
            // most `floor(total_weight/3)` can't fire this — it needs
            // strictly more — which is what keeps the
            // `TimeoutSpammer` adversary from dragging honest views to
            // `u64::MAX`.
            //
            // Fire on the exact crossing so we don't re-emit on every
            // subsequent vote into the same bucket. The evidence token
            // is minted inline with the threshold check; constructing
            // `OnRoundSync` outside this gate is a compile error
            // (audit finding 2-3 / issue #419).
            let crossed_honesty =
                prev_weight < honesty_threshold && bucket_weight >= honesty_threshold;
            let round_sync_evidence = if crossed_honesty {
                PacemakerHonestyThresholdEvidence::from_bucket_weight(
                    bucket_weight,
                    honesty_threshold,
                )
            } else {
                None
            };

            if bucket_weight < quorum_weight {
                return if let Some(evidence) = round_sync_evidence {
                    self.fire_round_sync(view, evidence, broadcaster, view_timer, signer)
                        .await
                } else {
                    Ok(())
                };
            }
            (bucket.best_high_qc.clone(), round_sync_evidence)
        };

        // We've also crossed full quorum — but if we passed the
        // honesty threshold on this same vote, surface the round-sync
        // hint first so the pacemaker has the latest view recorded
        // before the OnTimeoutCert flow runs.
        if let Some(evidence) = fired_round_sync {
            self.fire_round_sync(view, evidence, broadcaster, view_timer, signer)
                .await?;
        }

        tracing::debug!(
            target: TRACE_TARGET,
            view = view.0,
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
                dispatch::Verified::wrap_after_verify_with_signer(self_signed, signer_validator_id),
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

    /// Drop the lowest-`view` `timeout_buckets` entry if the map is
    /// at cap. The on-TC-formation prune
    /// (`timeout_buckets.retain(|&v, _| v > view)`) handles the
    /// happy-path cleanup; this helper handles the flood path where
    /// no TC ever fires because the attacker addresses each fake
    /// timeout vote at a distinct future view.
    pub(super) fn evict_timeout_buckets_to_fit_one(&mut self) {
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
                evicted_view = victim_view.0,
                cap = self.timeout_buckets_capacity,
                size_after = self.timeout_buckets.len(),
                "consensus_cache_evicted",
            );
        }
    }
}
