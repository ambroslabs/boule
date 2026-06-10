use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Context;
use bytes::Bytes;

use boule_consensus::View;
use boule_consensus::dispatch::{self, Outbound};
use boule_consensus::hotstuff::NewView;
use boule_consensus::hotstuff::QuorumCertificate;
use boule_consensus::hotstuff::qc::{
    TimeoutVote, honesty_weight_threshold, quorum_weight_threshold,
};
use boule_consensus::hotstuff::step::Event as SafetyEvent;
use boule_consensus::pacemaker::Event as PacemakerEvent;
use boule_consensus::pacemaker::HonestyThresholdEvidence as PacemakerHonestyThresholdEvidence;
use boule_consensus::view_timer::ViewTimer;
use boule_core::crypto::signed::{Signed, Signer};
use boule_core::identity::NodeId;
use boule_core::identity::node_id_to_base58;
use boule_core::transport::overlay::Broadcaster;

use super::{
    ConsensusNode, STORAGE_KEY_LAST_TIMEOUT_VOTE, TRACE_TARGET, decode_last_timeout_vote,
    encode_last_timeout_vote, send_outbound,
};
use boule_consensus::wire::WireMessage;

#[derive(Default)]
pub(super) struct TimeoutBucket {
    pub(super) signers: HashSet<NodeId>,

    pub(super) signer_weight: u128,
    pub(super) best_high_qc: Option<QuorumCertificate>,
}

impl ConsensusNode {
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
        Ok(payload)
    }

    pub(super) async fn send_timeout(
        &mut self,
        view: View,
        broadcaster: &dyn Broadcaster,
        view_timer: &mut ViewTimer,
        signer: &Arc<dyn Signer>,
    ) -> anyhow::Result<()> {
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

        let wire = WireMessage::TimeoutVote(signed.clone());
        let bytes = postcard::to_stdvec(&wire)
            .map(Bytes::from)
            .context("encoding TimeoutVote")?;
        send_outbound(
            broadcaster,
            self.rate_limiter.as_deref(),
            &self.peers_connected,
            Outbound::Broadcast(bytes),
        )
        .await;

        self.on_timeout_vote(signed, true, broadcaster, view_timer, signer)
            .await
    }

    pub(super) async fn on_timeout_vote(
        &mut self,
        signed: Signed<TimeoutVote>,
        high_qc_trusted: bool,
        broadcaster: &dyn Broadcaster,
        view_timer: &mut ViewTimer,
        signer: &Arc<dyn Signer>,
    ) -> anyhow::Result<()> {
        let view = signed.payload.view;

        let signer_pk = boule_consensus::validator_set::Pubkey::from_node_id(signed.signer);
        let Some(stable_id) = self.validator_key_history.validator_for(&signer_pk) else {
            return Ok(());
        };
        if !self.validator_set.contains(&stable_id) {
            return Ok(());
        }

        if view < self.pacemaker.current_view() {
            if self.role.is_full() {
                return Ok(());
            }
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
                    self.rate_limiter.as_deref(),
                    &self.peers_connected,
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

        let signer_weight = u128::from(self.validator_set.weight_for(&stable_id).unwrap_or(0));

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

            let prev_weight = bucket.signer_weight;
            bucket.signer_weight = bucket.signer_weight.saturating_add(signer_weight);

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
                bucket_weight = bucket_weight as u64,
                quorum_weight = quorum_weight as u64,
                is_local,
                "timeout_vote",
            );

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

        self.timeout_buckets.remove(&view);

        self.timeout_buckets.retain(|&v, _| v > view);

        if let Some(qc) = adopt_qc {
            let nv = NewView { high_qc: qc };
            let self_signed = Signed::sign(nv, signer.as_ref(), &self.chain_id)
                .context("signing self-NewView for TC adopt")?;

            let signer_node_id = signer.as_ref().node_id();
            let signer_pk = boule_consensus::validator_set::Pubkey::from_node_id(signer_node_id);
            let signer_validator_id = self
                .validator_key_history
                .validator_for(&signer_pk)
                .unwrap_or_else(|| {
                    boule_consensus::validator_set::ValidatorId::from_genesis_pubkey(signer_node_id)
                });
            let safety_actions = self.step_safety(SafetyEvent::NewViewReceived(
                dispatch::Verified::wrap_after_verify_with_signer(self_signed, signer_validator_id),
            ));
            self.apply_safety_actions(safety_actions, broadcaster, view_timer, signer)
                .await?;
        }

        let pm_actions = self.step_pacemaker(PacemakerEvent::OnTimeoutCert(view));

        Box::pin(self.apply_pacemaker_actions(pm_actions, broadcaster, view_timer, signer)).await
    }

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
