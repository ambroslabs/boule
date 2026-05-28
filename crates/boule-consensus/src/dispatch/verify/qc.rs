//! QC aggregate verification (#318–#322).
//!
//! Two entry points:
//!
//! - [`verify_qc_if_requested`]: hard-fail QC aggregate check used
//!   for the `Proposal.justify` and `NewView.high_qc` arms.
//! - [`verify_high_qc_piggyback`]: soft-verify counterpart for the
//!   `TimeoutVote.high_qc` piggyback (audit finding 10-F3, issue
//!   #321) — surfaces a `bool` rather than rejecting the envelope so
//!   a Byzantine voter can't suppress an honest timeout signal by
//!   attaching garbage.

use crate::View;
use crate::hotstuff::qc::QuorumCertificate;
use crate::validator_history::ValidatorSetHistory;
use crate::validator_key_history::ValidatorKeyHistory;
use boule::crypto::sig_scheme::SignatureSchemeChoice;
use boule::crypto::signed::ChainId;
use boule::identity::NodeId;

use super::super::{IngressError, QcVerification};
use super::domain::vote_preimage;

/// Verify a QC's aggregate signature per the requested
/// [`QcVerification`] policy. Genesis-shaped QCs (no signers) are
/// accepted unconditionally — the genesis QC is by construction
/// signature-free, and rejecting it here would refuse to bootstrap.
///
/// On `Skip`, returns `Ok(())` without inspecting the QC. On `Verify`,
/// the QC's scheme must match `scheme`; the per-historical-view
/// validator pubkeys are resolved at `qc.view` via `key_history`
/// (Ed25519) or `bls_key_history` (BLS); the corresponding
/// `verify_aggregate` / `verify_aggregate_bls` is called against the
/// canonical Vote pre-image `(qc.view, qc.block_hash)`.
pub(in crate::dispatch) fn verify_qc_if_requested(
    qc: &QuorumCertificate,
    history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
    qc_verification: &QcVerification<'_>,
    chain_id: &ChainId,
) -> Result<(), IngressError> {
    let (scheme, bls_key_history, genesis_hash) = match qc_verification {
        #[cfg(test)]
        QcVerification::Skip => return Ok(()),
        QcVerification::Verify {
            scheme,
            bls_key_history,
            min_v_eff_delay: _,
            genesis_hash,
        } => (scheme, bls_key_history, genesis_hash),
    };

    // Audit finding 7-4 (issue #418): a view-0 QC is the genesis
    // convention — every honest replica builds the same QC over the
    // genesis block hash. Reject view-0 QCs over any other block hash
    // here at ingress, before the unconditional skip below would
    // otherwise let a forged "genesis QC" past. The safety core's
    // parent walk catches this downstream too, but defense-in-depth
    // says reject the malformed envelope at the boundary rather than
    // relying on the safety core.
    if qc.view == View::ZERO && qc.block_hash != *genesis_hash {
        return Err(IngressError::InvalidQcAggregate {
            view: View::ZERO,
            scheme: scheme.name(),
        });
    }

    // Genesis QCs are a convention, not a cryptographic commitment:
    // every honest replica builds the same QC at view 0 over the
    // genesis block hash with all-zero placeholder signatures (see
    // `crate::hotstuff::qc::genesis_qc`). Aggregate
    // verification cannot succeed against placeholder sigs, and the
    // block_hash check above pins the QC to the real genesis, so
    // skipping at view 0 is safe.
    //
    // QCs with no signers at any other view also have nothing to
    // verify cryptographically — accept them and let the safety core
    // decide whether to act on a no-quorum QC.
    if qc.view == View::ZERO || qc.signer_count() == 0 {
        return Ok(());
    }

    let vs_at = history.set_at(qc.view);
    let vs = vs_at.for_view(qc.view);
    // Each partial in the QC is the Ed25519 / BLS signature on the
    // domain-separated Signed<Vote> envelope preimage — the same bytes
    // the voter signed in `Signed::sign(vote, signer)`. Reconstruct
    // that preimage here so verify_aggregate sees what the signer saw.
    let preimage_bytes = vote_preimage(qc.view, qc.block_hash, chain_id).map_err(|_| {
        IngressError::InvalidQcAggregate {
            view: qc.view,
            scheme: scheme.name(),
        }
    })?;

    match scheme {
        SignatureSchemeChoice::Ed25519Collected => {
            if !qc.is_ed25519() {
                return Err(IngressError::InvalidQcAggregate {
                    view: qc.view,
                    scheme: scheme.name(),
                });
            }
            // The verifier needs one Ed25519 pubkey per validator slot
            // at qc.view — the same pubkey under which a vote at that
            // view would have been signed. Resolve through the
            // per-historical-view key history so post-rotation lookups
            // pick up the right key.
            //
            // The `unwrap_or` falls back to the stable id's bytes when
            // a validator has no recorded key at the QC's view — this
            // is the same convention as before #328 (the stable id is
            // the validator's genesis pubkey, so using its bytes as a
            // pubkey here matches the pre-rotation case). The
            // verifier itself works at the `NodeId` byte layer.
            let pubkeys: Vec<NodeId> = vs
                .iter()
                .map(|stable_id| {
                    key_history
                        .key_at(stable_id, qc.view)
                        .map(NodeId::from)
                        .unwrap_or_else(|| stable_id.into_node_id())
                })
                .collect();
            qc.verify_aggregate(&preimage_bytes, &pubkeys)
                .map_err(|_| IngressError::InvalidQcAggregate {
                    view: qc.view,
                    scheme: scheme.name(),
                })?;
        }
        SignatureSchemeChoice::BlsAggregated => {
            if !qc.is_bls() {
                return Err(IngressError::InvalidQcAggregate {
                    view: qc.view,
                    scheme: scheme.name(),
                });
            }
            let bls_history = bls_key_history.ok_or(IngressError::InvalidQcAggregate {
                view: qc.view,
                scheme: scheme.name(),
            })?;
            let pubkeys = bls_history.pubkeys_for_set(vs, qc.view).map_err(|_| {
                IngressError::InvalidQcAggregate {
                    view: qc.view,
                    scheme: scheme.name(),
                }
            })?;
            qc.verify_aggregate_bls(&preimage_bytes, &pubkeys)
                .map_err(|_| IngressError::InvalidQcAggregate {
                    view: qc.view,
                    scheme: scheme.name(),
                })?;
        }
    }
    Ok(())
}

/// Soft-verify the `high_qc` piggyback on a [`TimeoutVote`](crate::hotstuff::qc::TimeoutVote).
///
/// Returns `true` if the piggyback is either absent, accompanied by a
/// `QcVerification::Skip` policy (legacy / test fixture path —
/// `cfg(test)`-only), or passes both well-formedness and aggregate-signature verification
/// against the validator set authoritative at `qc.view`. Returns
/// `false` if the piggyback is structurally malformed or fails
/// aggregate verification — the caller must then drop the piggyback
/// (treat it as if the timeout vote carried `high_qc: None`) but
/// **not** the envelope itself.
///
/// Why soft: an attacker who broadcasts `TimeoutVote { view, high_qc:
/// Some(forged) }` over their genuine timeout signal must not be able
/// to suppress that signal by attaching garbage. The envelope is
/// already authenticated by [`super::envelope::verify_signer_at`] and
/// [`super::envelope::verify_sig`]; the piggyback is the additional,
/// separable, cryptographically scoped object — and it's the *only*
/// part the bucket logic in `on_timeout_vote` propagates into
/// safety-core state. Refusing the bad piggyback while accepting the
/// timeout-quorum signal keeps `state.high_qc` honest without giving
/// a Byzantine voter a DoS vector against the round-advance machinery.
pub(in crate::dispatch) fn verify_high_qc_piggyback(
    high_qc: Option<&QuorumCertificate>,
    history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
    qc_verification: &QcVerification<'_>,
    chain_id: &ChainId,
) -> bool {
    let Some(qc) = high_qc else {
        return true;
    };
    #[cfg(test)]
    if matches!(qc_verification, QcVerification::Skip) {
        return true;
    }
    // The piggyback's bitmap is sized for the validator set authoritative
    // at `qc.view` (the same set that voted to mint the QC). Reject
    // bitmap-shape divergence before paying for an aggregate verify.
    let vs_at = history.set_at(qc.view);
    if !qc.is_well_formed(vs_at.for_view(qc.view)) {
        return false;
    }
    verify_qc_if_requested(qc, history, key_history, qc_verification, chain_id).is_ok()
}
