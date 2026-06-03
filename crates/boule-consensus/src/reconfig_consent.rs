//! Inbound-consent authentication for validator-set reconfiguration adds
//! (issue #548, first slice).
//!
//! Today a [`ReconfigCommand`](crate::reconfig::ReconfigCommand) is
//! completely unauthenticated: anyone with mempool access to a
//! leader-eligible node can inject a command that adds, removes, or
//! reweights any validator, subject only to structural floors. #548 is the
//! umbrella for closing that hole with a full two-sided approval flow
//! (inbound consent *and* ≥quorum existing-committee approval). The
//! existing-committee half needs tx-gossip to accumulate signatures across
//! validators and is out of scope until that primitive exists.
//!
//! This module is the **inbound-consent half** — buildable today on the
//! operator-key infrastructure from #549. It lets the validator being
//! admitted cryptographically attest, with its **operator key**, that it
//! consents to being seated on the exact terms in the add entry
//! (`node_id`, `addr`, `weight`, `v_eff`, `operator_pubkey`, and the BLS
//! identity). A Byzantine leader can still *choose* which signed adds to
//! include, but it can no longer conscript an honest operator's identity
//! into the set, nor alter the terms they agreed to: any tampering
//! invalidates the signature.
//!
//! # What this slice does NOT do
//!
//! - It does not close the "Byzantine leader unilaterally admits a friend
//!   *it* controls both keys for" hole — that needs existing-committee
//!   quorum approval (the gossip-dependent half of #548).
//! - It is a pure verifier + builder here. Wiring it into the commit-time
//!   apply path (so an add with an `operator_pubkey` but no valid consent
//!   is rejected) is the integration follow-up, mirroring the #656 split
//!   (pure verifier first, then enforcement).
//!
//! # Why the operator key (not the consensus key)
//!
//! The consensus signing key is the hot key used for votes/proposals; the
//! operator key is the cold-storage administrative key (#549). Consent to
//! *join* is an administrative act, so the operator key is the right
//! authority — the same key that can later recover or rotate the signing
//! key. An add with no `operator_pubkey` carries no recovery path and
//! likewise cannot be consent-authenticated; such adds are the
//! staking-driven / testnet case the umbrella issue leaves to the
//! committee-approval half.

use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::View;
use crate::reconfig::ValidatorEntry;
use boule_core::crypto::sig_scheme::BlsPop;
use boule_core::crypto::signed::{ChainId, SignedMessage, Signer, preimage};
use boule_core::identity::NodeId;

/// The canonical payload an inbound validator's operator key signs to
/// consent to being seated by a reconfig add.
///
/// Every field a leader could otherwise tamper with is bound into the
/// pre-image, so a valid signature attests to the *exact* terms of the
/// add. `operator_pubkey` is both bound here (it can't be swapped for a
/// key the leader controls) and serves as the verification key — the
/// consent is self-attesting: "the holder of `operator_pubkey` agrees to
/// seat `node_id` at `addr` with `weight`, effective at `v_eff`."
///
/// The fields mirror [`ValidatorEntry`] plus the command's `v_eff`;
/// [`Self::for_entry`] is the canonical constructor so the signed terms and
/// the committed entry cannot drift apart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconfigAddConsent {
    /// The consensus identity being seated (the add entry's `node_id`).
    pub node_id: NodeId,
    /// The routable address the validator is advertising.
    pub addr: SocketAddr,
    /// BLS proof-of-possession bundle, bound so the consent ties to the
    /// exact BLS identity on BLS chains; `None` on Ed25519 chains. Mirrors
    /// [`ValidatorEntry::bls_pop`].
    pub bls_pop: Option<BlsPop>,
    /// Voting weight the operator consents to being seated at.
    pub weight: u64,
    /// The operator key giving consent. Bound into the pre-image *and* used
    /// as the verification key for the signature.
    pub operator_pubkey: NodeId,
    /// The effective view the add takes hold at (the command's `v_eff`).
    pub v_eff: View,
}

impl SignedMessage for ReconfigAddConsent {
    const DOMAIN: &'static str = "boule.consensus.reconfig_add_consent.v1";
}

impl ReconfigAddConsent {
    /// Build the consent payload for an add entry at the command's `v_eff`.
    ///
    /// Returns `None` when the entry carries no `operator_pubkey`: consent
    /// is an operator-key act, and an add with no operator key has no
    /// authority to attest with (it falls to the committee-approval half of
    /// #548 instead). This is the canonical constructor — the commit-time
    /// verifier (integration follow-up) builds the pre-image the same way,
    /// so the terms signed and the terms applied are byte-identical.
    pub fn for_entry(entry: &ValidatorEntry, v_eff: View) -> Option<Self> {
        let operator_pubkey = entry.operator_pubkey?;
        Some(Self {
            node_id: entry.node_id,
            addr: entry.addr,
            bls_pop: entry.bls_pop.clone(),
            weight: entry.weight,
            operator_pubkey,
            v_eff,
        })
    }

    /// Sign this consent with the inbound validator's operator key,
    /// producing the signature that rides alongside the add entry. The
    /// `operator_signer` MUST hold the key named by `self.operator_pubkey`;
    /// signing under any other key produces a signature [`Self::verify`]
    /// rejects. `chain_id` (#324) scopes the consent to the deployment so it
    /// cannot be replayed against another chain.
    pub fn sign(
        &self,
        operator_signer: &dyn Signer,
        chain_id: &ChainId,
    ) -> anyhow::Result<[u8; 64]> {
        let bytes = preimage::<ReconfigAddConsent>(self, chain_id)?;
        Ok(operator_signer.sign(&bytes))
    }

    /// Verify `sig` is a valid operator-key consent over these exact terms.
    ///
    /// The verification key is `self.operator_pubkey` (bound into the
    /// pre-image), so this proves the holder of that operator key consented
    /// to seating `node_id` at `addr`/`weight`/`v_eff` with this BLS
    /// identity. Any tamper with the terms, the operator key, or the
    /// `chain_id` makes the signature fail.
    pub fn verify(&self, sig: &[u8; 64], chain_id: &ChainId) -> Result<(), ConsentVerifyError> {
        let bytes = preimage::<ReconfigAddConsent>(self, chain_id)
            .map_err(|e| ConsentVerifyError::Preimage(e.to_string()))?;
        UnparsedPublicKey::new(&ED25519, &self.operator_pubkey as &[u8])
            .verify(&bytes, sig)
            .map_err(|_| ConsentVerifyError::InvalidConsentSignature)?;
        Ok(())
    }
}

/// Reasons an inbound-consent signature can be rejected.
#[derive(Debug, PartialEq, Eq)]
pub enum ConsentVerifyError {
    /// The signature does not verify under `operator_pubkey` over the
    /// canonical pre-image of these terms. Covers a forged signature, a
    /// signature by the wrong key, a tampered add term (addr/weight/v_eff/
    /// node_id/operator_pubkey/bls), and a wrong-chain replay.
    InvalidConsentSignature,
    /// Re-serializing the payload to recover the canonical pre-image
    /// failed. Should never happen for this fixed-shape payload; surfaced
    /// as a distinct variant so a serialization regression is not masked
    /// behind a generic "invalid signature" verdict.
    Preimage(String),
}

impl std::fmt::Display for ConsentVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConsentSignature => {
                f.write_str("reconfig add consent does not verify under the entry's operator key")
            }
            Self::Preimage(e) => write!(f, "computing reconfig-consent pre-image failed: {e}"),
        }
    }
}

impl std::error::Error for ConsentVerifyError {}

#[cfg(test)]
mod tests {
    use super::*;

    use boule_core::crypto::signed::NodeSigner;
    use boule_core::identity::NodeIdentity;
    use rcgen::{KeyPair as RcgenKeyPair, PKCS_ED25519};
    use zeroize::Zeroizing;

    fn fresh_signer() -> NodeSigner {
        let kp = RcgenKeyPair::generate_for(&PKCS_ED25519).unwrap();
        let id = NodeIdentity {
            pkcs8_der: Zeroizing::new(kp.serialize_der()),
        };
        NodeSigner::from_identity(&id).unwrap()
    }

    fn addr() -> SocketAddr {
        "10.0.0.1:9000".parse().unwrap()
    }

    /// An add entry whose `operator_pubkey` is `operator`'s key.
    fn entry_with_operator(node_id: NodeId, operator: &NodeSigner) -> ValidatorEntry {
        ValidatorEntry {
            node_id,
            addr: addr(),
            bls_pop: None,
            weight: 7,
            operator_pubkey: Some(operator.node_id()),
            consent_sig: None,
        }
    }

    #[test]
    fn for_entry_is_none_without_operator_key() {
        let entry = ValidatorEntry {
            node_id: [1; 32],
            addr: addr(),
            bls_pop: None,
            weight: 1,
            operator_pubkey: None,
            consent_sig: None,
        };
        assert!(ReconfigAddConsent::for_entry(&entry, View(100)).is_none());
    }

    #[test]
    fn for_entry_mirrors_the_entry_terms() {
        let operator = fresh_signer();
        let entry = entry_with_operator([9; 32], &operator);
        let consent = ReconfigAddConsent::for_entry(&entry, View(60)).expect("has operator key");
        assert_eq!(consent.node_id, entry.node_id);
        assert_eq!(consent.addr, entry.addr);
        assert_eq!(consent.weight, entry.weight);
        assert_eq!(consent.operator_pubkey, operator.node_id());
        assert_eq!(consent.v_eff, View(60));
    }

    #[test]
    fn valid_consent_verifies() {
        let operator = fresh_signer();
        let entry = entry_with_operator([9; 32], &operator);
        let consent = ReconfigAddConsent::for_entry(&entry, View(60)).unwrap();
        let sig = consent.sign(&operator, &ChainId::TEST).unwrap();
        assert_eq!(consent.verify(&sig, &ChainId::TEST), Ok(()));
    }

    #[test]
    fn signature_by_a_different_key_is_rejected() {
        let operator = fresh_signer();
        let impostor = fresh_signer();
        let entry = entry_with_operator([9; 32], &operator);
        let consent = ReconfigAddConsent::for_entry(&entry, View(60)).unwrap();
        // The impostor signs the same terms, but the verification key is
        // the entry's declared operator key, not the impostor's.
        let sig = consent.sign(&impostor, &ChainId::TEST).unwrap();
        assert_eq!(
            consent.verify(&sig, &ChainId::TEST),
            Err(ConsentVerifyError::InvalidConsentSignature),
        );
    }

    #[test]
    fn tampering_with_weight_invalidates_the_consent() {
        let operator = fresh_signer();
        let entry = entry_with_operator([9; 32], &operator);
        let consent = ReconfigAddConsent::for_entry(&entry, View(60)).unwrap();
        let sig = consent.sign(&operator, &ChainId::TEST).unwrap();

        let mut tampered = consent.clone();
        tampered.weight += 1;
        assert_eq!(
            tampered.verify(&sig, &ChainId::TEST),
            Err(ConsentVerifyError::InvalidConsentSignature),
        );
    }

    #[test]
    fn tampering_with_v_eff_invalidates_the_consent() {
        let operator = fresh_signer();
        let entry = entry_with_operator([9; 32], &operator);
        let consent = ReconfigAddConsent::for_entry(&entry, View(60)).unwrap();
        let sig = consent.sign(&operator, &ChainId::TEST).unwrap();

        let mut tampered = consent.clone();
        tampered.v_eff = View(61);
        assert_eq!(
            tampered.verify(&sig, &ChainId::TEST),
            Err(ConsentVerifyError::InvalidConsentSignature),
        );
    }

    #[test]
    fn tampering_with_addr_invalidates_the_consent() {
        let operator = fresh_signer();
        let entry = entry_with_operator([9; 32], &operator);
        let consent = ReconfigAddConsent::for_entry(&entry, View(60)).unwrap();
        let sig = consent.sign(&operator, &ChainId::TEST).unwrap();

        let mut tampered = consent.clone();
        tampered.addr = "10.0.0.2:9000".parse().unwrap();
        assert_eq!(
            tampered.verify(&sig, &ChainId::TEST),
            Err(ConsentVerifyError::InvalidConsentSignature),
        );
    }

    #[test]
    fn tampering_with_node_id_invalidates_the_consent() {
        let operator = fresh_signer();
        let entry = entry_with_operator([9; 32], &operator);
        let consent = ReconfigAddConsent::for_entry(&entry, View(60)).unwrap();
        let sig = consent.sign(&operator, &ChainId::TEST).unwrap();

        let mut tampered = consent.clone();
        tampered.node_id = [0xAB; 32];
        assert_eq!(
            tampered.verify(&sig, &ChainId::TEST),
            Err(ConsentVerifyError::InvalidConsentSignature),
        );
    }

    #[test]
    fn consent_does_not_cross_chains() {
        let operator = fresh_signer();
        let entry = entry_with_operator([9; 32], &operator);
        let consent = ReconfigAddConsent::for_entry(&entry, View(60)).unwrap();
        let sig = consent.sign(&operator, &ChainId::TEST).unwrap();

        let other_chain = ChainId([7; 32]);
        assert_eq!(
            consent.verify(&sig, &other_chain),
            Err(ConsentVerifyError::InvalidConsentSignature),
        );
    }
}
