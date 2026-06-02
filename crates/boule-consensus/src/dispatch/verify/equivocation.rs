//! Equivocation-proof verification (#656) — the slashing-evidence core.
//!
//! An [`EquivocationProof`] is two conflicting *signed* messages from one
//! validator at the same view: a double-vote (two [`Vote`]s) or a
//! double-proposal (two [`Proposal`]s) naming different blocks. Honest
//! validators never produce one — a voter signs at most one vote per view, a
//! leader proposes at most one block per view — so a valid proof is
//! non-repudiable evidence a slashing action (#658) can act on.
//!
//! [`verify_equivocation_proof`] confirms this *independently*, composing the
//! same gates ingress uses ([`verify_sig`], [`verify_signer_at`]), and returns
//! the slashing-correct stable [`ValidatorId`].
//!
//! # Safety
//!
//! This is what a slash trusts; a false accept slashes an **honest**
//! validator. It accepts only when **both** envelopes carry a valid signature,
//! resolve to the **same** validator under the key **active at that view**
//! (key-rotation-correct, via [`verify_signer_at`] → [`ValidatorKeyHistory`]),
//! at the **same view**, for **different** blocks. Every other case — a forged
//! signature, an honest duplicate re-send (same block), a stale/rotated key,
//! two different validators, or messages at different views — is rejected. See
//! [`EquivocationError`] and the exhaustive tests below.

use boule_core::crypto::signed::{ChainId, Signed, SignedMessage};
use serde::{Deserialize, Serialize};

use super::envelope::{verify_sig, verify_signer_at};
use crate::View;
use crate::hotstuff::qc::{Proposal, Vote};
use crate::replication::block::BlockHash;
use crate::validator_history::ValidatorSetHistory;
use crate::validator_key_history::ValidatorKeyHistory;
use crate::validator_set::ValidatorId;

/// Two conflicting signed messages from one validator at one view —
/// non-repudiable evidence of a slashable equivocation.
///
/// Serializable so it can be gossiped and included in a block (#657).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EquivocationProof {
    /// A validator signed two votes at the same view for different blocks.
    /// Boxed to keep the enum variants similarly sized (a `Signed<Proposal>`
    /// is large, so it is boxed too).
    DoubleVote(Box<Signed<Vote>>, Box<Signed<Vote>>),
    /// A leader signed two proposals at the same view for different blocks.
    DoubleProposal(Box<Signed<Proposal>>, Box<Signed<Proposal>>),
}

/// Why an [`EquivocationProof`] is not valid evidence. Every variant is a
/// path that must **not** lead to a slash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EquivocationError {
    /// The two messages are at different views — not an equivocation.
    DifferentViews,
    /// The two messages name the same block — a duplicate, not a conflict.
    /// An honest validator re-sending its own message must never be slashed.
    NotConflicting,
    /// A signature failed to verify under its envelope's signer key.
    InvalidSignature,
    /// A signer is unknown, not in the validator set at that view, or its
    /// wire key is not the one active at that view (a stale/rotated/future
    /// key). Resolved via [`verify_signer_at`].
    BadSigner,
    /// The two messages were signed by different validators.
    DifferentValidators,
}

impl std::fmt::Display for EquivocationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::DifferentViews => "messages are at different views",
            Self::NotConflicting => "messages name the same block (not a conflict)",
            Self::InvalidSignature => "a signature failed to verify",
            Self::BadSigner => "a signer is unknown or used a key not active at that view",
            Self::DifferentValidators => "messages were signed by different validators",
        };
        f.write_str(s)
    }
}

impl std::error::Error for EquivocationError {}

impl EquivocationProof {
    /// The view the equivocation is claimed at (the first message's view).
    pub fn view(&self) -> View {
        match self {
            Self::DoubleVote(a, _) => a.payload.view,
            Self::DoubleProposal(a, _) => a.payload.block.header.view,
        }
    }
}

/// Verify `proof` and return the slashing-correct stable [`ValidatorId`] that
/// equivocated, or the reason it is not valid evidence. See the module docs
/// for the safety contract.
pub fn verify_equivocation_proof(
    proof: &EquivocationProof,
    history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
    chain_id: &ChainId,
) -> Result<ValidatorId, EquivocationError> {
    match proof {
        EquivocationProof::DoubleVote(a, b) => verify_conflicting_pair(
            a,
            b,
            a.payload.view,
            b.payload.view,
            a.payload.block_hash,
            b.payload.block_hash,
            history,
            key_history,
            chain_id,
        ),
        EquivocationProof::DoubleProposal(a, b) => verify_conflicting_pair(
            a,
            b,
            a.payload.block.header.view,
            b.payload.block.header.view,
            a.payload.block.hash(),
            b.payload.block.hash(),
            history,
            key_history,
            chain_id,
        ),
    }
}

/// Shared check for both proof kinds: same view, different block, both
/// signatures valid, both signers resolve to the same validator at that view.
#[allow(clippy::too_many_arguments)]
fn verify_conflicting_pair<T>(
    a: &Signed<T>,
    b: &Signed<T>,
    view_a: View,
    view_b: View,
    block_a: BlockHash,
    block_b: BlockHash,
    history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
    chain_id: &ChainId,
) -> Result<ValidatorId, EquivocationError>
where
    T: Serialize + SignedMessage,
{
    // Cheap structural checks first; they bound nothing security-critical
    // but give clear errors and avoid crypto on obviously-bad input.
    if view_a != view_b {
        return Err(EquivocationError::DifferentViews);
    }
    if block_a == block_b {
        return Err(EquivocationError::NotConflicting);
    }
    // Both signatures must be valid under the wire signer key.
    verify_sig(a, chain_id).map_err(|_| EquivocationError::InvalidSignature)?;
    verify_sig(b, chain_id).map_err(|_| EquivocationError::InvalidSignature)?;
    // Resolve each wire signer to its stable id, confirming the key is the
    // one active for that validator at this view (key-rotation-correct).
    let id_a = verify_signer_at(a.signer, view_a, history, key_history)
        .map_err(|_| EquivocationError::BadSigner)?;
    let id_b = verify_signer_at(b.signer, view_b, history, key_history)
        .map_err(|_| EquivocationError::BadSigner)?;
    if id_a != id_b {
        return Err(EquivocationError::DifferentValidators);
    }
    Ok(id_a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use boule_core::crypto::signed::{NodeSigner, Signer};
    use boule_core::identity::NodeIdentity;
    use rcgen::KeyPair as RcgenKeyPair;
    use rcgen::PKCS_ED25519;
    use zeroize::Zeroizing;

    use crate::validator_rotation::ValidatorKeyRotation;
    use crate::validator_set::ValidatorSet;

    fn fresh_signer() -> NodeSigner {
        let kp = RcgenKeyPair::generate_for(&PKCS_ED25519).unwrap();
        let identity = NodeIdentity {
            pkcs8_der: Zeroizing::new(kp.serialize_der()),
        };
        NodeSigner::from_identity(&identity).unwrap()
    }

    fn vid(s: &NodeSigner) -> ValidatorId {
        ValidatorId::from_genesis_pubkey(s.node_id())
    }

    fn vs_of(signers: &[&NodeSigner]) -> ValidatorSet {
        ValidatorSet::new(signers.iter().map(|s| vid(s)).collect())
    }

    fn vote(signer: &NodeSigner, view: u64, block: u8) -> Box<Signed<Vote>> {
        Box::new(
            Signed::sign(
                Vote {
                    view: View(view),
                    block_hash: [block; 32],
                },
                signer,
                &ChainId::TEST,
            )
            .unwrap(),
        )
    }

    /// `(history, key_history)` for a static genesis set, no rotations.
    fn histories(vs: &ValidatorSet) -> (ValidatorSetHistory, ValidatorKeyHistory) {
        (
            ValidatorSetHistory::from_genesis(vs.clone()),
            ValidatorKeyHistory::new(vs.iter().copied()),
        )
    }

    #[test]
    fn accepts_a_genuine_double_vote_and_returns_the_validator() {
        let s = fresh_signer();
        let vs = vs_of(&[&s, &fresh_signer()]);
        let (h, kh) = histories(&vs);
        // Same view, different blocks, same signer.
        let proof = EquivocationProof::DoubleVote(vote(&s, 7, 1), vote(&s, 7, 2));
        assert_eq!(
            verify_equivocation_proof(&proof, &h, &kh, &ChainId::TEST),
            Ok(vid(&s)),
        );
    }

    #[test]
    fn rejects_same_block_as_not_conflicting() {
        // An honest validator re-sending its own vote must NEVER slash.
        let s = fresh_signer();
        let vs = vs_of(&[&s]);
        let (h, kh) = histories(&vs);
        let proof = EquivocationProof::DoubleVote(vote(&s, 7, 1), vote(&s, 7, 1));
        assert_eq!(
            verify_equivocation_proof(&proof, &h, &kh, &ChainId::TEST),
            Err(EquivocationError::NotConflicting),
        );
    }

    #[test]
    fn rejects_different_views() {
        let s = fresh_signer();
        let vs = vs_of(&[&s]);
        let (h, kh) = histories(&vs);
        let proof = EquivocationProof::DoubleVote(vote(&s, 7, 1), vote(&s, 8, 2));
        assert_eq!(
            verify_equivocation_proof(&proof, &h, &kh, &ChainId::TEST),
            Err(EquivocationError::DifferentViews),
        );
    }

    #[test]
    fn rejects_a_tampered_signature() {
        let s = fresh_signer();
        let vs = vs_of(&[&s]);
        let (h, kh) = histories(&vs);
        let mut bad = vote(&s, 7, 2);
        bad.sig[0] ^= 0x01; // break the second signature
        let proof = EquivocationProof::DoubleVote(vote(&s, 7, 1), bad);
        assert_eq!(
            verify_equivocation_proof(&proof, &h, &kh, &ChainId::TEST),
            Err(EquivocationError::InvalidSignature),
        );
    }

    #[test]
    fn rejects_an_unknown_signer() {
        // The validator set knows `member` but not `outsider`.
        let member = fresh_signer();
        let outsider = fresh_signer();
        let vs = vs_of(&[&member]);
        let (h, kh) = histories(&vs);
        let proof = EquivocationProof::DoubleVote(vote(&outsider, 7, 1), vote(&outsider, 7, 2));
        assert_eq!(
            verify_equivocation_proof(&proof, &h, &kh, &ChainId::TEST),
            Err(EquivocationError::BadSigner),
        );
    }

    #[test]
    fn rejects_two_different_validators() {
        // Two validators each signing a (different) block at the same view is
        // not equivocation — it's normal disagreement, not slashable.
        let s1 = fresh_signer();
        let s2 = fresh_signer();
        let vs = vs_of(&[&s1, &s2]);
        let (h, kh) = histories(&vs);
        let proof = EquivocationProof::DoubleVote(vote(&s1, 7, 1), vote(&s2, 7, 2));
        assert_eq!(
            verify_equivocation_proof(&proof, &h, &kh, &ChainId::TEST),
            Err(EquivocationError::DifferentValidators),
        );
    }

    #[test]
    fn accepts_a_double_proposal() {
        use crate::hotstuff::qc::QuorumCertificate;
        use crate::replication::block::Block;

        let s = fresh_signer();
        let vs = vs_of(&[&s]);
        let (h, kh) = histories(&vs);
        let genesis = Block::genesis([0u8; 32], [0; 32]);
        let qc = QuorumCertificate::new(0, genesis.hash(), 1);
        // Two distinct blocks at the same view (different parents → different
        // hashes), both proposed by the same leader.
        let mut block_a = genesis.clone();
        block_a.header.view = View(5);
        block_a.header.height = crate::Height(1);
        let mut block_b = block_a.clone();
        block_b.header.timestamp = block_a.header.timestamp + 1; // distinct hash
        assert_ne!(block_a.hash(), block_b.hash());
        let prop = |blk: Block| {
            Box::new(
                Signed::sign(
                    Proposal {
                        block: blk,
                        justify: qc.clone(),
                    },
                    &s,
                    &ChainId::TEST,
                )
                .unwrap(),
            )
        };
        let proof = EquivocationProof::DoubleProposal(prop(block_a), prop(block_b));
        assert_eq!(
            verify_equivocation_proof(&proof, &h, &kh, &ChainId::TEST),
            Ok(vid(&s)),
        );
    }

    #[test]
    fn accepts_a_proof_signed_under_a_rotated_key_at_that_view() {
        // The slashing-critical case: a validator that rotated its signing key
        // equivocates under the NEW key after the rotation took effect. The
        // proof must verify and attribute to the stable (genesis) identity.
        let genesis_key = fresh_signer();
        let rotated_key = fresh_signer();
        let vs = vs_of(&[&genesis_key, &fresh_signer()]);
        let (h, mut kh) = histories(&vs);
        kh.apply_rotation(
            &ValidatorKeyRotation {
                validator: genesis_key.node_id(), // current (genesis) key
                new_pubkey: rotated_key.node_id(),
                v_eff: View(4),
                new_bls_pubkey: None,
                new_bls_pop: None,
            },
            View(0),
        )
        .expect("rotation applies");

        // Double-vote at view 6 (>= v_eff 4), both signed by the ROTATED key.
        let proof =
            EquivocationProof::DoubleVote(vote(&rotated_key, 6, 1), vote(&rotated_key, 6, 2));
        // Resolves to the stable genesis identity, not the ephemeral key.
        assert_eq!(
            verify_equivocation_proof(&proof, &h, &kh, &ChainId::TEST),
            Ok(vid(&genesis_key)),
        );
    }

    #[test]
    fn rejects_a_key_not_active_at_the_proof_view() {
        // Same rotation, but the proof is signed by the OLD (genesis) key at a
        // view AFTER the rotation — that key is no longer active there, so it
        // is not valid evidence (guards against replaying a retired key).
        let genesis_key = fresh_signer();
        let rotated_key = fresh_signer();
        let vs = vs_of(&[&genesis_key, &fresh_signer()]);
        let (h, mut kh) = histories(&vs);
        kh.apply_rotation(
            &ValidatorKeyRotation {
                validator: genesis_key.node_id(),
                new_pubkey: rotated_key.node_id(),
                v_eff: View(4),
                new_bls_pubkey: None,
                new_bls_pop: None,
            },
            View(0),
        )
        .expect("rotation applies");
        // Votes at view 6 signed by the now-retired genesis key.
        let proof =
            EquivocationProof::DoubleVote(vote(&genesis_key, 6, 1), vote(&genesis_key, 6, 2));
        assert_eq!(
            verify_equivocation_proof(&proof, &h, &kh, &ChainId::TEST),
            Err(EquivocationError::BadSigner),
        );
    }
}
