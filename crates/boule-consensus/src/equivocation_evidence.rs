//! Equivocation-evidence system transaction (#657).
//!
//! An [`EquivocationProof`](crate::dispatch::EquivocationProof) — two
//! conflicting [`Signed`](boule_core::crypto::signed::Signed) envelopes from
//! one validator at one view — is non-repudiable evidence of a Byzantine
//! double-sign (produced by #656). This module gives that proof a wire form
//! for `Block.commands`: a leader embeds it as a tagged system transaction so
//! it lands in a committed block, where the commit-time apply path records it
//! exactly once and a later slashing pass (#658) penalises the equivocator.
//!
//! # Wire format
//!
//! The byte stream is `EVIDENCE_TAG || postcard(EquivocationProof)`. The tag
//! prefix lets the block builder and the commit-apply path tell an evidence
//! payload apart from opaque application commands (and from the other tagged
//! system txs — [`reconfig`](crate::reconfig), [`validator_rotation`](crate::validator_rotation))
//! without attempt-then-rollback deserialization of every `Bytes` slot.
//!
//! The proof carries its own signatures, so — unlike a reconfig or a rotation
//! — it is **self-authenticating**: anyone can confirm a real validator
//! double-signed at a real view via
//! [`verify_equivocation_proof`](crate::dispatch::verify_equivocation_proof),
//! independent of which node relayed or proposed it. No outer signature from
//! the proposer is needed or wanted.

use bytes::Bytes;

use crate::dispatch::EquivocationProof;

/// Magic prefix that tags a `Block.commands` entry as an equivocation-evidence
/// payload.
pub const EVIDENCE_TAG: &[u8; 6] = b"EVDNC\0";

/// Maximum age, in views, between the equivocation's view and the view of the
/// block that includes the evidence, beyond which the evidence is rejected as
/// stale.
///
/// "Don't slash on stale evidence": an equivocation from the distant past must
/// not be replayable into a fresh block to grief a validator (e.g. one that
/// has since rotated keys or left and rejoined). The window is generous
/// relative to the proof-retention window the node builds proofs within (the
/// node retains signed envelopes for 256 views) so that any honestly-built
/// proof has ample time to be gossiped, proposed, and committed (~3-view
/// three-chain depth plus leader-rotation latency), yet bounded so ancient
/// evidence cannot be resurrected.
pub const MAX_EVIDENCE_AGE_VIEWS: u64 = 1024;

/// Encode a proof as a tagged byte sequence suitable for `Block.commands`.
pub fn encode_evidence(proof: &EquivocationProof) -> Bytes {
    let body =
        postcard::to_stdvec(proof).expect("postcard encoding of EquivocationProof cannot fail");
    let mut out = Vec::with_capacity(EVIDENCE_TAG.len() + body.len());
    out.extend_from_slice(EVIDENCE_TAG);
    out.extend_from_slice(&body);
    Bytes::from(out)
}

/// True iff `bytes` carries the evidence tag prefix.
pub fn is_evidence_payload(bytes: &[u8]) -> bool {
    bytes.starts_with(EVIDENCE_TAG)
}

/// Decode a tagged evidence payload. Errors if the tag is absent or the body
/// is malformed.
pub fn decode_evidence(bytes: &[u8]) -> anyhow::Result<EquivocationProof> {
    let body = bytes
        .strip_prefix(EVIDENCE_TAG.as_slice())
        .ok_or_else(|| anyhow::anyhow!("missing evidence tag prefix"))?;
    postcard::from_bytes(body).map_err(|e| anyhow::anyhow!("malformed EquivocationProof: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::View;
    use crate::hotstuff::qc::Vote;
    use boule_core::crypto::signed::{ChainId, NodeSigner, Signed};
    use boule_core::identity::NodeIdentity;
    use rcgen::KeyPair as RcgenKeyPair;
    use rcgen::PKCS_ED25519;
    use zeroize::Zeroizing;

    fn fresh_signer() -> NodeSigner {
        let kp = RcgenKeyPair::generate_for(&PKCS_ED25519).unwrap();
        let identity = NodeIdentity {
            pkcs8_der: Zeroizing::new(kp.serialize_der()),
        };
        NodeSigner::from_identity(&identity).unwrap()
    }

    fn signed_vote(view: u64, block: u8, signer: &NodeSigner) -> Box<Signed<Vote>> {
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

    #[test]
    fn tag_predicate_distinguishes_evidence_from_other_payloads() {
        let signer = fresh_signer();
        let proof = EquivocationProof::DoubleVote(
            signed_vote(3, 0xAA, &signer),
            signed_vote(3, 0xBB, &signer),
        );
        let bytes = encode_evidence(&proof);
        assert!(is_evidence_payload(&bytes));
        // A reconfig payload (different tag) is not mistaken for evidence.
        assert!(!is_evidence_payload(crate::reconfig::RECONFIG_TAG));
        assert!(!is_evidence_payload(b"random application command"));
    }

    #[test]
    fn encode_then_decode_round_trips() {
        let signer = fresh_signer();
        let proof = EquivocationProof::DoubleVote(
            signed_vote(7, 0x11, &signer),
            signed_vote(7, 0x22, &signer),
        );
        let bytes = encode_evidence(&proof);
        let decoded = decode_evidence(&bytes).expect("round-trip decode");
        assert_eq!(decoded, proof);
    }

    #[test]
    fn decode_rejects_untagged_bytes() {
        assert!(decode_evidence(b"no tag here").is_err());
    }
}
