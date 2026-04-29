//! Validator consensus-key rotation transaction (issue #142).
//!
//! A validator that wants to swap its consensus signing key without leaving
//! and rejoining the set submits a [`ValidatorKeyRotation`] payload wrapped
//! in a [`DualSignedRotation`] envelope. The envelope carries two
//! signatures over the same domain-separated pre-image:
//!
//! - `sig_old` — produced by the validator's *current* consensus key.
//! - `sig_new` — produced by the proposed `new_pubkey`.
//!
//! Both must verify before the rotation can be accepted: that's the
//! self-attestation property (#142, scope item 3) — proving the validator
//! controls both keys. Without it, an attacker who compromises only the
//! current key could rotate to a key only they hold, locking out the
//! legitimate operator.
//!
//! # Scope of this module
//!
//! Type definition, postcard codec, structural well-formedness checks,
//! dual-signature verification, and the tagged on-the-wire form used as
//! a `Block.commands` payload. The commit-time application path lives
//! in `consensus::node::ConsensusNode::apply_committed_rotations`
//! (#260) and reads via [`DualSignedRotation::is_rotation_payload`] +
//! [`DualSignedRotation::decode_command`].

use anyhow::Result;
use bytes::Bytes;
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

use crate::consensus::View;
use crate::crypto::sig_scheme::{BlsAggregated, BlsPop, BlsPublicKey, SignatureSchemeChoice};
use crate::crypto::signed::{ChainId, SignedMessage, Signer, preimage};
use crate::p2p::NodeId;

/// Magic prefix that tags a `Block.commands` entry as a tagged
/// [`DualSignedRotation`] payload. Mirrors the [`RECONFIG_TAG`] convention
/// from [`crate::consensus::reconfig`]: a 6-byte prefix lets the
/// commit-time scanner tell rotation txs apart from opaque application
/// commands without attempting `postcard::from_bytes` on every slot.
///
/// [`RECONFIG_TAG`]: crate::consensus::reconfig::RECONFIG_TAG
pub const ROTATION_TAG: &[u8; 6] = b"VKROT\0";

/// Minimum gap between the view in which a rotation is committed and its
/// effective view, matching the convention established by validator-set
/// reconfiguration (#140). Two views give the validator at least one full
/// view to provision the new key on the signing path before it must
/// produce votes/proposals under it.
pub const V_EFF_MIN_DELAY: View = 2;

/// Payload of a validator-key rotation transaction.
///
/// `validator` identifies the validator whose key is changing (currently
/// the validator's active consensus pubkey; once #140 introduces a stable
/// validator address this field's interpretation tightens but the wire
/// shape is unchanged). `new_pubkey` is the consensus key the validator
/// proposes to sign under starting at view `v_eff`.
///
/// On `bls_aggregated` chains every rotation must atomically swap both
/// halves of the validator's identity: `new_bls_pubkey` carries the new
/// BLS12-381 G1 pubkey and `new_bls_pop` is its proof-of-possession
/// (matching the `add-validator` reconfig contract from #291). On
/// `ed25519_collected` chains both fields must be absent. Splitting the
/// two halves into independent rotations would let the histories
/// disagree at a single view (#358 out-of-scope item).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorKeyRotation {
    pub validator: NodeId,
    pub new_pubkey: NodeId,
    pub v_eff: View,
    /// New BLS pubkey (#358). Required on BLS chains, must be `None`
    /// on Ed25519 chains; the consistency check is in
    /// [`Self::validate_scheme_consistency`].
    #[serde(default, with = "serde_optional_bls_pubkey")]
    pub new_bls_pubkey: Option<BlsPublicKey>,
    /// Proof-of-possession over `new_bls_pubkey` (#358). Required when
    /// `new_bls_pubkey` is `Some`; must be `None` otherwise. Verified
    /// by [`Self::validate_scheme_consistency`] under
    /// [`BlsAggregated::verify_pop`] before the rotation can be
    /// applied to [`crate::consensus::bls_key_history::BlsKeyHistory`].
    #[serde(default)]
    pub new_bls_pop: Option<BlsPop>,
}

impl SignedMessage for ValidatorKeyRotation {
    const DOMAIN: &'static str = "ambros.consensus.validator_rotation.v1";
}

/// A [`ValidatorKeyRotation`] envelope carrying both the old-key and
/// new-key signatures over the canonical pre-image of the payload.
///
/// The "signer" of each signature is implicit: `sig_new` verifies under
/// `payload.new_pubkey` (embedded in the payload itself), and `sig_old`
/// verifies under whatever key the validator is currently using — looked
/// up by the consumer against the active validator set, not carried on
/// the envelope. That's deliberate: an attacker who rewrites a `signer`
/// claim can already be defeated by [`crate::crypto::signed::Signed`],
/// but for a self-attestation envelope the trusted answer to "who is the
/// old signer?" comes from the validator set, not from the message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DualSignedRotation {
    pub payload: ValidatorKeyRotation,
    #[serde(with = "serde_sig")]
    pub sig_old: [u8; 64],
    #[serde(with = "serde_sig")]
    pub sig_new: [u8; 64],
}

/// Reasons a rotation can be rejected at the structural-validation stage,
/// before any cryptographic check. These are cheap to evaluate and apply
/// equally at admission time and at block-validation time.
#[derive(Debug, PartialEq, Eq)]
pub enum RotationStructuralError {
    EffectiveViewTooSoon {
        current_view: View,
        v_eff: View,
    },
    NewKeyEqualsValidator,
    /// On a `bls_aggregated` chain a rotation must carry both
    /// `new_bls_pubkey` and `new_bls_pop`; on `ed25519_collected` it
    /// must carry neither (#358). Splitting the two halves into
    /// independent rotations would leave the Ed25519 and BLS
    /// histories transiently disagreeing at a single view.
    BlsFieldsInconsistentWithScheme {
        scheme: SignatureSchemeChoice,
        bls_pubkey_present: bool,
        bls_pop_present: bool,
    },
    /// On a BLS chain, the proof-of-possession in `new_bls_pop` did
    /// not verify under `new_bls_pubkey`. Catches a rotator who
    /// supplies a BLS pubkey they don't actually hold the secret half
    /// of — the same rogue-key-attack defense the registration path
    /// runs (#291).
    BlsPopVerificationFailed,
}

impl std::fmt::Display for RotationStructuralError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EffectiveViewTooSoon {
                current_view,
                v_eff,
            } => write!(
                f,
                "rotation v_eff={v_eff} is not at least {V_EFF_MIN_DELAY} views ahead of \
                 current_view={current_view}",
            ),
            Self::NewKeyEqualsValidator => {
                write!(
                    f,
                    "rotation new_pubkey equals current validator key (no-op rotation)"
                )
            }
            Self::BlsFieldsInconsistentWithScheme {
                scheme,
                bls_pubkey_present,
                bls_pop_present,
            } => write!(
                f,
                "rotation BLS fields inconsistent with chain scheme {scheme}: \
                 new_bls_pubkey={bls_pubkey_present}, new_bls_pop={bls_pop_present}; \
                 BLS chains require both, Ed25519 chains require neither",
            ),
            Self::BlsPopVerificationFailed => f.write_str(
                "rotation new_bls_pop does not verify under new_bls_pubkey \
                 (rogue-key-attack defense)",
            ),
        }
    }
}

impl std::error::Error for RotationStructuralError {}

impl ValidatorKeyRotation {
    /// Validate fields that don't require any external state beyond the
    /// current view. Specifically:
    ///
    /// - `v_eff` is at least `V_EFF_MIN_DELAY` views ahead of `current_view`,
    ///   so the validator has time to provision the new key.
    /// - `new_pubkey != validator`, rejecting trivially no-op rotations
    ///   that would just churn the per-view key history.
    ///
    /// The `NodeId` shape (32 bytes) is enforced by postcard at decode
    /// time; this method covers the rest. Cryptographic checks
    /// (signature validity, `new_pubkey` being a valid Ed25519 point) are
    /// out of scope for this layer — they happen in the verification
    /// step that consumes a [`DualSignedRotation`].
    pub fn validate_structural(&self, current_view: View) -> Result<(), RotationStructuralError> {
        if self.v_eff < current_view.saturating_add(V_EFF_MIN_DELAY) {
            return Err(RotationStructuralError::EffectiveViewTooSoon {
                current_view,
                v_eff: self.v_eff,
            });
        }
        if self.new_pubkey == self.validator {
            return Err(RotationStructuralError::NewKeyEqualsValidator);
        }
        Ok(())
    }

    /// Check that the BLS half of this rotation matches the chain's
    /// signature scheme, and (on BLS chains) that `new_bls_pop`
    /// verifies under `new_bls_pubkey` (#358).
    ///
    /// Separate from [`Self::validate_structural`] because the chain
    /// scheme isn't part of the rotation payload — it's a property of
    /// the chain the rotation is being applied to. Callers thread the
    /// scheme in from `NodeConfigForConsensus.signature_scheme` (or
    /// `ConsensusNode.signature_scheme` post-construction).
    pub fn validate_scheme_consistency(
        &self,
        scheme: SignatureSchemeChoice,
    ) -> Result<(), RotationStructuralError> {
        match scheme {
            SignatureSchemeChoice::Ed25519Collected => {
                if self.new_bls_pubkey.is_some() || self.new_bls_pop.is_some() {
                    return Err(RotationStructuralError::BlsFieldsInconsistentWithScheme {
                        scheme,
                        bls_pubkey_present: self.new_bls_pubkey.is_some(),
                        bls_pop_present: self.new_bls_pop.is_some(),
                    });
                }
                Ok(())
            }
            SignatureSchemeChoice::BlsAggregated => {
                let (Some(pk), Some(pop)) = (&self.new_bls_pubkey, &self.new_bls_pop) else {
                    return Err(RotationStructuralError::BlsFieldsInconsistentWithScheme {
                        scheme,
                        bls_pubkey_present: self.new_bls_pubkey.is_some(),
                        bls_pop_present: self.new_bls_pop.is_some(),
                    });
                };
                BlsAggregated::verify_pop(pop, pk)
                    .map_err(|_| RotationStructuralError::BlsPopVerificationFailed)
            }
        }
    }
}

/// Reasons a [`DualSignedRotation`] can fail cryptographic verification,
/// after structural well-formedness has already been checked. These map
/// 1:1 to the four rejection cases enumerated in the acceptance criteria
/// for #258, so callers can log a precise reason without re-deriving it.
#[derive(Debug, PartialEq, Eq)]
pub enum RotationVerifyError {
    /// `sig_old` does not verify under the validator's currently-active
    /// consensus key. Covers the "signed only by the new key" case (the
    /// envelope still has *some* bytes in `sig_old`, but they are not a
    /// signature by the old key) and the "tampered old signature" case.
    InvalidOldSignature,
    /// `sig_new` does not verify under `payload.new_pubkey`. Covers the
    /// "signed only by the old key" case, the "tampered new signature"
    /// case, and the "sig_new is a real signature but over different
    /// bytes" case.
    InvalidNewSignature,
    /// Re-serializing the payload to recover the canonical pre-image
    /// failed. In practice this should never happen for the fixed-shape
    /// payload used here, but surfacing it as a distinct variant keeps
    /// the verifier from masking unexpected serialization regressions
    /// behind a generic "invalid signature" verdict.
    Preimage(String),
}

impl std::fmt::Display for RotationVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidOldSignature => f.write_str(
                "rotation sig_old does not verify under the validator's current consensus key",
            ),
            Self::InvalidNewSignature => {
                f.write_str("rotation sig_new does not verify under payload.new_pubkey")
            }
            Self::Preimage(e) => write!(f, "computing rotation pre-image failed: {e}"),
        }
    }
}

impl std::error::Error for RotationVerifyError {}

impl DualSignedRotation {
    /// Encode as a tagged byte sequence suitable for a
    /// `Block.commands` slot: [`ROTATION_TAG`] || `postcard(self)`.
    /// The tag prefix lets the commit-time scanner identify rotation
    /// txs without attempting `postcard::from_bytes` on every command
    /// in the block.
    pub fn encode_command(&self) -> Bytes {
        let body =
            postcard::to_stdvec(self).expect("postcard encoding of DualSignedRotation cannot fail");
        let mut out = Vec::with_capacity(ROTATION_TAG.len() + body.len());
        out.extend_from_slice(ROTATION_TAG);
        out.extend_from_slice(&body);
        Bytes::from(out)
    }

    /// True iff `bytes` carries the [`ROTATION_TAG`] prefix. Returns
    /// false on near-miss prefixes (5-byte truncations, off-by-one) so
    /// the commit-time scanner can short-circuit obvious non-rotations
    /// before paying the postcard decode.
    pub fn is_rotation_payload(bytes: &[u8]) -> bool {
        bytes.starts_with(ROTATION_TAG)
    }

    /// Decode a tagged rotation tx. Returns an error if the tag is
    /// absent or the postcard body is malformed. The caller is
    /// expected to follow this with [`Self::verify`] before applying
    /// the rotation — `decode_command` does not do cryptographic
    /// validation.
    pub fn decode_command(bytes: &[u8]) -> Result<Self> {
        let body = bytes
            .strip_prefix(ROTATION_TAG.as_slice())
            .ok_or_else(|| anyhow::anyhow!("missing rotation tag prefix"))?;
        postcard::from_bytes(body).map_err(|e| anyhow::anyhow!("malformed DualSignedRotation: {e}"))
    }

    /// Construct a dual-signed rotation envelope. The `current` signer
    /// must hold the validator's currently-active consensus key; the
    /// `new` signer must hold the key being rotated to (and its
    /// `node_id()` must equal `payload.new_pubkey`, which the helper
    /// asserts so callers can't accidentally produce an envelope whose
    /// `sig_new` would never verify).
    ///
    /// Both signatures are over the same canonical pre-image as
    /// [`crate::crypto::signed::Signed`] for `ValidatorKeyRotation` — the
    /// shared helper guarantees the bytes signed match the bytes
    /// [`Self::verify`] reconstructs.
    pub fn sign(
        payload: ValidatorKeyRotation,
        current: &dyn Signer,
        new: &dyn Signer,
        chain_id: &ChainId,
    ) -> Result<Self> {
        if new.node_id() != payload.new_pubkey {
            anyhow::bail!(
                "new signer's node_id does not match payload.new_pubkey; the resulting \
                 sig_new would never verify"
            );
        }
        let bytes = preimage::<ValidatorKeyRotation>(&payload, chain_id)?;
        let sig_old = current.sign(&bytes);
        let sig_new = new.sign(&bytes);
        Ok(Self {
            payload,
            sig_old,
            sig_new,
        })
    }

    /// Verify both signatures: `sig_old` under `current_pubkey` (the
    /// validator's currently-active consensus key, looked up by the
    /// caller against the live validator set), and `sig_new` under
    /// `self.payload.new_pubkey`. Both must verify against `chain_id`.
    ///
    /// This is the cryptographic half of the self-attestation property
    /// from #142: it proves the validator controls both keys at the
    /// moment the rotation was signed, so a compromise of only the old
    /// key cannot rotate to a key the legitimate operator does not hold.
    /// `chain_id` (#324) scopes the rotation to the deployment so a
    /// rotation signed for chain A cannot be replayed against chain B.
    /// Structural validation ([`ValidatorKeyRotation::validate_structural`])
    /// is independent — callers should run it first because it's
    /// strictly cheaper.
    pub fn verify(
        &self,
        current_pubkey: &NodeId,
        chain_id: &ChainId,
    ) -> Result<(), RotationVerifyError> {
        let bytes = preimage::<ValidatorKeyRotation>(&self.payload, chain_id)
            .map_err(|e| RotationVerifyError::Preimage(e.to_string()))?;

        UnparsedPublicKey::new(&ED25519, current_pubkey as &[u8])
            .verify(&bytes, &self.sig_old)
            .map_err(|_| RotationVerifyError::InvalidOldSignature)?;

        UnparsedPublicKey::new(&ED25519, &self.payload.new_pubkey as &[u8])
            .verify(&bytes, &self.sig_new)
            .map_err(|_| RotationVerifyError::InvalidNewSignature)?;

        Ok(())
    }
}

/// Serde adapter for `Option<BlsPublicKey>` — a 48-byte fixed array that
/// serde does not auto-derive past N=32. Mirrors the byte-sequence
/// shape used by `Option<BlsPartialSig>` in
/// [`crate::consensus::node::WireMessage::Vote`] (#355).
mod serde_optional_bls_pubkey {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    use crate::crypto::sig_scheme::BlsPublicKey;

    pub fn serialize<S: Serializer>(opt: &Option<BlsPublicKey>, s: S) -> Result<S::Ok, S::Error> {
        match opt {
            Some(pk) => s.serialize_some(&pk[..]),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<BlsPublicKey>, D::Error> {
        let opt: Option<Vec<u8>> = Option::deserialize(d)?;
        match opt {
            Some(v) => v
                .as_slice()
                .try_into()
                .map(Some)
                .map_err(|_| D::Error::custom("BLS pubkey must be exactly 48 bytes")),
            None => Ok(None),
        }
    }
}

/// Mirror of `crypto::signed::serde_sig` for the two raw signatures held
/// by [`DualSignedRotation`]. Kept private here so the envelope's wire
/// format stays decoupled from the `Signed<T>` envelope's internals.
mod serde_sig {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(sig: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&sig[..], s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Vec::<u8>::deserialize(d)?;
        v.as_slice()
            .try_into()
            .map_err(|_| D::Error::custom("signature must be exactly 64 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::crypto::signed::NodeSigner;
    use crate::p2p::identity::NodeIdentity;
    use rcgen::{KeyPair as RcgenKeyPair, PKCS_ED25519};
    use zeroize::Zeroizing;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn fresh_signer() -> NodeSigner {
        let kp = RcgenKeyPair::generate_for(&PKCS_ED25519).unwrap();
        let id = NodeIdentity {
            pkcs8_der: Zeroizing::new(kp.serialize_der()),
        };
        NodeSigner::from_identity(&id).unwrap()
    }

    fn sample_payload() -> ValidatorKeyRotation {
        ValidatorKeyRotation {
            validator: nid(1),
            new_pubkey: nid(2),
            v_eff: 100,
            new_bls_pubkey: None,
            new_bls_pop: None,
        }
    }

    fn sample_envelope() -> DualSignedRotation {
        DualSignedRotation {
            payload: sample_payload(),
            sig_old: [0xAA; 64],
            sig_new: [0xBB; 64],
        }
    }

    // ── tagged command codec (#260) ──────────────────────────────────────

    #[test]
    fn encode_decode_command_roundtrip() {
        let env = sample_envelope();
        let bytes = env.encode_command();
        assert!(DualSignedRotation::is_rotation_payload(&bytes));
        let back = DualSignedRotation::decode_command(&bytes).unwrap();
        assert_eq!(back, env);
    }

    #[test]
    fn is_rotation_payload_rejects_untagged_bytes() {
        assert!(!DualSignedRotation::is_rotation_payload(b""));
        assert!(!DualSignedRotation::is_rotation_payload(b"hello"));
        // A near-miss (5 of 6 tag bytes) must not match.
        assert!(!DualSignedRotation::is_rotation_payload(b"VKROT"));
        // The reconfig tag must not be misinterpreted as a rotation.
        assert!(!DualSignedRotation::is_rotation_payload(
            crate::consensus::reconfig::RECONFIG_TAG
        ));
    }

    #[test]
    fn decode_command_errors_without_tag() {
        let err = DualSignedRotation::decode_command(b"not a rotation").unwrap_err();
        assert!(err.to_string().contains("missing rotation tag prefix"));
    }

    #[test]
    fn decode_command_errors_on_truncated_body() {
        let env = sample_envelope();
        let bytes = env.encode_command();
        let truncated = &bytes[..bytes.len() - 1];
        assert!(DualSignedRotation::is_rotation_payload(truncated));
        let err = DualSignedRotation::decode_command(truncated).unwrap_err();
        assert!(err.to_string().contains("malformed DualSignedRotation"));
    }

    #[test]
    fn rotation_tag_does_not_collide_with_reconfig_tag() {
        // Both consume a `Block.commands` slot, so their first six bytes
        // must disambiguate which payload type a slot holds.
        assert_ne!(
            ROTATION_TAG.as_slice(),
            crate::consensus::reconfig::RECONFIG_TAG.as_slice()
        );
    }

    #[test]
    fn payload_round_trips_through_postcard() {
        let p = sample_payload();
        let bytes = postcard::to_stdvec(&p).unwrap();
        let back: ValidatorKeyRotation = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn envelope_round_trips_through_postcard() {
        let env = sample_envelope();
        let bytes = postcard::to_stdvec(&env).unwrap();
        let back: DualSignedRotation = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, env);
    }

    #[test]
    fn envelope_rejects_short_signature_on_decode() {
        // Hand-craft a postcard buffer where one of the signature byte
        // sequences is the wrong length. The custom serde adapter must
        // reject it, since a `[u8; 64]` decoded from a length-prefixed
        // byte sequence has no other layer enforcing the length.
        let env = sample_envelope();
        let mut bytes = postcard::to_stdvec(&env).unwrap();

        // Postcard encodes Vec<u8> as varint(len) || bytes. The payload
        // (validator + new_pubkey + v_eff) is fixed-shape; immediately
        // after it sits sig_old's varint length. For our V_EFF=100 the
        // payload occupies 32+32+1 bytes (varint 100 = 1 byte).
        let payload_len = 32 + 32 + 1;
        // Bump sig_old's length byte from 64 to 63 and drop the last byte.
        bytes[payload_len] = 63;
        bytes.truncate(bytes.len() - 1);

        let _ = postcard::from_bytes::<DualSignedRotation>(&bytes)
            .expect_err("decode of malformed signature should fail");
    }

    #[test]
    fn validate_structural_accepts_minimum_delay() {
        let p = ValidatorKeyRotation {
            validator: nid(1),
            new_pubkey: nid(2),
            v_eff: 10 + V_EFF_MIN_DELAY,
            new_bls_pubkey: None,
            new_bls_pop: None,
        };
        assert!(p.validate_structural(10).is_ok());
    }

    #[test]
    fn validate_structural_accepts_far_future() {
        let p = ValidatorKeyRotation {
            validator: nid(1),
            new_pubkey: nid(2),
            v_eff: u64::MAX,
            new_bls_pubkey: None,
            new_bls_pop: None,
        };
        assert!(p.validate_structural(0).is_ok());
    }

    #[test]
    fn validate_structural_rejects_one_view_ahead() {
        let p = ValidatorKeyRotation {
            validator: nid(1),
            new_pubkey: nid(2),
            v_eff: 11,
            new_bls_pubkey: None,
            new_bls_pop: None,
        };
        assert_eq!(
            p.validate_structural(10),
            Err(RotationStructuralError::EffectiveViewTooSoon {
                current_view: 10,
                v_eff: 11,
            })
        );
    }

    #[test]
    fn validate_structural_rejects_same_view() {
        let p = ValidatorKeyRotation {
            validator: nid(1),
            new_pubkey: nid(2),
            v_eff: 10,
            new_bls_pubkey: None,
            new_bls_pop: None,
        };
        assert!(matches!(
            p.validate_structural(10),
            Err(RotationStructuralError::EffectiveViewTooSoon { .. })
        ));
    }

    #[test]
    fn validate_structural_rejects_past_v_eff() {
        let p = ValidatorKeyRotation {
            validator: nid(1),
            new_pubkey: nid(2),
            v_eff: 5,
            new_bls_pubkey: None,
            new_bls_pop: None,
        };
        assert!(matches!(
            p.validate_structural(10),
            Err(RotationStructuralError::EffectiveViewTooSoon { .. })
        ));
    }

    #[test]
    fn validate_structural_rejects_no_op_rotation() {
        let p = ValidatorKeyRotation {
            validator: nid(7),
            new_pubkey: nid(7),
            v_eff: 1_000,
            new_bls_pubkey: None,
            new_bls_pop: None,
        };
        assert_eq!(
            p.validate_structural(0),
            Err(RotationStructuralError::NewKeyEqualsValidator)
        );
    }

    #[test]
    fn validate_structural_does_not_overflow_at_view_max() {
        // A current_view at the very top of the u64 range plus the min
        // delay would overflow; saturating_add must keep us in a defined,
        // monotonic regime so structural validation can't panic on
        // adversarial inputs.
        let p = ValidatorKeyRotation {
            validator: nid(1),
            new_pubkey: nid(2),
            v_eff: u64::MAX,
            new_bls_pubkey: None,
            new_bls_pop: None,
        };
        // Even at this extreme, v_eff == saturating_add result, so the
        // check passes (>= holds).
        assert!(p.validate_structural(u64::MAX).is_ok());
    }

    #[test]
    fn payload_has_stable_domain_string() {
        // The on-disk / on-wire signature pre-image embeds DOMAIN. Any
        // change to this constant invalidates every signature ever
        // produced under the old domain, so it's a wire-breaking change
        // and must trip a deliberate test update.
        assert_eq!(
            ValidatorKeyRotation::DOMAIN,
            "ambros.consensus.validator_rotation.v1"
        );
    }

    // ── verification ────────────────────────────────────────────────────────

    /// Helper: build a real, valid `DualSignedRotation` where `current` is
    /// the validator's currently-active key and `new` is the rotation
    /// target. Returns the envelope plus the two signers' pubkeys, since
    /// every rejection test wants to introspect at least one of them.
    fn valid_envelope() -> (DualSignedRotation, NodeId, NodeId) {
        let current = fresh_signer();
        let new = fresh_signer();
        let payload = ValidatorKeyRotation {
            validator: current.node_id(),
            new_pubkey: new.node_id(),
            v_eff: 100,
            new_bls_pubkey: None,
            new_bls_pop: None,
        };
        let env = DualSignedRotation::sign(payload, &current, &new, &ChainId::TEST).unwrap();
        (env, current.node_id(), new.node_id())
    }

    #[test]
    fn verify_accepts_valid_dual_signed_rotation() {
        let (env, current_pubkey, _) = valid_envelope();
        env.verify(&current_pubkey, &ChainId::TEST).unwrap();
    }

    #[test]
    fn verify_rejects_when_sig_old_is_zeroed() {
        // Zeroed signature stands in for "missing" in a wire format that
        // can't actually omit the field — postcard always serializes both.
        let (mut env, current_pubkey, _) = valid_envelope();
        env.sig_old = [0u8; 64];
        assert_eq!(
            env.verify(&current_pubkey, &ChainId::TEST),
            Err(RotationVerifyError::InvalidOldSignature)
        );
    }

    #[test]
    fn verify_rejects_when_sig_new_is_zeroed() {
        let (mut env, current_pubkey, _) = valid_envelope();
        env.sig_new = [0u8; 64];
        assert_eq!(
            env.verify(&current_pubkey, &ChainId::TEST),
            Err(RotationVerifyError::InvalidNewSignature)
        );
    }

    #[test]
    fn verify_rejects_when_sig_old_is_signed_by_unrelated_key() {
        // "Signed only by the new key" maps to: sig_old slot contains
        // some valid Ed25519 signature, just not one produced by the
        // validator's current key. Use a third unrelated signer so we're
        // exercising the verification check, not the equality check.
        let (env, current_pubkey, _) = valid_envelope();
        let attacker = fresh_signer();
        let bytes = preimage::<ValidatorKeyRotation>(&env.payload, &ChainId::TEST).unwrap();
        let mut tampered = env;
        tampered.sig_old = attacker.sign(&bytes);
        assert_eq!(
            tampered.verify(&current_pubkey, &ChainId::TEST),
            Err(RotationVerifyError::InvalidOldSignature)
        );
    }

    #[test]
    fn verify_rejects_when_sig_new_is_signed_by_unrelated_key() {
        // Mirror of the previous case: "signed only by the old key".
        let (env, current_pubkey, _) = valid_envelope();
        let attacker = fresh_signer();
        let bytes = preimage::<ValidatorKeyRotation>(&env.payload, &ChainId::TEST).unwrap();
        let mut tampered = env;
        tampered.sig_new = attacker.sign(&bytes);
        assert_eq!(
            tampered.verify(&current_pubkey, &ChainId::TEST),
            Err(RotationVerifyError::InvalidNewSignature)
        );
    }

    #[test]
    fn verify_rejects_when_sig_new_covers_different_payload() {
        // Both signatures must cover the same canonical encoding. If
        // sig_new is a real signature by new_pubkey but over a *different*
        // payload (different v_eff in this case), it must not verify
        // against the envelope's payload.
        let current = fresh_signer();
        let new = fresh_signer();
        let payload = ValidatorKeyRotation {
            validator: current.node_id(),
            new_pubkey: new.node_id(),
            v_eff: 100,
            new_bls_pubkey: None,
            new_bls_pop: None,
        };
        let other_payload = ValidatorKeyRotation {
            v_eff: 999,
            ..payload.clone()
        };
        let other_bytes = preimage::<ValidatorKeyRotation>(&other_payload, &ChainId::TEST).unwrap();
        let bad_sig_new = new.sign(&other_bytes);
        let bytes = preimage::<ValidatorKeyRotation>(&payload, &ChainId::TEST).unwrap();
        let env = DualSignedRotation {
            payload,
            sig_old: current.sign(&bytes),
            sig_new: bad_sig_new,
        };
        assert_eq!(
            env.verify(&current.node_id(), &ChainId::TEST),
            Err(RotationVerifyError::InvalidNewSignature)
        );
    }

    #[test]
    fn verify_rejects_when_caller_supplies_wrong_current_pubkey() {
        // Even with a perfectly valid envelope, verifying against the
        // wrong "current" key (e.g. the caller resolved a stale validator
        // set) must fail — never succeed by silently treating the
        // envelope's own claim as authoritative.
        let (env, _, _) = valid_envelope();
        let unrelated = fresh_signer();
        assert_eq!(
            env.verify(&unrelated.node_id(), &ChainId::TEST),
            Err(RotationVerifyError::InvalidOldSignature)
        );
    }

    /// Cross-deployment replay rejection for rotation envelopes (#324):
    /// a [`DualSignedRotation`] minted under chain_id A must not verify
    /// against chain_id B even when both signatures are real and the
    /// payload bytes are byte-identical. Without the chain_id mix-in
    /// an attacker could capture a rotation tx from a testnet and
    /// replay it against mainnet to roll the legitimate operator's
    /// consensus key forward to whatever `new_pubkey` the testnet
    /// rotation chose.
    #[test]
    fn verify_rejects_cross_chain_rotation_replay() {
        let chain_a = ChainId([0xAA; 32]);
        let chain_b = ChainId([0xBB; 32]);
        let current = fresh_signer();
        let new = fresh_signer();
        let payload = ValidatorKeyRotation {
            validator: current.node_id(),
            new_pubkey: new.node_id(),
            v_eff: 100,
            new_bls_pubkey: None,
            new_bls_pop: None,
        };
        let env = DualSignedRotation::sign(payload, &current, &new, &chain_a).unwrap();

        // Verifying under chain A succeeds (sanity).
        env.verify(&current.node_id(), &chain_a).unwrap();
        // Verifying under chain B fails — the chain_id mix-in changed
        // the bytes both signers signed under, so neither real
        // signature reproduces against the chain-B pre-image. The
        // verifier reports `sig_old` first because that's the fixed
        // check order in `DualSignedRotation::verify`.
        assert_eq!(
            env.verify(&current.node_id(), &chain_b),
            Err(RotationVerifyError::InvalidOldSignature),
        );
    }

    #[test]
    fn verify_rejects_when_payload_is_tampered_post_signing() {
        // Bumping v_eff after both signatures are produced makes both
        // signatures invalid (they cover the original v_eff). The
        // verifier reports the *first* failure in fixed order — sig_old —
        // which is enough to reject; we just want to confirm the bare
        // payload cannot pass through unchecked.
        let (mut env, current_pubkey, _) = valid_envelope();
        env.payload.v_eff = env.payload.v_eff.wrapping_add(1);
        assert!(matches!(
            env.verify(&current_pubkey, &ChainId::TEST),
            Err(RotationVerifyError::InvalidOldSignature)
        ));
    }

    #[test]
    fn verify_rejects_when_new_pubkey_field_is_swapped() {
        // The verifier reads new_pubkey out of the payload to know what
        // key to check sig_new against. Rewriting that field after
        // signing must invalidate the sig (because either the pre-image
        // changed too, breaking sig_old; or — more interesting — the new
        // field doesn't match the actual signer of sig_new).
        let (mut env, current_pubkey, _) = valid_envelope();
        let attacker = fresh_signer();
        env.payload.new_pubkey = attacker.node_id();
        // sig_old was over the original new_pubkey, so it now fails first.
        assert!(matches!(
            env.verify(&current_pubkey, &ChainId::TEST),
            Err(RotationVerifyError::InvalidOldSignature)
        ));
    }

    #[test]
    fn sign_rejects_mismatched_new_signer() {
        // Constructor guard: caller passed a `new` signer whose pubkey
        // doesn't match payload.new_pubkey. Producing the envelope would
        // succeed but the resulting sig_new could never verify, so we
        // fail loudly at sign time instead.
        let current = fresh_signer();
        let new = fresh_signer();
        let wrong_new = fresh_signer();
        let payload = ValidatorKeyRotation {
            validator: current.node_id(),
            new_pubkey: new.node_id(),
            v_eff: 100,
            new_bls_pubkey: None,
            new_bls_pop: None,
        };
        let err =
            DualSignedRotation::sign(payload, &current, &wrong_new, &ChainId::TEST).unwrap_err();
        assert!(format!("{err}").contains("new signer's node_id does not match"));
    }

    #[test]
    fn sign_envelope_round_trips_through_postcard_and_still_verifies() {
        // End-to-end: real signatures survive the wire encoding both
        // structurally and cryptographically.
        let (env, current_pubkey, _) = valid_envelope();
        let bytes = postcard::to_stdvec(&env).unwrap();
        let back: DualSignedRotation = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, env);
        back.verify(&current_pubkey, &ChainId::TEST).unwrap();
    }

    #[test]
    fn payload_changes_alter_serialization() {
        // Structural sanity: the three fields each contribute distinct
        // bytes to the encoding, so a downstream signature scheme
        // covering the postcard bytes will detect tampering with any
        // single field.
        let base = sample_payload();
        let base_bytes = postcard::to_stdvec(&base).unwrap();

        let mut a = base.clone();
        a.validator[0] ^= 1;
        assert_ne!(postcard::to_stdvec(&a).unwrap(), base_bytes);

        let mut b = base.clone();
        b.new_pubkey[0] ^= 1;
        assert_ne!(postcard::to_stdvec(&b).unwrap(), base_bytes);

        let mut c = base.clone();
        c.v_eff = c.v_eff.wrapping_add(1);
        assert_ne!(postcard::to_stdvec(&c).unwrap(), base_bytes);
    }

    // ── validate_scheme_consistency (#358) ───────────────────────────────

    fn bls_keypair(
        seed: u8,
    ) -> (
        crate::crypto::sig_scheme::BlsSecretKey,
        crate::crypto::sig_scheme::BlsPublicKey,
    ) {
        let mut ikm = [0u8; 32];
        ikm[0] = seed;
        BlsAggregated::keygen(&ikm).expect("test BLS keygen")
    }

    #[test]
    fn validate_scheme_consistency_ed25519_chain_accepts_no_bls_fields() {
        let p = sample_payload();
        assert_eq!(
            p.validate_scheme_consistency(SignatureSchemeChoice::Ed25519Collected),
            Ok(())
        );
    }

    #[test]
    fn validate_scheme_consistency_ed25519_chain_rejects_bls_pubkey_present() {
        let (_sk, pk) = bls_keypair(0xA0);
        let mut p = sample_payload();
        p.new_bls_pubkey = Some(pk);
        let err = p
            .validate_scheme_consistency(SignatureSchemeChoice::Ed25519Collected)
            .unwrap_err();
        assert!(matches!(
            err,
            RotationStructuralError::BlsFieldsInconsistentWithScheme {
                scheme: SignatureSchemeChoice::Ed25519Collected,
                bls_pubkey_present: true,
                bls_pop_present: false,
            }
        ));
    }

    #[test]
    fn validate_scheme_consistency_ed25519_chain_rejects_bls_pop_present() {
        let (sk, _pk) = bls_keypair(0xA1);
        let pop = BlsAggregated::sign_pop(&sk).unwrap();
        let mut p = sample_payload();
        p.new_bls_pop = Some(pop);
        let err = p
            .validate_scheme_consistency(SignatureSchemeChoice::Ed25519Collected)
            .unwrap_err();
        assert!(matches!(
            err,
            RotationStructuralError::BlsFieldsInconsistentWithScheme {
                bls_pubkey_present: false,
                bls_pop_present: true,
                ..
            }
        ));
    }

    #[test]
    fn validate_scheme_consistency_bls_chain_accepts_valid_pop() {
        let (sk, pk) = bls_keypair(0xB0);
        let pop = BlsAggregated::sign_pop(&sk).unwrap();
        let mut p = sample_payload();
        p.new_bls_pubkey = Some(pk);
        p.new_bls_pop = Some(pop);
        assert_eq!(
            p.validate_scheme_consistency(SignatureSchemeChoice::BlsAggregated),
            Ok(())
        );
    }

    #[test]
    fn validate_scheme_consistency_bls_chain_rejects_missing_bls_pubkey() {
        let p = sample_payload();
        let err = p
            .validate_scheme_consistency(SignatureSchemeChoice::BlsAggregated)
            .unwrap_err();
        assert!(matches!(
            err,
            RotationStructuralError::BlsFieldsInconsistentWithScheme {
                scheme: SignatureSchemeChoice::BlsAggregated,
                bls_pubkey_present: false,
                ..
            }
        ));
    }

    #[test]
    fn validate_scheme_consistency_bls_chain_rejects_missing_pop() {
        let (_sk, pk) = bls_keypair(0xB1);
        let mut p = sample_payload();
        p.new_bls_pubkey = Some(pk);
        let err = p
            .validate_scheme_consistency(SignatureSchemeChoice::BlsAggregated)
            .unwrap_err();
        assert!(matches!(
            err,
            RotationStructuralError::BlsFieldsInconsistentWithScheme {
                scheme: SignatureSchemeChoice::BlsAggregated,
                bls_pubkey_present: true,
                bls_pop_present: false,
            }
        ));
    }

    #[test]
    fn validate_scheme_consistency_bls_chain_rejects_pop_under_wrong_pubkey() {
        // Rotator supplies a PoP signed by sk_a but claims a different
        // BLS pubkey pk_b. Caught by `BlsAggregated::verify_pop`'s
        // PopPubkeyMismatch check, surfaced here as
        // `BlsPopVerificationFailed`. Same rogue-key-attack defense
        // the registration path runs (#291).
        let (sk_a, _pk_a) = bls_keypair(0xC0);
        let (_sk_b, pk_b) = bls_keypair(0xC1);
        let pop_under_a = BlsAggregated::sign_pop(&sk_a).unwrap();
        let mut p = sample_payload();
        p.new_bls_pubkey = Some(pk_b);
        p.new_bls_pop = Some(pop_under_a);
        let err = p
            .validate_scheme_consistency(SignatureSchemeChoice::BlsAggregated)
            .unwrap_err();
        assert!(matches!(
            err,
            RotationStructuralError::BlsPopVerificationFailed
        ));
    }

    #[test]
    fn validate_scheme_consistency_bls_chain_rejects_tampered_pop_signature() {
        let (sk, pk) = bls_keypair(0xD0);
        let mut pop = BlsAggregated::sign_pop(&sk).unwrap();
        pop.sig[0] ^= 0xFF;
        let mut p = sample_payload();
        p.new_bls_pubkey = Some(pk);
        p.new_bls_pop = Some(pop);
        let err = p
            .validate_scheme_consistency(SignatureSchemeChoice::BlsAggregated)
            .unwrap_err();
        assert!(matches!(
            err,
            RotationStructuralError::BlsPopVerificationFailed
        ));
    }

    #[test]
    fn rotation_with_bls_fields_round_trips_through_postcard() {
        // Wire-format sanity: the new optional BLS fields encode +
        // decode via the `serde_optional_bls_pubkey` adapter and the
        // existing `BlsPop` serde modules. Catches a layout regression
        // in either path before the payload ever reaches a chain.
        let (sk, pk) = bls_keypair(0xE0);
        let pop = BlsAggregated::sign_pop(&sk).unwrap();
        let mut p = sample_payload();
        p.new_bls_pubkey = Some(pk);
        p.new_bls_pop = Some(pop);
        let bytes = postcard::to_stdvec(&p).unwrap();
        let back: ValidatorKeyRotation = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, p);
    }
}
