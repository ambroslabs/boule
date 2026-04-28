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
//! Type definition, postcard codec, and structural well-formedness checks
//! (rejecting an effective view that gives the validator no time to
//! provision the new key, and rotations that don't actually change the
//! key). Cryptographic verification of the two signatures lives in a
//! follow-up (issue #258); per-view key resolution against historical QCs
//! lives in #259.

use serde::{Deserialize, Serialize};

use crate::consensus::View;
use crate::crypto::signed::SignedMessage;
use crate::p2p::NodeId;

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorKeyRotation {
    pub validator: NodeId,
    pub new_pubkey: NodeId,
    pub v_eff: View,
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
    EffectiveViewTooSoon { current_view: View, v_eff: View },
    NewKeyEqualsValidator,
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

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn sample_payload() -> ValidatorKeyRotation {
        ValidatorKeyRotation {
            validator: nid(1),
            new_pubkey: nid(2),
            v_eff: 100,
        }
    }

    fn sample_envelope() -> DualSignedRotation {
        DualSignedRotation {
            payload: sample_payload(),
            sig_old: [0xAA; 64],
            sig_new: [0xBB; 64],
        }
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
        };
        assert!(p.validate_structural(10).is_ok());
    }

    #[test]
    fn validate_structural_accepts_far_future() {
        let p = ValidatorKeyRotation {
            validator: nid(1),
            new_pubkey: nid(2),
            v_eff: u64::MAX,
        };
        assert!(p.validate_structural(0).is_ok());
    }

    #[test]
    fn validate_structural_rejects_one_view_ahead() {
        let p = ValidatorKeyRotation {
            validator: nid(1),
            new_pubkey: nid(2),
            v_eff: 11,
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
}
