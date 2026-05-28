//! Signed message envelopes using the node's long-term Ed25519 identity.
//!
//! # Why this exists
//!
//! Our TLS transport (`src/p2p/tls.rs`) authenticates a *hop*: the direct
//! peer we are speaking to. Consensus messages (votes, proposals) are
//! forwarded through intermediaries and persisted to disk, and must be
//! verifiable by parties that never held the original TLS session. We
//! therefore sign them at the application layer using the same Ed25519
//! node key that backs the TLS identity.
//!
//! # Pre-image
//!
//! Signatures are produced over a canonical byte string, NOT the wire
//! representation of the envelope. That pre-image is:
//!
//! ```text
//! chain_id || be_u32(|domain|) || domain || postcard(payload)
//! ```
//!
//! The domain tag is fixed per payload type via [`SignedMessage::DOMAIN`],
//! preventing a signature produced in one context from being replayed in
//! another (e.g. a vote signature reinterpreted as a proposal signature).
//! The 32-byte [`ChainId`] is fixed per deployment (see #324, audit
//! finding 7-F1) and prevents cross-deployment signature replay: an
//! Ed25519 keypair shared between two chains can no longer have
//! identically-shaped vote/proposal/timeout/rotation payloads accepted
//! across deployments. The ChainId is not length-prefixed — it is a
//! fixed-size 32-byte tag, so no ambiguity is possible at the boundary.
//!
//! Postcard is deterministic for the fixed-shape payloads we sign —
//! structs, enums, primitives, arrays. Callers should avoid payloads
//! whose serialization is order-dependent (e.g. `HashMap`); prefer
//! `BTreeMap` or explicit sequences.

use anyhow::{Context as _, Result, bail};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

use crate::crypto::sig_scheme::SignatureScheme;
use crate::identity::NodeId;
use crate::identity::NodeIdentity;

/// A key that can produce Ed25519 signatures over arbitrary byte strings.
///
/// Split out from the concrete [`NodeSigner`] so tests can substitute a
/// fake and so a future non-exportable backend (HSM / TPM / TEE) can plug
/// in without touching call sites.
///
/// The `Send + Sync` bounds allow `Arc<dyn Signer>` to be shared across
/// threads and held across await points in the async event loop.
pub trait Signer: Send + Sync {
    fn node_id(&self) -> NodeId;
    fn sign(&self, msg: &[u8]) -> [u8; 64];
}

/// Signer backed by the node's long-term Ed25519 identity key.
pub struct NodeSigner {
    node_id: NodeId,
    key: Ed25519KeyPair,
}

impl NodeSigner {
    /// Build a signer from a loaded [`NodeIdentity`] (PKCS#8 DER bytes).
    pub fn from_identity(identity: &NodeIdentity) -> Result<Self> {
        let key = Ed25519KeyPair::from_pkcs8_maybe_unchecked(&identity.pkcs8_der)
            .map_err(|e| anyhow::anyhow!("parsing node key as Ed25519 PKCS#8: {e}"))?;
        let node_id: NodeId = key
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected 32-byte Ed25519 public key"))?;
        Ok(Self { node_id, key })
    }
}

impl Signer for NodeSigner {
    fn node_id(&self) -> NodeId {
        self.node_id
    }

    fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let sig = self.key.sign(msg);
        let mut out = [0u8; 64];
        out.copy_from_slice(sig.as_ref());
        out
    }
}

/// A key that can produce one validator's contribution to a
/// QC-flavored aggregate, parameterized over the chain's
/// [`SignatureScheme`].
///
/// Distinct from [`Signer`] because the two cover different layers:
///
/// * [`Signer`] signs the **envelope** around every consensus message
///   (votes/proposals/new-views) using the validator's long-term Ed25519
///   network identity. Always returns `[u8; 64]`.
/// * [`PartialSigner<S>`] signs the **vote pre-image** that the leader
///   will fold into a QC aggregate. The shape of the partial is dictated
///   by the chain's scheme: `[u8; 64]` under
///   [`Ed25519Collected`](crate::crypto::sig_scheme::Ed25519Collected)
///   (a re-export of the envelope sig), `[u8; 96]` under
///   [`BlsAggregated`](crate::crypto::sig_scheme::BlsAggregated).
///
/// Keeping the two traits separate lets the network identity stay
/// Ed25519-only forever (TLS handshake, peer-id) while the QC scheme
/// is swappable per chain at genesis (#287, #288).
pub trait PartialSigner<S: SignatureScheme>: Send + Sync {
    /// The validator's public key under the chain's scheme. Used at
    /// `BlsKeyHistory::register` time and for client-side
    /// `verify_partial` round-trips in tests.
    fn pubkey(&self) -> S::PublicKey;

    /// Produce one validator's contribution to a QC aggregate over
    /// `msg`. Callers should pass `postcard(Vote { view, block_hash })`
    /// — the same pre-image the verifier will reconstruct.
    fn sign_partial(&self, msg: &[u8]) -> S::PartialSig;
}

/// 32-byte deployment-scoped identifier mixed into every signing
/// pre-image (issue #324, audit finding 7-F1).
///
/// A `ChainId` is defined at network-genesis time and never changes for
/// the life of the chain. The recommended construction is
/// `ChainId(genesis_block.hash())` — that ties the deployment's
/// identity to its genesis bytes, so a fork that changes any field of
/// the genesis block becomes a distinct chain by definition. Two
/// deployments that happen to share a validator key cannot accept the
/// same signed payload across their boundary, because the signing
/// pre-image differs in the leading 32 bytes.
///
/// `ChainId` is fixed-size and not length-prefixed in the pre-image.
/// Sign/verify symmetry requires that every honest participant on a
/// deployment use the same value; misconfiguration manifests as
/// "every signature fails" rather than as silent cross-chain replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChainId(pub [u8; 32]);

impl ChainId {
    /// Build a `ChainId` from the canonical genesis block hash. Pass
    /// `genesis_block.hash()` — see the type-level comment for why
    /// genesis bytes are the right binding.
    pub const fn from_genesis_hash(hash: [u8; 32]) -> Self {
        Self(hash)
    }

    /// Borrow the 32-byte tag.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
impl ChainId {
    /// Test sentinel: an all-zero `ChainId`. Gated to `cfg(test)` so a
    /// production deployment cannot accidentally select the all-zero
    /// chain id (which would be replay-compatible with every other
    /// deployment that did the same). Production callers must derive
    /// their `ChainId` from the genesis block via [`from_genesis_hash`].
    pub const TEST: Self = Self([0u8; 32]);
}

/// Payloads that can be placed inside a [`Signed`] envelope.
///
/// The associated `DOMAIN` string is mixed into the signing pre-image so
/// signatures produced for one message kind cannot be re-used as another.
/// Choose a stable, type-unique value (e.g. `"boule.vote.v1"`).
pub trait SignedMessage {
    const DOMAIN: &'static str;
}

/// Application-level signature envelope over a payload `T`.
///
/// Verifiable by any party that knows the claimed signer's [`NodeId`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed<T> {
    pub payload: T,
    pub signer: NodeId,
    #[serde(with = "serde_sig")]
    pub sig: [u8; 64],
}

impl<T> Signed<T>
where
    T: Serialize + SignedMessage,
{
    /// Produce a signed envelope over `payload`, scoped to `chain_id`.
    ///
    /// The 32-byte `chain_id` is mixed into the signing pre-image
    /// (#324) so a signature produced on one deployment cannot be
    /// replayed on another even if the same `NodeId` is in both
    /// validator sets. Callers should pass the same `ChainId`
    /// everywhere within one deployment — typically derived once at
    /// startup from the genesis block hash.
    ///
    /// # Example
    ///
    /// Sign and verify a consensus-style payload. The domain separator on
    /// `SignedMessage` makes a signature produced for `Vote` distinct from
    /// any other type, even when the byte layout happens to match.
    ///
    /// ```
    /// use boule::crypto::signed::{ChainId, NodeSigner, Signed, SignedMessage, Signer};
    /// use boule::identity::NodeIdentity;
    /// use rcgen::{KeyPair, PKCS_ED25519};
    /// use serde::{Deserialize, Serialize};
    /// use zeroize::Zeroizing;
    ///
    /// #[derive(Serialize, Deserialize, PartialEq, Debug)]
    /// struct Vote { round: u64, block_hash: [u8; 32] }
    ///
    /// impl SignedMessage for Vote {
    ///     const DOMAIN: &'static str = "example.vote.v1";
    /// }
    ///
    /// let kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    /// let identity = NodeIdentity { pkcs8_der: Zeroizing::new(kp.serialize_der()) };
    /// let signer = NodeSigner::from_identity(&identity).unwrap();
    ///
    /// let vote = Vote { round: 7, block_hash: [0xAB; 32] };
    /// let chain_id = ChainId([0x42; 32]);
    /// let signed = Signed::sign(vote, &signer, &chain_id).unwrap();
    ///
    /// signed.verify(&signer.node_id(), &chain_id).unwrap();
    /// ```
    pub fn sign<S: Signer + ?Sized>(payload: T, signer: &S, chain_id: &ChainId) -> Result<Self> {
        let bytes = preimage::<T>(&payload, chain_id)?;
        let sig = signer.sign(&bytes);
        Ok(Self {
            payload,
            signer: signer.node_id(),
            sig,
        })
    }

    /// Verify the signature against an *explicitly claimed* [`NodeId`]
    /// under `chain_id`.
    ///
    /// Returns `Ok(())` only if all three hold:
    /// 1. `self.signer == *expected_signer` (no implicit trust in the envelope's own claim),
    /// 2. `self.sig` is a valid Ed25519 signature over the domain-separated pre-image of `payload`
    ///    bound to `chain_id` under `expected_signer`,
    /// 3. the pre-image can be reproduced (re-serialization succeeds).
    ///
    /// A signature minted for a different `chain_id` fails step 2 even
    /// if the payload bytes are byte-identical (#324).
    pub fn verify(&self, expected_signer: &NodeId, chain_id: &ChainId) -> Result<()> {
        if &self.signer != expected_signer {
            bail!("signer mismatch: envelope claims a different NodeId");
        }
        let bytes = preimage::<T>(&self.payload, chain_id)?;
        UnparsedPublicKey::new(&ED25519, expected_signer as &[u8])
            .verify(&bytes, &self.sig)
            .map_err(|_| anyhow::anyhow!("signature verification failed"))
    }
}

/// Canonical signing pre-image:
/// `chain_id || be_u32(|domain|) || domain || postcard(payload)`.
///
/// Exposed at crate visibility so envelopes that carry more than one
/// signature over the same payload (e.g. the dual-signed validator-key
/// rotation tx in [`crate::consensus::validator_rotation`]) and
/// off-envelope signatures over the same payload (the per-signer
/// partial signatures aggregated into a [`crate::consensus::hotstuff::qc::QuorumCertificate`])
/// reuse this exact framing instead of duplicating it. Reusing the
/// helper keeps a single source of truth for "what bytes are signed".
///
/// The `chain_id` is the 32-byte deployment-scoped tag from #324; see
/// the module-level docs.
pub(crate) fn preimage<T: Serialize + SignedMessage>(
    payload: &T,
    chain_id: &ChainId,
) -> Result<Vec<u8>> {
    let domain = T::DOMAIN.as_bytes();
    if domain.len() > u32::MAX as usize {
        bail!("domain tag too long");
    }
    let body = postcard::to_stdvec(payload).context("serializing payload for signing")?;
    let mut out = Vec::with_capacity(32 + 4 + domain.len() + body.len());
    out.extend_from_slice(chain_id.as_bytes());
    out.extend_from_slice(&(domain.len() as u32).to_be_bytes());
    out.extend_from_slice(domain);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Serialize a 64-byte signature as a byte sequence rather than as 64
/// individually-serialized `u8`s. That keeps the encoding compact in both
/// bincode (same either way) and any non-binary format we might use later
/// for debug dumps (JSON: `[u8; 64]` becomes a 64-element array, with
/// `serde_bytes` semantics it stays a hex/b64 blob in human formats).
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
    use rcgen::{KeyPair as RcgenKeyPair, PKCS_ED25519};
    use zeroize::Zeroizing;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    struct Vote {
        round: u64,
        block_hash: [u8; 32],
    }

    impl SignedMessage for Vote {
        const DOMAIN: &'static str = "boule.test.vote.v1";
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    struct Proposal {
        round: u64,
        block_hash: [u8; 32],
    }

    impl SignedMessage for Proposal {
        const DOMAIN: &'static str = "boule.test.proposal.v1";
    }

    fn fresh_signer() -> NodeSigner {
        let kp = RcgenKeyPair::generate_for(&PKCS_ED25519).unwrap();
        let id = NodeIdentity {
            pkcs8_der: Zeroizing::new(kp.serialize_der()),
        };
        NodeSigner::from_identity(&id).unwrap()
    }

    #[test]
    fn node_signer_id_matches_identity_pubkey() {
        let kp = RcgenKeyPair::generate_for(&PKCS_ED25519).unwrap();
        let expected: NodeId = kp.public_key_raw().try_into().unwrap();
        let id = NodeIdentity {
            pkcs8_der: Zeroizing::new(kp.serialize_der()),
        };
        let signer = NodeSigner::from_identity(&id).unwrap();
        assert_eq!(signer.node_id(), expected);
    }

    #[test]
    fn sign_verify_round_trip_through_postcard() {
        let signer = fresh_signer();
        let vote = Vote {
            round: 42,
            block_hash: [0xAB; 32],
        };
        let signed = Signed::sign(vote.clone(), &signer, &ChainId::TEST).unwrap();

        // Serialize the envelope, deserialize it, verify on the reconstructed copy.
        let wire = postcard::to_stdvec(&signed).unwrap();
        let recovered: Signed<Vote> = postcard::from_bytes(&wire).unwrap();

        assert_eq!(recovered.payload, vote);
        assert_eq!(recovered.signer, signer.node_id());
        recovered.verify(&signer.node_id(), &ChainId::TEST).unwrap();
    }

    #[test]
    fn tampered_payload_rejected() {
        let signer = fresh_signer();
        let mut signed = Signed::sign(
            Vote {
                round: 1,
                block_hash: [1; 32],
            },
            &signer,
            &ChainId::TEST,
        )
        .unwrap();

        signed.payload.round = 999;

        let err = signed
            .verify(&signer.node_id(), &ChainId::TEST)
            .unwrap_err();
        assert!(format!("{err}").contains("signature verification failed"));
    }

    #[test]
    fn tampered_signature_rejected() {
        let signer = fresh_signer();
        let mut signed = Signed::sign(
            Vote {
                round: 1,
                block_hash: [1; 32],
            },
            &signer,
            &ChainId::TEST,
        )
        .unwrap();

        signed.sig[0] ^= 0x01;

        let err = signed
            .verify(&signer.node_id(), &ChainId::TEST)
            .unwrap_err();
        assert!(format!("{err}").contains("signature verification failed"));
    }

    #[test]
    fn verify_rejects_wrong_claimed_signer() {
        let alice = fresh_signer();
        let bob = fresh_signer();
        let signed = Signed::sign(
            Vote {
                round: 7,
                block_hash: [7; 32],
            },
            &alice,
            &ChainId::TEST,
        )
        .unwrap();

        // Passing bob's NodeId as the expected signer must fail even though the
        // signature is real — it's real for alice, not bob.
        let err = signed.verify(&bob.node_id(), &ChainId::TEST).unwrap_err();
        assert!(format!("{err}").contains("signer mismatch"));
    }

    #[test]
    fn envelope_with_forged_signer_claim_rejected() {
        let alice = fresh_signer();
        let bob = fresh_signer();
        let mut signed = Signed::sign(
            Vote {
                round: 9,
                block_hash: [9; 32],
            },
            &alice,
            &ChainId::TEST,
        )
        .unwrap();

        // Attacker rewrites the envelope to claim bob signed it, keeping alice's sig.
        signed.signer = bob.node_id();
        let err = signed.verify(&bob.node_id(), &ChainId::TEST).unwrap_err();
        assert!(format!("{err}").contains("signature verification failed"));
    }

    /// Cross-deployment replay rejection (issue #324, audit finding 7-F1):
    /// a vote signed under `chain_id` A does not verify against a verifier
    /// configured for `chain_id` B, even when the payload bytes are
    /// byte-identical and the signer's `NodeId` is in both deployments'
    /// validator sets. This is the property the new pre-image segment
    /// exists to enforce.
    #[test]
    fn chain_id_separation_prevents_cross_deployment_replay() {
        let signer = fresh_signer();
        let chain_a = ChainId([0xAA; 32]);
        let chain_b = ChainId([0xBB; 32]);

        let vote = Vote {
            round: 11,
            block_hash: [0x11; 32],
        };
        let signed_on_a = Signed::sign(vote.clone(), &signer, &chain_a).unwrap();

        // Same envelope bytes — verifier on chain B rejects.
        let err = signed_on_a.verify(&signer.node_id(), &chain_b).unwrap_err();
        assert!(
            format!("{err}").contains("signature verification failed"),
            "cross-chain replay must fail at the signature check, got {err}",
        );

        // Sanity: verification under the original chain_id still works.
        signed_on_a.verify(&signer.node_id(), &chain_a).unwrap();

        // Hand-craft a "Signed<Vote>" that copies the chain-A signature
        // and claims to be on chain B — i.e. a literal replay attempt
        // by an attacker who saw an honest A-vote and re-broadcasts it
        // to a B replica. The B replica must reject. This stresses the
        // fact that the chain_id is only present in the *pre-image*,
        // not on the wire — an attacker cannot rewrite a single field
        // to launder the signature.
        let replay: Signed<Vote> = Signed {
            payload: vote.clone(),
            signer: signed_on_a.signer,
            sig: signed_on_a.sig,
        };
        assert!(
            replay.verify(&signer.node_id(), &chain_b).is_err(),
            "a verbatim replay of an A-chain vote must not verify under chain B",
        );
    }

    #[test]
    fn domain_separation_prevents_cross_type_replay() {
        let signer = fresh_signer();

        let vote = Vote {
            round: 3,
            block_hash: [3; 32],
        };
        let signed_vote = Signed::sign(vote.clone(), &signer, &ChainId::TEST).unwrap();

        // Hand-craft a Signed<Proposal> that reuses the signature from the Vote.
        // Even though the struct layouts are identical, the domain separator
        // ("boule.test.vote.v1" vs "boule.test.proposal.v1") makes the
        // pre-images different, so the signature must not verify.
        let forged: Signed<Proposal> = Signed {
            payload: Proposal {
                round: vote.round,
                block_hash: vote.block_hash,
            },
            signer: signed_vote.signer,
            sig: signed_vote.sig,
        };

        let err = forged
            .verify(&signer.node_id(), &ChainId::TEST)
            .unwrap_err();
        assert!(format!("{err}").contains("signature verification failed"));
    }

    #[test]
    fn randomized_untampered_messages_all_verify() {
        // Property-ish: many random payloads sign/verify cleanly, and a single
        // bit flip anywhere in the envelope breaks verification.
        use rand::Rng as _;
        let signer = fresh_signer();
        let mut rng = rand::rng();

        for _ in 0..64 {
            let payload = Vote {
                round: rng.random(),
                block_hash: rng.random(),
            };
            let signed = Signed::sign(payload, &signer, &ChainId::TEST).unwrap();
            signed.verify(&signer.node_id(), &ChainId::TEST).unwrap();

            let mut tampered = signed.clone();
            tampered.payload.round = tampered.payload.round.wrapping_add(1);
            assert!(tampered.verify(&signer.node_id(), &ChainId::TEST).is_err());
        }
    }

    // ── Property tests (issue #52) ──────────────────────────────────────────

    use proptest::prelude::*;
    use std::sync::OnceLock;

    fn shared_signer() -> &'static NodeSigner {
        static SIGNER: OnceLock<NodeSigner> = OnceLock::new();
        SIGNER.get_or_init(fresh_signer)
    }

    fn shared_other_signer() -> &'static NodeSigner {
        static OTHER: OnceLock<NodeSigner> = OnceLock::new();
        OTHER.get_or_init(fresh_signer)
    }

    proptest! {
        // Any structurally valid Vote signs and then verifies under the same
        // NodeId. Catches accidental non-determinism in the pre-image (domain
        // framing, postcard output) that hand-written inputs wouldn't hit.
        #[test]
        fn prop_sign_verify_round_trip(round in any::<u64>(), hash in any::<[u8; 32]>()) {
            let signer = shared_signer();
            let vote = Vote { round, block_hash: hash };
            let signed = Signed::sign(vote.clone(), signer, &ChainId::TEST).unwrap();
            signed.verify(&signer.node_id(), &ChainId::TEST).unwrap();

            let wire = postcard::to_stdvec(&signed).unwrap();
            let back: Signed<Vote> = postcard::from_bytes(&wire).unwrap();
            prop_assert_eq!(&back.payload, &vote);
            prop_assert_eq!(back.signer, signer.node_id());
            back.verify(&signer.node_id(), &ChainId::TEST).unwrap();
        }

        // Any random 64-byte "signature" other than one the real signer would
        // produce must fail verification. We can't exclude the (astronomically
        // unlikely) real signature, so we only reject forgeries that are also
        // not the genuine signature for this payload.
        #[test]
        fn prop_forged_signature_rejected(
            round in any::<u64>(),
            hash in any::<[u8; 32]>(),
            forged in any::<[u8; 64]>(),
        ) {
            let signer = shared_signer();
            let vote = Vote { round, block_hash: hash };
            let real = Signed::sign(vote.clone(), signer, &ChainId::TEST).unwrap();
            prop_assume!(forged != real.sig);

            let tampered = Signed::<Vote> { payload: vote, signer: signer.node_id(), sig: forged };
            prop_assert!(tampered.verify(&signer.node_id(), &ChainId::TEST).is_err());
        }

        // A signature produced by one signer must not verify under a different
        // claimed signer, even when the claim on the envelope is rewritten to
        // match the verifier.
        #[test]
        fn prop_cross_signer_rejected(round in any::<u64>(), hash in any::<[u8; 32]>()) {
            let alice = shared_signer();
            let bob = shared_other_signer();
            prop_assume!(alice.node_id() != bob.node_id());

            let vote = Vote { round, block_hash: hash };
            let mut signed = Signed::sign(vote, alice, &ChainId::TEST).unwrap();

            // Passing bob as expected without rewriting the envelope: mismatch.
            prop_assert!(signed.verify(&bob.node_id(), &ChainId::TEST).is_err());

            // Rewriting the envelope's `signer` claim to bob while keeping
            // alice's signature: the ed25519 check must still fail.
            signed.signer = bob.node_id();
            prop_assert!(signed.verify(&bob.node_id(), &ChainId::TEST).is_err());
        }
    }

    #[test]
    fn sign_verify_latency_bench() {
        // Not a gated benchmark — just logs representative numbers so regressions
        // show up in CI output.
        let signer = fresh_signer();
        let payload = Vote {
            round: 1,
            block_hash: [0; 32],
        };

        let sign_start = std::time::Instant::now();
        let iterations = 200;
        let signed = Signed::sign(payload.clone(), &signer, &ChainId::TEST).unwrap();
        for _ in 0..iterations {
            let _ = Signed::sign(payload.clone(), &signer, &ChainId::TEST).unwrap();
        }
        let sign_avg = sign_start.elapsed() / (iterations + 1);

        let verify_start = std::time::Instant::now();
        for _ in 0..iterations {
            signed.verify(&signer.node_id(), &ChainId::TEST).unwrap();
        }
        let verify_avg = verify_start.elapsed() / iterations;

        eprintln!(
            "Signed<Vote> sign={:?}/op verify={:?}/op",
            sign_avg, verify_avg
        );
    }
}
