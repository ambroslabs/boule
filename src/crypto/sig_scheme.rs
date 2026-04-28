//! Pluggable signature schemes for HotStuff QC aggregation.
//!
//! HotStuff's quorum certificates carry a quorum of validator signatures
//! over a `(view, block_hash)` pair. There are two production-relevant
//! ways to encode that quorum on the wire:
//!
//! - [`Ed25519Collected`]: one raw 64-byte Ed25519 signature per signer
//!   plus a [`SignerBitmap`]. Verification is `O(n)` `ring::ED25519`
//!   verifies. QC wire size scales with the quorum count.
//! - `BlsAggregated` *(future, see #143)*: a single ~96-byte BLS point
//!   aggregating every partial signature. Verification is one pairing
//!   check. QC wire size is constant in `n`.
//!
//! This module establishes the trait surface so both schemes can plug in
//! through the same hooks. For #287 only [`Ed25519Collected`] is
//! implemented and wired through [`QuorumCertificate`]; BLS arrives in
//! #289 onward.
//!
//! # Chain-level scheme selection
//!
//! The signature scheme is fixed at genesis (see #288). Within a chain
//! every validator uses the same scheme, every QC carries one form of
//! aggregate, and switching schemes requires a coordinated chain restart
//! from new genesis. Mixed-scheme chains are out of scope.
//!
//! # Trait shape
//!
//! [`SignatureScheme`] is intentionally narrow: it covers the operations
//! the QC layer needs to *aggregate* and *verify* a quorum of partials.
//! Per-validator partial *signing* still goes through the existing
//! [`Signer`](crate::crypto::signed::Signer) trait — that's enough today
//! because the only scheme is Ed25519, whose partial signature is the
//! same 64 bytes the [`Signer`](crate::crypto::signed::Signer) returns.
//! When BLS lands the signing surface grows to return a scheme-shaped
//! partial; the design note for that work is in #293.
//!
//! [`SignerBitmap`]: crate::consensus::hotstuff::qc::SignerBitmap
//! [`QuorumCertificate`]: crate::consensus::hotstuff::qc::QuorumCertificate

use std::fmt::{self, Debug};

use ring::signature::{ED25519, UnparsedPublicKey};

use crate::consensus::hotstuff::qc::SignerBitmap;
use crate::p2p::NodeId;

/// A pluggable signature scheme for HotStuff QC aggregation.
///
/// Implementations describe how partial signatures combine into a
/// QC-shaped aggregate and how that aggregate is verified against the
/// pubkeys of the signers selected by a [`SignerBitmap`].
pub trait SignatureScheme: 'static {
    /// Single-signer partial signature. For [`Ed25519Collected`] this is
    /// the same `[u8; 64]` returned by
    /// [`Signer::sign`](crate::crypto::signed::Signer::sign).
    ///
    /// `Serialize`/`Deserialize` are intentionally not required at the
    /// trait level — serialization is the QC's concern, and the QC type
    /// applies its own field-level `#[serde(with = ...)]` so types like
    /// `[u8; 64]` (which serde does not auto-derive past `N=32`) work
    /// unchanged.
    type PartialSig: Clone + Debug + Eq + Send + Sync;

    /// Aggregate of partials, as carried inside a QC. For
    /// [`Ed25519Collected`] this is a parallel-on-set-bits
    /// `Vec<PartialSig>`; for BLS it will be a single point.
    type Aggregate: Clone + Debug + Eq + Send + Sync;

    /// Validator public key as registered in the validator set. For
    /// [`Ed25519Collected`] this is the same [`NodeId`] the network
    /// identity uses.
    type PublicKey: Clone + Debug + Eq + Send + Sync;

    /// Stable scheme name. Surfaces in the genesis config (#288) and in
    /// "you booted the wrong scheme" errors at startup.
    const NAME: &'static str;

    /// An empty aggregate that has accumulated zero partials.
    fn empty_aggregate() -> Self::Aggregate;

    /// Fold one partial signature from validator `validator_idx` into
    /// `agg`. `signers_before` is the bitmap *before* `validator_idx` is
    /// flipped on, so collected schemes can compute the parallel
    /// insertion position. The caller flips the bit on `signers` after
    /// this returns. Implementations must be a no-op idempotent if
    /// `signers_before.get(validator_idx)` is already true (collected
    /// schemes simply skip duplicates; aggregating schemes must not
    /// double-count).
    fn add_partial(
        agg: &mut Self::Aggregate,
        signers_before: &SignerBitmap,
        validator_idx: usize,
        partial: Self::PartialSig,
    );

    /// Number of partials currently folded into `agg`. Must equal
    /// `signers.count()` whenever the QC is well-formed.
    fn aggregate_count(agg: &Self::Aggregate) -> usize;

    /// Verify that `agg` is a valid aggregate over `message`, signed by
    /// the validators whose indices are set in `signers`. `pubkeys` is
    /// the *full* validator set's keys for the relevant view; only the
    /// indices set in `signers` are read.
    ///
    /// Implementations must reject:
    /// - bitmap-vs-pubkeys length mismatches,
    /// - aggregates whose internal partial count disagrees with the
    ///   bitmap (collected schemes only),
    /// - aggregates that do not cryptographically verify.
    fn verify_aggregate(
        agg: &Self::Aggregate,
        signers: &SignerBitmap,
        message: &[u8],
        pubkeys: &[Self::PublicKey],
    ) -> Result<(), AggregateVerifyError>;
}

/// Reasons [`SignatureScheme::verify_aggregate`] can refuse a QC's
/// aggregate.
#[derive(Debug, PartialEq, Eq)]
pub enum AggregateVerifyError {
    LengthMismatch {
        bitmap_len: usize,
        pubkeys_len: usize,
    },
    Malformed {
        reason: &'static str,
    },
    InvalidAggregate,
}

impl fmt::Display for AggregateVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AggregateVerifyError::LengthMismatch {
                bitmap_len,
                pubkeys_len,
            } => write!(
                f,
                "bitmap len {bitmap_len} disagrees with pubkeys len {pubkeys_len}",
            ),
            AggregateVerifyError::Malformed { reason } => {
                write!(f, "aggregate is structurally malformed: {reason}")
            }
            AggregateVerifyError::InvalidAggregate => {
                f.write_str("aggregate signature does not verify under the selected pubkeys")
            }
        }
    }
}

impl std::error::Error for AggregateVerifyError {}

/// Collected-Ed25519 scheme: each QC carries one 64-byte signature per
/// signer in a `Vec<[u8; 64]>` parallel to the [`SignerBitmap`].
///
/// This is the scheme HotStuff's reference implementation describes as
/// "Basic HotStuff" — safe and live, but with `O(n)` per-QC verification
/// cost. It is the production default until BLS lands (#143).
pub struct Ed25519Collected;

impl SignatureScheme for Ed25519Collected {
    type PartialSig = [u8; 64];
    type Aggregate = Vec<[u8; 64]>;
    type PublicKey = NodeId;

    const NAME: &'static str = "ed25519_collected";

    fn empty_aggregate() -> Self::Aggregate {
        Vec::new()
    }

    fn add_partial(
        agg: &mut Self::Aggregate,
        signers_before: &SignerBitmap,
        validator_idx: usize,
        partial: Self::PartialSig,
    ) {
        if signers_before.get(validator_idx) {
            return;
        }
        let insert_at = signers_before
            .iter_set()
            .take_while(|&i| i < validator_idx)
            .count();
        agg.insert(insert_at, partial);
    }

    fn aggregate_count(agg: &Self::Aggregate) -> usize {
        agg.len()
    }

    fn verify_aggregate(
        agg: &Self::Aggregate,
        signers: &SignerBitmap,
        message: &[u8],
        pubkeys: &[Self::PublicKey],
    ) -> Result<(), AggregateVerifyError> {
        if signers.len() != pubkeys.len() {
            return Err(AggregateVerifyError::LengthMismatch {
                bitmap_len: signers.len(),
                pubkeys_len: pubkeys.len(),
            });
        }
        if agg.len() != signers.count() {
            return Err(AggregateVerifyError::Malformed {
                reason: "aggregate sig count disagrees with bitmap set-bit count",
            });
        }
        for (idx, sig) in signers.iter_set().zip(agg.iter()) {
            let pk = &pubkeys[idx];
            UnparsedPublicKey::new(&ED25519, pk as &[u8])
                .verify(message, sig)
                .map_err(|_| AggregateVerifyError::InvalidAggregate)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rcgen::{KeyPair as RcgenKeyPair, PKCS_ED25519};
    use zeroize::Zeroizing;

    use crate::crypto::signed::{NodeSigner, Signer};
    use crate::p2p::identity::NodeIdentity;

    fn fresh_signer() -> NodeSigner {
        let kp = RcgenKeyPair::generate_for(&PKCS_ED25519).unwrap();
        let identity = NodeIdentity {
            pkcs8_der: Zeroizing::new(kp.serialize_der()),
        };
        NodeSigner::from_identity(&identity).unwrap()
    }

    #[test]
    fn empty_aggregate_has_zero_count() {
        let agg = Ed25519Collected::empty_aggregate();
        assert_eq!(Ed25519Collected::aggregate_count(&agg), 0);
    }

    #[test]
    fn add_partial_keeps_parallel_to_set_bits() {
        let mut signers = SignerBitmap::new(5);
        let mut agg = Ed25519Collected::empty_aggregate();

        // Insert in arbitrary order: 3, 0, 2.
        Ed25519Collected::add_partial(&mut agg, &signers, 3, [0x33; 64]);
        signers.set(3);
        Ed25519Collected::add_partial(&mut agg, &signers, 0, [0x00; 64]);
        signers.set(0);
        Ed25519Collected::add_partial(&mut agg, &signers, 2, [0x22; 64]);
        signers.set(2);

        // The aggregate must be parallel to set bits in ascending order.
        let pairs: Vec<(usize, [u8; 64])> = signers.iter_set().zip(agg.iter().copied()).collect();
        assert_eq!(
            pairs,
            vec![(0, [0x00; 64]), (2, [0x22; 64]), (3, [0x33; 64])]
        );
    }

    #[test]
    fn add_partial_is_idempotent_for_already_set_index() {
        let mut signers = SignerBitmap::new(3);
        let mut agg = Ed25519Collected::empty_aggregate();

        Ed25519Collected::add_partial(&mut agg, &signers, 1, [0x11; 64]);
        signers.set(1);
        // Repeat with same index: must not insert a second copy.
        Ed25519Collected::add_partial(&mut agg, &signers, 1, [0x99; 64]);

        assert_eq!(Ed25519Collected::aggregate_count(&agg), 1);
        assert_eq!(agg[0], [0x11; 64]);
    }

    #[test]
    fn verify_aggregate_accepts_real_signatures() {
        // Build three real signers, sign a message with each, aggregate.
        let s0 = fresh_signer();
        let s1 = fresh_signer();
        let s2 = fresh_signer();
        let pubkeys = vec![s0.node_id(), s1.node_id(), s2.node_id()];
        let message = b"hello consensus".to_vec();

        let mut signers = SignerBitmap::new(3);
        let mut agg = Ed25519Collected::empty_aggregate();
        for (idx, signer) in [&s0, &s1, &s2].iter().enumerate() {
            let sig = signer.sign(&message);
            Ed25519Collected::add_partial(&mut agg, &signers, idx, sig);
            signers.set(idx);
        }

        Ed25519Collected::verify_aggregate(&agg, &signers, &message, &pubkeys)
            .expect("real signatures must verify");
    }

    #[test]
    fn verify_aggregate_accepts_partial_quorum() {
        let s0 = fresh_signer();
        let s1 = fresh_signer();
        let s2 = fresh_signer();
        let pubkeys = vec![s0.node_id(), s1.node_id(), s2.node_id()];
        let message = b"partial quorum".to_vec();

        // Only validators 0 and 2 sign.
        let mut signers = SignerBitmap::new(3);
        let mut agg = Ed25519Collected::empty_aggregate();
        Ed25519Collected::add_partial(&mut agg, &signers, 0, s0.sign(&message));
        signers.set(0);
        Ed25519Collected::add_partial(&mut agg, &signers, 2, s2.sign(&message));
        signers.set(2);

        Ed25519Collected::verify_aggregate(&agg, &signers, &message, &pubkeys)
            .expect("partial quorum signatures must verify against indexed pubkeys");
    }

    #[test]
    fn verify_aggregate_rejects_tampered_signature() {
        let s0 = fresh_signer();
        let pubkeys = vec![s0.node_id()];
        let message = b"tamper test".to_vec();

        let mut signers = SignerBitmap::new(1);
        let mut agg = Ed25519Collected::empty_aggregate();
        let mut sig = s0.sign(&message);
        sig[0] ^= 0xFF;
        Ed25519Collected::add_partial(&mut agg, &signers, 0, sig);
        signers.set(0);

        assert_eq!(
            Ed25519Collected::verify_aggregate(&agg, &signers, &message, &pubkeys),
            Err(AggregateVerifyError::InvalidAggregate),
        );
    }

    #[test]
    fn verify_aggregate_rejects_wrong_message() {
        let s0 = fresh_signer();
        let pubkeys = vec![s0.node_id()];

        let mut signers = SignerBitmap::new(1);
        let mut agg = Ed25519Collected::empty_aggregate();
        Ed25519Collected::add_partial(&mut agg, &signers, 0, s0.sign(b"original"));
        signers.set(0);

        assert_eq!(
            Ed25519Collected::verify_aggregate(&agg, &signers, b"different", &pubkeys),
            Err(AggregateVerifyError::InvalidAggregate),
        );
    }

    #[test]
    fn verify_aggregate_rejects_bitmap_pubkey_length_mismatch() {
        let s0 = fresh_signer();
        let signers = SignerBitmap::new(2);
        let agg = Ed25519Collected::empty_aggregate();

        // Pubkey vec has only 1 entry but bitmap claims 2 slots.
        let result = Ed25519Collected::verify_aggregate(&agg, &signers, b"x", &[s0.node_id()]);
        assert_eq!(
            result,
            Err(AggregateVerifyError::LengthMismatch {
                bitmap_len: 2,
                pubkeys_len: 1
            }),
        );
    }

    #[test]
    fn verify_aggregate_rejects_count_mismatch() {
        let s0 = fresh_signer();
        let pubkeys = vec![s0.node_id()];
        let mut signers = SignerBitmap::new(1);
        signers.set(0);
        // Bitmap claims one signer, aggregate is empty.
        let agg = Ed25519Collected::empty_aggregate();

        assert!(matches!(
            Ed25519Collected::verify_aggregate(&agg, &signers, b"x", &pubkeys),
            Err(AggregateVerifyError::Malformed { .. }),
        ));
    }

    #[test]
    fn verify_aggregate_rejects_signer_index_pointing_at_wrong_pubkey() {
        // Signer at idx 1 signs the message, but the bitmap claims idx 0
        // signed it. The pubkey at idx 0 belongs to a different signer,
        // so verification must fail.
        let s0 = fresh_signer();
        let s1 = fresh_signer();
        let pubkeys = vec![s0.node_id(), s1.node_id()];
        let message = b"index swap".to_vec();

        let mut signers = SignerBitmap::new(2);
        let mut agg = Ed25519Collected::empty_aggregate();
        Ed25519Collected::add_partial(&mut agg, &signers, 0, s1.sign(&message));
        signers.set(0);

        assert_eq!(
            Ed25519Collected::verify_aggregate(&agg, &signers, &message, &pubkeys),
            Err(AggregateVerifyError::InvalidAggregate),
        );
    }
}
