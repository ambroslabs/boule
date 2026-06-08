//! Pluggable signature schemes for HotStuff QC aggregation.
//!
//! HotStuff's quorum certificates carry a quorum of validator signatures
//! over a `(view, block_hash)` pair. There are two production-relevant
//! ways to encode that quorum on the wire:
//!
//! - [`Ed25519Collected`]: one raw 64-byte Ed25519 signature per signer
//!   plus a [`SignerBitmap`]. Verification is `O(n)` `ring::ED25519`
//!   verifies. QC wire size scales with the quorum count.
//! - [`BlsAggregated`]: a single ~96-byte BLS12-381 G2 point aggregating
//!   every partial. Verification is one pairing check. QC wire size is
//!   constant in `n`.
//!
//! Both schemes are implemented at the trait level. `QuorumCertificate`
//! itself currently carries an Ed25519-shaped `signatures: Vec<[u8; 64]>`
//! field; widening it to dispatch on either scheme (tagged enum or
//! generic) lands when the BLS path is wired through the voting layer
//! in #293.
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
//! [`SignerBitmap`]: crate::crypto::sig_scheme::SignerBitmap

use std::fmt::{self, Debug};

use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

use crate::crypto::signed::ChainId;
use crate::identity::NodeId;

/// Compact signer set, indexed over a validator set's sorted order.
///
/// Internally: little-endian-packed bits in a `Vec<u8>`, with the bit
/// length stored as a `u32` so the postcard encoding is
/// platform-independent (the `usize` from a validator set's `len` would
/// be varint-encoded but we keep the on-wire width fixed to protect
/// future protocol changes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerBitmap {
    bits: Vec<u8>,
    len: u32,
}

impl SignerBitmap {
    /// Build an all-zero bitmap of exactly `len` bits.
    pub fn new(len: usize) -> Self {
        let len_u32 =
            u32::try_from(len).expect("validator set larger than u32::MAX is nonsensical");
        let byte_len = len.div_ceil(8);
        Self {
            bits: vec![0u8; byte_len],
            len: len_u32,
        }
    }

    /// Number of bit positions this map indexes (typically
    /// `validator_set.len()`).
    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Set bit `idx`. Panics if `idx >= self.len()`.
    pub fn set(&mut self, idx: usize) {
        assert!(
            idx < self.len(),
            "SignerBitmap::set index {idx} out of bounds (len {})",
            self.len()
        );
        self.bits[idx / 8] |= 1 << (idx % 8);
    }

    /// Returns whether bit `idx` is set. Out-of-range indices return
    /// `false` (callers shouldn't rely on it, but this keeps iteration
    /// code simple).
    pub fn get(&self, idx: usize) -> bool {
        if idx >= self.len() {
            return false;
        }
        (self.bits[idx / 8] >> (idx % 8)) & 1 == 1
    }

    /// Count the set bits.
    pub fn count(&self) -> usize {
        self.bits.iter().map(|b| b.count_ones() as usize).sum()
    }

    /// Iterate over the set-bit indices in ascending order.
    pub fn iter_set(&self) -> impl Iterator<Item = usize> + '_ {
        let len = self.len();
        self.bits
            .iter()
            .enumerate()
            .flat_map(move |(byte_idx, byte)| {
                (0..8).filter_map(move |bit| {
                    let idx = byte_idx * 8 + bit;
                    if idx < len && (byte >> bit) & 1 == 1 {
                        Some(idx)
                    } else {
                        None
                    }
                })
            })
    }

    /// Well-formedness check: no bits are set beyond `self.len()` and
    /// the backing byte length matches what `new(self.len())` would
    /// produce. Constructors maintain this; call it when accepting a
    /// bitmap from untrusted input.
    pub fn is_well_formed(&self) -> bool {
        let expected_bytes = self.len().div_ceil(8);
        if self.bits.len() != expected_bytes {
            return false;
        }
        // Check for stray bits past `self.len` inside the last byte.
        let len = self.len();
        if len % 8 != 0 {
            let last = *self.bits.last().unwrap_or(&0);
            let valid_bits_in_last = len % 8;
            let mask: u8 = (1u16 << valid_bits_in_last).wrapping_sub(1) as u8;
            if last & !mask != 0 {
                return false;
            }
        }
        true
    }
}

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

/// Chain-level choice of signature scheme, selected at genesis (#288).
///
/// Within a single chain every validator uses the same scheme and every
/// QC carries one form of aggregate. Switching schemes requires a
/// coordinated chain restart from new genesis (mixed-scheme chains are
/// out of scope, see #143).
///
/// Stored in `[consensus]` TOML as
/// `signature_scheme = "ed25519_collected"` (and, once #289 lands,
/// `"bls_aggregated"`). Unknown values fail to parse — callers should
/// surface that as a startup error.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureSchemeChoice {
    /// One raw Ed25519 signature per signer plus a [`SignerBitmap`].
    /// No longer selectable — the config layer rejects it; BLS is the
    /// only supported scheme. See [`Ed25519Collected`].
    Ed25519Collected,
    /// BLS12-381 signature aggregation: each QC carries one ~96-byte
    /// aggregate G2 point. `O(1)` pairing-check verification, constant
    /// QC wire size in `n`. The only supported scheme. See
    /// [`BlsAggregated`].
    #[default]
    BlsAggregated,
}

impl SignatureSchemeChoice {
    /// Stable name used on the wire and in error messages.
    pub fn name(self) -> &'static str {
        match self {
            Self::Ed25519Collected => Ed25519Collected::NAME,
            Self::BlsAggregated => BlsAggregated::NAME,
        }
    }
}

impl fmt::Display for SignatureSchemeChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

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

/// BLS12-381 signature aggregation scheme: each QC carries a single
/// ~96-byte aggregate G2 point. Verification is one pairing check.
///
/// Uses the `min-pk` BLS12-381 variant (G1 pubkeys, G2 sigs):
///
/// - [`PartialSig`]: 96-byte compressed G2 point (one validator's sig).
/// - [`Aggregate`]: 96-byte compressed G2 point (sum of all partials),
///   or the all-zeros sentinel for the empty aggregate.
/// - [`PublicKey`]: 48-byte compressed G1 point (validator's BLS pubkey).
///
/// The IETF DST is the standard `_POP_` variant — proof-of-possession
/// is the rogue-key-attack defense for chains that allow validators to
/// register their own pubkey. PoP enforcement at registration time
/// arrives in #291.
///
/// [`PartialSig`]: SignatureScheme::PartialSig
/// [`Aggregate`]: SignatureScheme::Aggregate
/// [`PublicKey`]: SignatureScheme::PublicKey
pub struct BlsAggregated;

/// Compressed BLS12-381 G2 point (one validator's partial signature, or
/// the aggregate). 96 bytes per the IETF compressed serialization.
pub type BlsPartialSig = [u8; 96];

/// Compressed BLS12-381 G2 point. Same size as a partial because
/// aggregation is point addition in G2.
pub type BlsAggregate = [u8; 96];

/// Compressed BLS12-381 G1 point (validator's BLS pubkey under the
/// `min-pk` variant). 48 bytes per IETF.
pub type BlsPublicKey = [u8; 48];

/// 32-byte serialized BLS12-381 secret key.
pub type BlsSecretKey = [u8; 32];

/// Sentinel used in [`BlsAggregated::empty_aggregate`] to mean "no
/// partials folded in yet." Distinct from any valid compressed G2
/// point because the IETF compressed-infinity encoding has the
/// infinity flag set in the high bits of byte 0, which is not all-zero.
const BLS_EMPTY_AGGREGATE_SENTINEL: BlsAggregate = [0u8; 96];

impl BlsAggregated {
    /// IETF BLS signature DST: `_POP_` ciphersuite for the `min-pk`
    /// G2-sig variant. Ties our protocol's DST to the standard
    /// proof-of-possession scheme so PoP signatures (#291) and QC
    /// signatures share the same hash-to-curve domain.
    pub const DST: &'static [u8] = b"BOULE_HOTSTUFF_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    /// True iff `agg` is the sentinel returned by
    /// [`Self::empty_aggregate`] — i.e. no partials have been folded in.
    /// Used by `boule_consensus::hotstuff::qc::QuorumCertificate::is_well_formed`
    /// for a cheap structural check that pairs the bitmap state with
    /// the aggregate state, before the cryptographic
    /// [`Self::verify_aggregate`] pairing check runs.
    pub fn is_empty_aggregate(agg: &BlsAggregate) -> bool {
        *agg == BLS_EMPTY_AGGREGATE_SENTINEL
    }

    /// Generate a fresh BLS keypair from input keying material.
    /// `ikm` must be at least 32 bytes per the IETF spec; shorter
    /// inputs are rejected.
    pub fn keygen(ikm: &[u8]) -> Result<(BlsSecretKey, BlsPublicKey), BlsKeyError> {
        let secret = blst::min_pk::SecretKey::key_gen(ikm, &[]).map_err(BlsKeyError::Blst)?;
        let public = secret.sk_to_pk();
        Ok((secret.to_bytes(), public.to_bytes()))
    }

    /// Produce a partial signature over `message` under `secret`. The
    /// returned 96-byte compressed point is one validator's contribution
    /// to a future QC aggregate.
    pub fn sign_partial(
        secret: &BlsSecretKey,
        message: &[u8],
    ) -> Result<BlsPartialSig, BlsKeyError> {
        let sk = blst::min_pk::SecretKey::from_bytes(secret).map_err(BlsKeyError::Blst)?;
        Ok(sk.sign(message, Self::DST, &[]).to_bytes())
    }

    /// Verify a single partial under `pubkey`. Used by leaders to
    /// validate each incoming partial *before* folding it into the
    /// aggregate — that way [`SignatureScheme::add_partial`] never sees
    /// malformed bytes.
    pub fn verify_partial(
        pubkey: &BlsPublicKey,
        message: &[u8],
        partial: &BlsPartialSig,
    ) -> Result<(), BlsKeyError> {
        let pk = blst::min_pk::PublicKey::from_bytes(pubkey).map_err(BlsKeyError::Blst)?;
        let sig = blst::min_pk::Signature::from_bytes(partial).map_err(BlsKeyError::Blst)?;
        match sig.verify(true, message, Self::DST, &[], &pk, true) {
            blst::BLST_ERROR::BLST_SUCCESS => Ok(()),
            err => Err(BlsKeyError::Blst(err)),
        }
    }

    /// Produce a proof-of-possession (PoP) over `pubkey` using
    /// `secret`, scoped to `chain_id`. The PoP is a BLS signature
    /// whose message is `chain_id || pubkey` — it proves the signer
    /// holds the secret half of the registered pubkey *on this
    /// specific deployment*.
    ///
    /// PoPs defend against rogue-key attacks: an attacker who picks a
    /// pubkey `K' = K_target − K_self` cannot produce a valid PoP for
    /// `K'` without holding its secret half, so the registration tx
    /// can reject the malicious key.
    ///
    /// The 32-byte `chain_id` is mixed into the pre-image (#410, audit
    /// finding 7-2) so a PoP minted for one deployment cannot be
    /// replayed on another deployment that happens to share the same
    /// validator BLS key. Both halves are fixed-size, so no
    /// length-prefix is needed at the boundary.
    pub fn sign_pop(secret: &BlsSecretKey, chain_id: &ChainId) -> Result<BlsPop, BlsKeyError> {
        let sk = blst::min_pk::SecretKey::from_bytes(secret).map_err(BlsKeyError::Blst)?;
        let pubkey = sk.sk_to_pk().to_bytes();
        let preimage = pop_preimage(chain_id, &pubkey);
        let sig = sk.sign(&preimage, Self::DST, &[]).to_bytes();
        Ok(BlsPop { pubkey, sig })
    }

    /// Verify a [`BlsPop`] under `chain_id`. Returns `Ok(())` iff:
    /// 1. `pop.pubkey` equals `expected_pubkey` — an attacker cannot
    ///    submit a PoP for someone else's key as their own.
    /// 2. `pop.sig` is a valid BLS signature over
    ///    `chain_id || pop.pubkey` under `pop.pubkey` — proving
    ///    possession of the secret half *on this deployment*.
    ///
    /// A PoP minted under `chain_id=A` fails verification under
    /// `chain_id=B`, blocking cross-deployment PoP replay (#410).
    pub fn verify_pop(
        pop: &BlsPop,
        expected_pubkey: &BlsPublicKey,
        chain_id: &ChainId,
    ) -> Result<(), BlsKeyError> {
        if pop.pubkey != *expected_pubkey {
            return Err(BlsKeyError::PopPubkeyMismatch);
        }
        let pk = blst::min_pk::PublicKey::from_bytes(&pop.pubkey).map_err(BlsKeyError::Blst)?;
        let sig = blst::min_pk::Signature::from_bytes(&pop.sig).map_err(BlsKeyError::Blst)?;
        let preimage = pop_preimage(chain_id, &pop.pubkey);
        match sig.verify(true, &preimage, Self::DST, &[], &pk, true) {
            blst::BLST_ERROR::BLST_SUCCESS => Ok(()),
            err => Err(BlsKeyError::Blst(err)),
        }
    }
}

/// Build the BLS proof-of-possession pre-image: `chain_id || pubkey`.
/// Both halves are fixed-size (32 + 48 bytes) so the concatenation is
/// unambiguous without a length prefix — same shape argument as the
/// envelope pre-image in [`crate::crypto::signed`].
fn pop_preimage(chain_id: &ChainId, pubkey: &BlsPublicKey) -> [u8; 32 + 48] {
    let mut out = [0u8; 32 + 48];
    out[..32].copy_from_slice(chain_id.as_bytes());
    out[32..].copy_from_slice(pubkey);
    out
}

/// Convert a 48-byte compressed `min-pk` G1 pubkey ([`BlsPublicKey`]) into its
/// **128-byte EIP-2537 uncompressed** G1 encoding: `x ‖ y`, each Fp coordinate
/// big-endian and left-zero-padded from 48 to 64 bytes (16 zero bytes + 48-byte
/// Fp).
///
/// This is the on-chain form the slashing predeploy (`Slashing.sol`) and the
/// BLS12-381 G1 precompiles consume: `Registry.keyAt` must return exactly this
/// 128-byte layout, so the #732 registry write path converts a rotated key with
/// this before `recordKey`. Factored here (next to the blst-backed signing) so
/// the EVM-facing crate and the slashing/QC test vectors
/// (`gen_slashing_vectors` / `gen_eip2537_vectors`) share one encoding rather
/// than each reimplementing the blst FFI dance.
///
/// Errors if `pubkey` is not a valid compressed G1 point (it is round-tripped
/// through blst `deserialize`, which validates the subgroup/encoding).
pub fn bls_pubkey_to_eip2537_g1(pubkey: &BlsPublicKey) -> Result<[u8; 128], BlsKeyError> {
    use blst::{BLST_ERROR, blst_bendian_from_fp, blst_fp, blst_p1_affine, blst_p1_deserialize};

    // EIP-2537 Fp: 48-byte big-endian coordinate left-padded to 64 bytes.
    fn fp64(fp: &blst_fp) -> [u8; 64] {
        let mut be = [0u8; 48];
        unsafe { blst_bendian_from_fp(be.as_mut_ptr(), fp) };
        let mut out = [0u8; 64];
        out[16..].copy_from_slice(&be);
        out
    }

    // Decompress 48-byte compressed -> 96-byte uncompressed, then to affine.
    let uncompressed = blst::min_pk::PublicKey::from_bytes(pubkey)
        .map_err(BlsKeyError::Blst)?
        .serialize();
    let mut aff = blst_p1_affine::default();
    // SAFETY: `uncompressed` is a valid 96-byte serialization produced by blst
    // just above, so `blst_p1_deserialize` reads exactly that buffer.
    let err = unsafe { blst_p1_deserialize(&mut aff, uncompressed.as_ptr()) };
    if err != BLST_ERROR::BLST_SUCCESS {
        return Err(BlsKeyError::Blst(err));
    }
    let mut out = [0u8; 128];
    out[..64].copy_from_slice(&fp64(&aff.x));
    out[64..].copy_from_slice(&fp64(&aff.y));
    Ok(out)
}

/// Proof-of-possession (PoP) bundle for a BLS validator pubkey.
/// Carries the pubkey explicitly so the wire shape is self-describing:
/// the PoP can be verified independently of the surrounding tx.
///
/// On BLS chains, every validator-registration tx (#140 / #251) embeds
/// a `BlsPop` per `adds` entry; the reconfig validator (#293) rejects
/// any add that lacks a PoP or whose PoP fails to verify. PoPs are
/// persisted alongside the historical pubkey in
/// `boule_consensus::validator_key_history` (#294) so historical
/// validator-set lookups never trust an unverified key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlsPop {
    #[serde(with = "serde_g1_pubkey")]
    pub pubkey: BlsPublicKey,
    #[serde(with = "serde_g2_sig")]
    pub sig: BlsPartialSig,
}

mod serde_g1_pubkey {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(pk: &[u8; 48], s: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&pk[..], s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 48], D::Error> {
        let v: Vec<u8> = Vec::<u8>::deserialize(d)?;
        v.as_slice()
            .try_into()
            .map_err(|_| D::Error::custom("BLS pubkey must be exactly 48 bytes"))
    }
}

mod serde_g2_sig {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(sig: &[u8; 96], s: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&sig[..], s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 96], D::Error> {
        let v: Vec<u8> = Vec::<u8>::deserialize(d)?;
        v.as_slice()
            .try_into()
            .map_err(|_| D::Error::custom("BLS sig must be exactly 96 bytes"))
    }
}

impl SignatureScheme for BlsAggregated {
    type PartialSig = BlsPartialSig;
    type Aggregate = BlsAggregate;
    type PublicKey = BlsPublicKey;

    const NAME: &'static str = "bls_aggregated";

    fn empty_aggregate() -> Self::Aggregate {
        BLS_EMPTY_AGGREGATE_SENTINEL
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
        let new_sig = blst::min_pk::Signature::from_bytes(&partial).unwrap_or_else(|e| {
            panic!(
                "BlsAggregated::add_partial: malformed partial sig for validator {validator_idx}: {e:?}. \
                 Caller must verify partials with BlsAggregated::verify_partial before aggregating.",
            )
        });

        if *agg == BLS_EMPTY_AGGREGATE_SENTINEL {
            *agg = new_sig.to_bytes();
            return;
        }

        let current_sig = blst::min_pk::Signature::from_bytes(agg)
            .expect("aggregate state must be a valid compressed G2 point");
        let mut combined = blst::min_pk::AggregateSignature::from_signature(&current_sig);
        combined
            .add_signature(&new_sig, false)
            .expect("partial was already deserialized; subgroup check optional here");
        *agg = combined.to_signature().to_bytes();
    }

    fn aggregate_count(_agg: &Self::Aggregate) -> usize {
        // BLS aggregates are a single point; the "count" lives in the
        // bitmap, not in the aggregate. Verification helpers consult
        // `signers.count()` directly. Returning 0 keeps the
        // QuorumCertificate well-formedness check (#287) honest by
        // preventing it from being driven off the aggregate side; that
        // path is BLS-aware in #293.
        0
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
        let signer_count = signers.count();
        let is_empty = *agg == BLS_EMPTY_AGGREGATE_SENTINEL;
        if signer_count == 0 {
            return if is_empty {
                Ok(())
            } else {
                Err(AggregateVerifyError::Malformed {
                    reason: "non-empty aggregate with no signers in bitmap",
                })
            };
        }
        if is_empty {
            return Err(AggregateVerifyError::Malformed {
                reason: "empty aggregate with non-zero signer bitmap",
            });
        }

        let signature = blst::min_pk::Signature::from_bytes(agg)
            .map_err(|_| AggregateVerifyError::InvalidAggregate)?;

        let selected: Vec<blst::min_pk::PublicKey> = signers
            .iter_set()
            .map(|idx| {
                blst::min_pk::PublicKey::from_bytes(&pubkeys[idx])
                    .map_err(|_| AggregateVerifyError::InvalidAggregate)
            })
            .collect::<Result<_, _>>()?;
        let pk_refs: Vec<&blst::min_pk::PublicKey> = selected.iter().collect();

        match signature.fast_aggregate_verify(true, message, Self::DST, &pk_refs) {
            blst::BLST_ERROR::BLST_SUCCESS => Ok(()),
            _ => Err(AggregateVerifyError::InvalidAggregate),
        }
    }
}

/// Errors produced by the BLS keygen / signing / partial-verify / PoP
/// helpers on [`BlsAggregated`]. Wraps the `blst` error code so callers
/// can distinguish "bad input bytes" from "bad signature" without
/// taking a transitive dep on the `blst` crate.
#[derive(Debug, PartialEq, Eq)]
pub enum BlsKeyError {
    Blst(blst::BLST_ERROR),
    /// A [`BlsPop`]'s embedded pubkey did not match the
    /// `expected_pubkey` argument passed to [`BlsAggregated::verify_pop`].
    /// Distinguished from [`Self::Blst`] so the registration path can
    /// surface "you submitted someone else's PoP" specifically.
    PopPubkeyMismatch,
}

impl fmt::Display for BlsKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Blst(err) => write!(f, "blst error: {err:?}"),
            Self::PopPubkeyMismatch => f.write_str(
                "BLS proof-of-possession pubkey does not match expected validator pubkey",
            ),
        }
    }
}

impl std::error::Error for BlsKeyError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`bls_pubkey_to_eip2537_g1`] must reproduce the **exact** 128-byte
    /// EIP-2537 G1 encoding the slashing test vectors carry (`SL_PUBKEY` from
    /// `boule_consensus::hotstuff::qc::gen_slashing_vectors`, the pubkey of
    /// `keygen(&[0x9a; 32])`). Pinning the public helper to that ground truth
    /// guarantees the #732 registry write path records a key in precisely the
    /// form `Slashing.sol`'s `keyAt` requires (`key.length == 128`).
    #[test]
    fn eip2537_g1_matches_slashing_ground_truth() {
        let (_, pk) = BlsAggregated::keygen(&[0x9a; 32]).unwrap();
        let got = bls_pubkey_to_eip2537_g1(&pk).unwrap();
        // Ground truth from `gen_slashing_vectors` (`SL_PUBKEY`).
        let want = "\
00000000000000000000000000000000056d20bb7bf8e8d5013333796f901ed1\
6cb97e0a64926665b47ed99e53a49d959c440f70d76cbb663543373f30d5d4aa\
0000000000000000000000000000000003ac6089db289c61c5e2b20935b02eac\
901edc4f81f10edd60832c3fc14b92f1f038a06e71a1541a681b9e7757e4f2f7";
        assert_eq!(hex::encode(got), want);
        // Structural: 16-byte zero pad before each 48-byte Fp coordinate.
        assert!(got[..16].iter().all(|b| *b == 0), "x Fp zero-padded");
        assert!(got[64..80].iter().all(|b| *b == 0), "y Fp zero-padded");
    }

    /// A malformed (non-curve) compressed pubkey is rejected rather than
    /// silently producing garbage 128 bytes.
    #[test]
    fn eip2537_g1_rejects_a_bad_pubkey() {
        assert!(bls_pubkey_to_eip2537_g1(&[0xFF; 48]).is_err());
    }

    // Ground-truth vector generator for the EIP-2537 BLS slashing precompile
    // (#732b). Emits a real boule BLS signature plus its verify inputs —
    // pubkey (G1), the hash-to-curve point H (G2), the signature (G2), and
    // -G1_generator — in **EIP-2537 uncompressed** encoding (each Fp coord
    // 16-byte-zero-padded to 64; Fp2 as c0||c1 via `.fp[0]`/`.fp[1]`, the
    // ordering that bit a naive blst `serialize()` conversion). These vectors
    // were used to confirm that the EIP-2537 pairing precompile validates a
    // boule signature on a live reth — `e(pubkey,H)·e(-G1gen,sig) == 1` returns
    // true — which is the core of the slashing precompile. `#[ignore]` so it
    // doesn't run in CI; regenerate with:
    //   cargo test -p boule-core gen_eip2537_vectors -- --nocapture --ignored
    #[test]
    #[ignore]
    fn gen_eip2537_vectors() {
        use blst::min_pk::SecretKey;
        use blst::{
            BLST_ERROR, blst_bendian_from_fp, blst_fp, blst_hash_to_g2, blst_p1, blst_p1_affine,
            blst_p1_cneg, blst_p1_deserialize, blst_p1_generator, blst_p1_to_affine, blst_p2,
            blst_p2_affine, blst_p2_deserialize, blst_p2_to_affine,
        };

        fn hx(b: &[u8]) -> String {
            b.iter().map(|x| format!("{x:02x}")).collect()
        }
        fn fp64(fp: &blst_fp) -> [u8; 64] {
            let mut be = [0u8; 48];
            unsafe { blst_bendian_from_fp(be.as_mut_ptr(), fp) };
            let mut out = [0u8; 64];
            out[16..].copy_from_slice(&be); // EIP-2537: 16 zero pad + 48-byte Fp
            out
        }
        fn g1(a: &blst_p1_affine) -> Vec<u8> {
            [fp64(&a.x), fp64(&a.y)].concat()
        }
        fn g2(a: &blst_p2_affine) -> Vec<u8> {
            // EIP-2537 Fp2 order is (c0, c1) == (.fp[0], .fp[1]).
            [
                fp64(&a.x.fp[0]),
                fp64(&a.x.fp[1]),
                fp64(&a.y.fp[0]),
                fp64(&a.y.fp[1]),
            ]
            .concat()
        }

        let sk = SecretKey::key_gen(&[7u8; 32], &[]).unwrap();
        let pk = sk.sk_to_pk();
        let msg: &[u8] = b"equivocation: same view, conflicting block hashes";
        let dst = BlsAggregated::DST;
        let sig = sk.sign(msg, dst, &[]);
        assert_eq!(
            sig.verify(true, msg, dst, &[], &pk, true),
            BLST_ERROR::BLST_SUCCESS,
            "blst self-check"
        );

        let mut h = blst_p2::default();
        let mut h_aff = blst_p2_affine::default();
        let mut pk_aff = blst_p1_affine::default();
        let mut sig_aff = blst_p2_affine::default();
        let pk_bytes = pk.serialize();
        let sig_bytes = sig.serialize();
        unsafe {
            blst_hash_to_g2(
                &mut h,
                msg.as_ptr(),
                msg.len(),
                dst.as_ptr(),
                dst.len(),
                std::ptr::null(),
                0,
            );
            blst_p2_to_affine(&mut h_aff, &h);
            assert_eq!(
                blst_p1_deserialize(&mut pk_aff, pk_bytes.as_ptr()),
                BLST_ERROR::BLST_SUCCESS
            );
            assert_eq!(
                blst_p2_deserialize(&mut sig_aff, sig_bytes.as_ptr()),
                BLST_ERROR::BLST_SUCCESS
            );
        }

        // -G1_generator (for the pairing equation e(pk,H)*e(-G1gen,sig)==1).
        let mut neg_aff = blst_p1_affine::default();
        unsafe {
            let mut neg: blst_p1 = *blst_p1_generator();
            blst_p1_cneg(&mut neg, true);
            blst_p1_to_affine(&mut neg_aff, &neg);
        }

        println!("VEC_MSG={}", hx(msg));
        println!("VEC_DST={}", hx(dst));
        println!("VEC_PUBKEY_G1={}", hx(&g1(&pk_aff)));
        println!("VEC_HMSG_G2={}", hx(&g2(&h_aff)));
        println!("VEC_SIG_G2={}", hx(&g2(&sig_aff)));
        println!("VEC_NEG_G1GEN={}", hx(&g1(&neg_aff)));
    }

    // ── SignerBitmap ─────────────────────────────────────────────

    #[test]
    fn signer_bitmap_basic_set_get_count() {
        let mut bm = SignerBitmap::new(10);
        assert_eq!(bm.len(), 10);
        assert_eq!(bm.count(), 0);

        bm.set(0);
        bm.set(3);
        bm.set(9);

        assert!(bm.get(0));
        assert!(!bm.get(1));
        assert!(bm.get(3));
        assert!(bm.get(9));
        assert!(!bm.get(10), "out-of-range read returns false, not panic");
        assert_eq!(bm.count(), 3);

        let set: Vec<usize> = bm.iter_set().collect();
        assert_eq!(set, vec![0, 3, 9]);
    }

    #[test]
    #[should_panic(expected = "out of bounds")]
    fn signer_bitmap_set_oob_panics() {
        let mut bm = SignerBitmap::new(4);
        bm.set(4);
    }

    #[test]
    fn signer_bitmap_is_well_formed_after_normal_construction() {
        let mut bm = SignerBitmap::new(13);
        for i in [1, 5, 12] {
            bm.set(i);
        }
        assert!(bm.is_well_formed());
    }

    #[test]
    fn signer_bitmap_rejects_stray_bits_past_len() {
        let mut bm = SignerBitmap::new(5);
        // Poke a stray bit 7 (inside byte 0 but past len=5).
        bm.bits[0] |= 0b1000_0000;
        assert!(!bm.is_well_formed());
    }

    #[test]
    fn signer_bitmap_rejects_wrong_byte_length() {
        let mut bm = SignerBitmap::new(5);
        bm.bits.push(0);
        assert!(!bm.is_well_formed());
    }

    #[test]
    fn signer_bitmap_postcard_roundtrip() {
        let mut bm = SignerBitmap::new(17);
        for i in [0, 7, 8, 16] {
            bm.set(i);
        }
        let wire = postcard::to_stdvec(&bm).unwrap();
        let back: SignerBitmap = postcard::from_bytes(&wire).unwrap();
        assert_eq!(back, bm);
    }
    // ── BlsAggregated scaffold (#289) ────────────────────────────────

    #[test]
    fn bls_aggregated_name_is_bls_aggregated() {
        assert_eq!(BlsAggregated::NAME, "bls_aggregated");
        assert_eq!(
            SignatureSchemeChoice::BlsAggregated.name(),
            "bls_aggregated",
        );
    }

    #[test]
    fn bls_scheme_choice_round_trips_through_toml() {
        // Genesis-config field uses snake_case; both variants round trip.
        let raw = "scheme = \"bls_aggregated\"\n";
        #[derive(serde::Deserialize)]
        struct Wrap {
            scheme: SignatureSchemeChoice,
        }
        let parsed: Wrap = toml::from_str(raw).unwrap();
        assert_eq!(parsed.scheme, SignatureSchemeChoice::BlsAggregated);
    }

    #[test]
    fn bls_aggregated_empty_aggregate_is_sentinel() {
        // The sentinel represents "no partials folded in." It is
        // distinct from any valid compressed G2 point because IETF
        // compressed-infinity has the infinity flag set in byte 0 (a
        // non-zero high bit), so all-zeros is unambiguously empty.
        assert_eq!(BlsAggregated::empty_aggregate(), [0u8; 96]);
    }

    #[test]
    fn bls_keygen_produces_consistent_pubkey() {
        let ikm = [0x42u8; 32];
        let (sk1, pk1) = BlsAggregated::keygen(&ikm).unwrap();
        let (sk2, pk2) = BlsAggregated::keygen(&ikm).unwrap();
        assert_eq!(sk1, sk2, "keygen is deterministic in ikm");
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn bls_keygen_rejects_short_ikm() {
        // IETF requires at least 32 bytes of IKM.
        let short = [0u8; 16];
        assert!(BlsAggregated::keygen(&short).is_err());
    }

    fn bls_signer(seed: u8) -> (BlsSecretKey, BlsPublicKey) {
        let mut ikm = [0u8; 32];
        ikm.fill(seed);
        BlsAggregated::keygen(&ikm).expect("seeded keygen must succeed")
    }

    #[test]
    fn bls_sign_partial_round_trips_with_verify_partial() {
        let (sk, pk) = bls_signer(0x11);
        let message = b"hello bls";
        let sig = BlsAggregated::sign_partial(&sk, message).unwrap();
        BlsAggregated::verify_partial(&pk, message, &sig).expect("real signature must verify");
    }

    #[test]
    fn bls_verify_partial_rejects_wrong_message() {
        let (sk, pk) = bls_signer(0x22);
        let sig = BlsAggregated::sign_partial(&sk, b"original").unwrap();
        assert!(BlsAggregated::verify_partial(&pk, b"different", &sig).is_err());
    }

    #[test]
    fn bls_verify_partial_rejects_wrong_pubkey() {
        let (sk_a, _pk_a) = bls_signer(0x33);
        let (_sk_b, pk_b) = bls_signer(0x44);
        let sig = BlsAggregated::sign_partial(&sk_a, b"msg").unwrap();
        assert!(BlsAggregated::verify_partial(&pk_b, b"msg", &sig).is_err());
    }

    #[test]
    fn bls_aggregate_of_one_partial_verifies() {
        let (sk, pk) = bls_signer(0x55);
        let message = b"single signer aggregate";
        let sig = BlsAggregated::sign_partial(&sk, message).unwrap();

        let mut signers = SignerBitmap::new(1);
        let mut agg = BlsAggregated::empty_aggregate();
        BlsAggregated::add_partial(&mut agg, &signers, 0, sig);
        signers.set(0);

        BlsAggregated::verify_aggregate(&agg, &signers, message, &[pk])
            .expect("single-signer BLS aggregate must verify");
    }

    #[test]
    fn bls_aggregate_of_three_partials_verifies() {
        let (sk0, pk0) = bls_signer(0xA0);
        let (sk1, pk1) = bls_signer(0xA1);
        let (sk2, pk2) = bls_signer(0xA2);
        let pubkeys = vec![pk0, pk1, pk2];
        let message = b"three-party quorum".to_vec();

        let mut signers = SignerBitmap::new(3);
        let mut agg = BlsAggregated::empty_aggregate();
        for (idx, sk) in [&sk0, &sk1, &sk2].iter().enumerate() {
            let sig = BlsAggregated::sign_partial(sk, &message).unwrap();
            BlsAggregated::add_partial(&mut agg, &signers, idx, sig);
            signers.set(idx);
        }
        BlsAggregated::verify_aggregate(&agg, &signers, &message, &pubkeys)
            .expect("3-of-3 BLS aggregate must verify");
    }

    #[test]
    fn bls_aggregate_of_partial_quorum_verifies_only_signed_indices() {
        // Five validators, only 0/2/4 sign. Verification must use the
        // selected pubkeys (per the bitmap) and succeed; if it tried to
        // include 1 and 3, it would fail.
        let signers_all: Vec<(BlsSecretKey, BlsPublicKey)> =
            (0..5u8).map(|i| bls_signer(0xB0 | i)).collect();
        let pubkeys: Vec<BlsPublicKey> = signers_all.iter().map(|(_, pk)| *pk).collect();
        let message = b"partial quorum, sparse signers";

        let mut signers = SignerBitmap::new(5);
        let mut agg = BlsAggregated::empty_aggregate();
        for &idx in &[0usize, 2, 4] {
            let sig = BlsAggregated::sign_partial(&signers_all[idx].0, message).unwrap();
            BlsAggregated::add_partial(&mut agg, &signers, idx, sig);
            signers.set(idx);
        }
        BlsAggregated::verify_aggregate(&agg, &signers, message, &pubkeys)
            .expect("3-of-5 BLS aggregate over indices {0,2,4} must verify");
    }

    #[test]
    fn bls_verify_aggregate_rejects_tampered_aggregate() {
        let (sk, pk) = bls_signer(0xC0);
        let message = b"will tamper";
        let sig = BlsAggregated::sign_partial(&sk, message).unwrap();
        let mut signers = SignerBitmap::new(1);
        let mut agg = BlsAggregated::empty_aggregate();
        BlsAggregated::add_partial(&mut agg, &signers, 0, sig);
        signers.set(0);
        agg[10] ^= 0xFF;

        assert!(matches!(
            BlsAggregated::verify_aggregate(&agg, &signers, message, &[pk]),
            Err(AggregateVerifyError::InvalidAggregate),
        ));
    }

    #[test]
    fn bls_verify_aggregate_rejects_wrong_message() {
        let (sk, pk) = bls_signer(0xC1);
        let sig = BlsAggregated::sign_partial(&sk, b"signed").unwrap();
        let mut signers = SignerBitmap::new(1);
        let mut agg = BlsAggregated::empty_aggregate();
        BlsAggregated::add_partial(&mut agg, &signers, 0, sig);
        signers.set(0);

        assert!(matches!(
            BlsAggregated::verify_aggregate(&agg, &signers, b"different", &[pk]),
            Err(AggregateVerifyError::InvalidAggregate),
        ));
    }

    #[test]
    fn bls_verify_aggregate_rejects_signer_index_pointing_at_wrong_pubkey() {
        // Validator 1 signs, but the aggregate is registered as if
        // validator 0 signed. The pubkey at idx 0 belongs to the wrong
        // signer, so verification fails.
        let (_sk0, pk0) = bls_signer(0xD0);
        let (sk1, pk1) = bls_signer(0xD1);
        let pubkeys = vec![pk0, pk1];
        let message = b"index swap";

        let sig1 = BlsAggregated::sign_partial(&sk1, message).unwrap();
        let mut signers = SignerBitmap::new(2);
        let mut agg = BlsAggregated::empty_aggregate();
        BlsAggregated::add_partial(&mut agg, &signers, 0, sig1);
        signers.set(0);

        assert!(matches!(
            BlsAggregated::verify_aggregate(&agg, &signers, message, &pubkeys),
            Err(AggregateVerifyError::InvalidAggregate),
        ));
    }

    #[test]
    fn bls_verify_aggregate_rejects_bitmap_pubkey_length_mismatch() {
        let agg = BlsAggregated::empty_aggregate();
        let signers = SignerBitmap::new(2);
        assert_eq!(
            BlsAggregated::verify_aggregate(&agg, &signers, b"x", &[[0u8; 48]]),
            Err(AggregateVerifyError::LengthMismatch {
                bitmap_len: 2,
                pubkeys_len: 1
            }),
        );
    }

    #[test]
    fn bls_verify_aggregate_rejects_empty_aggregate_with_signers() {
        // Bitmap claims a signer but the aggregate is the empty
        // sentinel — structurally malformed.
        let mut signers = SignerBitmap::new(1);
        signers.set(0);
        let agg = BlsAggregated::empty_aggregate();
        assert!(matches!(
            BlsAggregated::verify_aggregate(&agg, &signers, b"x", &[[0u8; 48]]),
            Err(AggregateVerifyError::Malformed { .. }),
        ));
    }

    #[test]
    fn bls_aggregate_resolution_constant_size_independent_of_n() {
        // Sanity: the aggregate carried inside a QC is always 96 bytes
        // regardless of the quorum size. This is the load-bearing
        // property the BLS path is supposed to deliver vs.
        // Ed25519Collected's `64 * (2f+1)` growth.
        let large_n = 50;
        let signers_all: Vec<(BlsSecretKey, BlsPublicKey)> =
            (0..large_n).map(|i| bls_signer(i as u8)).collect();
        let pubkeys: Vec<BlsPublicKey> = signers_all.iter().map(|(_, pk)| *pk).collect();
        let message = b"size test";

        let mut signers = SignerBitmap::new(large_n);
        let mut agg = BlsAggregated::empty_aggregate();
        for (idx, (sk, _)) in signers_all.iter().enumerate() {
            let sig = BlsAggregated::sign_partial(sk, message).unwrap();
            BlsAggregated::add_partial(&mut agg, &signers, idx, sig);
            signers.set(idx);
        }
        // Aggregate size is the trait associated type's size, not a
        // function of N.
        assert_eq!(std::mem::size_of_val(&agg), 96);
        BlsAggregated::verify_aggregate(&agg, &signers, message, &pubkeys)
            .expect("50-of-50 aggregate must still verify in O(1) pairings");
    }

    #[test]
    fn bls_add_partial_is_idempotent_for_already_set_index() {
        let (sk, pk) = bls_signer(0xE0);
        let message = b"idempotent add";
        let sig = BlsAggregated::sign_partial(&sk, message).unwrap();
        let mut signers = SignerBitmap::new(1);
        let mut agg = BlsAggregated::empty_aggregate();
        BlsAggregated::add_partial(&mut agg, &signers, 0, sig);
        signers.set(0);
        let after_first = agg;
        BlsAggregated::add_partial(&mut agg, &signers, 0, sig);
        assert_eq!(agg, after_first, "duplicate add must not mutate aggregate");

        // Sanity: still verifies (it's still a 1-of-1 aggregate).
        BlsAggregated::verify_aggregate(&agg, &signers, message, &[pk])
            .expect("idempotent add must keep aggregate valid");
    }

    // ── BLS proof-of-possession (#291, #410) ──────────────────────────

    #[test]
    fn bls_pop_round_trips_under_correct_pubkey() {
        let (sk, pk) = bls_signer(0xF0);
        let pop = BlsAggregated::sign_pop(&sk, &ChainId::TEST).expect("PoP signing must succeed");
        assert_eq!(pop.pubkey, pk);
        BlsAggregated::verify_pop(&pop, &pk, &ChainId::TEST).expect("real PoP must verify");
    }

    #[test]
    fn bls_pop_rejects_pubkey_mismatch() {
        // An attacker who substitutes someone else's PoP for their own
        // registration tx must be caught. `verify_pop` checks the
        // embedded pubkey first.
        let (sk_a, _pk_a) = bls_signer(0xF1);
        let (_sk_b, pk_b) = bls_signer(0xF2);
        let pop = BlsAggregated::sign_pop(&sk_a, &ChainId::TEST).unwrap();
        // pop.pubkey is pk_a; checking against pk_b must fail.
        assert_eq!(
            BlsAggregated::verify_pop(&pop, &pk_b, &ChainId::TEST),
            Err(BlsKeyError::PopPubkeyMismatch),
        );
    }

    #[test]
    fn bls_pop_rejects_tampered_signature() {
        let (sk, pk) = bls_signer(0xF3);
        let mut pop = BlsAggregated::sign_pop(&sk, &ChainId::TEST).unwrap();
        pop.sig[0] ^= 0xFF;
        assert!(BlsAggregated::verify_pop(&pop, &pk, &ChainId::TEST).is_err());
    }

    #[test]
    fn bls_pop_postcard_roundtrip() {
        // Wire-format stability: the PoP encodes/decodes through
        // postcard. `[u8; 48]` and `[u8; 96]` go through the
        // dedicated serde modules above.
        let (sk, _pk) = bls_signer(0xF4);
        let pop = BlsAggregated::sign_pop(&sk, &ChainId::TEST).unwrap();
        let bytes = postcard::to_stdvec(&pop).unwrap();
        let back: BlsPop = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, pop);
    }

    #[test]
    fn bls_pop_for_one_validator_does_not_validate_under_another() {
        // Forgery defense: a PoP signed under sk_a is not a valid PoP
        // for any other pubkey, even if the byte payload (the embedded
        // pubkey) is swapped to pk_b. The signature itself is over the
        // pubkey, so swapping invalidates the signature.
        let (sk_a, pk_a) = bls_signer(0xF5);
        let (_sk_b, pk_b) = bls_signer(0xF6);
        let mut pop = BlsAggregated::sign_pop(&sk_a, &ChainId::TEST).unwrap();
        // Forge: replace embedded pubkey with pk_b but keep sig from sk_a.
        pop.pubkey = pk_b;
        // Now caller passes pk_b as expected, so the mismatch check
        // passes, but the signature verifies over pk_b's bytes under
        // pk_a's signature — must fail at the BLS verify step.
        assert!(matches!(
            BlsAggregated::verify_pop(&pop, &pk_b, &ChainId::TEST),
            Err(BlsKeyError::Blst(_)),
        ));
        // For completeness: with the correct expected pubkey (pk_a), the
        // mismatch check fires first.
        assert_eq!(
            BlsAggregated::verify_pop(&pop, &pk_a, &ChainId::TEST),
            Err(BlsKeyError::PopPubkeyMismatch),
        );
    }

    /// Audit finding 7-2 (#410): a PoP minted under `chain_id=A` does
    /// not verify under `chain_id=B`, even with the same validator
    /// BLS key. Without the chain_id binding, an attacker who runs the
    /// same BLS key on two deployments could replay the genesis-time
    /// PoP across them.
    #[test]
    fn bls_pop_chain_id_separation_prevents_cross_deployment_replay() {
        let (sk, pk) = bls_signer(0x10);
        let chain_a = ChainId([0xAA; 32]);
        let chain_b = ChainId([0xBB; 32]);

        let pop_a = BlsAggregated::sign_pop(&sk, &chain_a).unwrap();

        // Sanity: same chain still verifies.
        BlsAggregated::verify_pop(&pop_a, &pk, &chain_a)
            .expect("PoP must verify under its own chain_id");

        // The cross-chain replay attempt fails at the BLS verify step
        // (the embedded pubkey is the same as `expected_pubkey`, so the
        // mismatch check passes — only the signature math catches it).
        assert!(matches!(
            BlsAggregated::verify_pop(&pop_a, &pk, &chain_b),
            Err(BlsKeyError::Blst(_)),
        ));
    }
}
