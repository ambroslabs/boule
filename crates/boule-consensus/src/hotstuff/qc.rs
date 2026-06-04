//! Quorum certificates and the consensus wire types they appear in.
//!
//! A [`QuorumCertificate`] (QC) is a proof that a quorum of validators
//! signed off on a `(view, block_hash)` pair. HotStuff piles QCs on
//! top of each other to reach a three-chain commit: see the
//! `safety_rules` module (7.B / #92) for the rule itself.
//!
//! # Signature representation
//!
//! The `(view, block_hash)`-pair quorum is encoded as a
//! [`SignerBitmap`] plus an aggregate of partial signatures. The
//! aggregate is carried in the scheme-tagged [`QcSignatures`] enum:
//!
//! - [`QcSignatures::Ed25519Collected`]: a `Vec<[u8; 64]>` of raw
//!   Ed25519 signatures parallel to the bitmap's set bits. The k-th
//!   entry belongs to the k-th validator index whose bit is set in
//!   [`QuorumCertificate::signers`] (scanning low→high).
//! - [`QcSignatures::BlsAggregated`]: a single ~96-byte BLS12-381 G2
//!   point aggregating every partial signature.
//!
//! Choose at construction:
//! [`QuorumCertificate::new`] + [`QuorumCertificate::add_signature`]
//! for Ed25519, or [`QuorumCertificate::new_bls`] +
//! [`QuorumCertificate::add_bls_partial`] for BLS. The
//! Ed25519/BLS-flavored helpers (`add_signature` / `add_bls_partial` /
//! `verify_aggregate` / `verify_aggregate_bls`) panic if invoked on a
//! QC whose variant they don't match — chains pick one scheme at
//! genesis (#288) so a mixed call site is a programming error, not a
//! runtime input the protocol must tolerate.
//!
//! Wire format: postcard tags the [`QcSignatures`] variant with one
//! byte. The pre-#293 layout (a bare `Vec<[u8; 64]>`) is no longer
//! compatible — the scheme tag is mandatory so an inbound QC can be
//! decoded without ambient knowledge of the chain's scheme.
//!
//! # Wire types
//!
//! The three message payloads are [`Proposal`], [`Vote`], and
//! [`NewView`]. Each implements [`SignedMessage`] with a distinct
//! `DOMAIN` string — a signature produced for one kind cannot be
//! replayed as another kind, even when the serialized bytes happen to
//! collide. The integration layer (#24) wraps outgoing payloads in
//! [`Signed`] before putting them on the wire; the safety core trusts
//! that inbound [`Signed`] values have already been verified.
//!
//! [`ValidatorSet`]: crate::validator_set::ValidatorSet
//! [`SignedMessage`]: boule_core::crypto::signed::SignedMessage
//! [`Signed`]: boule_core::crypto::signed::Signed

use serde::{Deserialize, Serialize};

use crate::View;
use crate::replication::block::{Block, BlockHash};
use crate::validator_set::ValidatorSet;
use boule_core::crypto::sig_scheme::{
    AggregateVerifyError, BlsAggregate, BlsAggregated, BlsPublicKey, Ed25519Collected,
    SignatureScheme,
};
use boule_core::crypto::signed::SignedMessage;
use boule_core::identity::NodeId;

/// HotStuff quorum threshold over a flat (count-based) committee:
/// `2n/3 + 1`.
///
/// For `n = 3f + 1` this equals `2f + 1`, the usual BFT quorum.
/// `quorum_size(0)` returns `1` (a harmless default — an empty
/// validator set has no quorum).
///
/// **Note (#461):** The protocol's quorum predicate
/// ([`QuorumCertificate::has_quorum`]) is **weight-based**, not
/// count-based. This helper survives because test fixtures and
/// simulation adversaries that operate at uniform weight = 1 still
/// reason about "the count threshold" in the degenerate case;
/// production paths in `step.rs`, `node/`, and `dispatch/` go through
/// the weighted predicate. Equivalent at weight = 1: `quorum_size(n) =
/// quorum_weight_threshold(uniform-1 set of size n)`.
pub const fn quorum_size(n: usize) -> usize {
    (2 * n) / 3 + 1
}

/// Honesty threshold over a flat (count-based) committee: `n/3 + 1`.
///
/// Any set of `n/3 + 1` distinct signers includes at least one honest
/// signer under the standard `n = 3f + 1` BFT assumption (at most `f =
/// n/3` faulty replicas, so `f + 1` is the smallest set guaranteed to
/// contain an honest member).
///
/// Used historically by the round-sync hint (`OnRoundSync`) so a
/// single Byzantine `TimeoutVote` cannot drag honest replicas'
/// `current_view` forward (issue #218).
///
/// **Note (#461):** The integration layer's round-sync gate is
/// weight-based via [`honesty_weight_threshold`]; this helper survives
/// at the count-based weight = 1 degenerate case for tests.
///
/// `honesty_threshold(0)` returns `1` (mirrors [`quorum_size`]'s
/// degenerate-default behaviour).
pub const fn honesty_threshold(n: usize) -> usize {
    n / 3 + 1
}

/// HotStuff weighted quorum threshold: the smallest signer-weight `w`
/// satisfying `3*w > 2*total_weight`. Equivalently
/// `floor(2*total_weight/3) + 1`.
///
/// At uniform weight = 1 this collapses to [`quorum_size`]`(vs.len())`.
/// Returns `1` for an empty validator set (mirrors the `quorum_size(0)
/// = 1` degenerate default).
///
/// Use this only for diagnostics / human-readable surfaces — the
/// predicate ([`QuorumCertificate::has_quorum`]) uses the
/// multiply-not-divide form `3*signer_weight > 2*total_weight`
/// directly to avoid rounding bugs at the boundary.
pub fn quorum_weight_threshold(vs: &ValidatorSet) -> u128 {
    let total = vs.total_weight();
    if total == 0 {
        1
    } else {
        // 2*total fits in u128 because total ≤ n * u64::MAX ≪ u128::MAX
        // for any realistic n. Saturating is defensive against future
        // changes that lift the per-weight upper bound.
        2u128.saturating_mul(total) / 3 + 1
    }
}

/// Honesty threshold over a weighted committee: the smallest signer-
/// weight whose tally is guaranteed to contain at least one honest
/// signer under the chain's BFT assumption (Byzantine weight ≤
/// `floor(total_weight / 3)`).
///
/// `floor(total_weight / 3) + 1` — strictly greater than the largest
/// possible Byzantine weight. At uniform weight = 1 this collapses to
/// [`honesty_threshold`]`(vs.len())`.
///
/// Used by the round-sync hint at the integration layer
/// (`timeout_bucket.rs`).
pub fn honesty_weight_threshold(vs: &ValidatorSet) -> u128 {
    let total = vs.total_weight();
    if total == 0 { 1 } else { total / 3 + 1 }
}

/// Compact signer set indexed over a [`ValidatorSet`]'s sorted order.
///
/// Defined in the crypto layer (it is the signature-aggregation bitmap)
/// and surfaced here as part of the QC API.
pub use boule_core::crypto::sig_scheme::SignerBitmap;

/// A proof that a quorum of validators signed off on
/// `(view, block_hash)`.
///
/// The `signatures` field is scheme-shaped — see [`QcSignatures`]. On
/// Ed25519 chains it carries the parallel-on-set-bits Vec; on BLS
/// chains it carries a single ~96-byte aggregate G2 point.
///
/// Fields are `pub(crate)` so safety-rule tests can hand-construct QCs
/// without forcing new `add_signature` + `seal` plumbing here; outside
/// the crate, construct via [`QuorumCertificate::new`] +
/// [`QuorumCertificate::add_signature`] (Ed25519) or
/// [`QuorumCertificate::new_bls`] + [`QuorumCertificate::add_bls_partial`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumCertificate {
    pub view: View,
    pub block_hash: BlockHash,
    pub(crate) signers: SignerBitmap,
    pub(crate) signatures: QcSignatures,
}

/// The aggregate-signature payload carried in a [`QuorumCertificate`].
///
/// Tagged at the wire-format level by a postcard variant byte (one
/// extra byte per QC vs. the pre-#293 collected-only layout) so a node
/// can decode an inbound QC without ambient knowledge of the chain's
/// scheme. Mismatched-scheme QCs are caught structurally instead of
/// silently mis-deserializing.
///
/// Mixed-scheme chains are out of scope (parent issue non-goal): a
/// chain commits to one scheme at genesis (#288), and only that
/// variant ever appears in committed blocks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QcSignatures {
    /// One raw Ed25519 signature per signer, parallel to the set bits
    /// of the QC's [`SignerBitmap`]. Wire size grows with the quorum.
    Ed25519Collected(#[serde(with = "serde_sig_vec")] Vec<[u8; 64]>),
    /// A single ~96-byte BLS12-381 G2 point aggregating every partial.
    /// Wire size is constant in the quorum count.
    BlsAggregated(#[serde(with = "serde_g2_aggregate")] BlsAggregate),
}

impl QcSignatures {
    /// Variant name for diagnostics. Matches
    /// [`boule_core::crypto::sig_scheme::SignatureScheme::NAME`] so logs
    /// stay consistent.
    pub fn scheme_name(&self) -> &'static str {
        match self {
            Self::Ed25519Collected(_) => Ed25519Collected::NAME,
            Self::BlsAggregated(_) => BlsAggregated::NAME,
        }
    }
}

/// Serialize a `Vec<[u8; 64]>` as a sequence of byte arrays. Needed
/// because the stdlib's `serde` derive stops auto-implementing
/// `Deserialize` for `[u8; N]` at N=32; we keep the representation
/// explicit so the wire format stays stable across serde versions.
/// Mirrors the `serde_sig` module in `src/crypto/signed.rs`.
mod serde_sig_vec {
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

    // `&Vec<_>` is forced by serde's `#[serde(with = "...")]` convention
    // — the signature must match the field type exactly.
    #[allow(clippy::ptr_arg)]
    pub fn serialize<S: Serializer>(sigs: &Vec<[u8; 64]>, s: S) -> Result<S::Ok, S::Error> {
        // Encode as `Vec<&[u8]>` — postcard writes each as length-prefixed bytes.
        let as_slices: Vec<&[u8]> = sigs.iter().map(|a| &a[..]).collect();
        as_slices.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u8; 64]>, D::Error> {
        let v: Vec<Vec<u8>> = Vec::<Vec<u8>>::deserialize(d)?;
        v.into_iter()
            .map(|bytes| {
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| D::Error::custom("signature must be exactly 64 bytes"))
            })
            .collect()
    }
}

mod serde_g2_aggregate {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(agg: &[u8; 96], s: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&agg[..], s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 96], D::Error> {
        let v: Vec<u8> = Vec::<u8>::deserialize(d)?;
        v.as_slice()
            .try_into()
            .map_err(|_| D::Error::custom("BLS aggregate must be exactly 96 bytes"))
    }
}

impl QuorumCertificate {
    /// Construct a QC from raw parts, including a possibly-malformed
    /// `signers`/`signatures` pair. Test-only (gated behind `cfg(test)` /
    /// the `testing` feature) so the wire fuzzer in `boule-node` can mint
    /// adversarial QCs that the normal `new` + `add_signature` path would
    /// never produce; production code must go through those constructors.
    #[cfg(any(test, feature = "testing"))]
    pub fn from_raw_parts(
        view: View,
        block_hash: BlockHash,
        signers: SignerBitmap,
        signatures: QcSignatures,
    ) -> Self {
        Self {
            view,
            block_hash,
            signers,
            signatures,
        }
    }

    /// Start an empty Ed25519-collected QC that can accumulate up to
    /// `validator_set_len` signatures. Use [`add_signature`] to populate
    /// it.
    ///
    /// [`add_signature`]: Self::add_signature
    pub fn new(view: impl Into<View>, block_hash: BlockHash, validator_set_len: usize) -> Self {
        Self {
            view: view.into(),
            block_hash,
            signers: SignerBitmap::new(validator_set_len),
            signatures: QcSignatures::Ed25519Collected(Vec::new()),
        }
    }

    /// Start an empty BLS-aggregated QC that can accumulate up to
    /// `validator_set_len` partials. Use [`add_bls_partial`] to populate
    /// it.
    ///
    /// [`add_bls_partial`]: Self::add_bls_partial
    pub fn new_bls(view: impl Into<View>, block_hash: BlockHash, validator_set_len: usize) -> Self {
        Self {
            view: view.into(),
            block_hash,
            signers: SignerBitmap::new(validator_set_len),
            signatures: QcSignatures::BlsAggregated(BlsAggregated::empty_aggregate()),
        }
    }

    /// True iff this QC carries an Ed25519 collected aggregate.
    pub fn is_ed25519(&self) -> bool {
        matches!(self.signatures, QcSignatures::Ed25519Collected(_))
    }

    /// True iff this QC carries a BLS aggregate.
    pub fn is_bls(&self) -> bool {
        matches!(self.signatures, QcSignatures::BlsAggregated(_))
    }

    /// Record one signer's `[u8; 64]` Ed25519 signature. `validator_idx`
    /// is the validator's index in the sorted [`ValidatorSet`].
    ///
    /// Keeps the "parallel on set bits" invariant: the signature is
    /// inserted at the position corresponding to where `validator_idx`
    /// falls among the already-set bits. Ignored (no-op) if the bit is
    /// already set — duplicate signatures for the same signer do not
    /// change quorum status.
    ///
    /// **Panics** if this QC was constructed for a non-Ed25519 scheme.
    /// Use [`Self::add_bls_partial`] on BLS QCs.
    pub fn add_signature(&mut self, validator_idx: usize, sig: [u8; 64]) {
        let QcSignatures::Ed25519Collected(sigs) = &mut self.signatures else {
            panic!(
                "QuorumCertificate::add_signature called on a {} QC; use add_bls_partial",
                self.signatures.scheme_name(),
            );
        };
        if self.signers.get(validator_idx) {
            return;
        }
        Ed25519Collected::add_partial(sigs, &self.signers, validator_idx, sig);
        self.signers.set(validator_idx);
        debug_assert_eq!(
            self.signers.count(),
            Ed25519Collected::aggregate_count(sigs),
            "signer bits and signatures must stay parallel",
        );
    }

    /// Record one signer's BLS partial signature on a BLS-flavored QC.
    /// `validator_idx` is the index in the sorted [`ValidatorSet`].
    ///
    /// **Panics** if this QC was constructed for a non-BLS scheme.
    /// The caller MUST have validated `partial` against the signer's
    /// pubkey via
    /// [`BlsAggregated::verify_partial`](boule_core::crypto::sig_scheme::BlsAggregated::verify_partial)
    /// before calling this — folding a malformed partial into the
    /// aggregate corrupts it for everyone.
    pub fn add_bls_partial(
        &mut self,
        validator_idx: usize,
        partial: boule_core::crypto::sig_scheme::BlsPartialSig,
    ) {
        let QcSignatures::BlsAggregated(agg) = &mut self.signatures else {
            panic!(
                "QuorumCertificate::add_bls_partial called on a {} QC; use add_signature",
                self.signatures.scheme_name(),
            );
        };
        if self.signers.get(validator_idx) {
            return;
        }
        BlsAggregated::add_partial(agg, &self.signers, validator_idx, partial);
        self.signers.set(validator_idx);
    }

    /// Verify that this QC's Ed25519 aggregate is valid over `message`
    /// under `pubkeys`. `pubkeys` must contain one entry per validator
    /// in the relevant validator set, in the same sorted order the
    /// [`SignerBitmap`] indexes.
    ///
    /// **Panics** if this QC carries a non-Ed25519 scheme.
    pub fn verify_aggregate(
        &self,
        message: &[u8],
        pubkeys: &[NodeId],
    ) -> Result<(), AggregateVerifyError> {
        let QcSignatures::Ed25519Collected(sigs) = &self.signatures else {
            panic!(
                "verify_aggregate called on a {} QC; use verify_aggregate_bls",
                self.signatures.scheme_name(),
            );
        };
        Ed25519Collected::verify_aggregate(sigs, &self.signers, message, pubkeys)
    }

    /// Verify that this QC's BLS aggregate is valid over `message`
    /// under `pubkeys`. Single pairing check.
    ///
    /// **Panics** if this QC carries a non-BLS scheme.
    pub fn verify_aggregate_bls(
        &self,
        message: &[u8],
        pubkeys: &[BlsPublicKey],
    ) -> Result<(), AggregateVerifyError> {
        let QcSignatures::BlsAggregated(agg) = &self.signatures else {
            panic!(
                "verify_aggregate_bls called on a {} QC; use verify_aggregate",
                self.signatures.scheme_name(),
            );
        };
        BlsAggregated::verify_aggregate(agg, &self.signers, message, pubkeys)
    }

    /// Number of validators whose signature this QC carries.
    pub fn signer_count(&self) -> usize {
        self.signers.count()
    }

    /// The validator indices whose bit is set in this QC's
    /// [`SignerBitmap`] — i.e. who signed. Scheme-agnostic (the bitmap is
    /// populated for both Ed25519 and BLS QCs), unlike
    /// [`Self::iter_signatures`] which yields only Ed25519 partial
    /// signatures. Each index is into the validator set authoritative at
    /// `qc.view`; resolve it with [`ValidatorSet::get`] /
    /// [`ValidatorSet::weight_at`]. Used to surface commit-info to the
    /// application (#653).
    pub fn signer_indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.signers.iter_set()
    }

    /// Sum of the voting weights of validators whose bit is set in
    /// this QC's [`SignerBitmap`], evaluated against `vs`. `vs` must
    /// be the validator set authoritative at `qc.view` (#460/#461).
    ///
    /// Returns `u128` so weights summing near `u64::MAX` don't wrap.
    pub fn signer_weight(&self, vs: &ValidatorSet) -> u128 {
        debug_assert_eq!(
            self.signers.len(),
            vs.len(),
            "signer_weight: bitmap length and validator-set length must match",
        );
        let mut acc: u128 = 0;
        for idx in self.signers.iter_set() {
            // Defensive bound: a malformed bitmap can have set bits
            // past `vs.len()` if the caller skipped `is_well_formed`.
            // Iterating `iter_set` past the validator set's range
            // would panic on `weight_at`; skip instead so the predicate
            // returns false on bogus QCs rather than panicking.
            if idx >= vs.len() {
                continue;
            }
            acc = acc.saturating_add(u128::from(vs.weight_at(idx)));
        }
        acc
    }

    /// True iff the validators whose bits are set in this QC's bitmap
    /// account for **strictly more than** two-thirds of `vs`'s total
    /// voting weight. The integer-math form `3*signer_weight >
    /// 2*total_weight` avoids division and rounding bugs at the
    /// boundary.
    ///
    /// At uniform weight = 1 this is exactly `signer_count >=
    /// quorum_size(vs.len())`, so existing weight = 1 fixtures behave
    /// byte-identically.
    pub fn has_quorum(&self, vs: &ValidatorSet) -> bool {
        let signer = self.signer_weight(vs);
        let total = vs.total_weight();
        // saturating_mul: a pathological u128-overflow input saturates
        // both sides to u128::MAX, the strict-`>` returns false — i.e.
        // the safe direction is "no quorum."
        3u128.saturating_mul(signer) > 2u128.saturating_mul(total)
    }

    /// Well-formedness check used when accepting a QC from the wire:
    /// the bitmap sizes match the claimed validator set, no stray bits
    /// are set, and the `signatures` payload is structurally consistent
    /// with the bitmap. Does **not** check signature validity — that's
    /// the integration layer's job.
    ///
    /// For Ed25519: the parallel `Vec<[u8; 64]>` length must equal the
    /// bitmap's set-bit count.
    /// For BLS: the aggregate is a single G2 point, so there's no count
    /// to check, but the bitmap-emptiness and aggregate-emptiness must
    /// agree: an empty bitmap requires the empty-aggregate sentinel,
    /// and a non-empty bitmap requires a non-sentinel aggregate.
    /// `verify_aggregate_bls` would catch the cryptographic side of the
    /// same problem, but a structural reject here is cheap and lets
    /// callers drop malformed QCs without paying a pairing check.
    pub fn is_well_formed(&self, vs: &ValidatorSet) -> bool {
        if self.signers.len() != vs.len() || !self.signers.is_well_formed() {
            return false;
        }
        match &self.signatures {
            QcSignatures::Ed25519Collected(sigs) => sigs.len() == self.signers.count(),
            QcSignatures::BlsAggregated(agg) => {
                (self.signers.count() == 0) == BlsAggregated::is_empty_aggregate(agg)
            }
        }
    }

    /// Iterate `(validator_idx, &signature)` pairs in validator-index
    /// order. Ed25519-only — BLS QCs carry a single aggregate, not a
    /// per-signer view.
    ///
    /// **Panics** if this QC carries a non-Ed25519 scheme.
    pub fn iter_signatures(&self) -> impl Iterator<Item = (usize, &[u8; 64])> + '_ {
        let QcSignatures::Ed25519Collected(sigs) = &self.signatures else {
            panic!(
                "iter_signatures called on a {} QC; the BLS aggregate is a single point",
                self.signatures.scheme_name(),
            );
        };
        self.signers.iter_set().zip(sigs.iter())
    }
}

/// A [`QuorumCertificate`] whose aggregate signature has been verified
/// against the validator set authoritative at `qc.view`.
///
/// Mirrors the [`crate::dispatch::Verified`] envelope
/// pattern at the QC layer: the safety core's `state.high_qc` is typed
/// `Option<VerifiedQc>` so a future snapshot importer or persistence
/// path that decodes a QC from bytes cannot land it in the safety
/// core without a typed-by-construction trust justification. Audit
/// finding 5-1 / issue #408.
///
/// # Constructors
///
/// - [`VerifiedQc::unchecked`]: production callers MUST be at named
///   audit sites (currently enumerated in that constructor's doc);
///   tests use freely. Every production call site is grep-able by
///   name and explains its trust model in an inline comment.
///
/// The wire format is unchanged — `QuorumCertificate` is what crosses
/// the network and what is persisted to disk; `VerifiedQc` only
/// exists in-memory inside the safety core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedQc(QuorumCertificate);

impl VerifiedQc {
    /// Construct a `VerifiedQc` without running aggregate verification.
    ///
    /// **Production code MUST NOT call this except at audited-by-name
    /// sites.** Every call site in production is grep-able as
    /// `VerifiedQc::unchecked` and includes an inline comment
    /// justifying its trust model. The currently-allowed production
    /// trust paths are:
    ///
    /// 1. **Genesis QC seed** — `ConsensusNode::new` and
    ///    `recover_state` mint the cluster-agreed genesis QC via
    ///    [`genesis_qc`] / [`genesis_qc_bls`] before the safety core
    ///    has seen any wire traffic. The dispatch verifier
    ///    `crate::dispatch::verify::qc::verify_qc_if_requested`
    ///    short-circuits at `view == 0 || signer_count == 0`, so
    ///    wrapping unchecked is exactly equivalent.
    /// 2. **QC adopted from a `Verified<Signed<Proposal>>` /
    ///    `Verified<Signed<NewView>>` envelope** — the dispatch
    ///    verifier ran `verify_qc_if_requested` against the
    ///    historical validator set at `qc.view` before constructing
    ///    the envelope. Extracting the QC for `state.high_qc` carries
    ///    that same proof.
    /// 3. **Locally-formed QC from ingress-verified vote envelopes**
    ///    (`HotStuffCore::on_vote_received`). Ed25519 partials and
    ///    BLS partials each get verified at ingress against the
    ///    signer's per-historical-view pubkey before they reach the
    ///    safety core; the locally-assembled aggregate is
    ///    well-formed by construction.
    /// 4. **QC piggybacked on a `TimeoutVote` that survived
    ///    `verify_high_qc_piggyback`** (`high_qc_trusted == true`).
    ///    The piggyback verifier runs the same aggregate-verify
    ///    check as the hard path; on failure the piggyback is
    ///    dropped before the bucket sees it (audit finding 10-F3 /
    ///    issue #321).
    /// 5. **QC decoded by `recover_state` from our own durable
    ///    storage**. The QC was a `VerifiedQc` at the time we
    ///    persisted it; trust on read mirrors what we extend to
    ///    `last_voted_view` and `locked` from the same store.
    /// 6. **QC adopted via
    ///    [`crate::hotstuff::step::HotStuffCore::adopt_snapshot`]
    ///    from a `SnapshotManifest`** that survived
    ///    `SnapshotManifest::verify` upstream.
    ///
    /// Tests use this freely.
    pub fn unchecked(qc: QuorumCertificate) -> Self {
        Self(qc)
    }

    /// Borrow the inner QC. Read-only access for safety-rule
    /// predicates and any caller that needs the raw signature payload
    /// (e.g. wire-egress, where the typestate is stripped).
    pub fn inner(&self) -> &QuorumCertificate {
        &self.0
    }

    /// Consume and unwrap. Used at wire-egress to extract the raw
    /// `QuorumCertificate` for serialization (the wire format is
    /// `QuorumCertificate`, not `VerifiedQc`).
    pub fn into_inner(self) -> QuorumCertificate {
        self.0
    }

    /// Shortcut for `self.inner().view` so safety-rule readers stay
    /// terse.
    pub fn view(&self) -> View {
        self.0.view
    }

    /// Shortcut for `self.inner().block_hash`.
    pub fn block_hash(&self) -> BlockHash {
        self.0.block_hash
    }
}

// ───────────────────────────── wire types ─────────────────────────────

/// A leader's proposal for a new block at some view, justified by a QC
/// over its parent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    pub block: Block,
    pub justify: QuorumCertificate,
}

impl SignedMessage for Proposal {
    const DOMAIN: &'static str = "boule.hotstuff.proposal.v1";
}

/// A replica's vote for a block it considers safe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vote {
    pub view: View,
    pub block_hash: BlockHash,
}

impl SignedMessage for Vote {
    const DOMAIN: &'static str = "boule.hotstuff.vote.v1";
}

/// A replica entering a new view and announcing the highest QC it
/// knows. Forwarded to the leader of the new view so that leader can
/// build a proposal whose `justify` descends from the cluster's
/// highest-known chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewView {
    pub high_qc: QuorumCertificate,
}

impl SignedMessage for NewView {
    const DOMAIN: &'static str = "boule.hotstuff.newview.v1";
}

/// A replica's signed "I am giving up on `view`" notice. Quoted across
/// a quorum these form a *timeout certificate* that lets the pacemaker
/// advance to `view + 1` even when the leader crashed or its proposal
/// never reached enough replicas.
///
/// The piggybacked `high_qc` lets the cluster converge on the freshest
/// QC any timed-out replica had observed — the standard HotStuff
/// liveness trick that prevents a departing leader's fresher QC from
/// being lost. `None` means this replica has never seen any QC (only
/// possible at very early bootstrap; the genesis-QC seed normally
/// keeps this `Some`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeoutVote {
    pub view: View,
    pub high_qc: Option<QuorumCertificate>,
}

impl SignedMessage for TimeoutVote {
    const DOMAIN: &'static str = "boule.hotstuff.timeout.v1";
}

/// Logical consensus message emitted by the safety core via
/// [`Action::Broadcast`]. The integration layer (#24) wraps the
/// contained payload in a [`Signed`] before putting it on the wire.
///
/// [`Action::Broadcast`]: super::step::Action::Broadcast
/// [`Signed`]: boule_core::crypto::signed::Signed
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// The `Proposal` variant carries a full block and is inherently far
// larger than the vote/new-view variants; boxing it would churn every
// construction and match site across dispatch and the integration layer
// for no real memory win at consensus-message volumes.
#[allow(clippy::large_enum_variant)]
pub enum ConsensusMsg {
    Proposal(Proposal),
    Vote(Vote),
    NewView(NewView),
}

/// Build the cluster-agreed genesis [`QuorumCertificate`] every replica
/// seeds into its `high_qc` at boot.
///
/// By convention a genesis QC has `view = 0`, `block_hash =
/// genesis.hash()`, and the lowest-indexed validator slots signed with
/// all-zero placeholders, filled until the running weight sum crosses
/// the weighted-quorum threshold (#461). The safety core never re-
/// verifies embedded QC signatures (that is the ingress layer's job at
/// the envelope level), so the placeholder signatures never reach a
/// verifier; they exist only to make the QC's
/// [`QuorumCertificate::has_quorum`] / [`QuorumCertificate::is_well_formed`]
/// predicates tell the truth about "a quorum signed off on the chain
/// root."
///
/// At uniform weight = 1 (the case for every chain that has not yet
/// committed a non-uniform reconfig) the fill is byte-identical to the
/// pre-#461 `0..quorum_size(n)` loop — both stop after exactly
/// `quorum_size(n)` iterations.
///
/// Every honest replica constructs an identical genesis QC from the
/// same `(genesis, vs)` pair, so the view-1 leader's proposal —
/// justified by this QC — is indistinguishable across replicas.
pub fn genesis_qc(genesis: &Block, vs: &ValidatorSet) -> QuorumCertificate {
    let mut qc = QuorumCertificate::new(View::ZERO, genesis.hash(), vs.len());
    let mut accum: u128 = 0;
    let total = vs.total_weight();
    for i in 0..vs.len() {
        qc.add_signature(i, [0u8; 64]);
        accum = accum.saturating_add(u128::from(vs.weight_at(i)));
        // Stop as soon as the running weight strictly crosses 2/3.
        if 3u128.saturating_mul(accum) > 2u128.saturating_mul(total) {
            break;
        }
    }
    qc
}

/// BLS-flavored counterpart to [`genesis_qc`]. Returns the empty BLS QC
/// over the genesis block: an empty signer bitmap and the
/// `BLS_EMPTY_AGGREGATE_SENTINEL` aggregate.
///
/// **The bitmap is left empty intentionally.** The `Ed25519Collected`
/// genesis QC fills its bitmap with `quorum_size` placeholder
/// signatures because the verifier's well-formedness invariant
/// requires `signatures.len() == signers.count()`. The BLS variant
/// does not need this because its well-formedness check (#338) is the
/// dual `(empty bitmap) ↔ (empty-aggregate sentinel)` invariant — and
/// the dispatch-layer QC verifier (#345/#353) treats `signer_count == 0`
/// as the genesis-skip condition in addition to `view == 0`. Mirroring
/// the Ed25519 placeholder fill here would set bits without folding
/// any real partials, leaving the aggregate at the empty sentinel and
/// failing the `(non-empty bitmap) ↔ (non-sentinel aggregate)` half of
/// the well-formedness check.
///
/// Every honest replica on a `bls_aggregated` chain derives the same
/// QC from the shared `(genesis, validator_set_len)` pair, so the
/// view-1 leader's proposal — justified by this QC — is byte-identical
/// across replicas.
pub fn genesis_qc_bls(genesis: &Block, validator_set_len: usize) -> QuorumCertificate {
    QuorumCertificate::new_bls(View::ZERO, genesis.hash(), validator_set_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use boule_core::crypto::signed::{ChainId, NodeSigner, Signed, Signer};
    use boule_core::identity::NodeId;
    use boule_core::identity::NodeIdentity;
    use rcgen::{KeyPair as RcgenKeyPair, PKCS_ED25519};
    use zeroize::Zeroizing;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn vid(b: u8) -> crate::validator_set::ValidatorId {
        crate::validator_set::ValidatorId::from_genesis_pubkey(nid(b))
    }

    fn four_validators() -> ValidatorSet {
        ValidatorSet::new(vec![vid(1), vid(2), vid(3), vid(4)])
    }

    fn fresh_signer() -> NodeSigner {
        let kp = RcgenKeyPair::generate_for(&PKCS_ED25519).unwrap();
        let identity = NodeIdentity {
            pkcs8_der: Zeroizing::new(kp.serialize_der()),
        };
        NodeSigner::from_identity(&identity).unwrap()
    }

    // ── quorum_size ──────────────────────────────────────────────

    #[test]
    fn quorum_size_matches_hotstuff_2f_plus_1() {
        // n = 3f+1 → quorum = 2f+1
        assert_eq!(quorum_size(1), 1); // f=0
        assert_eq!(quorum_size(4), 3); // f=1
        assert_eq!(quorum_size(7), 5); // f=2
        assert_eq!(quorum_size(10), 7); // f=3
        // Non-3f+1 sizes still obey 2n/3+1.
        assert_eq!(quorum_size(2), 2);
        assert_eq!(quorum_size(3), 3);
        assert_eq!(quorum_size(0), 1);
    }

    // ── QuorumCertificate ────────────────────────────────────────

    fn sample_block_hash() -> BlockHash {
        [0xBB; 32]
    }

    #[test]
    fn qc_empty_has_no_quorum() {
        let vs = four_validators();
        let qc = QuorumCertificate::new(View(5), sample_block_hash(), vs.len());
        assert_eq!(qc.signer_count(), 0);
        assert!(!qc.has_quorum(&vs));
        assert!(qc.is_well_formed(&vs));
    }

    #[test]
    fn qc_below_threshold_is_not_quorum() {
        let vs = four_validators();
        let mut qc = QuorumCertificate::new(View(1), sample_block_hash(), vs.len());
        // n=4 → quorum=3. Two signatures is not enough.
        qc.add_signature(0, [1; 64]);
        qc.add_signature(2, [2; 64]);
        assert_eq!(qc.signer_count(), 2);
        assert!(!qc.has_quorum(&vs));
    }

    #[test]
    fn qc_at_threshold_reaches_quorum() {
        let vs = four_validators();
        let mut qc = QuorumCertificate::new(View(1), sample_block_hash(), vs.len());
        qc.add_signature(0, [1; 64]);
        qc.add_signature(1, [2; 64]);
        qc.add_signature(3, [3; 64]);
        assert_eq!(qc.signer_count(), 3);
        assert!(qc.has_quorum(&vs));
    }

    #[test]
    fn qc_duplicate_signature_is_noop() {
        let vs = four_validators();
        let mut qc = QuorumCertificate::new(View(1), sample_block_hash(), vs.len());
        qc.add_signature(2, [7; 64]);
        qc.add_signature(2, [9; 64]); // duplicate — first write wins
        assert_eq!(qc.signer_count(), 1);
        let QcSignatures::Ed25519Collected(sigs) = &qc.signatures else {
            panic!("expected Ed25519");
        };
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0], [7; 64]);
    }

    #[test]
    fn qc_signatures_stay_parallel_to_set_bits_regardless_of_insertion_order() {
        let vs = four_validators();
        let mut qc = QuorumCertificate::new(View(2), sample_block_hash(), vs.len());
        // Insert out of order: 3, then 0, then 2.
        qc.add_signature(3, [0x33; 64]);
        qc.add_signature(0, [0x00; 64]);
        qc.add_signature(2, [0x22; 64]);

        // iter_signatures must yield them in validator-index order.
        let collected: Vec<(usize, [u8; 64])> =
            qc.iter_signatures().map(|(i, s)| (i, *s)).collect();
        assert_eq!(
            collected,
            vec![(0, [0x00; 64]), (2, [0x22; 64]), (3, [0x33; 64])]
        );
    }

    #[test]
    fn qc_is_well_formed_rejects_size_mismatch() {
        let vs = four_validators();
        let qc_wrong_size = QuorumCertificate::new(View(1), sample_block_hash(), vs.len() + 1);
        assert!(!qc_wrong_size.is_well_formed(&vs));
    }

    #[test]
    fn qc_postcard_roundtrip_stable() {
        let vs = four_validators();
        let mut qc = QuorumCertificate::new(View(9), [0xAB; 32], vs.len());
        qc.add_signature(0, [0x10; 64]);
        qc.add_signature(3, [0x40; 64]);

        let wire = postcard::to_stdvec(&qc).unwrap();
        let back: QuorumCertificate = postcard::from_bytes(&wire).unwrap();
        assert_eq!(back, qc);
        assert!(back.is_well_formed(&vs));
    }

    // ── wire types via Signed<_> ────────────────────────────────

    #[test]
    fn proposal_signs_and_verifies_under_its_domain() {
        let signer = fresh_signer();
        let vs = four_validators();
        let mut justify = QuorumCertificate::new(View::ZERO, [0; 32], vs.len());
        justify.add_signature(0, [0x01; 64]);
        justify.add_signature(1, [0x02; 64]);
        justify.add_signature(2, [0x03; 64]);
        let proposal = Proposal {
            block: Block::genesis([0; 32], [0; 32]),
            justify,
        };
        let signed = Signed::sign(proposal.clone(), &signer, &ChainId::TEST).unwrap();
        signed.verify(&signer.node_id(), &ChainId::TEST).unwrap();

        let wire = postcard::to_stdvec(&signed).unwrap();
        let back: Signed<Proposal> = postcard::from_bytes(&wire).unwrap();
        assert_eq!(back.payload, proposal);
        back.verify(&signer.node_id(), &ChainId::TEST).unwrap();
    }

    #[test]
    fn vote_signs_and_verifies_under_its_domain() {
        let signer = fresh_signer();
        let vote = Vote {
            view: View(7),
            block_hash: [0x77; 32],
        };
        let signed = Signed::sign(vote.clone(), &signer, &ChainId::TEST).unwrap();
        signed.verify(&signer.node_id(), &ChainId::TEST).unwrap();

        let wire = postcard::to_stdvec(&signed).unwrap();
        let back: Signed<Vote> = postcard::from_bytes(&wire).unwrap();
        assert_eq!(back.payload, vote);
        back.verify(&signer.node_id(), &ChainId::TEST).unwrap();
    }

    #[test]
    fn newview_signs_and_verifies_under_its_domain() {
        let signer = fresh_signer();
        let vs = four_validators();
        let mut high_qc = QuorumCertificate::new(View(11), [0xCC; 32], vs.len());
        high_qc.add_signature(1, [0xAA; 64]);
        let nv = NewView { high_qc };
        let signed = Signed::sign(nv.clone(), &signer, &ChainId::TEST).unwrap();
        signed.verify(&signer.node_id(), &ChainId::TEST).unwrap();
    }

    #[test]
    fn cross_domain_replay_rejected() {
        // A signature produced for a Vote must NOT verify when the same
        // bytes are placed inside a forged Signed<NewView>. We mimic this
        // by hand-constructing two payloads whose byte content could
        // coincide and verifying that the domain tag foils the forgery.
        let signer = fresh_signer();

        // Sign a Vote.
        let vote = Vote {
            view: View(3),
            block_hash: [0x33; 32],
        };
        let signed_vote = Signed::sign(vote.clone(), &signer, &ChainId::TEST).unwrap();

        // Hand-craft a Signed<Proposal> reusing Vote's signature + signer
        // on any reasonable Proposal payload. Even if the inner byte
        // layout happened to match (it doesn't have to — we just need to
        // cover the cross-type replay path), the per-type DOMAIN string
        // ensures verification fails.
        let vs = four_validators();
        let forged: Signed<Proposal> = Signed {
            payload: Proposal {
                block: Block::genesis([0; 32], [0; 32]),
                justify: QuorumCertificate::new(vote.view, vote.block_hash, vs.len()),
            },
            signer: signed_vote.signer,
            sig: signed_vote.sig,
        };
        assert!(forged.verify(&signer.node_id(), &ChainId::TEST).is_err());
    }

    #[test]
    fn consensus_msg_enum_roundtrip() {
        let vs = four_validators();
        let mut justify = QuorumCertificate::new(View::ZERO, [0; 32], vs.len());
        justify.add_signature(0, [0xFE; 64]);
        let msg = ConsensusMsg::Proposal(Proposal {
            block: Block::genesis([0; 32], [0; 32]),
            justify,
        });
        let wire = postcard::to_stdvec(&msg).unwrap();
        let back: ConsensusMsg = postcard::from_bytes(&wire).unwrap();
        assert_eq!(back, msg);
    }

    // ── BLS-flavored QCs (#293) ──────────────────────────────────

    use boule_core::crypto::sig_scheme::{BlsAggregated, BlsPublicKey, BlsSecretKey};

    fn bls_keypair(seed: u8) -> (BlsSecretKey, BlsPublicKey) {
        let mut ikm = [0u8; 32];
        ikm.fill(seed);
        BlsAggregated::keygen(&ikm).unwrap()
    }

    // Ground-truth vectors for the EVM slashing predeploy (#732b): one validator
    // double-signs two `Vote`s at the same view (an equivocation), each over the
    // production pre-image `preimage::<Vote>(vote, chain_id)`. Emits everything
    // `Slashing.sol` needs to reconstruct + verify, in EIP-2537 uncompressed
    // encoding. `#[ignore]`; run:
    //   cargo test -p boule-consensus gen_slashing_vectors -- --nocapture --ignored
    #[test]
    #[ignore]
    fn gen_slashing_vectors() {
        use blst::min_pk::{PublicKey, Signature};
        use blst::{
            BLST_ERROR, blst_bendian_from_fp, blst_fp, blst_p1, blst_p1_affine, blst_p1_cneg,
            blst_p1_deserialize, blst_p1_generator, blst_p1_to_affine, blst_p2_affine,
            blst_p2_deserialize,
        };
        use boule_core::crypto::signed::{ChainId, preimage};

        fn hx(b: &[u8]) -> String {
            b.iter().map(|x| format!("{x:02x}")).collect()
        }
        fn fp64(fp: &blst_fp) -> [u8; 64] {
            let mut be = [0u8; 48];
            unsafe { blst_bendian_from_fp(be.as_mut_ptr(), fp) };
            let mut out = [0u8; 64];
            out[16..].copy_from_slice(&be);
            out
        }
        fn g1(a: &blst_p1_affine) -> Vec<u8> {
            [fp64(&a.x), fp64(&a.y)].concat()
        }
        fn g2(a: &blst_p2_affine) -> Vec<u8> {
            [
                fp64(&a.x.fp[0]),
                fp64(&a.x.fp[1]),
                fp64(&a.y.fp[0]),
                fp64(&a.y.fp[1]),
            ]
            .concat()
        }
        fn pk_g1(pk: &BlsPublicKey) -> Vec<u8> {
            let mut aff = blst_p1_affine::default();
            let un = PublicKey::from_bytes(pk).unwrap().serialize();
            unsafe {
                assert_eq!(
                    blst_p1_deserialize(&mut aff, un.as_ptr()),
                    BLST_ERROR::BLST_SUCCESS
                )
            };
            g1(&aff)
        }
        fn sig_g2(sig: &[u8; 96]) -> Vec<u8> {
            let mut aff = blst_p2_affine::default();
            let un = Signature::from_bytes(sig).unwrap().serialize();
            unsafe {
                assert_eq!(
                    blst_p2_deserialize(&mut aff, un.as_ptr()),
                    BLST_ERROR::BLST_SUCCESS
                )
            };
            g2(&aff)
        }

        let (sk, pk) = bls_keypair(0x9a);
        let chain = ChainId::TEST;
        let view = View(42);
        let a = [0xAAu8; 32];
        let b = [0xBBu8; 32];
        let pre_a = preimage::<Vote>(
            &Vote {
                view,
                block_hash: a,
            },
            &chain,
        )
        .unwrap();
        let pre_b = preimage::<Vote>(
            &Vote {
                view,
                block_hash: b,
            },
            &chain,
        )
        .unwrap();
        let sig_a = BlsAggregated::sign_partial(&sk, &pre_a).unwrap();
        let sig_b = BlsAggregated::sign_partial(&sk, &pre_b).unwrap();

        let mut neg_aff = blst_p1_affine::default();
        unsafe {
            let mut neg: blst_p1 = *blst_p1_generator();
            blst_p1_cneg(&mut neg, true);
            blst_p1_to_affine(&mut neg_aff, &neg);
        }

        // The registry keys by the validator's stable NodeId, independent of the
        // BLS key; any bytes32 stands in for the test.
        println!("SL_VALIDATOR={}", hx(&[0x42u8; 32]));
        println!("SL_CHAINID={}", hx(chain.as_bytes()));
        println!("SL_VIEW={}", view.0);
        println!("SL_BLOCKA={}", hx(&a));
        println!("SL_BLOCKB={}", hx(&b));
        println!("SL_PUBKEY={}", hx(&pk_g1(&pk)));
        println!("SL_SIGA={}", hx(&sig_g2(&sig_a)));
        println!("SL_SIGB={}", hx(&sig_g2(&sig_b)));
        println!("SL_NEGGEN={}", hx(&g1(&neg_aff)));
    }

    #[test]
    fn bls_qc_starts_empty_and_passes_well_formed() {
        let vs = four_validators();
        let qc = QuorumCertificate::new_bls(View(7), [0xAA; 32], vs.len());
        assert!(qc.is_bls());
        assert!(!qc.is_ed25519());
        assert_eq!(qc.signer_count(), 0);
        assert!(!qc.has_quorum(&vs));
        assert!(qc.is_well_formed(&vs));
    }

    #[test]
    fn bls_qc_aggregates_partials_and_verifies() {
        let vs = four_validators();
        let block_hash = [0xBB; 32];
        let view: View = View(11);
        let message = postcard::to_stdvec(&Vote { view, block_hash }).unwrap();

        let signers: Vec<(BlsSecretKey, BlsPublicKey)> =
            (0..vs.len() as u8).map(|i| bls_keypair(0x70 | i)).collect();
        let pubkeys: Vec<BlsPublicKey> = signers.iter().map(|(_, pk)| *pk).collect();

        let mut qc = QuorumCertificate::new_bls(view, block_hash, vs.len());
        for (idx, (sk, _)) in signers.iter().enumerate().take(quorum_size(vs.len())) {
            let partial = BlsAggregated::sign_partial(sk, &message).unwrap();
            qc.add_bls_partial(idx, partial);
        }
        assert!(qc.has_quorum(&vs));
        assert!(qc.is_well_formed(&vs));
        qc.verify_aggregate_bls(&message, &pubkeys)
            .expect("BLS QC must verify under selected pubkeys");
    }

    #[test]
    fn bls_qc_postcard_roundtrip_byte_size_constant_in_n() {
        // Aggregate is a fixed 96 bytes plus bitmap + metadata,
        // regardless of how many partials we fold in.
        let vs_small = ValidatorSet::new((0..4u8).map(|b| vid(b + 1)).collect());
        let vs_large = ValidatorSet::new((0..50u8).map(|b| vid(b + 1)).collect());
        let block_hash = [0xCC; 32];

        let mut qc_small = QuorumCertificate::new_bls(View(1), block_hash, vs_small.len());
        let mut qc_large = QuorumCertificate::new_bls(View(1), block_hash, vs_large.len());

        let message = b"benchmark";
        for (idx, qc) in [&mut qc_small, &mut qc_large].into_iter().enumerate() {
            let n = if idx == 0 {
                vs_small.len()
            } else {
                vs_large.len()
            };
            for i in 0..n {
                let (sk, _) = bls_keypair((idx * 100 + i) as u8);
                let partial = BlsAggregated::sign_partial(&sk, message).unwrap();
                qc.add_bls_partial(i, partial);
            }
        }
        let wire_small = postcard::to_stdvec(&qc_small).unwrap();
        let wire_large = postcard::to_stdvec(&qc_large).unwrap();
        // The aggregate-sig portion is fixed at 96 bytes + 1 byte
        // length prefix; growth between small (n=4) and large (n=50)
        // should come only from the bitmap and signer-count varints,
        // not from the signature payload.
        let bitmap_diff = vs_large.len().div_ceil(8) - vs_small.len().div_ceil(8);
        assert!(
            wire_large.len() <= wire_small.len() + bitmap_diff + 4,
            "BLS QC wire size grew faster than the bitmap: small={} large={} bitmap_diff={}",
            wire_small.len(),
            wire_large.len(),
            bitmap_diff,
        );
    }

    #[test]
    fn bls_qc_rejects_tampered_aggregate() {
        let vs = four_validators();
        let view: View = View(5);
        let block_hash = [0xDD; 32];
        let message = postcard::to_stdvec(&Vote { view, block_hash }).unwrap();
        let (sk0, pk0) = bls_keypair(0x80);
        let (sk1, pk1) = bls_keypair(0x81);
        let (sk2, pk2) = bls_keypair(0x82);
        let (_, pk3) = bls_keypair(0x83);
        let pubkeys = vec![pk0, pk1, pk2, pk3];

        let mut qc = QuorumCertificate::new_bls(view, block_hash, vs.len());
        for (idx, sk) in [&sk0, &sk1, &sk2].iter().enumerate() {
            qc.add_bls_partial(idx, BlsAggregated::sign_partial(sk, &message).unwrap());
        }
        // Tamper the aggregate.
        if let QcSignatures::BlsAggregated(agg) = &mut qc.signatures {
            agg[0] ^= 0xFF;
        }
        assert!(qc.verify_aggregate_bls(&message, &pubkeys).is_err());
    }

    #[test]
    #[should_panic(expected = "called on a bls_aggregated QC")]
    fn ed25519_helpers_panic_on_bls_qc() {
        let mut qc = QuorumCertificate::new_bls(View::ZERO, [0; 32], 4);
        qc.add_signature(0, [0; 64]); // wrong API
    }

    #[test]
    #[should_panic(expected = "called on a ed25519_collected QC")]
    fn bls_helpers_panic_on_ed25519_qc() {
        let mut qc = QuorumCertificate::new(View::ZERO, [0; 32], 4);
        qc.add_bls_partial(0, [0; 96]); // wrong API
    }

    #[test]
    fn bls_qc_is_well_formed_rejects_signers_with_empty_aggregate() {
        // A bitmap claiming signers but the aggregate still at the
        // empty-sentinel is structurally malformed. Catch it at
        // is_well_formed time so callers don't pay a pairing check.
        let vs = four_validators();
        let mut qc = QuorumCertificate::new_bls(View(3), [0xEE; 32], vs.len());
        // Hand-set a bit without folding a partial in: leaves the
        // aggregate at the sentinel.
        qc.signers.set(1);
        assert!(!qc.is_well_formed(&vs));
    }

    #[test]
    fn bls_qc_is_well_formed_rejects_no_signers_with_non_sentinel_aggregate() {
        // The other direction: empty bitmap but a non-sentinel
        // aggregate is also structurally malformed. Forge by signing
        // outside the QC API, then dropping the bytes into the
        // aggregate slot without setting any signer bit.
        let vs = four_validators();
        let (sk, _) = bls_keypair(0x9A);
        let stray = BlsAggregated::sign_partial(&sk, b"unrelated").unwrap();
        let mut qc = QuorumCertificate::new_bls(View(4), [0xEF; 32], vs.len());
        if let QcSignatures::BlsAggregated(agg) = &mut qc.signatures {
            *agg = stray;
        }
        assert_eq!(qc.signer_count(), 0);
        assert!(!qc.is_well_formed(&vs));
    }

    #[test]
    fn qc_signatures_scheme_name_matches_variant() {
        let qc_ed = QuorumCertificate::new(View::ZERO, [0; 32], 4);
        let qc_bls = QuorumCertificate::new_bls(View::ZERO, [0; 32], 4);
        assert_eq!(qc_ed.signatures.scheme_name(), "ed25519_collected");
        assert_eq!(qc_bls.signatures.scheme_name(), "bls_aggregated");
    }

    // ── genesis_qc_bls (#354 step 2) ───────────────────────────────────

    #[test]
    fn genesis_qc_bls_is_well_formed_under_validator_set() {
        // The empty-bitmap, empty-aggregate-sentinel shape must satisfy
        // `is_well_formed` so the dispatch verifier accepts it under
        // its `signer_count == 0` genesis-skip condition.
        let vs = four_validators();
        let genesis = Block::genesis([0; 32], [0; 32]);
        let qc = genesis_qc_bls(&genesis, vs.len());
        assert!(qc.is_well_formed(&vs));
        assert_eq!(qc.signer_count(), 0);
        assert!(qc.is_bls());
        assert_eq!(qc.view, View::ZERO);
        assert_eq!(qc.block_hash, genesis.hash());
    }

    // ── #461: weighted quorum predicate ─────────────────────────────────

    fn vid_for(b: u8) -> crate::validator_set::ValidatorId {
        crate::validator_set::ValidatorId::from_genesis_pubkey(nid(b))
    }

    /// Sanity: the weighted threshold collapses to the count-based one
    /// when every weight is 1. This is the byte-identity test that
    /// existing weight-1 fixtures rely on.
    #[test]
    fn weighted_quorum_collapses_to_count_at_weight_one() {
        for n in [1usize, 2, 3, 4, 7, 10] {
            let vs = ValidatorSet::new((0..n as u8).map(|i| vid_for(i + 1)).collect::<Vec<_>>());
            assert_eq!(
                quorum_weight_threshold(&vs) as usize,
                quorum_size(n),
                "n = {n}"
            );
            assert_eq!(
                honesty_weight_threshold(&vs) as usize,
                honesty_threshold(n),
                "n = {n}"
            );
        }
    }

    /// Non-uniform weights: a stake-heavy validator can swing quorum.
    /// Weights `[5, 1, 1, 1]` total 8; quorum threshold = `2*8/3 + 1 =
    /// 6`. Two-validator subsets meeting the threshold are the
    /// stake-heavy validator (5) plus *any* other (5+1=6 ≥ 6 ✓).
    /// Without the heavy validator, three small ones (3) do *not*
    /// meet quorum.
    #[test]
    fn nondegenerate_weights_change_quorum_subsets() {
        let vs = ValidatorSet::with_weights(vec![
            (vid_for(1), 5),
            (vid_for(2), 1),
            (vid_for(3), 1),
            (vid_for(4), 1),
        ])
        .unwrap();
        // ValidatorSet sorts by id ascending; with byte-identical
        // genesis pubkeys vid_for(1) sorts first. Confirm before
        // building bitmaps that depend on that ordering.
        assert_eq!(vs.weight_at(0), 5);

        let threshold = quorum_weight_threshold(&vs);
        assert_eq!(threshold, 6);

        // Heavy + one small: signer weight = 6 ≥ 6 ⇒ quorum.
        let mut qc_heavy_plus_small =
            QuorumCertificate::new(View(1), sample_block_hash(), vs.len());
        qc_heavy_plus_small.add_signature(0, [0; 64]); // weight 5
        qc_heavy_plus_small.add_signature(1, [0; 64]); // weight 1
        assert_eq!(qc_heavy_plus_small.signer_weight(&vs), 6);
        assert!(qc_heavy_plus_small.has_quorum(&vs));

        // Three small validators: weight = 3 < 6 ⇒ no quorum.
        let mut qc_three_small = QuorumCertificate::new(View(1), sample_block_hash(), vs.len());
        qc_three_small.add_signature(1, [0; 64]);
        qc_three_small.add_signature(2, [0; 64]);
        qc_three_small.add_signature(3, [0; 64]);
        assert_eq!(qc_three_small.signer_weight(&vs), 3);
        assert!(!qc_three_small.has_quorum(&vs));
    }

    /// The `>` (strict) comparison must reject signer weight that
    /// hits exactly `2/3` of the total. Boundary sample: total = 9,
    /// signer_weight = 6 → `3*6 = 18`, `2*9 = 18`, NOT quorum. Same
    /// total, signer_weight = 7 → `21 > 18`, quorum.
    #[test]
    fn quorum_predicate_strictly_above_two_thirds() {
        let vs =
            ValidatorSet::with_weights(vec![(vid_for(1), 3), (vid_for(2), 3), (vid_for(3), 3)])
                .unwrap();
        assert_eq!(vs.total_weight(), 9);

        let mut qc_at = QuorumCertificate::new(View(1), sample_block_hash(), vs.len());
        qc_at.add_signature(0, [0; 64]); // weight 3
        qc_at.add_signature(1, [0; 64]); // weight 3 → 6 total
        assert_eq!(qc_at.signer_weight(&vs), 6);
        assert!(
            !qc_at.has_quorum(&vs),
            "signer weight equal to 2/3 of total must NOT be quorum"
        );

        let mut qc_above = QuorumCertificate::new(View(1), sample_block_hash(), vs.len());
        qc_above.add_signature(0, [0; 64]);
        qc_above.add_signature(1, [0; 64]);
        qc_above.add_signature(2, [0; 64]);
        assert_eq!(qc_above.signer_weight(&vs), 9);
        assert!(qc_above.has_quorum(&vs));
    }

    /// Weights summing near `u64::MAX` must not wrap. The QC's
    /// `signer_weight` method aggregates into `u128`; the predicate
    /// uses saturating multiplication so a pathological u128-overflow
    /// input fails closed (returns false), never falsely declares
    /// quorum.
    #[test]
    fn has_quorum_handles_weights_near_u64_max_without_wrapping() {
        let vs = ValidatorSet::with_weights(vec![
            (vid_for(1), u64::MAX),
            (vid_for(2), u64::MAX),
            (vid_for(3), u64::MAX),
            (vid_for(4), 1),
        ])
        .unwrap();
        // total = 3 * u64::MAX + 1
        let expected_total = (u64::MAX as u128) * 3 + 1;
        assert_eq!(vs.total_weight(), expected_total);

        // Two of the three heavy validators: signer_weight = 2 *
        // u64::MAX. Threshold (in math): 3 * 2 * u64::MAX > 2 * (3 *
        // u64::MAX + 1) ⇔ 6 * u64::MAX > 6 * u64::MAX + 2 ⇔ false.
        let mut qc_two_heavy = QuorumCertificate::new(View(1), sample_block_hash(), vs.len());
        qc_two_heavy.add_signature(0, [0; 64]);
        qc_two_heavy.add_signature(1, [0; 64]);
        assert_eq!(qc_two_heavy.signer_weight(&vs), (u64::MAX as u128) * 2);
        assert!(
            !qc_two_heavy.has_quorum(&vs),
            "two-of-three heavy validators do not strictly exceed 2/3 of total"
        );

        // Add the light validator → signer_weight = 2*u64::MAX + 1.
        // 3 * (2*u64::MAX + 1) = 6*u64::MAX + 3, vs 2*total =
        // 6*u64::MAX + 2. 6*u64::MAX + 3 > 6*u64::MAX + 2 ⇒ quorum.
        let mut qc_two_heavy_plus_one =
            QuorumCertificate::new(View(1), sample_block_hash(), vs.len());
        qc_two_heavy_plus_one.add_signature(0, [0; 64]);
        qc_two_heavy_plus_one.add_signature(1, [0; 64]);
        qc_two_heavy_plus_one.add_signature(3, [0; 64]); // weight 1
        assert_eq!(
            qc_two_heavy_plus_one.signer_weight(&vs),
            (u64::MAX as u128) * 2 + 1
        );
        assert!(qc_two_heavy_plus_one.has_quorum(&vs));
    }

    /// `genesis_qc`'s fill loop is byte-identical to the pre-#461
    /// `0..quorum_size(n)` loop when every weight is 1. Spot-check for
    /// n in {4, 7, 10}.
    #[test]
    fn genesis_qc_fill_collapses_to_quorum_size_at_weight_one() {
        for n in [4usize, 7, 10] {
            let vs = ValidatorSet::new((0..n as u8).map(|i| vid_for(i + 1)).collect::<Vec<_>>());
            let g = Block::genesis([0; 32], [0; 32]);
            let qc = genesis_qc(&g, &vs);
            assert_eq!(qc.signer_count(), quorum_size(n));
            assert!(qc.has_quorum(&vs), "n = {n}");
            assert!(qc.is_well_formed(&vs));
        }
    }

    /// Boundary u128 arithmetic in `quorum_weight_threshold` and
    /// `has_quorum`: weights summing to a value that, when multiplied
    /// by 3, would overflow u64 must be aggregated and compared in
    /// u128 without wrap. This is the dual of
    /// `has_quorum_handles_weights_near_u64_max_without_wrapping`
    /// for the predicate's helper rather than the predicate itself,
    /// and pins the `2 * total_weight` operand specifically (the
    /// other side of the integer-math comparison).
    #[test]
    fn quorum_weight_threshold_u128_safe_against_3x_total_overflow() {
        // total = 4 * u64::MAX > 2^64 — would wrap a u64 product but
        // fits in u128 with room to triple. Threshold computed in
        // u128 must equal floor(2*total/3) + 1.
        let vs = ValidatorSet::with_weights(vec![
            (vid_for(1), u64::MAX),
            (vid_for(2), u64::MAX),
            (vid_for(3), u64::MAX),
            (vid_for(4), u64::MAX),
        ])
        .unwrap();
        let total = vs.total_weight();
        assert_eq!(total, (u64::MAX as u128) * 4);
        let threshold = quorum_weight_threshold(&vs);
        let expected = 2u128 * total / 3 + 1;
        assert_eq!(threshold, expected);
        // honesty threshold: total/3 + 1, also overflow-free.
        assert_eq!(honesty_weight_threshold(&vs), total / 3 + 1);
    }

    /// `genesis_qc` correctly fills enough bits even when a single
    /// stake-heavy validator dominates. Weights `[5, 1, 1, 1]` →
    /// quorum threshold = 6; the loop must add the heavy validator
    /// (sorted index 0; weight 5) PLUS at least one small to cross.
    #[test]
    fn genesis_qc_fill_handles_nonuniform_weights() {
        let vs = ValidatorSet::with_weights(vec![
            (vid_for(1), 5),
            (vid_for(2), 1),
            (vid_for(3), 1),
            (vid_for(4), 1),
        ])
        .unwrap();
        let g = Block::genesis([0; 32], [0; 32]);
        let qc = genesis_qc(&g, &vs);
        assert!(qc.has_quorum(&vs));
        // Heavy validator (5) plus one small (1) = 6 = threshold.
        assert_eq!(qc.signer_weight(&vs), 6);
        assert_eq!(qc.signer_count(), 2);
    }

    /// #469 gap 1 — pin the issue body's "weight change requires a
    /// larger signer subset" claim.
    ///
    /// Two `ValidatorSet`s differ only in one validator's weight:
    /// pre-boundary `[2, 2, 2, 2]` (total 8, threshold weight 6),
    /// post-boundary `[4, 2, 2, 2]` (total 10, threshold weight 7).
    /// The same QC bitmap covering the three light validators
    /// (sorted indices 1, 2, 3 — total signer weight 6 in both sets)
    /// is quorum pre-boundary and NOT quorum post-boundary. Crossing
    /// the boundary therefore forces either the heavy validator
    /// (weight 4) or a fourth signer to participate. Audit-by-name
    /// for the #144 acceptance criterion that the parent issue's
    /// proptest only covered indirectly.
    #[test]
    fn weight_change_recomputes_quorum_subsets() {
        let pre = ValidatorSet::with_weights(vec![
            (vid_for(1), 2),
            (vid_for(2), 2),
            (vid_for(3), 2),
            (vid_for(4), 2),
        ])
        .unwrap();
        let post = ValidatorSet::with_weights(vec![
            (vid_for(1), 4),
            (vid_for(2), 2),
            (vid_for(3), 2),
            (vid_for(4), 2),
        ])
        .unwrap();
        // ValidatorSet sorts by id ascending. vid_for(1) sorts to
        // index 0; the heavy validator post-boundary is at sorted
        // index 0. The QC's bitmap covers indices 1, 2, 3 — the
        // three light validators — in BOTH sets.
        let mut qc = QuorumCertificate::new(View(7), sample_block_hash(), pre.len());
        qc.add_signature(1, [0; 64]);
        qc.add_signature(2, [0; 64]);
        qc.add_signature(3, [0; 64]);

        // Pre-boundary: signer weight 2+2+2 = 6 > 2/3 of 8 (= 5.33)
        // ⇒ quorum.
        assert_eq!(qc.signer_weight(&pre), 6);
        assert_eq!(quorum_weight_threshold(&pre), 6);
        assert!(
            qc.has_quorum(&pre),
            "3-of-4 light validators must reach quorum at uniform weight 2",
        );

        // Post-boundary: same bitmap, same signer weight 6, but
        // total is now 10 and threshold is 7. 3*6 = 18, 2*10 = 20,
        // 18 > 20 is false ⇒ NOT quorum.
        assert_eq!(qc.signer_weight(&post), 6);
        assert_eq!(quorum_weight_threshold(&post), 7);
        assert!(
            !qc.has_quorum(&post),
            "the 3-light subset that was quorum pre-boundary must NOT \
             be quorum post-boundary — heavy validator or a 4th signer required",
        );

        // Confirm the post-boundary "larger signer set" — adding the
        // heavy validator (sorted index 0; weight 4) lifts signer
        // weight to 10 ⇒ quorum.
        let mut qc_with_heavy = QuorumCertificate::new(View(7), sample_block_hash(), post.len());
        qc_with_heavy.add_signature(0, [0; 64]);
        qc_with_heavy.add_signature(1, [0; 64]);
        qc_with_heavy.add_signature(2, [0; 64]);
        qc_with_heavy.add_signature(3, [0; 64]);
        assert_eq!(qc_with_heavy.signer_weight(&post), 10);
        assert!(qc_with_heavy.has_quorum(&post));
    }

    /// #469 gap 2 — pin "historical QCs from before a weight change
    /// still verify correctly."
    ///
    /// A QC formed at view 5 under uniform weights `[1, 1, 1, 1]`
    /// covers 3-of-4 signers (quorum: `signer_count = 3 = quorum_size(4)`).
    /// At view 10 the cluster commits a reconfig that bumps the
    /// first validator's weight to 5. The exact same bitmap, looked
    /// up against the pre-boundary set via
    /// `ValidatorSetHistory::set_at(qc.view)`, must still be quorum.
    /// The same bitmap looked up against the post-boundary set must
    /// NOT be quorum — without the historical lookup, an honest
    /// replica would mis-verify a perfectly-good archived QC.
    #[test]
    fn historical_qc_verifies_under_pre_boundary_weights_after_weight_change() {
        use crate::validator_history::ValidatorSetHistory;

        let pre = ValidatorSet::new(vec![vid_for(1), vid_for(2), vid_for(3), vid_for(4)]);
        let post = ValidatorSet::with_weights(vec![
            (vid_for(1), 5),
            (vid_for(2), 1),
            (vid_for(3), 1),
            (vid_for(4), 1),
        ])
        .unwrap();
        let mut history = ValidatorSetHistory::from_genesis(pre.clone());
        history.insert_boundary(10u64, post.clone()).unwrap();

        // Build a pre-boundary QC at view 5: 3-of-4 light signers,
        // covering sorted indices 1, 2, 3.
        let mut qc = QuorumCertificate::new(View(5), sample_block_hash(), pre.len());
        qc.add_signature(1, [0; 64]);
        qc.add_signature(2, [0; 64]);
        qc.add_signature(3, [0; 64]);

        // Historical verification: the historical-set lookup at
        // qc.view returns the pre-boundary set, and the QC is quorum
        // there.
        let pre_set_at_qc = history.set_at(View(5));
        assert!(
            qc.has_quorum(pre_set_at_qc.for_view(View(5))),
            "pre-boundary QC must remain quorum under the validator \
             set authoritative at qc.view",
        );

        // Conversely, looking up the post-boundary set at view 11
        // and applying the SAME bitmap is NOT quorum: 3 light
        // signers = weight 3, threshold = floor(2*8/3)+1 = 6. The
        // distinction proves the historical lookup is load-bearing
        // — without it, an honest replica would (incorrectly) reject
        // the archived QC.
        let post_set_at_v11 = history.set_at(View(11));
        let mut qc_against_post = QuorumCertificate::new(
            View(11), // synthetic view at which the post-boundary set is authoritative
            sample_block_hash(),
            post.len(),
        );
        qc_against_post.add_signature(1, [0; 64]);
        qc_against_post.add_signature(2, [0; 64]);
        qc_against_post.add_signature(3, [0; 64]);
        assert_eq!(
            qc_against_post.signer_weight(post_set_at_v11.for_view(View(11))),
            3
        );
        assert!(
            !qc_against_post.has_quorum(post_set_at_v11.for_view(View(11))),
            "the post-boundary 3-light subset must NOT be quorum — \
             confirms the historical lookup at qc.view is load-bearing",
        );
    }

    #[test]
    fn genesis_qc_bls_aggregate_is_empty_sentinel() {
        let vs = four_validators();
        let genesis = Block::genesis([7; 32], [0; 32]);
        let qc = genesis_qc_bls(&genesis, vs.len());
        let QcSignatures::BlsAggregated(agg) = &qc.signatures else {
            panic!("genesis_qc_bls must produce a BLS QC");
        };
        assert!(BlsAggregated::is_empty_aggregate(agg));
    }
}
