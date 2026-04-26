//! Quorum certificates and the consensus wire types they appear in.
//!
//! A [`QuorumCertificate`] (QC) is a proof that a quorum of validators
//! signed off on a `(view, block_hash)` pair. HotStuff piles QCs on
//! top of each other to reach a three-chain commit: see the
//! `safety_rules` module (7.B / #92) for the rule itself.
//!
//! # Signature representation
//!
//! Milestone 7 (#23) deliberately targets *collected-sig* QCs: the
//! certificate carries one raw Ed25519 signature per signer plus a
//! [`SignerBitmap`] indexed over the [`ValidatorSet`]. BLS / threshold
//! aggregation is a later optimization.
//!
//! The [`SignerBitmap`] + `signatures: Vec<[u8; 64]>` layout is
//! "parallel on set bits": the k-th entry of [`QuorumCertificate::signatures`]
//! belongs to the k-th validator index whose bit is set in
//! [`QuorumCertificate::signers`] (scanning low→high). Constructors in
//! this module maintain that invariant for you; direct field mutation
//! is possible only inside the crate.
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
//! [`ValidatorSet`]: crate::consensus::validator_set::ValidatorSet
//! [`SignedMessage`]: crate::crypto::signed::SignedMessage
//! [`Signed`]: crate::crypto::signed::Signed

use serde::{Deserialize, Serialize};

use crate::consensus::View;
use crate::consensus::validator_set::ValidatorSet;
use crate::crypto::signed::SignedMessage;
use crate::replication::block::{Block, BlockHash};

/// HotStuff quorum threshold: `2n/3 + 1`.
///
/// For `n = 3f + 1` this equals `2f + 1`, the usual BFT quorum.
/// `quorum_size(0)` returns `1` (a harmless default — an empty
/// validator set has no quorum).
pub const fn quorum_size(n: usize) -> usize {
    (2 * n) / 3 + 1
}

/// Honesty threshold: any set of `n/3 + 1` distinct signers
/// includes at least one honest signer (under the standard `n = 3f + 1`
/// BFT assumption: at most `f = n/3` faulty replicas, so `f + 1` is the
/// smallest set guaranteed to contain an honest member).
///
/// Used by the round-sync hint (`OnRoundSync`) so a single Byzantine
/// `TimeoutVote` cannot drag honest replicas' `current_view` forward —
/// see issue #218.
///
/// `honesty_threshold(0)` returns `1` (mirrors [`quorum_size`]'s
/// degenerate-default behaviour).
pub const fn honesty_threshold(n: usize) -> usize {
    n / 3 + 1
}

/// Compact signer set, indexed over a [`ValidatorSet`]'s sorted order.
///
/// Internally: little-endian-packed bits in a `Vec<u8>`, with the bit
/// length stored as a `u32` so the postcard encoding is
/// platform-independent (the `usize` from [`ValidatorSet::len`] would
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

/// A proof that a quorum of validators signed off on
/// `(view, block_hash)`.
///
/// Fields are `pub(crate)` so 7.B/7.C can hand-construct QCs in tests
/// without forcing new `add_signature` + `seal` plumbing here; outside
/// the crate, construct via [`QuorumCertificate::new`] +
/// [`QuorumCertificate::add_signature`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumCertificate {
    pub view: View,
    pub block_hash: BlockHash,
    pub(crate) signers: SignerBitmap,
    #[serde(with = "serde_sig_vec")]
    pub(crate) signatures: Vec<[u8; 64]>,
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

impl QuorumCertificate {
    /// Start an empty QC that can accumulate up to `validator_set_len`
    /// signatures. Use [`add_signature`] to populate it.
    ///
    /// [`add_signature`]: Self::add_signature
    pub fn new(view: View, block_hash: BlockHash, validator_set_len: usize) -> Self {
        Self {
            view,
            block_hash,
            signers: SignerBitmap::new(validator_set_len),
            signatures: Vec::new(),
        }
    }

    /// Record one signer's [`[u8; 64]`] Ed25519 signature. `validator_idx`
    /// is the validator's index in the sorted [`ValidatorSet`].
    ///
    /// Keeps the "parallel on set bits" invariant: the signature is
    /// inserted at the position corresponding to where `validator_idx`
    /// falls among the already-set bits. Ignored (no-op) if the bit is
    /// already set — duplicate signatures for the same signer do not
    /// change quorum status.
    pub fn add_signature(&mut self, validator_idx: usize, sig: [u8; 64]) {
        if self.signers.get(validator_idx) {
            return;
        }
        // Find the insertion position by counting set bits strictly
        // below `validator_idx`.
        let insert_at = self
            .signers
            .iter_set()
            .take_while(|&i| i < validator_idx)
            .count();
        self.signers.set(validator_idx);
        self.signatures.insert(insert_at, sig);
        debug_assert_eq!(
            self.signers.count(),
            self.signatures.len(),
            "signer bits and signatures must stay parallel",
        );
    }

    /// Number of validators whose signature this QC carries.
    pub fn signer_count(&self) -> usize {
        self.signers.count()
    }

    /// True iff at least `quorum_size(vs.len())` validators from `vs`
    /// have a signature recorded here.
    pub fn has_quorum(&self, vs: &ValidatorSet) -> bool {
        self.signer_count() >= quorum_size(vs.len())
    }

    /// Well-formedness check used when accepting a QC from the wire:
    /// the bitmap sizes match the claimed validator set, no stray bits
    /// are set, and the `signatures` vector is parallel to the set
    /// bits. Does **not** check signature validity — that's the
    /// integration layer's job.
    pub fn is_well_formed(&self, vs: &ValidatorSet) -> bool {
        self.signers.len() == vs.len()
            && self.signers.is_well_formed()
            && self.signatures.len() == self.signers.count()
    }

    /// Iterate `(validator_idx, &signature)` pairs in validator-index
    /// order.
    pub fn iter_signatures(&self) -> impl Iterator<Item = (usize, &[u8; 64])> + '_ {
        self.signers.iter_set().zip(self.signatures.iter())
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
    const DOMAIN: &'static str = "ambros.hotstuff.proposal.v1";
}

/// A replica's vote for a block it considers safe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vote {
    pub view: View,
    pub block_hash: BlockHash,
}

impl SignedMessage for Vote {
    const DOMAIN: &'static str = "ambros.hotstuff.vote.v1";
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
    const DOMAIN: &'static str = "ambros.hotstuff.newview.v1";
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
    const DOMAIN: &'static str = "ambros.hotstuff.timeout.v1";
}

/// Logical consensus message emitted by the safety core via
/// [`Action::Broadcast`] / [`Action::SendTo`]. The integration layer
/// (#24) wraps the contained payload in a [`Signed`] before putting it
/// on the wire.
///
/// [`Action::Broadcast`]: super::step::Action::Broadcast
/// [`Action::SendTo`]: super::step::Action::SendTo
/// [`Signed`]: crate::crypto::signed::Signed
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusMsg {
    Proposal(Proposal),
    Vote(Vote),
    NewView(NewView),
}

/// Build the cluster-agreed genesis [`QuorumCertificate`] every replica
/// seeds into its `high_qc` at boot.
///
/// By convention a genesis QC has `view = 0`, `block_hash =
/// genesis.hash()`, and the first `quorum_size(vs_len)` validator slots
/// signed with all-zero placeholders. The safety core never re-verifies
/// embedded QC signatures (that is the ingress layer's job at the
/// envelope level), so the placeholder signatures never reach a
/// verifier; they exist only to make the QC's
/// [`QuorumCertificate::has_quorum`] / [`QuorumCertificate::is_well_formed`]
/// predicates tell the truth about "a quorum signed off on the chain
/// root."
///
/// Every honest replica constructs an identical genesis QC from the
/// same `(genesis, validator_set_len)` pair, so the view-1 leader's
/// proposal — justified by this QC — is indistinguishable across
/// replicas.
pub fn genesis_qc(genesis: &Block, validator_set_len: usize) -> QuorumCertificate {
    let mut qc = QuorumCertificate::new(0, genesis.hash(), validator_set_len);
    for i in 0..quorum_size(validator_set_len) {
        qc.add_signature(i, [0u8; 64]);
    }
    qc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signed::{NodeSigner, Signed, Signer};
    use crate::p2p::NodeId;
    use crate::p2p::identity::NodeIdentity;
    use rcgen::{KeyPair as RcgenKeyPair, PKCS_ED25519};
    use zeroize::Zeroizing;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn four_validators() -> ValidatorSet {
        ValidatorSet::new(vec![nid(1), nid(2), nid(3), nid(4)])
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

    // ── QuorumCertificate ────────────────────────────────────────

    fn sample_block_hash() -> BlockHash {
        [0xBB; 32]
    }

    #[test]
    fn qc_empty_has_no_quorum() {
        let vs = four_validators();
        let qc = QuorumCertificate::new(5, sample_block_hash(), vs.len());
        assert_eq!(qc.signer_count(), 0);
        assert!(!qc.has_quorum(&vs));
        assert!(qc.is_well_formed(&vs));
    }

    #[test]
    fn qc_below_threshold_is_not_quorum() {
        let vs = four_validators();
        let mut qc = QuorumCertificate::new(1, sample_block_hash(), vs.len());
        // n=4 → quorum=3. Two signatures is not enough.
        qc.add_signature(0, [1; 64]);
        qc.add_signature(2, [2; 64]);
        assert_eq!(qc.signer_count(), 2);
        assert!(!qc.has_quorum(&vs));
    }

    #[test]
    fn qc_at_threshold_reaches_quorum() {
        let vs = four_validators();
        let mut qc = QuorumCertificate::new(1, sample_block_hash(), vs.len());
        qc.add_signature(0, [1; 64]);
        qc.add_signature(1, [2; 64]);
        qc.add_signature(3, [3; 64]);
        assert_eq!(qc.signer_count(), 3);
        assert!(qc.has_quorum(&vs));
    }

    #[test]
    fn qc_duplicate_signature_is_noop() {
        let vs = four_validators();
        let mut qc = QuorumCertificate::new(1, sample_block_hash(), vs.len());
        qc.add_signature(2, [7; 64]);
        qc.add_signature(2, [9; 64]); // duplicate — first write wins
        assert_eq!(qc.signer_count(), 1);
        assert_eq!(qc.signatures.len(), 1);
        assert_eq!(qc.signatures[0], [7; 64]);
    }

    #[test]
    fn qc_signatures_stay_parallel_to_set_bits_regardless_of_insertion_order() {
        let vs = four_validators();
        let mut qc = QuorumCertificate::new(2, sample_block_hash(), vs.len());
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
        let qc_wrong_size = QuorumCertificate::new(1, sample_block_hash(), vs.len() + 1);
        assert!(!qc_wrong_size.is_well_formed(&vs));
    }

    #[test]
    fn qc_postcard_roundtrip_stable() {
        let vs = four_validators();
        let mut qc = QuorumCertificate::new(9, [0xAB; 32], vs.len());
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
        let mut justify = QuorumCertificate::new(0, [0; 32], vs.len());
        justify.add_signature(0, [0x01; 64]);
        justify.add_signature(1, [0x02; 64]);
        justify.add_signature(2, [0x03; 64]);
        let proposal = Proposal {
            block: Block::genesis([0; 32]),
            justify,
        };
        let signed = Signed::sign(proposal.clone(), &signer).unwrap();
        signed.verify(&signer.node_id()).unwrap();

        let wire = postcard::to_stdvec(&signed).unwrap();
        let back: Signed<Proposal> = postcard::from_bytes(&wire).unwrap();
        assert_eq!(back.payload, proposal);
        back.verify(&signer.node_id()).unwrap();
    }

    #[test]
    fn vote_signs_and_verifies_under_its_domain() {
        let signer = fresh_signer();
        let vote = Vote {
            view: 7,
            block_hash: [0x77; 32],
        };
        let signed = Signed::sign(vote.clone(), &signer).unwrap();
        signed.verify(&signer.node_id()).unwrap();

        let wire = postcard::to_stdvec(&signed).unwrap();
        let back: Signed<Vote> = postcard::from_bytes(&wire).unwrap();
        assert_eq!(back.payload, vote);
        back.verify(&signer.node_id()).unwrap();
    }

    #[test]
    fn newview_signs_and_verifies_under_its_domain() {
        let signer = fresh_signer();
        let vs = four_validators();
        let mut high_qc = QuorumCertificate::new(11, [0xCC; 32], vs.len());
        high_qc.add_signature(1, [0xAA; 64]);
        let nv = NewView { high_qc };
        let signed = Signed::sign(nv.clone(), &signer).unwrap();
        signed.verify(&signer.node_id()).unwrap();
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
            view: 3,
            block_hash: [0x33; 32],
        };
        let signed_vote = Signed::sign(vote.clone(), &signer).unwrap();

        // Hand-craft a Signed<Proposal> reusing Vote's signature + signer
        // on any reasonable Proposal payload. Even if the inner byte
        // layout happened to match (it doesn't have to — we just need to
        // cover the cross-type replay path), the per-type DOMAIN string
        // ensures verification fails.
        let vs = four_validators();
        let forged: Signed<Proposal> = Signed {
            payload: Proposal {
                block: Block::genesis([0; 32]),
                justify: QuorumCertificate::new(vote.view, vote.block_hash, vs.len()),
            },
            signer: signed_vote.signer,
            sig: signed_vote.sig,
        };
        assert!(forged.verify(&signer.node_id()).is_err());
    }

    #[test]
    fn consensus_msg_enum_roundtrip() {
        let vs = four_validators();
        let mut justify = QuorumCertificate::new(0, [0; 32], vs.len());
        justify.add_signature(0, [0xFE; 64]);
        let msg = ConsensusMsg::Proposal(Proposal {
            block: Block::genesis([0; 32]),
            justify,
        });
        let wire = postcard::to_stdvec(&msg).unwrap();
        let back: ConsensusMsg = postcard::from_bytes(&wire).unwrap();
        assert_eq!(back, msg);
    }
}
