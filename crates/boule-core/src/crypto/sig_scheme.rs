use std::fmt::{self, Debug};

use serde::{Deserialize, Serialize};

use crate::crypto::signed::ChainId;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerBitmap {
    bits: Vec<u8>,
    len: u32,
}

impl SignerBitmap {
    pub fn new(len: usize) -> Self {
        let len_u32 =
            u32::try_from(len).expect("validator set larger than u32::MAX is nonsensical");
        let byte_len = len.div_ceil(8);
        Self {
            bits: vec![0u8; byte_len],
            len: len_u32,
        }
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn set(&mut self, idx: usize) {
        assert!(
            idx < self.len(),
            "SignerBitmap::set index {idx} out of bounds (len {})",
            self.len()
        );
        self.bits[idx / 8] |= 1 << (idx % 8);
    }

    pub fn get(&self, idx: usize) -> bool {
        if idx >= self.len() {
            return false;
        }
        (self.bits[idx / 8] >> (idx % 8)) & 1 == 1
    }

    pub fn count(&self) -> usize {
        self.bits.iter().map(|b| b.count_ones() as usize).sum()
    }

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

    pub fn is_well_formed(&self) -> bool {
        let expected_bytes = self.len().div_ceil(8);
        if self.bits.len() != expected_bytes {
            return false;
        }

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

pub trait SignatureScheme: 'static {
    type PartialSig: Clone + Debug + Eq + Send + Sync;

    type Aggregate: Clone + Debug + Eq + Send + Sync;

    type PublicKey: Clone + Debug + Eq + Send + Sync;

    const NAME: &'static str;

    fn empty_aggregate() -> Self::Aggregate;

    fn add_partial(
        agg: &mut Self::Aggregate,
        signers_before: &SignerBitmap,
        validator_idx: usize,
        partial: Self::PartialSig,
    );

    fn aggregate_count(agg: &Self::Aggregate) -> usize;

    fn verify_aggregate(
        agg: &Self::Aggregate,
        signers: &SignerBitmap,
        message: &[u8],
        pubkeys: &[Self::PublicKey],
    ) -> Result<(), AggregateVerifyError>;
}

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

pub struct BlsAggregated;

pub type BlsPartialSig = [u8; 96];

pub type BlsAggregate = [u8; 96];

pub type BlsPublicKey = [u8; 48];

pub type BlsSecretKey = [u8; 32];

const BLS_EMPTY_AGGREGATE_SENTINEL: BlsAggregate = [0u8; 96];

impl BlsAggregated {
    pub const DST: &'static [u8] = b"BOULE_HOTSTUFF_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    pub fn is_empty_aggregate(agg: &BlsAggregate) -> bool {
        *agg == BLS_EMPTY_AGGREGATE_SENTINEL
    }

    pub fn keygen(ikm: &[u8]) -> Result<(BlsSecretKey, BlsPublicKey), BlsKeyError> {
        let secret = blst::min_pk::SecretKey::key_gen(ikm, &[]).map_err(BlsKeyError::Blst)?;
        let public = secret.sk_to_pk();
        Ok((secret.to_bytes(), public.to_bytes()))
    }

    pub fn sign_partial(
        secret: &BlsSecretKey,
        message: &[u8],
    ) -> Result<BlsPartialSig, BlsKeyError> {
        let sk = blst::min_pk::SecretKey::from_bytes(secret).map_err(BlsKeyError::Blst)?;
        Ok(sk.sign(message, Self::DST, &[]).to_bytes())
    }

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

    pub fn sign_pop(secret: &BlsSecretKey, chain_id: &ChainId) -> Result<BlsPop, BlsKeyError> {
        let sk = blst::min_pk::SecretKey::from_bytes(secret).map_err(BlsKeyError::Blst)?;
        let pubkey = sk.sk_to_pk().to_bytes();
        let preimage = pop_preimage(chain_id, &pubkey);
        let sig = sk.sign(&preimage, Self::DST, &[]).to_bytes();
        Ok(BlsPop { pubkey, sig })
    }

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

fn pop_preimage(chain_id: &ChainId, pubkey: &BlsPublicKey) -> [u8; 32 + 48] {
    let mut out = [0u8; 32 + 48];
    out[..32].copy_from_slice(chain_id.as_bytes());
    out[32..].copy_from_slice(pubkey);
    out
}

pub fn bls_pubkey_to_eip2537_g1(pubkey: &BlsPublicKey) -> Result<[u8; 128], BlsKeyError> {
    use blst::{BLST_ERROR, blst_bendian_from_fp, blst_fp, blst_p1_affine, blst_p1_deserialize};

    fn fp64(fp: &blst_fp) -> [u8; 64] {
        let mut be = [0u8; 48];
        unsafe { blst_bendian_from_fp(be.as_mut_ptr(), fp) };
        let mut out = [0u8; 64];
        out[16..].copy_from_slice(&be);
        out
    }

    let uncompressed = blst::min_pk::PublicKey::from_bytes(pubkey)
        .map_err(BlsKeyError::Blst)?
        .serialize();
    let mut aff = blst_p1_affine::default();

    let err = unsafe { blst_p1_deserialize(&mut aff, uncompressed.as_ptr()) };
    if err != BLST_ERROR::BLST_SUCCESS {
        return Err(BlsKeyError::Blst(err));
    }
    let mut out = [0u8; 128];
    out[..64].copy_from_slice(&fp64(&aff.x));
    out[64..].copy_from_slice(&fp64(&aff.y));
    Ok(out)
}

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

#[derive(Debug, PartialEq, Eq)]
pub enum BlsKeyError {
    Blst(blst::BLST_ERROR),

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
