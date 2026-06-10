use serde::{Deserialize, Serialize};

use crate::View;
use crate::replication::block::{Block, BlockHash};
use crate::validator_set::ValidatorSet;
use boule_core::crypto::sig_scheme::{
    AggregateVerifyError, BlsAggregate, BlsAggregated, BlsPublicKey, SignatureScheme,
};
use boule_core::crypto::signed::SignedMessage;

pub const fn quorum_size(n: usize) -> usize {
    (2 * n) / 3 + 1
}

pub const fn honesty_threshold(n: usize) -> usize {
    n / 3 + 1
}

pub fn quorum_weight_threshold(vs: &ValidatorSet) -> u128 {
    let total = vs.total_weight();
    if total == 0 {
        1
    } else {
        2u128.saturating_mul(total) / 3 + 1
    }
}

pub fn honesty_weight_threshold(vs: &ValidatorSet) -> u128 {
    let total = vs.total_weight();
    if total == 0 { 1 } else { total / 3 + 1 }
}

pub use boule_core::crypto::sig_scheme::SignerBitmap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumCertificate {
    pub view: View,
    pub block_hash: BlockHash,
    pub(crate) signers: SignerBitmap,
    pub(crate) signatures: QcSignatures,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QcSignatures {
    BlsAggregated(#[serde(with = "serde_g2_aggregate")] BlsAggregate),
}

impl QcSignatures {
    pub fn scheme_name(&self) -> &'static str {
        BlsAggregated::NAME
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
    pub fn new(view: impl Into<View>, block_hash: BlockHash, validator_set_len: usize) -> Self {
        Self {
            view: view.into(),
            block_hash,
            signers: SignerBitmap::new(validator_set_len),
            signatures: QcSignatures::BlsAggregated(BlsAggregated::empty_aggregate()),
        }
    }

    pub fn new_bls(view: impl Into<View>, block_hash: BlockHash, validator_set_len: usize) -> Self {
        Self::new(view, block_hash, validator_set_len)
    }

    pub fn is_bls(&self) -> bool {
        true
    }

    pub fn add_bls_partial(
        &mut self,
        validator_idx: usize,
        partial: boule_core::crypto::sig_scheme::BlsPartialSig,
    ) {
        let QcSignatures::BlsAggregated(agg) = &mut self.signatures;
        if self.signers.get(validator_idx) {
            return;
        }
        BlsAggregated::add_partial(agg, &self.signers, validator_idx, partial);
        self.signers.set(validator_idx);
    }

    pub fn verify_aggregate_bls(
        &self,
        message: &[u8],
        pubkeys: &[BlsPublicKey],
    ) -> Result<(), AggregateVerifyError> {
        let QcSignatures::BlsAggregated(agg) = &self.signatures;
        BlsAggregated::verify_aggregate(agg, &self.signers, message, pubkeys)
    }

    pub fn signer_count(&self) -> usize {
        self.signers.count()
    }

    pub fn signer_indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.signers.iter_set()
    }

    pub fn signer_weight(&self, vs: &ValidatorSet) -> u128 {
        debug_assert_eq!(
            self.signers.len(),
            vs.len(),
            "signer_weight: bitmap length and validator-set length must match",
        );
        let mut acc: u128 = 0;
        for idx in self.signers.iter_set() {
            if idx >= vs.len() {
                continue;
            }
            acc = acc.saturating_add(u128::from(vs.weight_at(idx)));
        }
        acc
    }

    pub fn has_quorum(&self, vs: &ValidatorSet) -> bool {
        let signer = self.signer_weight(vs);
        let total = vs.total_weight();

        3u128.saturating_mul(signer) > 2u128.saturating_mul(total)
    }

    pub fn is_well_formed(&self, vs: &ValidatorSet) -> bool {
        if self.signers.len() != vs.len() || !self.signers.is_well_formed() {
            return false;
        }
        let QcSignatures::BlsAggregated(agg) = &self.signatures;
        (self.signers.count() == 0) == BlsAggregated::is_empty_aggregate(agg)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedQc(QuorumCertificate);

impl VerifiedQc {
    pub fn unchecked(qc: QuorumCertificate) -> Self {
        Self(qc)
    }

    pub fn inner(&self) -> &QuorumCertificate {
        &self.0
    }

    pub fn into_inner(self) -> QuorumCertificate {
        self.0
    }

    pub fn view(&self) -> View {
        self.0.view
    }

    pub fn block_hash(&self) -> BlockHash {
        self.0.block_hash
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    pub block: Block,
    pub justify: QuorumCertificate,
}

impl SignedMessage for Proposal {
    const DOMAIN: &'static str = "boule.hotstuff.proposal.v1";
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vote {
    pub view: View,
    pub block_hash: BlockHash,
}

impl SignedMessage for Vote {
    const DOMAIN: &'static str = "boule.hotstuff.vote.v1";
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewView {
    pub high_qc: QuorumCertificate,
}

impl SignedMessage for NewView {
    const DOMAIN: &'static str = "boule.hotstuff.newview.v1";
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeoutVote {
    pub view: View,
    pub high_qc: Option<QuorumCertificate>,
}

impl SignedMessage for TimeoutVote {
    const DOMAIN: &'static str = "boule.hotstuff.timeout.v1";
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum ConsensusMsg {
    Proposal(Proposal),
    Vote(Vote),
    NewView(NewView),
}

pub fn genesis_qc(genesis: &Block, vs: &ValidatorSet) -> QuorumCertificate {
    genesis_qc_bls(genesis, vs.len())
}

pub fn genesis_qc_bls(genesis: &Block, validator_set_len: usize) -> QuorumCertificate {
    QuorumCertificate::new_bls(View::ZERO, genesis.hash(), validator_set_len)
}
