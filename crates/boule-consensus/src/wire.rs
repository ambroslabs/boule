use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::Height;
use crate::hotstuff::qc::TimeoutVote;
use crate::replication::block::{Block, BlockHash};
use boule_core::crypto::signed::{Signed, SignedMessage};

pub const PROTOCOL_ID: u8 = 0x03;

pub use boule_core::config::MAX_FRAME_BYTES;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockResponsePayload {
    pub requested_hash: BlockHash,

    pub block: Option<Block>,
}

impl SignedMessage for BlockResponsePayload {
    const DOMAIN: &'static str = "boule.consensus.block_response.v1";
}

pub const BLOCK_RANGE_RESPONSE_MAX_BLOCKS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockRangeResponsePayload {
    pub from_height: Height,

    pub to_height: Height,

    pub blocks: Vec<Block>,
}

impl SignedMessage for BlockRangeResponsePayload {
    const DOMAIN: &'static str = "boule.consensus.block_range_response.v1";
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireMessage {
    Proposal(Signed<crate::hotstuff::Proposal>),

    Vote(
        Signed<crate::hotstuff::qc::Vote>,
        #[serde(with = "serde_optional_bls_partial")]
        Option<boule_core::crypto::sig_scheme::BlsPartialSig>,
    ),
    NewView(Signed<crate::hotstuff::NewView>),

    TimeoutVote(Signed<TimeoutVote>),

    BlockRequest(BlockHash),

    BlockResponse(Signed<BlockResponsePayload>),

    SnapshotManifestRequest {
        height: Option<u64>,
    },

    SnapshotManifestResponse(Option<crate::replication::snapshot::SnapshotManifest>),

    SnapshotChunkRequest {
        height: u64,
        chunk_idx: u32,
    },

    SnapshotChunkResponse {
        height: u64,
        chunk_idx: u32,
        payload: Option<Bytes>,
    },

    BlockRangeRequest {
        from_height: Height,
        to_height: Height,
    },

    BlockRangeResponse(Signed<BlockRangeResponsePayload>),

    EquivocationEvidence(crate::dispatch::EquivocationProof),

    Status {
        committed_height: Height,
    },
}

mod serde_optional_bls_partial {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    use boule_core::crypto::sig_scheme::BlsPartialSig;

    pub fn serialize<S: Serializer>(opt: &Option<BlsPartialSig>, s: S) -> Result<S::Ok, S::Error> {
        match opt {
            Some(sig) => s.serialize_some(&sig[..]),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<BlsPartialSig>, D::Error> {
        let opt: Option<Vec<u8>> = Option::deserialize(d)?;
        match opt {
            Some(v) => v
                .as_slice()
                .try_into()
                .map(Some)
                .map_err(|_| D::Error::custom("BLS partial must be exactly 96 bytes")),
            None => Ok(None),
        }
    }
}
