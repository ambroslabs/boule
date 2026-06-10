#![allow(dead_code)]
use bytes::Bytes;

use crate::hotstuff::qc::TimeoutVote;
use crate::replication::block::{Block, BlockHash};
use crate::replication::snapshot::SnapshotManifest;
use crate::validator_set::ValidatorId;
use crate::{Height, View};
use boule_core::crypto::signed::Signed;
use boule_core::identity::NodeId;

pub mod codec;
pub mod egress;
pub mod ingress;
pub mod verify;

pub use egress::{
    egress_block_range_request, egress_block_range_response, egress_block_request,
    egress_block_response, egress_consensus_msg_with_loopback, egress_equivocation_evidence,
    egress_safety, egress_snapshot_chunk_request, egress_snapshot_chunk_response,
    egress_snapshot_manifest_request, egress_snapshot_manifest_response, egress_status,
};
pub use ingress::{
    ingress_block_range_request, ingress_block_range_response, ingress_block_request,
    ingress_block_response, ingress_equivocation_evidence, ingress_new_view, ingress_proposal,
    ingress_snapshot_chunk_request, ingress_snapshot_chunk_response,
    ingress_snapshot_manifest_request, ingress_snapshot_manifest_response, ingress_timeout_vote,
    ingress_vote, ingress_wire_with_qc_verification, ingress_with_qc_verification,
};
pub use verify::equivocation::{EquivocationError, EquivocationProof, verify_equivocation_proof};

#[allow(unused_imports)]
use crate::wire::WireMessage;

#[derive(Debug)]
pub enum NodeEvent {
    Inbound { from: NodeId, msg: Box<WireMessage> },

    ViewTimerFired(View),

    PeerConnected(NodeId),

    PeerDisconnected(NodeId),

    Shutdown,
}

#[derive(Debug)]
pub enum Dispatch {
    Safety(crate::hotstuff::step::Event),

    Pacemaker(crate::pacemaker::Event),

    ServeBlock {
        hash: BlockHash,
        to: NodeId,
    },

    PeerStatus {
        from: NodeId,
        height: Height,
    },

    ReceiveBlock {
        requested_hash: BlockHash,
        block: Option<Block>,
        from: NodeId,
    },

    TimeoutVote {
        signed: Signed<TimeoutVote>,
        high_qc_trusted: bool,
    },

    ServeSnapshotManifest {
        height: Option<u64>,
        to: NodeId,
    },

    ReceiveSnapshotManifest {
        manifest: Option<SnapshotManifest>,
        from: NodeId,
    },

    ServeSnapshotChunk {
        height: Height,
        chunk_idx: u32,
        to: NodeId,
    },

    ReceiveSnapshotChunk {
        height: Height,
        chunk_idx: u32,
        payload: Option<bytes::Bytes>,
        from: NodeId,
    },

    ServeBlockRange {
        from_height: Height,
        to_height: Height,
        to: NodeId,
    },

    ReceiveBlockRange {
        from_height: Height,
        to_height: Height,
        blocks: Vec<crate::replication::block::Block>,
        from: NodeId,
    },

    ReceiveEquivocationEvidence {
        proof: EquivocationProof,
        validator_id: crate::validator_set::ValidatorId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outbound {
    Broadcast(Bytes),

    SendTo { to: NodeId, payload: Bytes },
}

#[derive(Debug)]
pub enum IngressError {
    Decode(postcard::Error),
    UnknownSigner(NodeId),
    InvalidSignature(anyhow::Error),

    MalformedHighQc {
        view: View,
    },

    InvalidQcAggregate {
        view: View,
        scheme: &'static str,
    },

    InvalidBlsPartial {
        view: View,
        signer: NodeId,
    },

    InvalidValidatorHistoryCommitment {
        view: View,
        height: Height,
        claimed: [u8; 32],
        actual: [u8; 32],
    },

    InvalidEquivocationEvidence(EquivocationError),
}

impl std::fmt::Display for IngressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IngressError::Decode(e) => write!(f, "postcard decode failed: {e}"),
            IngressError::UnknownSigner(id) => {
                write!(f, "signer {id:?} is not in the validator set")
            }
            IngressError::InvalidSignature(e) => write!(f, "signature verification failed: {e}"),
            IngressError::MalformedHighQc { view } => write!(
                f,
                "NewView's high_qc at view {view} is not well-formed under the historical validator set",
            ),
            IngressError::InvalidQcAggregate { view, scheme } => write!(
                f,
                "QC at view {view} ({scheme}) failed aggregate verification under the historical validator set",
            ),
            IngressError::InvalidBlsPartial { view, signer } => write!(
                f,
                "BLS partial on Vote at view {view} from signer {signer:?} is missing or did not verify under the historical BLS pubkey",
            ),
            IngressError::InvalidValidatorHistoryCommitment {
                view,
                height,
                claimed,
                actual,
            } => write!(
                f,
                "validator_history_commitment mismatch on Proposal at height={height} view={view}: \
                 leader stamped {} but follower computes {} over the block's reconfig/rotation \
                 commands (audit #325/7-F2)",
                hex::encode(claimed),
                hex::encode(actual),
            ),
            IngressError::InvalidEquivocationEvidence(e) => {
                write!(f, "gossiped equivocation evidence did not verify: {e}")
            }
        }
    }
}

impl std::error::Error for IngressError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            IngressError::Decode(e) => Some(e),
            IngressError::InvalidSignature(e) => Some(e.as_ref()),
            IngressError::InvalidEquivocationEvidence(e) => Some(e),
            IngressError::UnknownSigner(_)
            | IngressError::MalformedHighQc { .. }
            | IngressError::InvalidQcAggregate { .. }
            | IngressError::InvalidBlsPartial { .. }
            | IngressError::InvalidValidatorHistoryCommitment { .. } => None,
        }
    }
}

impl From<postcard::Error> for IngressError {
    fn from(e: postcard::Error) -> Self {
        IngressError::Decode(e)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified<T> {
    value: T,
    signer_validator_id: ValidatorId,
}

impl<T> Verified<T> {
    pub fn wrap_after_verify_with_signer(value: T, signer_validator_id: ValidatorId) -> Self {
        Self {
            value,
            signer_validator_id,
        }
    }

    pub fn unchecked_with_signer(value: T, signer_validator_id: ValidatorId) -> Self {
        Self {
            value,
            signer_validator_id,
        }
    }

    pub fn inner(&self) -> &T {
        &self.value
    }

    pub fn into_inner(self) -> T {
        self.value
    }

    pub fn signer_validator_id(&self) -> ValidatorId {
        self.signer_validator_id
    }

    pub fn into_parts(self) -> (T, ValidatorId) {
        (self.value, self.signer_validator_id)
    }
}

impl<T> Verified<Signed<T>> {
    pub fn unchecked(value: Signed<T>) -> Self {
        let signer_validator_id = ValidatorId::from_genesis_pubkey(value.signer);
        Self::unchecked_with_signer(value, signer_validator_id)
    }
}

pub enum QcVerification<'a> {
    Verify {
        bls_key_history: Option<&'a crate::bls_key_history::BlsKeyHistory>,

        operator_key_history: Option<&'a crate::operator_key_history::OperatorKeyHistory>,

        min_v_eff_delay: View,

        genesis_hash: BlockHash,
    },
}
