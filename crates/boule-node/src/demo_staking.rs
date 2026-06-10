use bytes::Bytes;
use serde::{Deserialize, Serialize};

use boule_consensus::replication::stake_source::StakeOp;
use boule_core::identity::NodeId;

const STAKE_TAG: &[u8] = b"STAKEv2\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StakeCommand {
    pub node_id: NodeId,

    pub op: StakeOp,
}

impl StakeCommand {
    pub fn bond(node_id: NodeId, amount: u64) -> Self {
        Self {
            node_id,
            op: StakeOp::Bond { amount },
        }
    }

    pub fn unbond(node_id: NodeId, amount: u64) -> Self {
        Self {
            node_id,
            op: StakeOp::Unbond { amount },
        }
    }

    pub fn encode(&self) -> Bytes {
        let body =
            postcard::to_stdvec(self).expect("postcard encoding of StakeCommand cannot fail");
        let mut out = Vec::with_capacity(STAKE_TAG.len() + body.len());
        out.extend_from_slice(STAKE_TAG);
        out.extend_from_slice(&body);
        Bytes::from(out)
    }

    pub fn is_stake_payload(bytes: &[u8]) -> bool {
        bytes.starts_with(STAKE_TAG)
    }

    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let body = bytes
            .strip_prefix(STAKE_TAG)
            .ok_or_else(|| anyhow::anyhow!("missing stake tag prefix"))?;
        postcard::from_bytes(body).map_err(|e| anyhow::anyhow!("malformed StakeCommand: {e}"))
    }
}
