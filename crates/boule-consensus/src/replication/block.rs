use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Height, View};
use boule_core::identity::NodeId;

pub type BlockHash = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub parent_hash: BlockHash,

    pub height: Height,

    pub view: View,

    pub proposer: NodeId,

    pub state_commitment: [u8; 32],

    pub commands_commitment: [u8; 32],

    pub validator_history_commitment: [u8; 32],

    pub committed_height: Height,

    pub committed_state_root: [u8; 32],

    pub timestamp: u64,
}

impl BlockHeader {
    pub fn hash(&self) -> BlockHash {
        let bytes =
            postcard::to_stdvec(self).expect("postcard encoding of BlockHeader cannot fail");
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub commands: Vec<Bytes>,
}

impl Block {
    pub fn hash(&self) -> BlockHash {
        self.header.hash()
    }

    pub fn genesis(state_commitment: [u8; 32], validator_history_commitment: [u8; 32]) -> Self {
        let commands: Vec<Bytes> = Vec::new();
        Self {
            header: BlockHeader {
                parent_hash: [0u8; 32],
                height: Height::ZERO,
                view: View::ZERO,
                proposer: [0u8; 32],
                state_commitment,
                commands_commitment: Self::commands_commitment(&commands),
                validator_history_commitment,

                committed_height: Height::ZERO,
                committed_state_root: state_commitment,
                timestamp: 0,
            },
            commands,
        }
    }

    pub fn commands_commitment(commands: &[Bytes]) -> [u8; 32] {
        let bytes = postcard::to_stdvec(commands)
            .expect("postcard encoding of Vec<Bytes> cannot fail for owned buffers");
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        hasher.finalize().into()
    }
}

pub fn validate_structural(child: &Block, parent_header: &BlockHeader) -> anyhow::Result<()> {
    let parent_hash = parent_header.hash();
    if child.header.parent_hash != parent_hash {
        anyhow::bail!(
            "parent_hash mismatch: child claims {}, parent hashes to {}",
            hex::encode(child.header.parent_hash),
            hex::encode(parent_hash),
        );
    }
    let expected_height = parent_header
        .height
        .checked_add(Height(1))
        .ok_or_else(|| anyhow::anyhow!("parent height {} overflows u64", parent_header.height))?;
    if child.header.height != expected_height {
        anyhow::bail!(
            "height mismatch: expected {}, got {}",
            expected_height,
            child.header.height,
        );
    }
    if child.header.view <= parent_header.view {
        anyhow::bail!(
            "view must strictly increase: parent view {}, child view {}",
            parent_header.view,
            child.header.view,
        );
    }
    let recomputed = Block::commands_commitment(&child.commands);
    if child.header.commands_commitment != recomputed {
        anyhow::bail!(
            "commands_commitment mismatch: header {}, recomputed {}",
            hex::encode(child.header.commands_commitment),
            hex::encode(recomputed),
        );
    }
    if child.header.timestamp < parent_header.timestamp {
        anyhow::bail!(
            "timestamp must not decrease: parent {}, child {}",
            parent_header.timestamp,
            child.header.timestamp,
        );
    }
    Ok(())
}
