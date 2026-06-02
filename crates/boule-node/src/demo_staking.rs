//! Toy "staking" command for the demo (counter) application.
//!
//! A [`StakeCommand`] submitted to the mempool (e.g. via `POST
//! /mempool/submit`) rides in a block like any other command. The demo
//! [`Application`](boule_consensus::replication::application::Application)
//! — the counter `MempoolBlockBuilder` — recognises it, leaves the counter
//! state machine untouched, and surfaces it from `commit` as a
//! [`ValidatorUpdate`]. A submitted stake command therefore drives an
//! app-driven validator-set change through the deferred-materialisation
//! path (#225 M5/M6): `commit` → staged update → minted `ReconfigCommand`
//! → boundary. `weight == 0` removes the validator.
//!
//! This is a reference/demo backend exercising the application seam
//! end-to-end, not production staking — the EVM-native staking interface
//! is the production path.

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use boule_consensus::replication::application::ValidatorUpdate;
use boule_core::identity::NodeId;

/// Tag prefix marking a postcard-encoded [`StakeCommand`], so the demo
/// application can tell it apart from counter commands in a block.
const STAKE_TAG: &[u8] = b"STAKEv1\0";

/// A toy staking instruction: set `node_id`'s voting weight to `weight`
/// (`0` removes the validator).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StakeCommand {
    /// The validator the instruction targets.
    pub node_id: NodeId,
    /// The voting weight to assign at the next view boundary; `0` removes.
    pub weight: u64,
}

impl StakeCommand {
    /// Encode as a tagged byte sequence suitable for `Block.commands`.
    pub fn encode(&self) -> Bytes {
        let body =
            postcard::to_stdvec(self).expect("postcard encoding of StakeCommand cannot fail");
        let mut out = Vec::with_capacity(STAKE_TAG.len() + body.len());
        out.extend_from_slice(STAKE_TAG);
        out.extend_from_slice(&body);
        Bytes::from(out)
    }

    /// True iff `bytes` carries the stake tag prefix.
    pub fn is_stake_payload(bytes: &[u8]) -> bool {
        bytes.starts_with(STAKE_TAG)
    }

    /// Decode a tagged stake command. Errors if the tag is absent or the
    /// body is malformed.
    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let body = bytes
            .strip_prefix(STAKE_TAG)
            .ok_or_else(|| anyhow::anyhow!("missing stake tag prefix"))?;
        postcard::from_bytes(body).map_err(|e| anyhow::anyhow!("malformed StakeCommand: {e}"))
    }

    /// The validator-set change this command requests.
    pub fn to_validator_update(&self) -> ValidatorUpdate {
        ValidatorUpdate {
            node_id: self.node_id,
            weight: self.weight,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_is_tagged() {
        let cmd = StakeCommand {
            node_id: [7u8; 32],
            weight: 0,
        };
        let bytes = cmd.encode();
        assert!(StakeCommand::is_stake_payload(&bytes));
        assert!(!StakeCommand::is_stake_payload(b"not-a-stake-command"));
        assert_eq!(StakeCommand::decode(&bytes).unwrap(), cmd);
        let u = cmd.to_validator_update();
        assert_eq!(u.node_id, [7u8; 32]);
        assert_eq!(u.weight, 0);
    }
}
