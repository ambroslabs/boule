//! Toy "staking" command for the demo (counter) application.
//!
//! A [`StakeCommand`] submitted to the mempool (e.g. via `POST
//! /mempool/submit`) rides in a block like any other command. The demo
//! [`Application`](boule_consensus::replication::application::Application)
//! — the counter `MempoolBlockBuilder` — recognises it, leaves the counter
//! state machine untouched, and applies it to a
//! [`StakeSource`](boule_consensus::replication::stake_source::StakeSource)
//! (a CL-native bonded-stake ledger). The resulting validator-set deltas
//! are surfaced from `commit` and drive an app-driven validator-set change
//! through the deferred-materialisation path (#225 M5/M6): `commit` →
//! staged update → minted `ReconfigCommand` → boundary.
//!
//! This is a reference/demo backend exercising the application seam and the
//! `StakeSource` abstraction (#654) end-to-end, not production staking — the
//! EVM-native staking interface (#655) is another `StakeSource`.

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use boule_consensus::replication::stake_source::StakeOp;
use boule_core::identity::NodeId;

/// Tag prefix marking a postcard-encoded [`StakeCommand`], so the demo
/// application can tell it apart from counter commands in a block.
const STAKE_TAG: &[u8] = b"STAKEv2\0";

/// A toy staking instruction: bond or unbond stake for `node_id`. A full
/// unbond drops the validator's weight to zero, removing it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StakeCommand {
    /// The validator the instruction targets.
    pub node_id: NodeId,
    /// The stake operation to apply against the validator's bonded balance.
    pub op: StakeOp,
}

impl StakeCommand {
    /// Bond `amount` stake to `node_id`.
    pub fn bond(node_id: NodeId, amount: u64) -> Self {
        Self {
            node_id,
            op: StakeOp::Bond { amount },
        }
    }

    /// Unbond `amount` stake from `node_id` (a large enough amount removes
    /// the validator).
    pub fn unbond(node_id: NodeId, amount: u64) -> Self {
        Self {
            node_id,
            op: StakeOp::Unbond { amount },
        }
    }

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_is_tagged() {
        let cmd = StakeCommand::unbond([7u8; 32], 1);
        let bytes = cmd.encode();
        assert!(StakeCommand::is_stake_payload(&bytes));
        assert!(!StakeCommand::is_stake_payload(b"not-a-stake-command"));
        assert_eq!(StakeCommand::decode(&bytes).unwrap(), cmd);
        assert_eq!(cmd.op, StakeOp::Unbond { amount: 1 });

        let bonded = StakeCommand::bond([8u8; 32], 5);
        assert_eq!(
            StakeCommand::decode(&bonded.encode()).unwrap().op,
            StakeOp::Bond { amount: 5 }
        );
    }
}
