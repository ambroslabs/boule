//! On-chain identifiers for the governance-reconfiguration predeploy (#729).
//!
//! A validator-set membership change (a *reconfig*) is approved on-chain by the
//! seated validators calling the `Governance` contract
//! (`contracts/Governance.sol`), deployed as a genesis predeploy at
//! [`GOVERNANCE_ADDRESS`]. The contract tallies distinct approvals per proposal
//! and, once they cross quorum, emits a single `Approved(proposalId,
//! reconfigCommand)`. boule reads those `Approved` events from each committed
//! block — filtered by [`APPROVED_TOPIC`] — via [`parse_approved_logs`], turning
//! the carried `reconfigCommand` back into the encoded command bytes. Those
//! become a
//! [`ValidatorEffect`](boule_consensus::replication::application::ValidatorEffect)
//! on the widened `CommitResult` (#727); consensus re-materialises the command
//! into a block, where the existing reconfig path validates it and schedules the
//! membership change at a view boundary. This supersedes the committee-approval
//! half of #548: approvals ride the ordinary EVM mempool/gossip rather than a
//! bespoke consensus-side signature-accumulation + tx-gossip path.
//!
//! The contract's *tally* logic (quorum crossing, double-approval dedup) is the
//! interesting part and is exercised against a live reth (see the PR /
//! `Governance.sol` doc); this module is just the read half plus the on-chain
//! identifiers. The MVP weight model is one-validator-one-vote — distinct
//! approving addresses, not stake weight — documented on the contract.
//!
//! These constants are the authoritative identifiers and match the compiled
//! runtime bytecode embedded in `genesis.json`; the tests below pin the address,
//! topic, and selector to the genesis artifact so the Rust constants and the
//! on-chain contract cannot drift.

use bytes::Bytes;
use serde_json::{Value, json};

/// Fixed genesis-predeploy address of the governance contract (one past the
/// slashing predeploy at `…b13`).
pub const GOVERNANCE_ADDRESS: &str = "0x0000000000000000000000000000000000000b14";

/// `keccak256("Approved(bytes32,bytes)")` — topic0 of the `Approved` event,
/// emitted once per proposal by `approve(bytes32,bytes,uint64)` when the
/// distinct-approver tally first reaches quorum.
pub const APPROVED_TOPIC: &str =
    "0xd686e9e9eda221dfab37aa6cae405e85e661ed8e45cbe791790ed38093d85b75";

/// 4-byte selector of `approve(bytes32,bytes,uint64)`.
pub const APPROVE_SELECTOR: [u8; 4] = [0x41, 0x0f, 0xa9, 0x55];

/// 4-byte selector of `approvals(bytes32)` (the running distinct-approver tally).
pub const APPROVALS_SELECTOR: [u8; 4] = [0xbf, 0x7c, 0x21, 0x31];

/// 4-byte selector of `isApproved(bytes32)`.
pub const IS_APPROVED_SELECTOR: [u8; 4] = [0x48, 0xae, 0xfc, 0x32];

/// The `eth_getLogs` filter selecting one block's governance approvals: the
/// predeploy address, the block by hash, and the event topic.
pub fn logs_filter(block_hash: &str) -> Value {
    json!([{
        "blockHash": block_hash,
        "address": GOVERNANCE_ADDRESS,
        "topics": [[APPROVED_TOPIC]],
    }])
}

/// The `eth_getLogs` filter selecting one block's governance approvals *by EVM
/// block number* rather than hash — the by-number counterpart used when
/// backfilling blocks the EL self-synced past (cf. `staking::logs_filter_by_number`).
pub fn logs_filter_by_number(number: u64) -> Value {
    let block = format!("0x{number:x}");
    json!([{
        "fromBlock": block,
        "toBlock": block,
        "address": GOVERNANCE_ADDRESS,
        "topics": [[APPROVED_TOPIC]],
    }])
}

/// Parse an `eth_getLogs` result into the encoded reconfig-command bytes carried
/// by each matching `Approved` log, in log order — a thin wrapper over the shared
/// [`parse_command_logs`](crate::predeploy_log::parse_command_logs) keyed on
/// [`APPROVED_TOPIC`]. Malformed or wrong-topic logs are skipped; consensus
/// validates each returned command (tag + reconfig checks) before acting on it.
pub fn parse_approved_logs(logs: &Value) -> Vec<Bytes> {
    crate::predeploy_log::parse_command_logs(logs, APPROVED_TOPIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::predeploy_log::test_support::{abi_log_bytes, topic_node};

    /// The predeploy address the read path filters logs on must match the
    /// account actually seeded in `genesis.json` with non-empty code — else
    /// boule would watch the wrong address and never see an approval. Pins the
    /// Rust constant to the on-chain artifact.
    #[test]
    fn governance_predeploy_present_in_genesis_at_address() {
        let g: serde_json::Value =
            serde_json::from_str(include_str!("../genesis.json")).expect("genesis.json parses");
        let code = g["alloc"][GOVERNANCE_ADDRESS]["code"]
            .as_str()
            .expect("a predeploy with code is seeded at GOVERNANCE_ADDRESS");
        assert!(code.starts_with("0x60"), "looks like EVM runtime bytecode");
        assert!(code.len() > 2 + 400 * 2, "non-trivial contract code");
    }

    /// The event topic and function selectors the Rust constants declare must be
    /// the ones solc compiled into the predeploy bytecode (the `PUSH32` operand
    /// before the `LOG2`, and the dispatcher selectors). Ties the constants to
    /// the artifact without a keccak dependency: if the contract's ABI changes,
    /// the embedded bytecode changes and this fails.
    #[test]
    fn topic_and_selector_match_genesis_bytecode() {
        let g: serde_json::Value =
            serde_json::from_str(include_str!("../genesis.json")).expect("genesis.json parses");
        let code = g["alloc"][GOVERNANCE_ADDRESS]["code"].as_str().unwrap();
        assert!(
            code.contains(APPROVED_TOPIC.trim_start_matches("0x")),
            "event topic constant must appear as the PUSH32 operand in the bytecode",
        );
        for (name, sel) in [
            ("approve", APPROVE_SELECTOR),
            ("approvals", APPROVALS_SELECTOR),
            ("isApproved", IS_APPROVED_SELECTOR),
        ] {
            assert!(
                code.contains(&hex::encode(sel)),
                "{name} selector must appear in the dispatcher",
            );
        }
    }

    #[test]
    fn parses_reconfig_command_from_log_data() {
        // An Approved event carries the indexed proposalId in topics[1] and the
        // reconfig command bytes in data — the same shape as Rotation/Endpoint.
        let cmd = b"RECFG-encoded-validator-set-reconfig-command";
        let logs = json!([
            { "topics": [APPROVED_TOPIC, topic_node(7)], "data": abi_log_bytes(cmd) },
        ]);
        let got = parse_approved_logs(&logs);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].as_ref(), cmd.as_ref());
    }

    #[test]
    fn parses_multiple_in_log_order() {
        let a = b"first-reconfig";
        let b = b"second-reconfig-longer-than-thirty-two-bytes-to-cross-a-word";
        let logs = json!([
            { "topics": [APPROVED_TOPIC, topic_node(1)], "data": abi_log_bytes(a) },
            { "topics": [APPROVED_TOPIC, topic_node(2)], "data": abi_log_bytes(b) },
        ]);
        let got = parse_approved_logs(&logs);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].as_ref(), a.as_ref());
        assert_eq!(got[1].as_ref(), b.as_ref());
    }

    #[test]
    fn skips_wrong_topic_and_malformed_data() {
        let logs = json!([
            // wrong topic0
            { "topics": [topic_node(0xab), topic_node(7)], "data": abi_log_bytes(b"x") },
            // missing topics
            { "data": abi_log_bytes(b"x") },
            // data too short (no length word)
            { "topics": [APPROVED_TOPIC, topic_node(7)], "data": "0x20" },
            // not an object
            "garbage",
        ]);
        assert!(parse_approved_logs(&logs).is_empty());
        assert!(parse_approved_logs(&serde_json::Value::Null).is_empty());
    }

    #[test]
    fn logs_filter_targets_the_predeploy_and_topic() {
        let f = logs_filter("0xabc");
        assert_eq!(f[0]["address"], GOVERNANCE_ADDRESS);
        assert_eq!(f[0]["blockHash"], "0xabc");
        assert_eq!(f[0]["topics"][0][0], APPROVED_TOPIC);
    }
}
