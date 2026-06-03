//! On-chain identifiers for the validator-staking predeploy (#655).
//!
//! Users stake/unstake by calling the `Staking` contract
//! (`contracts/Staking.sol`), deployed as a genesis predeploy at
//! [`STAKING_ADDRESS`]. boule reads the events it emits from each committed
//! block — filtered by [`DEPOSIT_TOPIC`] / [`WITHDRAW_TOPIC`] — via
//! [`parse_stake_logs`], turning them into stake operations that feed a
//! [`StakeSource`] and so drive its validator set.
//!
//! These constants are the authoritative identifiers and match the compiled
//! runtime bytecode embedded in `genesis.json`; the test below pins the
//! address to the genesis account so the two cannot drift.
//!
//! [`StakeSource`]: boule_consensus::replication::stake_source::StakeSource

use serde_json::{Value, json};

use boule_consensus::replication::stake_source::StakeOp;
use boule_core::identity::NodeId;

use crate::engine::root_from_hex;

/// Fixed genesis-predeploy address of the staking contract.
pub const STAKING_ADDRESS: &str = "0x0000000000000000000000000000000000000b0e";

/// `keccak256("Deposit(bytes32,uint256)")` — topic0 of the `Deposit` event,
/// emitted by `deposit(bytes32 nodeId)` with the bonded `amount`.
pub const DEPOSIT_TOPIC: &str =
    "0x98e783c3864bbf744a057ef605a2a61701c3b62b5ed68b3745b99094497daf1f";

/// `keccak256("Withdraw(bytes32,uint256)")` — topic0 of the `Withdraw`
/// event, emitted by `withdraw(bytes32 nodeId, uint256 amount)`.
pub const WITHDRAW_TOPIC: &str =
    "0x4591ca0897d0d8e83f7153dfe0b2912125672084ab8d84be59ee13240a1778bc";

/// 4-byte selector of `deposit(bytes32)`.
pub const DEPOSIT_SELECTOR: [u8; 4] = [0xb2, 0x14, 0xfa, 0xa5];

/// 4-byte selector of `withdraw(bytes32,uint256)`.
pub const WITHDRAW_SELECTOR: [u8; 4] = [0x04, 0x0c, 0xf0, 0x20];

/// The `eth_getLogs` filter selecting one block's staking events: the
/// predeploy address, the block by hash, and either event topic.
pub fn logs_filter(block_hash: &str) -> Value {
    json!([{
        "blockHash": block_hash,
        "address": STAKING_ADDRESS,
        "topics": [[DEPOSIT_TOPIC, WITHDRAW_TOPIC]],
    }])
}

/// The `eth_getLogs` filter selecting one block's staking events *by EVM
/// block number* rather than hash. Used to backfill the staking events of
/// blocks the EL executed via background self-sync that `commit` skipped
/// while the EL was `SYNCING` (#674): on catch-up we know only each skipped
/// block's boule height (→ its canonical EVM number), not its hash.
pub fn logs_filter_by_number(number: u64) -> Value {
    let block = format!("0x{number:x}");
    json!([{
        "fromBlock": block,
        "toBlock": block,
        "address": STAKING_ADDRESS,
        "topics": [[DEPOSIT_TOPIC, WITHDRAW_TOPIC]],
    }])
}

/// Parse an `eth_getLogs` result (an array of staking-predeploy log objects)
/// into `(node_id, StakeOp)` pairs in log order. A `Deposit` becomes a
/// [`StakeOp::Bond`], a `Withdraw` a [`StakeOp::Unbond`]; `node_id` is the
/// indexed `topics[1]` and the amount is the 32-byte data word. Logs that
/// don't match the expected shape are skipped.
pub fn parse_stake_logs(logs: &Value) -> Vec<(NodeId, StakeOp)> {
    let Some(arr) = logs.as_array() else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(arr.len());
    for log in arr {
        let Some(topics) = log["topics"].as_array() else {
            continue;
        };
        if topics.len() < 2 {
            continue;
        }
        let topic0 = topics[0].as_str().unwrap_or_default().to_ascii_lowercase();
        // topics[1] is the indexed bytes32 nodeId (a 32-byte hex word).
        let Ok(node_id) = root_from_hex(topics[1].as_str().unwrap_or_default()) else {
            continue;
        };
        let amount = data_word_to_u64(log["data"].as_str().unwrap_or_default());
        let op = if topic0 == DEPOSIT_TOPIC {
            StakeOp::Bond { amount }
        } else if topic0 == WITHDRAW_TOPIC {
            StakeOp::Unbond { amount }
        } else {
            continue;
        };
        out.push((node_id, op));
    }
    out
}

/// Interpret a 32-byte ABI data word (hex) as a `u64`, saturating if the
/// value exceeds `u64::MAX` (the toy 1:1 stake↔weight model assumes amounts
/// fit a `u64`).
fn data_word_to_u64(data: &str) -> u64 {
    let h = data.trim_start_matches("0x");
    if h.len() <= 16 {
        return u64::from_str_radix(h, 16).unwrap_or(0);
    }
    let (high, low) = h.split_at(h.len() - 16);
    if high.bytes().any(|b| b != b'0') {
        return u64::MAX; // value exceeds u64 — saturate
    }
    u64::from_str_radix(low, 16).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The predeploy address the read path will filter logs on must match
    /// the account actually seeded in `genesis.json` with non-empty code —
    /// otherwise boule would watch the wrong address and never see a stake
    /// event. Pins the Rust constant to the on-chain artifact.
    #[test]
    fn staking_predeploy_present_in_genesis_at_address() {
        let g: serde_json::Value =
            serde_json::from_str(include_str!("../genesis.json")).expect("genesis.json parses");
        let code = g["alloc"][STAKING_ADDRESS]["code"]
            .as_str()
            .expect("a predeploy with code is seeded at STAKING_ADDRESS");
        assert!(code.starts_with("0x60"), "looks like EVM runtime bytecode");
        assert!(
            code.len() > 2 + 400 * 2,
            "non-trivial contract code (~536 bytes)"
        );
    }

    fn topic_node(b: u8) -> String {
        format!("0x{}", format!("{b:02x}").repeat(32))
    }
    fn data_word(v: u64) -> String {
        format!("0x{v:064x}")
    }

    #[test]
    fn parses_deposit_as_bond_and_withdraw_as_unbond() {
        let logs = json!([
            { "topics": [DEPOSIT_TOPIC, topic_node(7)], "data": data_word(5) },
            { "topics": [WITHDRAW_TOPIC, topic_node(7)], "data": data_word(2) },
        ]);
        assert_eq!(
            parse_stake_logs(&logs),
            vec![
                ([7u8; 32], StakeOp::Bond { amount: 5 }),
                ([7u8; 32], StakeOp::Unbond { amount: 2 }),
            ],
        );
    }

    #[test]
    fn skips_unknown_topics_and_malformed_logs() {
        let logs = json!([
            // unknown topic0
            { "topics": [topic_node(0xab), topic_node(7)], "data": data_word(1) },
            // missing indexed nodeId
            { "topics": [DEPOSIT_TOPIC], "data": data_word(1) },
            // not an object
            "garbage",
        ]);
        assert!(parse_stake_logs(&logs).is_empty());
        // A non-array result (reth returned null/error-shaped) yields nothing.
        assert!(parse_stake_logs(&serde_json::Value::Null).is_empty());
    }

    #[test]
    fn amount_above_u64_saturates() {
        let big = format!("0x{}", "f".repeat(64));
        let logs = json!([{ "topics": [DEPOSIT_TOPIC, topic_node(1)], "data": big }]);
        assert_eq!(
            parse_stake_logs(&logs),
            vec![([1u8; 32], StakeOp::Bond { amount: u64::MAX })]
        );
    }

    #[test]
    fn logs_filter_targets_the_predeploy_and_both_topics() {
        let f = logs_filter("0xabc");
        assert_eq!(f[0]["address"], STAKING_ADDRESS);
        assert_eq!(f[0]["blockHash"], "0xabc");
        assert_eq!(f[0]["topics"][0][0], DEPOSIT_TOPIC);
        assert_eq!(f[0]["topics"][0][1], WITHDRAW_TOPIC);
    }
}
