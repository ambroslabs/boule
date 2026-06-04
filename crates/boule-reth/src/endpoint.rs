//! On-chain identifiers for the validator endpoint-advertisement predeploy
//! (#731).
//!
//! A validator publishes or updates its consensus-traffic endpoints (#546) by
//! calling the `Endpoint` contract (`contracts/Endpoint.sol`), deployed as a
//! genesis predeploy at [`ENDPOINT_ADDRESS`], with the already-signed boule
//! endpoint command as calldata. boule reads the `EndpointSubmitted` events it
//! emits from each committed block — filtered by [`ENDPOINT_TOPIC`] — via
//! [`parse_endpoint_logs`], turning each back into the encoded endpoint command
//! bytes. Those become a
//! [`ValidatorEffect::EndpointUpdate`](boule_consensus::replication::application::ValidatorEffect::EndpointUpdate)
//! on the widened `CommitResult` (#727); consensus re-materialises the command
//! into a block, where the existing endpoint path (#546) verifies the
//! validator's signature and the strictly-monotone `seq`, then applies it to
//! the `EndpointRegistry`. The registry + apply mechanism is unchanged — only
//! the *submission* path moves onto the EVM, replacing the bespoke endpoint
//! mempool tx + hex CLIs. Endpoint advertisement is optional and a
//! discovery-hint only.
//!
//! The contract is a pure event emitter: it does no verification (consensus
//! does, on the carried command). These constants are the authoritative
//! identifiers and match the compiled runtime bytecode embedded in
//! `genesis.json`; the tests below pin the address, topic, and selector to the
//! genesis artifact so the Rust constants and the on-chain contract cannot
//! drift.

use bytes::Bytes;
use serde_json::{Value, json};

/// Fixed genesis-predeploy address of the endpoint contract (one past the
/// rotation predeploy at `…b0f`).
pub const ENDPOINT_ADDRESS: &str = "0x0000000000000000000000000000000000000b10";

/// `keccak256("EndpointSubmitted(bytes32,bytes)")` — topic0 of the
/// `EndpointSubmitted` event, emitted by
/// `submitEndpoint(bytes32 validator, bytes endpointCommand)`.
pub const ENDPOINT_TOPIC: &str =
    "0x26a38d91fc47b4cd0e93f73c87346a4236d696ffe5a241f95c33fc2670d28349";

/// 4-byte selector of `submitEndpoint(bytes32,bytes)`.
pub const SUBMIT_SELECTOR: [u8; 4] = [0x18, 0xd8, 0x84, 0x38];

/// The `eth_getLogs` filter selecting one block's endpoint events: the
/// predeploy address, the block by hash, and the event topic.
pub fn logs_filter(block_hash: &str) -> Value {
    json!([{
        "blockHash": block_hash,
        "address": ENDPOINT_ADDRESS,
        "topics": [[ENDPOINT_TOPIC]],
    }])
}

/// The `eth_getLogs` filter selecting one block's endpoint events *by EVM block
/// number* rather than hash — the by-number counterpart used when backfilling
/// blocks the EL self-synced past (cf. `staking::logs_filter_by_number`).
pub fn logs_filter_by_number(number: u64) -> Value {
    let block = format!("0x{number:x}");
    json!([{
        "fromBlock": block,
        "toBlock": block,
        "address": ENDPOINT_ADDRESS,
        "topics": [[ENDPOINT_TOPIC]],
    }])
}

/// Parse an `eth_getLogs` result into the encoded endpoint-command bytes
/// carried by each matching log, in log order — a thin wrapper over the shared
/// [`parse_command_logs`](crate::predeploy_log::parse_command_logs) keyed on
/// [`ENDPOINT_TOPIC`]. Malformed or wrong-topic logs are skipped; consensus
/// validates each returned command (tag + signature + seq) before acting on it.
pub fn parse_endpoint_logs(logs: &Value) -> Vec<Bytes> {
    crate::predeploy_log::parse_command_logs(logs, ENDPOINT_TOPIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::predeploy_log::test_support::{abi_log_bytes, topic_node};

    /// The predeploy address the read path filters logs on must match the
    /// account seeded in `genesis.json` with non-empty code — else boule would
    /// watch the wrong address and never see an endpoint update. Pins the Rust
    /// constant to the on-chain artifact.
    #[test]
    fn endpoint_predeploy_present_in_genesis_at_address() {
        let g: serde_json::Value =
            serde_json::from_str(include_str!("../genesis.json")).expect("genesis.json parses");
        let code = g["alloc"][ENDPOINT_ADDRESS]["code"]
            .as_str()
            .expect("a predeploy with code is seeded at ENDPOINT_ADDRESS");
        assert!(code.starts_with("0x60"), "looks like EVM runtime bytecode");
        assert!(code.len() > 2 + 400 * 2, "non-trivial contract code");
    }

    /// The event topic and function selector the Rust constants declare must be
    /// the ones solc compiled into the predeploy bytecode (the `PUSH32` operand
    /// before the `LOG2`, and the dispatcher selector). Ties the constants to
    /// the artifact without a keccak dependency: if the ABI changes, the
    /// embedded bytecode changes and this fails.
    #[test]
    fn topic_and_selector_match_genesis_bytecode() {
        let g: serde_json::Value =
            serde_json::from_str(include_str!("../genesis.json")).expect("genesis.json parses");
        let code = g["alloc"][ENDPOINT_ADDRESS]["code"].as_str().unwrap();
        assert!(
            code.contains(ENDPOINT_TOPIC.trim_start_matches("0x")),
            "event topic constant must appear as the PUSH32 operand in the bytecode",
        );
        assert!(
            code.contains(&hex::encode(SUBMIT_SELECTOR)),
            "function selector constant must appear in the dispatcher",
        );
    }

    #[test]
    fn parses_endpoint_command_from_log_data() {
        let cmd = b"ENDPT-encoded-signed-endpoint-command";
        let logs = json!([
            { "topics": [ENDPOINT_TOPIC, topic_node(7)], "data": abi_log_bytes(cmd) },
        ]);
        let got = parse_endpoint_logs(&logs);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].as_ref(), cmd.as_ref());
    }

    #[test]
    fn skips_wrong_topic() {
        // A rotation-topic log must not be read by the endpoint parser.
        let rotation_topic = "0xde7f9466fbeb5e013694b9e04812cc106a0a764766c202e2f88a480ee27120d1";
        let logs = json!([
            { "topics": [rotation_topic, topic_node(1)], "data": abi_log_bytes(b"x") },
        ]);
        assert!(parse_endpoint_logs(&logs).is_empty());
    }

    #[test]
    fn logs_filter_targets_the_predeploy_and_topic() {
        let f = logs_filter("0xabc");
        assert_eq!(f[0]["address"], ENDPOINT_ADDRESS);
        assert_eq!(f[0]["blockHash"], "0xabc");
        assert_eq!(f[0]["topics"][0][0], ENDPOINT_TOPIC);
    }
}
