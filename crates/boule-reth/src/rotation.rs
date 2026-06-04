//! On-chain identifiers for the validator key-rotation predeploy (#730).
//!
//! A validator submits a consensus key / operator-key rotation by calling the
//! `Rotation` contract (`contracts/Rotation.sol`), deployed as a genesis
//! predeploy at [`ROTATION_ADDRESS`], with the already-encoded, dual-signed
//! boule rotation command as calldata. boule reads the `RotationSubmitted`
//! events it emits from each committed block — filtered by [`ROTATION_TOPIC`]
//! — via [`parse_rotation_logs`], turning each back into the encoded rotation
//! command bytes. Those become a
//! [`ValidatorEffect::KeyRotation`](boule_consensus::replication::application::ValidatorEffect::KeyRotation)
//! on the widened `CommitResult` (#727); consensus re-materialises the command
//! into a block, where the existing rotation path verifies the self-attestation
//! signatures and schedules the `v_eff` key swap. The `RotatableSigner` /
//! key-history mechanism (#312/#258) is unchanged — only the *submission* path
//! moves onto the EVM, replacing the bespoke rotation mempool tx + hex CLIs.
//!
//! The contract is a pure event emitter: it does no verification (consensus
//! does, on the carried command). These constants are the authoritative
//! identifiers and match the compiled runtime bytecode embedded in
//! `genesis.json`; the tests below pin the address, topic, and selector to the
//! genesis artifact so the Rust constants and the on-chain contract cannot
//! drift.

use bytes::Bytes;
use serde_json::{Value, json};

/// Fixed genesis-predeploy address of the rotation contract (one past the
/// staking predeploy at `…b0e`).
pub const ROTATION_ADDRESS: &str = "0x0000000000000000000000000000000000000b0f";

/// `keccak256("RotationSubmitted(bytes32,bytes)")` — topic0 of the
/// `RotationSubmitted` event, emitted by
/// `submitRotation(bytes32 validator, bytes rotationCommand)`.
pub const ROTATION_TOPIC: &str =
    "0xde7f9466fbeb5e013694b9e04812cc106a0a764766c202e2f88a480ee27120d1";

/// 4-byte selector of `submitRotation(bytes32,bytes)`.
pub const SUBMIT_SELECTOR: [u8; 4] = [0x37, 0xfe, 0x3f, 0x23];

/// The `eth_getLogs` filter selecting one block's rotation events: the
/// predeploy address, the block by hash, and the event topic.
pub fn logs_filter(block_hash: &str) -> Value {
    json!([{
        "blockHash": block_hash,
        "address": ROTATION_ADDRESS,
        "topics": [[ROTATION_TOPIC]],
    }])
}

/// The `eth_getLogs` filter selecting one block's rotation events *by EVM block
/// number* rather than hash — the by-number counterpart used when backfilling
/// blocks the EL self-synced past (cf. `staking::logs_filter_by_number`).
pub fn logs_filter_by_number(number: u64) -> Value {
    let block = format!("0x{number:x}");
    json!([{
        "fromBlock": block,
        "toBlock": block,
        "address": ROTATION_ADDRESS,
        "topics": [[ROTATION_TOPIC]],
    }])
}

/// Parse an `eth_getLogs` result into the encoded rotation-command bytes
/// carried by each matching log, in log order — a thin wrapper over the shared
/// [`parse_command_logs`](crate::predeploy_log::parse_command_logs) keyed on
/// [`ROTATION_TOPIC`]. Malformed or wrong-topic logs are skipped; consensus
/// validates each returned command (tag + signatures) before acting on it.
pub fn parse_rotation_logs(logs: &Value) -> Vec<Bytes> {
    crate::predeploy_log::parse_command_logs(logs, ROTATION_TOPIC)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The predeploy address the read path filters logs on must match the
    /// account actually seeded in `genesis.json` with non-empty code — else
    /// boule would watch the wrong address and never see a rotation. Pins the
    /// Rust constant to the on-chain artifact.
    #[test]
    fn rotation_predeploy_present_in_genesis_at_address() {
        let g: serde_json::Value =
            serde_json::from_str(include_str!("../genesis.json")).expect("genesis.json parses");
        let code = g["alloc"][ROTATION_ADDRESS]["code"]
            .as_str()
            .expect("a predeploy with code is seeded at ROTATION_ADDRESS");
        assert!(code.starts_with("0x60"), "looks like EVM runtime bytecode");
        assert!(code.len() > 2 + 400 * 2, "non-trivial contract code");
    }

    /// The event topic and function selector the Rust constants declare must be
    /// the ones solc actually compiled into the predeploy bytecode (the
    /// `PUSH32` operand before the `LOG2`, and the dispatcher selector). This
    /// ties the constants to the artifact without a keccak dependency: if the
    /// contract's ABI changes, the embedded bytecode changes and this fails.
    #[test]
    fn topic_and_selector_match_genesis_bytecode() {
        let g: serde_json::Value =
            serde_json::from_str(include_str!("../genesis.json")).expect("genesis.json parses");
        let code = g["alloc"][ROTATION_ADDRESS]["code"].as_str().unwrap();
        assert!(
            code.contains(ROTATION_TOPIC.trim_start_matches("0x")),
            "event topic constant must appear as the PUSH32 operand in the bytecode",
        );
        assert!(
            code.contains(&hex::encode(SUBMIT_SELECTOR)),
            "function selector constant must appear in the dispatcher",
        );
    }

    fn topic_node(b: u8) -> String {
        format!("0x{}", format!("{b:02x}").repeat(32))
    }

    /// ABI-encode a dynamic `bytes` value the way the EVM lays it out in log
    /// data: offset word (`0x20`), length word, then the right-padded bytes.
    fn abi_bytes(payload: &[u8]) -> String {
        let mut data = Vec::new();
        let mut word = [0u8; 32];
        word[31] = 0x20; // offset = 32
        data.extend_from_slice(&word);
        let mut lenw = [0u8; 32];
        lenw[24..32].copy_from_slice(&(payload.len() as u64).to_be_bytes());
        data.extend_from_slice(&lenw);
        data.extend_from_slice(payload);
        // right-pad to a 32-byte boundary
        let pad = (32 - payload.len() % 32) % 32;
        data.extend(std::iter::repeat_n(0u8, pad));
        format!("0x{}", hex::encode(data))
    }

    #[test]
    fn parses_rotation_command_from_log_data() {
        let cmd = b"OKROT-encoded-dual-signed-rotation-command";
        let logs = json!([
            { "topics": [ROTATION_TOPIC, topic_node(7)], "data": abi_bytes(cmd) },
        ]);
        let got = parse_rotation_logs(&logs);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].as_ref(), cmd.as_ref());
    }

    #[test]
    fn parses_multiple_in_log_order() {
        let a = b"first-rotation";
        let b = b"second-rotation-longer-than-thirty-two-bytes-to-cross-a-word";
        let logs = json!([
            { "topics": [ROTATION_TOPIC, topic_node(1)], "data": abi_bytes(a) },
            { "topics": [ROTATION_TOPIC, topic_node(2)], "data": abi_bytes(b) },
        ]);
        let got = parse_rotation_logs(&logs);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].as_ref(), a.as_ref());
        assert_eq!(got[1].as_ref(), b.as_ref());
    }

    #[test]
    fn skips_wrong_topic_and_malformed_data() {
        let logs = json!([
            // wrong topic0
            { "topics": [topic_node(0xab), topic_node(7)], "data": abi_bytes(b"x") },
            // missing topics
            { "data": abi_bytes(b"x") },
            // data too short (no length word)
            { "topics": [ROTATION_TOPIC, topic_node(7)], "data": "0x20" },
            // not an object
            "garbage",
        ]);
        assert!(parse_rotation_logs(&logs).is_empty());
        assert!(parse_rotation_logs(&serde_json::Value::Null).is_empty());
    }

    #[test]
    fn rejects_length_running_past_the_data() {
        // offset 0x20, length 0x40 (64) but only 1 byte of payload follows.
        let bad = "0x".to_string() + &"0".repeat(62) + "20" + &"0".repeat(62) + "40" + "ff";
        let logs = json!([{ "topics": [ROTATION_TOPIC, topic_node(1)], "data": bad }]);
        assert!(parse_rotation_logs(&logs).is_empty());
    }

    #[test]
    fn logs_filter_targets_the_predeploy_and_topic() {
        let f = logs_filter("0xabc");
        assert_eq!(f[0]["address"], ROTATION_ADDRESS);
        assert_eq!(f[0]["blockHash"], "0xabc");
        assert_eq!(f[0]["topics"][0][0], ROTATION_TOPIC);
    }
}
