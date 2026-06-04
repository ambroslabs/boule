//! On-chain identifiers for the live consensus-parameter-update predeploy
//! (#542 producer, authorization #746).
//!
//! A consensus parameter is changed by having the seated validators approve the
//! specific update on the `Param` contract (`contracts/Param.sol`), deployed as
//! a genesis predeploy at [`PARAM_ADDRESS`]. Each validator calls
//! `approve(proposalId, paramCommand, validator)`; the contract staticcalls the
//! `Registry` (#759) for the validator's seated `weightOf`/`totalWeight`,
//! accumulates approving weight per proposal (deduplicated per validator), and
//! emits a single `ParamSubmitted(paramCommand)` once the accrued weight crosses
//! a `> 2/3 · totalWeight` supermajority — a validator-weighted quorum mirroring
//! the #729 governance tally. boule reads those `ParamSubmitted` events from each
//! committed block — filtered by [`PARAM_TOPIC`] — via [`parse_param_logs`],
//! turning each back into the encoded command bytes. Those become a
//! [`ValidatorEffect::ParamUpdate`](boule_consensus::replication::application::ValidatorEffect::ParamUpdate)
//! on the widened `CommitResult` (#727); consensus re-materialises the command
//! into a block, where the existing param path (#542) validates the `v_eff`
//! delay and schedules the change at its view boundary so every replica adopts
//! the new value at the same view.
//!
//! The `ParamSubmitted(bytes)` event shape/topic and the `ConsensusParamHistory`
//! apply mechanism are **unchanged** by #746 — only the *gating* moved: a single
//! unauthenticated `submitParam` no longer emits; authorization is now an
//! upstream weighted quorum. Unlike rotation/endpoint, the event carries no
//! indexed `validator` (the vote-time `validator` arg is not part of the emitted
//! command). The `validator` arg is caller-supplied (the same dumb-carrier caveat
//! as the sibling predeploys): exposure is bounded because the carried command is
//! consensus-validated and the `v_eff` floor stays as defense-in-depth.
//!
//! These constants are the authoritative identifiers and match the compiled
//! runtime bytecode embedded in `genesis.json`; the tests below pin the
//! address, topic, and selectors to the genesis artifact so the Rust constants
//! and the on-chain contract cannot drift.

use bytes::Bytes;
use serde_json::{Value, json};

/// Fixed genesis-predeploy address of the parameter contract (one past the
/// endpoint predeploy at `…b10`).
pub const PARAM_ADDRESS: &str = "0x0000000000000000000000000000000000000b11";

/// `keccak256("ParamSubmitted(bytes)")` — topic0 of the `ParamSubmitted`
/// event, emitted by `approve(...)` once a weighted supermajority approves.
/// Shape and topic are deliberately unchanged from the original #542 producer so
/// the read/apply path stays compatible — only the gating moved upstream (#746).
pub const PARAM_TOPIC: &str = "0x27d1e5d546bb0a37e323040c28412ac11a38a95061bbe56c3f95d635f8826a0b";

/// 4-byte selector of `approve(bytes32,bytes,bytes32)` — a validator's weighted
/// approval of a parameter update (#746).
pub const APPROVE_SELECTOR: [u8; 4] = [0x80, 0x30, 0x9c, 0x0a];

/// 4-byte selector of `approvals(bytes32)` (the running accrued-weight tally).
pub const APPROVALS_SELECTOR: [u8; 4] = [0xbf, 0x7c, 0x21, 0x31];

/// 4-byte selector of `isApproved(bytes32)` (whether the supermajority crossed).
pub const IS_APPROVED_SELECTOR: [u8; 4] = [0x48, 0xae, 0xfc, 0x32];

/// The `eth_getLogs` filter selecting one block's parameter events: the
/// predeploy address, the block by hash, and the event topic.
pub fn logs_filter(block_hash: &str) -> Value {
    json!([{
        "blockHash": block_hash,
        "address": PARAM_ADDRESS,
        "topics": [[PARAM_TOPIC]],
    }])
}

/// The `eth_getLogs` filter selecting one block's parameter events *by EVM block
/// number* rather than hash — the by-number counterpart used when backfilling
/// blocks the EL self-synced past (cf. `staking::logs_filter_by_number`).
pub fn logs_filter_by_number(number: u64) -> Value {
    let block = format!("0x{number:x}");
    json!([{
        "fromBlock": block,
        "toBlock": block,
        "address": PARAM_ADDRESS,
        "topics": [[PARAM_TOPIC]],
    }])
}

/// Parse an `eth_getLogs` result into the encoded param-update-command bytes
/// carried by each matching log, in log order — a thin wrapper over the shared
/// [`parse_command_logs`](crate::predeploy_log::parse_command_logs) keyed on
/// [`PARAM_TOPIC`]. Malformed or wrong-topic logs are skipped; consensus
/// validates each returned command (tag + `v_eff` delay) before acting on it.
pub fn parse_param_logs(logs: &Value) -> Vec<Bytes> {
    crate::predeploy_log::parse_command_logs(logs, PARAM_TOPIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::predeploy_log::test_support::abi_log_bytes;

    /// The predeploy address the read path filters logs on must match the
    /// account seeded in `genesis.json` with non-empty code — else boule would
    /// watch the wrong address and never see a parameter update. Pins the Rust
    /// constant to the on-chain artifact.
    #[test]
    fn param_predeploy_present_in_genesis_at_address() {
        let g: serde_json::Value =
            serde_json::from_str(include_str!("../genesis.json")).expect("genesis.json parses");
        let code = g["alloc"][PARAM_ADDRESS]["code"]
            .as_str()
            .expect("a predeploy with code is seeded at PARAM_ADDRESS");
        assert!(code.starts_with("0x60"), "looks like EVM runtime bytecode");
        assert!(code.len() > 2 + 300 * 2, "non-trivial contract code");
    }

    /// The event topic and function selectors the Rust constants declare must be
    /// the ones solc compiled into the predeploy bytecode (the `PUSH32` operand
    /// before the `LOG1`, and the dispatcher selectors). Ties the constants to
    /// the artifact without a keccak dependency: if the ABI changes, the
    /// embedded bytecode changes and this fails. Also pins the `Registry` weight
    /// selectors the contract staticcalls (#746/#759), so a drift in either the
    /// read side or the registry surface is caught here.
    #[test]
    fn topic_and_selector_match_genesis_bytecode() {
        let g: serde_json::Value =
            serde_json::from_str(include_str!("../genesis.json")).expect("genesis.json parses");
        let code = g["alloc"][PARAM_ADDRESS]["code"].as_str().unwrap();
        assert!(
            code.contains(PARAM_TOPIC.trim_start_matches("0x")),
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
        // The weighted-quorum gate staticcalls the Registry's weight surface;
        // those selectors must appear as PUSH4 operands in the staticcall path.
        for (name, sel) in [
            ("weightOf", crate::registry::WEIGHT_OF_SELECTOR),
            ("totalWeight", crate::registry::TOTAL_WEIGHT_SELECTOR),
        ] {
            assert!(
                code.contains(&hex::encode(sel)),
                "registry {name} selector must appear in the staticcall path",
            );
        }
    }

    /// The Registry address the gate staticcalls (`weightOf`/`totalWeight`) must
    /// be the real registry predeploy — else every `approve` would call a dead
    /// address and revert. solc compiles the small constant address
    /// (`0x…0b12`) to its minimal `PUSH2 0x0b12` form (leading zero bytes
    /// dropped), so this pins that minimal operand baked into the Param bytecode
    /// to [`crate::registry::REGISTRY_ADDRESS`] rather than the 20-byte form.
    #[test]
    fn staticcalls_the_registry_predeploy_address() {
        let g: serde_json::Value =
            serde_json::from_str(include_str!("../genesis.json")).expect("genesis.json parses");
        let code = g["alloc"][PARAM_ADDRESS]["code"]
            .as_str()
            .unwrap()
            .to_ascii_lowercase();
        // REGISTRY_ADDRESS with leading zero bytes stripped == "b12"; solc pushes
        // it as PUSH2 (0x61) 0x0b12, i.e. the operand "0b12" in the bytecode.
        let minimal = crate::registry::REGISTRY_ADDRESS
            .trim_start_matches("0x")
            .trim_start_matches('0');
        assert_eq!(
            minimal, "b12",
            "registry address is the small …0b12 predeploy"
        );
        assert!(
            code.contains("610b12"),
            "the registry predeploy address must appear as the PUSH2 staticcall target",
        );
    }

    #[test]
    fn parses_param_command_from_log_data() {
        // A ParamSubmitted event carries only the dynamic bytes (no indexed
        // validator), so its topics are just [topic0].
        let cmd = b"CPARM-encoded-consensus-param-update";
        let logs = json!([
            { "topics": [PARAM_TOPIC], "data": abi_log_bytes(cmd) },
        ]);
        let got = parse_param_logs(&logs);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].as_ref(), cmd.as_ref());
    }

    #[test]
    fn skips_wrong_topic() {
        let endpoint_topic = "0x26a38d91fc47b4cd0e93f73c87346a4236d696ffe5a241f95c33fc2670d28349";
        let logs = json!([
            { "topics": [endpoint_topic], "data": abi_log_bytes(b"x") },
        ]);
        assert!(parse_param_logs(&logs).is_empty());
    }

    #[test]
    fn logs_filter_targets_the_predeploy_and_topic() {
        let f = logs_filter("0xabc");
        assert_eq!(f[0]["address"], PARAM_ADDRESS);
        assert_eq!(f[0]["blockHash"], "0xabc");
        assert_eq!(f[0]["topics"][0][0], PARAM_TOPIC);
    }
}
