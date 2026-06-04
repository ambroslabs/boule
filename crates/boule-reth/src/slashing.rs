//! On-chain identifiers for the equivocation-slashing predeploy (#732b).
//!
//! The `Slashing` contract (`contracts/Slashing.sol`), deployed as a genesis
//! predeploy at [`SLASHING_ADDRESS`], verifies a validator equivocation proof
//! **in the EVM** and, on success, emits [`Slashed`](SLASHED_TOPIC). A watcher
//! submits two `Vote`s for the same view but different blocks; the predeploy
//! first gates on the registry's **settled frontier** (#732/#767 — only accept a
//! proof for `view <= Registry.settledView()`, so it never verifies against a
//! key the registry has not yet recorded *in executed EVM state*; the proposer
//! advances that frontier conservatively, a margin behind the committed view and
//! only once its registry writes have executed, so the gate is lag-free by
//! construction; see [`SETTLED_VIEW_SELECTOR`] and
//! [`registry::SETTLED_VIEW_MARGIN`](crate::registry::SETTLED_VIEW_MARGIN)), then
//! reads the validator's BLS key from the registry (#732a `keyAt`), reconstructs
//! both `preimage::<Vote>` signing messages, and verifies both signatures via
//! the Prague EIP-2537 precompiles (see `contracts/BlsVerify.sol`).
//!
//! It only **verifies + signals** — the economic penalty stays
//! consensus-authoritative (#654): boule reads `Slashed` from each committed
//! block (the #655/#730 `eth_getLogs` pattern, the next #732 step) and applies
//! it through its `StakeSource` → jail (the #658 apply-target). So this module,
//! like the staking/rotation ones, declares the on-chain identifiers (mirrored
//! as constants and pinned to the genesis bytecode by the tests below).
//!
//! The full verify + emit path is exercised against a live reth (see the PR /
//! `contracts/test/slashing.mjs`): a valid equivocation emits `Slashed`, while a
//! same-block proof or a signature that does not match its block reverts.
//!
//! The read half lives here: [`logs_filter`] selects one committed block's
//! `Slashed` events and [`parse_slashed_logs`] extracts the equivocator's
//! [`NodeId`] from the indexed `topics[1]`. Unlike the rotation/endpoint
//! predeploys (whose events carry an opaque consensus command in the log
//! `data`), `Slashed` is purely a *signal*: the validator id is the only
//! payload boule needs — it applies the penalty directly through its
//! `StakeSource::slash` (#658b) → jail (#658a). So this parser mirrors the
//! staking read path ([`parse_stake_logs`](crate::staking::parse_stake_logs)),
//! not the command-bytes one.

use serde_json::{Value, json};

use boule_core::identity::NodeId;

use crate::engine::root_from_hex;

/// Fixed genesis-predeploy address of the slashing contract (one past the
/// registry predeploy at `…b12`).
pub const SLASHING_ADDRESS: &str = "0x0000000000000000000000000000000000000b13";

/// `keccak256("Slashed(bytes32,uint64,bytes32,bytes32)")` — topic0 of the
/// `Slashed` event boule's read path (next #732 step) filters on.
pub const SLASHED_TOPIC: &str =
    "0xaa027002e2293d2bdf5dfdb36085da833212945f22a1bc33658aab00be192988";

/// 4-byte selector of
/// `submitEquivocation(bytes32,bytes,uint64,bytes32,bytes,bytes32,bytes)` — the
/// proof-submission entrypoint a watcher calls.
pub const SUBMIT_EQUIVOCATION_SELECTOR: [u8; 4] = [0xa3, 0x9f, 0xe9, 0xc0];

/// 4-byte selector of the registry's `settledView()` getter, which the slashing
/// predeploy `staticcall`s to gate a proof on the **settled frontier** (#732):
/// `submitEquivocation` reverts (`"view not settled"`) unless
/// `view <= Registry.settledView()`, so it never verifies against a key the
/// registry has not yet recorded. Mirrors [`registry::SETTLED_VIEW_SELECTOR`];
/// pinned to the predeploy bytecode by the genesis test below.
///
/// [`registry::SETTLED_VIEW_SELECTOR`]: crate::registry::SETTLED_VIEW_SELECTOR
pub const SETTLED_VIEW_SELECTOR: [u8; 4] = [0x7a, 0x68, 0x6e, 0xf2];

/// The `eth_getLogs` filter selecting one committed block's `Slashed` events:
/// the predeploy address, the block by hash, and the `Slashed` topic. Mirrors
/// the staking read path's filter.
pub fn logs_filter(block_hash: &str) -> Value {
    json!([{
        "blockHash": block_hash,
        "address": SLASHING_ADDRESS,
        "topics": [SLASHED_TOPIC],
    }])
}

/// Parse an `eth_getLogs` result (an array of slashing-predeploy log objects)
/// into the equivocators' [`NodeId`]s, in log order — one per `Slashed` event.
///
/// `Slashed(bytes32 indexed validator, uint64 viewNum, bytes32 blockA,
/// bytes32 blockB)` carries the validator id in the indexed `topics[1]` (the
/// 32-byte node id); the view and the two conflicting block hashes ride the
/// non-indexed `data` and are the on-chain proof's audit trail, not needed by
/// the apply path (the EVM already verified the equivocation). Logs whose
/// `topics[0]` is not [`SLASHED_TOPIC`], that lack the indexed validator, or
/// whose validator word is not a 32-byte hex value are skipped.
pub fn parse_slashed_logs(logs: &Value) -> Vec<NodeId> {
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
        if topics[0].as_str().unwrap_or_default().to_ascii_lowercase() != SLASHED_TOPIC {
            continue;
        }
        // topics[1] is the indexed bytes32 validator id — the same on-chain →
        // NodeId mapping the staking/rotation read paths use (the raw 32 bytes).
        if let Ok(node_id) = root_from_hex(topics[1].as_str().unwrap_or_default()) {
            out.push(node_id);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The slashing predeploy must be seeded in `genesis.json` at
    /// [`SLASHING_ADDRESS`] with non-empty code, or watchers would submit proofs
    /// to a dead address. Pins the Rust constant to the (generated) on-chain
    /// artifact.
    #[test]
    fn slashing_predeploy_present_in_genesis_at_address() {
        let g: serde_json::Value =
            serde_json::from_str(include_str!("../genesis.json")).expect("genesis.json parses");
        let code = g["alloc"][SLASHING_ADDRESS]["code"]
            .as_str()
            .expect("a predeploy with code is seeded at SLASHING_ADDRESS");
        assert!(code.starts_with("0x60"), "looks like EVM runtime bytecode");
        assert!(code.len() > 2 + 1000 * 2, "non-trivial contract code");
    }

    /// The event topic and function selector the Rust constants declare must be
    /// the ones solc compiled into the predeploy bytecode. Ties the constants to
    /// the artifact without a keccak dependency: if the ABI changes, the
    /// generated bytecode changes and this fails.
    #[test]
    fn topic_and_selector_match_genesis_bytecode() {
        let g: serde_json::Value =
            serde_json::from_str(include_str!("../genesis.json")).expect("genesis.json parses");
        let code = g["alloc"][SLASHING_ADDRESS]["code"].as_str().unwrap();
        assert!(
            code.contains(SLASHED_TOPIC.trim_start_matches("0x")),
            "Slashed event topic must appear as the LOG topic operand",
        );
        assert!(
            code.contains(&hex::encode(SUBMIT_EQUIVOCATION_SELECTOR)),
            "submitEquivocation selector must appear in the dispatcher",
        );
        // The settled-frontier gate (#732) staticcalls Registry.settledView();
        // its selector must be embedded as the staticcall calldata constant.
        assert!(
            code.contains(&hex::encode(SETTLED_VIEW_SELECTOR)),
            "settledView() selector must appear (the settled-frontier gate calls it)",
        );
    }

    /// The Rust [`SETTLED_VIEW_SELECTOR`] mirror must equal the registry's own
    /// `settledView()` selector — they are the same on-chain getter, so a drift
    /// would mean the slashing gate calls a different function than the registry
    /// exposes.
    #[test]
    fn settled_view_selector_matches_registry() {
        assert_eq!(
            SETTLED_VIEW_SELECTOR,
            crate::registry::SETTLED_VIEW_SELECTOR,
            "slashing's settledView selector must match the registry's",
        );
    }

    /// A 32-byte topic word for validator id byte `b` (an indexed bytes32).
    fn topic_node(b: u8) -> String {
        format!("0x{}", format!("{b:02x}").repeat(32))
    }

    /// The 96-byte `Slashed` data payload: `viewNum` (uint64, left-padded to a
    /// word), then the two conflicting block hashes — none of which the apply
    /// path reads. Just enough to make the log realistic.
    fn slashed_data(view: u64, block_a: u8, block_b: u8) -> String {
        format!(
            "0x{:064x}{}{}",
            view,
            format!("{block_a:02x}").repeat(32),
            format!("{block_b:02x}").repeat(32),
        )
    }

    #[test]
    fn parses_the_indexed_validator_from_each_slashed_log() {
        let logs = json!([
            { "topics": [SLASHED_TOPIC, topic_node(7)], "data": slashed_data(3, 0xaa, 0xbb) },
            { "topics": [SLASHED_TOPIC, topic_node(9)], "data": slashed_data(4, 0xcc, 0xdd) },
        ]);
        assert_eq!(parse_slashed_logs(&logs), vec![[7u8; 32], [9u8; 32]]);
    }

    #[test]
    fn slashed_topic_is_matched_case_insensitively() {
        // reth returns lowercase hex; tolerate a mixed-case topic0 too.
        let upper = SLASHED_TOPIC.to_ascii_uppercase().replace("0X", "0x");
        let logs = json!([{ "topics": [upper, topic_node(1)], "data": slashed_data(1, 0, 0) }]);
        assert_eq!(parse_slashed_logs(&logs), vec![[1u8; 32]]);
    }

    #[test]
    fn skips_wrong_topic_missing_validator_and_malformed() {
        let other = "0xabababababababababababababababababababababababababababababababab";
        let logs = json!([
            // wrong topic0
            { "topics": [other, topic_node(1)], "data": slashed_data(1, 0, 0) },
            // missing the indexed validator
            { "topics": [SLASHED_TOPIC], "data": slashed_data(1, 0, 0) },
            // validator word is not 32 bytes
            { "topics": [SLASHED_TOPIC, "0x1234"], "data": slashed_data(1, 0, 0) },
            // not an object
            "garbage",
        ]);
        assert!(parse_slashed_logs(&logs).is_empty());
        // A non-array result (reth returned null/error-shaped) yields nothing.
        assert!(parse_slashed_logs(&Value::Null).is_empty());
    }

    #[test]
    fn logs_filter_targets_the_predeploy_and_slashed_topic() {
        let f = logs_filter("0xabc");
        assert_eq!(f[0]["address"], SLASHING_ADDRESS);
        assert_eq!(f[0]["blockHash"], "0xabc");
        assert_eq!(f[0]["topics"][0], SLASHED_TOPIC);
    }
}
