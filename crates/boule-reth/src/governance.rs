//! On-chain identifiers for the governance-reconfiguration predeploy (#729).
//!
//! A validator-set membership change (a *reconfig*) is approved on-chain by the
//! seated validators calling the `Governance` contract
//! (`contracts/Governance.sol`), deployed as a genesis predeploy at
//! [`GOVERNANCE_ADDRESS`]. The contract accumulates each distinct approving
//! validator's on-chain weight per proposal and, once that weight crosses a
//! two-thirds supermajority of the `Registry`'s `totalWeight()`, emits a single
//! `Approved(proposalId, reconfigCommand)`. boule reads those events from each
//! committed
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
//! The contract's *tally* logic (the stake-weighted supermajority crossing,
//! validator-gating, double-approval dedup, and #764 BLS authentication) is the
//! interesting part and is exercised against a live reth (see the PR /
//! `Governance.sol` doc); this module is just the read half plus the on-chain
//! identifiers. The tally is **weight-based** (#729) and **authenticated** (#764):
//! `approve` takes the 32-byte validator id the caller votes as plus the
//! validator's BLS signature over a domain-separated digest, staticcalls the
//! `Registry`'s `weightOf`/`totalWeight`/`keyAt`/`settledView` surface (#759),
//! requires `weightOf > 0` (seated), verifies the signature against
//! `keyAt(validator, settledView())` via `BlsVerify`, and emits `Approved` once
//! the accumulated approving weight crosses a strict two-thirds supermajority of
//! `totalWeight()`.
//!
//! ## #764: the forged-quorum hole and its fix
//!
//! The earlier gate checked only `weightOf(validator) > 0`, so — validator ids
//! being public — a single actor could `approve` once per real validator id and
//! forge a ⅔ supermajority `Approved` that consensus then applied. #764 closes
//! this: each approval must carry the validator's own **BLS signature** over
//! `keccak256(abi.encode(AUTH_DOMAIN, chainId, contract, proposalId,
//! validator))`, verified in-EVM against the registry key. Naming a validator you
//! don't control no longer counts — you cannot produce its signature. The
//! authenticated in-EVM tally is thus the authority; consensus still validates
//! the carried command's well-formedness but need not re-run the quorum.
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
/// emitted once per proposal by `approve(bytes32,bytes,bytes32)` when the
/// accumulated approving **weight** first crosses the supermajority. The event
/// shape (and so this topic) is unchanged by the weighted tally (#729), so the
/// read path is untouched.
pub const APPROVED_TOPIC: &str =
    "0xd686e9e9eda221dfab37aa6cae405e85e661ed8e45cbe791790ed38093d85b75";

/// 4-byte selector of
/// `approve(bytes32 proposalId, bytes reconfigCommand, bytes32 validator, bytes blsSig)`
/// — the **authenticated**, stake-weighted, validator-gated tally entry point
/// (#729 + #764). The third arg is the 32-byte validator id the caller votes as
/// (the contract reads its `Registry.weightOf`, gated `> 0`); the fourth is the
/// validator's BLS signature (EIP-2537 G2, 256 bytes) over the approval digest,
/// verified in-EVM via `BlsVerify` against `Registry.keyAt(validator,
/// settledView())` before its weight is accrued — so naming a validator you do
/// not control cannot contribute its weight (the #764 forged-quorum fix).
pub const APPROVE_SELECTOR: [u8; 4] = [0x8e, 0x4a, 0x23, 0xcb];

/// 4-byte selector of `approveDigest(bytes32 proposalId, bytes32 validator)` —
/// the view helper returning the 32-byte digest a validator must BLS-sign to
/// approve (#764): `keccak256(abi.encode(AUTH_DOMAIN, chainId, contract,
/// proposalId, validator))`. Off-chain signers reconstruct exactly this.
pub const APPROVE_DIGEST_SELECTOR: [u8; 4] = [0x73, 0x87, 0x53, 0xb8];

/// `keccak256("BOULE_GOV_APPROVE_V1")` — the governance approval-signing domain
/// tag (#764). Embedded as `AUTH_DOMAIN` in `Governance.sol`; it separates a
/// governance approval signature from a `Param` approval (distinct domain) and
/// from any other use of the validator's BLS key, closing cross-context replay.
pub const AUTH_DOMAIN: [u8; 32] = [
    0x1c, 0x22, 0x99, 0xbe, 0x36, 0x1b, 0x40, 0xa5, 0x31, 0x53, 0x98, 0x8f, 0x6f, 0x3d, 0xb6, 0x5c,
    0xee, 0x90, 0x2f, 0x43, 0xa7, 0xd6, 0x4d, 0x94, 0x8a, 0xbe, 0x0a, 0x4e, 0xaa, 0x15, 0x6f, 0xe9,
];

/// 4-byte selector of `approvals(bytes32)` (the running accumulated approving
/// weight).
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
            ("approveDigest", APPROVE_DIGEST_SELECTOR),
            ("approvals", APPROVALS_SELECTOR),
            ("isApproved", IS_APPROVED_SELECTOR),
        ] {
            assert!(
                code.contains(&hex::encode(sel)),
                "{name} selector must appear in the dispatcher",
            );
        }
        // #764: the approval-signing domain tag must be the PUSH32 operand the
        // contract embeds, so the digest the contract checks matches what an
        // off-chain signer reconstructs from `AUTH_DOMAIN`.
        assert!(
            code.contains(&hex::encode(AUTH_DOMAIN)),
            "AUTH_DOMAIN must appear as the PUSH32 operand in the bytecode",
        );
    }

    /// #764 authentication staticcalls `Registry.keyAt` / `settledView` to fetch
    /// the validator's settled BLS key, then verifies the approval signature
    /// in-EVM. The Governance bytecode must therefore embed both Registry
    /// selectors (as `abi.encodeWithSelector` PUSH4 operands) so the cross-contract
    /// auth path cannot silently drift from `crate::registry`'s canonical values.
    #[test]
    fn registry_key_surface_pinned_in_governance_bytecode() {
        use crate::registry::{KEY_AT_SELECTOR, SETTLED_VIEW_SELECTOR};
        let g: serde_json::Value =
            serde_json::from_str(include_str!("../genesis.json")).expect("genesis.json parses");
        let code = g["alloc"][GOVERNANCE_ADDRESS]["code"]
            .as_str()
            .unwrap()
            .to_ascii_lowercase();
        assert!(
            code.contains(&hex::encode(KEY_AT_SELECTOR)),
            "Registry keyAt selector must appear in Governance's #764 auth staticcall",
        );
        assert!(
            code.contains(&hex::encode(SETTLED_VIEW_SELECTOR)),
            "Registry settledView selector must appear in Governance's #764 auth staticcall",
        );
    }

    /// The stake-weighted tally (#729) staticcalls the `Registry`'s weight
    /// surface, so the Governance bytecode must embed the **Registry**
    /// `weightOf(bytes32)` and `totalWeight()` selectors (as `abi.encodeWithSelector`
    /// PUSH4 operands) and the Registry address. Pins the cross-contract
    /// constants in `Governance.sol` to `crate::registry`'s canonical values: if
    /// the Registry's ABI/address drifts from what Governance calls, the
    /// staticcalls would silently fail and this catches it at build time.
    #[test]
    fn registry_weight_surface_pinned_in_governance_bytecode() {
        use crate::registry::{REGISTRY_ADDRESS, TOTAL_WEIGHT_SELECTOR, WEIGHT_OF_SELECTOR};
        let g: serde_json::Value =
            serde_json::from_str(include_str!("../genesis.json")).expect("genesis.json parses");
        let code = g["alloc"][GOVERNANCE_ADDRESS]["code"]
            .as_str()
            .unwrap()
            .to_ascii_lowercase();
        assert!(
            code.contains(&hex::encode(WEIGHT_OF_SELECTOR)),
            "Registry weightOf selector must appear in Governance's staticcall",
        );
        assert!(
            code.contains(&hex::encode(TOTAL_WEIGHT_SELECTOR)),
            "Registry totalWeight selector must appear in Governance's staticcall",
        );
        // The Registry address is the staticcall target. solc emits the small
        // `…b12` address as a minimal PUSH (leading zero bytes truncated), so
        // pin the meaningful low bytes rather than the full 20-byte zero-padding.
        let addr = REGISTRY_ADDRESS
            .trim_start_matches("0x")
            .to_ascii_lowercase();
        let addr_suffix = addr.trim_start_matches('0');
        assert!(
            code.contains(addr_suffix),
            "the Registry predeploy address (low bytes {addr_suffix}) must appear as the staticcall target",
        );
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
