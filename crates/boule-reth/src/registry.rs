//! On-chain identifiers for the validator BLS-key registry predeploy (#732a).
//!
//! The `Registry` contract (`contracts/Registry.sol`), deployed as a genesis
//! predeploy at [`REGISTRY_ADDRESS`], holds boule's per-validator BLS key
//! history in EVM **storage** — the materialised mirror of consensus's
//! `BlsKeyHistory`. Its purpose is to let an in-EVM **slashing precompile**
//! (#732b) look up *which BLS key a validator signed under at a past view*
//! (`keyAt(validator, view)`), the settled, lag-free read the design
//! (`docs/validator-registry-and-slashing.md`) relies on.
//!
//! Unlike the submission predeploys (staking/rotation/endpoint/param), the
//! registry is read **in the EVM** (by the slashing predeploy via `SLOAD`), not
//! by boule via `eth_getLogs` — so this module carries the on-chain identifiers
//! (mirrored as constants and pinned to the genesis bytecode by the tests
//! below) plus the **genesis-seed** half of the write path (#732 step 2):
//! [`genesis_seed_storage`] derives the `alloc[Registry].storage` words that
//! pre-populate the genesis validators' keys — the EVM analogue of
//! `BlsKeyHistory::with_genesis`. The *rotation* half of the write path is
//! handled boule-side (rotations are postcard-encoded and not decodable in
//! Solidity — see `docs/validator-registry-and-slashing.md` "The write path").
//!
//! The contract's storage logic is exercised against a live reth (see the PR /
//! `Registry.sol` doc): `recordKey` appends a monotone `(vEff, key)` entry and
//! `keyAt` returns the entry with the greatest `vEff <= view`.

/// Fixed genesis-predeploy address of the registry contract (one past the
/// parameter predeploy at `…b11`).
pub const REGISTRY_ADDRESS: &str = "0x0000000000000000000000000000000000000b12";

/// `keccak256("KeyRecorded(bytes32,uint64,bytes)")` — topic0 of the
/// `KeyRecorded` event, emitted by `recordKey`.
pub const KEY_RECORDED_TOPIC: &str =
    "0x6a8fd2a0f1d9cf8a45c363bc1be9d77d28519827b041057dce545b44ff9680dd";

/// 4-byte selector of `keyAt(bytes32,uint64)` (the settled historical lookup the
/// slashing precompile calls).
pub const KEY_AT_SELECTOR: [u8; 4] = [0x3a, 0x9e, 0x35, 0x8a];

/// 4-byte selector of `recordKey(bytes32,uint64,bytes)`.
pub const RECORD_KEY_SELECTOR: [u8; 4] = [0x82, 0x4b, 0x98, 0x02];

/// 4-byte selector of `historyLength(bytes32)`.
pub const HISTORY_LENGTH_SELECTOR: [u8; 4] = [0x43, 0x90, 0x58, 0x59];

/// Declaration slot of the registry's `mapping(bytes32 => KeyEntry[]) history`
/// — the single state variable in `Registry.sol`, so it occupies slot `0`.
const HISTORY_MAPPING_SLOT: u64 = 0;

/// Slots a `KeyEntry { uint64 vEff; bytes key; }` element occupies in the
/// packed array storage: one slot for `vEff` (a `uint64` does not pack with the
/// following dynamic `bytes`), one for the `key` length/pointer header.
const KEY_ENTRY_SLOTS: u64 = 2;

use boule_consensus::View;
use boule_core::crypto::sig_scheme::BlsPublicKey;
use boule_core::identity::NodeId;

/// keccak256 of `bytes`.
fn keccak256(bytes: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    let mut h = Keccak256::new();
    h.update(bytes);
    h.finalize().into()
}

/// `slot + delta`, treating the 32-byte slot as a big-endian integer. Storage
/// slots never wrap in practice (they are keccak outputs offset by tiny
/// indices), so an overflow here is a derivation bug.
fn slot_add(slot: &[u8; 32], delta: u64) -> [u8; 32] {
    let mut out = *slot;
    let mut carry = delta as u128;
    for byte in out.iter_mut().rev() {
        if carry == 0 {
            break;
        }
        let sum = *byte as u128 + (carry & 0xff);
        *byte = sum as u8;
        carry = (carry >> 8) + (sum >> 8);
    }
    assert_eq!(carry, 0, "registry storage slot derivation overflowed");
    out
}

/// A single `(slot, value)` storage write, both 32-byte big-endian.
type StorageEntry = ([u8; 32], [u8; 32]);

/// Compute the `alloc[Registry].storage` entries that seed the genesis
/// validators' BLS keys into the registry predeploy — the EVM analogue of
/// `BlsKeyHistory::with_genesis`.
///
/// Each genesis validator gets a one-element history `[(vEff: 0, key)]`, exactly
/// as `with_genesis` seeds consensus-side at `View::ZERO`. The resulting map is
/// what would be merged into the `alloc` entry at [`REGISTRY_ADDRESS`] in a
/// *deployment-specific* genesis (the committed `genesis.template.json` carries
/// no validator keys — they are per-deployment), so a live reth answers
/// `keyAt(validator, V) == key` from block zero without any transaction.
///
/// ## Storage-slot layout (Solidity `mapping(bytes32 => KeyEntry[])` at slot 0)
///
/// For `history[validator]`:
/// - `arraySlot = keccak256(validator ‖ uint256(0))` holds the array **length**.
/// - element `i` lives at `dataBase = keccak256(arraySlot)` offset by
///   `i * KEY_ENTRY_SLOTS`:
///   - `+0`: `vEff` (`uint64`, right-aligned in the 32-byte slot).
///   - `+1`: the `key` `bytes` header. A 48-byte BLS key exceeds 31 bytes, so
///     it uses the **long form**: this slot holds `2 * len + 1`, and the bytes
///     themselves start at `keccak256(headerSlot)`, one 32-byte slot at a time
///     (48 bytes → 2 slots, the second right-padded with zeros).
///
/// All genesis entries are `vEff = 0` so each validator's array length is `1`.
pub fn genesis_seed_storage(
    genesis: impl IntoIterator<Item = (NodeId, BlsPublicKey)>,
) -> Vec<StorageEntry> {
    let mut out = Vec::new();
    for (validator, key) in genesis {
        out.extend(validator_history_storage(&validator, &[(View::ZERO, key)]));
    }
    out
}

/// Storage entries for one validator's `(vEff, key)` history (entries must be
/// vEff-ascending, matching the contract's monotonicity invariant). Factored
/// out of [`genesis_seed_storage`] so the slot math is exercised on its own and
/// reusable for non-genesis seeds (e.g. a reconfig add).
fn validator_history_storage(
    validator: &NodeId,
    entries: &[(View, BlsPublicKey)],
) -> Vec<StorageEntry> {
    let mut out = Vec::new();

    // arraySlot = keccak256(validator ‖ uint256(mappingSlot))
    let mut key_preimage = [0u8; 64];
    key_preimage[..32].copy_from_slice(validator);
    key_preimage[32 + 24..].copy_from_slice(&HISTORY_MAPPING_SLOT.to_be_bytes());
    let array_slot = keccak256(&key_preimage);

    // Array length at arraySlot.
    let mut len_word = [0u8; 32];
    len_word[24..].copy_from_slice(&(entries.len() as u64).to_be_bytes());
    out.push((array_slot, len_word));

    let data_base = keccak256(&array_slot);
    for (i, (v_eff, key)) in entries.iter().enumerate() {
        let elem = slot_add(&data_base, i as u64 * KEY_ENTRY_SLOTS);

        // +0: vEff (uint64), right-aligned.
        let mut v_word = [0u8; 32];
        v_word[24..].copy_from_slice(&v_eff.0.to_be_bytes());
        out.push((elem, v_word));

        // +1: bytes header (long form: 2*len + 1).
        let header_slot = slot_add(&elem, 1);
        let mut header = [0u8; 32];
        let coded_len = (key.len() as u128) * 2 + 1;
        header[16..].copy_from_slice(&coded_len.to_be_bytes());
        out.push((header_slot, header));

        // bytes data at keccak256(headerSlot), one 32-byte slot at a time.
        let chunk_base = keccak256(&header_slot);
        for (j, chunk) in key.chunks(32).enumerate() {
            let mut word = [0u8; 32];
            word[..chunk.len()].copy_from_slice(chunk);
            out.push((slot_add(&chunk_base, j as u64), word));
        }
    }
    out
}

/// Render [`genesis_seed_storage`] as a `serde_json` object suitable for an
/// `alloc[Registry].storage` field (`"0x<slot>": "0x<value>"`, both 32-byte
/// hex) — the form `reth`'s genesis loader and the genesis-pin tests expect.
pub fn genesis_seed_storage_json(
    genesis: impl IntoIterator<Item = (NodeId, BlsPublicKey)>,
) -> serde_json::Map<String, serde_json::Value> {
    let mut map = serde_json::Map::new();
    for (slot, value) in genesis_seed_storage(genesis) {
        map.insert(
            format!("0x{}", hex::encode(slot)),
            serde_json::Value::String(format!("0x{}", hex::encode(value))),
        );
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registry predeploy must be seeded in `genesis.json` at
    /// [`REGISTRY_ADDRESS`] with non-empty code, or an in-EVM reader would call
    /// a dead address. Pins the Rust constant to the (generated) on-chain
    /// artifact.
    #[test]
    fn registry_predeploy_present_in_genesis_at_address() {
        let g: serde_json::Value =
            serde_json::from_str(include_str!("../genesis.json")).expect("genesis.json parses");
        let code = g["alloc"][REGISTRY_ADDRESS]["code"]
            .as_str()
            .expect("a predeploy with code is seeded at REGISTRY_ADDRESS");
        assert!(code.starts_with("0x60"), "looks like EVM runtime bytecode");
        assert!(code.len() > 2 + 1000 * 2, "non-trivial contract code");
    }

    /// The event topic and function selectors the Rust constants declare must be
    /// the ones solc compiled into the predeploy bytecode. Ties the constants to
    /// the artifact without a keccak dependency: if the ABI changes, the
    /// generated bytecode changes and this fails.
    #[test]
    fn topic_and_selectors_match_genesis_bytecode() {
        let g: serde_json::Value =
            serde_json::from_str(include_str!("../genesis.json")).expect("genesis.json parses");
        let code = g["alloc"][REGISTRY_ADDRESS]["code"].as_str().unwrap();
        assert!(
            code.contains(KEY_RECORDED_TOPIC.trim_start_matches("0x")),
            "KeyRecorded event topic must appear as the PUSH32 operand",
        );
        for (name, sel) in [
            ("keyAt", KEY_AT_SELECTOR),
            ("recordKey", RECORD_KEY_SELECTOR),
            ("historyLength", HISTORY_LENGTH_SELECTOR),
        ] {
            assert!(
                code.contains(&hex::encode(sel)),
                "{name} selector must appear in the dispatcher",
            );
        }
    }

    fn val(b: u8) -> NodeId {
        [b; 32]
    }
    fn key(b: u8) -> BlsPublicKey {
        [b; 48]
    }

    // Ground-truth storage words for the genesis seed of
    // validator = 0xaa*32, key = 0x11*48, vEff = 0 — captured from a live reth
    // via `eth_getStorageAt` (see `contracts/test/registry-seed.mjs`).
    const REG_SEED_ARRAY_SLOT: &str =
        "0xd4e804f1354b8536b910364132804434559ef187d3b44e1868ebcf9bee54434b";
    const REG_SEED_LEN_VALUE: &str =
        "0x0000000000000000000000000000000000000000000000000000000000000001";
    const REG_SEED_VEFF_SLOT: &str =
        "0x58fe01d67c0d3b0bdcb10eb4c6d3db43abdb90eae559ad453ab2251865a9f3bd";
    const REG_SEED_VEFF_VALUE: &str =
        "0x0000000000000000000000000000000000000000000000000000000000000000";
    const REG_SEED_HEADER_SLOT: &str =
        "0x58fe01d67c0d3b0bdcb10eb4c6d3db43abdb90eae559ad453ab2251865a9f3be";
    const REG_SEED_HEADER_VALUE: &str =
        "0x0000000000000000000000000000000000000000000000000000000000000061";
    const REG_SEED_CHUNK0_SLOT: &str =
        "0xc25886be15ecb57b4bb548a15123446d24bef1a38ef876e5a3e3e7a43ae2cd9a";
    const REG_SEED_CHUNK0_VALUE: &str =
        "0x1111111111111111111111111111111111111111111111111111111111111111";
    const REG_SEED_CHUNK1_SLOT: &str =
        "0xc25886be15ecb57b4bb548a15123446d24bef1a38ef876e5a3e3e7a43ae2cd9b";
    const REG_SEED_CHUNK1_VALUE: &str =
        "0x1111111111111111111111111111111100000000000000000000000000000000";

    /// The seed for one validator writes exactly the five storage words the
    /// layout requires: array length, `vEff`, the `bytes` long-form header, and
    /// the two key-data chunks. (48 bytes → 2 chunks.)
    #[test]
    fn one_validator_writes_five_words() {
        let seed = genesis_seed_storage([(val(0xaa), key(0x11))]);
        assert_eq!(seed.len(), 5, "len + vEff + header + 2 data chunks");
    }

    /// Pins the full slot/value derivation for one genesis validator
    /// (validator = `0xaa*32`, key = `0x11*48`, vEff = 0). The expected
    /// `(slot, value)` words below are the ground truth observed on a **live
    /// reth** via `eth_getStorageAt` after seeding this exact entry into
    /// `alloc[Registry].storage` (see `contracts/test/registry-seed.mjs`), so if
    /// the slot math drifts from Solidity's actual layout this fails.
    #[test]
    fn slot_derivation_matches_live_reth_ground_truth() {
        let seed = genesis_seed_storage([(val(0xaa), key(0x11))]);
        // Ground truth from a live reth (`registry-seed.mjs`): the exact
        // `(slot -> value)` words `eth_getStorageAt` returns for this entry.
        let want: &[(&str, &str)] = &[
            (REG_SEED_ARRAY_SLOT, REG_SEED_LEN_VALUE),
            (REG_SEED_VEFF_SLOT, REG_SEED_VEFF_VALUE),
            (REG_SEED_HEADER_SLOT, REG_SEED_HEADER_VALUE),
            (REG_SEED_CHUNK0_SLOT, REG_SEED_CHUNK0_VALUE),
            (REG_SEED_CHUNK1_SLOT, REG_SEED_CHUNK1_VALUE),
        ];
        let got: std::collections::HashMap<String, String> = seed
            .iter()
            .map(|(s, v)| (hex::encode(s), hex::encode(v)))
            .collect();
        assert_eq!(got.len(), want.len(), "exactly the expected words");
        for (slot, value) in want {
            let slot = slot.trim_start_matches("0x");
            let value = value.trim_start_matches("0x");
            assert_eq!(
                got.get(slot).map(String::as_str),
                Some(value),
                "slot {slot} must equal the live-reth value",
            );
        }

        assert_eq!(seed.len(), 5);
        // Array length word == 1 (single genesis entry).
        let mut len_word = [0u8; 32];
        len_word[31] = 1;
        assert!(
            seed.iter().any(|(_, v)| *v == len_word),
            "array length word == 1 present",
        );
        // vEff word is all-zero at genesis (View::ZERO).
        assert!(
            seed.iter().any(|(_, v)| *v == [0u8; 32]),
            "vEff == 0 word present",
        );
        // bytes long-form header: 2*48+1 = 97 = 0x61 in the low byte.
        assert!(
            seed.iter()
                .any(|(_, v)| v[31] == 0x61 && v[..31].iter().all(|b| *b == 0)),
            "bytes long-form header (2*48+1) present",
        );
        // The two key chunks: 0x11*32, then 0x11*16 ‖ zero*16.
        let mut chunk0 = [0u8; 32];
        chunk0.fill(0x11);
        let mut chunk1 = [0u8; 32];
        chunk1[..16].fill(0x11);
        assert!(seed.iter().any(|(_, v)| *v == chunk0), "key chunk0 present");
        assert!(seed.iter().any(|(_, v)| *v == chunk1), "key chunk1 present");
    }

    /// Two genesis validators are independent: 10 words, each validator's slots
    /// distinct (different keccak buckets), and the JSON renders both.
    #[test]
    fn two_validators_are_independent() {
        let seed = genesis_seed_storage([(val(0x01), key(0xa1)), (val(0x02), key(0xa2))]);
        assert_eq!(seed.len(), 10, "5 words each, no slot collisions");
        let slots: std::collections::HashSet<_> = seed.iter().map(|(s, _)| *s).collect();
        assert_eq!(slots.len(), 10, "all ten slots distinct");

        let json = genesis_seed_storage_json([(val(0x01), key(0xa1)), (val(0x02), key(0xa2))]);
        assert_eq!(json.len(), 10);
        for (k, v) in &json {
            assert!(k.starts_with("0x") && k.len() == 66, "32-byte hex slot key");
            assert!(
                v.as_str().unwrap().starts_with("0x") && v.as_str().unwrap().len() == 66,
                "32-byte hex value",
            );
        }
    }
}
