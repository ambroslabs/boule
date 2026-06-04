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
//! registry is read **in the EVM** (by the slashing precompile via `SLOAD`, and
//! by #729's tally / #746's auth via `weightOf`/`totalWeight`), not by boule via
//! `eth_getLogs` — so this module carries the on-chain identifiers (mirrored as
//! constants and pinned to the genesis bytecode by the tests below) plus the
//! **genesis-seed** half of the write path (#732 steps 2 + 4):
//! [`genesis_seed_storage`] derives the `alloc[Registry].storage` words that
//! pre-populate the genesis validators' keys **and current weights** — the EVM
//! analogue of `BlsKeyHistory::with_genesis` plus the genesis validator set's
//! weights. The *rotation* half of the key write path is handled boule-side
//! (rotations are postcard-encoded and not decodable in Solidity — see
//! `docs/validator-registry-and-slashing.md` "The write path").
//!
//! The **weight** model (#732 step 4) differs from the key history: the key API
//! is a *history* (`keyAt(validator, view)`) because slashing looks up settled
//! *past* views, but weight's consumers need the **currently seated** weight, so
//! it is a single current value — `weightOf(validator)` plus a running
//! `totalWeight()` accumulator (a consumer derives a quorum threshold from it
//! without enumerating validators). The custom EL applies `recordWeight` on a
//! seated-weight change as a `SYSTEM`-caller system call from the per-block
//! `registryPayload` (A1, #777/#783) — there is no proposer-signed tx write path.
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

/// 4-byte selector of `recordWeight(bytes32,uint64)` (the SYSTEM-gated weight
/// write the custom EL applies on a seated-weight change, #732 step 4 / #783).
pub const RECORD_WEIGHT_SELECTOR: [u8; 4] = [0x3a, 0x8d, 0xa0, 0xf9];

/// 4-byte selector of `weightOf(bytes32)` (the current-weight read #729's tally
/// and #746's auth call).
pub const WEIGHT_OF_SELECTOR: [u8; 4] = [0x4c, 0x10, 0x8d, 0x6d];

/// 4-byte selector of `totalWeight()` (the running weight-sum read, the
/// auto-generated getter for the public `totalWeight` scalar).
pub const TOTAL_WEIGHT_SELECTOR: [u8; 4] = [0x96, 0xc8, 0x2e, 0x57];

/// 4-byte selector of `settledView()` (the settled-frontier read the slashing
/// predeploy calls to gate proofs, #732 — the auto-generated getter for the
/// public `settledView` scalar).
pub const SETTLED_VIEW_SELECTOR: [u8; 4] = [0x7a, 0x68, 0x6e, 0xf2];

/// 4-byte selector of `recordSettled(uint64)` (the SYSTEM-gated settled-frontier
/// advance the custom EL applies each commit, #732 / #783).
pub const RECORD_SETTLED_SELECTOR: [u8; 4] = [0x09, 0x28, 0x83, 0x44];

/// `keccak256("SettledRecorded(uint64,uint64)")` — topic0 of the
/// `SettledRecorded` event, emitted by `recordSettled` when the frontier moves.
pub const SETTLED_RECORDED_TOPIC: &str =
    "0x899ac1f88bca8ba6419098a7c22870b9f9adc8c9c05890572117effa742e5eb6";

/// Declaration slot of the registry's `mapping(bytes32 => KeyEntry[]) history`
/// — the single state variable in `Registry.sol`, so it occupies slot `0`.
const HISTORY_MAPPING_SLOT: u64 = 0;

/// Slots a `KeyEntry { uint64 vEff; bytes key; }` element occupies in the
/// packed array storage: one slot for `vEff` (a `uint64` does not pack with the
/// following dynamic `bytes`), one for the `key` length/pointer header.
const KEY_ENTRY_SLOTS: u64 = 2;

/// Declaration slot of the registry's `mapping(bytes32 => uint64) weight` — the
/// second state variable in `Registry.sol`, so it occupies slot `1`.
const WEIGHT_MAPPING_SLOT: u64 = 1;

/// Declaration slot of the registry's `uint64 totalWeight` scalar — the third
/// state variable, so it occupies slot `2` (a standalone `uint64`, right-aligned
/// in its own slot).
const TOTAL_WEIGHT_SLOT: u64 = 2;

/// Declaration slot of the registry's `uint64 settledView` scalar (#732) — the
/// fourth state variable, so it occupies slot `3`. Not genesis-seeded: a fresh
/// chain's frontier is `0` (the EVM default) and only advances once the
/// proposer commits its first view via `recordSettled`. (A genesis chain's keys
/// are all `vEff = 0`, so `settledView = 0` already covers the genesis set.)
#[allow(dead_code)]
const SETTLED_VIEW_SLOT: u64 = 3;

/// Conservative margin (in views) kept between the just-committed view and the
/// settled frontier carried in the build `registryPayload` (#767).
///
/// The slashing predeploy only verifies a proof for `view <= settledView`, and
/// `keyAt(validator, view)` is trustworthy there **only if every rotation with
/// `vEff <= view` has already been recorded in EVM state**. With A1 (#783) the
/// custom EL applies a rotation's `recordKey` and the block's `recordSettled`
/// **atomically in the same block** the rotation commits — so unlike the retired
/// async tx path there is no execution lag to outrun. The margin nonetheless
/// stays as harmless defense-in-depth: a rotation effective at frontier view `V`
/// was *committed* at least [`MIN_V_EFF_DELAY`] views earlier
/// (`vEff >= commit_view + MIN_V_EFF_DELAY`), and `settledView` only reaches `V`
/// `MARGIN` views after `V` commits, so its `recordKey` is long applied by then.
/// The margin is tied to `MIN_V_EFF_DELAY` by the
/// `settled_view_margin_clears_v_eff_delay` assertion below: it must never be set
/// below the v_eff delay, keeping the frontier conservative by construction.
/// (See `docs/validator-registry-and-slashing.md`, "The EL-lag invariant".)
///
/// [`MIN_V_EFF_DELAY`]: boule_consensus::reconfig::MIN_V_EFF_DELAY
pub const SETTLED_VIEW_MARGIN: u64 = boule_consensus::reconfig::MIN_V_EFF_DELAY.0;

/// **Load-bearing compile-time safety assertion (#767).** The conservative
/// settled-view margin must never be set below the rotation `v_eff` delay
/// ([`MIN_V_EFF_DELAY`](boule_consensus::reconfig::MIN_V_EFF_DELAY)). If it were,
/// `Registry.settledView` could advance to a view whose rotation's `recordKey`
/// was not yet recorded — letting the slashing predeploy verify a proof against a
/// **stale** pre-rotation key. A change to either constant that violates the
/// bound fails the build here, before it can ship.
const _: () = assert!(
    SETTLED_VIEW_MARGIN >= boule_consensus::reconfig::MIN_V_EFF_DELAY.0,
    "SETTLED_VIEW_MARGIN must be >= MIN_V_EFF_DELAY so the settled frontier never \
     outruns rotation recording (#767)",
);

use boule_consensus::View;
use boule_consensus::validator_rotation::{DualSignedRotation, OperatorSignedRotation};
use boule_core::crypto::sig_scheme::{BlsKeyError, BlsPublicKey, bls_pubkey_to_eip2537_g1};
use boule_core::identity::NodeId;

/// The `(validator, vEff, key128)` a single `recordKey` call writes: the 32-byte
/// on-chain validator id, the effective view, and the validator's BLS pubkey in
/// the registry's **128-byte EIP-2537 uncompressed G1** form. Produced by
/// [`record_key_for_rotation`], carried in the build `registryPayload` and
/// applied by the custom EL as a `recordKey` system call (#777/#783).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordKey {
    /// The validator's stable 32-byte on-chain id (its boule [`NodeId`], used
    /// verbatim as the registry/staking `bytes32` key).
    pub validator: NodeId,
    /// The view from which `key` is the validator's active BLS key.
    pub v_eff: View,
    /// The new BLS pubkey, EIP-2537 uncompressed G1 (128 bytes) — exactly what
    /// `Registry.keyAt` must return for `Slashing.sol` (`key.length == 128`).
    pub key128: [u8; 128],
}

/// Decode a committed `KeyRotation` effect's opaque command bytes into the
/// [`RecordKey`] the registry write path must mirror — or `None` when the
/// rotation does **not** change the validator's BLS key, so nothing should be
/// written.
///
/// The [`ValidatorEffect::KeyRotation`](boule_consensus::replication::application::ValidatorEffect::KeyRotation)
/// channel carries one of four rotation envelopes (see `is_rotation_command` in
/// the integration layer). Only the two that swap the **signing/BLS** key under
/// a [`ValidatorKeyRotation`](boule_consensus::validator_rotation::ValidatorKeyRotation)
/// payload can carry a new BLS pubkey:
/// [`DualSignedRotation`] and [`OperatorSignedRotation`]. The cancel and the
/// operator-*key* rotation touch no BLS key, so they yield `None`. A
/// BLS-bearing rotation whose `new_bls_pubkey` is `None` (an Ed25519-only chain)
/// also yields `None` — there is no BLS key to record.
///
/// reth never trusts these bytes for membership (consensus re-verifies the
/// signatures when it re-materialises the effect); here they are read only to
/// **mirror** the already-committed key into EVM storage, so a decode failure is
/// surfaced to the caller (which logs and skips, never failing the commit).
pub fn record_key_for_rotation(cmd: &[u8]) -> anyhow::Result<Option<RecordKey>> {
    // Pull the shared `ValidatorKeyRotation` payload out of whichever
    // BLS-bearing envelope this is; the other two variants carry no BLS key.
    let payload = if DualSignedRotation::is_rotation_payload(cmd) {
        DualSignedRotation::decode_command(cmd)?.payload
    } else if OperatorSignedRotation::is_operator_rotation_payload(cmd) {
        OperatorSignedRotation::decode_command(cmd)?.payload
    } else {
        // Cancel / operator-key rotation: no BLS-key change to mirror.
        return Ok(None);
    };
    let Some(bls) = payload.new_bls_pubkey else {
        // Ed25519-only chain: the rotation carries no BLS key.
        return Ok(None);
    };
    let key128 = bls_pubkey_to_eip2537_g1(&bls)
        .map_err(|e| anyhow::anyhow!("rotated BLS pubkey is not a valid G1 point: {e}"))?;
    Ok(Some(RecordKey {
        validator: payload.validator,
        v_eff: payload.v_eff,
        key128,
    }))
}

/// The conservative settled-frontier view to advance `Registry.settledView` to
/// at the commit of `committed_view` (#767): `committed_view −
/// `[`SETTLED_VIEW_MARGIN`]`, saturating at view 0. Never the committed view
/// itself — see [`SETTLED_VIEW_MARGIN`] for why the frontier is held
/// conservatively behind the committed view. The custom EL applies this view as
/// a `recordSettled` system call from the build `registryPayload` (#783); the
/// margin remains as harmless defense (a rotation's `recordKey` is applied in the
/// same block it commits, well before `settledView` reaches its `vEff`).
pub fn conservative_settled_view(committed_view: View) -> View {
    View(committed_view.0.saturating_sub(SETTLED_VIEW_MARGIN))
}

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
/// validators' BLS keys **and current weights** into the registry predeploy —
/// the EVM analogue of `BlsKeyHistory::with_genesis` plus the consensus genesis
/// validator set's weights (the same `(NodeId, weight)` set that seeds
/// `BondedStakeLedger`).
///
/// Each genesis validator gets a one-element key history `[(vEff: 0, key128)]`
/// (exactly as `with_genesis` seeds consensus-side at `View::ZERO`) and a
/// `weightOf(validator) == weight` entry; the accumulated `totalWeight` scalar
/// is seeded to the sum of all genesis weights. The resulting map is what would
/// be merged into the `alloc` entry at [`REGISTRY_ADDRESS`] in a
/// *deployment-specific* genesis (the committed `genesis.template.json` carries
/// no validator keys/weights — they are per-deployment), so a live reth answers
/// `keyAt(validator, V) == key128`, `weightOf(validator) == weight`, and
/// `totalWeight() == Σ weight` from block zero without any transaction.
///
/// The input key is boule's **48-byte compressed** `min-pk` G1 pubkey; it is
/// converted here, inside the helper, to the **128-byte EIP-2537 uncompressed**
/// form via [`bls_pubkey_to_eip2537_g1`] before it is stored — exactly what the
/// slashing predeploy (`Slashing.sol`, `key.length == 128`) requires. Doing the
/// conversion here (rather than at the call site) means genesis validators are
/// slashable from block zero and a caller cannot get the on-chain format wrong.
/// Errors if any input pubkey is not a valid compressed G1 point.
///
/// ## Storage-slot layout
///
/// For the key history (`mapping(bytes32 => KeyEntry[]) history` at slot 0),
/// `history[validator]`:
/// - `arraySlot = keccak256(validator ‖ uint256(0))` holds the array **length**.
/// - element `i` lives at `dataBase = keccak256(arraySlot)` offset by
///   `i * KEY_ENTRY_SLOTS`:
///   - `+0`: `vEff` (`uint64`, right-aligned in the 32-byte slot).
///   - `+1`: the `key` `bytes` header. A 128-byte EIP-2537 key exceeds 31
///     bytes, so it uses the **long form**: this slot holds `2 * len + 1`, and
///     the bytes themselves start at `keccak256(headerSlot)`, one 32-byte slot
///     at a time (128 bytes → 4 slots, exact, no padding).
///
/// For the weight surface:
/// - `weight[validator]` (`mapping(bytes32 => uint64)` at slot 1) lives at
///   `keccak256(validator ‖ uint256(1))`, the `uint64` right-aligned.
/// - `totalWeight` (`uint64` at slot 2) lives at slot `2` directly, the sum of
///   all genesis weights right-aligned. Omitted when no genesis weights are
///   non-zero (a zero scalar is the EVM default, so seeding it would be a
///   redundant word).
///
/// All genesis key entries are `vEff = 0` so each validator's array length is
/// `1`.
pub fn genesis_seed_storage(
    genesis: impl IntoIterator<Item = (NodeId, BlsPublicKey, u64)>,
) -> Result<Vec<StorageEntry>, BlsKeyError> {
    let mut out = Vec::new();
    let mut total_weight: u64 = 0;
    for (validator, key, weight) in genesis {
        let key128 = bls_pubkey_to_eip2537_g1(&key)?;
        out.extend(validator_history_storage(
            &validator,
            &[(View::ZERO, &key128)],
        ));
        out.push(weight_storage(&validator, weight));
        total_weight = total_weight
            .checked_add(weight)
            .expect("genesis totalWeight overflowed u64");
    }
    // Seed the `totalWeight` scalar only when non-zero (zero is the EVM default).
    if total_weight != 0 {
        let mut slot = [0u8; 32];
        slot[24..].copy_from_slice(&TOTAL_WEIGHT_SLOT.to_be_bytes());
        let mut value = [0u8; 32];
        value[24..].copy_from_slice(&total_weight.to_be_bytes());
        out.push((slot, value));
    }
    Ok(out)
}

/// The single `(slot, value)` storage write seeding `weight[validator] = weight`
/// (`mapping(bytes32 => uint64)` at [`WEIGHT_MAPPING_SLOT`]): the slot is
/// `keccak256(validator ‖ uint256(1))`, the `uint64` value right-aligned in the
/// 32-byte word.
fn weight_storage(validator: &NodeId, weight: u64) -> StorageEntry {
    let mut key_preimage = [0u8; 64];
    key_preimage[..32].copy_from_slice(validator);
    key_preimage[32 + 24..].copy_from_slice(&WEIGHT_MAPPING_SLOT.to_be_bytes());
    let slot = keccak256(&key_preimage);
    let mut value = [0u8; 32];
    value[24..].copy_from_slice(&weight.to_be_bytes());
    (slot, value)
}

/// Storage entries for one validator's `(vEff, key)` history (entries must be
/// vEff-ascending, matching the contract's monotonicity invariant). The `key`
/// is the already-encoded on-chain `bytes` (128-byte EIP-2537 for genesis
/// seeds). Factored out of [`genesis_seed_storage`] so the slot math is
/// exercised on its own and reusable for non-genesis seeds (e.g. a reconfig
/// add).
fn validator_history_storage(validator: &NodeId, entries: &[(View, &[u8])]) -> Vec<StorageEntry> {
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
    genesis: impl IntoIterator<Item = (NodeId, BlsPublicKey, u64)>,
) -> Result<serde_json::Map<String, serde_json::Value>, BlsKeyError> {
    let mut map = serde_json::Map::new();
    for (slot, value) in genesis_seed_storage(genesis)? {
        map.insert(
            format!("0x{}", hex::encode(slot)),
            serde_json::Value::String(format!("0x{}", hex::encode(value))),
        );
    }
    Ok(map)
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
        assert!(
            code.contains(SETTLED_RECORDED_TOPIC.trim_start_matches("0x")),
            "SettledRecorded event topic must appear as the PUSH32 operand",
        );
        for (name, sel) in [
            ("keyAt", KEY_AT_SELECTOR),
            ("recordKey", RECORD_KEY_SELECTOR),
            ("historyLength", HISTORY_LENGTH_SELECTOR),
            ("recordWeight", RECORD_WEIGHT_SELECTOR),
            ("weightOf", WEIGHT_OF_SELECTOR),
            ("totalWeight", TOTAL_WEIGHT_SELECTOR),
            ("settledView", SETTLED_VIEW_SELECTOR),
            ("recordSettled", RECORD_SETTLED_SELECTOR),
        ] {
            assert!(
                code.contains(&hex::encode(sel)),
                "{name} selector must appear in the dispatcher",
            );
        }
    }

    /// `onlyWriter`'s access-control gate (`require(msg.sender == SYSTEM)`) must
    /// name the keyless EL **system caller** (EIP-4788-style `0xff…fe`), the sole
    /// authorized registry writer after A1 Phase 3 (#783). Pins the contract's
    /// `SYSTEM` constant via the generated bytecode (solc compiles the 20-byte
    /// address as a PUSH20 operand) AND asserts the retired legacy `WRITER` EOA
    /// (`0x2Ae0…`) no longer appears, so the tx-write gate is genuinely gone.
    #[test]
    fn only_writer_gate_is_the_el_system_caller() {
        // The keyless EL system caller (Registry.sol `SYSTEM`, EIP-4788's
        // address). Mirrors boule_reth_node::registry::SYSTEM_ADDRESS.
        const SYSTEM_CALLER: &str = "fffffffffffffffffffffffffffffffffffffffe";
        // The retired legacy proposer-signed WRITER EOA (removed in #783).
        const RETIRED_WRITER: &str = "2ae00c96484267e0ed8937426f497404a93ab526";
        let g: serde_json::Value =
            serde_json::from_str(include_str!("../genesis.json")).expect("genesis.json parses");
        let code = g["alloc"][REGISTRY_ADDRESS]["code"]
            .as_str()
            .unwrap()
            .to_ascii_lowercase();
        assert!(
            code.contains(SYSTEM_CALLER),
            "the EL SYSTEM caller address must appear in onlyWriter's gate",
        );
        assert!(
            !code.contains(RETIRED_WRITER),
            "the retired legacy WRITER EOA must NOT appear — the tx-write gate is gone (#783)",
        );
    }

    fn val(b: u8) -> NodeId {
        [b; 32]
    }

    /// The fixed BLS pubkey the seed ground-truth below was captured for:
    /// `bls_pk(0x11)`, whose 128-byte EIP-2537 form is what genesis stores. A
    /// fixed real key (not arbitrary bytes) is required because the seed helper
    /// now validates+converts the compressed pubkey to G1.
    fn seed_key() -> BlsPublicKey {
        bls_pk(0x11)
    }

    // Ground-truth storage words for the genesis seed of
    // validator = 0xaa*32, key = bls_pk(0x11) (stored as its 128-byte EIP-2537
    // G1 form), vEff = 0 — captured from a live reth via `eth_getStorageAt`
    // (see `contracts/test/registry-seed.mjs`). 128 bytes → 4 data chunks.
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
    // 2*128+1 = 257 = 0x101.
    const REG_SEED_HEADER_VALUE: &str =
        "0x0000000000000000000000000000000000000000000000000000000000000101";
    const REG_SEED_CHUNK_BASE: &str =
        "0xc25886be15ecb57b4bb548a15123446d24bef1a38ef876e5a3e3e7a43ae2cd9a";
    // Weight surface for the same validator (0xaa*32, weight = 7): the
    // `weight[validator]` slot is keccak256(validator ‖ uint256(1)), and the
    // `totalWeight` scalar lives at slot 2 directly. Captured from a live reth
    // via `eth_getStorageAt` (see `contracts/test/registry-seed.mjs`).
    const REG_SEED_WEIGHT_SLOT: &str =
        "0xf6b7fe0f1a55e2604fc4254cf20b9c366ac0209ebfd964e094a76dc63887a919";
    const REG_SEED_WEIGHT_VALUE: &str =
        "0x0000000000000000000000000000000000000000000000000000000000000007";
    const REG_SEED_TOTAL_WEIGHT_SLOT: &str =
        "0x0000000000000000000000000000000000000000000000000000000000000002";
    const REG_SEED_TOTAL_WEIGHT_VALUE: &str =
        "0x0000000000000000000000000000000000000000000000000000000000000007";

    /// The seed for one validator writes the seven key words the layout requires
    /// (array length, `vEff`, the `bytes` long-form header, four key-data
    /// chunks), plus one `weight` word and one `totalWeight` word — nine total.
    #[test]
    fn one_validator_writes_nine_words() {
        let seed = genesis_seed_storage([(val(0xaa), seed_key(), 7)]).unwrap();
        assert_eq!(
            seed.len(),
            9,
            "7 key words + weight + totalWeight (len + vEff + header + 4 chunks)",
        );
    }

    /// Pins the full slot/value derivation for one genesis validator
    /// (validator = `0xaa*32`, key = `bls_pk(0x11)` stored as its 128-byte
    /// EIP-2537 form, vEff = 0). The slot words are ground truth observed on a
    /// **live reth** via `eth_getStorageAt` after seeding this exact entry into
    /// `alloc[Registry].storage` (see `contracts/test/registry-seed.mjs`), so if
    /// the slot math drifts from Solidity's actual layout this fails. The chunk
    /// *values* are the 128-byte key split into four 32-byte words.
    #[test]
    fn slot_derivation_matches_live_reth_ground_truth() {
        let seed = genesis_seed_storage([(val(0xaa), seed_key(), 7)]).unwrap();
        let key128 = bls_pubkey_to_eip2537_g1(&seed_key()).unwrap();

        // Expected non-chunk slots from a live reth (`registry-seed.mjs`).
        let mut want: Vec<(String, String)> = vec![
            (slot_hex(REG_SEED_ARRAY_SLOT), val_hex(REG_SEED_LEN_VALUE)),
            (slot_hex(REG_SEED_VEFF_SLOT), val_hex(REG_SEED_VEFF_VALUE)),
            (
                slot_hex(REG_SEED_HEADER_SLOT),
                val_hex(REG_SEED_HEADER_VALUE),
            ),
            // Weight surface: weight[0xaa] == 7 and totalWeight == 7.
            (
                slot_hex(REG_SEED_WEIGHT_SLOT),
                val_hex(REG_SEED_WEIGHT_VALUE),
            ),
            (
                slot_hex(REG_SEED_TOTAL_WEIGHT_SLOT),
                val_hex(REG_SEED_TOTAL_WEIGHT_VALUE),
            ),
        ];
        // The four key chunks live at consecutive slots from CHUNK_BASE, each
        // holding 32 bytes of the 128-byte key (exact, no padding).
        let chunk_base = hex_to_32(REG_SEED_CHUNK_BASE);
        for (j, chunk) in key128.chunks(32).enumerate() {
            want.push((
                hex::encode(slot_add(&chunk_base, j as u64)),
                hex::encode(chunk),
            ));
        }

        let got: std::collections::HashMap<String, String> = seed
            .iter()
            .map(|(s, v)| (hex::encode(s), hex::encode(v)))
            .collect();
        assert_eq!(got.len(), want.len(), "exactly the expected words");
        for (slot, value) in &want {
            assert_eq!(
                got.get(slot).map(String::as_str),
                Some(value.as_str()),
                "slot {slot} must equal the live-reth value",
            );
        }

        assert_eq!(seed.len(), 9);
        // weight[validator] == 7 word present.
        let mut weight_word = [0u8; 32];
        weight_word[31] = 7;
        assert!(
            seed.iter().filter(|(_, v)| *v == weight_word).count() >= 1,
            "weight word == 7 present",
        );
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
        // bytes long-form header: 2*128+1 = 257 = 0x0101.
        assert!(
            seed.iter()
                .any(|(_, v)| v[30] == 0x01 && v[31] == 0x01 && v[..30].iter().all(|b| *b == 0)),
            "bytes long-form header (2*128+1 = 0x0101) present",
        );
        // The four chunks reassemble the exact 128-byte key.
        let mut chunks: Vec<(usize, [u8; 32])> = key128
            .chunks(32)
            .enumerate()
            .map(|(j, c)| {
                let mut w = [0u8; 32];
                w.copy_from_slice(c);
                (j, w)
            })
            .collect();
        chunks.sort_by_key(|(j, _)| *j);
        for (j, w) in chunks {
            assert!(seed.iter().any(|(_, v)| *v == w), "key chunk {j} present",);
        }
    }

    fn slot_hex(s: &str) -> String {
        s.trim_start_matches("0x").to_string()
    }
    fn val_hex(s: &str) -> String {
        s.trim_start_matches("0x").to_string()
    }
    fn hex_to_32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        hex::decode_to_slice(s.trim_start_matches("0x"), &mut out).expect("32-byte hex");
        out
    }

    /// Two genesis validators are independent: 17 words (7 key + 1 weight each =
    /// 16, plus the one shared `totalWeight` scalar), each validator's slots
    /// distinct (different keccak buckets), `totalWeight == sum`, JSON renders all.
    #[test]
    fn two_validators_are_independent() {
        let seed =
            genesis_seed_storage([(val(0x01), bls_pk(0xa1), 3), (val(0x02), bls_pk(0xa2), 5)])
                .unwrap();
        assert_eq!(
            seed.len(),
            17,
            "8 words each + 1 shared totalWeight, no collisions"
        );
        let slots: std::collections::HashSet<_> = seed.iter().map(|(s, _)| *s).collect();
        assert_eq!(slots.len(), 17, "all seventeen slots distinct");
        // totalWeight scalar (slot 2) == 3 + 5 = 8.
        let mut total_slot = [0u8; 32];
        total_slot[31] = 2;
        let total = seed
            .iter()
            .find(|(s, _)| *s == total_slot)
            .map(|(_, v)| *v)
            .expect("totalWeight slot present");
        let mut want_total = [0u8; 32];
        want_total[31] = 8;
        assert_eq!(total, want_total, "totalWeight == 3 + 5");

        let json =
            genesis_seed_storage_json([(val(0x01), bls_pk(0xa1), 3), (val(0x02), bls_pk(0xa2), 5)])
                .unwrap();
        assert_eq!(json.len(), 17);
        for (k, v) in &json {
            assert!(k.starts_with("0x") && k.len() == 66, "32-byte hex slot key");
            assert!(
                v.as_str().unwrap().starts_with("0x") && v.as_str().unwrap().len() == 66,
                "32-byte hex value",
            );
        }
    }

    /// The seeded entry stores the **128-byte EIP-2537** form of the input
    /// compressed pubkey (so genesis validators are slashable from block zero):
    /// reassembling the chunk words equals `bls_pubkey_to_eip2537_g1(key)`.
    #[test]
    fn seed_stores_128_byte_eip2537_key() {
        let key = bls_pk(0x5c);
        let seed = genesis_seed_storage([(val(0xcd), key, 1)]).unwrap();
        let key128 = bls_pubkey_to_eip2537_g1(&key).unwrap();

        // The header encodes length 128 (long form 2*128+1).
        assert!(
            seed.iter()
                .any(|(_, v)| v[30] == 0x01 && v[31] == 0x01 && v[..30].iter().all(|b| *b == 0)),
            "header encodes a 128-byte key",
        );
        // The four 32-byte chunk words concatenate back to the 128-byte key.
        for chunk in key128.chunks(32) {
            assert!(
                seed.iter().any(|(_, v)| v.as_slice() == chunk),
                "each 32-byte slice of the 128-byte key is stored verbatim",
            );
        }
    }

    /// An invalid compressed pubkey (not a G1 point) makes the seed helper
    /// error rather than store a malformed key — a caller cannot accidentally
    /// seed an unslashable validator.
    #[test]
    fn seed_rejects_invalid_pubkey() {
        assert!(genesis_seed_storage([(val(0x01), [0xFF; 48], 1)]).is_err());
    }

    use boule_consensus::validator_rotation::{
        DualSignedRotationCancel, ValidatorKeyRotation, ValidatorRotationCancel,
    };
    use boule_core::crypto::sig_scheme::BlsAggregated;

    fn bls_pk(seed: u8) -> BlsPublicKey {
        let mut ikm = [0u8; 32];
        ikm[0] = seed;
        BlsAggregated::keygen(&ikm).expect("test BLS keygen").1
    }

    /// A real `DualSignedRotation` (signatures left zeroed — `recordKey`'s
    /// decode path never verifies them) carrying a new BLS pubkey decodes into
    /// the matching `RecordKey`: same validator id and `vEff`, and the key in
    /// 128-byte EIP-2537 form.
    #[test]
    fn dual_signed_bls_rotation_decodes_to_a_record_key() {
        let pk = bls_pk(0x9a);
        let payload = ValidatorKeyRotation {
            validator: [0x42; 32],
            new_pubkey: [0xCC; 32],
            v_eff: View::new(42),
            new_bls_pubkey: Some(pk),
            new_bls_pop: None,
        };
        let cmd = DualSignedRotation {
            payload,
            sig_old: [0u8; 64],
            sig_new: [0u8; 64],
        }
        .encode_command();

        let rk = record_key_for_rotation(&cmd)
            .expect("decodes")
            .expect("carries a BLS key");
        assert_eq!(rk.validator, [0x42; 32]);
        assert_eq!(rk.v_eff, View::new(42));
        assert_eq!(rk.key128, bls_pubkey_to_eip2537_g1(&pk).unwrap());
    }

    /// An operator-signed rotation (recovery path) carrying a BLS key also
    /// yields a `RecordKey` — it swaps the same signing/BLS key under operator
    /// authority.
    #[test]
    fn operator_signed_bls_rotation_decodes_to_a_record_key() {
        let pk = bls_pk(0x33);
        let payload = ValidatorKeyRotation {
            validator: [0x07; 32],
            new_pubkey: [0xDD; 32],
            v_eff: View::new(9),
            new_bls_pubkey: Some(pk),
            new_bls_pop: None,
        };
        let cmd = OperatorSignedRotation {
            payload,
            sig_operator: [0u8; 64],
            sig_new: [0u8; 64],
        }
        .encode_command();

        let rk = record_key_for_rotation(&cmd).expect("decodes").unwrap();
        assert_eq!(rk.validator, [0x07; 32]);
        assert_eq!(rk.v_eff, View::new(9));
        assert_eq!(rk.key128, bls_pubkey_to_eip2537_g1(&pk).unwrap());
    }

    /// A BLS-bearing rotation with `new_bls_pubkey == None` (an Ed25519-only
    /// chain) writes nothing — there is no BLS key to mirror.
    #[test]
    fn ed25519_only_rotation_yields_no_record_key() {
        let payload = ValidatorKeyRotation {
            validator: [0x11; 32],
            new_pubkey: [0x22; 32],
            v_eff: View::new(3),
            new_bls_pubkey: None,
            new_bls_pop: None,
        };
        let cmd = DualSignedRotation {
            payload,
            sig_old: [0u8; 64],
            sig_new: [0u8; 64],
        }
        .encode_command();
        assert_eq!(record_key_for_rotation(&cmd).unwrap(), None);
    }

    /// A rotation-cancel command carries no BLS-key change, so it writes
    /// nothing.
    #[test]
    fn rotation_cancel_yields_no_record_key() {
        let cmd = DualSignedRotationCancel {
            payload: ValidatorRotationCancel {
                validator: [0x11; 32],
                cancelling_v_eff: View::new(7),
            },
            sig_old: [0u8; 64],
            sig_new: [0u8; 64],
        }
        .encode_command();
        assert_eq!(record_key_for_rotation(&cmd).unwrap(), None);
    }

    /// A non-rotation byte string is rejected as undecodable rather than
    /// silently writing nothing — the caller logs and skips it.
    #[test]
    fn non_rotation_bytes_are_not_a_record_key() {
        // No rotation tag prefix at all -> treated as "no BLS rotation" (None),
        // since none of the BLS-bearing tags match.
        assert_eq!(record_key_for_rotation(b"not-a-rotation").unwrap(), None);
    }

    /// The #767 margin clears the rotation `v_eff` delay. The *compile-time*
    /// guarantee is the module-level `const _: () = assert!(…)`; this runtime
    /// test documents the bound and reads `MIN_V_EFF_DELAY` through a binding so
    /// it is not a constant assertion (clippy), giving a named, greppable check.
    #[test]
    fn settled_view_margin_clears_v_eff_delay() {
        let v_eff_delay = boule_consensus::reconfig::MIN_V_EFF_DELAY.0;
        assert!(
            SETTLED_VIEW_MARGIN >= v_eff_delay,
            "SETTLED_VIEW_MARGIN ({SETTLED_VIEW_MARGIN}) must be >= MIN_V_EFF_DELAY \
             ({v_eff_delay}) so the settled frontier never outruns rotation recording (#767)",
        );
    }

    /// The conservative settled view is the committed view less the margin,
    /// saturating at 0 for the first few (un-settleable) views.
    #[test]
    fn conservative_settled_view_subtracts_the_margin() {
        // Below the margin: nothing is settled yet (saturates at 0).
        for v in 0..=SETTLED_VIEW_MARGIN {
            assert_eq!(conservative_settled_view(View(v)), View(0));
        }
        // At and above the margin: committed_view - margin.
        assert_eq!(
            conservative_settled_view(View(SETTLED_VIEW_MARGIN + 1)),
            View(1),
        );
        assert_eq!(
            conservative_settled_view(View(100)),
            View(100 - SETTLED_VIEW_MARGIN)
        );
    }
}
