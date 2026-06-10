pub const REGISTRY_ADDRESS: &str = "0x0000000000000000000000000000000000000b12";

pub const KEY_RECORDED_TOPIC: &str =
    "0x6a8fd2a0f1d9cf8a45c363bc1be9d77d28519827b041057dce545b44ff9680dd";

pub const KEY_AT_SELECTOR: [u8; 4] = [0x3a, 0x9e, 0x35, 0x8a];

pub const RECORD_KEY_SELECTOR: [u8; 4] = [0x82, 0x4b, 0x98, 0x02];

pub const HISTORY_LENGTH_SELECTOR: [u8; 4] = [0x43, 0x90, 0x58, 0x59];

pub const RECORD_WEIGHT_SELECTOR: [u8; 4] = [0x3a, 0x8d, 0xa0, 0xf9];

pub const WEIGHT_OF_SELECTOR: [u8; 4] = [0x4c, 0x10, 0x8d, 0x6d];

pub const TOTAL_WEIGHT_SELECTOR: [u8; 4] = [0x96, 0xc8, 0x2e, 0x57];

pub const SETTLED_VIEW_SELECTOR: [u8; 4] = [0x7a, 0x68, 0x6e, 0xf2];

pub const RECORD_SETTLED_SELECTOR: [u8; 4] = [0x09, 0x28, 0x83, 0x44];

pub const SETTLED_RECORDED_TOPIC: &str =
    "0x899ac1f88bca8ba6419098a7c22870b9f9adc8c9c05890572117effa742e5eb6";

const HISTORY_MAPPING_SLOT: u64 = 0;

const KEY_ENTRY_SLOTS: u64 = 2;

const WEIGHT_MAPPING_SLOT: u64 = 1;

const TOTAL_WEIGHT_SLOT: u64 = 2;

#[allow(dead_code)]
const SETTLED_VIEW_SLOT: u64 = 3;

pub const SETTLED_VIEW_MARGIN: u64 = boule_consensus::reconfig::MIN_V_EFF_DELAY.0;

const _: () = assert!(
    SETTLED_VIEW_MARGIN >= boule_consensus::reconfig::MIN_V_EFF_DELAY.0,
    "SETTLED_VIEW_MARGIN must be >= MIN_V_EFF_DELAY so the settled frontier never \
     outruns rotation recording (#767)",
);

use boule_consensus::View;
use boule_consensus::validator_rotation::{DualSignedRotation, OperatorSignedRotation};
use boule_core::crypto::sig_scheme::{BlsKeyError, BlsPublicKey, bls_pubkey_to_eip2537_g1};
use boule_core::identity::NodeId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordKey {
    pub validator: NodeId,

    pub v_eff: View,

    pub key128: [u8; 128],
}

pub fn record_key_for_rotation(cmd: &[u8]) -> anyhow::Result<Option<RecordKey>> {
    let payload = if DualSignedRotation::is_rotation_payload(cmd) {
        DualSignedRotation::decode_command(cmd)?.payload
    } else if OperatorSignedRotation::is_operator_rotation_payload(cmd) {
        OperatorSignedRotation::decode_command(cmd)?.payload
    } else {
        return Ok(None);
    };
    let Some(bls) = payload.new_bls_pubkey else {
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

pub fn conservative_settled_view(committed_view: View) -> View {
    View(committed_view.0.saturating_sub(SETTLED_VIEW_MARGIN))
}

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    let mut h = Keccak256::new();
    h.update(bytes);
    h.finalize().into()
}

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

type StorageEntry = ([u8; 32], [u8; 32]);

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

    if total_weight != 0 {
        let mut slot = [0u8; 32];
        slot[24..].copy_from_slice(&TOTAL_WEIGHT_SLOT.to_be_bytes());
        let mut value = [0u8; 32];
        value[24..].copy_from_slice(&total_weight.to_be_bytes());
        out.push((slot, value));
    }
    Ok(out)
}

fn weight_storage(validator: &NodeId, weight: u64) -> StorageEntry {
    let mut key_preimage = [0u8; 64];
    key_preimage[..32].copy_from_slice(validator);
    key_preimage[32 + 24..].copy_from_slice(&WEIGHT_MAPPING_SLOT.to_be_bytes());
    let slot = keccak256(&key_preimage);
    let mut value = [0u8; 32];
    value[24..].copy_from_slice(&weight.to_be_bytes());
    (slot, value)
}

fn validator_history_storage(validator: &NodeId, entries: &[(View, &[u8])]) -> Vec<StorageEntry> {
    let mut out = Vec::new();

    let mut key_preimage = [0u8; 64];
    key_preimage[..32].copy_from_slice(validator);
    key_preimage[32 + 24..].copy_from_slice(&HISTORY_MAPPING_SLOT.to_be_bytes());
    let array_slot = keccak256(&key_preimage);

    let mut len_word = [0u8; 32];
    len_word[24..].copy_from_slice(&(entries.len() as u64).to_be_bytes());
    out.push((array_slot, len_word));

    let data_base = keccak256(&array_slot);
    for (i, (v_eff, key)) in entries.iter().enumerate() {
        let elem = slot_add(&data_base, i as u64 * KEY_ENTRY_SLOTS);

        let mut v_word = [0u8; 32];
        v_word[24..].copy_from_slice(&v_eff.0.to_be_bytes());
        out.push((elem, v_word));

        let header_slot = slot_add(&elem, 1);
        let mut header = [0u8; 32];
        let coded_len = (key.len() as u128) * 2 + 1;
        header[16..].copy_from_slice(&coded_len.to_be_bytes());
        out.push((header_slot, header));

        let chunk_base = keccak256(&header_slot);
        for (j, chunk) in key.chunks(32).enumerate() {
            let mut word = [0u8; 32];
            word[..chunk.len()].copy_from_slice(chunk);
            out.push((slot_add(&chunk_base, j as u64), word));
        }
    }
    out
}

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
