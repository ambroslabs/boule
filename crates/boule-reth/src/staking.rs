use serde_json::{Value, json};

use boule_consensus::replication::stake_source::StakeOp;
use boule_core::identity::NodeId;

use crate::engine::root_from_hex;

pub const STAKING_ADDRESS: &str = "0x0000000000000000000000000000000000000b0e";

pub const OWNER_SLOT: u64 = 0;

pub fn owner_seed_storage_json(owner: &str) -> Result<(String, String), String> {
    let bytes = hex::decode(owner.trim_start_matches("0x").trim_start_matches("0X"))
        .map_err(|e| format!("staking owner {owner:?}: bad address hex: {e}"))?;
    if bytes.len() != 20 {
        return Err(format!(
            "staking owner {owner:?}: address must be 20 bytes (40 hex chars), got {}",
            bytes.len()
        ));
    }
    let mut slot = [0u8; 32];
    slot[24..].copy_from_slice(&OWNER_SLOT.to_be_bytes());
    let mut value = [0u8; 32];
    value[12..].copy_from_slice(&bytes);
    Ok((
        format!("0x{}", hex::encode(slot)),
        format!("0x{}", hex::encode(value)),
    ))
}

pub const DEPOSIT_TOPIC: &str =
    "0x98e783c3864bbf744a057ef605a2a61701c3b62b5ed68b3745b99094497daf1f";

pub const WITHDRAW_TOPIC: &str =
    "0x4591ca0897d0d8e83f7153dfe0b2912125672084ab8d84be59ee13240a1778bc";

pub const DEPOSIT_SELECTOR: [u8; 4] = [0xb2, 0x14, 0xfa, 0xa5];

pub const WITHDRAW_SELECTOR: [u8; 4] = [0x04, 0x0c, 0xf0, 0x20];

pub fn logs_filter(block_hash: &str) -> Value {
    json!([{
        "blockHash": block_hash,
        "address": STAKING_ADDRESS,
        "topics": [[DEPOSIT_TOPIC, WITHDRAW_TOPIC]],
    }])
}

pub fn logs_filter_by_number(number: u64) -> Value {
    let block = format!("0x{number:x}");
    json!([{
        "fromBlock": block,
        "toBlock": block,
        "address": STAKING_ADDRESS,
        "topics": [[DEPOSIT_TOPIC, WITHDRAW_TOPIC]],
    }])
}

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

fn data_word_to_u64(data: &str) -> u64 {
    let h = data.trim_start_matches("0x");
    if h.len() <= 16 {
        return u64::from_str_radix(h, 16).unwrap_or(0);
    }
    let (high, low) = h.split_at(h.len() - 16);
    if high.bytes().any(|b| b != b'0') {
        return u64::MAX;
    }
    u64::from_str_radix(low, 16).unwrap_or(0)
}
