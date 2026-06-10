use serde_json::{Value, json};

use boule_core::identity::NodeId;

use crate::engine::root_from_hex;

pub const SLASHING_ADDRESS: &str = "0x0000000000000000000000000000000000000b13";

pub const SLASHED_TOPIC: &str =
    "0xaa027002e2293d2bdf5dfdb36085da833212945f22a1bc33658aab00be192988";

pub const SUBMIT_EQUIVOCATION_SELECTOR: [u8; 4] = [0xa3, 0x9f, 0xe9, 0xc0];

pub const SETTLED_VIEW_SELECTOR: [u8; 4] = [0x7a, 0x68, 0x6e, 0xf2];

pub fn logs_filter(block_hash: &str) -> Value {
    json!([{
        "blockHash": block_hash,
        "address": SLASHING_ADDRESS,
        "topics": [SLASHED_TOPIC],
    }])
}

pub fn logs_filter_by_number(number: u64) -> Value {
    let block = format!("0x{number:x}");
    json!([{
        "fromBlock": block,
        "toBlock": block,
        "address": SLASHING_ADDRESS,
        "topics": [SLASHED_TOPIC],
    }])
}

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

        if let Ok(node_id) = root_from_hex(topics[1].as_str().unwrap_or_default()) {
            out.push(node_id);
        }
    }
    out
}
