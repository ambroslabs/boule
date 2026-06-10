use bytes::Bytes;
use serde_json::{Value, json};

pub const GOVERNANCE_ADDRESS: &str = "0x0000000000000000000000000000000000000b14";

pub const APPROVED_TOPIC: &str =
    "0xd686e9e9eda221dfab37aa6cae405e85e661ed8e45cbe791790ed38093d85b75";

pub const APPROVE_SELECTOR: [u8; 4] = [0x8e, 0x4a, 0x23, 0xcb];

pub const APPROVE_DIGEST_SELECTOR: [u8; 4] = [0x73, 0x87, 0x53, 0xb8];

pub const AUTH_DOMAIN: [u8; 32] = [
    0x1c, 0x22, 0x99, 0xbe, 0x36, 0x1b, 0x40, 0xa5, 0x31, 0x53, 0x98, 0x8f, 0x6f, 0x3d, 0xb6, 0x5c,
    0xee, 0x90, 0x2f, 0x43, 0xa7, 0xd6, 0x4d, 0x94, 0x8a, 0xbe, 0x0a, 0x4e, 0xaa, 0x15, 0x6f, 0xe9,
];

pub const APPROVALS_SELECTOR: [u8; 4] = [0xbf, 0x7c, 0x21, 0x31];

pub const IS_APPROVED_SELECTOR: [u8; 4] = [0x48, 0xae, 0xfc, 0x32];

pub fn logs_filter(block_hash: &str) -> Value {
    json!([{
        "blockHash": block_hash,
        "address": GOVERNANCE_ADDRESS,
        "topics": [[APPROVED_TOPIC]],
    }])
}

pub fn logs_filter_by_number(number: u64) -> Value {
    let block = format!("0x{number:x}");
    json!([{
        "fromBlock": block,
        "toBlock": block,
        "address": GOVERNANCE_ADDRESS,
        "topics": [[APPROVED_TOPIC]],
    }])
}

pub fn parse_approved_logs(logs: &Value) -> Vec<Bytes> {
    crate::predeploy_log::parse_command_logs(logs, APPROVED_TOPIC)
}
