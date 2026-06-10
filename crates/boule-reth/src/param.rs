use bytes::Bytes;
use serde_json::{Value, json};

pub const PARAM_ADDRESS: &str = "0x0000000000000000000000000000000000000b11";

pub const PARAM_TOPIC: &str = "0x27d1e5d546bb0a37e323040c28412ac11a38a95061bbe56c3f95d635f8826a0b";

pub const APPROVE_SELECTOR: [u8; 4] = [0x8e, 0x4a, 0x23, 0xcb];

pub const APPROVE_DIGEST_SELECTOR: [u8; 4] = [0x73, 0x87, 0x53, 0xb8];

pub const AUTH_DOMAIN: [u8; 32] = [
    0xfa, 0x56, 0x6b, 0x51, 0xe8, 0xb3, 0xf0, 0xea, 0x73, 0xbb, 0x6b, 0xd0, 0xa5, 0x60, 0x40, 0x63,
    0x46, 0x97, 0xf7, 0xad, 0x06, 0xbd, 0xed, 0xc3, 0xe6, 0x70, 0x75, 0x9f, 0xbf, 0x84, 0xc6, 0xcd,
];

pub const APPROVALS_SELECTOR: [u8; 4] = [0xbf, 0x7c, 0x21, 0x31];

pub const IS_APPROVED_SELECTOR: [u8; 4] = [0x48, 0xae, 0xfc, 0x32];

pub fn logs_filter(block_hash: &str) -> Value {
    json!([{
        "blockHash": block_hash,
        "address": PARAM_ADDRESS,
        "topics": [[PARAM_TOPIC]],
    }])
}

pub fn logs_filter_by_number(number: u64) -> Value {
    let block = format!("0x{number:x}");
    json!([{
        "fromBlock": block,
        "toBlock": block,
        "address": PARAM_ADDRESS,
        "topics": [[PARAM_TOPIC]],
    }])
}

pub fn parse_param_logs(logs: &Value) -> Vec<Bytes> {
    crate::predeploy_log::parse_command_logs(logs, PARAM_TOPIC)
}
