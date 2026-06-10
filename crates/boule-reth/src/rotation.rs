use bytes::Bytes;
use serde_json::{Value, json};

pub const ROTATION_ADDRESS: &str = "0x0000000000000000000000000000000000000b0f";

pub const ROTATION_TOPIC: &str =
    "0xde7f9466fbeb5e013694b9e04812cc106a0a764766c202e2f88a480ee27120d1";

pub const SUBMIT_SELECTOR: [u8; 4] = [0x37, 0xfe, 0x3f, 0x23];

pub fn logs_filter(block_hash: &str) -> Value {
    json!([{
        "blockHash": block_hash,
        "address": ROTATION_ADDRESS,
        "topics": [[ROTATION_TOPIC]],
    }])
}

pub fn logs_filter_by_number(number: u64) -> Value {
    let block = format!("0x{number:x}");
    json!([{
        "fromBlock": block,
        "toBlock": block,
        "address": ROTATION_ADDRESS,
        "topics": [[ROTATION_TOPIC]],
    }])
}

pub fn parse_rotation_logs(logs: &Value) -> Vec<Bytes> {
    crate::predeploy_log::parse_command_logs(logs, ROTATION_TOPIC)
}
