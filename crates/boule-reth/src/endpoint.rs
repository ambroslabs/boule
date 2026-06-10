use bytes::Bytes;
use serde_json::{Value, json};

pub const ENDPOINT_ADDRESS: &str = "0x0000000000000000000000000000000000000b10";

pub const ENDPOINT_TOPIC: &str =
    "0x26a38d91fc47b4cd0e93f73c87346a4236d696ffe5a241f95c33fc2670d28349";

pub const SUBMIT_SELECTOR: [u8; 4] = [0x18, 0xd8, 0x84, 0x38];

pub fn logs_filter(block_hash: &str) -> Value {
    json!([{
        "blockHash": block_hash,
        "address": ENDPOINT_ADDRESS,
        "topics": [[ENDPOINT_TOPIC]],
    }])
}

pub fn logs_filter_by_number(number: u64) -> Value {
    let block = format!("0x{number:x}");
    json!([{
        "fromBlock": block,
        "toBlock": block,
        "address": ENDPOINT_ADDRESS,
        "topics": [[ENDPOINT_TOPIC]],
    }])
}

pub fn parse_endpoint_logs(logs: &Value) -> Vec<Bytes> {
    crate::predeploy_log::parse_command_logs(logs, ENDPOINT_TOPIC)
}
