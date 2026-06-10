use bytes::Bytes;
use serde_json::Value;

pub fn parse_command_logs(logs: &Value, topic: &str) -> Vec<Bytes> {
    let Some(arr) = logs.as_array() else {
        return Vec::new();
    };
    let want = topic.to_ascii_lowercase();
    let mut out = Vec::with_capacity(arr.len());
    for log in arr {
        let Some(topics) = log["topics"].as_array() else {
            continue;
        };
        if topics
            .first()
            .and_then(|t| t.as_str())
            .map(str::to_ascii_lowercase)
            != Some(want.clone())
        {
            continue;
        }
        if let Some(cmd) = decode_abi_bytes(log["data"].as_str().unwrap_or_default()) {
            out.push(Bytes::from(cmd));
        }
    }
    out
}

fn decode_abi_bytes(data: &str) -> Option<Vec<u8>> {
    let raw = hex::decode(data.trim_start_matches("0x")).ok()?;

    if raw.len() < 64 {
        return None;
    }

    if word_to_usize(&raw[0..32])? != 32 {
        return None;
    }
    let len = word_to_usize(&raw[32..64])?;
    let start: usize = 64;
    let end = start.checked_add(len)?;
    if end > raw.len() {
        return None;
    }
    Some(raw[start..end].to_vec())
}

fn word_to_usize(word: &[u8]) -> Option<usize> {
    if word[..24].iter().any(|&b| b != 0) {
        return None;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&word[24..32]);
    usize::try_from(u64::from_be_bytes(buf)).ok()
}
