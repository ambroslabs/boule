//! Shared decoding for boule system commands carried in EVM predeploy event
//! logs (milestone #4: #730 rotation, #731 endpoint, …).
//!
//! Each milestone-#4 submission predeploy is a pure event emitter whose event
//! carries the already-encoded, already-signed consensus command as a single
//! non-indexed dynamic `bytes` argument. boule reads it back from each
//! committed block via `eth_getLogs`, filtered by the event's topic0, and hands
//! the opaque command to consensus — which validates the tag and signatures
//! before acting on it. This module is the read half shared by every such
//! predeploy module.

use bytes::Bytes;
use serde_json::Value;

/// Parse an `eth_getLogs` result (an array of predeploy log objects) into the
/// encoded command bytes carried by each log whose `topics[0]` matches `topic`,
/// in log order.
///
/// The command argument is a non-indexed dynamic `bytes`, so it lives in the
/// log `data` ABI-encoded as `offset(32) || length(32) || bytes(padded)`. Logs
/// with a different topic or malformed data are skipped — consensus still
/// validates each returned command (tag + signatures) before acting on it, so a
/// junk log is harmless here.
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

/// Decode a single ABI-encoded dynamic `bytes` value from a hex `data` blob:
/// a 32-byte offset (expected `0x20`), a 32-byte length, then that many bytes.
/// Returns `None` if the blob is too short, the offset is unexpected, or the
/// declared length runs past the data.
fn decode_abi_bytes(data: &str) -> Option<Vec<u8>> {
    let raw = hex::decode(data.trim_start_matches("0x")).ok()?;
    // [0..32] offset, [32..64] length, then the bytes.
    if raw.len() < 64 {
        return None;
    }
    // The offset to the single dynamic argument is always 0x20 (one word).
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

/// Interpret a 32-byte ABI word as a `usize`, rejecting any value that does not
/// fit (a length/offset that large is a malformed log, not a real command).
fn word_to_usize(word: &[u8]) -> Option<usize> {
    // Only the low 8 bytes can be non-zero for a plausible length/offset.
    if word[..24].iter().any(|&b| b != 0) {
        return None;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&word[24..32]);
    usize::try_from(u64::from_be_bytes(buf)).ok()
}

#[cfg(test)]
pub(crate) mod test_support {
    /// ABI-encode a dynamic `bytes` value as the EVM lays it out in log data:
    /// offset word (`0x20`), length word, then the right-padded payload. Shared
    /// by the predeploy modules' tests.
    pub fn abi_log_bytes(payload: &[u8]) -> String {
        let mut data = Vec::new();
        let mut off = [0u8; 32];
        off[31] = 0x20;
        data.extend_from_slice(&off);
        let mut len = [0u8; 32];
        len[24..32].copy_from_slice(&(payload.len() as u64).to_be_bytes());
        data.extend_from_slice(&len);
        data.extend_from_slice(payload);
        data.extend(std::iter::repeat_n(0u8, (32 - payload.len() % 32) % 32));
        format!("0x{}", hex::encode(data))
    }

    /// A 32-byte topic word for validator id byte `b` (the indexed topic).
    pub fn topic_node(b: u8) -> String {
        format!("0x{}", format!("{b:02x}").repeat(32))
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{abi_log_bytes, topic_node};
    use super::*;
    use serde_json::json;

    const TOPIC: &str = "0xde7f9466fbeb5e013694b9e04812cc106a0a764766c202e2f88a480ee27120d1";

    #[test]
    fn parses_matching_topic_logs_in_order() {
        let a = b"first-command";
        let b = b"second-command-longer-than-thirty-two-bytes-to-cross-a-word";
        let logs = json!([
            { "topics": [TOPIC, topic_node(1)], "data": abi_log_bytes(a) },
            { "topics": [TOPIC, topic_node(2)], "data": abi_log_bytes(b) },
        ]);
        let got = parse_command_logs(&logs, TOPIC);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].as_ref(), a.as_ref());
        assert_eq!(got[1].as_ref(), b.as_ref());
    }

    #[test]
    fn skips_wrong_topic_and_malformed() {
        let other = "0xabababababababababababababababababababababababababababababababab";
        let logs = json!([
            { "topics": [other, topic_node(1)], "data": abi_log_bytes(b"x") },
            { "data": abi_log_bytes(b"x") },
            { "topics": [TOPIC, topic_node(1)], "data": "0x20" }, // too short
            "garbage",
        ]);
        assert!(parse_command_logs(&logs, TOPIC).is_empty());
        assert!(parse_command_logs(&serde_json::Value::Null, TOPIC).is_empty());
    }

    #[test]
    fn rejects_length_running_past_the_data() {
        // offset 0x20, length 0x40 (64) but only 1 byte of payload follows.
        let bad = "0x".to_string() + &"0".repeat(62) + "20" + &"0".repeat(62) + "40" + "ff";
        let logs = json!([{ "topics": [TOPIC, topic_node(1)], "data": bad }]);
        assert!(parse_command_logs(&logs, TOPIC).is_empty());
    }
}
