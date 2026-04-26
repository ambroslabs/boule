//! `testnet telemetry`: scrape interesting counters out of every
//! node's log. Same anti-pattern as the §9b shell script (grep against
//! tracing output), but immune to ANSI escapes because we count
//! occurrences of the *event-name* substring rather than parse with
//! `grep -oE`.
//!
//! The set of counters is intentionally small and curated. Operators
//! who need richer data should subscribe to the `tracing` JSON output
//! rather than scrape the log post-hoc.

use std::collections::BTreeMap;

use super::workdir::State;

/// Counters tallied per node. Keys are stable — the CLI relies on
/// them to render a tabular report.
pub const COUNTERS: &[&str] = &[
    "consensus_resumed",
    "block_sync_request_emitted",
    "block_sync_response_received",
    "block_sync_request_received",
    "proposal_rejected_unknown_parent",
    "gossip_send_to_dispatched",
];

pub type NodeCounters = BTreeMap<String, usize>;

/// Build a per-node counter table by scanning each log file for the
/// counter names.
pub fn collect(state: &State) -> anyhow::Result<BTreeMap<String, NodeCounters>> {
    let mut out: BTreeMap<String, NodeCounters> = BTreeMap::new();
    for n in &state.nodes {
        let mut counters: NodeCounters = COUNTERS.iter().map(|c| ((*c).to_string(), 0)).collect();
        if n.log_path.exists() {
            let bytes = std::fs::read(&n.log_path)?;
            let text = String::from_utf8_lossy(&bytes);
            for line in text.lines() {
                for c in COUNTERS {
                    if line.contains(c) {
                        *counters.get_mut(*c).unwrap() += 1;
                    }
                }
            }
        }
        out.insert(n.display_name(), counters);
    }
    Ok(out)
}
