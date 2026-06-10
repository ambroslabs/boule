use std::collections::BTreeMap;

use super::workdir::State;

pub const COUNTERS: &[&str] = &[
    "consensus_resumed",
    "block_sync_request_emitted",
    "block_sync_response_received",
    "block_sync_request_received",
    "proposal_rejected_unknown_parent",
    "gossip_send_to_dispatched",
];

pub type NodeCounters = BTreeMap<String, usize>;

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
