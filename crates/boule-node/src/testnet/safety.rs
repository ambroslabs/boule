//! `testnet verify-safety`: extract every `(height, view)` pair from
//! every node's log and confirm that no two nodes ever committed
//! different views at the same height. Mirrors the shell-based verifier,
//! but immune to ANSI escape codes (the regex
//! matches the `height=N view=N` substring even when surrounded by
//! tracing color codes).

use std::collections::BTreeMap;
use std::path::Path;

use super::workdir::State;

/// One commit-log row distilled from the tracing output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitRecord {
    pub height: u64,
    pub view: u64,
}

/// Cross-node violation discovered by `verify-safety`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub height: u64,
    /// `node_name -> view at that height`. Two distinct view values
    /// are sufficient to declare a safety violation.
    pub views_by_node: BTreeMap<String, u64>,
}

/// Parse one line for `committed block` records and return the
/// embedded `(height, view)` pair if both are present.
pub fn parse_commit_line(line: &str) -> Option<CommitRecord> {
    if !line.contains("committed block") {
        return None;
    }
    let height = scan_kv(line, "height=")?;
    let view = scan_kv(line, "view=")?;
    Some(CommitRecord { height, view })
}

/// Find the first occurrence of `key` (e.g. `"height="`), then read
/// digits until a non-digit appears. Tolerant of surrounding ANSI
/// escapes because we never look back across the key match.
fn scan_kv(line: &str, key: &str) -> Option<u64> {
    let idx = line.find(key)?;
    let rest = &line[idx + key.len()..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    rest[..end].parse().ok()
}

/// Read every per-node log under the workdir and collect each node's
/// commit records. Missing logs are silently skipped (a node that has
/// never been started has nothing to violate).
pub fn collect_records(state: &State) -> anyhow::Result<BTreeMap<String, Vec<CommitRecord>>> {
    let mut out = BTreeMap::new();
    for n in &state.nodes {
        let records = read_log(&n.log_path)?;
        out.insert(n.display_name(), records);
    }
    Ok(out)
}

fn read_log(path: &Path) -> anyhow::Result<Vec<CommitRecord>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = std::fs::read(path)?;
    let text = String::from_utf8_lossy(&bytes);
    Ok(text.lines().filter_map(parse_commit_line).collect())
}

/// Run the full safety check. Returns the set of detected violations;
/// an empty vec means the cluster is consistent.
pub fn verify(state: &State) -> anyhow::Result<Vec<Violation>> {
    let per_node = collect_records(state)?;
    // Per node, take the first observed (height -> view) — committing
    // the same height twice with the same view is impossible by
    // design, so duplicates just confirm one another.
    let mut per_node_first: BTreeMap<String, BTreeMap<u64, u64>> = BTreeMap::new();
    for (name, records) in &per_node {
        let entry = per_node_first.entry(name.clone()).or_default();
        for r in records {
            entry.entry(r.height).or_insert(r.view);
        }
    }

    // Now look up each height across every node and flag mismatches.
    let mut all_heights: Vec<u64> = per_node_first
        .values()
        .flat_map(|m| m.keys().copied())
        .collect();
    all_heights.sort_unstable();
    all_heights.dedup();

    let mut violations = Vec::new();
    for h in all_heights {
        let mut seen: BTreeMap<String, u64> = BTreeMap::new();
        for (name, m) in &per_node_first {
            if let Some(&v) = m.get(&h) {
                seen.insert(name.clone(), v);
            }
        }
        let mut distinct: Vec<u64> = seen.values().copied().collect();
        distinct.sort_unstable();
        distinct.dedup();
        if distinct.len() > 1 {
            violations.push(Violation {
                height: h,
                views_by_node: seen,
            });
        }
    }
    Ok(violations)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_height_and_view_from_committed_block_line() {
        let line = "2026-04-26T10:00:00Z INFO boule_core::consensus::node: consensus: committed block height=12 view=14";
        let r = parse_commit_line(line).unwrap();
        assert_eq!(r.height, 12);
        assert_eq!(r.view, 14);
    }

    #[test]
    fn parse_handles_ansi_escape_codes_in_log() {
        // Simulate ANSI escape sequences from `tracing-subscriber`'s
        // pretty formatter wrapping the field values.
        let line = "\u{1b}[2mINFO\u{1b}[0m committed block \u{1b}[34mheight=42\u{1b}[0m view=43";
        let r = parse_commit_line(line).unwrap();
        assert_eq!(r.height, 42);
        assert_eq!(r.view, 43);
    }

    #[test]
    fn parse_skips_unrelated_lines() {
        assert!(parse_commit_line("INFO p2p: connecting to peer").is_none());
        assert!(parse_commit_line("committed block height=").is_none());
    }
}
