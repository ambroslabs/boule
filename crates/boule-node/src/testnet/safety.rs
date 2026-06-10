use std::collections::BTreeMap;
use std::path::Path;

use super::workdir::State;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitRecord {
    pub height: u64,
    pub view: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub height: u64,

    pub views_by_node: BTreeMap<String, u64>,
}

pub fn parse_commit_line(line: &str) -> Option<CommitRecord> {
    if !line.contains("committed block") {
        return None;
    }
    let height = scan_kv(line, "height=")?;
    let view = scan_kv(line, "view=")?;
    Some(CommitRecord { height, view })
}

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

pub fn verify(state: &State) -> anyhow::Result<Vec<Violation>> {
    let per_node = collect_records(state)?;

    let mut per_node_first: BTreeMap<String, BTreeMap<u64, u64>> = BTreeMap::new();
    for (name, records) in &per_node {
        let entry = per_node_first.entry(name.clone()).or_default();
        for r in records {
            entry.entry(r.height).or_insert(r.view);
        }
    }

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
