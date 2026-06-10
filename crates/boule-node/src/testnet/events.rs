use std::io::Write as _;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::workdir::EVENTS_FILE;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub at: DateTime<Utc>,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub node: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub detail: Option<String>,
}

pub fn record(workdir: &Path, kind: &str, node: Option<&str>, detail: Option<&str>) {
    let path = workdir.join(EVENTS_FILE);
    let evt = Event {
        at: Utc::now(),
        kind: kind.to_string(),
        node: node.map(str::to_string),
        detail: detail.map(str::to_string),
    };
    let line = match serde_json::to_string(&evt) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("testnet: serializing event failed: {e}");
            return;
        }
    };
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(mut f) => {
            if let Err(e) = writeln!(f, "{line}") {
                tracing::warn!("testnet: writing events log {}: {e}", path.display());
            }
        }
        Err(e) => {
            tracing::warn!("testnet: opening events log {}: {e}", path.display());
        }
    }
}
