//! Admin-API client used by `info`, `snap`, `wait`, and the scenario
//! engine. All endpoints are GET and return JSON, so a single thin
//! wrapper is enough.
//!
//! Errors are intentionally permissive: a node that refuses connections
//! (because it's down, or hasn't bound its listener yet) returns
//! `Ok(None)` from [`maybe_consensus_status`] and [`maybe_peers`],
//! matching the "wait until everyone is healthy" pattern. Strict
//! variants ([`consensus_status`], [`peers`]) bubble up the error.

use std::net::SocketAddr;
use std::time::Duration;

use boule_consensus::status::ConsensusStatus;

/// Default per-request timeout. Short — the admin endpoints are
/// cheap and we'd rather time out and retry than block the wait loop.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .expect("reqwest::Client::build with hard-coded options")
}

/// `GET /consensus/status`. Returns `None` if the node refused the
/// connection or the call timed out (treated as "not up yet"). A 404
/// is propagated as an error because that means the node *is* up but
/// has no `[consensus]` section configured.
pub async fn maybe_consensus_status(
    api_addr: SocketAddr,
) -> anyhow::Result<Option<ConsensusStatus>> {
    let url = format!("http://{api_addr}/consensus/status");
    let resp = match client().get(&url).send().await {
        Ok(r) => r,
        Err(e) if e.is_timeout() || e.is_connect() => return Ok(None),
        Err(e) => return Err(anyhow::anyhow!("GET {url}: {e}")),
    };
    if resp.status().as_u16() == 404 {
        anyhow::bail!("{url}: 404 (no [consensus] configured on this node)");
    }
    if !resp.status().is_success() {
        anyhow::bail!("{url}: HTTP {}", resp.status());
    }
    let body: ConsensusStatus = resp.json().await?;
    Ok(Some(body))
}

/// Strict consensus-status fetch — connection refused becomes an error.
pub async fn consensus_status(api_addr: SocketAddr) -> anyhow::Result<ConsensusStatus> {
    maybe_consensus_status(api_addr)
        .await?
        .ok_or_else(|| anyhow::anyhow!("admin API at {api_addr} not reachable"))
}

/// `GET /peers`. Returns base58-encoded peer IDs, or `None` if the
/// node is unreachable.
pub async fn maybe_peers(api_addr: SocketAddr) -> anyhow::Result<Option<Vec<String>>> {
    let url = format!("http://{api_addr}/peers");
    let resp = match client().get(&url).send().await {
        Ok(r) => r,
        Err(e) if e.is_timeout() || e.is_connect() => return Ok(None),
        Err(e) => return Err(anyhow::anyhow!("GET {url}: {e}")),
    };
    if !resp.status().is_success() {
        anyhow::bail!("{url}: HTTP {}", resp.status());
    }
    let peers: Vec<String> = resp.json().await?;
    Ok(Some(peers))
}

/// Strict peers fetch.
pub async fn peers(api_addr: SocketAddr) -> anyhow::Result<Vec<String>> {
    maybe_peers(api_addr)
        .await?
        .ok_or_else(|| anyhow::anyhow!("admin API at {api_addr} not reachable"))
}
