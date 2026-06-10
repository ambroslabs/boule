use std::net::SocketAddr;
use std::time::Duration;

use boule_consensus::status::ConsensusStatus;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .expect("reqwest::Client::build with hard-coded options")
}

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

pub async fn consensus_status(api_addr: SocketAddr) -> anyhow::Result<ConsensusStatus> {
    maybe_consensus_status(api_addr)
        .await?
        .ok_or_else(|| anyhow::anyhow!("admin API at {api_addr} not reachable"))
}

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

pub async fn peers(api_addr: SocketAddr) -> anyhow::Result<Vec<String>> {
    maybe_peers(api_addr)
        .await?
        .ok_or_else(|| anyhow::anyhow!("admin API at {api_addr} not reachable"))
}
