//! Transport seam for the Engine API driver.
//!
//! [`EngineTransport`] abstracts a single authenticated `engine_*` call so
//! [`crate::engine::RethEngine`] can run against a live reth ([`HttpTransport`])
//! or, in tests, against the committed golden fixtures. The `tag` argument is
//! the fixture basename; the HTTP transport uses it to record each exchange.

use anyhow::{Context, Result, bail};
use boule_core::clock::BoxFuture;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::jwt;

/// One authenticated Engine API round-trip.
///
/// Object-safe via the codebase's [`BoxFuture`] convention (rather than
/// `-> impl Future`), so the driver and the application can hold a
/// `Box<dyn EngineTransport>` and swap the live HTTP transport for the
/// fixture transport without a type parameter — matching the async-trait
/// style of `boule_core`'s `Clock`/`Broadcaster`.
pub trait EngineTransport: Send + Sync {
    fn call(&self, method: &str, params: Value, tag: &str) -> BoxFuture<'_, Result<Value>>;

    /// A public `eth_*` JSON-RPC call (no JWT) — e.g. `eth_getLogs`, used to
    /// read the staking predeploy's events (#655). The default errors; only
    /// transports backed by reth's public RPC (the live [`HttpTransport`])
    /// or test fixtures override it.
    fn eth_rpc(&self, method: &str, _params: Value) -> BoxFuture<'_, Result<Value>> {
        let method = method.to_string();
        Box::pin(async move { bail!("eth_* RPC unsupported by this transport: {method}") })
    }
}

/// Live transport over reth's two ports: authenticated Engine API (`:8551`,
/// JWT) and the public `eth_*` JSON-RPC (`:8545`, no auth).
pub struct HttpTransport {
    http: reqwest::Client,
    engine_url: String,
    eth_url: String,
    secret: Vec<u8>,
    /// When set, each engine call's request+response is captured here as a
    /// golden fixture (used to (re)capture the test fixtures against a live
    /// reth). A running node leaves it `None`.
    fixtures_dir: Option<PathBuf>,
    id: AtomicU64,
}

impl HttpTransport {
    pub fn new(
        engine_url: String,
        eth_url: String,
        secret: Vec<u8>,
        fixtures_dir: Option<PathBuf>,
    ) -> Self {
        Self {
            http: reqwest::Client::new(),
            engine_url,
            eth_url,
            secret,
            fixtures_dir,
            id: AtomicU64::new(1),
        }
    }

    async fn rpc(&self, url: &str, method: &str, params: Value, jwt_auth: bool) -> Result<Value> {
        let id = self.id.fetch_add(1, Ordering::Relaxed);
        let req = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let mut rb = self.http.post(url).json(&req);
        if jwt_auth {
            rb = rb.bearer_auth(jwt::mint(&self.secret)?);
        }
        let resp: Value = rb
            .send()
            .await
            .with_context(|| format!("POST {method} -> {url}"))?
            .json()
            .await
            .with_context(|| format!("decoding {method} response"))?;
        if let Some(err) = resp.get("error") {
            bail!("{method} JSON-RPC error: {err}");
        }
        Ok(resp.get("result").cloned().unwrap_or(Value::Null))
    }

    /// Public `eth_*` call on `:8545`, no auth.
    pub async fn eth(&self, method: &str, params: Value) -> Result<Value> {
        self.rpc(&self.eth_url, method, params, false).await
    }

    /// Forward a *pre-built* JSON-RPC payload (single object or batch array)
    /// verbatim to the public eth endpoint and return reth's raw response,
    /// unmodified. Unlike [`Self::eth`] this does not rewrite the `id` or
    /// re-wrap the request, so it preserves the caller's `id` and batch shape —
    /// used by the public RPC proxy (#806) to relay client requests as-is. No
    /// JWT (public RPC).
    pub async fn eth_raw(&self, payload: Value) -> Result<Value> {
        let resp: Value = self
            .http
            .post(&self.eth_url)
            .json(&payload)
            .send()
            .await
            .with_context(|| format!("POST (raw) -> {}", self.eth_url))?
            .json()
            .await
            .context("decoding raw eth RPC response")?;
        Ok(resp)
    }
}

impl EngineTransport for HttpTransport {
    fn eth_rpc(&self, method: &str, params: Value) -> BoxFuture<'_, Result<Value>> {
        let method = method.to_string();
        Box::pin(async move { self.rpc(&self.eth_url, &method, params, false).await })
    }

    fn call(&self, method: &str, params: Value, tag: &str) -> BoxFuture<'_, Result<Value>> {
        let method = method.to_string();
        let tag = tag.to_string();
        Box::pin(async move {
            let result = self
                .rpc(&self.engine_url, &method, params.clone(), true)
                .await?;
            // Capture the exchange as a golden fixture when a dir is configured.
            if let Some(dir) = &self.fixtures_dir {
                let record = json!({ "method": method, "params": params, "result": result });
                if let Ok(bytes) = serde_json::to_vec_pretty(&record) {
                    let _ = std::fs::write(dir.join(format!("{tag}.json")), bytes);
                }
            }
            Ok(result)
        })
    }
}

/// Fetch reth's genesis block hash and state root (`eth_getBlockByNumber(0)`),
/// used to bridge the consensus genesis `state_commitment` to reth's genesis
/// state root and to anchor the first built block. No JWT (public RPC).
pub async fn fetch_genesis(eth_url: &str) -> Result<(String, [u8; 32])> {
    let transport = HttpTransport::new(String::new(), eth_url.to_string(), Vec::new(), None);
    let block = transport
        .eth("eth_getBlockByNumber", json!(["0x0", false]))
        .await
        .context("querying reth genesis block")?;
    let hash = block["hash"]
        .as_str()
        .context("genesis block hash")?
        .to_string();
    let root =
        crate::engine::root_from_hex(block["stateRoot"].as_str().context("genesis stateRoot")?)?;
    Ok((hash, root))
}

/// Connect the local reth (at `eth_url`) to each peer `enode://…` via
/// `admin_addPeer` over the public RPC. Requires reth's `admin` namespace
/// (`--http.api …,admin`).
///
/// Best-effort: a failed add is logged and skipped — reth keeps retrying the
/// dial, and the other peers may still connect. Peering the validator reths
/// enables EVM tx-pool gossip (any leader sees a tx submitted to any node) and
/// lets a behind/fresh reth self-sync (snap/full) from its peers. No JWT.
pub async fn peer_reths(eth_url: &str, enodes: &[String]) -> Result<()> {
    if enodes.is_empty() {
        return Ok(());
    }
    let transport = HttpTransport::new(String::new(), eth_url.to_string(), Vec::new(), None);
    for enode in enodes {
        match transport.eth("admin_addPeer", json!([enode])).await {
            Ok(_) => tracing::info!(target: "boule::reth", %enode, "added reth peer"),
            Err(e) => tracing::warn!(
                target: "boule::reth",
                %enode,
                error = %e,
                "admin_addPeer failed (reth `admin` RPC enabled? peer reachable?); continuing",
            ),
        }
    }
    Ok(())
}

/// Fetch reth's finalized head — its persisted forkchoice `finalized` block —
/// as `(height, state_root)`, used to recover [`crate::RethApplication`]'s
/// committed frontier on restart (reth keeps its own state DB across restarts,
/// so its finalized block is the true committed frontier). `None` when reth has
/// finalized nothing past genesis (a fresh node), in which case the caller
/// keeps the genesis-initialized frontier. No JWT (public RPC).
pub async fn fetch_finalized_head(eth_url: &str) -> Result<Option<(u64, [u8; 32])>> {
    let transport = HttpTransport::new(String::new(), eth_url.to_string(), Vec::new(), None);
    let block = transport
        .eth("eth_getBlockByNumber", json!(["finalized", false]))
        .await
        .context("querying reth finalized block")?;
    parse_finalized_head(&block)
}

/// Parse an `eth_getBlockByNumber("finalized")` result into the committed
/// frontier. A `null` result (reth has no finalized block) or a finalized block
/// still at genesis (height 0) both yield `None` — there is nothing to recover
/// past the genesis-initialized frontier.
fn parse_finalized_head(block: &Value) -> Result<Option<(u64, [u8; 32])>> {
    if block.is_null() {
        return Ok(None);
    }
    let height = u64::from_str_radix(
        block["number"]
            .as_str()
            .context("finalized block number")?
            .trim_start_matches("0x"),
        16,
    )
    .context("finalized block number not hex")?;
    if height == 0 {
        return Ok(None);
    }
    let root =
        crate::engine::root_from_hex(block["stateRoot"].as_str().context("finalized stateRoot")?)?;
    Ok(Some((height, root)))
}

#[cfg(test)]
mod tests {
    use super::{parse_finalized_head, peer_reths};
    use serde_json::json;

    #[tokio::test]
    async fn peer_reths_empty_is_a_noop() {
        assert!(peer_reths("http://127.0.0.1:1", &[]).await.is_ok());
    }

    #[tokio::test]
    async fn peer_reths_is_best_effort_when_reth_unreachable() {
        // No reth at that port → admin_addPeer fails, but peering is
        // best-effort and must not fail node startup.
        let enodes = vec!["enode://ab@127.0.0.1:30303".to_string()];
        assert!(peer_reths("http://127.0.0.1:1", &enodes).await.is_ok());
    }

    #[test]
    fn finalized_head_none_when_null_or_genesis() {
        // reth has finalized nothing → null result.
        assert_eq!(
            parse_finalized_head(&serde_json::Value::Null).unwrap(),
            None
        );
        // Finalized still at genesis (height 0) → nothing to recover.
        let genesis = json!({ "number": "0x0", "stateRoot": format!("0x{}", "11".repeat(32)) });
        assert_eq!(parse_finalized_head(&genesis).unwrap(), None);
    }

    #[test]
    fn finalized_head_parses_height_and_root() {
        let block = json!({
            "number": "0x2a",
            "stateRoot": format!("0x{}", "ab".repeat(32)),
        });
        assert_eq!(
            parse_finalized_head(&block).unwrap(),
            Some((42, [0xab; 32]))
        );
    }

    #[test]
    fn finalized_head_errors_on_malformed_number() {
        let block = json!({ "number": "not-hex", "stateRoot": format!("0x{}", "11".repeat(32)) });
        assert!(parse_finalized_head(&block).is_err());
    }
}
