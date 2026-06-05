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
use std::time::Duration;

use crate::jwt;

/// Engine-API / eth-RPC retry policy for the consensus↔EL hop (#803).
///
/// The boule node and its reth run as two processes; the hop between them is a
/// loopback (or LAN, for a remote EL) HTTP call that can fail *transiently* —
/// reth still warming up at boot, a momentary connection reset, a brief 5xx, a
/// truncated body. Without a retry the caller treats every such blip as a hard
/// error: a `newPayload`/`forkchoiceUpdated` blip stalls block production, and a
/// failed `eth_getLogs` (staking/slashing/governance) silently drops that
/// block's validator-set deltas — which on a *subset* of nodes is a registry
/// divergence (a safety split). So both the authenticated `engine_*` calls and
/// the public `eth_*` calls retry transient failures with bounded exponential
/// backoff.
///
/// What is **not** retried: a JSON-RPC *application* error (`resp.error`, e.g.
/// `newPayload` returning `INVALID`, or a bad-params error) is a definitive
/// answer from a healthy EL, not a transient transport blip — retrying it would
/// only waste time and mask a real protocol bug. Only the transport-level
/// failures above (send error, body-decode error, non-2xx status) are retried.
#[derive(Clone, Copy, Debug)]
pub struct RetryPolicy {
    /// Total attempts (1 = no retry). Bounded so a genuinely-down EL surfaces an
    /// error to the caller's own alert/timeout path rather than spinning here.
    pub max_attempts: u32,
    /// Backoff before the first retry; doubles each attempt (capped at `max`).
    pub base: Duration,
    /// Backoff ceiling.
    pub max: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        // ~50ms, 100, 200, 400, 800 → 5 attempts, ≈1.5s total worst case: long
        // enough to ride out a reth restart blip / GC pause, short enough that a
        // truly-down EL surfaces fast.
        Self {
            max_attempts: 5,
            base: Duration::from_millis(50),
            max: Duration::from_millis(800),
        }
    }
}

impl RetryPolicy {
    /// A no-retry policy (single attempt) — for the one-shot helper transports
    /// (`fetch_genesis`, `peer_reths`, …) where a retry loop adds nothing.
    pub fn none() -> Self {
        Self {
            max_attempts: 1,
            base: Duration::from_millis(0),
            max: Duration::from_millis(0),
        }
    }

    /// Backoff before the retry that follows `attempt` (0-based): `base · 2^attempt`,
    /// capped at `max`.
    fn backoff(&self, attempt: u32) -> Duration {
        let factor = 1u64.checked_shl(attempt).unwrap_or(u64::MAX);
        let millis = (self.base.as_millis() as u64).saturating_mul(factor);
        Duration::from_millis(millis.min(self.max.as_millis() as u64))
    }
}

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
    /// Retry/backoff for transient transport failures on the consensus↔EL hop
    /// (#803). See [`RetryPolicy`].
    retry: RetryPolicy,
}

/// One round-trip's outcome, classified for the retry loop: a [`Transport`]
/// failure (send error / non-2xx / decode error) is retried; an [`Application`]
/// error (JSON-RPC `error`, or a JWT mint failure) is a definitive answer and
/// is returned immediately.
///
/// [`Transport`]: RpcError::Transport
/// [`Application`]: RpcError::Application
enum RpcError {
    Transport(anyhow::Error),
    Application(anyhow::Error),
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
            retry: RetryPolicy::default(),
        }
    }

    /// Override the retry policy (e.g. [`RetryPolicy::none`] for one-shot helper
    /// transports, or a longer policy for a flaky remote EL).
    pub fn with_retry(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    async fn rpc(&self, url: &str, method: &str, params: Value, jwt_auth: bool) -> Result<Value> {
        let mut attempt = 0u32;
        loop {
            match self.rpc_once(url, method, params.clone(), jwt_auth).await {
                Ok(v) => return Ok(v),
                // A JSON-RPC application error is a definitive answer from a
                // healthy EL — never retried (see `RetryPolicy`).
                Err(RpcError::Application(e)) => return Err(e),
                // A transport blip — retry with backoff until the budget is spent.
                Err(RpcError::Transport(e)) => {
                    attempt += 1;
                    if attempt >= self.retry.max_attempts {
                        return Err(e.context(format!(
                            "{method} -> {url} failed after {attempt} attempt(s)"
                        )));
                    }
                    let wait = self.retry.backoff(attempt - 1);
                    tracing::warn!(
                        target: "boule::reth",
                        method,
                        url,
                        attempt,
                        max_attempts = self.retry.max_attempts,
                        backoff_ms = wait.as_millis() as u64,
                        error = %e,
                        "EL RPC transport error; retrying after backoff",
                    );
                    tokio::time::sleep(wait).await;
                }
            }
        }
    }

    /// One RPC round-trip, classifying the outcome into a retryable transport
    /// failure vs. a non-retryable JSON-RPC application error.
    async fn rpc_once(
        &self,
        url: &str,
        method: &str,
        params: Value,
        jwt_auth: bool,
    ) -> std::result::Result<Value, RpcError> {
        let id = self.id.fetch_add(1, Ordering::Relaxed);
        let req = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let mut rb = self.http.post(url).json(&req);
        if jwt_auth {
            // A JWT mint failure is a config error, not a transport blip — don't
            // retry it.
            rb = rb.bearer_auth(jwt::mint(&self.secret).map_err(RpcError::Application)?);
        }
        let resp = rb
            .send()
            .await
            .with_context(|| format!("POST {method} -> {url}"))
            .map_err(RpcError::Transport)?;
        // A non-2xx (e.g. reth returning 503 while warming up) is transient.
        let resp = resp
            .error_for_status()
            .with_context(|| format!("{method} -> {url} HTTP status"))
            .map_err(RpcError::Transport)?;
        let resp: Value = resp
            .json()
            .await
            .with_context(|| format!("decoding {method} response"))
            .map_err(RpcError::Transport)?;
        if let Some(err) = resp.get("error") {
            return Err(RpcError::Application(anyhow::anyhow!(
                "{method} JSON-RPC error: {err}"
            )));
        }
        Ok(resp.get("result").cloned().unwrap_or(Value::Null))
    }

    /// Public `eth_*` call on `:8545`, no auth.
    pub async fn eth(&self, method: &str, params: Value) -> Result<Value> {
        self.rpc(&self.eth_url, method, params, false).await
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
    use super::{HttpTransport, RetryPolicy, parse_finalized_head, peer_reths};
    use serde_json::json;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn backoff_doubles_and_caps() {
        let p = RetryPolicy {
            max_attempts: 8,
            base: Duration::from_millis(50),
            max: Duration::from_millis(800),
        };
        assert_eq!(p.backoff(0), Duration::from_millis(50));
        assert_eq!(p.backoff(1), Duration::from_millis(100));
        assert_eq!(p.backoff(2), Duration::from_millis(200));
        assert_eq!(p.backoff(3), Duration::from_millis(400));
        assert_eq!(p.backoff(4), Duration::from_millis(800));
        // Capped, and no overflow at large attempt counts.
        assert_eq!(p.backoff(5), Duration::from_millis(800));
        assert_eq!(p.backoff(63), Duration::from_millis(800));
        assert_eq!(p.backoff(99), Duration::from_millis(800));
    }

    #[test]
    fn none_policy_is_a_single_attempt() {
        assert_eq!(RetryPolicy::none().max_attempts, 1);
    }

    /// A throwaway HTTP server that, for the first `fail_first` connections,
    /// drops the socket without responding (a transport blip), then replies with
    /// a fixed JSON body. Returns its `http://127.0.0.1:PORT` URL and the count
    /// of connections it actually accepted.
    async fn flaky_server(fail_first: u32, body: serde_json::Value) -> (String, Arc<AtomicU32>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicU32::new(0));
        let hits2 = hits.clone();
        let resp = serde_json::to_string(&body).unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let n = hits2.fetch_add(1, Ordering::SeqCst);
                if n < fail_first {
                    // Read the request then drop the connection: a reset / no body.
                    let mut buf = [0u8; 1024];
                    let _ = sock.read(&mut buf).await;
                    drop(sock);
                    continue;
                }
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let out = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    resp.len(),
                    resp
                );
                let _ = sock.write_all(out.as_bytes()).await;
                let _ = sock.flush().await;
            }
        });
        (format!("http://{addr}"), hits)
    }

    #[tokio::test]
    async fn retries_transient_failure_then_succeeds() {
        // Server drops the first 2 connections, then answers — the retry ring
        // (5 attempts) must ride it out and return the result.
        let (url, hits) =
            flaky_server(2, json!({ "jsonrpc": "2.0", "id": 1, "result": "0x2a" })).await;
        let t = HttpTransport::new(String::new(), url, Vec::new(), None).with_retry(RetryPolicy {
            max_attempts: 5,
            base: Duration::from_millis(5),
            max: Duration::from_millis(20),
        });
        let got = t.eth("eth_blockNumber", json!([])).await.unwrap();
        assert_eq!(got, json!("0x2a"));
        assert_eq!(hits.load(Ordering::SeqCst), 3, "2 failures + 1 success");
    }

    #[tokio::test]
    async fn exhausts_retries_and_errors_on_persistent_failure() {
        // Server always drops — every attempt fails, and after the budget the
        // call surfaces an error (not a silent empty).
        let (url, hits) =
            flaky_server(1000, json!({ "jsonrpc": "2.0", "id": 1, "result": null })).await;
        let t = HttpTransport::new(String::new(), url, Vec::new(), None).with_retry(RetryPolicy {
            max_attempts: 3,
            base: Duration::from_millis(2),
            max: Duration::from_millis(8),
        });
        let err = t.eth("eth_blockNumber", json!([])).await.unwrap_err();
        assert!(format!("{err:#}").contains("after 3 attempt"));
        assert_eq!(hits.load(Ordering::SeqCst), 3, "all 3 attempts tried");
    }

    #[tokio::test]
    async fn json_rpc_application_error_is_not_retried() {
        // A JSON-RPC `error` body is a definitive answer → exactly one attempt.
        let (url, hits) = flaky_server(
            0,
            json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": -32000, "message": "bad" } }),
        )
        .await;
        let t = HttpTransport::new(String::new(), url, Vec::new(), None).with_retry(RetryPolicy {
            max_attempts: 5,
            base: Duration::from_millis(2),
            max: Duration::from_millis(8),
        });
        let err = t.eth("eth_call", json!([])).await.unwrap_err();
        assert!(format!("{err:#}").contains("JSON-RPC error"));
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "application error not retried"
        );
    }

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
