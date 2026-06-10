use anyhow::{Context, Result, bail};
use boule_core::clock::BoxFuture;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::jwt;

#[derive(Clone, Copy, Debug)]
pub struct RetryPolicy {
    pub max_attempts: u32,

    pub base: Duration,

    pub max: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            base: Duration::from_millis(50),
            max: Duration::from_millis(800),
        }
    }
}

impl RetryPolicy {
    pub fn none() -> Self {
        Self {
            max_attempts: 1,
            base: Duration::from_millis(0),
            max: Duration::from_millis(0),
        }
    }

    fn backoff(&self, attempt: u32) -> Duration {
        let factor = 1u64.checked_shl(attempt).unwrap_or(u64::MAX);
        let millis = (self.base.as_millis() as u64).saturating_mul(factor);
        Duration::from_millis(millis.min(self.max.as_millis() as u64))
    }
}

pub trait EngineTransport: Send + Sync {
    fn call(&self, method: &str, params: Value, tag: &str) -> BoxFuture<'_, Result<Value>>;

    fn eth_rpc(&self, method: &str, _params: Value) -> BoxFuture<'_, Result<Value>> {
        let method = method.to_string();
        Box::pin(async move { bail!("eth_* RPC unsupported by this transport: {method}") })
    }
}

pub struct HttpTransport {
    http: reqwest::Client,
    engine_url: String,
    eth_url: String,
    secret: Vec<u8>,

    fixtures_dir: Option<PathBuf>,
    id: AtomicU64,

    retry: RetryPolicy,
}

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

    pub fn with_retry(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    async fn rpc(&self, url: &str, method: &str, params: Value, jwt_auth: bool) -> Result<Value> {
        let mut attempt = 0u32;
        loop {
            match self.rpc_once(url, method, params.clone(), jwt_auth).await {
                Ok(v) => return Ok(v),

                Err(RpcError::Application(e)) => return Err(e),

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
            rb = rb.bearer_auth(jwt::mint(&self.secret).map_err(RpcError::Application)?);
        }
        let resp = rb
            .send()
            .await
            .with_context(|| format!("POST {method} -> {url}"))
            .map_err(RpcError::Transport)?;

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

    pub async fn eth(&self, method: &str, params: Value) -> Result<Value> {
        self.rpc(&self.eth_url, method, params, false).await
    }

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

pub async fn fetch_finalized_head(eth_url: &str) -> Result<Option<(u64, [u8; 32])>> {
    let transport = HttpTransport::new(String::new(), eth_url.to_string(), Vec::new(), None);
    let block = transport
        .eth("eth_getBlockByNumber", json!(["finalized", false]))
        .await
        .context("querying reth finalized block")?;
    parse_finalized_head(&block)
}

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
