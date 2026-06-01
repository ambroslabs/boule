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
}

impl EngineTransport for HttpTransport {
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
