//! In-process [`EngineTransport`] (#884): the consensus↔EL hop is a function
//! call into the *same process's* reth, not an HTTP+JWT round trip.
//!
//! [`boule_reth::engine::RethEngine`] drives reth's Engine API entirely through
//! JSON `serde_json::Value` round-trips over the [`EngineTransport`] seam. The
//! standalone node uses [`boule_reth::HttpTransport`] (two processes, JWT). The
//! bundle (#885) launches reth in-process and uses this transport instead:
//!
//! - `call` (the authenticated `engine_*` path) dispatches to reth's
//!   **auth-server in-process IPC client** — a `jsonrpsee` async client over the
//!   auth server's unix-socket IPC endpoint, which bypasses both TCP and the JWT
//!   bearer check (`cfg(unix)`; the bundle targets Linux). This is the same
//!   handler the HTTP auth server wraps, so the custom `registryPayload` build
//!   attribute (`BoulePayloadAttributes`, serde-flattened) round-trips through it
//!   **unchanged** — every predeploy decoder in `engine.rs`/`application.rs` is
//!   reused verbatim.
//! - `eth_rpc` (the public `eth_*` path) dispatches to an in-process eth client
//!   (the node's HTTP RPC server handle).
//!
//! The `tag` argument (golden-fixture recording, for the offline test transport)
//! is meaningless in-process and is ignored.

use anyhow::{Context, Result};
use boule_core::clock::BoxFuture;
use boule_reth::EngineTransport;
use jsonrpsee::core::client::ClientT;
use jsonrpsee::core::params::ArrayParams;
use serde_json::Value;

/// In-process Engine/eth transport backed by reth's in-process `jsonrpsee`
/// clients (#884). Holds the auth-server IPC client (`engine_*`, no JWT) and the
/// public eth HTTP client (`eth_*`).
pub struct InProcessTransport {
    /// Authenticated Engine API client over the auth server's IPC endpoint.
    /// Bypasses TCP + JWT (it is the same in-process handler the HTTP auth
    /// server wraps). `cfg(unix)`-only — the bundle targets Linux.
    engine: jsonrpsee::async_client::Client,
    /// Public `eth_*` JSON-RPC client (the node's HTTP RPC server handle).
    eth: jsonrpsee::http_client::HttpClient,
}

impl InProcessTransport {
    /// Build from the two in-process `jsonrpsee` clients obtained from a launched
    /// reth `FullNode` (see `runtime::run_bundled`).
    pub fn new(
        engine: jsonrpsee::async_client::Client,
        eth: jsonrpsee::http_client::HttpClient,
    ) -> Self {
        Self { engine, eth }
    }

    /// Read-only public `eth_*` call used by the runtime for in-process genesis /
    /// finalized-head reads (replacing `fetch_genesis`/`fetch_finalized_head`).
    pub async fn eth(&self, method: &str, params: Value) -> Result<Value> {
        eth_request(&self.eth, method, params).await
    }
}

/// Convert a JSON array of params into `jsonrpsee`'s [`ArrayParams`]. A non-array
/// `Value` (or `Null`) yields empty params — the boule engine driver always
/// passes a JSON array, so this is the only shape in practice.
fn to_array_params(params: Value) -> Result<ArrayParams> {
    let mut out = ArrayParams::new();
    if let Value::Array(items) = params {
        for item in items {
            out.insert(item)
                .context("encoding JSON-RPC array param for in-process call")?;
        }
    }
    Ok(out)
}

/// One in-process `engine_*` round-trip over the auth IPC client.
async fn engine_request(
    client: &jsonrpsee::async_client::Client,
    method: &str,
    params: Value,
) -> Result<Value> {
    let p = to_array_params(params)?;
    client
        .request::<Value, _>(method, p)
        .await
        .with_context(|| format!("in-process engine call {method}"))
}

/// One in-process `eth_*` round-trip over the eth HTTP client.
async fn eth_request(
    client: &jsonrpsee::http_client::HttpClient,
    method: &str,
    params: Value,
) -> Result<Value> {
    let p = to_array_params(params)?;
    client
        .request::<Value, _>(method, p)
        .await
        .with_context(|| format!("in-process eth call {method}"))
}

impl EngineTransport for InProcessTransport {
    fn call(&self, method: &str, params: Value, _tag: &str) -> BoxFuture<'_, Result<Value>> {
        let method = method.to_string();
        Box::pin(async move { engine_request(&self.engine, &method, params).await })
    }

    fn eth_rpc(&self, method: &str, params: Value) -> BoxFuture<'_, Result<Value>> {
        let method = method.to_string();
        Box::pin(async move { eth_request(&self.eth, &method, params).await })
    }
}

#[cfg(test)]
mod tests {
    use super::to_array_params;
    use serde_json::json;

    #[test]
    fn array_params_roundtrip_preserves_each_element() {
        // The boule engine driver passes a JSON array; each element must be
        // inserted in order (e.g. `[blockHash, false]` for eth_getBlockByNumber).
        let p = to_array_params(json!(["0x0", false])).unwrap();
        // `ArrayParams` has no public read-back; assert it encodes to the
        // expected JSON-RPC params array via `ToRpcParams`.
        use jsonrpsee::core::traits::ToRpcParams;
        let raw = p.to_rpc_params().unwrap().unwrap();
        assert_eq!(raw.get(), "[\"0x0\",false]");
    }

    #[test]
    fn non_array_params_encode_as_empty() {
        use jsonrpsee::core::traits::ToRpcParams;
        let p = to_array_params(json!(null)).unwrap();
        // Empty params: `to_rpc_params` yields `None` (no params object).
        assert!(p.to_rpc_params().unwrap().is_none());
    }
}
