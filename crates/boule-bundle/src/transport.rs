use anyhow::{Context, Result};
use boule_core::clock::BoxFuture;
use boule_reth::EngineTransport;
use jsonrpsee::core::client::ClientT;
use jsonrpsee::core::params::ArrayParams;
use serde_json::Value;

pub struct InProcessTransport {

    engine: jsonrpsee::async_client::Client,

    eth: jsonrpsee::http_client::HttpClient,
}

impl InProcessTransport {

    pub fn new(
        engine: jsonrpsee::async_client::Client,
        eth: jsonrpsee::http_client::HttpClient,
    ) -> Self {
        Self { engine, eth }
    }

    pub async fn eth(&self, method: &str, params: Value) -> Result<Value> {
        eth_request(&self.eth, method, params).await
    }
}

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
