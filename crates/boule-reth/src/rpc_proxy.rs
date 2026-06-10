use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde_json::{Value, json};

use crate::HttpTransport;

pub const DEFAULT_RPC_IP_WINDOW: Duration = Duration::from_secs(1);

pub const DEFAULT_RPC_IP_MAX_PER_WINDOW: u32 = 20;

pub const DEFAULT_MAX_BATCH: usize = 20;

pub const DEFAULT_MAX_BODY_BYTES: usize = 256 * 1024;

pub const ALLOWED_METHODS: &[&str] = &[
    "eth_chainId",
    "eth_blockNumber",
    "eth_getBalance",
    "eth_getCode",
    "eth_getStorageAt",
    "eth_getTransactionCount",
    "eth_getBlockByHash",
    "eth_getBlockByNumber",
    "eth_getBlockTransactionCountByHash",
    "eth_getBlockTransactionCountByNumber",
    "eth_getTransactionByHash",
    "eth_getTransactionByBlockHashAndIndex",
    "eth_getTransactionByBlockNumberAndIndex",
    "eth_getTransactionReceipt",
    "eth_getLogs",
    "eth_gasPrice",
    "eth_maxPriorityFeePerGas",
    "eth_feeHistory",
    "eth_estimateGas",
    "eth_call",
    "eth_sendRawTransaction",
    "net_version",
    "net_listening",
    "net_peerCount",
    "web3_clientVersion",
    "web3_sha3",
];

pub fn is_allowed(method: &str) -> bool {
    ALLOWED_METHODS.contains(&method)
}

#[derive(Debug, Clone)]
pub struct PublicRpcConfig {
    pub eth_url: String,

    pub max_batch: usize,

    pub max_body_bytes: usize,

    pub ip_window: Duration,

    pub ip_max_per_window: u32,
}

impl PublicRpcConfig {
    pub fn new(eth_url: String) -> Self {
        Self {
            eth_url,
            max_batch: DEFAULT_MAX_BATCH,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            ip_window: DEFAULT_RPC_IP_WINDOW,
            ip_max_per_window: DEFAULT_RPC_IP_MAX_PER_WINDOW,
        }
    }
}

#[derive(Debug)]
pub struct RpcRateLimiter {
    window: Duration,
    max_per_window: u32,
    hits: HashMap<IpAddr, Vec<Instant>>,
}

impl RpcRateLimiter {
    pub fn new(cfg: &PublicRpcConfig) -> Self {
        Self {
            window: cfg.ip_window,
            max_per_window: cfg.ip_max_per_window,
            hits: HashMap::new(),
        }
    }

    pub fn admit(&mut self, ip: IpAddr, now: Instant) -> bool {
        let window = self.window;
        let hits = self.hits.entry(ip).or_default();
        hits.retain(|t| now.saturating_duration_since(*t) < window);
        if hits.len() as u32 >= self.max_per_window {
            return false;
        }
        hits.push(now);
        true
    }

    pub fn gc(&mut self, now: Instant) {
        let window = self.window;
        self.hits.retain(|_, hits| {
            hits.iter()
                .any(|t| now.saturating_duration_since(*t) < window)
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    BodyTooLarge,

    Malformed,

    BatchTooLarge,

    MethodNotAllowed,
}

pub fn validate_payload(payload: &Value, max_batch: usize) -> Result<(), Rejection> {
    match payload {
        Value::Array(items) => {
            if items.is_empty() || items.len() > max_batch {
                return Err(Rejection::BatchTooLarge);
            }
            for item in items {
                check_method(item)?;
            }
            Ok(())
        }
        Value::Object(_) => check_method(payload),
        _ => Err(Rejection::Malformed),
    }
}

pub fn first_denied_method(payload: &Value) -> Option<String> {
    let check_one = |v: &Value| -> Option<String> {
        let m = v.get("method").and_then(Value::as_str)?;
        (!is_allowed(m)).then(|| m.to_string())
    };
    match payload {
        Value::Array(items) => items.iter().find_map(check_one),
        other => check_one(other),
    }
}

fn check_method(item: &Value) -> Result<(), Rejection> {
    let method = item
        .get("method")
        .and_then(Value::as_str)
        .ok_or(Rejection::Malformed)?;
    if is_allowed(method) {
        Ok(())
    } else {
        Err(Rejection::MethodNotAllowed)
    }
}

pub fn rejection_to_jsonrpc(rej: Rejection, id: Value) -> Value {
    let (code, msg) = match rej {
        Rejection::BodyTooLarge => (-32600, "request body too large"),
        Rejection::Malformed => (-32700, "parse error"),
        Rejection::BatchTooLarge => (-32600, "batch too large"),
        Rejection::MethodNotAllowed => (-32601, "method not found on public endpoint"),
    };
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": msg } })
}

pub struct PublicRpcState {
    pub cfg: PublicRpcConfig,
    pub transport: HttpTransport,
    pub limiter: Mutex<RpcRateLimiter>,
}

impl PublicRpcState {
    pub fn new(cfg: PublicRpcConfig) -> Arc<Self> {
        let limiter = Mutex::new(RpcRateLimiter::new(&cfg));
        let transport = HttpTransport::new(String::new(), cfg.eth_url.clone(), Vec::new(), None);
        Arc::new(Self {
            cfg,
            transport,
            limiter,
        })
    }
}
