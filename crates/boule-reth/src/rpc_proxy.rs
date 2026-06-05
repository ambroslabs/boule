//! Public eth JSON-RPC exposure (#806).
//!
//! reth already *provides* the `eth_*` JSON-RPC; on a full node we want to put
//! it in front of public users safely rather than exposing reth's port raw.
//! This is a thin reverse-proxy / policy layer that sits in front of reth's
//! public RPC (`:8545`) and forwards only what a public endpoint should serve,
//! with limits suitable for the open internet:
//!
//! - **Method allow-list.** Only read-only `eth_*` / `net_*` / `web3_*` methods
//!   plus `eth_sendRawTransaction` (so users can broadcast signed txs) are
//!   forwarded. reth's `admin_*`, `debug_*`, `txpool_*`, `engine_*`, and any
//!   account-unlocking `personal_*` methods are rejected with a JSON-RPC error
//!   — they are operator/abuse surface, not public surface. The allow-list is
//!   the *documented exposed surface* (`ALLOWED_METHODS`).
//! - **Max batch size.** A JSON-RPC batch is capped at [`PublicRpcConfig::max_batch`]
//!   so one request can't fan out into thousands of backend calls.
//! - **Max request body size.** Bounded by [`PublicRpcConfig::max_body_bytes`]
//!   so an attacker can't stream an unbounded body.
//! - **Per-IP rate limit.** [`PublicRpcConfig::ip_max_per_window`] requests per
//!   [`PublicRpcConfig::ip_window`] per client IP, mirroring the faucet's
//!   limiter.
//!
//! # Why a proxy rather than reth's own flags
//!
//! reth's `--http.api` does coarse namespace gating, but a public endpoint
//! wants method-level control, batch/body caps, and per-IP rate limiting that
//! reth doesn't expose. Running this in front lets the operator keep reth's RPC
//! bound to loopback (reachable only by this proxy + the node) while the proxy
//! is the single public ingress — no reth patch, and the policy lives in one
//! auditable place.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde_json::{Value, json};

use crate::HttpTransport;

/// Default public-RPC per-IP window.
pub const DEFAULT_RPC_IP_WINDOW: Duration = Duration::from_secs(1);
/// Default public-RPC per-IP cap (requests per window).
pub const DEFAULT_RPC_IP_MAX_PER_WINDOW: u32 = 20;
/// Default max JSON-RPC batch length.
pub const DEFAULT_MAX_BATCH: usize = 20;
/// Default max request body (256 KiB) — generous for signed-tx submission,
/// far short of an unbounded stream.
pub const DEFAULT_MAX_BODY_BYTES: usize = 256 * 1024;

/// The exact set of JSON-RPC methods this proxy forwards to reth. Everything
/// else is rejected. This is the **documented public surface**: read-only
/// chain/state queries plus signed-tx broadcast. No operator/debug/admin
/// namespaces, no account-unlocking methods.
pub const ALLOWED_METHODS: &[&str] = &[
    // chain / block / state reads
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
    // fee / gas estimation
    "eth_gasPrice",
    "eth_maxPriorityFeePerGas",
    "eth_feeHistory",
    "eth_estimateGas",
    "eth_call",
    // tx broadcast (the one state-changing method a public user needs)
    "eth_sendRawTransaction",
    // misc read-only namespaces
    "net_version",
    "net_listening",
    "net_peerCount",
    "web3_clientVersion",
    "web3_sha3",
];

/// Is `method` on the public allow-list?
pub fn is_allowed(method: &str) -> bool {
    ALLOWED_METHODS.contains(&method)
}

/// Public-RPC proxy configuration (operator-supplied).
#[derive(Debug, Clone)]
pub struct PublicRpcConfig {
    /// reth's public `eth_*` endpoint to forward to (typically loopback,
    /// e.g. `http://127.0.0.1:8545`).
    pub eth_url: String,
    /// Max JSON-RPC batch length.
    pub max_batch: usize,
    /// Max request body in bytes.
    pub max_body_bytes: usize,
    /// Per-IP sliding window.
    pub ip_window: Duration,
    /// Max requests per IP per window.
    pub ip_max_per_window: u32,
}

impl PublicRpcConfig {
    /// Build with the documented defaults from the backend URL.
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

/// Per-IP sliding-window rate limiter for the public RPC. Time is injected
/// (`now: Instant`) so the policy is unit-testable.
#[derive(Debug)]
pub struct RpcRateLimiter {
    window: Duration,
    max_per_window: u32,
    hits: HashMap<IpAddr, Vec<Instant>>,
}

impl RpcRateLimiter {
    /// Build from a config.
    pub fn new(cfg: &PublicRpcConfig) -> Self {
        Self {
            window: cfg.ip_window,
            max_per_window: cfg.ip_max_per_window,
            hits: HashMap::new(),
        }
    }

    /// Admit (and record) a request from `ip` at `now`, or reject if the IP is
    /// over budget. Returns `true` when admitted.
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

    /// Drop IPs with no in-window hits so the map stays bounded.
    pub fn gc(&mut self, now: Instant) {
        let window = self.window;
        self.hits.retain(|_, hits| {
            hits.iter()
                .any(|t| now.saturating_duration_since(*t) < window)
        });
    }
}

/// One reason a request was rejected before reaching reth. Maps to a JSON-RPC
/// error (and, for rate limiting, an HTTP 429 at the edge).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// Body exceeded `max_body_bytes`.
    BodyTooLarge,
    /// Body wasn't valid JSON, or wasn't an object/array.
    Malformed,
    /// Batch length exceeded `max_batch`.
    BatchTooLarge,
    /// A request in the (possibly batched) payload named a non-allow-listed
    /// method.
    MethodNotAllowed,
}

/// Validate a parsed JSON-RPC payload (single object or batch array) against
/// the policy: batch size + method allow-list. Returns the offending method
/// for `MethodNotAllowed` is handled by the caller via [`first_denied_method`].
///
/// Pure (no network), so the policy is unit-testable.
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

/// The first method named by `payload` that is *not* allow-listed, if any —
/// for a precise error message.
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

/// Build a JSON-RPC error envelope for a rejection, echoing the request `id`
/// when present.
pub fn rejection_to_jsonrpc(rej: Rejection, id: Value) -> Value {
    let (code, msg) = match rej {
        Rejection::BodyTooLarge => (-32600, "request body too large"),
        Rejection::Malformed => (-32700, "parse error"),
        Rejection::BatchTooLarge => (-32600, "batch too large"),
        Rejection::MethodNotAllowed => (-32601, "method not found on public endpoint"),
    };
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": msg } })
}

/// Shared proxy state behind the axum router: the backend transport + the
/// rate limiter + the policy config.
pub struct PublicRpcState {
    pub cfg: PublicRpcConfig,
    pub transport: HttpTransport,
    pub limiter: Mutex<RpcRateLimiter>,
}

impl PublicRpcState {
    /// Build the proxy state from a config.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn rpc(method: &str) -> Value {
        json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": [] })
    }

    #[test]
    fn allow_list_admits_reads_and_send_raw_only() {
        assert!(is_allowed("eth_getBalance"));
        assert!(is_allowed("eth_call"));
        assert!(is_allowed("eth_sendRawTransaction"));
        assert!(is_allowed("net_version"));
        // Operator / debug / admin surface is denied.
        assert!(!is_allowed("admin_addPeer"));
        assert!(!is_allowed("debug_traceTransaction"));
        assert!(!is_allowed("txpool_content"));
        assert!(!is_allowed("engine_newPayloadV3"));
        assert!(!is_allowed("personal_unlockAccount"));
        assert!(!is_allowed("eth_sendTransaction")); // would need an unlocked acct
    }

    #[test]
    fn validate_single_allowed_and_denied() {
        assert_eq!(validate_payload(&rpc("eth_blockNumber"), 10), Ok(()));
        assert_eq!(
            validate_payload(&rpc("admin_addPeer"), 10),
            Err(Rejection::MethodNotAllowed)
        );
        assert_eq!(
            first_denied_method(&rpc("admin_addPeer")).as_deref(),
            Some("admin_addPeer")
        );
        assert_eq!(first_denied_method(&rpc("eth_blockNumber")), None);
    }

    #[test]
    fn validate_batch_size_and_methods() {
        let batch = Value::Array(vec![rpc("eth_blockNumber"), rpc("eth_chainId")]);
        assert_eq!(validate_payload(&batch, 10), Ok(()));

        let too_big = Value::Array((0..11).map(|_| rpc("eth_chainId")).collect());
        assert_eq!(
            validate_payload(&too_big, 10),
            Err(Rejection::BatchTooLarge)
        );

        let empty = Value::Array(vec![]);
        assert_eq!(validate_payload(&empty, 10), Err(Rejection::BatchTooLarge));

        // A denied method anywhere in the batch rejects the whole batch.
        let mixed = Value::Array(vec![rpc("eth_chainId"), rpc("debug_traceBlock")]);
        assert_eq!(
            validate_payload(&mixed, 10),
            Err(Rejection::MethodNotAllowed)
        );
        assert_eq!(
            first_denied_method(&mixed).as_deref(),
            Some("debug_traceBlock")
        );
    }

    #[test]
    fn validate_rejects_non_object_or_missing_method() {
        assert_eq!(
            validate_payload(&json!("hi"), 10),
            Err(Rejection::Malformed)
        );
        assert_eq!(
            validate_payload(&json!({ "jsonrpc": "2.0", "id": 1 }), 10),
            Err(Rejection::Malformed)
        );
    }

    #[test]
    fn rate_limiter_caps_per_ip_and_slides() {
        let mut cfg = PublicRpcConfig::new("http://x".into());
        cfg.ip_window = Duration::from_secs(1);
        cfg.ip_max_per_window = 2;
        let mut rl = RpcRateLimiter::new(&cfg);
        let ip = IpAddr::from([1, 2, 3, 4]);
        let t0 = Instant::now();
        assert!(rl.admit(ip, t0));
        assert!(rl.admit(ip, t0));
        assert!(!rl.admit(ip, t0)); // third in window rejected
        // After the window slides, admitted again.
        assert!(rl.admit(ip, t0 + Duration::from_secs(2)));
        // A different IP has its own budget.
        let ip2 = IpAddr::from([5, 6, 7, 8]);
        assert!(rl.admit(ip2, t0));
    }

    #[test]
    fn rejection_envelope_echoes_id_and_codes() {
        let v = rejection_to_jsonrpc(Rejection::MethodNotAllowed, json!(7));
        assert_eq!(v["id"], json!(7));
        assert_eq!(v["error"]["code"], json!(-32601));
        let v = rejection_to_jsonrpc(Rejection::BatchTooLarge, Value::Null);
        assert_eq!(v["error"]["code"], json!(-32600));
    }
}
