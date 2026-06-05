//! Testnet faucet (#806): dispense gas tokens so public users can pay the
//! live EIP-1559 fees.
//!
//! On `POST /faucet { "address": "0x…" }` the service signs and submits an
//! EIP-1559 funding transaction (a fixed drip amount) from an operator-supplied
//! prefunded EOA via reth's public `eth_*` JSON-RPC (`eth_sendRawTransaction`),
//! managing nonce + chain-id itself.
//!
//! # Decoupling from genesis (#804)
//!
//! The faucet's signing key is a **config/env input** ([`FaucetConfig::signer`])
//! — a private key the operator supplies. The faucet does *not* touch genesis
//! structure; it simply assumes that key's address is prefunded. The deployment
//! genesis (#804's `prefund` allocations) MUST seed the faucet address with
//! enough balance to cover many drips, or every drip reverts for insufficient
//! funds. That is the only cross-issue contract, and it is satisfied purely by
//! operator configuration.
//!
//! # Abuse protection
//!
//! A drainable / DoS-able faucet is worse than none. Two independent limits
//! gate every request ([`RateLimiter`]):
//!
//! - **Per-address cooldown.** A given recipient address can be funded at most
//!   once per [`FaucetConfig::address_cooldown`]. This is the primary
//!   anti-drain control: the drip amount is fixed, so an attacker cannot pull
//!   more than `drip_wei` per address per window.
//! - **Per-IP rate limit.** A given client IP can make at most
//!   [`FaucetConfig::ip_max_per_window`] requests per
//!   [`FaucetConfig::ip_window`]. This blunts a single host cycling many fresh
//!   addresses (Sybil over addresses is cheap; Sybil over IPs is not).
//!
//! Both are best-effort in-memory counters — the faucet is itself a trusted
//! testnet operator service, not a consensus-critical component — but they make
//! casual draining and request floods ineffective without external infra.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use anyhow::{Context, Result, bail};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::HttpTransport;

/// Default drip: 1 ETH (1e18 wei) — plenty for many testnet transactions at
/// the configured fee floor, while still bounded per address per window.
pub const DEFAULT_DRIP_WEI: u128 = 1_000_000_000_000_000_000;
/// Default per-address cooldown: one drip per address per 24h.
pub const DEFAULT_ADDRESS_COOLDOWN: Duration = Duration::from_secs(24 * 60 * 60);
/// Default per-IP window: 1 hour.
pub const DEFAULT_IP_WINDOW: Duration = Duration::from_secs(60 * 60);
/// Default per-IP cap: at most 5 drips/hour from one IP.
pub const DEFAULT_IP_MAX_PER_WINDOW: u32 = 5;
/// Gas limit for a plain value transfer (no calldata).
const TRANSFER_GAS_LIMIT: u64 = 21_000;

/// Faucet configuration (operator-supplied).
#[derive(Debug, Clone)]
pub struct FaucetConfig {
    /// Public `eth_*` JSON-RPC endpoint of the reth full node to submit
    /// through, e.g. `http://127.0.0.1:8545`.
    pub eth_url: String,
    /// The faucet's funding key (operator-supplied; its address must be
    /// prefunded in genesis — see module docs / #804).
    pub signer: PrivateKeySigner,
    /// Fixed amount dispensed per successful drip, in wei.
    pub drip_wei: u128,
    /// `max_fee_per_gas` for the drip tx (wei). Must clear the chain's
    /// EIP-1559 base fee.
    pub max_fee_per_gas: u128,
    /// `max_priority_fee_per_gas` for the drip tx (wei).
    pub max_priority_fee_per_gas: u128,
    /// Minimum spacing between drips to the *same recipient address*.
    pub address_cooldown: Duration,
    /// Sliding window for the per-IP request cap.
    pub ip_window: Duration,
    /// Max requests allowed from one IP within [`Self::ip_window`].
    pub ip_max_per_window: u32,
}

impl FaucetConfig {
    /// Build from the bare essentials, applying the documented defaults for
    /// the limits + drip amount.
    pub fn new(eth_url: String, signer: PrivateKeySigner) -> Self {
        Self {
            eth_url,
            signer,
            drip_wei: DEFAULT_DRIP_WEI,
            // 2 gwei tip + 2 gwei max fee mirrors the e2e helper defaults;
            // operators raise these if the chain's base fee climbs.
            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            address_cooldown: DEFAULT_ADDRESS_COOLDOWN,
            ip_window: DEFAULT_IP_WINDOW,
            ip_max_per_window: DEFAULT_IP_MAX_PER_WINDOW,
        }
    }
}

/// Outcome of a rate-limit admission check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// The request may proceed.
    Allowed,
    /// The recipient address was funded too recently; retry after the
    /// contained duration.
    AddressCooldown(Duration),
    /// The client IP exceeded its per-window request budget; retry after the
    /// contained duration.
    IpRateLimited(Duration),
}

/// In-memory per-address + per-IP rate limiter.
///
/// Pure w.r.t. time: every method takes an explicit `now: Instant`, so the
/// admission policy is unit-testable without sleeping. The node wraps it with
/// `Instant::now()` at the HTTP edge.
#[derive(Debug)]
pub struct RateLimiter {
    address_cooldown: Duration,
    ip_window: Duration,
    ip_max_per_window: u32,
    /// recipient address → last time it was successfully funded.
    last_drip: HashMap<Address, Instant>,
    /// client IP → request timestamps within the current window.
    ip_hits: HashMap<IpAddr, Vec<Instant>>,
}

impl RateLimiter {
    /// Build from a [`FaucetConfig`].
    pub fn new(cfg: &FaucetConfig) -> Self {
        Self {
            address_cooldown: cfg.address_cooldown,
            ip_window: cfg.ip_window,
            ip_max_per_window: cfg.ip_max_per_window,
            last_drip: HashMap::new(),
            ip_hits: HashMap::new(),
        }
    }

    /// Check whether a request from `ip` for `address` may proceed at `now`.
    ///
    /// This is a pure *check*: it records the IP hit (so repeated checks count
    /// against the IP budget) but does **not** record the address drip — the
    /// caller records that only after the drip actually submits, via
    /// [`Self::record_drip`], so a failed submission doesn't burn the address
    /// cooldown.
    pub fn check(&mut self, ip: IpAddr, address: Address, now: Instant) -> Admission {
        // Per-address cooldown first: cheap and the primary anti-drain gate.
        if let Some(&last) = self.last_drip.get(&address) {
            let elapsed = now.saturating_duration_since(last);
            if elapsed < self.address_cooldown {
                return Admission::AddressCooldown(self.address_cooldown - elapsed);
            }
        }

        // Per-IP sliding window. Prune expired hits, then admit-or-reject.
        let hits = self.ip_hits.entry(ip).or_default();
        let window = self.ip_window;
        hits.retain(|t| now.saturating_duration_since(*t) < window);
        if hits.len() as u32 >= self.ip_max_per_window {
            // Retry once the oldest in-window hit ages out.
            let retry = hits
                .iter()
                .map(|t| window.saturating_sub(now.saturating_duration_since(*t)))
                .min()
                .unwrap_or(window);
            return Admission::IpRateLimited(retry);
        }
        hits.push(now);
        Admission::Allowed
    }

    /// Record a successful drip to `address` at `now`, starting its cooldown.
    /// Called only after the funding tx submits.
    pub fn record_drip(&mut self, address: Address, now: Instant) {
        self.last_drip.insert(address, now);
    }

    /// Drop stale per-IP windows so the map doesn't grow without bound across
    /// many distinct clients. Call periodically (e.g. on each request).
    pub fn gc(&mut self, now: Instant) {
        let window = self.ip_window;
        self.ip_hits.retain(|_, hits| {
            hits.iter()
                .any(|t| now.saturating_duration_since(*t) < window)
        });
        let cooldown = self.address_cooldown;
        self.last_drip
            .retain(|_, last| now.saturating_duration_since(*last) < cooldown);
    }
}

/// Build an EIP-1559 value-transfer drip tx and RLP-encode it for
/// `eth_sendRawTransaction`. Pure (no network): given the chain id + nonce +
/// recipient + fee params, returns the `0x…`-prefixed raw tx hex.
///
/// Split out from [`FaucetService::drip`] so the tx-construction + signing is
/// unit-testable without a live reth.
pub fn build_drip_raw_tx(
    signer: &PrivateKeySigner,
    chain_id: u64,
    nonce: u64,
    to: Address,
    value_wei: u128,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
) -> Result<String> {
    let tx = TxEip1559 {
        chain_id,
        nonce,
        gas_limit: TRANSFER_GAS_LIMIT,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        to: TxKind::Call(to),
        value: U256::from(value_wei),
        access_list: Default::default(),
        input: Default::default(),
    };
    let sig = signer
        .sign_hash_sync(&tx.signature_hash())
        .context("signing faucet drip tx")?;
    let env: TxEnvelope = tx.into_signed(sig).into();
    Ok(format!("0x{}", hex::encode(env.encoded_2718())))
}

/// The faucet's EL-facing half: signs + submits drips through reth's public
/// RPC. Holds no rate-limit state (that lives in [`RateLimiter`]); separated so
/// the submission path can be exercised against a single live reth without the
/// HTTP layer.
pub struct FaucetService {
    cfg: FaucetConfig,
    transport: HttpTransport,
    /// Serializes the whole fetch-nonce → sign → submit sequence (#823).
    ///
    /// The pending nonce comes from reth's mempool view, which only advances
    /// once a tx is *accepted*. Two concurrent drips that both read the pending
    /// nonce before either submits would build txs with the **same** nonce —
    /// one wins, the other is rejected as a duplicate (or, worse, replaces the
    /// first), so the drip silently fails or sticks. Holding this lock across
    /// the read+submit makes nonce acquisition atomic per faucet account, so
    /// back-to-back drips get strictly increasing nonces. The lock is only held
    /// for the (single-account) submit path, so it does not serialize unrelated
    /// faucet work.
    nonce_lock: tokio::sync::Mutex<()>,
}

impl FaucetService {
    /// Construct over the configured public RPC endpoint.
    pub fn new(cfg: FaucetConfig) -> Self {
        // Engine URL + secret unused (we only call public eth_* RPC).
        let transport = HttpTransport::new(String::new(), cfg.eth_url.clone(), Vec::new(), None);
        Self {
            cfg,
            transport,
            nonce_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// The faucet's funding address (its key's address).
    pub fn faucet_address(&self) -> Address {
        self.cfg.signer.address()
    }

    /// The fixed drip amount.
    pub fn drip_wei(&self) -> u128 {
        self.cfg.drip_wei
    }

    /// Read the chain id from reth (`eth_chainId`).
    async fn chain_id(&self) -> Result<u64> {
        let v = self.transport.eth("eth_chainId", json!([])).await?;
        parse_hex_u64(v.as_str().context("eth_chainId result")?).context("eth_chainId not hex")
    }

    /// Read the faucet account's pending nonce (`eth_getTransactionCount …
    /// pending`), so back-to-back drips don't collide on nonce.
    async fn pending_nonce(&self) -> Result<u64> {
        let from = format!("0x{}", hex::encode(self.faucet_address()));
        let v = self
            .transport
            .eth("eth_getTransactionCount", json!([from, "pending"]))
            .await?;
        parse_hex_u64(v.as_str().context("nonce result")?).context("nonce not hex")
    }

    /// Sign + submit a drip to `to`, returning the tx hash. Reads chain id +
    /// pending nonce from reth, builds an EIP-1559 transfer, and submits it via
    /// `eth_sendRawTransaction`.
    ///
    /// Nonce acquisition is serialized (#823): the read-pending-nonce → submit
    /// window is held under [`Self::nonce_lock`] so two concurrent drips cannot
    /// observe the same pending nonce and collide. The chain id is read outside
    /// the lock (it never changes), so only the nonce-sensitive tail is
    /// serialized.
    pub async fn drip(&self, to: Address) -> Result<String> {
        let chain_id = self.chain_id().await?;
        // Hold the lock across read-nonce → submit so concurrent drips get
        // strictly increasing nonces rather than colliding on the same one.
        let _guard = self.nonce_lock.lock().await;
        let nonce = self.pending_nonce().await?;
        let raw = build_drip_raw_tx(
            &self.cfg.signer,
            chain_id,
            nonce,
            to,
            self.cfg.drip_wei,
            self.cfg.max_fee_per_gas,
            self.cfg.max_priority_fee_per_gas,
        )?;
        let res = self
            .transport
            .eth("eth_sendRawTransaction", json!([raw]))
            .await
            .context("submitting drip via eth_sendRawTransaction")?;
        match res.as_str() {
            Some(h) => Ok(h.to_string()),
            None => bail!("eth_sendRawTransaction returned no hash: {res}"),
        }
    }
}

/// Shared faucet state behind the axum router: the submission service plus the
/// (mutex-guarded) rate limiter.
pub struct FaucetState {
    pub service: FaucetService,
    pub limiter: Mutex<RateLimiter>,
}

impl FaucetState {
    /// Build the state (service + limiter) from a config.
    pub fn new(cfg: FaucetConfig) -> Arc<Self> {
        let limiter = Mutex::new(RateLimiter::new(&cfg));
        Arc::new(Self {
            service: FaucetService::new(cfg),
            limiter,
        })
    }
}

/// Request body for `POST /faucet`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DripRequest {
    /// Recipient address (`0x…`).
    pub address: String,
}

/// Success body for `POST /faucet`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DripResponse {
    /// Submitted tx hash.
    pub tx_hash: String,
    /// Amount dripped, in wei (stringified so large values survive JSON).
    pub amount_wei: String,
    /// Recipient address, normalized.
    pub address: String,
}

/// Parse + normalize a recipient address string (`0x…`), returning the
/// canonical lowercase `0x`-prefixed form alongside the parsed [`Address`].
/// Exposed so the HTTP layer (which doesn't depend on `alloy-primitives`) can
/// validate the request body. Returns `None` for anything that isn't a
/// 20-byte hex address.
pub fn parse_address(s: &str) -> Option<(Address, String)> {
    let addr: Address = s.trim().parse().ok()?;
    Some((addr, format!("0x{}", hex::encode(addr))))
}

/// Parse a `0x`-prefixed (or bare) hex u64, tolerating an empty `0x`.
fn parse_hex_u64(s: &str) -> Result<u64> {
    let s = s.trim_start_matches("0x");
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(s, 16).context("hex u64")
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::transaction::SignerRecoverable;
    use alloy_eips::eip2718::Decodable2718;

    fn test_signer() -> PrivateKeySigner {
        // anvil dev account #0 — deterministic, only used to exercise signing.
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .unwrap()
    }

    fn cfg() -> FaucetConfig {
        let mut c = FaucetConfig::new("http://127.0.0.1:8545".into(), test_signer());
        c.address_cooldown = Duration::from_secs(100);
        c.ip_window = Duration::from_secs(10);
        c.ip_max_per_window = 2;
        c
    }

    fn addr(b: u8) -> Address {
        Address::from([b; 20])
    }

    fn ip(b: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, b])
    }

    // ---- tx building ------------------------------------------------------

    #[test]
    fn drip_tx_is_well_formed_and_recovers_to_faucet() {
        let signer = test_signer();
        let raw = build_drip_raw_tx(&signer, 1337, 7, addr(0xee), 1_000, 2_000, 1_000).unwrap();
        assert!(raw.starts_with("0x02"), "must be a typed (EIP-1559) tx");
        // Decode it back and confirm the fields + recovered sender.
        let bytes = hex::decode(raw.trim_start_matches("0x")).unwrap();
        let env = TxEnvelope::decode_2718(&mut bytes.as_slice()).unwrap();
        let tx = env.as_eip1559().expect("eip1559");
        assert_eq!(tx.tx().chain_id, 1337);
        assert_eq!(tx.tx().nonce, 7);
        assert_eq!(tx.tx().to, TxKind::Call(addr(0xee)));
        assert_eq!(tx.tx().value, U256::from(1_000u64));
        assert_eq!(tx.tx().gas_limit, TRANSFER_GAS_LIMIT);
        assert_eq!(env.recover_signer().unwrap(), signer.address());
    }

    #[test]
    fn distinct_nonces_produce_distinct_raw_txs() {
        let signer = test_signer();
        let a = build_drip_raw_tx(&signer, 1, 0, addr(1), 1, 1, 1).unwrap();
        let b = build_drip_raw_tx(&signer, 1, 1, addr(1), 1, 1, 1).unwrap();
        assert_ne!(a, b);
    }

    // ---- rate limiting ----------------------------------------------------

    #[test]
    fn address_cooldown_blocks_repeat_until_window_elapses() {
        let mut rl = RateLimiter::new(&cfg());
        let t0 = Instant::now();
        // First request for addr(1) from ip(1): allowed.
        assert_eq!(rl.check(ip(1), addr(1), t0), Admission::Allowed);
        rl.record_drip(addr(1), t0);
        // Immediate repeat for the same address (even from a fresh IP) is on
        // cooldown.
        match rl.check(ip(2), addr(1), t0 + Duration::from_secs(1)) {
            Admission::AddressCooldown(d) => assert!(d <= Duration::from_secs(100)),
            other => panic!("expected cooldown, got {other:?}"),
        }
        // After the cooldown elapses, allowed again.
        assert_eq!(
            rl.check(ip(2), addr(1), t0 + Duration::from_secs(101)),
            Admission::Allowed
        );
    }

    #[test]
    fn per_ip_window_caps_requests_across_addresses() {
        let mut rl = RateLimiter::new(&cfg()); // ip_max_per_window = 2
        let t0 = Instant::now();
        // Same IP cycling fresh addresses: first two allowed, third blocked.
        assert_eq!(rl.check(ip(9), addr(1), t0), Admission::Allowed);
        assert_eq!(
            rl.check(ip(9), addr(2), t0 + Duration::from_secs(1)),
            Admission::Allowed
        );
        match rl.check(ip(9), addr(3), t0 + Duration::from_secs(2)) {
            Admission::IpRateLimited(d) => assert!(d <= Duration::from_secs(10)),
            other => panic!("expected ip rate limit, got {other:?}"),
        }
        // A different IP is unaffected.
        assert_eq!(
            rl.check(ip(10), addr(4), t0 + Duration::from_secs(2)),
            Admission::Allowed
        );
        // Once the window slides past, the busy IP is allowed again.
        assert_eq!(
            rl.check(ip(9), addr(5), t0 + Duration::from_secs(11)),
            Admission::Allowed
        );
    }

    #[test]
    fn gc_prunes_stale_entries() {
        let mut rl = RateLimiter::new(&cfg());
        let t0 = Instant::now();
        rl.check(ip(1), addr(1), t0);
        rl.record_drip(addr(1), t0);
        assert!(!rl.ip_hits.is_empty());
        assert!(!rl.last_drip.is_empty());
        // Far in the future, everything is stale and pruned.
        rl.gc(t0 + Duration::from_secs(10_000));
        assert!(rl.ip_hits.is_empty());
        assert!(rl.last_drip.is_empty());
    }

    #[test]
    fn parse_hex_u64_handles_prefix_and_empty() {
        assert_eq!(parse_hex_u64("0x0").unwrap(), 0);
        assert_eq!(parse_hex_u64("0x").unwrap(), 0);
        assert_eq!(parse_hex_u64("0x2a").unwrap(), 42);
        assert_eq!(parse_hex_u64("2a").unwrap(), 42);
        assert!(parse_hex_u64("0xnothex").is_err());
    }

    // ---- concurrent drip nonce serialization (#823) -----------------------

    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A minimal mock reth that models the mempool-pending-nonce hazard the
    /// faucet's `nonce_lock` guards against:
    ///
    /// - `eth_chainId` → `0x539` (1337).
    /// - `eth_getTransactionCount(_, "pending")` → the count of txs *accepted*
    ///   so far, hex-encoded. This is exactly reth's pending-nonce behavior:
    ///   it only advances once a tx is accepted, so two reads before either
    ///   submit return the *same* value.
    /// - `eth_sendRawTransaction` → records the nonce carried by the tx,
    ///   bumps the accepted count, and returns a synthetic hash.
    ///
    /// Returns the bound `http://127.0.0.1:PORT` URL and a shared `Vec` that
    /// collects every submitted nonce, so the test can assert there were no
    /// collisions.
    async fn spawn_mock_reth() -> (String, Arc<Mutex<Vec<u64>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let accepted = Arc::new(AtomicU64::new(0));
        let nonces: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        let nonces_srv = Arc::clone(&nonces);
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let accepted = Arc::clone(&accepted);
                let nonces = Arc::clone(&nonces_srv);
                tokio::spawn(async move {
                    // Read the request (small bodies); find the JSON body after
                    // the header/body separator.
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 2048];
                    loop {
                        let n = sock.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(pos) = find_body(&buf) {
                            let declared = content_length(&buf);
                            if buf.len() - pos >= declared {
                                break;
                            }
                        }
                    }
                    let pos = find_body(&buf).unwrap();
                    let body = &buf[pos..];
                    let req: serde_json::Value = serde_json::from_slice(body).unwrap();
                    let method = req["method"].as_str().unwrap();
                    let id = req["id"].clone();
                    let result = match method {
                        "eth_chainId" => json!("0x539"),
                        "eth_getTransactionCount" => {
                            // Tiny delay so concurrent drips genuinely overlap
                            // their read window absent the lock.
                            tokio::time::sleep(Duration::from_millis(5)).await;
                            json!(format!("0x{:x}", accepted.load(Ordering::SeqCst)))
                        }
                        "eth_sendRawTransaction" => {
                            let raw = req["params"][0].as_str().unwrap();
                            let bytes = hex::decode(raw.trim_start_matches("0x")).unwrap();
                            let env = TxEnvelope::decode_2718(&mut bytes.as_slice()).unwrap();
                            let nonce = env.as_eip1559().unwrap().tx().nonce;
                            nonces.lock().push(nonce);
                            accepted.fetch_add(1, Ordering::SeqCst);
                            json!(format!("0x{nonce:064x}"))
                        }
                        other => panic!("unexpected method {other}"),
                    };
                    let resp = json!({ "jsonrpc": "2.0", "id": id, "result": result });
                    let body = serde_json::to_vec(&resp).unwrap();
                    let head = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(&body).await;
                    let _ = sock.flush().await;
                });
            }
        });
        (url, nonces)
    }

    fn find_body(buf: &[u8]) -> Option<usize> {
        buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
    }

    fn content_length(buf: &[u8]) -> usize {
        let text = String::from_utf8_lossy(buf);
        for line in text.lines() {
            if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                return v.trim().parse().unwrap_or(0);
            }
        }
        0
    }

    /// Concurrent drips must get strictly-increasing, distinct nonces — the
    /// `nonce_lock` serializes read-nonce → submit so they cannot collide on
    /// the same pending nonce. Without the lock, the 5ms read delay makes the
    /// drips race and several would reuse nonce 0.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_drips_get_distinct_nonces() {
        let (url, nonces) = spawn_mock_reth().await;
        let svc = Arc::new(FaucetService::new(FaucetConfig::new(url, test_signer())));

        const N: u64 = 8;
        let mut handles = Vec::new();
        for i in 0..N {
            let svc = Arc::clone(&svc);
            handles.push(tokio::spawn(async move {
                svc.drip(Address::from([i as u8 + 1; 20])).await
            }));
        }
        for h in handles {
            h.await.unwrap().expect("drip must succeed");
        }

        let mut got = nonces.lock().clone();
        got.sort_unstable();
        assert_eq!(
            got,
            (0..N).collect::<Vec<_>>(),
            "concurrent drips must produce the contiguous distinct nonce set 0..N (no collisions)",
        );
    }
}
