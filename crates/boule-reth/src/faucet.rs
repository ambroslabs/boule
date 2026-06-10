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

pub const DEFAULT_DRIP_WEI: u128 = 1_000_000_000_000_000_000;

pub const DEFAULT_ADDRESS_COOLDOWN: Duration = Duration::from_secs(24 * 60 * 60);

pub const DEFAULT_IP_WINDOW: Duration = Duration::from_secs(60 * 60);

pub const DEFAULT_IP_MAX_PER_WINDOW: u32 = 5;

const TRANSFER_GAS_LIMIT: u64 = 21_000;

#[derive(Debug, Clone)]
pub struct FaucetConfig {
    pub eth_url: String,

    pub signer: PrivateKeySigner,

    pub drip_wei: u128,

    pub max_fee_per_gas: u128,

    pub max_priority_fee_per_gas: u128,

    pub address_cooldown: Duration,

    pub ip_window: Duration,

    pub ip_max_per_window: u32,
}

impl FaucetConfig {
    pub fn new(eth_url: String, signer: PrivateKeySigner) -> Self {
        Self {
            eth_url,
            signer,
            drip_wei: DEFAULT_DRIP_WEI,

            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            address_cooldown: DEFAULT_ADDRESS_COOLDOWN,
            ip_window: DEFAULT_IP_WINDOW,
            ip_max_per_window: DEFAULT_IP_MAX_PER_WINDOW,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Allowed,

    AddressCooldown(Duration),

    IpRateLimited(Duration),
}

#[derive(Debug)]
pub struct RateLimiter {
    address_cooldown: Duration,
    ip_window: Duration,
    ip_max_per_window: u32,

    last_drip: HashMap<Address, Instant>,

    ip_hits: HashMap<IpAddr, Vec<Instant>>,
}

impl RateLimiter {
    pub fn new(cfg: &FaucetConfig) -> Self {
        Self {
            address_cooldown: cfg.address_cooldown,
            ip_window: cfg.ip_window,
            ip_max_per_window: cfg.ip_max_per_window,
            last_drip: HashMap::new(),
            ip_hits: HashMap::new(),
        }
    }

    pub fn check(&mut self, ip: IpAddr, address: Address, now: Instant) -> Admission {
        if let Some(&last) = self.last_drip.get(&address) {
            let elapsed = now.saturating_duration_since(last);
            if elapsed < self.address_cooldown {
                return Admission::AddressCooldown(self.address_cooldown - elapsed);
            }
        }

        let hits = self.ip_hits.entry(ip).or_default();
        let window = self.ip_window;
        hits.retain(|t| now.saturating_duration_since(*t) < window);
        if hits.len() as u32 >= self.ip_max_per_window {
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

    pub fn record_drip(&mut self, address: Address, now: Instant) {
        self.last_drip.insert(address, now);
    }

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

pub struct FaucetService {
    cfg: FaucetConfig,
    transport: HttpTransport,

    nonce_lock: tokio::sync::Mutex<()>,
}

impl FaucetService {
    pub fn new(cfg: FaucetConfig) -> Self {
        let transport = HttpTransport::new(String::new(), cfg.eth_url.clone(), Vec::new(), None);
        Self {
            cfg,
            transport,
            nonce_lock: tokio::sync::Mutex::new(()),
        }
    }

    pub fn faucet_address(&self) -> Address {
        self.cfg.signer.address()
    }

    pub fn drip_wei(&self) -> u128 {
        self.cfg.drip_wei
    }

    async fn chain_id(&self) -> Result<u64> {
        let v = self.transport.eth("eth_chainId", json!([])).await?;
        parse_hex_u64(v.as_str().context("eth_chainId result")?).context("eth_chainId not hex")
    }

    async fn pending_nonce(&self) -> Result<u64> {
        let from = format!("0x{}", hex::encode(self.faucet_address()));
        let v = self
            .transport
            .eth("eth_getTransactionCount", json!([from, "pending"]))
            .await?;
        parse_hex_u64(v.as_str().context("nonce result")?).context("nonce not hex")
    }

    pub async fn drip(&self, to: Address) -> Result<String> {
        let chain_id = self.chain_id().await?;

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

pub struct FaucetState {
    pub service: FaucetService,
    pub limiter: Mutex<RateLimiter>,
}

impl FaucetState {
    pub fn new(cfg: FaucetConfig) -> Arc<Self> {
        let limiter = Mutex::new(RateLimiter::new(&cfg));
        Arc::new(Self {
            service: FaucetService::new(cfg),
            limiter,
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DripRequest {
    pub address: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DripResponse {
    pub tx_hash: String,

    pub amount_wei: String,

    pub address: String,
}

pub fn parse_address(s: &str) -> Option<(Address, String)> {
    let addr: Address = s.trim().parse().ok()?;
    Some((addr, format!("0x{}", hex::encode(addr))))
}

fn parse_hex_u64(s: &str) -> Result<u64> {
    let s = s.trim_start_matches("0x");
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(s, 16).context("hex u64")
}
