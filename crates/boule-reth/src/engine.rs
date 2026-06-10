use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::time::Duration;

use crate::transport::EngineTransport;

fn zero32() -> String {
    format!("0x{}", "00".repeat(32))
}

fn hex_u64(v: &Value, field: &str) -> Result<u64> {
    let s = v
        .as_str()
        .with_context(|| format!("{field}: expected hex string"))?;
    u64::from_str_radix(s.trim_start_matches("0x"), 16)
        .with_context(|| format!("{field}: not hex ({s})"))
}

#[derive(Debug, Clone)]
pub struct BuiltBlock {
    pub execution_payload: Value,
    pub block_hash: String,
    pub state_root: String,
    pub block_number: u64,
    pub tx_count: usize,
}

impl BuiltBlock {
    pub fn state_root_bytes(&self) -> Result<[u8; 32]> {
        root_from_hex(&self.state_root)
    }
}

pub fn root_from_hex(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s.trim_start_matches("0x")).context("root hex")?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("root is not 32 bytes"))
}

pub struct RethEngine<'a> {
    transport: &'a dyn EngineTransport,
    fee_recipient: String,
}

impl<'a> RethEngine<'a> {
    pub fn new(transport: &'a dyn EngineTransport, fee_recipient: impl Into<String>) -> Self {
        Self {
            transport,
            fee_recipient: fee_recipient.into(),
        }
    }

    pub async fn build_block(
        &self,
        head_hash: &str,
        evm_timestamp: u64,
        build_wait: Duration,
        registry_payload: &str,
    ) -> Result<BuiltBlock> {
        let z = zero32();
        let mut attrs = json!({
            "timestamp": format!("0x{evm_timestamp:x}"),
            "prevRandao": z,
            "suggestedFeeRecipient": self.fee_recipient,
            "withdrawals": [],
            "parentBeaconBlockRoot": z,
        });

        if !registry_payload.is_empty() {
            attrs["registryPayload"] = json!(registry_payload);
        }
        let fcs = forkchoice(head_hash);
        let started = self
            .transport
            .call(
                "engine_forkchoiceUpdatedV3",
                json!([fcs, attrs]),
                "01-fcu-attrs",
            )
            .await?;
        expect_valid(
            &started["payloadStatus"]["status"],
            "forkchoiceUpdatedV3(attrs)",
        )?;
        let payload_id = started["payloadId"]
            .as_str()
            .context("forkchoiceUpdatedV3(attrs) returned no payloadId (attrs/fork mismatch?)")?
            .to_string();

        if !build_wait.is_zero() {
            tokio::time::sleep(build_wait).await;
        }

        let got = self
            .transport
            .call("engine_getPayloadV4", json!([payload_id]), "02-getpayload")
            .await?;
        let payload = got["executionPayload"].clone();
        Ok(BuiltBlock {
            block_hash: payload["blockHash"]
                .as_str()
                .context("payload blockHash")?
                .to_string(),
            state_root: payload["stateRoot"]
                .as_str()
                .context("payload stateRoot")?
                .to_string(),
            block_number: hex_u64(&payload["blockNumber"], "blockNumber")?,
            tx_count: payload["transactions"]
                .as_array()
                .map(|a| a.len())
                .unwrap_or(0),
            execution_payload: payload,
        })
    }

    pub async fn commit_block(&self, payload: &Value) -> Result<(String, ElStatus)> {
        let executed = self
            .transport
            .call(
                "engine_newPayloadV4",
                json!([payload, [], zero32(), []]),
                "03-newpayload",
            )
            .await?;
        let exec_status = payload_status(&executed["status"], "newPayloadV4")?;

        let hash = payload["blockHash"]
            .as_str()
            .context("payload blockHash")?
            .to_string();

        let finalized = self
            .transport
            .call(
                "engine_forkchoiceUpdatedV3",
                json!([forkchoice(&hash), Value::Null]),
                "04-fcu-final",
            )
            .await?;
        let fcu_status = payload_status(
            &finalized["payloadStatus"]["status"],
            "forkchoiceUpdatedV3(final)",
        )?;

        let status = if exec_status == ElStatus::Valid && fcu_status == ElStatus::Valid {
            ElStatus::Valid
        } else {
            ElStatus::Syncing
        };
        Ok((hash, status))
    }

    pub async fn register_payload(&self, payload: &Value) -> Result<ElStatus> {
        let executed = self
            .transport
            .call(
                "engine_newPayloadV4",
                json!([payload, [], zero32(), []]),
                "03-newpayload",
            )
            .await?;
        payload_status(&executed["status"], "newPayloadV4(register)")
    }

    pub async fn forkchoice(&self, payload: &Value) -> Result<ElStatus> {
        let hash = payload["blockHash"].as_str().context("payload blockHash")?;
        let finalized = self
            .transport
            .call(
                "engine_forkchoiceUpdatedV3",
                json!([forkchoice(hash), Value::Null]),
                "04-fcu-final",
            )
            .await?;
        payload_status(
            &finalized["payloadStatus"]["status"],
            "forkchoiceUpdatedV3(final)",
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElStatus {
    Valid,

    Syncing,
}

fn forkchoice(hash: &str) -> Value {
    json!({ "headBlockHash": hash, "safeBlockHash": hash, "finalizedBlockHash": hash })
}

fn payload_status(status: &Value, what: &str) -> Result<ElStatus> {
    match status.as_str() {
        Some("VALID") => Ok(ElStatus::Valid),
        Some("SYNCING") | Some("ACCEPTED") => Ok(ElStatus::Syncing),
        Some("INVALID") => bail!("{what}: EL rejected the payload as INVALID"),
        other => bail!("{what}: unexpected Engine API status {other:?}"),
    }
}

fn expect_valid(status: &Value, what: &str) -> Result<()> {
    match status.as_str() {
        Some("VALID") => Ok(()),
        other => bail!("{what}: expected status VALID, got {other:?}"),
    }
}
