//! `RethEngine` — the Engine API V3 driver.
//!
//! Two operations, matching the deferred-execution model:
//! - [`RethEngine::build_block`] — leader side: `forkchoiceUpdatedV3(attrs)` +
//!   `getPayloadV3`. Produces the EVM block and its state root.
//! - [`RethEngine::commit_block`] — all nodes: `newPayloadV3` (execute) +
//!   `forkchoiceUpdatedV3(head=safe=finalized)`.
//!
//! V3, Cancun-at-genesis, `withdrawals=[]`, zero blob/beacon fields, zero
//! `prevRandao` for the single-validator case.

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::time::Duration;

use crate::transport::EngineTransport;

/// 32 zero bytes as a `0x`-hex string (prevRandao / parentBeaconBlockRoot / etc.).
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

/// Outcome of [`RethEngine::build_block`]: the opaque execution payload plus
/// the fields consensus needs (the block hash and the post-state root that
/// becomes the boule block's `state_commitment`).
#[derive(Debug, Clone)]
pub struct BuiltBlock {
    pub execution_payload: Value,
    pub block_hash: String,
    pub state_root: String,
    pub block_number: u64,
    pub tx_count: usize,
}

impl BuiltBlock {
    /// The post-state root as raw 32 bytes (for the boule header commitment).
    pub fn state_root_bytes(&self) -> Result<[u8; 32]> {
        root_from_hex(&self.state_root)
    }
}

/// Parse a `0x`-prefixed 32-byte hex string into raw bytes.
pub fn root_from_hex(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s.trim_start_matches("0x")).context("root hex")?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("root is not 32 bytes"))
}

pub struct RethEngine<'a, T> {
    transport: &'a T,
    fee_recipient: String,
}

impl<'a, T: EngineTransport> RethEngine<'a, T> {
    pub fn new(transport: &'a T, fee_recipient: impl Into<String>) -> Self {
        Self {
            transport,
            fee_recipient: fee_recipient.into(),
        }
    }

    /// Leader side: start a build on `head_hash` and retrieve the payload.
    /// `build_wait` lets the async build pull pool txs in before `getPayload`
    /// (pass `Duration::ZERO` in tests / when the transport is synchronous).
    pub async fn build_block(
        &self,
        head_hash: &str,
        parent_ts: u64,
        build_wait: Duration,
    ) -> Result<BuiltBlock> {
        let z = zero32();
        let attrs = json!({
            "timestamp": format!("0x{:x}", parent_ts + 1), // strictly > parent.
            "prevRandao": z,
            "suggestedFeeRecipient": self.fee_recipient,
            "withdrawals": [],
            "parentBeaconBlockRoot": z,
        });
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
            .call("engine_getPayloadV3", json!([payload_id]), "02-getpayload")
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

    /// All nodes: execute `payload` and advance forkchoice to it
    /// (`head = safe = finalized` — BFT finality, no reorgs). Returns the
    /// committed block hash.
    pub async fn commit_block(&self, payload: &Value) -> Result<String> {
        let executed = self
            .transport
            .call(
                "engine_newPayloadV3",
                json!([payload, [], zero32()]),
                "03-newpayload",
            )
            .await?;
        expect_valid(&executed["status"], "newPayloadV3")?;

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
        expect_valid(
            &finalized["payloadStatus"]["status"],
            "forkchoiceUpdatedV3(final)",
        )?;
        Ok(hash)
    }

    /// Deliver a built payload to reth (`newPayloadV3`) WITHOUT finalizing, so
    /// the block becomes known and later builds can chain on it. Needed under
    /// HotStuff pipelining: when the leader builds block N, its parent N-1 may
    /// not be committed/finalized yet, so reth must already know N-1's payload.
    pub async fn register_payload(&self, payload: &Value) -> Result<()> {
        let executed = self
            .transport
            .call(
                "engine_newPayloadV3",
                json!([payload, [], zero32()]),
                "03-newpayload",
            )
            .await?;
        expect_valid(&executed["status"], "newPayloadV3(register)")?;
        Ok(())
    }
}

fn forkchoice(hash: &str) -> Value {
    json!({ "headBlockHash": hash, "safeBlockHash": hash, "finalizedBlockHash": hash })
}

fn expect_valid(status: &Value, what: &str) -> Result<()> {
    match status.as_str() {
        Some("VALID") => Ok(()),
        other => bail!("{what}: expected status VALID, got {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::FixtureTransport;

    const GENESIS: &str = "0x48d8efff29130c4b1149a8cb877448dc06421f6617b92dc0f817ef96d8973767";
    const BLOCK1: &str = "0x24df01d105151ebf3d2a6c33530c4d3078d632fb7be477e4ce038ec645a61e91";
    const BLOCK1_STATE_ROOT: &str =
        "0x351714af72d74259f45cd7eab0b04527cd40e74836a45abcae50f92d919d988f";

    fn engine() -> RethEngine<'static, FixtureTransport> {
        // Leak a unit transport so the test engine can be 'static; trivial.
        RethEngine::new(
            Box::leak(Box::new(FixtureTransport)),
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        )
    }

    #[tokio::test]
    async fn build_block_parses_payload_and_state_root() {
        let built = engine()
            .build_block(GENESIS, 0, Duration::ZERO)
            .await
            .expect("build");
        assert_eq!(built.block_number, 1);
        assert_eq!(built.block_hash, BLOCK1);
        assert_eq!(built.state_root, BLOCK1_STATE_ROOT);
        assert_eq!(built.tx_count, 0, "empty-block golden run");
    }

    #[tokio::test]
    async fn commit_block_validates_and_returns_hash() {
        let payload = serde_json::from_str::<Value>(include_str!("../fixtures/02-getpayload.json"))
            .unwrap()["result"]["executionPayload"]
            .clone();
        let hash = engine().commit_block(&payload).await.expect("commit");
        assert_eq!(hash, BLOCK1);
    }

    #[tokio::test]
    async fn build_then_commit_threads_the_payload_through() {
        let eng = engine();
        let built = eng.build_block(GENESIS, 0, Duration::ZERO).await.unwrap();
        let committed = eng.commit_block(&built.execution_payload).await.unwrap();
        assert_eq!(committed, built.block_hash);
    }
}
