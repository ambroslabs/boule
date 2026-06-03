//! Reth execution-layer backend for boule.
//!
//! Boule consensus orders opaque commands; this crate makes those commands
//! Ethereum execution payloads, executed by a [reth](https://github.com/paradigmxyz/reth)
//! node over the Engine API. One boule block carries one execution payload.
//!
//! The model is **deferred (lagged) execution**, the Ethereum CL/EL-native
//! shape: the leader asks reth to build a payload
//! ([`RethEngine::build_block`] — `forkchoiceUpdatedV3` + `getPayloadV3`),
//! and at commit every node executes it and finalizes
//! ([`RethEngine::commit_block`] — `newPayloadV3` + `forkchoiceUpdatedV3`
//! with `head = safe = finalized`, since BFT finality means no reorgs).
//! The wire is Engine API **V3** with Cancun active at genesis.
//!
//! # Layout
//!
//! - [`transport`] — the [`transport::EngineTransport`] seam (one
//!   authenticated `engine_*` round-trip). [`transport::HttpTransport`]
//!   runs against a live reth (JWT-authenticated Engine API on `:8551`,
//!   public `eth_*` on `:8545`); tests run against committed golden
//!   fixtures.
//! - [`engine`] — [`engine::RethEngine`], the Engine API V3 driver
//!   (build / commit / register).
//! - [`jwt`] — HS256 JWT minting for the Engine API authrpc port.
//! - [`application`] — [`RethApplication`], the consensus
//!   [`Application`](boule_consensus::replication::application::Application)
//!   implementation that drives the driver against the boule block
//!   lifecycle (one block = one payload; build / commit / state queries).
//!
//! Wiring [`RethApplication`] into a node behind a cargo feature is a
//! follow-up.

pub mod application;
pub mod engine;
pub mod jwt;
pub mod rotation;
pub mod staking;
pub mod transport;

pub use application::RethApplication;
pub use engine::{BuiltBlock, RethEngine, root_from_hex};
pub use transport::{
    EngineTransport, HttpTransport, fetch_finalized_head, fetch_genesis, peer_reths,
};

/// Test-only transport that replays the committed golden Engine API
/// fixtures, so the driver can be exercised offline without a live reth.
#[cfg(test)]
pub(crate) mod testing {
    use anyhow::bail;
    use boule_core::clock::BoxFuture;
    use serde_json::Value;

    use crate::transport::EngineTransport;

    pub struct FixtureTransport;

    impl FixtureTransport {
        fn result(raw: &str) -> Value {
            serde_json::from_str::<Value>(raw).unwrap()["result"].clone()
        }
    }

    impl EngineTransport for FixtureTransport {
        fn call(
            &self,
            method: &str,
            params: Value,
            _tag: &str,
        ) -> BoxFuture<'_, anyhow::Result<Value>> {
            let out = (|| {
                Ok(match method {
                    // fcU with attrs (param 1 non-null) starts a build (01);
                    // fcU with null attrs finalizes (04).
                    "engine_forkchoiceUpdatedV3" => {
                        let has_attrs = params.get(1).is_some_and(|v| !v.is_null());
                        if has_attrs {
                            Self::result(include_str!("../fixtures/01-fcu-attrs.json"))
                        } else {
                            Self::result(include_str!("../fixtures/04-fcu-final.json"))
                        }
                    }
                    "engine_getPayloadV3" => {
                        Self::result(include_str!("../fixtures/02-getpayload.json"))
                    }
                    "engine_newPayloadV3" => {
                        Self::result(include_str!("../fixtures/03-newpayload.json"))
                    }
                    other => bail!("FixtureTransport: unexpected method {other}"),
                })
            })();
            Box::pin(async move { out })
        }
    }
}
