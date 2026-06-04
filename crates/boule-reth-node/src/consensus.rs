//! Custom `ConsensusBuilder` that **relaxes the 32-byte `extra_data` cap** for
//! boule's chain — the encoding decision **(a)** from #777/#781.
//!
//! We carry the full `(keys, weights, settledView)` preimage in the header
//! `extra_data` (see [`crate::registry`]), which exceeds the Ethereum yellow-paper
//! 32-byte `extra_data` limit reth enforces by default in `EthBeaconConsensus`.
//! Since boule runs its own chain (not Ethereum mainnet), relaxing that single
//! header-validation rule is sound. We bound it at
//! [`crate::registry::MAX_EXTRA_DATA`] so a malicious oversized header is still
//! rejected.
//!
//! ## This is one of *two* `extra_data` caps (#791)
//!
//! Relaxing `EthBeaconConsensus` here covers header validation, but it is **not**
//! sufficient on its own: the **verify path** (`newPayloadV4`) converts the
//! incoming `ExecutionPayload` to a block through alloy's
//! `ExecutionPayloadV1::into_block_raw_*`, which hardcodes a separate
//! `MAXIMUM_EXTRA_DATA_SIZE = 32` that is not a parameter. So a >32-byte payload
//! would build fine but be rejected on verify. That second cap is routed around
//! in the custom engine validator
//! ([`crate::engine_types::BouleEngineValidator`]), which converts with the cap
//! bypassed. Both relaxations together get the full payload through
//! build → propagate → `newPayloadV4`.
//!
//! This is the only *consensus* rule we change; everything else delegates to the
//! stock `EthBeaconConsensus`.

use std::sync::Arc;

use reth_ethereum::{
    EthPrimitives,
    chainspec::{EthChainSpec, EthereumHardforks},
    consensus::EthBeaconConsensus,
    node::{
        api::{FullNodeTypes, NodeTypes},
        builder::{BuilderContext, components::ConsensusBuilder},
    },
};

use crate::registry::MAX_EXTRA_DATA;

/// Builds an [`EthBeaconConsensus`] with the relaxed `extra_data` cap.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct BouleConsensusBuilder;

impl<Node> ConsensusBuilder<Node> for BouleConsensusBuilder
where
    Node: FullNodeTypes<
        Types: NodeTypes<ChainSpec: EthChainSpec + EthereumHardforks, Primitives = EthPrimitives>,
    >,
{
    type Consensus = Arc<EthBeaconConsensus<<Node::Types as NodeTypes>::ChainSpec>>;

    async fn build_consensus(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Consensus> {
        Ok(Arc::new(
            EthBeaconConsensus::new(ctx.chain_spec()).with_max_extra_data_size(MAX_EXTRA_DATA),
        ))
    }
}
