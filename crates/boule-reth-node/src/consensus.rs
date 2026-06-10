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
