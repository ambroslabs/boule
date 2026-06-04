//! The custom node assembly — wires boule's components into a reth
//! `NodeBuilder`-composed node (Option A, #777): the custom executor (registry
//! system writes), the custom payload builder (extra_data transcription), the
//! custom engine types/validator (registry-payload ingress), and the custom
//! consensus builder (relaxed extra_data cap).
//!
//! No reth source is forked — this is the AlphaNet/op-reth pattern of composing
//! the SDK's swappable components.

use reth_ethereum::{
    EthPrimitives,
    chainspec::ChainSpec,
    node::{
        EthereumEthApiBuilder, EthereumNetworkBuilder, EthereumPoolBuilder,
        api::{FullNodeTypes, NodeTypes},
        builder::{
            Node, NodeAdapter,
            components::{ComponentsBuilder, ExecutorBuilder},
            rpc::RpcAddOns,
        },
    },
    provider::EthStorage,
};

use crate::{
    consensus::BouleConsensusBuilder,
    engine_types::{BouleEngineTypes, BouleEngineValidatorBuilder},
    executor::CustomEvmConfig,
    payload::BoulePayloadServiceBuilder,
};

/// The custom executor builder — returns our [`CustomEvmConfig`] (wraps the
/// stock Ethereum EVM config so each block executor applies the registry
/// writes). Adapted from the Phase-0 spike.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct BouleExecutorBuilder;

impl<Types, Node> ExecutorBuilder<Node> for BouleExecutorBuilder
where
    Types: NodeTypes<ChainSpec = ChainSpec, Primitives = EthPrimitives>,
    Node: FullNodeTypes<Types = Types>,
{
    type EVM = CustomEvmConfig;

    async fn build_evm(
        self,
        ctx: &reth_ethereum::node::builder::BuilderContext<Node>,
    ) -> eyre::Result<Self::EVM> {
        Ok(CustomEvmConfig::new(ctx.chain_spec()))
    }
}

/// The boule custom node type.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct BouleNode;

impl NodeTypes for BouleNode {
    type Primitives = EthPrimitives;
    type ChainSpec = ChainSpec;
    type Storage = EthStorage;
    type Payload = BouleEngineTypes;
}

/// Add-ons: stock eth RPC + our engine validator (accepts the custom attribute).
pub type BouleNodeAddOns<N> = RpcAddOns<N, EthereumEthApiBuilder, BouleEngineValidatorBuilder>;

impl<N> Node<N> for BouleNode
where
    N: FullNodeTypes<Types = Self>,
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        EthereumPoolBuilder,
        BoulePayloadServiceBuilder,
        EthereumNetworkBuilder,
        BouleExecutorBuilder,
        BouleConsensusBuilder,
    >;
    type AddOns = BouleNodeAddOns<NodeAdapter<N>>;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        ComponentsBuilder::default()
            .node_types::<N>()
            .pool(EthereumPoolBuilder::default())
            .executor(BouleExecutorBuilder)
            .payload(BoulePayloadServiceBuilder::default())
            .network(EthereumNetworkBuilder::default())
            .consensus(BouleConsensusBuilder)
    }

    fn add_ons(&self) -> Self::AddOns {
        BouleNodeAddOns::default()
    }
}
