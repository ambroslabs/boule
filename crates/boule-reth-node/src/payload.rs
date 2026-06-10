use reth_basic_payload_builder::{BuildArguments, BuildOutcome, PayloadBuilder, PayloadConfig};
use reth_ethereum::{
    EthPrimitives, TransactionSigned,
    chainspec::{ChainSpec, ChainSpecProvider},
    evm::primitives::{ConfigureEvm, NextBlockEnvAttributes},
    node::{
        api::{FullNodeTypes, NodeTypes},
        builder::{
            BuilderContext, PayloadBuilderConfig,
            components::{BasicPayloadServiceBuilder, PayloadBuilderBuilder},
        },
    },
    pool::{PoolTransaction, TransactionPool},
    provider::StateProviderFactory,
};
use reth_ethereum_payload_builder::{EthereumBuilderConfig, default_ethereum_payload};
use reth_payload_builder::{EthBuiltPayload, PayloadBuilderError};

use crate::engine_types::{BouleEngineTypes, BoulePayloadAttributes};

pub type BoulePayloadServiceBuilder = BasicPayloadServiceBuilder<BoulePayloadBuilderBuilder>;

#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct BoulePayloadBuilderBuilder;

impl<Node, Pool, Evm> PayloadBuilderBuilder<Node, Pool, Evm> for BoulePayloadBuilderBuilder
where
    Node: FullNodeTypes<
        Types: NodeTypes<
            Payload = BouleEngineTypes,
            ChainSpec = ChainSpec,
            Primitives = EthPrimitives,
        >,
    >,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TransactionSigned>>
        + Unpin
        + 'static,
    Evm: ConfigureEvm<Primitives = EthPrimitives, NextBlockEnvCtx = NextBlockEnvAttributes>
        + 'static,
{
    type PayloadBuilder = BoulePayloadBuilder<Pool, Node::Provider, Evm>;

    async fn build_payload_builder(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
        evm_config: Evm,
    ) -> eyre::Result<Self::PayloadBuilder> {
        Ok(BoulePayloadBuilder {
            client: ctx.provider().clone(),
            pool,
            evm_config,

            default_extra_data: ctx.payload_builder_config().extra_data(),

            builder_gas_limit: ctx.payload_builder_config().gas_limit(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct BoulePayloadBuilder<Pool, Client, Evm> {
    client: Client,
    pool: Pool,
    evm_config: Evm,
    default_extra_data: alloy_primitives::Bytes,

    builder_gas_limit: Option<u64>,
}

impl<Pool, Client, Evm> PayloadBuilder for BoulePayloadBuilder<Pool, Client, Evm>
where
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec = ChainSpec> + Clone,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TransactionSigned>>,
    Evm: ConfigureEvm<Primitives = EthPrimitives, NextBlockEnvCtx = NextBlockEnvAttributes>,
{
    type Attributes = BoulePayloadAttributes;
    type BuiltPayload = EthBuiltPayload;

    fn try_build(
        &self,
        args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
    ) -> Result<BuildOutcome<Self::BuiltPayload>, PayloadBuilderError> {
        let BuildArguments {
            cached_reads,
            execution_cache,
            trie_handle,
            config,
            cancel,
            best_payload,
        } = args;
        let PayloadConfig {
            parent_header,
            attributes,
            payload_id,
        } = config;

        let builder_config = self.builder_config(&attributes);

        default_ethereum_payload(
            self.evm_config.clone(),
            self.client.clone(),
            self.pool.clone(),
            builder_config,
            BuildArguments {
                cached_reads,
                execution_cache,
                trie_handle,
                config: PayloadConfig {
                    parent_header,
                    attributes: attributes.inner,
                    payload_id,
                },
                cancel,
                best_payload,
            },
            |attrs| self.pool.best_transactions_with_attributes(attrs),
        )
    }

    fn build_empty_payload(
        &self,
        config: PayloadConfig<Self::Attributes>,
    ) -> Result<Self::BuiltPayload, PayloadBuilderError> {
        let PayloadConfig {
            parent_header,
            attributes,
            payload_id,
        } = config;
        let builder_config = self.builder_config(&attributes);

        let args = BuildArguments::new(
            Default::default(),
            Default::default(),
            None,
            PayloadConfig {
                parent_header,
                attributes: attributes.inner,
                payload_id,
            },
            Default::default(),
            None,
        );

        default_ethereum_payload(
            self.evm_config.clone(),
            self.client.clone(),
            self.pool.clone(),
            builder_config,
            args,
            |attrs| self.pool.best_transactions_with_attributes(attrs),
        )?
        .into_payload()
        .ok_or(PayloadBuilderError::MissingPayload)
    }
}

impl<Pool, Client, Evm> BoulePayloadBuilder<Pool, Client, Evm> {
    fn extra_data_for(&self, attributes: &BoulePayloadAttributes) -> alloy_primitives::Bytes {
        let registry = attributes.registry_extra_data();
        if registry.is_empty() {
            self.default_extra_data.clone()
        } else {
            registry
        }
    }

    fn builder_config(&self, attributes: &BoulePayloadAttributes) -> EthereumBuilderConfig {
        let cfg = EthereumBuilderConfig::new().with_extra_data(self.extra_data_for(attributes));
        match self.builder_gas_limit {
            Some(gl) => cfg.with_gas_limit(gl),
            None => cfg,
        }
    }
}
