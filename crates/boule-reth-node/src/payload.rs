//! The thin custom **payload builder** — the build-path glue that was the real
//! missing piece after Phase 0.
//!
//! Stock reth fills `NextBlockEnvAttributes.extra_data` from a *static*
//! node-config constant (the client-version string), NOT from the per-block
//! `PayloadAttributes`. So to carry boule's per-block registry payload we must
//! transcribe [`BoulePayloadAttributes::registry_extra_data`] into the builder's
//! `extra_data` on every build. We do this by calling
//! [`default_ethereum_payload`] with a per-call [`EthereumBuilderConfig`] whose
//! `extra_data` is the encoded registry payload. The block assembler then writes
//! those bytes straight into the sealed header, where the verify-path executor
//! reads them back — closing the determinism loop.

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

/// Service builder that constructs [`BoulePayloadBuilder`]. Wired into the node
/// via [`BasicPayloadServiceBuilder`].
pub type BoulePayloadServiceBuilder = BasicPayloadServiceBuilder<BoulePayloadBuilderBuilder>;

/// Component builder for [`BoulePayloadBuilder`].
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
            // The node-config default extra_data (client-version string); used
            // verbatim for blocks that carry NO registry payload, so a plain
            // boule block looks like a stock Ethereum block.
            default_extra_data: ctx.payload_builder_config().extra_data(),
            // The operator's `--builder.gaslimit` target. `EthereumBuilderConfig`
            // otherwise defaults `desired_gas_limit` to 30M, so without this the
            // block gas limit ramps toward 30M regardless of the flag (it is read
            // from node config here, exactly like `extra_data` above).
            builder_gas_limit: ctx.payload_builder_config().gas_limit(),
        })
    }
}

/// The custom payload builder. For each build it decides `extra_data`:
/// - if the attributes carry a registry payload → those bytes (so the executor
///   applies the writes and a verifier re-applies the identical ones);
/// - otherwise → the node-config default.
#[derive(Debug, Clone)]
pub struct BoulePayloadBuilder<Pool, Client, Evm> {
    client: Client,
    pool: Pool,
    evm_config: Evm,
    default_extra_data: alloy_primitives::Bytes,
    /// Operator `--builder.gaslimit` target, or `None` to keep reth's default.
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

        // Strip our custom field and run the stock builder, but with the per-call
        // extra_data carrying the registry payload into the sealed header, and the
        // operator's configured gas limit (else reth ramps the limit toward 30M).
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
    /// The extra_data to seal into this block's header: the registry payload if
    /// the attributes carry one, else the node-config default.
    fn extra_data_for(&self, attributes: &BoulePayloadAttributes) -> alloy_primitives::Bytes {
        let registry = attributes.registry_extra_data();
        if registry.is_empty() {
            self.default_extra_data.clone()
        } else {
            registry
        }
    }

    /// The per-build [`EthereumBuilderConfig`]: carries the registry `extra_data`
    /// and honors the operator's `--builder.gaslimit` (else reth's 30M default).
    fn builder_config(&self, attributes: &BoulePayloadAttributes) -> EthereumBuilderConfig {
        let cfg = EthereumBuilderConfig::new().with_extra_data(self.extra_data_for(attributes));
        match self.builder_gas_limit {
            Some(gl) => cfg.with_gas_limit(gl),
            None => cfg,
        }
    }
}
