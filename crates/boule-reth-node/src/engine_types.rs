use std::sync::Arc;

use alloy_primitives::{B256, Bytes};
use reth_ethereum::{
    Block,
    EthPrimitives,
    TransactionSigned,
    chainspec::{ChainSpec, EthereumHardforks},
    node::{
        api::{
            AddOnsContext, BuiltPayload, EngineApiValidator, EngineTypes, FullNodeComponents,
            InvalidPayloadAttributesError, NewPayloadError, NodePrimitives, NodeTypes,
            PayloadAttributes, PayloadTypes, PayloadValidator,
            payload::{EngineApiMessageVersion, EngineObjectValidationError, PayloadOrAttributes},
            validate_version_specific_fields,
        },
        builder::rpc::PayloadValidatorBuilder,
    },
    primitives::{Block as _, Header, SealedBlock},
    provider::EthStorage,

    rpc::types::engine::{
        ExecutionData, ExecutionPayload, ExecutionPayloadEnvelopeV2, ExecutionPayloadEnvelopeV3,
        ExecutionPayloadEnvelopeV4, ExecutionPayloadEnvelopeV5, ExecutionPayloadEnvelopeV6,
        ExecutionPayloadSidecar, ExecutionPayloadV1, PayloadAttributes as EthPayloadAttributes,
        PayloadError, PayloadId,
    },
};
use reth_ethereum_payload_builder::EthereumExecutionPayloadValidator;
use reth_payload_builder::EthBuiltPayload;
use reth_payload_validator::{cancun, prague, shanghai};
use serde::{Deserialize, Serialize};

use crate::registry::RegistryPayload;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoulePayloadAttributes {

    #[serde(flatten)]
    pub inner: EthPayloadAttributes,

    #[serde(default, rename = "registryPayload")]
    pub registry_payload: String,
}

impl BoulePayloadAttributes {

    pub fn registry_extra_data(&self) -> Bytes {
        let s = self.registry_payload.trim_start_matches("0x");
        if s.is_empty() {
            return Bytes::new();
        }
        match hex::decode(s) {
            Ok(b) => Bytes::from(b),

            Err(_) => Bytes::new(),
        }
    }

    pub fn from_payload(inner: EthPayloadAttributes, payload: &RegistryPayload) -> Self {
        let registry_payload = if payload.is_empty() {
            String::new()
        } else {
            format!("0x{}", hex::encode(payload.encode()))
        };
        Self {
            inner,
            registry_payload,
        }
    }
}

impl PayloadAttributes for BoulePayloadAttributes {
    fn payload_id(&self, parent_hash: &B256) -> PayloadId {
        self.inner.payload_id(parent_hash)
    }

    fn timestamp(&self) -> u64 {
        self.inner.timestamp()
    }

    fn withdrawals(&self) -> Option<&Vec<reth_ethereum::rpc::eth::primitives::Withdrawal>> {
        self.inner.withdrawals()
    }

    fn parent_beacon_block_root(&self) -> Option<B256> {
        self.inner.parent_beacon_block_root()
    }

    fn slot_number(&self) -> Option<u64> {
        self.inner.slot_number()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[non_exhaustive]
pub struct BouleEngineTypes;

impl PayloadTypes for BouleEngineTypes {
    type ExecutionData = ExecutionData;
    type BuiltPayload = EthBuiltPayload;
    type PayloadAttributes = BoulePayloadAttributes;

    fn block_to_payload(
        block: SealedBlock<
            <<Self::BuiltPayload as BuiltPayload>::Primitives as NodePrimitives>::Block,
        >,
    ) -> ExecutionData {
        let (payload, sidecar) =
            ExecutionPayload::from_block_unchecked(block.hash(), &block.into_block());
        ExecutionData { payload, sidecar }
    }
}

impl EngineTypes for BouleEngineTypes {
    type ExecutionPayloadEnvelopeV1 = ExecutionPayloadV1;
    type ExecutionPayloadEnvelopeV2 = ExecutionPayloadEnvelopeV2;
    type ExecutionPayloadEnvelopeV3 = ExecutionPayloadEnvelopeV3;
    type ExecutionPayloadEnvelopeV4 = ExecutionPayloadEnvelopeV4;
    type ExecutionPayloadEnvelopeV5 = ExecutionPayloadEnvelopeV5;
    type ExecutionPayloadEnvelopeV6 = ExecutionPayloadEnvelopeV6;
}

#[derive(Debug, Clone)]
pub struct BouleEngineValidator {
    inner: EthereumExecutionPayloadValidator<ChainSpec>,
}

impl BouleEngineValidator {
    pub const fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self {
            inner: EthereumExecutionPayloadValidator::new(chain_spec),
        }
    }

    fn chain_spec(&self) -> &ChainSpec {
        self.inner.chain_spec()
    }

    fn ensure_well_formed_payload_uncapped(
        &self,
        payload: ExecutionData,
    ) -> Result<SealedBlock<Block>, PayloadError> {
        let ExecutionData { payload, sidecar } = payload;

        let expected_hash = payload.block_hash();

        let sealed_block = block_from_payload_uncapped(payload, &sidecar)?;
        if expected_hash != sealed_block.hash() {
            return Err(PayloadError::BlockHash {
                execution: sealed_block.hash(),
                consensus: expected_hash,
            });
        }

        let chain_spec = self.chain_spec();
        let timestamp = sealed_block.timestamp;

        shanghai::ensure_well_formed_fields(
            sealed_block.body(),
            chain_spec.is_shanghai_active_at_timestamp(timestamp),
        )?;

        cancun::ensure_well_formed_fields(
            &sealed_block,
            sidecar.cancun(),
            chain_spec.is_cancun_active_at_timestamp(timestamp),
        )?;

        prague::ensure_well_formed_fields(
            sealed_block.body(),
            sidecar.prague(),
            chain_spec.is_prague_active_at_timestamp(timestamp),
        )?;

        Ok(sealed_block)
    }
}

fn block_from_payload_uncapped(
    mut payload: ExecutionPayload,
    sidecar: &ExecutionPayloadSidecar,
) -> Result<SealedBlock<Block>, PayloadError> {
    let extra_data = std::mem::take(&mut payload.as_v1_mut().extra_data);
    let mut block: Block = payload.try_into_block_with_sidecar::<TransactionSigned>(sidecar)?;
    block.header.extra_data = extra_data;
    Ok(block.seal_slow())
}

impl PayloadValidator<BouleEngineTypes> for BouleEngineValidator {
    type Block = Block;

    fn convert_payload_to_block(
        &self,
        payload: ExecutionData,
    ) -> Result<SealedBlock<Self::Block>, NewPayloadError> {
        Ok(self.ensure_well_formed_payload_uncapped(payload)?)
    }

    fn validate_payload_attributes_against_header(
        &self,
        _attr: &BoulePayloadAttributes,
        _header: &Header,
    ) -> Result<(), InvalidPayloadAttributesError> {
        Ok(())
    }
}

impl EngineApiValidator<BouleEngineTypes> for BouleEngineValidator {
    fn validate_version_specific_fields(
        &self,
        version: EngineApiMessageVersion,
        payload_or_attrs: PayloadOrAttributes<'_, ExecutionData, BoulePayloadAttributes>,
    ) -> Result<(), EngineObjectValidationError> {
        validate_version_specific_fields(self.chain_spec(), version, payload_or_attrs)
    }

    fn ensure_well_formed_attributes(
        &self,
        version: EngineApiMessageVersion,
        attributes: &BoulePayloadAttributes,
    ) -> Result<(), EngineObjectValidationError> {
        validate_version_specific_fields(
            self.chain_spec(),
            version,
            PayloadOrAttributes::<ExecutionData, BoulePayloadAttributes>::PayloadAttributes(
                attributes,
            ),
        )
    }
}

#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct BouleEngineValidatorBuilder;

impl<N> PayloadValidatorBuilder<N> for BouleEngineValidatorBuilder
where
    N: FullNodeComponents,
    N::Types: NodeTypes<
            Payload = BouleEngineTypes,
            ChainSpec = ChainSpec,
            Primitives = EthPrimitives,
            Storage = EthStorage,
        >,
{
    type Validator = BouleEngineValidator;

    async fn build(self, ctx: &AddOnsContext<'_, N>) -> eyre::Result<Self::Validator> {
        Ok(BouleEngineValidator::new(ctx.config.chain.clone()))
    }
}
