//! The custom engine types: a `PayloadAttributes` carrying boule's registry
//! write payload as the **ingress** (boule → EL over `forkchoiceUpdatedV3`),
//! plus the `EngineTypes` / validator wiring needed to accept it.
//!
//! Modeled on reth's `examples/custom-engine-types`. The custom field is a
//! build-only input — it does NOT survive into the sealed block — so the custom
//! payload builder ([`crate::payload`]) transcribes it into the header
//! `extra_data` (the actual carrier), and the executor reads it back from there
//! on both the build and the verify path. See the Phase-0 findings doc.
//!
//! The custom field is the hex-encoded [`RegistryPayload`] bytes
//! ([`RegistryPayload::encode`]). Hex keeps the JSON-RPC attribute a plain
//! string; the builder decodes it back to bytes for `extra_data`.

use std::sync::Arc;

use alloy_primitives::{B256, Bytes};
use reth_ethereum::{
    Block,
    EthPrimitives,
    chainspec::ChainSpec,
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
    primitives::{Header, SealedBlock},
    provider::EthStorage,
    // The engine/rpc types via reth's own re-export, so they are the SAME crate
    // instance reth's traits expect (avoids a duplicate alloy_rpc_types_engine).
    rpc::types::engine::{
        ExecutionData, ExecutionPayload, ExecutionPayloadEnvelopeV2, ExecutionPayloadEnvelopeV3,
        ExecutionPayloadEnvelopeV4, ExecutionPayloadEnvelopeV5, ExecutionPayloadEnvelopeV6,
        ExecutionPayloadV1, PayloadAttributes as EthPayloadAttributes, PayloadId,
    },
};
use reth_ethereum_payload_builder::EthereumExecutionPayloadValidator;
use reth_payload_builder::EthBuiltPayload;
use serde::{Deserialize, Serialize};

use crate::registry::RegistryPayload;

/// boule's custom payload attributes: the stock Ethereum attributes plus a
/// hex-encoded registry-write payload (`(keys, weights, settledView)`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoulePayloadAttributes {
    /// The standard Ethereum payload attributes.
    #[serde(flatten)]
    pub inner: EthPayloadAttributes,
    /// Hex-encoded (`0x`-prefixed) [`RegistryPayload`] bytes the leader computed
    /// for this block. Empty / absent means "no registry writes this block".
    #[serde(default, rename = "registryPayload")]
    pub registry_payload: String,
}

impl BoulePayloadAttributes {
    /// Decode the carried registry payload bytes (for the builder to transcribe
    /// into `extra_data`). An empty string yields empty bytes (a plain block).
    pub fn registry_extra_data(&self) -> Bytes {
        let s = self.registry_payload.trim_start_matches("0x");
        if s.is_empty() {
            return Bytes::new();
        }
        match hex::decode(s) {
            Ok(b) => Bytes::from(b),
            // Malformed ingress → no registry write (a verifier would no-op
            // anyway); the build simply produces a plain block.
            Err(_) => Bytes::new(),
        }
    }

    /// Construct from standard attributes + a [`RegistryPayload`].
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

/// boule's custom engine types — custom attributes ingress, stock built-payload.
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

/// Engine validator: the stock Ethereum validator, but it skips the default
/// `validate_payload_attributes_against_header` timestamp check and accepts our
/// custom attribute (the registry payload needs no engine-level validation —
/// the executor no-ops a malformed one).
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
}

impl PayloadValidator<BouleEngineTypes> for BouleEngineValidator {
    type Block = Block;

    fn convert_payload_to_block(
        &self,
        payload: ExecutionData,
    ) -> Result<SealedBlock<Self::Block>, NewPayloadError> {
        self.inner
            .ensure_well_formed_payload(payload)
            .map_err(Into::into)
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

/// Builder for [`BouleEngineValidator`].
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
