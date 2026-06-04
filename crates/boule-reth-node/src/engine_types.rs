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
    // The engine/rpc types via reth's own re-export, so they are the SAME crate
    // instance reth's traits expect (avoids a duplicate alloy_rpc_types_engine).
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

    /// Convert an [`ExecutionData`] into a `SealedBlock`, running the **same**
    /// consensus-layout checks as reth's stock
    /// [`EthereumExecutionPayloadValidator::ensure_well_formed_payload`] —
    /// **except** alloy's hardcoded 32-byte `extra_data` cap, which boule's chain
    /// relaxes (encoding option (a), #781/#788) so the full
    /// `(keys, weights, settledView)` registry payload fits in the header.
    ///
    /// ## Why this can't just call the stock validator (#791)
    ///
    /// The 32-byte cap lives inside alloy's `ExecutionPayloadV1::into_block_raw_*`
    /// (`MAXIMUM_EXTRA_DATA_SIZE`), which the stock validator funnels every
    /// `newPayloadV4` through. It is not a parameter, so it cannot be raised the
    /// way the *build*-path `EthBeaconConsensus` cap is (see [`crate::consensus`]).
    /// We therefore replicate the validator here and route around the cap by
    /// converting with the `extra_data` temporarily stripped to empty, then
    /// **restoring the full bytes on the header before sealing** — so the recomputed
    /// block hash is taken over the real header (matching the proposer's sealed
    /// hash) and the body/hardfork checks run on the identical block. Everything
    /// else is byte-for-byte the stock validator.
    ///
    /// `extra_data` is still bounded: the build path caps it at
    /// [`crate::registry::MAX_EXTRA_DATA`], and an oversized payload that survived
    /// to here would only fail the codec ([`RegistryPayload::decode`] no-ops it).
    fn ensure_well_formed_payload_uncapped(
        &self,
        payload: ExecutionData,
    ) -> Result<SealedBlock<Block>, PayloadError> {
        let ExecutionData { payload, sidecar } = payload;

        let expected_hash = payload.block_hash();

        // Convert with the `extra_data` cap bypassed, then verify the hash —
        // exactly as the stock validator does, on the real (full) header.
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

/// Convert an [`ExecutionPayload`] (+ its sidecar) into a `SealedBlock`, routing
/// **around** alloy's hardcoded 32-byte `extra_data` cap (#791) without forking
/// alloy or re-implementing its version-aware conversion.
///
/// The cap lives only in alloy's `ExecutionPayloadV1::into_block_raw_*`
/// (`MAXIMUM_EXTRA_DATA_SIZE`), checked on the `extra_data` carried by the V1
/// inner payload. We lift those bytes out (`as_v1_mut`), run alloy's stock
/// `try_into_block_with_sidecar` on the now-empty `extra_data` (so the check
/// passes for any size), then **restore the full bytes on the resulting header
/// before sealing** — so the recomputed block hash is over the true header,
/// matching the bytes the proposer sealed and every replica propagates. The
/// caller checks that hash against the payload's declared hash, exactly as the
/// stock validator does.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal sealed `Block` carrying `extra_data` of the given length,
    /// then re-derive its V1 `ExecutionPayload` (as a verifier receives it).
    fn payload_with_extra_data(len: usize) -> (B256, ExecutionPayload) {
        let mut header = Header {
            extra_data: Bytes::from(vec![0xAB; len]),
            ..Default::default()
        };
        // A base fee is required for the payload→block conversion to succeed.
        header.base_fee_per_gas = Some(7);
        let block = Block {
            header,
            body: Default::default(),
        };
        let sealed: SealedBlock<Block> = block.seal_slow();
        let hash = sealed.hash();
        // A block with no withdrawals / beacon root → a V1 execution payload
        // (and an empty sidecar, which we don't need here).
        let (payload, _sidecar) =
            ExecutionPayload::from_block_unchecked(hash, &sealed.into_block());
        (hash, payload)
    }

    /// The #791 core: alloy's stock conversion rejects a >32-byte `extra_data`,
    /// but [`block_from_payload_uncapped`] accepts it and reproduces the exact
    /// sealed-header bytes and hash — so the verify path round-trips the full
    /// registry payload that build sealed.
    #[test]
    fn uncapped_conversion_accepts_oversized_extra_data() {
        // 64 bytes > MAXIMUM_EXTRA_DATA_SIZE (32): the registry-payload case.
        let (hash, payload) = payload_with_extra_data(64);

        // Stock alloy conversion rejects it (this is the verify-path gap #791).
        let stock = payload
            .clone()
            .try_into_block_with_sidecar::<TransactionSigned>(&ExecutionPayloadSidecar::none());
        assert!(
            matches!(stock, Err(PayloadError::ExtraData(_))),
            "stock conversion enforces the 32-byte cap (got {stock:?})",
        );

        // Our uncapped conversion accepts it and recovers the true header.
        let sealed = block_from_payload_uncapped(payload, &ExecutionPayloadSidecar::none())
            .expect("uncapped conversion accepts >32-byte extra_data");
        assert_eq!(
            sealed.hash(),
            hash,
            "the recomputed hash matches the proposer's sealed hash",
        );
        assert_eq!(
            sealed.into_block().header.extra_data.as_ref(),
            vec![0xAB; 64].as_slice(),
            "the full extra_data is restored on the header",
        );
    }

    /// A ≤32-byte `extra_data` (the common settled-only block) round-trips through
    /// the uncapped path identically — it is a strict superset of the stock path.
    #[test]
    fn uncapped_conversion_handles_small_extra_data() {
        let (hash, payload) = payload_with_extra_data(22); // settled-only size
        let sealed = block_from_payload_uncapped(payload, &ExecutionPayloadSidecar::none())
            .expect("small extra_data converts");
        assert_eq!(sealed.hash(), hash);
        assert_eq!(sealed.into_block().header.extra_data.len(), 22);
    }
}
