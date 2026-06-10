use std::{fmt::Display, sync::Arc};

use alloy_evm::{
    EthEvm, EthEvmFactory, EvmFactory,
    block::{BlockExecutorFactory, ExecutableTx, GasOutput},
    eth::{EthBlockExecutionCtx, EthBlockExecutor, EthTxResult},
    precompiles::PrecompilesMap,
};
use reth_ethereum::{
    Block, Receipt, TransactionSigned, TxType,
    chainspec::ChainSpec,
    evm::{
        EthBlockAssembler, EthEvmConfig, RethReceiptBuilder,
        primitives::{
            Evm, EvmEnv, EvmEnvFor, ExecutionCtxFor, InspectorFor, NextBlockEnvAttributes,
            OnStateHook,
            block::StateDB,
            execute::{BlockExecutionError, BlockExecutor, InternalBlockExecutionError},
        },
        revm::{DatabaseCommit, context::TxEnv, primitives::hardfork::SpecId},
    },
    node::api::{ConfigureEngineEvm, ConfigureEvm, ExecutableTxIterator},
    primitives::{Header, SealedBlock, SealedHeader},
    provider::BlockExecutionResult,
    rpc::types::engine::ExecutionData,
};

use crate::registry::{
    REGISTRY_ADDRESS, RegistryPayload, SYSTEM_ADDRESS, record_key_calldata,
    record_settled_calldata, record_weight_calldata,
};

#[derive(Debug, Clone)]
pub struct CustomEvmConfig {
    inner: EthEvmConfig,
}

impl CustomEvmConfig {
    pub fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self {
            inner: EthEvmConfig::new(chain_spec),
        }
    }
}

impl BlockExecutorFactory for CustomEvmConfig {
    type EvmFactory = EthEvmFactory;
    type ExecutionCtx<'a> = EthBlockExecutionCtx<'a>;
    type Transaction = TransactionSigned;
    type Receipt = Receipt;
    type TxExecutionResult = EthTxResult<<EthEvmFactory as EvmFactory>::HaltReason, TxType>;
    type Executor<'a, DB: StateDB, I: InspectorFor<Self, DB>> =
        CustomBlockExecutor<'a, EthEvm<DB, I, PrecompilesMap>>;

    fn evm_factory(&self) -> &Self::EvmFactory {
        self.inner.evm_factory()
    }

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: EthEvm<DB, I, PrecompilesMap>,
        ctx: EthBlockExecutionCtx<'a>,
    ) -> Self::Executor<'a, DB, I>
    where
        DB: StateDB,
        I: InspectorFor<Self, DB>,
    {
        let payload = RegistryPayload::decode(ctx.extra_data.as_ref());
        CustomBlockExecutor {
            payload,
            inner: EthBlockExecutor::new(
                evm,
                ctx,
                self.inner.chain_spec(),
                self.inner.executor_factory.receipt_builder(),
            ),
        }
    }
}

impl ConfigureEvm for CustomEvmConfig {
    type Primitives = <EthEvmConfig as ConfigureEvm>::Primitives;
    type Error = <EthEvmConfig as ConfigureEvm>::Error;
    type NextBlockEnvCtx = <EthEvmConfig as ConfigureEvm>::NextBlockEnvCtx;
    type BlockExecutorFactory = Self;
    type BlockAssembler = EthBlockAssembler<ChainSpec>;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        self
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        self.inner.block_assembler()
    }

    fn evm_env(&self, header: &Header) -> Result<EvmEnv<SpecId>, Self::Error> {
        self.inner.evm_env(header)
    }

    fn next_evm_env(
        &self,
        parent: &Header,
        attributes: &NextBlockEnvAttributes,
    ) -> Result<EvmEnv<SpecId>, Self::Error> {
        self.inner.next_evm_env(parent, attributes)
    }

    fn context_for_block<'a>(
        &self,
        block: &'a SealedBlock<Block>,
    ) -> Result<EthBlockExecutionCtx<'a>, Self::Error> {
        self.inner.context_for_block(block)
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader,
        attributes: Self::NextBlockEnvCtx,
    ) -> Result<EthBlockExecutionCtx<'_>, Self::Error> {
        self.inner.context_for_next_block(parent, attributes)
    }
}

impl ConfigureEngineEvm<ExecutionData> for CustomEvmConfig {
    fn evm_env_for_payload(&self, payload: &ExecutionData) -> Result<EvmEnvFor<Self>, Self::Error> {
        self.inner.evm_env_for_payload(payload)
    }

    fn context_for_payload<'a>(
        &self,
        payload: &'a ExecutionData,
    ) -> Result<ExecutionCtxFor<'a, Self>, Self::Error> {
        self.inner.context_for_payload(payload)
    }

    fn tx_iterator_for_payload(
        &self,
        payload: &ExecutionData,
    ) -> Result<impl ExecutableTxIterator<Self>, Self::Error> {
        self.inner.tx_iterator_for_payload(payload)
    }
}

pub struct CustomBlockExecutor<'a, Evm> {
    payload: Option<RegistryPayload>,
    inner: EthBlockExecutor<'a, Evm, &'a Arc<ChainSpec>, &'a RethReceiptBuilder>,
}

impl<E> BlockExecutor for CustomBlockExecutor<'_, E>
where
    E: Evm<DB: StateDB, Tx = TxEnv>,
{
    type Transaction = TransactionSigned;
    type Receipt = Receipt;
    type Evm = E;
    type Result = EthTxResult<E::HaltReason, TxType>;

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        if let Some(payload) = self.payload.take() {
            apply_registry_writes(&payload, self.inner.evm_mut())?;
        }
        self.inner.apply_pre_execution_changes()
    }

    fn receipts(&self) -> &[Self::Receipt] {
        self.inner.receipts()
    }

    fn execute_transaction_without_commit(
        &mut self,
        tx: impl ExecutableTx<Self>,
    ) -> Result<Self::Result, BlockExecutionError> {
        self.inner.execute_transaction_without_commit(tx)
    }

    fn commit_transaction(&mut self, output: Self::Result) -> GasOutput {
        self.inner.commit_transaction(output)
    }

    fn finish(self) -> Result<(Self::Evm, BlockExecutionResult<Receipt>), BlockExecutionError> {
        self.inner.finish()
    }

    fn set_state_hook(&mut self, hook: Option<Box<dyn OnStateHook>>) {
        self.inner.set_state_hook(hook)
    }

    fn evm_mut(&mut self) -> &mut Self::Evm {
        self.inner.evm_mut()
    }

    fn evm(&self) -> &Self::Evm {
        self.inner.evm()
    }
}

pub fn apply_registry_writes(
    payload: &RegistryPayload,
    evm: &mut impl Evm<Error: Display, DB: DatabaseCommit>,
) -> Result<(), BlockExecutionError> {
    for k in &payload.keys {
        system_call(evm, record_key_calldata(k), "recordKey")?;
    }
    for w in &payload.weights {
        system_call(evm, record_weight_calldata(w), "recordWeight")?;
    }
    if let Some(view) = payload.settled_view {
        system_call(evm, record_settled_calldata(view), "recordSettled")?;
    }
    Ok(())
}

fn system_call(
    evm: &mut impl Evm<Error: Display, DB: DatabaseCommit>,
    calldata: Vec<u8>,
    what: &str,
) -> Result<(), BlockExecutionError> {
    let mut state =
        match evm.transact_system_call(SYSTEM_ADDRESS, REGISTRY_ADDRESS, calldata.into()) {
            Ok(res) => res.state,
            Err(e) => {
                return Err(BlockExecutionError::Internal(
                    InternalBlockExecutionError::Other(
                        format!("{what} system call reverted: {e}").into(),
                    ),
                ));
            }
        };
    state.remove(&SYSTEM_ADDRESS);
    evm.db_mut().commit(state);
    Ok(())
}
