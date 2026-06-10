use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use boule_consensus::replication::mempool::Mempool;
use boule_core::crypto::signed::{ChainId, Signer};
use boule_core::identity::NodeId;

use crate::rotatable_signer::RotatableSigner;

pub const DEFAULT_V_EFF_MARGIN: u64 = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationReceipt {
    pub validator: NodeId,

    pub new_pubkey: NodeId,

    pub v_eff: u64,

    pub current_view: u64,
}

#[allow(dead_code)]
pub struct RotationHandle {
    self_id: NodeId,

    chain_id: ChainId,

    signing_view: Arc<AtomicU64>,

    mempool: Arc<dyn Mempool>,

    signer: Arc<RotatableSigner>,
}

impl RotationHandle {
    pub fn new(
        self_id: NodeId,
        chain_id: ChainId,
        signing_view: Arc<AtomicU64>,
        mempool: Arc<dyn Mempool>,
        signer: Arc<RotatableSigner>,
    ) -> Self {
        Self {
            self_id,
            chain_id,
            signing_view,
            mempool,
            signer,
        }
    }

    pub fn rotate(
        &self,
        _new_signer: Arc<dyn Signer>,
        _requested_v_eff: Option<u64>,
    ) -> anyhow::Result<RotationReceipt> {
        anyhow::bail!(
            "hot key rotation is not yet supported on BLS chains — a BLS rotation must \
             atomically swap the BLS key + proof-of-possession too (#358). Use the \
             commit-then-restart path for BLS chains."
        )
    }
}
