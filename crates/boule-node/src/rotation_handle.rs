//! [`RotationHandle`] — the runtime trigger that would hot-rotate a
//! validator's consensus signing key on a live node, no restart (#707).
//!
//! Hot rotation is **not currently supported**: every chain is now a
//! `bls_aggregated` chain, and a BLS rotation must atomically swap the
//! BLS key + proof-of-possession too (#358), which the live-swap path
//! does not yet do. [`RotationHandle::rotate`] therefore errors. The
//! commit-then-restart rotation path (`boule rotation propose`) is the
//! supported route until the BLS hot-rotation follow-up lands.

use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use boule_consensus::replication::mempool::Mempool;
use boule_core::crypto::signed::{ChainId, Signer};
use boule_core::identity::NodeId;

use crate::rotatable_signer::RotatableSigner;

/// Default gap (in views) between the node's current view and a hot
/// rotation's `v_eff` when the operator does not request a specific one.
/// Retained for the admin surface's documentation; hot rotation itself is
/// not yet supported on a BLS chain (see the module docs).
pub const DEFAULT_V_EFF_MARGIN: u64 = 32;

/// What a hot rotation scheduled, returned to the operator for their records
/// (and so the receipt can be echoed by an admin endpoint / CLI).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationReceipt {
    /// The validator's stable id (unchanged by rotation).
    pub validator: NodeId,
    /// The key the validator will sign under at and after `v_eff`.
    pub new_pubkey: NodeId,
    /// The effective view the swap takes hold at.
    pub v_eff: u64,
    /// The node's current view when the rotation was triggered.
    pub current_view: u64,
}

/// Runtime handle bundling everything needed to trigger a hot rotation on a
/// live node. Cheap to `Arc`-share; all fields are handles into the running
/// node.
///
/// Hot rotation is not currently supported (every chain is `bls_aggregated`
/// and the live-swap path does not yet rotate the BLS half + PoP, #358), so
/// the held handles are dormant until that follow-up lands.
#[allow(dead_code)]
pub struct RotationHandle {
    /// Stable validator id — the rotation payload's `validator` field.
    self_id: NodeId,
    /// Deployment chain id; the rotation pre-image binds to it (#324).
    chain_id: ChainId,
    /// Shared current-view counter (advanced by the pacemaker) — read to
    /// pick a safe `v_eff`.
    signing_view: Arc<AtomicU64>,
    /// The node's mempool — the rotation tx is admitted here.
    mempool: Arc<dyn Mempool>,
    /// The live signer. Doubles as the `sig_old` signer (it signs with the
    /// currently-active key) and the target of `register_rotation`.
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

    /// Hot-rotate this node's consensus signing key to `new_signer`.
    ///
    /// **Not currently supported.** Every chain is a `bls_aggregated`
    /// chain, and a BLS rotation must atomically swap the BLS key +
    /// proof-of-possession too (#358), which the live-swap path does not
    /// yet do — so this always errors. Use the commit-then-restart path
    /// (`boule rotation propose`) instead.
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

#[cfg(test)]
mod tests {
    use super::*;
    use boule_consensus::replication::impls::InMemoryMempool;
    use boule_core::crypto::signed::NodeSigner;
    use boule_core::identity::NodeIdentity;
    use rcgen::{KeyPair as RcgenKeyPair, PKCS_ED25519};
    use zeroize::Zeroizing;

    fn fresh_signer() -> Arc<dyn Signer> {
        let kp = RcgenKeyPair::generate_for(&PKCS_ED25519).unwrap();
        let id = NodeIdentity {
            pkcs8_der: Zeroizing::new(kp.serialize_der()),
        };
        Arc::new(NodeSigner::from_identity(&id).unwrap())
    }

    /// Hot rotation is unsupported on a BLS chain — every chain is now a
    /// BLS chain, so `rotate` always errors and admits nothing.
    #[test]
    fn rotate_errors_on_bls_chains() {
        let genesis = fresh_signer();
        let view = Arc::new(AtomicU64::new(0));
        let signer = Arc::new(RotatableSigner::new(
            Arc::clone(&genesis),
            Arc::clone(&view),
        ));
        let mempool: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(64));
        let handle = RotationHandle::new(
            genesis.node_id(),
            ChainId::TEST,
            view,
            Arc::clone(&mempool),
            signer,
        );
        let err = handle
            .rotate(fresh_signer(), Some(60))
            .expect_err("BLS chains are unsupported");
        assert!(err.to_string().contains("BLS"), "{err}");
        assert_eq!(mempool.len(), 0);
    }
}
