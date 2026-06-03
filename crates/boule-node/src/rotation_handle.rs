//! [`RotationHandle`] — the runtime trigger that hot-rotates a validator's
//! consensus signing key on a live node, no restart (#707).
//!
//! [`RotatableSigner`](crate::rotatable_signer::RotatableSigner) (#312) is the
//! *mechanism*: it swaps the active signing key at a rotation's `v_eff`. What
//! was missing was the operator-facing *trigger* to actually drive it on a
//! running node. `RotationHandle` is that trigger. Given a freshly-minted new
//! signing key, it:
//!
//! 1. computes a safe future `v_eff` from the node's current view,
//! 2. builds the dual-signed [`DualSignedRotation`] envelope — `sig_old` by the
//!    node's *currently-active* key (via the [`RotatableSigner`] itself, which
//!    signs with the live key) and `sig_new` by the new key,
//! 3. submits that envelope into the node's own mempool, so the next leader
//!    commits it and every replica's key history records the rotation, and
//! 4. registers the rotation with the live [`RotatableSigner`] so this node
//!    swaps to the new key at `v_eff` without a restart.
//!
//! Steps 2–4 happen on the running node from in-memory state — no config file
//! re-read, no disk key load for the *old* key (the [`RotatableSigner`] already
//! holds it). The caller supplies the *new* signer (loaded/minted from wherever
//! the operator keeps it).
//!
//! # Why this is safe to expose
//!
//! Registering a rotation only schedules *this* node to sign with a different
//! key at `v_eff`. For those post-`v_eff` messages to be *accepted*, the
//! matching `DualSignedRotation` must also commit on-chain (step 3) — and
//! building it requires the node's current signing key to produce `sig_old`.
//! A spurious registration with no committed tx just makes the node go silent
//! at `v_eff` (a self-inflicted liveness fault, recoverable by rotating again),
//! never a takeover: it cannot forge acceptance of a key the chain didn't
//! record.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use boule_consensus::View;
use boule_consensus::replication::mempool::Mempool;
use boule_consensus::validator_rotation::{
    DualSignedRotation, V_EFF_MIN_DELAY, ValidatorKeyRotation,
};
use boule_core::crypto::sig_scheme::SignatureSchemeChoice;
use boule_core::crypto::signed::{ChainId, Signer};
use boule_core::identity::NodeId;

use crate::rotatable_signer::RotatableSigner;

/// Default gap (in views) between the node's current view and a hot
/// rotation's `v_eff` when the operator does not request a specific one.
///
/// Generous on purpose: the rotation tx must first *commit* (≈3 views under
/// the happy path, more under timeouts) and only then may `v_eff` land
/// (`>= commit_view + V_EFF_MIN_DELAY`). A wide default absorbs commit
/// latency so the swap is not overtaken by its own boundary. Operators who
/// want a tighter or later boundary pass an explicit `v_eff`.
pub const DEFAULT_V_EFF_MARGIN: u64 = 32;

/// The minimum gap a *requested* `v_eff` must clear above the current view:
/// enough for the tx to commit (≈3) plus the [`V_EFF_MIN_DELAY`] the apply
/// path enforces, with a little slack. A request below this is rejected
/// rather than silently bumped, so the operator's intent is never altered.
const MIN_REQUESTED_V_EFF_MARGIN: u64 = V_EFF_MIN_DELAY.0 + 5;

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
pub struct RotationHandle {
    /// Stable validator id — the rotation payload's `validator` field.
    self_id: NodeId,
    /// Deployment chain id; the rotation pre-image binds to it (#324).
    chain_id: ChainId,
    /// The chain's signature scheme. Hot rotation is Ed25519-only for now
    /// (BLS chains must also rotate the BLS half + PoP — a follow-up).
    scheme: SignatureSchemeChoice,
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
        scheme: SignatureSchemeChoice,
        signing_view: Arc<AtomicU64>,
        mempool: Arc<dyn Mempool>,
        signer: Arc<RotatableSigner>,
    ) -> Self {
        Self {
            self_id,
            chain_id,
            scheme,
            signing_view,
            mempool,
            signer,
        }
    }

    /// Hot-rotate this node's consensus signing key to `new_signer`, taking
    /// effect at `requested_v_eff` (or a safe default if `None`). Builds +
    /// admits the dual-signed rotation tx and schedules the live swap.
    ///
    /// Errors if the chain is BLS (unsupported here), if a requested `v_eff`
    /// is too close to the current view to commit in time, or if a later
    /// rotation is already scheduled on the signer (non-monotonic `v_eff`).
    pub fn rotate(
        &self,
        new_signer: Arc<dyn Signer>,
        requested_v_eff: Option<u64>,
    ) -> anyhow::Result<RotationReceipt> {
        if matches!(self.scheme, SignatureSchemeChoice::BlsAggregated) {
            anyhow::bail!(
                "hot key rotation is not yet supported on BLS chains — a BLS rotation must \
                 atomically swap the BLS key + proof-of-possession too (#358). Use the \
                 commit-then-restart path for BLS chains."
            );
        }

        let current_view = self.signing_view.load(Ordering::Relaxed);
        let v_eff = match requested_v_eff {
            Some(req) => {
                let min = current_view + MIN_REQUESTED_V_EFF_MARGIN;
                if req < min {
                    anyhow::bail!(
                        "requested v_eff {req} is too close to the current view {current_view}: \
                         the rotation tx must commit and then take effect, so v_eff must be \
                         >= {min}. Pass a larger v_eff or omit it for the default \
                         (current + {DEFAULT_V_EFF_MARGIN})."
                    );
                }
                req
            }
            None => current_view + DEFAULT_V_EFF_MARGIN,
        };

        let payload = ValidatorKeyRotation {
            validator: self.self_id,
            new_pubkey: new_signer.node_id(),
            v_eff: View(v_eff),
            new_bls_pubkey: None,
            new_bls_pop: None,
        };

        // Build + sign BEFORE registering: `sig_old` is produced by the
        // currently-active key via the RotatableSigner (`&*self.signer`).
        // Because `v_eff > current_view`, registering would not change the
        // active key yet — but signing first keeps the ordering obviously
        // correct regardless.
        let envelope =
            DualSignedRotation::sign(payload, &*self.signer, &*new_signer, &self.chain_id)?;
        let cmd = envelope.encode_command();

        // Admit into the node's own mempool so the next leader commits it
        // and every replica records the rotation in its key history.
        self.mempool
            .insert(cmd)
            .map_err(|e| anyhow::anyhow!("admitting rotation tx into the mempool failed: {e}"))?;

        // Schedule the live swap. `register_rotation` enforces strict-
        // monotone `v_eff`, so a stale/duplicate request is refused.
        if !self
            .signer
            .register_rotation(v_eff, Arc::clone(&new_signer))
        {
            anyhow::bail!(
                "could not register the rotation at v_eff {v_eff}: a rotation with an equal or \
                 later v_eff is already scheduled on this node's signer"
            );
        }

        Ok(RotationReceipt {
            validator: self.self_id,
            new_pubkey: new_signer.node_id(),
            v_eff,
            current_view,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boule_consensus::replication::impls::InMemoryMempool;
    use boule_consensus::validator_rotation::DualSignedRotation;
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

    fn handle_with(
        genesis: Arc<dyn Signer>,
        view: Arc<AtomicU64>,
    ) -> (RotationHandle, Arc<RotatableSigner>, Arc<dyn Mempool>) {
        let signer = Arc::new(RotatableSigner::new(
            Arc::clone(&genesis),
            Arc::clone(&view),
        ));
        let mempool: Arc<dyn Mempool> = Arc::new(InMemoryMempool::new(64));
        let handle = RotationHandle::new(
            genesis.node_id(),
            ChainId::TEST,
            SignatureSchemeChoice::Ed25519Collected,
            view,
            Arc::clone(&mempool),
            Arc::clone(&signer),
        );
        (handle, signer, mempool)
    }

    #[test]
    fn rotate_admits_a_verifiable_tx_and_schedules_the_swap() {
        let genesis = fresh_signer();
        let view = Arc::new(AtomicU64::new(7));
        let (handle, signer, mempool) = handle_with(Arc::clone(&genesis), Arc::clone(&view));

        let new = fresh_signer();
        let receipt = handle
            .rotate(Arc::clone(&new), Some(60))
            .expect("rotate must succeed");
        assert_eq!(receipt.validator, genesis.node_id());
        assert_eq!(receipt.new_pubkey, new.node_id());
        assert_eq!(receipt.v_eff, 60);
        assert_eq!(receipt.current_view, 7);

        // The mempool holds exactly the rotation tx, and it verifies as a
        // dual-signed rotation: sig_old under the (genesis) current key,
        // sig_new under the new key, bound to the chain_id.
        let proposed = mempool.propose(16);
        assert_eq!(proposed.len(), 1);
        assert!(DualSignedRotation::is_rotation_payload(&proposed[0]));
        let env = DualSignedRotation::decode_command(&proposed[0]).unwrap();
        assert_eq!(env.payload.validator, genesis.node_id());
        assert_eq!(env.payload.new_pubkey, new.node_id());
        assert_eq!(env.payload.v_eff, View(60));
        env.verify(&genesis.node_id(), &ChainId::TEST)
            .expect("envelope must verify under the current (genesis) key + chain_id");

        // The live signer swaps to the new key at v_eff, no restart.
        view.store(59, Ordering::Relaxed);
        assert_eq!(signer.node_id(), genesis.node_id());
        view.store(60, Ordering::Relaxed);
        assert_eq!(signer.node_id(), new.node_id());
    }

    #[test]
    fn rotate_defaults_v_eff_when_unspecified() {
        let genesis = fresh_signer();
        let view = Arc::new(AtomicU64::new(100));
        let (handle, _signer, _mempool) = handle_with(genesis, Arc::clone(&view));

        let receipt = handle.rotate(fresh_signer(), None).expect("must succeed");
        assert_eq!(receipt.v_eff, 100 + DEFAULT_V_EFF_MARGIN);
    }

    #[test]
    fn rotate_rejects_a_v_eff_too_close_to_now() {
        let genesis = fresh_signer();
        let view = Arc::new(AtomicU64::new(100));
        let (handle, _signer, mempool) = handle_with(genesis, view);

        let err = handle
            .rotate(fresh_signer(), Some(101))
            .expect_err("v_eff one view out must be rejected");
        assert!(err.to_string().contains("too close"), "{err}");
        // Nothing was admitted on the rejected path.
        assert_eq!(mempool.len(), 0);
    }

    #[test]
    fn rotate_rejects_when_a_later_rotation_is_already_scheduled() {
        let genesis = fresh_signer();
        let view = Arc::new(AtomicU64::new(10));
        let (handle, _signer, _mempool) = handle_with(genesis, view);

        handle.rotate(fresh_signer(), Some(80)).expect("first ok");
        // A second rotation at an earlier-or-equal v_eff is refused by the
        // signer's monotonicity guard.
        let err = handle
            .rotate(fresh_signer(), Some(80))
            .expect_err("non-monotonic v_eff must be rejected");
        assert!(err.to_string().contains("already scheduled"), "{err}");
    }

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
            SignatureSchemeChoice::BlsAggregated,
            view,
            mempool,
            signer,
        );
        let err = handle
            .rotate(fresh_signer(), Some(60))
            .expect_err("BLS chains are unsupported");
        assert!(err.to_string().contains("BLS"), "{err}");
    }
}
