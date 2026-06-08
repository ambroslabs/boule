//! [`RotatableSigner`] — a [`Signer`] that swaps its consensus signing key at
//! a rotation's effective view, *without* a binary restart (#312).
//!
//! # The gap this closes
//!
//! A validator's consensus loop signs votes/proposals through a fixed
//! [`NodeSigner`](boule_core::crypto::signed::NodeSigner). After a committed
//! key rotation (#142/#258) takes effect at `v_eff`, the verify path
//! ([`verify_signer_at`](boule_consensus::dispatch) and friends) enforces that
//! a message's wire `signer` equals the key **active at the message's view** —
//! so a vote still signed under the *old* key at `view >= v_eff` is rejected.
//! With a fixed signer the rotated validator therefore goes silent at `v_eff`
//! until its operator restarts the binary pointed at the new key. That restart
//! is the operational wart #312 removes.
//!
//! # How it works
//!
//! `RotatableSigner` holds a `v_eff`-ordered list of `(v_eff, inner signer)`
//! entries and a shared *current-view* counter (the same atomic the pacemaker
//! advances). [`Signer::node_id`] and [`Signer::sign`] both resolve to the
//! entry with the largest `v_eff <= current_view` — i.e. the key active right
//! now. Because the stable validator identity lives elsewhere
//! (`ConsensusNode.self_id`, `block.header.proposer`, the leader selector all
//! use the genesis id, not `signer.node_id()`), reporting the *active* key from
//! `node_id()` is exactly what the wire layer wants: the envelope's `signer`
//! field becomes the new key at `v_eff`, which the verifier resolves back to
//! the stable id through the validator-key history.
//!
//! [`register_rotation`](RotatableSigner::register_rotation) appends a key with
//! interior mutability, so the running node can learn its own committed
//! rotation and schedule the swap with no restart.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use boule_core::crypto::signed::Signer;
use boule_core::identity::NodeId;
use parking_lot::RwLock;

/// One scheduled key: at and after view `v_eff`, sign with `signer`.
struct KeyAt {
    v_eff: u64,
    signer: Arc<dyn Signer>,
}

/// A view-aware [`Signer`] that swaps signing keys at rotation boundaries.
/// See the module docs. Cheap to `Arc`-share: `node_id`/`sign` take `&self`
/// and only read the current view + a short entry list under a read lock.
pub struct RotatableSigner {
    /// The cluster's current view, advanced by the pacemaker. Reads pick the
    /// key active at this view.
    current_view: Arc<AtomicU64>,
    /// `(v_eff, signer)` entries, kept sorted ascending by `v_eff` with a
    /// genesis entry at `v_eff = 0` always present at index 0.
    entries: RwLock<Vec<KeyAt>>,
}

impl RotatableSigner {
    /// A signer active from view 0 with `genesis`, reading `current_view` to
    /// decide which key is live. `current_view` is shared with the pacemaker
    /// (or, in tests, driven by hand).
    pub fn new(genesis: Arc<dyn Signer>, current_view: Arc<AtomicU64>) -> Self {
        Self {
            current_view,
            entries: RwLock::new(vec![KeyAt {
                v_eff: 0,
                signer: genesis,
            }]),
        }
    }

    /// Schedule `new_signer` to become active at and after `v_eff`. Returns
    /// `false` (and ignores the request) if `v_eff` is not strictly greater
    /// than the latest scheduled `v_eff` — the same monotonicity the key
    /// history enforces, so a duplicate or stale rotation can't reorder keys.
    pub fn register_rotation(&self, v_eff: u64, new_signer: Arc<dyn Signer>) -> bool {
        let mut entries = self.entries.write();
        let last_v_eff = entries
            .last()
            .expect("entries always has the genesis entry")
            .v_eff;
        if v_eff <= last_v_eff {
            return false;
        }
        entries.push(KeyAt {
            v_eff,
            signer: new_signer,
        });
        true
    }

    /// The signer active at the current view — the entry with the largest
    /// `v_eff <= current_view`.
    fn active(&self) -> Arc<dyn Signer> {
        let view = self.current_view.load(Ordering::Relaxed);
        let entries = self.entries.read();
        entries
            .iter()
            .rev()
            .find(|k| k.v_eff <= view)
            .map(|k| Arc::clone(&k.signer))
            // Pre-genesis views (shouldn't happen — genesis is v_eff 0) fall
            // back to the genesis key.
            .unwrap_or_else(|| Arc::clone(&entries[0].signer))
    }
}

impl Signer for RotatableSigner {
    fn node_id(&self) -> NodeId {
        self.active().node_id()
    }

    fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.active().sign(msg)
    }
}

/// One scheduled BLS partial signer: at and after view `v_eff`, fold
/// partials with `signer`.
struct BlsKeyAt {
    v_eff: u64,
    signer: Arc<
        dyn boule_core::crypto::signed::PartialSigner<boule_core::crypto::sig_scheme::BlsAggregated>,
    >,
}

/// BLS analogue of [`RotatableSigner`] (#358 hot-swap): a view-aware
/// [`PartialSigner`](boule_core::crypto::signed::PartialSigner) that swaps the
/// BLS partial-signing key at a rotation's effective view, without a restart.
///
/// On a BLS-only chain a dual key rotation rotates both the Ed25519 *and* the
/// BLS half. The Ed25519 half hot-swaps through [`RotatableSigner`]; this is
/// the BLS sibling, sharing the same `current_view` atomic so both halves flip
/// together at `v_eff`. Without it, a rotated validator that keeps leading
/// post-boundary would fold partials under its *old* BLS key, which the
/// dispatch-layer QC verifier (resolving the new BLS pubkey from history)
/// rejects.
pub struct RotatableBlsSigner {
    current_view: Arc<AtomicU64>,
    entries: RwLock<Vec<BlsKeyAt>>,
}

impl RotatableBlsSigner {
    /// A BLS partial signer active from view 0 with `genesis`, reading
    /// `current_view` (shared with the pacemaker / [`RotatableSigner`]) to
    /// decide which key is live.
    pub fn new(
        genesis: Arc<
            dyn boule_core::crypto::signed::PartialSigner<
                    boule_core::crypto::sig_scheme::BlsAggregated,
                >,
        >,
        current_view: Arc<AtomicU64>,
    ) -> Self {
        Self {
            current_view,
            entries: RwLock::new(vec![BlsKeyAt {
                v_eff: 0,
                signer: genesis,
            }]),
        }
    }

    /// Schedule `new_signer` to become active at and after `v_eff`. Returns
    /// `false` (and ignores the request) on a non-monotonic `v_eff`, matching
    /// [`RotatableSigner::register_rotation`].
    pub fn register_rotation(
        &self,
        v_eff: u64,
        new_signer: Arc<
            dyn boule_core::crypto::signed::PartialSigner<
                    boule_core::crypto::sig_scheme::BlsAggregated,
                >,
        >,
    ) -> bool {
        let mut entries = self.entries.write();
        let last_v_eff = entries
            .last()
            .expect("entries always has the genesis entry")
            .v_eff;
        if v_eff <= last_v_eff {
            return false;
        }
        entries.push(BlsKeyAt {
            v_eff,
            signer: new_signer,
        });
        true
    }

    fn active(
        &self,
    ) -> Arc<
        dyn boule_core::crypto::signed::PartialSigner<boule_core::crypto::sig_scheme::BlsAggregated>,
    > {
        let view = self.current_view.load(Ordering::Relaxed);
        let entries = self.entries.read();
        entries
            .iter()
            .rev()
            .find(|k| k.v_eff <= view)
            .map(|k| Arc::clone(&k.signer))
            .unwrap_or_else(|| Arc::clone(&entries[0].signer))
    }
}

impl boule_core::crypto::signed::PartialSigner<boule_core::crypto::sig_scheme::BlsAggregated>
    for RotatableBlsSigner
{
    fn pubkey(&self) -> boule_core::crypto::sig_scheme::BlsPublicKey {
        self.active().pubkey()
    }

    fn sign_partial(&self, msg: &[u8]) -> boule_core::crypto::sig_scheme::BlsPartialSig {
        self.active().sign_partial(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn reports_genesis_key_before_any_rotation() {
        let genesis = fresh_signer();
        let view = Arc::new(AtomicU64::new(0));
        let rs = RotatableSigner::new(Arc::clone(&genesis), Arc::clone(&view));
        assert_eq!(rs.node_id(), genesis.node_id());
        view.store(999, Ordering::Relaxed);
        assert_eq!(
            rs.node_id(),
            genesis.node_id(),
            "no rotation → always genesis"
        );
    }

    #[test]
    fn swaps_to_the_new_key_at_v_eff() {
        let genesis = fresh_signer();
        let new = fresh_signer();
        let view = Arc::new(AtomicU64::new(0));
        let rs = RotatableSigner::new(Arc::clone(&genesis), Arc::clone(&view));
        assert!(rs.register_rotation(10, Arc::clone(&new)));

        // Before v_eff: genesis key (id + signatures).
        view.store(9, Ordering::Relaxed);
        assert_eq!(rs.node_id(), genesis.node_id());
        // At and after v_eff: the new key.
        view.store(10, Ordering::Relaxed);
        assert_eq!(rs.node_id(), new.node_id());
        view.store(11, Ordering::Relaxed);
        assert_eq!(rs.node_id(), new.node_id());
    }

    #[test]
    fn signatures_track_the_active_key() {
        // Ed25519 (RFC 8032) signing is deterministic, so the rotatable
        // signer's output must be byte-identical to the active inner signer's
        // — and differ from the inactive one. This proves `sign` routes to the
        // key live at the current view, without pulling in a verifier.
        let genesis = fresh_signer();
        let new = fresh_signer();
        let view = Arc::new(AtomicU64::new(0));
        let rs = RotatableSigner::new(Arc::clone(&genesis), Arc::clone(&view));
        rs.register_rotation(10, Arc::clone(&new));
        let msg = b"a consensus message";

        // Pre-rotation: signs with the genesis key.
        view.store(5, Ordering::Relaxed);
        let sig = rs.sign(msg);
        assert_eq!(
            sig,
            genesis.sign(msg),
            "pre-rotation sig must be the genesis key's"
        );
        assert_ne!(sig, new.sign(msg));

        // Post-rotation: signs with the new key, not the stale genesis key.
        view.store(10, Ordering::Relaxed);
        let sig = rs.sign(msg);
        assert_eq!(
            sig,
            new.sign(msg),
            "post-rotation sig must be the new key's"
        );
        assert_ne!(
            sig,
            genesis.sign(msg),
            "post-rotation sig must not be the stale key's"
        );
    }

    #[test]
    fn register_rotation_rejects_non_monotonic_v_eff() {
        let genesis = fresh_signer();
        let view = Arc::new(AtomicU64::new(0));
        let rs = RotatableSigner::new(genesis, view);
        assert!(rs.register_rotation(10, fresh_signer()));
        // Equal or earlier v_eff is refused (keeps the timeline ordered).
        assert!(!rs.register_rotation(10, fresh_signer()));
        assert!(!rs.register_rotation(5, fresh_signer()));
        assert!(rs.register_rotation(11, fresh_signer()));
    }

    #[test]
    fn supports_consecutive_rotations() {
        let genesis = fresh_signer();
        let k1 = fresh_signer();
        let k2 = fresh_signer();
        let view = Arc::new(AtomicU64::new(0));
        let rs = RotatableSigner::new(Arc::clone(&genesis), Arc::clone(&view));
        rs.register_rotation(10, Arc::clone(&k1));
        rs.register_rotation(20, Arc::clone(&k2));

        view.store(0, Ordering::Relaxed);
        assert_eq!(rs.node_id(), genesis.node_id());
        view.store(15, Ordering::Relaxed);
        assert_eq!(rs.node_id(), k1.node_id());
        view.store(25, Ordering::Relaxed);
        assert_eq!(rs.node_id(), k2.node_id());
    }
}
