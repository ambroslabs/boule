use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use boule_core::crypto::signed::Signer;
use boule_core::identity::NodeId;
use parking_lot::RwLock;

struct KeyAt {
    v_eff: u64,
    signer: Arc<dyn Signer>,
}

pub struct RotatableSigner {
    current_view: Arc<AtomicU64>,

    entries: RwLock<Vec<KeyAt>>,
}

impl RotatableSigner {
    pub fn new(genesis: Arc<dyn Signer>, current_view: Arc<AtomicU64>) -> Self {
        Self {
            current_view,
            entries: RwLock::new(vec![KeyAt {
                v_eff: 0,
                signer: genesis,
            }]),
        }
    }

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

    fn active(&self) -> Arc<dyn Signer> {
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

impl Signer for RotatableSigner {
    fn node_id(&self) -> NodeId {
        self.active().node_id()
    }

    fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.active().sign(msg)
    }
}

struct BlsKeyAt {
    v_eff: u64,
    signer: Arc<
        dyn boule_core::crypto::signed::PartialSigner<boule_core::crypto::sig_scheme::BlsAggregated>,
    >,
}

pub struct RotatableBlsSigner {
    current_view: Arc<AtomicU64>,
    entries: RwLock<Vec<BlsKeyAt>>,
}

impl RotatableBlsSigner {
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
