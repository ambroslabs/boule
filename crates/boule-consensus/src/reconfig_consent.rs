use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::View;
use crate::endpoint_registry::EndpointEntry;
use crate::reconfig::ValidatorEntry;
use boule_core::crypto::sig_scheme::BlsPop;
use boule_core::crypto::signed::{ChainId, SignedMessage, Signer, preimage};
use boule_core::identity::NodeId;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconfigAddConsent {
    pub node_id: NodeId,

    pub addr: SocketAddr,

    pub bls_pop: Option<BlsPop>,

    pub weight: u64,

    pub operator_pubkey: NodeId,

    pub v_eff: View,

    pub initial_endpoints: Vec<EndpointEntry>,
}

impl SignedMessage for ReconfigAddConsent {
    const DOMAIN: &'static str = "boule.consensus.reconfig_add_consent.v1";
}

impl ReconfigAddConsent {
    pub fn for_entry(entry: &ValidatorEntry, v_eff: View) -> Option<Self> {
        let operator_pubkey = entry.operator_pubkey?;
        Some(Self {
            node_id: entry.node_id,
            addr: entry.addr,
            bls_pop: entry.bls_pop.clone(),
            weight: entry.weight,
            operator_pubkey,
            v_eff,
            initial_endpoints: entry.initial_endpoints.clone(),
        })
    }

    pub fn sign(
        &self,
        operator_signer: &dyn Signer,
        chain_id: &ChainId,
    ) -> anyhow::Result<[u8; 64]> {
        let bytes = preimage::<ReconfigAddConsent>(self, chain_id)?;
        Ok(operator_signer.sign(&bytes))
    }

    pub fn verify(&self, sig: &[u8; 64], chain_id: &ChainId) -> Result<(), ConsentVerifyError> {
        let bytes = preimage::<ReconfigAddConsent>(self, chain_id)
            .map_err(|e| ConsentVerifyError::Preimage(e.to_string()))?;
        UnparsedPublicKey::new(&ED25519, &self.operator_pubkey as &[u8])
            .verify(&bytes, sig)
            .map_err(|_| ConsentVerifyError::InvalidConsentSignature)?;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConsentVerifyError {
    InvalidConsentSignature,

    Preimage(String),
}

impl std::fmt::Display for ConsentVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConsentSignature => {
                f.write_str("reconfig add consent does not verify under the entry's operator key")
            }
            Self::Preimage(e) => write!(f, "computing reconfig-consent pre-image failed: {e}"),
        }
    }
}

impl std::error::Error for ConsentVerifyError {}
