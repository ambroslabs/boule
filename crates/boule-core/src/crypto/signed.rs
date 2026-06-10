use anyhow::{Context as _, Result, bail};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

use crate::crypto::sig_scheme::SignatureScheme;
use crate::identity::NodeId;
use crate::identity::NodeIdentity;

pub trait Signer: Send + Sync {
    fn node_id(&self) -> NodeId;
    fn sign(&self, msg: &[u8]) -> [u8; 64];
}

pub struct NodeSigner {
    node_id: NodeId,
    key: Ed25519KeyPair,
}

impl NodeSigner {
    pub fn from_identity(identity: &NodeIdentity) -> Result<Self> {
        let key = Ed25519KeyPair::from_pkcs8_maybe_unchecked(&identity.pkcs8_der)
            .map_err(|e| anyhow::anyhow!("parsing node key as Ed25519 PKCS#8: {e}"))?;
        let node_id: NodeId = key
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected 32-byte Ed25519 public key"))?;
        Ok(Self { node_id, key })
    }
}

impl Signer for NodeSigner {
    fn node_id(&self) -> NodeId {
        self.node_id
    }

    fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let sig = self.key.sign(msg);
        let mut out = [0u8; 64];
        out.copy_from_slice(sig.as_ref());
        out
    }
}

pub trait PartialSigner<S: SignatureScheme>: Send + Sync {
    fn pubkey(&self) -> S::PublicKey;

    fn sign_partial(&self, msg: &[u8]) -> S::PartialSig;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChainId(pub [u8; 32]);

impl ChainId {
    pub const fn from_genesis_hash(hash: [u8; 32]) -> Self {
        Self(hash)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub trait SignedMessage {
    const DOMAIN: &'static str;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed<T> {
    pub payload: T,
    pub signer: NodeId,
    #[serde(with = "serde_sig")]
    pub sig: [u8; 64],
}

impl<T> Signed<T>
where
    T: Serialize + SignedMessage,
{
    pub fn sign<S: Signer + ?Sized>(payload: T, signer: &S, chain_id: &ChainId) -> Result<Self> {
        let bytes = preimage::<T>(&payload, chain_id)?;
        let sig = signer.sign(&bytes);
        Ok(Self {
            payload,
            signer: signer.node_id(),
            sig,
        })
    }

    pub fn verify(&self, expected_signer: &NodeId, chain_id: &ChainId) -> Result<()> {
        if &self.signer != expected_signer {
            bail!("signer mismatch: envelope claims a different NodeId");
        }
        let bytes = preimage::<T>(&self.payload, chain_id)?;
        UnparsedPublicKey::new(&ED25519, expected_signer as &[u8])
            .verify(&bytes, &self.sig)
            .map_err(|_| anyhow::anyhow!("signature verification failed"))
    }
}

pub fn preimage<T: Serialize + SignedMessage>(payload: &T, chain_id: &ChainId) -> Result<Vec<u8>> {
    let domain = T::DOMAIN.as_bytes();
    if domain.len() > u32::MAX as usize {
        bail!("domain tag too long");
    }
    let body = postcard::to_stdvec(payload).context("serializing payload for signing")?;
    let mut out = Vec::with_capacity(32 + 4 + domain.len() + body.len());
    out.extend_from_slice(chain_id.as_bytes());
    out.extend_from_slice(&(domain.len() as u32).to_be_bytes());
    out.extend_from_slice(domain);
    out.extend_from_slice(&body);
    Ok(out)
}

mod serde_sig {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(sig: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&sig[..], s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Vec::<u8>::deserialize(d)?;
        v.as_slice()
            .try_into()
            .map_err(|_| D::Error::custom("signature must be exactly 64 bytes"))
    }
}
