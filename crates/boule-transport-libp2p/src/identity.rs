use anyhow::{Context, Result};
use boule_core::identity::NodeId;
use libp2p::identity::{self, PeerId, PublicKey};

pub use libp2p::identity::Keypair;

const IDENTITY_MULTIHASH_CODE: u64 = 0x00;

pub fn public_key_for(node_id: &NodeId) -> Result<PublicKey> {
    let ed = identity::ed25519::PublicKey::try_from_bytes(node_id)
        .context("NodeId is not a valid Ed25519 public key")?;
    Ok(PublicKey::from(ed))
}

pub fn peer_id_for(node_id: &NodeId) -> Result<PeerId> {
    Ok(public_key_for(node_id)?.to_peer_id())
}

pub fn node_id_for(peer_id: &PeerId) -> Option<NodeId> {
    let mh = peer_id.as_ref();
    if mh.code() != IDENTITY_MULTIHASH_CODE {
        return None;
    }

    let pk = PublicKey::try_decode_protobuf(mh.digest()).ok()?;
    let ed = pk.try_into_ed25519().ok()?;
    Some(ed.to_bytes())
}

pub fn keypair_from_ed25519_secret(secret: [u8; 32]) -> Result<identity::Keypair> {
    identity::Keypair::ed25519_from_bytes(secret).context("invalid Ed25519 secret key bytes")
}

pub fn keypair_from_pkcs8_der(pkcs8_der: &[u8]) -> Result<identity::Keypair> {
    use ed25519_dalek::pkcs8::DecodePrivateKey;
    let signing = ed25519_dalek::SigningKey::from_pkcs8_der(pkcs8_der)
        .context("parsing node PKCS#8 DER as Ed25519")?;
    keypair_from_ed25519_secret(signing.to_bytes())
}
