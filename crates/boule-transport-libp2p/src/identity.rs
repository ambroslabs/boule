//! `NodeId` ↔ libp2p `PeerId` identity adapter.
//!
//! boule's [`NodeId`] is the raw 32-byte
//! Ed25519 public key. libp2p's `PeerId` for an Ed25519 key is the
//! *identity* multihash of the protobuf-encoded public key — because the
//! encoded key is ≤ 42 bytes, libp2p embeds it verbatim rather than hashing
//! it (SHA-256). That makes the mapping **1:1 and fully recoverable in both
//! directions, with no side table**, which is what lets libp2p slot in
//! behind the `Broadcaster`/`Discovery` seam without consensus learning a
//! new address type. See #840 / #841.
//!
//! (RSA / secp256k1 peers, whose keys exceed the identity-hash threshold,
//! are *not* recoverable from their `PeerId`. boule nodes are always
//! Ed25519, so [`node_id_for`] returning `None` means "not a boule node".)

use anyhow::{Context, Result};
use boule_core::identity::NodeId;
use libp2p::identity::{self, PeerId, PublicKey};

/// Multihash code for the identity hash (raw, un-hashed digest). Ed25519
/// `PeerId`s use this, which is what makes them reversible.
const IDENTITY_MULTIHASH_CODE: u64 = 0x00;

/// Reconstruct the libp2p [`PublicKey`] from a boule [`NodeId`].
pub fn public_key_for(node_id: &NodeId) -> Result<PublicKey> {
    let ed = identity::ed25519::PublicKey::try_from_bytes(node_id)
        .context("NodeId is not a valid Ed25519 public key")?;
    Ok(PublicKey::from(ed))
}

/// Derive the libp2p [`PeerId`] for a boule [`NodeId`] (raw Ed25519 pubkey).
pub fn peer_id_for(node_id: &NodeId) -> Result<PeerId> {
    Ok(public_key_for(node_id)?.to_peer_id())
}

/// Recover the boule [`NodeId`] from a libp2p [`PeerId`].
///
/// Returns `None` if the `PeerId` is not an Ed25519 identity-multihash
/// (i.e. not a boule node).
pub fn node_id_for(peer_id: &PeerId) -> Option<NodeId> {
    let mh = peer_id.as_ref();
    if mh.code() != IDENTITY_MULTIHASH_CODE {
        return None;
    }
    // For an identity multihash the digest IS the protobuf-encoded pubkey.
    let pk = PublicKey::try_decode_protobuf(mh.digest()).ok()?;
    let ed = pk.try_into_ed25519().ok()?;
    Some(ed.to_bytes())
}

/// Build a libp2p [`identity::Keypair`] from a raw 32-byte Ed25519 secret
/// (seed). Phase 1 (#841) uses this to key the libp2p TLS transport with the
/// node's existing consensus key, guaranteeing
/// `keypair.public().to_peer_id() == peer_id_for(node_id)`.
pub fn keypair_from_ed25519_secret(secret: [u8; 32]) -> Result<identity::Keypair> {
    identity::Keypair::ed25519_from_bytes(secret).context("invalid Ed25519 secret key bytes")
}

/// Build a libp2p [`identity::Keypair`] from a node's PKCS#8 DER private key
/// — the exact bytes every boule identity backend holds in
/// `NodeIdentity { pkcs8_der }`. This is how Phase 1 (#841) keys the libp2p
/// transport with the node's *existing* consensus key, so the libp2p
/// `PeerId` equals [`peer_id_for`] of the node's `NodeId` (no second key).
///
/// Accepts both RFC 8410 v1 (seed only) and v2 (seed + public key, as ring
/// emits) forms — the seed is extracted and the keypair re-derived from it.
pub fn keypair_from_pkcs8_der(pkcs8_der: &[u8]) -> Result<identity::Keypair> {
    use ed25519_dalek::pkcs8::DecodePrivateKey;
    let signing = ed25519_dalek::SigningKey::from_pkcs8_der(pkcs8_der)
        .context("parsing node PKCS#8 DER as Ed25519")?;
    keypair_from_ed25519_secret(signing.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;

    /// Generate an Ed25519 keypair and return its boule `NodeId` (raw pubkey).
    fn node_id_of(kp: &Keypair) -> NodeId {
        kp.public().try_into_ed25519().unwrap().to_bytes()
    }

    #[test]
    fn node_id_round_trips_through_peer_id() {
        let kp = Keypair::generate_ed25519();
        let node_id = node_id_of(&kp);

        let peer_id = peer_id_for(&node_id).unwrap();
        // The adapter's PeerId matches libp2p's own derivation.
        assert_eq!(peer_id, kp.public().to_peer_id());
        // And the NodeId is fully recoverable from the PeerId — no side table.
        let recovered = node_id_for(&peer_id).expect("Ed25519 PeerId is recoverable");
        assert_eq!(node_id, recovered);
    }

    #[test]
    fn keypair_from_secret_yields_matching_peer_id() {
        // Any 32 bytes are a valid Ed25519 seed.
        let secret = [7u8; 32];
        let kp = keypair_from_ed25519_secret(secret).unwrap();
        let node_id = node_id_of(&kp);

        // Phase 1's invariant: the transport keypair's PeerId equals the
        // PeerId the adapter derives from the node's NodeId.
        assert_eq!(kp.public().to_peer_id(), peer_id_for(&node_id).unwrap());
        assert_eq!(node_id_for(&kp.public().to_peer_id()).unwrap(), node_id);
    }

    #[test]
    fn rejects_non_ed25519_bytes() {
        // A 31-byte slice can never be an Ed25519 pubkey.
        let short = [0u8; 31];
        let ed = libp2p::identity::ed25519::PublicKey::try_from_bytes(&short);
        assert!(ed.is_err());
    }

    #[test]
    fn pkcs8_bridge_reproduces_node_identity() {
        // Generate a key in the EXACT PKCS#8 form boule's identity backends
        // store (ring's v2 OneAsymmetricKey with the public key included).
        use ring::signature::{Ed25519KeyPair, KeyPair};
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let ring_kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let node_id: NodeId = ring_kp.public_key().as_ref().try_into().unwrap();

        // The libp2p keypair built from the same DER must carry the same
        // identity the rest of boule addresses this node by.
        let libp2p_kp = keypair_from_pkcs8_der(pkcs8.as_ref()).unwrap();
        assert_eq!(
            libp2p_kp.public().to_peer_id(),
            peer_id_for(&node_id).unwrap()
        );
    }
}
