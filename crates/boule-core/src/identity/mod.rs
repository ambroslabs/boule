#![allow(missing_docs)]
pub mod encrypted_file;
pub mod env;
pub mod exec;
pub mod file;

#[cfg(feature = "keyring-backend")]
pub mod keyring;

use anyhow::Context as _;
use base64::Engine as _;
use rcgen::{KeyPair, PKCS_ED25519};
use zeroize::Zeroizing;

pub type NodeId = [u8; 32];

pub fn node_id_to_base58(id: &NodeId) -> String {
    bs58::encode(id).into_string()
}

pub fn base58_to_node_id(s: &str) -> anyhow::Result<NodeId> {
    let bytes = bs58::decode(s).into_vec().context("invalid base58")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("node ID must be 32 bytes"))
}

pub struct NodeIdentity {
    pub pkcs8_der: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeIdentity")
            .field(
                "pkcs8_der",
                &format_args!("<redacted, {} bytes>", self.pkcs8_der.len()),
            )
            .finish()
    }
}

impl NodeIdentity {
    pub fn validate(&self) -> anyhow::Result<()> {
        self.key_pair().map(|_| ())
    }

    pub fn node_id(&self) -> anyhow::Result<NodeId> {
        let kp = self.key_pair()?;
        kp.public_key_raw()
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected 32-byte Ed25519 public key"))
    }

    fn key_pair(&self) -> anyhow::Result<KeyPair> {
        let pkcs8 = rustls::pki_types::PrivatePkcs8KeyDer::from(self.pkcs8_der.as_slice());
        KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &PKCS_ED25519)
            .context("parsing node key as Ed25519 PKCS#8 DER")
    }
}

pub trait KeyProvider: Send + Sync {
    fn load_or_init(&self) -> anyhow::Result<NodeIdentity>;

    fn name(&self) -> &'static str;

    fn provision(&self, _identity: &NodeIdentity) -> anyhow::Result<()> {
        anyhow::bail!("backend {} is read-only; cannot provision", self.name())
    }

    fn is_provisioning_capable(&self) -> bool {
        false
    }

    fn try_load(&self) -> anyhow::Result<Option<NodeIdentity>>;
}

pub(crate) fn generate_pkcs8_der() -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let kp = KeyPair::generate_for(&PKCS_ED25519).context("generating Ed25519 key")?;
    Ok(Zeroizing::new(kp.serialize_der()))
}

pub(crate) fn decode_pkcs8(raw: &[u8]) -> anyhow::Result<(Zeroizing<Vec<u8>>, Encoding)> {
    if raw.first() == Some(&0x30) {
        return Ok((Zeroizing::new(raw.to_vec()), Encoding::Der));
    }
    if raw.starts_with(b"-----BEGIN") {
        let der = pem_to_der(raw).context("parsing PEM")?;
        return Ok((der, Encoding::Pem));
    }
    anyhow::bail!("key blob is neither PEM nor PKCS#8 DER");
}

pub fn der_to_pem(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::with_capacity(b64.len() + 64);
    out.push_str("-----BEGIN PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END PRIVATE KEY-----\n");
    out
}

fn pem_to_der(raw: &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let text = std::str::from_utf8(raw).context("PEM is not valid UTF-8")?;
    let mut body = String::new();
    let mut inside = false;
    for line in text.lines() {
        if line.starts_with("-----BEGIN") {
            if !line.contains("PRIVATE KEY") {
                anyhow::bail!("unexpected PEM label: {line}");
            }
            inside = true;
            continue;
        }
        if line.starts_with("-----END") {
            break;
        }
        if inside {
            body.push_str(line.trim());
        }
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .context("base64-decoding PEM body")?;
    Ok(Zeroizing::new(decoded))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Encoding {
    Der,
    Pem,
}
