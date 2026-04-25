//! Pluggable node identity (Ed25519 private key) storage.
//!
//! The node's long-term identity is an Ed25519 key pair whose 32-byte public
//! key IS the node ID in the gossip overlay. A leaked private key lets an
//! attacker impersonate this node permanently, so key material must be
//! handled carefully and operators need flexibility in how keys are
//! sourced (file, env var, OS keyring, encrypted file, external command).
//!
//! All built-in backends today return exportable PKCS#8 DER bytes. The
//! trait intentionally hides that detail so a future non-exportable
//! backend (e.g. PKCS#11 / HSM) can plug in via a `NodeSigner` adapter
//! without changing call sites.

// Backends expose small, operator-facing surfaces (constructors, one trait
// method). They're promoted to library-public items by lifting the crate to
// a library target, but their documentation burden is covered by the
// module-level doc above. Matches the `#[allow(missing_docs)]` style used on
// the other p2p submodules (connection, dialer, listener, manager, tls).
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

/// Loaded node identity: the PKCS#8 DER bytes of the Ed25519 key.
///
/// The DER buffer is zeroized when dropped. Callers should keep this
/// struct alive only long enough to build a `TlsIdentity`.
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
    /// Validate the bytes parse as an Ed25519 PKCS#8 key pair.
    pub fn validate(&self) -> anyhow::Result<()> {
        let pkcs8 = rustls::pki_types::PrivatePkcs8KeyDer::from(self.pkcs8_der.as_slice());
        KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &PKCS_ED25519)
            .context("parsing node key as Ed25519 PKCS#8 DER")?;
        Ok(())
    }
}

/// Source of the node's long-term private key.
///
/// Implementations load an existing key from their backing store, or
/// provision a fresh one on first use and persist it. Callers invoke
/// `load_or_init` exactly once at startup.
pub trait KeyProvider: Send + Sync {
    fn load_or_init(&self) -> anyhow::Result<NodeIdentity>;

    /// Human-readable name for logging ("file", "env", "keyring", ...).
    fn name(&self) -> &'static str;

    /// Overwrite the backend's stored key with the given identity. Used by
    /// the `key migrate` subcommand. Read-only backends return an error.
    fn provision(&self, _identity: &NodeIdentity) -> anyhow::Result<()> {
        anyhow::bail!("backend {} is read-only; cannot provision", self.name())
    }

    /// Whether this backend can autonomously create a fresh key on first
    /// use. Backends that wrap externally-managed key material (`env`,
    /// `exec`, OS keyring) return `false`; the `init` subcommand then
    /// prints an "externally managed" notice instead of generating one.
    fn is_provisioning_capable(&self) -> bool {
        false
    }

    /// Load the existing key without ever creating one. Returns `None`
    /// if the backing store does not yet hold a key. Used by both `init`
    /// (to detect first-time provisioning) and `start` (to refuse to
    /// run before `init` has been called).
    fn try_load(&self) -> anyhow::Result<Option<NodeIdentity>>;
}

// ── Shared helpers ──────────────────────────────────────────────────────────

/// Generate a fresh Ed25519 PKCS#8 DER key.
pub(crate) fn generate_pkcs8_der() -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let kp = KeyPair::generate_for(&PKCS_ED25519).context("generating Ed25519 key")?;
    Ok(Zeroizing::new(kp.serialize_der()))
}

/// Accept either PEM-encoded PKCS#8 or raw DER and return DER bytes.
///
/// DER starts with `0x30` (SEQUENCE). PEM starts with `-----BEGIN`. Anything
/// else is an error. Returns the decoded bytes plus a flag indicating the
/// source was DER (callers may use this to trigger auto-migration).
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

/// Serialize PKCS#8 DER as PEM (`-----BEGIN PRIVATE KEY-----`).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_pem_der() {
        let der = generate_pkcs8_der().unwrap();
        let pem = der_to_pem(&der);
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        let (back, encoding) = decode_pkcs8(pem.as_bytes()).unwrap();
        assert_eq!(encoding, Encoding::Pem);
        assert_eq!(&back[..], &der[..]);
    }

    #[test]
    fn decode_raw_der_passes_through() {
        let der = generate_pkcs8_der().unwrap();
        let (back, encoding) = decode_pkcs8(&der).unwrap();
        assert_eq!(encoding, Encoding::Der);
        assert_eq!(&back[..], &der[..]);
    }

    #[test]
    fn decode_junk_rejected() {
        let err = decode_pkcs8(b"not a key").unwrap_err();
        assert!(err.to_string().contains("neither PEM nor PKCS#8 DER"));
    }

    #[test]
    fn validate_accepts_generated_key() {
        let der = generate_pkcs8_der().unwrap();
        let id = NodeIdentity { pkcs8_der: der };
        id.validate().unwrap();
    }

    #[test]
    fn validate_rejects_garbage() {
        let id = NodeIdentity {
            pkcs8_der: Zeroizing::new(vec![0x30, 0x02, 0x05, 0x00]),
        };
        assert!(id.validate().is_err());
    }
}
