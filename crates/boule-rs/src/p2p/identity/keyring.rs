//! OS keyring identity backend (macOS Keychain / Windows Credential Manager /
//! Linux Secret Service).
//!
//! Stores PKCS#8 DER as a binary secret under (service, account). Gated by
//! the `keyring-backend` cargo feature because the Linux backend needs a
//! running D-Bus / Secret Service daemon at runtime.

use anyhow::Context as _;
use base64::Engine as _;
use tracing::info;

use super::{KeyProvider, NodeIdentity, decode_pkcs8, generate_pkcs8_der};

#[derive(Debug, Clone)]
pub struct KeyringKeyProvider {
    service: String,
    account: String,
}

impl KeyringKeyProvider {
    pub fn new(service: impl Into<String>, account: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            account: account.into(),
        }
    }

    fn entry(&self) -> anyhow::Result<keyring::Entry> {
        keyring::Entry::new(&self.service, &self.account)
            .with_context(|| format!("opening keyring entry {}/{}", self.service, self.account))
    }
}

impl KeyProvider for KeyringKeyProvider {
    fn name(&self) -> &'static str {
        "keyring"
    }

    fn load_or_init(&self) -> anyhow::Result<NodeIdentity> {
        let entry = self.entry()?;
        match entry.get_password() {
            Ok(b64) => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(b64.trim().as_bytes())
                    .context("decoding keyring secret")?;
                let (der, _) = decode_pkcs8(&bytes)?;
                let id = NodeIdentity { pkcs8_der: der };
                id.validate().context("validating key from keyring")?;
                Ok(id)
            }
            Err(keyring::Error::NoEntry) => {
                let der = generate_pkcs8_der()?;
                let b64 = base64::engine::general_purpose::STANDARD.encode(&der[..]);
                entry.set_password(&b64).with_context(|| {
                    format!("writing to keyring {}/{}", self.service, self.account)
                })?;
                info!(
                    "generated new node key in OS keyring ({}:{})",
                    self.service, self.account
                );
                Ok(NodeIdentity { pkcs8_der: der })
            }
            Err(e) => Err(anyhow::Error::new(e).context(format!(
                "reading keyring entry {}/{}",
                self.service, self.account
            ))),
        }
    }

    fn provision(&self, identity: &NodeIdentity) -> anyhow::Result<()> {
        let entry = self.entry()?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&identity.pkcs8_der[..]);
        entry
            .set_password(&b64)
            .with_context(|| format!("writing to keyring {}/{}", self.service, self.account))?;
        info!(
            "provisioned node key in OS keyring ({}:{})",
            self.service, self.account
        );
        Ok(())
    }

    fn try_load(&self) -> anyhow::Result<Option<NodeIdentity>> {
        let entry = self.entry()?;
        match entry.get_password() {
            Ok(b64) => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(b64.trim().as_bytes())
                    .context("decoding keyring secret")?;
                let (der, _) = decode_pkcs8(&bytes)?;
                let id = NodeIdentity { pkcs8_der: der };
                id.validate().context("validating key from keyring")?;
                Ok(Some(id))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow::Error::new(e).context(format!(
                "reading keyring entry {}/{}",
                self.service, self.account
            ))),
        }
    }
}
