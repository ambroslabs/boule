use anyhow::Context as _;
use base64::Engine as _;

use super::{KeyProvider, NodeIdentity, decode_pkcs8};

#[derive(Debug, Clone)]
pub struct EnvKeyProvider {
    env_var: String,
}

impl EnvKeyProvider {
    pub fn new(env_var: impl Into<String>) -> Self {
        Self {
            env_var: env_var.into(),
        }
    }
}

impl KeyProvider for EnvKeyProvider {
    fn name(&self) -> &'static str {
        "env"
    }

    fn load_or_init(&self) -> anyhow::Result<NodeIdentity> {
        let raw = std::env::var(&self.env_var)
            .with_context(|| format!("reading env var {}", self.env_var))?;

        let der = if raw.contains("-----BEGIN") {
            let (der, _) = decode_pkcs8(raw.as_bytes())?;
            der
        } else {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(raw.trim().as_bytes())
                .with_context(|| format!("base64-decoding {} value", self.env_var))?;
            let (der, _) = decode_pkcs8(&bytes)?;
            der
        };

        let identity = NodeIdentity { pkcs8_der: der };
        identity
            .validate()
            .with_context(|| format!("validating key from {}", self.env_var))?;
        Ok(identity)
    }

    fn try_load(&self) -> anyhow::Result<Option<NodeIdentity>> {
        match std::env::var(&self.env_var) {
            Ok(_) => Ok(Some(self.load_or_init()?)),
            Err(_) => Ok(None),
        }
    }
}
