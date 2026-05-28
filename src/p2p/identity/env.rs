//! Environment-variable identity backend.
//!
//! Reads a base64-encoded PKCS#8 DER key (or PEM) from `env_var`. Never
//! writes to disk. Intended for K8s secret-volume-as-env or CI pipelines.

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

        // Allow both PEM (with BEGIN/END lines) and base64 of DER.
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
        // Only attempt the actual decode if the env var is present —
        // an unset var means "no key here" (the operator hasn't wired
        // it up yet) and is the sentinel `init` looks for.
        match std::env::var(&self.env_var) {
            Ok(_) => Ok(Some(self.load_or_init()?)),
            Err(_) => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::identity::{der_to_pem, generate_pkcs8_der};

    // Env vars are process-global; pick names unique to each test.

    #[test]
    fn loads_base64_der() {
        let der = generate_pkcs8_der().unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der[..]);
        let var = "BOULE_TEST_KEY_B64";
        // SAFETY: test-only, no other thread reads this var
        unsafe { std::env::set_var(var, b64) };

        let id = EnvKeyProvider::new(var).load_or_init().unwrap();
        assert_eq!(&id.pkcs8_der[..], &der[..]);

        unsafe { std::env::remove_var(var) };
    }

    #[test]
    fn loads_pem() {
        let der = generate_pkcs8_der().unwrap();
        let pem = der_to_pem(&der);
        let var = "BOULE_TEST_KEY_PEM";
        unsafe { std::env::set_var(var, pem) };

        let id = EnvKeyProvider::new(var).load_or_init().unwrap();
        assert_eq!(&id.pkcs8_der[..], &der[..]);

        unsafe { std::env::remove_var(var) };
    }

    #[test]
    fn missing_env_errors() {
        let err = EnvKeyProvider::new("BOULE_DEFINITELY_NOT_SET_KEY_XZ42")
            .load_or_init()
            .unwrap_err();
        assert!(format!("{err}").contains("reading env var"));
    }

    #[test]
    fn bad_base64_errors() {
        let var = "BOULE_TEST_KEY_BAD";
        unsafe { std::env::set_var(var, "$$$not-base64$$$") };
        let err = EnvKeyProvider::new(var).load_or_init().unwrap_err();
        assert!(format!("{err}").contains("base64"));
        unsafe { std::env::remove_var(var) };
    }

    #[test]
    fn malformed_key_rejected() {
        let var = "BOULE_TEST_KEY_MALFORMED";
        // valid base64 but not a valid PKCS#8 key
        let b64 = base64::engine::general_purpose::STANDARD.encode([0x30u8, 0x02, 0x05, 0x00]);
        unsafe { std::env::set_var(var, b64) };
        let err = EnvKeyProvider::new(var).load_or_init().unwrap_err();
        assert!(
            format!("{err:#}").contains("Ed25519"),
            "expected Ed25519 validation error, got: {err:#}"
        );
        unsafe { std::env::remove_var(var) };
    }
}
