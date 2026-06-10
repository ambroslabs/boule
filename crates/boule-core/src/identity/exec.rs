use std::process::Command;

use anyhow::Context as _;

use super::{KeyProvider, NodeIdentity, decode_pkcs8};

#[derive(Debug, Clone)]
pub struct ExecKeyProvider {
    argv: Vec<String>,
}

impl ExecKeyProvider {
    pub fn new(argv: Vec<String>) -> anyhow::Result<Self> {
        if argv.is_empty() {
            anyhow::bail!("exec backend requires at least one argv entry");
        }
        Ok(Self { argv })
    }
}

impl KeyProvider for ExecKeyProvider {
    fn name(&self) -> &'static str {
        "exec"
    }

    fn load_or_init(&self) -> anyhow::Result<NodeIdentity> {
        let (program, rest) = self.argv.split_first().expect("non-empty by construction");
        let output = Command::new(program)
            .args(rest)
            .output()
            .with_context(|| format!("spawning key command {program:?}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "key command {program:?} exited with {}: {}",
                output.status,
                stderr.trim()
            );
        }

        let (der, _) = decode_pkcs8(&output.stdout)
            .with_context(|| format!("decoding key from {program:?} stdout"))?;
        let id = NodeIdentity { pkcs8_der: der };
        id.validate().context("validating key from exec backend")?;
        Ok(id)
    }

    fn try_load(&self) -> anyhow::Result<Option<NodeIdentity>> {
        Ok(self.load_or_init().ok())
    }
}
