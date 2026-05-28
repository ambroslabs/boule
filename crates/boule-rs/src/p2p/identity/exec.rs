//! External-command identity backend.
//!
//! Runs an operator-provided command and reads the key from its stdout.
//! Accepts PEM or raw DER. Exists to let operators integrate with Vault,
//! AWS Secrets Manager, cloud KMS, etc. by writing a small wrapper script
//! before a first-class backend lands.
//!
//! This backend is read-only: it cannot provision a new key. The command
//! must already have access to one.

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
        // The exec backend has no cheap "exists" check — running the
        // command is the only way to know. Defer to load_or_init and
        // report any failure as "no key here" so `init` can print the
        // externally-managed notice rather than crashing on the
        // operator's behalf.
        Ok(self.load_or_init().ok())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::p2p::identity::{der_to_pem, generate_pkcs8_der};
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;

    fn write_script(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
        let path = dir.join("emit-key.sh");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        f.sync_all().unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn reads_pem_from_stdout() {
        let dir = tempfile::tempdir().unwrap();
        let der = generate_pkcs8_der().unwrap();
        let pem = der_to_pem(&der);
        let key_file = dir.path().join("key.pem");
        std::fs::write(&key_file, &pem).unwrap();

        let script = write_script(
            dir.path(),
            &format!("#!/bin/sh\ncat {}\n", key_file.display()),
        );
        let provider = ExecKeyProvider::new(vec![script.display().to_string()]).unwrap();
        let id = provider.load_or_init().unwrap();
        assert_eq!(&id.pkcs8_der[..], &der[..]);
    }

    #[test]
    fn nonzero_exit_errors() {
        let dir = tempfile::tempdir().unwrap();
        let script = write_script(
            dir.path(),
            "#!/bin/sh\necho something went wrong >&2\nexit 1\n",
        );
        let err = ExecKeyProvider::new(vec![script.display().to_string()])
            .unwrap()
            .load_or_init()
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("exited"), "unexpected error: {msg}");
    }

    #[test]
    fn empty_argv_rejected() {
        let err = ExecKeyProvider::new(vec![]).unwrap_err();
        assert!(format!("{err}").contains("at least one"));
    }
}
