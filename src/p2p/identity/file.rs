//! File-backed identity: PKCS#8 PEM on disk with `0600` permissions.
//!
//! Read path accepts both PEM and legacy DER (auto-migrated to PEM + `0600`
//! on next startup). Write path is atomic: write to a temp file in the same
//! directory, fsync, then rename.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use tracing::{info, warn};

use super::{Encoding, KeyProvider, NodeIdentity, decode_pkcs8, der_to_pem, generate_pkcs8_der};

#[derive(Debug, Clone)]
pub struct FileKeyProvider {
    path: PathBuf,
    /// If true, skip the "world/group readable" permission check on read.
    /// For dev use only.
    allow_insecure_perms: bool,
}

impl FileKeyProvider {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            allow_insecure_perms: false,
        }
    }

    pub fn with_allow_insecure_perms(mut self, allow: bool) -> Self {
        self.allow_insecure_perms = allow;
        self
    }
}

impl KeyProvider for FileKeyProvider {
    fn name(&self) -> &'static str {
        "file"
    }

    fn load_or_init(&self) -> anyhow::Result<NodeIdentity> {
        if self.path.exists() {
            check_permissions(&self.path, self.allow_insecure_perms)?;
            let raw = fs::read(&self.path).context("reading node key")?;
            let (der, encoding) = decode_pkcs8(&raw).context("decoding node key")?;
            let identity = NodeIdentity { pkcs8_der: der };
            identity.validate().context("validating node key")?;

            if encoding == Encoding::Der {
                warn!(
                    "node key at {} is legacy DER; migrating to PEM and tightening permissions",
                    self.path.display()
                );
                let backup = self.path.with_extension("key.bak");
                if let Err(e) = fs::copy(&self.path, &backup) {
                    warn!("could not create DER backup at {}: {e}", backup.display());
                }
                atomic_write_pem(&self.path, &identity.pkcs8_der)
                    .context("rewriting node key as PEM")?;
            }

            Ok(identity)
        } else {
            if let Some(parent) = self.path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent).context("creating key directory")?;
                }
            }
            let der = generate_pkcs8_der()?;
            atomic_write_pem(&self.path, &der).context("writing node key")?;
            info!("generated new node key at {}", self.path.display());
            Ok(NodeIdentity { pkcs8_der: der })
        }
    }

    fn provision(&self, identity: &NodeIdentity) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).context("creating key directory")?;
            }
        }
        atomic_write_pem(&self.path, &identity.pkcs8_der).context("writing node key")?;
        info!("provisioned node key at {}", self.path.display());
        Ok(())
    }
}

fn atomic_write_pem(path: &Path, der: &[u8]) -> anyhow::Result<()> {
    let pem = der_to_pem(der);
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let mut builder = tempfile::Builder::new();
    builder.prefix(".node-key-").suffix(".tmp");

    let mut tmp = if let Some(dir) = dir {
        builder.tempfile_in(dir).context("creating temp key file")?
    } else {
        builder
            .tempfile_in(".")
            .context("creating temp key file in cwd")?
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let perms = fs::Permissions::from_mode(0o600);
        tmp.as_file()
            .set_permissions(perms)
            .context("setting 0600 on temp key file")?;
    }

    tmp.as_file_mut()
        .write_all(pem.as_bytes())
        .context("writing PEM to temp file")?;
    tmp.as_file_mut().sync_all().context("fsync on temp file")?;
    tmp.persist(path)
        .map_err(|e| anyhow::anyhow!("renaming temp file into place: {e}"))?;
    Ok(())
}

#[cfg(unix)]
fn check_permissions(path: &Path, allow_insecure: bool) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let meta = fs::metadata(path).context("stat'ing node key")?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        if allow_insecure {
            warn!(
                "node key at {} has permissive mode 0o{:o} (group/world bits set); proceeding because --allow-insecure-key-perms was given",
                path.display(),
                mode
            );
        } else {
            anyhow::bail!(
                "node key at {} has insecure permissions 0o{:o} (group or world readable). Run `chmod 600 {}` or pass --allow-insecure-key-perms to override.",
                path.display(),
                mode,
                path.display()
            );
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path, _allow_insecure: bool) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn generates_key_on_first_use() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.key");
        let provider = FileKeyProvider::new(path.clone());

        let id = provider.load_or_init().unwrap();
        id.validate().unwrap();
        assert!(path.exists());

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "new key should have mode 0600");

        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.starts_with("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn reuses_existing_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.key");
        let provider = FileKeyProvider::new(path.clone());

        let first = provider.load_or_init().unwrap();
        let second = provider.load_or_init().unwrap();
        assert_eq!(&first.pkcs8_der[..], &second.pkcs8_der[..]);
    }

    #[test]
    fn migrates_der_to_pem() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.key");
        let der = generate_pkcs8_der().unwrap();
        fs::write(&path, &der[..]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let provider = FileKeyProvider::new(path.clone());
        let id = provider.load_or_init().unwrap();
        assert_eq!(&id.pkcs8_der[..], &der[..]);

        let after = fs::read_to_string(&path).unwrap();
        assert!(after.starts_with("-----BEGIN PRIVATE KEY-----"));

        let backup = path.with_extension("key.bak");
        assert!(backup.exists());
        let backup_bytes = fs::read(&backup).unwrap();
        assert_eq!(backup_bytes, &der[..]);
    }

    #[test]
    fn rejects_world_readable_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.key");
        let der = generate_pkcs8_der().unwrap();
        fs::write(&path, der_to_pem(&der)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let err = FileKeyProvider::new(path.clone())
            .load_or_init()
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("insecure permissions"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn allow_insecure_flag_bypasses_perm_check() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.key");
        let der = generate_pkcs8_der().unwrap();
        fs::write(&path, der_to_pem(&der)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        FileKeyProvider::new(path)
            .with_allow_insecure_perms(true)
            .load_or_init()
            .unwrap();
    }
}
