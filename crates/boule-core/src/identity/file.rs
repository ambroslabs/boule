use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use tracing::{info, warn};

use super::{Encoding, KeyProvider, NodeIdentity, decode_pkcs8, der_to_pem, generate_pkcs8_der};

#[derive(Debug, Clone)]
pub struct FileKeyProvider {
    path: PathBuf,

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

    fn is_provisioning_capable(&self) -> bool {
        true
    }

    fn try_load(&self) -> anyhow::Result<Option<NodeIdentity>> {
        if !self.path.exists() {
            return Ok(None);
        }
        check_permissions(&self.path, self.allow_insecure_perms)?;
        let raw = fs::read(&self.path).context("reading node key")?;
        let (der, _encoding) = decode_pkcs8(&raw).context("decoding node key")?;
        let identity = NodeIdentity { pkcs8_der: der };
        identity.validate().context("validating node key")?;
        Ok(Some(identity))
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
