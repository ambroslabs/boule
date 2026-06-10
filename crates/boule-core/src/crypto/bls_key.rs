use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use zeroize::Zeroizing;

use crate::crypto::sig_scheme::{BlsAggregated, BlsPartialSig, BlsPublicKey, BlsSecretKey};
use crate::crypto::signed::PartialSigner;

pub const FORMAT_VERSION: u8 = 1;

const FILE_LEN: usize = 1 + 32;

#[derive(Debug, Clone)]
pub struct BlsKeyFile {
    path: PathBuf,

    allow_insecure_perms: bool,
}

pub trait BlsKeyProvider: Send + Sync {
    fn load_or_init(&self) -> anyhow::Result<BlsValidatorIdentity>;

    fn try_load(&self) -> anyhow::Result<Option<BlsValidatorIdentity>>;

    fn name(&self) -> &'static str;
}

pub struct BlsValidatorIdentity {
    pub secret: Zeroizing<BlsSecretKey>,
    pub public: BlsPublicKey,
}

impl std::fmt::Debug for BlsValidatorIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlsValidatorIdentity")
            .field("secret", &"<redacted>")
            .field("public", &hex::encode(self.public))
            .finish()
    }
}

pub struct BlsPartialSignerImpl {
    secret: Zeroizing<BlsSecretKey>,
    public: BlsPublicKey,
}

impl BlsPartialSignerImpl {
    pub fn from_identity(id: BlsValidatorIdentity) -> Self {
        Self {
            secret: id.secret,
            public: id.public,
        }
    }
}

impl std::fmt::Debug for BlsPartialSignerImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlsPartialSignerImpl")
            .field("secret", &"<redacted>")
            .field("public", &hex::encode(self.public))
            .finish()
    }
}

impl PartialSigner<BlsAggregated> for BlsPartialSignerImpl {
    fn pubkey(&self) -> BlsPublicKey {
        self.public
    }

    fn sign_partial(&self, msg: &[u8]) -> BlsPartialSig {
        BlsAggregated::sign_partial(&self.secret, msg)
            .expect("loaded BLS secret keys must produce signatures")
    }
}

impl BlsKeyFile {
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

impl BlsKeyProvider for BlsKeyFile {
    fn name(&self) -> &'static str {
        "bls-file"
    }

    fn load_or_init(&self) -> anyhow::Result<BlsValidatorIdentity> {
        if self.path.exists() {
            let raw = fs::read(&self.path).context("reading BLS validator key")?;
            check_permissions(&self.path, self.allow_insecure_perms)?;
            decode_and_derive(&raw)
        } else {
            if let Some(parent) = self.path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent).context("creating BLS key directory")?;
                }
            }

            let mut ikm = Zeroizing::new([0u8; 32]);
            getrandom_or_panic(&mut ikm[..]);
            let (secret, public) = BlsAggregated::keygen(&ikm[..])
                .map_err(|e| anyhow::anyhow!("BLS keygen failed: {e}"))?;
            let secret = Zeroizing::new(secret);
            atomic_write(&self.path, &secret).context("writing BLS validator key")?;
            tracing::info!("generated new BLS validator key at {}", self.path.display(),);
            Ok(BlsValidatorIdentity { secret, public })
        }
    }

    fn try_load(&self) -> anyhow::Result<Option<BlsValidatorIdentity>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let raw = fs::read(&self.path).context("reading BLS validator key")?;
        check_permissions(&self.path, self.allow_insecure_perms)?;
        decode_and_derive(&raw).map(Some)
    }
}

fn decode_and_derive(raw: &[u8]) -> anyhow::Result<BlsValidatorIdentity> {
    if raw.len() != FILE_LEN {
        bail!(
            "BLS validator key file length {} != expected {} bytes",
            raw.len(),
            FILE_LEN,
        );
    }
    if raw[0] != FORMAT_VERSION {
        bail!(
            "BLS validator key file version {} not supported (expected {})",
            raw[0],
            FORMAT_VERSION,
        );
    }
    let mut secret = Zeroizing::new([0u8; 32]);
    secret[..].copy_from_slice(&raw[1..FILE_LEN]);

    let sk = blst::min_pk::SecretKey::from_bytes(&secret[..])
        .map_err(|e| anyhow::anyhow!("malformed BLS secret key on disk: {e:?}"))?;
    let public: BlsPublicKey = sk.sk_to_pk().to_bytes();
    Ok(BlsValidatorIdentity { secret, public })
}

fn atomic_write(path: &Path, secret: &BlsSecretKey) -> anyhow::Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let mut tmp = tempfile::NamedTempFile::new_in(&dir).context("opening temp BLS key file")?;
    {
        let f = tmp.as_file_mut();
        let mut buf = [0u8; FILE_LEN];
        buf[0] = FORMAT_VERSION;
        buf[1..].copy_from_slice(secret);
        f.write_all(&buf).context("writing BLS key bytes")?;
        f.sync_all().context("fsyncing BLS key file")?;
    }
    set_owner_only(tmp.path())?;
    tmp.persist(path)
        .map_err(|e| anyhow::anyhow!("renaming BLS key tempfile: {e}"))?;
    Ok(())
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_only(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn check_permissions(path: &Path, allow_insecure: bool) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    if allow_insecure {
        return Ok(());
    }
    let mode = fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .permissions()
        .mode();

    if mode & 0o077 != 0 {
        bail!(
            "BLS key file {} has insecure permissions (mode 0o{:o}); set 0o600 or pass allow_insecure_perms",
            path.display(),
            mode & 0o777,
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path, _allow_insecure: bool) -> anyhow::Result<()> {
    Ok(())
}

fn getrandom_or_panic(buf: &mut [u8]) {
    use rand::TryRngCore as _;
    rand::rngs::OsRng
        .try_fill_bytes(buf)
        .expect("OS RNG must produce key material");
}
