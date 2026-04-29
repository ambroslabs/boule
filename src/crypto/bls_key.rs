//! File-backed BLS validator-key persistence (#292).
//!
//! On chains whose genesis declares `signature_scheme = "bls_aggregated"`
//! every validator holds a separate BLS12-381 secret key for QC
//! signing, alongside the Ed25519 key that backs network identity (#141
//! split network identity from validator signing). This module loads,
//! generates, and persists the BLS half.
//!
//! # On-disk format
//!
//! Files are versioned to make rotation (#142) and format migrations
//! mechanical: the first byte is a [`FORMAT_VERSION`] tag, followed by
//! 32 raw secret-key bytes. PEM/PKCS#8 framing is unnecessary —
//! BLS12-381 keys aren't an X.509 algorithm — and would only obscure
//! the wire-format invariants.
//!
//! Permissions are tightened to `0o600` on write (matching the Ed25519
//! file backend in [`crate::p2p::identity::file`]).
//!
//! # Cross-scheme mismatch
//!
//! [`BlsKeyFile::load_or_init`] is the validator-side half of the
//! "node booted for the wrong scheme" check called out in
//! `crate::crypto::sig_scheme` and #288: a node whose genesis declares
//! BLS but cannot load (or generate) a BLS key here refuses to start.
//! The startup-time scheme/identity reconciliation lives in #293 where
//! the rest of the BLS integration is wired.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use zeroize::Zeroizing;

use crate::crypto::sig_scheme::{BlsAggregated, BlsPartialSig, BlsPop, BlsPublicKey, BlsSecretKey};
use crate::crypto::signed::PartialSigner;

/// Format version stamped at the head of the on-disk key file.
/// Bump when the layout changes; old files are then either migrated
/// or surfaced as a startup error.
pub const FORMAT_VERSION: u8 = 1;

/// On-disk file size: 1 version byte + 32 secret-key bytes.
const FILE_LEN: usize = 1 + 32;

/// File-backed [`BlsKeyProvider`]. Generates a fresh key on first
/// startup; persists to `path` with tight permissions; reloads on
/// subsequent boots.
#[derive(Debug, Clone)]
pub struct BlsKeyFile {
    path: PathBuf,
    /// Skip the "group/world readable" check on read. Dev escape hatch
    /// — production should leave this `false`.
    allow_insecure_perms: bool,
}

/// Trait surface for sourcing a validator's BLS signing key. Mirrors
/// the existing [`crate::p2p::identity::KeyProvider`] design but stays
/// scoped to BLS — TLS / network identity remains Ed25519 (parent
/// issue non-goal).
pub trait BlsKeyProvider: Send + Sync {
    /// Load an existing BLS validator key, or provision a fresh one if
    /// the backing store is empty. Returns the (secret, public,
    /// proof-of-possession) triple. The PoP is freshly computed from
    /// the secret on every load — no need to persist it separately.
    fn load_or_init(&self) -> anyhow::Result<BlsValidatorIdentity>;

    /// Try to load without creating. `None` if the backing store has no
    /// key yet — used by the startup reconciliation in #293 to
    /// distinguish "first boot needs init" from "operator forgot to
    /// configure BLS for a BLS chain."
    fn try_load(&self) -> anyhow::Result<Option<BlsValidatorIdentity>>;

    /// Human-readable backend name for logs.
    fn name(&self) -> &'static str;
}

/// A loaded BLS validator identity: secret + public + a freshly-derived
/// proof-of-possession.
///
/// `secret` is wrapped in [`Zeroizing`] so the buffer is wiped on
/// drop. Callers should keep this struct alive only long enough to
/// build the in-memory signer.
pub struct BlsValidatorIdentity {
    pub secret: Zeroizing<BlsSecretKey>,
    pub public: BlsPublicKey,
    pub pop: BlsPop,
}

impl std::fmt::Debug for BlsValidatorIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlsValidatorIdentity")
            .field("secret", &"<redacted>")
            .field("public", &hex::encode(self.public))
            .field("pop", &"<computed>")
            .finish()
    }
}

/// In-memory [`PartialSigner<BlsAggregated>`] backed by a loaded
/// [`BlsValidatorIdentity`]. Holds the secret in a [`Zeroizing`] buffer
/// for the lifetime of the signer; drop the signer to wipe the key.
///
/// Construct with [`Self::from_identity`]; do not reconstruct from raw
/// secret bytes, so the only way in is via a [`BlsKeyProvider`].
pub struct BlsPartialSignerImpl {
    secret: Zeroizing<BlsSecretKey>,
    public: BlsPublicKey,
}

impl BlsPartialSignerImpl {
    /// Build a signer from a freshly-loaded validator identity.
    /// Consumes the identity to avoid leaving two copies of the secret
    /// material in memory.
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
        // `sign_partial` only fails on malformed secret-key bytes, and
        // those would have been rejected at load time by
        // `BlsKeyProvider::load_or_init`. Treat as infallible at this
        // layer — same posture as `Signer::sign` for Ed25519.
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
            // ChaChaRng-seeded IKM is overkill — blst's `key_gen` already
            // hashes the IKM internally. Use OS randomness as the IKM.
            let mut ikm = Zeroizing::new([0u8; 32]);
            getrandom_or_panic(&mut ikm[..]);
            let (secret, public) = BlsAggregated::keygen(&ikm[..])
                .map_err(|e| anyhow::anyhow!("BLS keygen failed: {e}"))?;
            let secret = Zeroizing::new(secret);
            atomic_write(&self.path, &secret).context("writing BLS validator key")?;
            tracing::info!("generated new BLS validator key at {}", self.path.display(),);
            let pop = BlsAggregated::sign_pop(&secret)
                .map_err(|e| anyhow::anyhow!("PoP signing failed: {e}"))?;
            Ok(BlsValidatorIdentity {
                secret,
                public,
                pop,
            })
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

    // Derive pubkey + PoP from the secret. Both are quick.
    let sk = blst::min_pk::SecretKey::from_bytes(&secret[..])
        .map_err(|e| anyhow::anyhow!("malformed BLS secret key on disk: {e:?}"))?;
    let public: BlsPublicKey = sk.sk_to_pk().to_bytes();
    let pop = BlsAggregated::sign_pop(&secret)
        .map_err(|e| anyhow::anyhow!("PoP signing failed for loaded key: {e}"))?;
    Ok(BlsValidatorIdentity {
        secret,
        public,
        pop,
    })
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
    // 0o077 catches any group/world bits.
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn load_or_init_creates_then_reloads_consistently() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bls.key");
        let provider = BlsKeyFile::new(path.clone());

        let id1 = provider.load_or_init().unwrap();
        assert!(path.exists());
        // The file is exactly 33 bytes (1 version + 32 secret).
        assert_eq!(fs::metadata(&path).unwrap().len() as usize, FILE_LEN);

        let id2 = provider.load_or_init().unwrap();
        assert_eq!(id1.secret[..], id2.secret[..], "reload yields same secret");
        assert_eq!(id1.public, id2.public);
        assert_eq!(id1.pop, id2.pop, "PoP is deterministic in the secret");
    }

    #[test]
    fn try_load_returns_none_when_unprovisioned() {
        let dir = TempDir::new().unwrap();
        let provider = BlsKeyFile::new(dir.path().join("missing.key"));
        assert!(provider.try_load().unwrap().is_none());
    }

    #[test]
    fn try_load_returns_some_after_init() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bls.key");
        let provider = BlsKeyFile::new(path);
        provider.load_or_init().unwrap();
        let loaded = provider.try_load().unwrap();
        assert!(loaded.is_some());
    }

    #[test]
    fn pop_verifies_under_loaded_pubkey() {
        // End-to-end check: the PoP we hand back is a valid PoP for the
        // pubkey we hand back.
        let dir = TempDir::new().unwrap();
        let provider = BlsKeyFile::new(dir.path().join("bls.key"));
        let id = provider.load_or_init().unwrap();
        BlsAggregated::verify_pop(&id.pop, &id.public).expect("self-PoP must verify");
    }

    #[test]
    fn partial_signer_round_trips_under_registered_pubkey() {
        // The acceptance criterion for #330: a validator on a BLS chain
        // can produce a partial signature that BlsAggregated::verify_partial
        // accepts under the validator's registered BLS pubkey.
        let dir = TempDir::new().unwrap();
        let provider = BlsKeyFile::new(dir.path().join("bls.key"));
        let id = provider.load_or_init().unwrap();
        let pubkey_after_load = id.public;
        let signer = BlsPartialSignerImpl::from_identity(id);

        // The pubkey reported by the signer matches what the loader returned.
        assert_eq!(signer.pubkey(), pubkey_after_load);

        let msg = b"vote(view=11,block=0xAB...)";
        let partial = signer.sign_partial(msg);
        BlsAggregated::verify_partial(&signer.pubkey(), msg, &partial)
            .expect("partial must verify under the signer's own pubkey");
    }

    #[test]
    fn signing_round_trips_with_loaded_key() {
        let dir = TempDir::new().unwrap();
        let provider = BlsKeyFile::new(dir.path().join("bls.key"));
        let id = provider.load_or_init().unwrap();
        let msg = b"sign with loaded key";
        let sig = BlsAggregated::sign_partial(&id.secret, msg).unwrap();
        BlsAggregated::verify_partial(&id.public, msg, &sig).expect("round trip must verify");
    }

    #[test]
    fn rejects_wrong_version_byte() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bls.key");
        let mut bytes = [0u8; FILE_LEN];
        bytes[0] = 99; // Unknown version.
        fs::write(&path, bytes).unwrap();
        // Tighten perms so the perm check passes on Unix.
        set_owner_only(&path).unwrap();
        let provider = BlsKeyFile::new(path);
        let err = provider.load_or_init().unwrap_err();
        assert!(
            err.to_string().contains("version") || err.to_string().contains("supported"),
            "expected version error, got: {err}",
        );
    }

    #[test]
    fn rejects_truncated_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bls.key");
        // Only 10 bytes — less than FILE_LEN.
        fs::write(&path, [1u8; 10]).unwrap();
        set_owner_only(&path).unwrap();
        let provider = BlsKeyFile::new(path);
        assert!(provider.load_or_init().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_insecure_permissions() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bls.key");
        let mut bytes = [0u8; FILE_LEN];
        bytes[0] = FORMAT_VERSION;
        fs::write(&path, bytes).unwrap();
        // Make it group-readable.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let provider = BlsKeyFile::new(path);
        let err = provider.load_or_init().unwrap_err();
        assert!(err.to_string().contains("insecure permissions"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn allow_insecure_perms_escape_hatch_works() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bls.key");
        // Provision normally first to get a valid file.
        BlsKeyFile::new(path.clone()).load_or_init().unwrap();
        // Loosen perms.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        // With allow_insecure_perms, the load succeeds.
        let provider = BlsKeyFile::new(path).with_allow_insecure_perms(true);
        provider
            .load_or_init()
            .expect("escape hatch must allow loose perms");
    }
}
