//! Passphrase-encrypted file backend.
//!
//! On-disk format (base64-wrapped inside a PEM-like envelope):
//!
//!     magic:       "AMBROS\0"   (7 bytes)
//!     version:     1            (1 byte)
//!     argon_m:     u32 BE       (memory cost in KiB)
//!     argon_t:     u32 BE       (iterations)
//!     argon_p:     u32 BE       (lanes)
//!     salt:        16 bytes
//!     nonce:       24 bytes     (XChaCha20)
//!     ciphertext:  PKCS#8 DER encrypted with XChaCha20-Poly1305, AAD = first 40 bytes
//!
//! The passphrase is taken from `passphrase_env` if set, else read from the
//! TTY via rpassword. Passphrases are held in `SecretBox<String>` and zeroed
//! on drop.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use secrecy::{ExposeSecret, SecretBox};
use tracing::info;
use zeroize::Zeroizing;

use super::{KeyProvider, NodeIdentity, generate_pkcs8_der};

const MAGIC: &[u8; 7] = b"AMBROS\0";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = 7 + 1 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN;
const PEM_LABEL: &str = "AMBROS ENCRYPTED PRIVATE KEY";

const ARGON_M_KIB: u32 = 64 * 1024; // 64 MiB
const ARGON_T: u32 = 3;
const ARGON_P: u32 = 1;

#[derive(Debug, Clone)]
pub struct EncryptedFileKeyProvider {
    path: PathBuf,
    passphrase_env: Option<String>,
}

impl EncryptedFileKeyProvider {
    pub fn new(path: PathBuf, passphrase_env: Option<String>) -> Self {
        Self {
            path,
            passphrase_env,
        }
    }

    fn passphrase(&self, confirm: bool) -> anyhow::Result<SecretBox<String>> {
        if let Some(var) = &self.passphrase_env {
            let raw = std::env::var(var)
                .with_context(|| format!("reading passphrase from env var {var}"))?;
            return Ok(SecretBox::new(Box::new(raw)));
        }
        let prompt = format!("Passphrase for {}: ", self.path.display());
        let first = rpassword::prompt_password(&prompt).context("reading passphrase from TTY")?;
        if confirm {
            let second = rpassword::prompt_password("Confirm passphrase: ")
                .context("reading passphrase confirmation")?;
            if first != second {
                anyhow::bail!("passphrases do not match");
            }
        }
        Ok(SecretBox::new(Box::new(first)))
    }
}

impl KeyProvider for EncryptedFileKeyProvider {
    fn name(&self) -> &'static str {
        "encrypted-file"
    }

    fn load_or_init(&self) -> anyhow::Result<NodeIdentity> {
        if self.path.exists() {
            let raw = fs::read(&self.path).context("reading encrypted key")?;
            let blob = decode_envelope(&raw).context("decoding encrypted key envelope")?;
            let passphrase = self.passphrase(false)?;
            let der = decrypt_blob(&blob, &passphrase)?;
            let id = NodeIdentity { pkcs8_der: der };
            id.validate().context("validating decrypted node key")?;
            Ok(id)
        } else {
            if let Some(parent) = self.path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent).context("creating key directory")?;
                }
            }
            let passphrase = self.passphrase(true)?;
            let der = generate_pkcs8_der()?;
            let blob = encrypt_blob(&der, &passphrase)?;
            atomic_write_envelope(&self.path, &blob).context("writing encrypted key")?;
            info!(
                "generated new encrypted node key at {}",
                self.path.display()
            );
            Ok(NodeIdentity { pkcs8_der: der })
        }
    }

    fn provision(&self, identity: &NodeIdentity) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).context("creating key directory")?;
            }
        }
        let passphrase = self.passphrase(!self.path.exists())?;
        let blob = encrypt_blob(&identity.pkcs8_der, &passphrase)?;
        atomic_write_envelope(&self.path, &blob).context("writing encrypted key")?;
        info!("provisioned encrypted node key at {}", self.path.display());
        Ok(())
    }
}

fn argon2_key(
    passphrase: &SecretBox<String>,
    salt: &[u8],
    params: Params,
) -> anyhow::Result<[u8; 32]> {
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase.expose_secret().as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("Argon2id KDF failed: {e}"))?;
    Ok(key)
}

fn encrypt_blob(plaintext: &[u8], passphrase: &SecretBox<String>) -> anyhow::Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut salt);
    rand::rng().fill_bytes(&mut nonce);

    let params = Params::new(ARGON_M_KIB, ARGON_T, ARGON_P, Some(32))
        .map_err(|e| anyhow::anyhow!("invalid Argon2 params: {e}"))?;
    let key_bytes = argon2_key(passphrase, &salt, params)?;
    let key = Key::from_slice(&key_bytes);
    let cipher = XChaCha20Poly1305::new(key);
    let xnonce = XNonce::from_slice(&nonce);

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&ARGON_M_KIB.to_be_bytes());
    header.extend_from_slice(&ARGON_T.to_be_bytes());
    header.extend_from_slice(&ARGON_P.to_be_bytes());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);
    debug_assert_eq!(header.len(), HEADER_LEN);

    let ct = cipher
        .encrypt(
            xnonce,
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|e| anyhow::anyhow!("AEAD encryption failed: {e}"))?;

    let mut blob = header;
    blob.extend_from_slice(&ct);
    Ok(blob)
}

fn decrypt_blob(blob: &[u8], passphrase: &SecretBox<String>) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    if blob.len() < HEADER_LEN {
        anyhow::bail!("encrypted blob is too short ({} bytes)", blob.len());
    }
    if &blob[..7] != MAGIC {
        anyhow::bail!("encrypted blob: bad magic");
    }
    if blob[7] != VERSION {
        anyhow::bail!("encrypted blob: unsupported version {}", blob[7]);
    }
    let m = u32::from_be_bytes(blob[8..12].try_into().unwrap());
    let t = u32::from_be_bytes(blob[12..16].try_into().unwrap());
    let p = u32::from_be_bytes(blob[16..20].try_into().unwrap());
    let salt = &blob[20..20 + SALT_LEN];
    let nonce = &blob[20 + SALT_LEN..HEADER_LEN];
    let ct = &blob[HEADER_LEN..];
    let header = &blob[..HEADER_LEN];

    let params = Params::new(m, t, p, Some(32))
        .map_err(|e| anyhow::anyhow!("invalid Argon2 params in file: {e}"))?;
    let key_bytes = argon2_key(passphrase, salt, params)?;
    let key = Key::from_slice(&key_bytes);
    let cipher = XChaCha20Poly1305::new(key);
    let xnonce = XNonce::from_slice(nonce);

    let pt = cipher
        .decrypt(
            xnonce,
            Payload {
                msg: ct,
                aad: header,
            },
        )
        .map_err(|_| anyhow::anyhow!("decryption failed (wrong passphrase or corrupt file)"))?;
    Ok(Zeroizing::new(pt))
}

fn encode_envelope(blob: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(blob);
    let mut out = String::with_capacity(b64.len() + 80);
    out.push_str("-----BEGIN ");
    out.push_str(PEM_LABEL);
    out.push_str("-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(PEM_LABEL);
    out.push_str("-----\n");
    out
}

fn decode_envelope(raw: &[u8]) -> anyhow::Result<Vec<u8>> {
    let text = std::str::from_utf8(raw).context("envelope is not valid UTF-8")?;
    let mut body = String::new();
    let mut inside = false;
    for line in text.lines() {
        if line.starts_with("-----BEGIN") {
            if !line.contains(PEM_LABEL) {
                anyhow::bail!("unexpected envelope label: {line}");
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
    base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .context("base64-decoding envelope body")
}

fn atomic_write_envelope(path: &Path, blob: &[u8]) -> anyhow::Result<()> {
    let envelope = encode_envelope(blob);
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let mut builder = tempfile::Builder::new();
    builder.prefix(".node-key-").suffix(".tmp");

    let mut tmp = if let Some(dir) = dir {
        builder.tempfile_in(dir).context("creating temp file")?
    } else {
        builder.tempfile_in(".").context("creating temp file")?
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .context("setting 0600 on temp file")?;
    }

    tmp.as_file_mut()
        .write_all(envelope.as_bytes())
        .context("writing envelope")?;
    tmp.as_file_mut().sync_all().context("fsync temp file")?;
    tmp.persist(path)
        .map_err(|e| anyhow::anyhow!("renaming temp into place: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pass(s: &str) -> SecretBox<String> {
        SecretBox::new(Box::new(s.to_string()))
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let passphrase = pass("hunter2");
        let msg = b"node key material bytes";
        let blob = encrypt_blob(msg, &passphrase).unwrap();
        let back = decrypt_blob(&blob, &passphrase).unwrap();
        assert_eq!(&back[..], msg);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let blob = encrypt_blob(b"secret", &pass("right")).unwrap();
        let err = decrypt_blob(&blob, &pass("wrong")).unwrap_err();
        assert!(format!("{err}").contains("decryption failed"));
    }

    #[test]
    fn tamper_fails() {
        let mut blob = encrypt_blob(b"secret", &pass("p")).unwrap();
        // Flip a byte in the ciphertext section.
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        let err = decrypt_blob(&blob, &pass("p")).unwrap_err();
        assert!(format!("{err}").contains("decryption failed"));
    }

    #[test]
    fn envelope_round_trip() {
        let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9];
        let env = encode_envelope(&data);
        let back = decode_envelope(env.as_bytes()).unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn provider_generates_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.enc");
        let var = "AMBROS_TEST_ENC_PASS";
        unsafe { std::env::set_var(var, "p@ssw0rd!") };

        let provider = EncryptedFileKeyProvider::new(path.clone(), Some(var.to_string()));
        let first = provider.load_or_init().unwrap();
        assert!(path.exists());

        let second = provider.load_or_init().unwrap();
        assert_eq!(&first.pkcs8_der[..], &second.pkcs8_der[..]);

        unsafe { std::env::remove_var(var) };
    }

    #[test]
    fn provider_wrong_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.enc");
        let var = "AMBROS_TEST_ENC_PASS_WRONG";
        unsafe { std::env::set_var(var, "correct-passphrase") };
        let provider = EncryptedFileKeyProvider::new(path.clone(), Some(var.to_string()));
        provider.load_or_init().unwrap();

        unsafe { std::env::set_var(var, "different-one") };
        let err = provider.load_or_init().unwrap_err();
        assert!(format!("{err:#}").contains("decryption failed"));

        unsafe { std::env::remove_var(var) };
    }
}
