use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

pub fn load_secret(path: &Path) -> Result<Vec<u8>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading jwt secret {}", path.display()))?;
    let text = text.trim().trim_start_matches("0x");
    hex::decode(text).context("jwt secret is not valid hex")
}

pub fn mint(secret: &[u8]) -> Result<String> {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let iat = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"iat":{iat}}}"#).as_bytes());
    let signing_input = format!("{header}.{payload}");
    let mut mac = HmacSha256::new_from_slice(secret).context("hmac key init")?;
    mac.update(signing_input.as_bytes());
    let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    Ok(format!("{signing_input}.{sig}"))
}
