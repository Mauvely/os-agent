//! Request signing, `mauvely-device-v1` (brief 19, "Device keys and signing").
//!
//! The message is six lines joined with `\n`, no trailing newline:
//! the format tag, the method, the path with its query, the Unix timestamp,
//! the nonce, and the lowercase hex SHA-256 of the raw body bytes.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use rand::TryRng;
use rand::rngs::SysRng;
use sha2::{Digest, Sha256};

use crate::Error;

pub const FORMAT: &str = "mauvely-device-v1";

pub const HEADER_DEVICE: &str = "X-Mauvely-Device";
pub const HEADER_TIMESTAMP: &str = "X-Mauvely-Timestamp";
pub const HEADER_NONCE: &str = "X-Mauvely-Nonce";
pub const HEADER_SIGNATURE: &str = "X-Mauvely-Signature";

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// The exact string that is signed.
pub fn message(method: &str, path: &str, timestamp: u64, nonce: &str, body: &[u8]) -> String {
    format!(
        "{FORMAT}\n{method}\n{path}\n{timestamp}\n{nonce}\n{}",
        sha256_hex(body)
    )
}

/// The signature over [`message`], base64url unpadded.
pub fn signature(
    key: &SigningKey,
    method: &str,
    path: &str,
    timestamp: u64,
    nonce: &str,
    body: &[u8],
) -> String {
    let msg = message(method, path, timestamp, nonce, body);
    URL_SAFE_NO_PAD.encode(key.sign(msg.as_bytes()).to_bytes())
}

/// The `X-Mauvely-*` headers for one request. `device` is `None` on enrol,
/// where the header is absent.
pub fn headers(
    key: &SigningKey,
    device: Option<&str>,
    method: &str,
    path: &str,
    timestamp: u64,
    nonce: &str,
    body: &[u8],
) -> Vec<(&'static str, String)> {
    let mut out = Vec::with_capacity(4);
    if let Some(device) = device {
        out.push((HEADER_DEVICE, device.to_owned()));
    }
    out.push((HEADER_TIMESTAMP, timestamp.to_string()));
    out.push((HEADER_NONCE, nonce.to_owned()));
    out.push((
        HEADER_SIGNATURE,
        signature(key, method, path, timestamp, nonce, body),
    ));
    out
}

/// The public key as it travels: 32 raw bytes, base64url unpadded.
pub fn public_key(key: &SigningKey) -> String {
    URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes())
}

/// 16 random bytes, base64url unpadded.
pub fn new_nonce() -> Result<String, Error> {
    let mut bytes = [0u8; 16];
    SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| Error::Random(e.to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// A fresh 32-byte Ed25519 seed from the operating system.
pub fn new_seed() -> Result<[u8; 32], Error> {
    let mut seed = [0u8; 32];
    SysRng
        .try_fill_bytes(&mut seed)
        .map_err(|e| Error::Random(e.to_string()))?;
    Ok(seed)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0xf) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_is_16_bytes() {
        let nonce = new_nonce().unwrap();
        assert_eq!(URL_SAFE_NO_PAD.decode(&nonce).unwrap().len(), 16);
        assert_ne!(nonce, new_nonce().unwrap());
    }

    #[test]
    fn enrol_headers_have_no_device() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let h = headers(&key, None, "POST", "/x", 1, "n", b"");
        let names: Vec<_> = h.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, [HEADER_TIMESTAMP, HEADER_NONCE, HEADER_SIGNATURE]);
        let h = headers(&key, Some("dev_1"), "POST", "/x", 1, "n", b"");
        assert_eq!(h[0], (HEADER_DEVICE, "dev_1".to_owned()));
    }
}
