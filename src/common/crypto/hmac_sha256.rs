//! Port of `com.xerika.auth.common.crypto.HmacSha256`.
//!
//! HMAC-SHA256 utility used for at-rest hashes of high-value opaque tokens
//! (refresh tokens, password reset tokens, email verification tokens). The
//! point over plain SHA-256 is defence against a DB-only leak: an attacker
//! with the raw `token_hash` column still needs the server-side HMAC key to
//! grind candidates, so a compromised DB snapshot alone doesn't yield usable
//! tokens.
//!
//! The key is sourced from `AUTH_TOKEN_HMAC_KEY` (mirroring
//! `auth.token-hmac.key`). The dev default is a placeholder — operators MUST
//! set a long random value in production; rotating it invalidates every
//! currently-issued refresh / reset / verify token (the hashes won't match),
//! which is the intended emergency-rotation behaviour.
//!
//! Output is base64url **without padding**, identical in shape to
//! [`crate::common::crypto::sha256::base64_url`].

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256Inner = Hmac<Sha256>;

#[derive(Clone)]
pub struct HmacSha256 {
    key: Vec<u8>,
}

impl HmacSha256 {
    /// Build an instance from the configured key string. The empty key is
    /// rejected at construction so misconfiguration fails fast instead of
    /// producing predictable hashes silently.
    pub fn new(key: impl Into<String>) -> Self {
        let key = key.into();
        assert!(!key.is_empty(), "HMAC key must not be empty");
        Self {
            key: key.into_bytes(),
        }
    }

    /// HMAC-SHA256(`value`) → base64url without padding.
    pub fn compute(&self, value: &str) -> String {
        let mut mac = HmacSha256Inner::new_from_slice(&self.key)
            .expect("HMAC key length always valid for HMAC-SHA256");
        mac.update(value.as_bytes());
        let digest = mac.finalize().into_bytes();
        URL_SAFE_NO_PAD.encode(digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_same_input() {
        let h = HmacSha256::new("test-key");
        assert_eq!(h.compute("xerika"), h.compute("xerika"));
    }

    #[test]
    fn different_keys_produce_different_output() {
        let a = HmacSha256::new("key-a");
        let b = HmacSha256::new("key-b");
        assert_ne!(a.compute("same-input"), b.compute("same-input"));
    }

    #[test]
    fn url_safe_no_padding() {
        let h = HmacSha256::new("k");
        let out = h.compute("payload");
        assert!(!out.contains('+'));
        assert!(!out.contains('/'));
        assert!(!out.contains('='));
        assert_eq!(out.len(), 43); // 32 bytes → 43 chars base64url
    }
}
