//! Port of `com.xerika.auth.common.crypto.Sha256`.
//!
//! `base64Url(raw)` → SHA-256 of UTF-8 bytes, base64url-encoded **without
//! padding**. Same shape as Java's `Base64.getUrlEncoder().withoutPadding()`.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

pub fn base64_url(raw: &str) -> String {
    let hash = Sha256::digest(raw.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_same_input() {
        assert_eq!(base64_url("xerika"), base64_url("xerika"));
    }

    #[test]
    fn different_input_different_output() {
        assert_ne!(base64_url("a"), base64_url("b"));
    }

    #[test]
    fn produces_43_char_output() {
        // SHA-256 = 32 bytes → ceil(32 * 4 / 3) = 43 base64url chars (no padding).
        assert_eq!(base64_url("anything").len(), 43);
        assert_eq!(base64_url("").len(), 43);
    }

    #[test]
    fn uses_url_safe_alphabet() {
        let re = regex::Regex::new(r"^[A-Za-z0-9_\-]+$").unwrap();
        for i in 0..50 {
            let h = base64_url(&format!("input-{i}"));
            assert!(re.is_match(&h), "expected url-safe, got: {h}");
        }
    }
}
