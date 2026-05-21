//! Port of `com.xerika.auth.common.crypto.RandomTokens`.
//!
//! Generates `byte_length` cryptographically-random bytes via `OsRng`
//! (Java side uses `SecureRandom`) and base64url-encodes them without
//! padding — matches `Base64.getUrlEncoder().withoutPadding()`.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use rand::rngs::OsRng;

pub fn url_safe(byte_length: usize) -> String {
    let mut bytes = vec![0u8; byte_length];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn successive_calls_are_unique() {
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            seen.insert(url_safe(32));
        }
        assert_eq!(seen.len(), 1000, "duplicate tokens generated");
    }

    #[test]
    fn length_32_bytes_produces_43_chars() {
        // 32 bytes → ceil(32 * 4 / 3) = 43.
        assert_eq!(url_safe(32).len(), 43);
    }

    #[test]
    fn length_48_bytes_produces_64_chars() {
        // 48 bytes → 48 * 4 / 3 = 64 (exact, no padding).
        assert_eq!(url_safe(48).len(), 64);
    }

    #[test]
    fn uses_url_safe_alphabet_only() {
        let re = regex::Regex::new(r"^[A-Za-z0-9_\-]+$").unwrap();
        for _ in 0..50 {
            let t = url_safe(48);
            assert!(re.is_match(&t), "non-urlsafe char in: {t}");
        }
    }
}
