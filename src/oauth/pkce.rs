//! Port of `com.xerika.auth.oauth.pkce.PkceVerifier`.
//!
//! RFC 7636 PKCE — supports `plain` and `S256` methods. `plain` compares
//! the verifier directly; `S256` computes `base64url(sha256(verifier))`
//! and compares against the stored challenge.

use crate::common::crypto::sha256;

const SUPPORTED_METHODS: &[&str] = &["S256", "plain"];

pub fn is_method_supported(method: Option<&str>) -> bool {
    let Some(m) = method else { return false };
    SUPPORTED_METHODS.iter().any(|s| *s == m)
}

pub fn verify(code_verifier: &str, code_challenge: &str, method: &str) -> bool {
    if code_verifier.is_empty() || code_challenge.is_empty() {
        return false;
    }
    if method.eq_ignore_ascii_case("plain") {
        return code_verifier == code_challenge;
    }
    if method.eq_ignore_ascii_case("S256") {
        return sha256::base64_url(code_verifier) == code_challenge;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_match() {
        assert!(verify("abc", "abc", "plain"));
        assert!(!verify("abc", "xyz", "plain"));
    }

    #[test]
    fn s256_match() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        // Computed with: base64url(no-padding)(sha256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
        let challenge = sha256::base64_url(verifier);
        assert!(verify(verifier, &challenge, "S256"));
        assert!(verify(verifier, &challenge, "s256")); // case-insensitive
    }

    #[test]
    fn unknown_method_rejected() {
        assert!(!verify("abc", "abc", "made-up"));
        assert!(!is_method_supported(Some("HS512")));
        assert!(is_method_supported(Some("S256")));
        assert!(is_method_supported(Some("plain")));
    }
}
