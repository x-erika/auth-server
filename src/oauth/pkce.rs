//! Port of `com.xerika.auth.oauth.pkce.PkceVerifier`.
//!
//! RFC 7636 PKCE — only `S256` is supported.
//!
//! OAuth 2.0 Security BCP §2.1.1.1 / RFC 9700: the `plain` method MUST NOT be
//! used. Clients are responsible for hashing the verifier with SHA-256 before
//! sending the challenge.

use subtle::ConstantTimeEq;

use crate::common::crypto::sha256;

const SUPPORTED_METHODS: &[&str] = &["S256"];

pub fn is_method_supported(method: Option<&str>) -> bool {
    let Some(m) = method else { return false };
    SUPPORTED_METHODS.iter().any(|s| *s == m)
}

pub fn verify(code_verifier: &str, code_challenge: &str, method: &str) -> bool {
    if code_verifier.is_empty() || code_challenge.is_empty() {
        return false;
    }
    if !method.eq_ignore_ascii_case("S256") {
        return false;
    }
    let computed = sha256::base64_url(code_verifier);
    // Constant-time compare: the challenge is server-known after /authorize,
    // so a timing leak doesn't help an attacker here, but
    // `subtle::ConstantTimeEq` keeps the codebase free of `==` on
    // security-sensitive byte strings.
    computed
        .as_bytes()
        .ct_eq(code_challenge.as_bytes())
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s256_match() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = sha256::base64_url(verifier);
        assert!(verify(verifier, &challenge, "S256"));
        assert!(verify(verifier, &challenge, "s256")); // case-insensitive
    }

    #[test]
    fn plain_rejected() {
        assert!(!verify("abc", "abc", "plain"));
        assert!(!is_method_supported(Some("plain")));
    }

    #[test]
    fn unknown_method_rejected() {
        assert!(!verify("abc", "abc", "made-up"));
        assert!(!is_method_supported(Some("HS512")));
        assert!(is_method_supported(Some("S256")));
    }
}
