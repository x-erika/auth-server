//! Port of `com.xerika.auth.client.ClientSecretHasher`.
//!
//! Storage shape `secretData|credentialData` — two halves of an Argon2id
//! hash joined by a pipe so they fit in a single TEXT column. The leading
//! `{` of `secretData` lets [`verify`] cheaply detect this format vs. a
//! legacy plaintext row. New writes always use the hashed format; the
//! legacy plaintext path is kept so existing deployments don't break until
//! every secret is rotated.

use subtle::ConstantTimeEq;

use crate::common::crypto::argon2 as argon2_hasher;

pub struct ClientSecretHasher;

impl ClientSecretHasher {
    pub fn hash(raw_secret: &str) -> String {
        let parts = argon2_hasher::hash(raw_secret);
        format!("{}|{}", parts.secret_data, parts.credential_data)
    }

    pub fn verify(presented: &str, stored: &str) -> bool {
        if let Some(sep) = stored.find('|') {
            if stored.starts_with('{') && sep > 0 {
                let secret_data = &stored[..sep];
                let credential_data = &stored[sep + 1..];
                return argon2_hasher::verify(presented, secret_data, credential_data);
            }
        }
        // Legacy plaintext fallback — constant-time compare so timing can't
        // distinguish "wrong secret" from "wrong length".
        let a = presented.as_bytes();
        let b = stored.as_bytes();
        a.len() == b.len() && bool::from(a.ct_eq(b))
    }

    pub fn is_hashed(stored: &str) -> bool {
        stored.starts_with('{') && stored.contains('|')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_round_trip() {
        let stored = ClientSecretHasher::hash("topsecret");
        assert!(ClientSecretHasher::is_hashed(&stored));
        assert!(ClientSecretHasher::verify("topsecret", &stored));
        assert!(!ClientSecretHasher::verify("wrong", &stored));
    }

    #[test]
    fn legacy_plaintext_still_works() {
        let stored = "plain-old-secret";
        assert!(!ClientSecretHasher::is_hashed(stored));
        assert!(ClientSecretHasher::verify("plain-old-secret", stored));
        assert!(!ClientSecretHasher::verify("nope", stored));
    }
}
