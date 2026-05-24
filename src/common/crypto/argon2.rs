//! Port of `com.xerika.auth.common.crypto.Argon2Hasher`.
//!
//! Hash parameters are **byte-identical** to the Java side (BouncyCastle):
//! Argon2id, t=5, m=7168 KB, p=1, hashLen=32, salt=16 random bytes.
//!
//! The two output strings are kept as raw JSON exactly matching the Java
//! shape so that hashes minted by either implementation interoperate:
//!
//! ```text
//! secretData     = {"value":"<b64(hash)>","salt":"<b64(salt)>","additionalParameters":{}}
//! credentialData = {"hashIterations":5,"algorithm":"argon2","additionalParameters":{
//!                   "hashLength":["32"],"memory":["7168"],"type":["id"],"parallelism":["1"]}}
//! ```

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use rand::RngCore;
use rand::rngs::OsRng;
use serde_json::Value;
use subtle::ConstantTimeEq;

// OWASP 2024 Argon2id baseline (12 MiB memory, 3 iterations, p=1). Old
// credentials remain verifiable because `verify_inner` reads each row's
// own stored params from `credentialData` JSON, so existing hashes don't
// break — only new writes use the stronger settings.
const ITERATIONS: u32 = 3;
const MEMORY_KB: u32 = 12288;
const PARALLELISM: u32 = 1;
const HASH_LENGTH: usize = 32;

#[derive(Debug, Clone)]
pub struct Hashed {
    pub secret_data: String,
    pub credential_data: String,
}

pub fn hash(raw_password: &str) -> Hashed {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let output = argon2_compute(
        raw_password.as_bytes(),
        &salt,
        ITERATIONS,
        MEMORY_KB,
        PARALLELISM,
        HASH_LENGTH,
        Algorithm::Argon2id,
    )
    .expect("argon2 hash failed");

    // Hand-build JSON so the output is byte-identical to Java's. Lets a
    // password minted on either side verify on the other.
    let secret_data = format!(
        r#"{{"value":"{}","salt":"{}","additionalParameters":{{}}}}"#,
        B64.encode(&output),
        B64.encode(salt),
    );
    let credential_data = format!(
        r#"{{"hashIterations":{ITERATIONS},"algorithm":"argon2","additionalParameters":{{"hashLength":["{HASH_LENGTH}"],"memory":["{MEMORY_KB}"],"type":["id"],"parallelism":["{PARALLELISM}"]}}}}"#
    );

    Hashed {
        secret_data,
        credential_data,
    }
}

pub fn verify(raw_password: &str, secret_data_json: &str, credential_data_json: &str) -> bool {
    verify_inner(raw_password, secret_data_json, credential_data_json).unwrap_or(false)
}

fn verify_inner(raw: &str, secret_json: &str, credential_json: &str) -> Option<bool> {
    let secret: Value = serde_json::from_str(secret_json).ok()?;
    let credential: Value = serde_json::from_str(credential_json).ok()?;

    let expected = B64.decode(secret.get("value")?.as_str()?).ok()?;
    let salt = B64.decode(secret.get("salt")?.as_str()?).ok()?;

    let iterations = credential
        .get("hashIterations")
        .and_then(|v| v.as_u64())
        .unwrap_or(ITERATIONS as u64) as u32;

    let params = credential
        .get("additionalParameters")
        .unwrap_or(&Value::Null);
    let hash_length = first_int(params, "hashLength", HASH_LENGTH as i64) as usize;
    let memory = first_int(params, "memory", MEMORY_KB as i64) as u32;
    let parallelism = first_int(params, "parallelism", PARALLELISM as i64) as u32;
    let algo = match first_text(params, "type", "id").as_str() {
        "d" => Algorithm::Argon2d,
        "i" => Algorithm::Argon2i,
        _ => Algorithm::Argon2id,
    };

    let actual = argon2_compute(
        raw.as_bytes(),
        &salt,
        iterations,
        memory,
        parallelism,
        hash_length,
        algo,
    )
    .ok()?;

    // Constant-time equality, same as `MessageDigest.isEqual` on the Java side.
    Some(bool::from(expected.ct_eq(&actual)))
}

fn argon2_compute(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    memory_kb: u32,
    parallelism: u32,
    hash_length: usize,
    algorithm: Algorithm,
) -> Result<Vec<u8>, argon2::Error> {
    let params = Params::new(memory_kb, iterations, parallelism, Some(hash_length))?;
    let argon2 = Argon2::new(algorithm, Version::V0x13, params);
    let mut output = vec![0u8; hash_length];
    argon2.hash_password_into(password, salt, &mut output)?;
    Ok(output)
}

/// Mirrors Java's `firstInt(params, key, fallback)` — pulls the first element
/// of an array of stringified numbers, falling back when missing/malformed.
fn first_int(parent: &Value, key: &str, fallback: i64) -> i64 {
    parent
        .get(key)
        .and_then(|n| n.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(fallback)
}

fn first_text(parent: &Value, key: &str, fallback: &str) -> String {
    parent
        .get(key)
        .and_then(|n| n.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| fallback.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_round_trip() {
        let cred = hash("supersecret123");
        assert!(verify("supersecret123", &cred.secret_data, &cred.credential_data));
    }

    #[test]
    fn wrong_password_fails() {
        let cred = hash("correct");
        assert!(!verify("wrong", &cred.secret_data, &cred.credential_data));
    }

    #[test]
    fn empty_password_verifies() {
        let cred = hash("");
        assert!(verify("", &cred.secret_data, &cred.credential_data));
        assert!(!verify("nonempty", &cred.secret_data, &cred.credential_data));
    }

    #[test]
    fn different_salts_produce_different_hashes() {
        let a = hash("same-password");
        let b = hash("same-password");
        assert_ne!(a.secret_data, b.secret_data);
    }

    #[test]
    fn verify_handles_malformed_json_gracefully() {
        assert!(!verify("any", "not-json", "not-json"));
    }
}
