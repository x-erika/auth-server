//! Port of `RequestObjectParser.java`.
//!
//! Accepts a JWS request object (HS256 only). `alg=none` and asymmetric
//! algs are rejected outright — the request object can override
//! `redirect_uri` / `scope` / `code_challenge`, so accepting an unsigned
//! blob from a public client defeats PKCE binding entirely.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::client::Client;

type HmacSha256 = Hmac<Sha256>;

pub struct RequestObjectParser;

impl RequestObjectParser {
    pub fn parse(request_jwt: &str, client: &Client) -> Option<Value> {
        if request_jwt.trim().is_empty() {
            return None;
        }
        let parts: Vec<&str> = request_jwt.split('.').collect();
        if parts.len() != 3 {
            // Java accepts 2 or 3 parts; an unsigned (2-part) token is
            // rejected by the alg=none check anyway, so collapse to "must
            // be a signed JWS".
            return None;
        }

        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).ok()?;
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
        let header: Value = serde_json::from_slice(&header_bytes).ok()?;
        let payload: Value = serde_json::from_slice(&payload_bytes).ok()?;

        let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
        if !alg.eq_ignore_ascii_case("HS256") {
            return None;
        }

        let secret = client.client_secret.as_deref()?;
        if secret.is_empty() {
            return None;
        }

        if !verify_hs256(&format!("{}.{}", parts[0], parts[1]), parts[2], secret) {
            return None;
        }

        Some(payload)
    }
}

fn verify_hs256(signing_input: &str, signature_b64url: &str, secret: &str) -> bool {
    let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(signing_input.as_bytes());
    let expected = mac.finalize().into_bytes();
    let Ok(provided) = URL_SAFE_NO_PAD.decode(signature_b64url) else {
        return false;
    };
    if expected.len() != provided.len() {
        return false;
    }
    bool::from(expected.as_slice().ct_eq(&provided))
}
