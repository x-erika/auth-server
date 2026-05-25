//! Port of `JwtSigner` + `JwtValidator`.
//!
//! Backed by [`jsonwebtoken`] (RS256 only). Identical claim shape to the
//! SmallRye-JWT side:
//! * access tokens carry `typ: at+jwt` (RFC 9068 §2.1)
//! * id tokens carry default `typ: JWT` plus `auth_time` & optional `nonce`
//! * backchannel-logout tokens carry the OIDC `events` claim + `sid`
//!
//! Validator semantics match Java line-for-line: hard-locks `alg=RS256`,
//! requires `iss` to match the configured issuer, requires `exp` not yet
//! expired, honors `nbf`, and optionally enforces `aud`.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use jsonwebtoken::{Algorithm, Header, Validation, decode, decode_header, encode};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::common::crypto::rsa_keys::RsaKeyProvider;

pub struct JwtSigner {
    keys: Arc<RsaKeyProvider>,
    issuer: String,
    access_ttl: Duration,
    id_ttl: Duration,
}

impl JwtSigner {
    pub fn new(
        keys: Arc<RsaKeyProvider>,
        issuer: impl Into<String>,
        access_ttl: Duration,
        id_ttl: Duration,
    ) -> Self {
        Self {
            keys,
            issuer: issuer.into(),
            access_ttl,
            id_ttl,
        }
    }

    #[allow(dead_code)]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn access_token_ttl_seconds(&self) -> u64 {
        self.access_ttl.as_secs()
    }

    #[allow(dead_code)]
    pub fn id_token_ttl_seconds(&self) -> u64 {
        self.id_ttl.as_secs()
    }

    pub fn sign_access_token(
        &self,
        subject: &str,
        audience: &str,
        extra_claims: Map<String, Value>,
    ) -> Result<String> {
        let claims = self.base_claims(subject, audience, self.access_ttl, extra_claims);
        self.signed_with_type(&claims, Some("at+jwt"))
    }

    pub fn sign_id_token(
        &self,
        subject: &str,
        audience: &str,
        nonce: Option<&str>,
        auth_time: i64,
        mut extra_claims: Map<String, Value>,
    ) -> Result<String> {
        // `auth_time` + (optional) `nonce` are set first so that explicit
        // entries in `extra_claims` take precedence — matches the Java
        // order-of-application via `applyClaims` running after the base.
        let mut claims = self.base_claims(subject, audience, self.id_ttl, Map::new());
        claims.insert("auth_time".to_string(), json!(auth_time));
        if let Some(n) = nonce {
            if !n.is_empty() {
                claims.insert("nonce".to_string(), json!(n));
            }
        }
        for (k, v) in extra_claims.iter_mut() {
            claims.insert(k.clone(), v.take());
        }
        self.signed_with_type(&claims, None)
    }

    pub fn sign_logout_token(
        &self,
        subject: Option<&str>,
        audience: &str,
        session_id: &str,
    ) -> Result<String> {
        let mut claims = Map::new();
        claims.insert("iss".to_string(), json!(&self.issuer));
        claims.insert("aud".to_string(), json!(audience));
        claims.insert("jti".to_string(), json!(Uuid::new_v4().to_string()));
        claims.insert("iat".to_string(), json!(now_seconds()));

        let mut events = Map::new();
        events.insert(
            "http://schemas.openid.net/event/backchannel-logout".to_string(),
            Value::Object(Map::new()),
        );
        claims.insert("events".to_string(), Value::Object(events));
        claims.insert("sid".to_string(), json!(session_id));

        if let Some(s) = subject {
            if !s.is_empty() {
                claims.insert("sub".to_string(), json!(s));
            }
        }
        self.signed_with_type(&claims, None)
    }

    fn base_claims(
        &self,
        subject: &str,
        audience: &str,
        ttl: Duration,
        extra: Map<String, Value>,
    ) -> Map<String, Value> {
        let now = now_seconds();
        let mut claims = Map::new();
        claims.insert("iss".to_string(), json!(&self.issuer));
        claims.insert("aud".to_string(), json!(audience));
        claims.insert("sub".to_string(), json!(subject));
        claims.insert("jti".to_string(), json!(Uuid::new_v4().to_string()));
        claims.insert("exp".to_string(), json!(now + ttl.as_secs() as i64));
        for (k, v) in extra {
            claims.insert(k, v);
        }
        claims
    }

    fn signed_with_type(&self, claims: &Map<String, Value>, typ: Option<&str>) -> Result<String> {
        let (kid, encoding_key) = self.keys.active_encoding_key();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid);
        if let Some(t) = typ {
            header.typ = Some(t.to_string());
        }
        encode(&header, claims, &encoding_key).context("jwt encode")
    }
}

pub struct JwtValidator {
    keys: Arc<RsaKeyProvider>,
    expected_issuer: String,
}

impl JwtValidator {
    pub fn new(keys: Arc<RsaKeyProvider>, expected_issuer: impl Into<String>) -> Self {
        Self {
            keys,
            expected_issuer: expected_issuer.into(),
        }
    }

    /// Validates without audience binding — equivalent to `validate(token)` on
    /// the Java side.
    pub fn validate(&self, token: &str) -> Option<Value> {
        self.validate_internal(token, None, false)
    }

    /// Validates and additionally enforces that the token's `aud` matches
    /// `expected_audience`. Use this from any caller that knows which client a
    /// token should be bound to (e.g. an OIDC client checking an id_token
    /// meant for itself).
    #[allow(dead_code)]
    pub fn validate_with(&self, token: &str, expected_audience: Option<&str>) -> Option<Value> {
        self.validate_internal(token, expected_audience, false)
    }

    /// Validates signature + iss + (nbf) but tolerates an expired `exp`. Used
    /// by `/oauth/logout` for the `id_token_hint`: OIDC RP-Initiated Logout
    /// 1.0 §3 says the OP SHOULD accept the hint regardless of expiry,
    /// because users often log out after their id_token's lifetime has
    /// lapsed.
    pub fn validate_allow_expired(&self, token: &str) -> Option<Value> {
        self.validate_internal(token, None, true)
    }

    /// RFC 9068 §4 — protected resources SHOULD reject anything that is not
    /// `typ=at+jwt`, so an id_token (which has matching iss/aud/exp) can't
    /// be presented as an access token via the same Bearer header.
    /// Returns `true` if the JWT header carries `typ: at+jwt`. Does NOT
    /// verify the signature — call alongside `validate()` for that.
    pub fn is_access_token_type(token: &str) -> bool {
        decode_header(token)
            .ok()
            .and_then(|h| h.typ)
            .is_some_and(|t| t.eq_ignore_ascii_case("at+jwt"))
    }

    fn validate_internal(
        &self,
        token: &str,
        expected_audience: Option<&str>,
        allow_expired: bool,
    ) -> Option<Value> {
        if token.trim().is_empty() {
            return None;
        }

        let header = decode_header(token).ok()?;
        if header.alg != Algorithm::RS256 {
            // Lock the algorithm: anything but RS256 is rejected up-front.
            // Defends against alg=none, HS256-confusion, etc.
            return None;
        }
        // Strict kid lookup: if the header names a kid that we don't know,
        // reject outright instead of falling back to the active key. Missing
        // kid is allowed (legacy / our own pre-kid issuance) and uses the
        // active key.
        let decoding_key = self.keys.decoding_key_by_kid(header.kid.as_deref())?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.expected_issuer]);
        validation.validate_exp = !allow_expired;
        validation.validate_nbf = true;
        if allow_expired {
            // jsonwebtoken's `validate_exp = false` still rejects missing `exp`.
            // Required-spec-claims keeps the presence check; we just disabled
            // the freshness comparison.
            validation.leeway = 0;
        }
        if let Some(aud) = expected_audience {
            validation.set_audience(&[aud]);
        } else {
            validation.validate_aud = false;
        }
        validation.set_required_spec_claims(&["iss", "exp"]);

        decode::<Value>(token, &decoding_key, &validation)
            .ok()
            .map(|td| td.claims)
    }
}

fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> Arc<RsaKeyProvider> {
        let tmp = std::env::temp_dir().join(format!(
            "auth-server-jwt-test-{}",
            uuid::Uuid::new_v4()
        ));
        Arc::new(
            RsaKeyProvider::init(Some(tmp.to_str().unwrap())).expect("init key provider"),
        )
    }

    #[test]
    fn access_token_round_trip() {
        let keys = provider();
        let issuer = "http://localhost:8080";
        let signer = JwtSigner::new(
            keys.clone(),
            issuer,
            Duration::from_secs(900),
            Duration::from_secs(3600),
        );
        let validator = JwtValidator::new(keys, issuer);

        let mut extras = Map::new();
        extras.insert("scope".to_string(), json!("openid profile"));
        let token = signer
            .sign_access_token("user-123", "client-abc", extras)
            .expect("sign");

        let claims = validator.validate(&token).expect("validate ok");
        assert_eq!(claims["sub"], "user-123");
        assert_eq!(claims["scope"], "openid profile");
        assert_eq!(claims["iss"], issuer);
    }

    #[test]
    fn wrong_issuer_rejected() {
        let keys = provider();
        let signer = JwtSigner::new(
            keys.clone(),
            "http://localhost:8080",
            Duration::from_secs(900),
            Duration::from_secs(3600),
        );
        let token = signer
            .sign_access_token("user", "client", Map::new())
            .expect("sign");

        let validator = JwtValidator::new(keys, "http://evil.example");
        assert!(validator.validate(&token).is_none());
    }

    #[test]
    fn audience_binding_enforced_when_provided() {
        let keys = provider();
        let issuer = "http://localhost:8080";
        let signer = JwtSigner::new(
            keys.clone(),
            issuer,
            Duration::from_secs(900),
            Duration::from_secs(3600),
        );
        let validator = JwtValidator::new(keys, issuer);

        let token = signer
            .sign_id_token("user", "client-A", Some("nonce-1"), 1700000000, Map::new())
            .expect("sign");

        // Correct aud: pass. Mismatched aud: reject.
        assert!(validator.validate_with(&token, Some("client-A")).is_some());
        assert!(validator.validate_with(&token, Some("client-B")).is_none());
    }
}
