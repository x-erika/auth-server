//! Port of `TokenIssuer.java`.
//!
//! Mints access tokens (RS256, RFC 9068 `typ: at+jwt`), refresh tokens
//! (random URL-safe + SHA-256 stored), and — when scope contains `openid`
//! — an id_token. Claim shape is byte-identical to Java so existing
//! clients keep parsing what they got.

use std::sync::Arc;

use chrono::{Duration as ChronoDuration, Utc};
use serde_json::{Map, Value, json};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::client::Client;
use crate::common::crypto::jwt::JwtSigner;
use crate::common::crypto::random_tokens;
use crate::common::crypto::sha256;
use crate::oauth::authorize::ClaimsRequest;
use crate::oauth::scopes;
use crate::role::RoleRepository;
use crate::session::UserSession;
use crate::user::User;

use super::model::RefreshToken;
use super::repository::RefreshTokenRepository;

const REFRESH_TOKEN_TTL_DAYS: i64 = 30;

#[derive(Clone)]
pub struct TokenIssuer {
    jwt_signer: Arc<JwtSigner>,
    roles: RoleRepository,
    refresh_tokens: RefreshTokenRepository,
}

impl TokenIssuer {
    pub fn new(
        jwt_signer: Arc<JwtSigner>,
        roles: RoleRepository,
        refresh_tokens: RefreshTokenRepository,
    ) -> Self {
        Self {
            jwt_signer,
            roles,
            refresh_tokens,
        }
    }

    /// `client_credentials` issue path — no refresh token, no id_token,
    /// minimal access claim shape.
    pub fn issue_for_client(&self, client: &Client, scope: Option<&str>) -> anyhow::Result<Value> {
        let mut claims = Map::new();
        claims.insert("scope".to_string(), json!(scope.unwrap_or("")));
        claims.insert("client_id".to_string(), json!(&client.client_id));

        let access_token =
            self.jwt_signer
                .sign_access_token(&client.client_id, &client.client_id, claims)?;

        Ok(json!({
            "token_type": "Bearer",
            "expires_in": self.jwt_signer.access_token_ttl_seconds(),
            "access_token": access_token,
            "scope": scope.unwrap_or(""),
        }))
    }

    /// Full `authorization_code` / `refresh_token` / `device_code` issue
    /// path — access + refresh + (conditional) id_token. `tx` is the
    /// caller's open transaction; the new refresh token is persisted in it.
    #[allow(clippy::too_many_arguments)]
    pub async fn issue(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        user: &User,
        client: &Client,
        session: &UserSession,
        scope: Option<&str>,
        nonce: Option<&str>,
        claims_requested_json: Option<&str>,
    ) -> anyhow::Result<Value> {
        let roles = self.roles.find_effective_names_by_user_id(user.id).await?;
        let scope_set = scopes::parse(scope);
        let claims_request = ClaimsRequest::parse(claims_requested_json);

        let access_token = self.jwt_signer.sign_access_token(
            &user.id.to_string(),
            &client.client_id,
            build_access_token_claims(user, client, session, &roles, scope, &claims_request),
        )?;

        let refresh_token_raw = random_tokens::url_safe(48);
        let refresh_token_hash = sha256::base64_url(&refresh_token_raw);
        let now = Utc::now().naive_utc();
        let refresh = RefreshToken {
            id: Uuid::new_v4(),
            user_id: user.id,
            client_id: client.id,
            session_id: session.id,
            token_hash: refresh_token_hash,
            expires_at: Some(now + ChronoDuration::days(REFRESH_TOKEN_TTL_DAYS)),
            revoked: false,
            created_at: now,
        };
        RefreshTokenRepository::persist_in_tx(tx, &refresh).await?;

        let mut response = serde_json::Map::new();
        response.insert("token_type".to_string(), json!("Bearer"));
        response.insert(
            "expires_in".to_string(),
            json!(self.jwt_signer.access_token_ttl_seconds()),
        );
        response.insert("access_token".to_string(), json!(access_token));
        response.insert("refresh_token".to_string(), json!(refresh_token_raw));
        response.insert("scope".to_string(), json!(scope.unwrap_or("")));

        if scope_set.contains("openid") {
            let auth_time = session.created_at.and_utc().timestamp();
            let id_token = self.jwt_signer.sign_id_token(
                &user.id.to_string(),
                &client.client_id,
                nonce,
                auth_time,
                build_id_token_claims(user, session, &scope_set, &claims_request),
            )?;
            response.insert("id_token".to_string(), json!(id_token));
        }

        Ok(Value::Object(response))
    }
}

fn build_access_token_claims(
    user: &User,
    client: &Client,
    session: &UserSession,
    roles: &[String],
    scope: Option<&str>,
    claims_request: &ClaimsRequest,
) -> Map<String, Value> {
    let mut claims = Map::new();
    // RFC 9068 §2.2.
    claims.insert("client_id".to_string(), json!(&client.client_id));
    claims.insert("email".to_string(), json!(&user.email));
    claims.insert("username".to_string(), json!(&user.username));
    claims.insert("sid".to_string(), json!(session.id.to_string()));
    claims.insert("roles".to_string(), json!(roles));
    claims.insert("scope".to_string(), json!(scope.unwrap_or("")));
    if !claims_request.userinfo_claims().is_empty() {
        let mut list: Vec<&String> = claims_request.userinfo_claims().iter().collect();
        list.sort(); // stable ordering for token bit-equality
        claims.insert("claims_userinfo".to_string(), json!(list));
    }
    claims
}

fn build_id_token_claims(
    user: &User,
    session: &UserSession,
    scopes: &std::collections::HashSet<String>,
    claims_request: &ClaimsRequest,
) -> Map<String, Value> {
    let mut claims = Map::new();
    // OIDC Back-Channel Logout 1.0 §2.1 — `sid` lets LogoutFlow identify
    // which session a logout_token targets.
    claims.insert("sid".to_string(), json!(session.id.to_string()));

    let include_email =
        scopes.contains("email") || claims_request.id_token_claims().contains("email");
    let include_email_verified =
        scopes.contains("email") || claims_request.id_token_claims().contains("email_verified");
    let include_profile = scopes.contains("profile");

    if include_email {
        claims.insert("email".to_string(), json!(&user.email));
    }
    if include_email_verified {
        claims.insert("email_verified".to_string(), json!(user.email_verified));
    }
    if include_profile || claims_request.id_token_claims().contains("preferred_username") {
        claims.insert("preferred_username".to_string(), json!(&user.username));
    }
    if include_profile || claims_request.id_token_claims().contains("given_name") {
        if let Some(ref first) = user.first_name {
            claims.insert("given_name".to_string(), json!(first));
        }
    }
    if include_profile || claims_request.id_token_claims().contains("family_name") {
        if let Some(ref last) = user.last_name {
            claims.insert("family_name".to_string(), json!(last));
        }
    }
    if include_profile || claims_request.id_token_claims().contains("name") {
        if let (Some(f), Some(l)) = (user.first_name.as_ref(), user.last_name.as_ref()) {
            claims.insert("name".to_string(), json!(format!("{} {}", f, l)));
        }
    }
    claims
}
