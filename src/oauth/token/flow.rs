//! Port of `TokenFlow.java`.

use chrono::Utc;

use crate::client::{Client, ClientRepository, ClientSecretHasher};
use crate::common::crypto::hmac_sha256::HmacSha256;
use crate::db::Db;
use crate::oauth::authorize::AuthCodeStore;
use crate::oauth::device::{
    DeviceAuthorizationRepository,
    model::{STATUS_APPROVED, STATUS_CONSUMED, STATUS_DENIED, STATUS_PENDING},
};
use crate::oauth::pkce;
use crate::oauth::scopes;
use crate::session::SessionRepository;
use crate::user::UserRepository;

use super::issuer::TokenIssuer;
use super::repository::RefreshTokenRepository;
use super::result::TokenResult;

#[derive(Clone)]
pub struct TokenFlow {
    db: Db,
    clients: ClientRepository,
    users: UserRepository,
    sessions: SessionRepository,
    auth_codes: AuthCodeStore,
    // Mirrors Java's `@Inject RefreshTokenRepository` (TokenFlow.java:40). Rust
    // calls go through `RefreshTokenRepository::*_in_tx` static methods because
    // sqlx threads the transaction explicitly, so this field isn't read via
    // `self.` — kept for 1:1 parity with the Java DI shape.
    #[allow(dead_code)]
    refresh_tokens: RefreshTokenRepository,
    issuer: TokenIssuer,
    device_repo: DeviceAuthorizationRepository,
    hmac: HmacSha256,
}

#[allow(clippy::too_many_arguments)]
pub struct TokenRequest<'a> {
    pub grant_type: Option<&'a str>,
    pub code: Option<&'a str>,
    pub redirect_uri: Option<&'a str>,
    pub client_id: Option<&'a str>,
    pub client_secret: Option<&'a str>,
    pub code_verifier: Option<&'a str>,
    pub refresh_token: Option<&'a str>,
    pub scope: Option<&'a str>,
    pub device_code: Option<&'a str>,
}

impl TokenFlow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db: Db,
        clients: ClientRepository,
        users: UserRepository,
        sessions: SessionRepository,
        auth_codes: AuthCodeStore,
        refresh_tokens: RefreshTokenRepository,
        issuer: TokenIssuer,
        device_repo: DeviceAuthorizationRepository,
        hmac: HmacSha256,
    ) -> Self {
        Self {
            db,
            clients,
            users,
            sessions,
            auth_codes,
            refresh_tokens,
            issuer,
            device_repo,
            hmac,
        }
    }

    pub async fn token(&self, req: TokenRequest<'_>) -> anyhow::Result<TokenResult> {
        match req.grant_type.unwrap_or("") {
            "authorization_code" => self.from_authorization_code(&req).await,
            "refresh_token" => self.from_refresh_token(&req).await,
            "client_credentials" => self.from_client_credentials(&req).await,
            "urn:ietf:params:oauth:grant-type:device_code" => self.from_device_code(&req).await,
            _ => Ok(TokenResult::error(
                "unsupported_grant_type",
                "Supported: authorization_code, refresh_token, client_credentials, device_code",
            )),
        }
    }

    async fn from_device_code(&self, req: &TokenRequest<'_>) -> anyhow::Result<TokenResult> {
        let device_code = req.device_code.unwrap_or("");
        let client_id = req.client_id.unwrap_or("");
        if device_code.is_empty() || client_id.is_empty() {
            return Ok(TokenResult::error(
                "invalid_request",
                "device_code and client_id are required",
            ));
        }
        let Some(client) = self.clients.find_by_client_id(client_id).await? else {
            return Ok(TokenResult::error(
                "unauthorized_client",
                "Unknown or disabled client",
            ));
        };
        if !client.enabled {
            return Ok(TokenResult::error(
                "unauthorized_client",
                "Unknown or disabled client",
            ));
        }
        if !authenticate_client(&client, req.client_secret) {
            return Ok(TokenResult::error(
                "invalid_client",
                "Invalid client credentials",
            ));
        }

        let mut auth = match self.device_repo.find_by_device_code(device_code).await? {
            Some(a) => a,
            None => return Ok(TokenResult::error("invalid_grant", "Unknown device_code")),
        };
        if auth.client_id != client_id {
            return Ok(TokenResult::error(
                "invalid_grant",
                "device_code does not belong to this client",
            ));
        }
        if auth.expires_at < Utc::now().naive_utc() {
            return Ok(TokenResult::error("expired_token", "device_code expired"));
        }
        match auth.status.as_str() {
            s if s == STATUS_PENDING => {
                return Ok(TokenResult::error(
                    "authorization_pending",
                    "User has not yet approved",
                ));
            }
            s if s == STATUS_DENIED => {
                return Ok(TokenResult::error(
                    "access_denied",
                    "User denied the authorization request",
                ));
            }
            s if s == STATUS_CONSUMED => {
                return Ok(TokenResult::error(
                    "invalid_grant",
                    "device_code already used",
                ));
            }
            s if s == STATUS_APPROVED => { /* fallthrough */ }
            _ => {
                return Ok(TokenResult::error(
                    "invalid_grant",
                    "Unknown device_code state",
                ));
            }
        }

        let Some(user_id) = auth.user_id else {
            return Ok(TokenResult::error(
                "invalid_grant",
                "Approved device_code missing user binding",
            ));
        };
        let Some(session_id) = auth.session_id else {
            return Ok(TokenResult::error(
                "invalid_grant",
                "Approved device_code missing user binding",
            ));
        };

        let user = self.users.find_by_id(user_id).await?;
        let session = self.sessions.find_by_id(session_id).await?;
        let (Some(user), Some(session)) = (user, session) else {
            return Ok(TokenResult::error("invalid_grant", "User/session not found"));
        };

        auth.status = STATUS_CONSUMED.to_string();
        self.device_repo.update(&auth).await?;

        let mut tx = self.db.begin().await?;
        let payload = self
            .issuer
            .issue(
                &mut tx,
                &user,
                &client,
                &session,
                auth.scope.as_deref(),
                None,
                None,
            )
            .await?;
        tx.commit().await?;
        Ok(TokenResult::success(payload))
    }

    async fn from_client_credentials(
        &self,
        req: &TokenRequest<'_>,
    ) -> anyhow::Result<TokenResult> {
        let client_id = req.client_id.unwrap_or("");
        if client_id.is_empty() {
            return Ok(TokenResult::error("invalid_request", "client_id is required"));
        }
        let Some(client) = self.clients.find_by_client_id(client_id).await? else {
            return Ok(TokenResult::error(
                "unauthorized_client",
                "Unknown or disabled client",
            ));
        };
        if !client.enabled {
            return Ok(TokenResult::error(
                "unauthorized_client",
                "Unknown or disabled client",
            ));
        }
        if client.client_type.as_deref().unwrap_or("").to_ascii_lowercase() != "confidential" {
            return Ok(TokenResult::error(
                "unauthorized_client",
                "client_credentials grant requires a confidential client",
            ));
        }
        if !authenticate_client(&client, req.client_secret) {
            return Ok(TokenResult::error(
                "invalid_client",
                "Invalid client credentials",
            ));
        }
        if !scopes::is_subset_of(req.scope, client.scopes.as_deref()) {
            return Ok(TokenResult::error(
                "invalid_scope",
                "Requested scope is not allowed for this client",
            ));
        }
        let payload = self.issuer.issue_for_client(&client, req.scope)?;
        Ok(TokenResult::success(payload))
    }

    async fn from_authorization_code(
        &self,
        req: &TokenRequest<'_>,
    ) -> anyhow::Result<TokenResult> {
        let code = req.code.unwrap_or("");
        let redirect_uri = req.redirect_uri.unwrap_or("");
        let client_id = req.client_id.unwrap_or("");
        if code.is_empty() || redirect_uri.is_empty() || client_id.is_empty() {
            return Ok(TokenResult::error(
                "invalid_request",
                "code, redirect_uri, client_id are required",
            ));
        }
        let Some(client) = self.clients.find_by_client_id(client_id).await? else {
            return Ok(TokenResult::error(
                "unauthorized_client",
                "Unknown or disabled client",
            ));
        };
        if !client.enabled {
            return Ok(TokenResult::error(
                "unauthorized_client",
                "Unknown or disabled client",
            ));
        }
        if !authenticate_client(&client, req.client_secret) {
            return Ok(TokenResult::error(
                "invalid_client",
                "Invalid client credentials",
            ));
        }

        let auth_code = self.auth_codes.consume(code).await?;
        let Some(auth_code) = auth_code else {
            return Ok(TokenResult::error("invalid_grant", "Invalid authorization code"));
        };
        if auth_code.expires_at < Utc::now().naive_utc() {
            return Ok(TokenResult::error("invalid_grant", "Authorization code expired"));
        }
        if auth_code.client_id != client_id || auth_code.redirect_uri != redirect_uri {
            return Ok(TokenResult::error("invalid_grant", "Code binding mismatch"));
        }

        // PKCE: verify whenever a challenge exists, even if not required.
        let code_has_challenge = auth_code
            .code_challenge
            .as_deref()
            .is_some_and(|c| !c.is_empty());
        if client.pkce_required || code_has_challenge {
            let verifier = req.code_verifier.unwrap_or("");
            if verifier.is_empty() {
                return Ok(TokenResult::error(
                    "invalid_request",
                    "code_verifier is required",
                ));
            }
            let challenge = auth_code.code_challenge.as_deref().unwrap_or("");
            let method = auth_code.code_challenge_method.as_deref().unwrap_or("");
            if !pkce::verify(verifier, challenge, method) {
                return Ok(TokenResult::error("invalid_grant", "PKCE verification failed"));
            }
        }

        let user = self.users.find_by_id(auth_code.user_id).await?;
        let session = self.sessions.find_by_id(auth_code.session_id).await?;
        let (Some(user), Some(session)) = (user, session) else {
            return Ok(TokenResult::error("invalid_grant", "User/session not found"));
        };

        let mut tx = self.db.begin().await?;
        let payload = self
            .issuer
            .issue(
                &mut tx,
                &user,
                &client,
                &session,
                auth_code.scope.as_deref(),
                auth_code.nonce.as_deref(),
                auth_code.claims_requested.as_deref(),
            )
            .await?;
        tx.commit().await?;
        Ok(TokenResult::success(payload))
    }

    async fn from_refresh_token(&self, req: &TokenRequest<'_>) -> anyhow::Result<TokenResult> {
        let raw = req.refresh_token.unwrap_or("");
        let client_id = req.client_id.unwrap_or("");
        if raw.is_empty() || client_id.is_empty() {
            return Ok(TokenResult::error(
                "invalid_request",
                "refresh_token and client_id are required",
            ));
        }
        let Some(client) = self.clients.find_by_client_id(client_id).await? else {
            return Ok(TokenResult::error(
                "unauthorized_client",
                "Unknown or disabled client",
            ));
        };
        if !client.enabled {
            return Ok(TokenResult::error(
                "unauthorized_client",
                "Unknown or disabled client",
            ));
        }
        if !authenticate_client(&client, req.client_secret) {
            return Ok(TokenResult::error(
                "invalid_client",
                "Invalid client credentials",
            ));
        }

        let refresh_hash = self.hmac.compute(raw);

        // Single transaction holds the FOR UPDATE row lock across
        // read → check → revoke → insert-new. Two concurrent refreshes with
        // the same raw token can't both observe revoked=false.
        let mut tx = self.db.begin().await?;
        let stored =
            RefreshTokenRepository::find_by_token_hash_for_update(&mut *tx, &refresh_hash).await?;
        let Some(stored) = stored else {
            return Ok(TokenResult::error("invalid_grant", "Invalid refresh token"));
        };

        // Reuse detection (OAuth Security BCP §4.13): a presented-but-revoked
        // token means replay or compromise — kill the whole session-family.
        if stored.revoked {
            let _ = RefreshTokenRepository::revoke_by_session_id_in_tx(&mut *tx, stored.session_id)
                .await;
            tx.commit().await?;
            return Ok(TokenResult::error(
                "invalid_grant",
                "Refresh token revoked — session terminated",
            ));
        }

        if let Some(exp) = stored.expires_at {
            if exp < Utc::now().naive_utc() {
                return Ok(TokenResult::error("invalid_grant", "Refresh token expired"));
            }
        }
        if stored.client_id != client.id {
            return Ok(TokenResult::error(
                "invalid_grant",
                "Refresh token client mismatch",
            ));
        }

        let user = self.users.find_by_id(stored.user_id).await?;
        let session = self.sessions.find_by_id(stored.session_id).await?;
        let (Some(user), Some(session)) = (user, session) else {
            return Ok(TokenResult::error("invalid_grant", "User/session not valid"));
        };
        if !user.enabled {
            return Ok(TokenResult::error("invalid_grant", "User/session not valid"));
        }

        RefreshTokenRepository::update_revoked_in_tx(&mut *tx, stored.id, true).await?;

        let payload = self
            .issuer
            .issue(
                &mut tx,
                &user,
                &client,
                &session,
                client.scopes.as_deref(),
                None,
                None,
            )
            .await?;
        tx.commit().await?;
        Ok(TokenResult::success(payload))
    }
}

/// Client auth. Public clients pass through; confidential require a
/// matching `client_secret` (Argon2-verified, with legacy-plaintext fallback
/// inside `ClientSecretHasher::verify`).
fn authenticate_client(client: &Client, presented_secret: Option<&str>) -> bool {
    if client.client_type.as_deref().unwrap_or("").to_ascii_lowercase() != "confidential" {
        return true;
    }
    let Some(presented) = presented_secret else {
        return false;
    };
    if presented.is_empty() {
        return false;
    }
    let Some(stored) = client.client_secret.as_deref() else {
        return false;
    };
    ClientSecretHasher::verify(presented, stored)
}
