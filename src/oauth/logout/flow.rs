//! Port of `LogoutFlow.java`.
//!
//! `id_token_hint` resolves both the requester client (for
//! `post_logout_redirect_uri` validation) and — falling back to the
//! session cookie — the session to terminate. The flow revokes every
//! refresh token bound to that session, deletes the session row, builds
//! the frontchannel iframe URIs, and fires off backchannel logout POSTs.

use std::sync::Arc;

use uuid::Uuid;

use crate::client::{Client, ClientRepository};
use crate::common::crypto::jwt::JwtValidator;
use crate::db::Db;
use crate::oauth::token::RefreshTokenRepository;
use crate::session::{SessionRepository, SessionService};

use super::notifier::BackchannelLogoutNotifier;
use super::result::LogoutResult;

#[derive(Clone)]
pub struct LogoutFlow {
    db: Db,
    jwt_validator: Arc<JwtValidator>,
    sessions: SessionRepository,
    session_service: SessionService,
    refresh_tokens: RefreshTokenRepository,
    clients: ClientRepository,
    notifier: BackchannelLogoutNotifier,
    issuer_url: String,
}

impl LogoutFlow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db: Db,
        jwt_validator: Arc<JwtValidator>,
        sessions: SessionRepository,
        session_service: SessionService,
        refresh_tokens: RefreshTokenRepository,
        clients: ClientRepository,
        notifier: BackchannelLogoutNotifier,
        issuer_url: String,
    ) -> Self {
        Self {
            db,
            jwt_validator,
            sessions,
            session_service,
            refresh_tokens,
            clients,
            notifier,
            issuer_url,
        }
    }

    pub async fn logout(
        &self,
        id_token_hint: Option<&str>,
        session_token: Option<&str>,
        post_logout_redirect_uri: Option<&str>,
    ) -> anyhow::Result<LogoutResult> {
        // post_logout_redirect_uri validation. Trade-off (matches Java):
        // piggyback on the client's redirect_uri list rather than a separate
        // post_logout_redirect_uris column — collapses two OIDC concepts but
        // keeps the schema simple.
        let mut validated_post_logout: Option<String> = None;
        if let Some(uri) = post_logout_redirect_uri.filter(|s| !s.is_empty()) {
            if let Some(client) = self.resolve_client_from_id_token_hint(id_token_hint).await? {
                if self
                    .clients
                    .is_redirect_uri_allowed(client.id, uri)
                    .await?
                {
                    validated_post_logout = Some(uri.to_string());
                }
            }
            if validated_post_logout.is_none() {
                tracing::warn!(
                    %uri,
                    "dropped post_logout_redirect_uri — not registered or id_token_hint missing"
                );
            }
        }

        let session_id = self
            .resolve_session_id(id_token_hint, session_token)
            .await?;
        let Some(session_id) = session_id else {
            return Ok(LogoutResult::none(validated_post_logout));
        };

        let user_id = self.sessions.find_by_id(session_id).await?.map(|s| s.user_id);
        let client_ids = self
            .refresh_tokens
            .find_client_ids_by_session_id(session_id)
            .await?;
        let mut involved: Vec<Client> = Vec::new();
        for cid in client_ids {
            if let Some(c) = self.clients.find_by_id(cid).await? {
                involved.push(c);
            }
        }

        // Revoke + delete in two passes (matches Java order so a partial
        // failure leaves no zombie active token referencing a dead session).
        let mut tx = self.db.begin().await?;
        let _ =
            RefreshTokenRepository::revoke_by_session_id_in_tx(&mut *tx, session_id).await?;
        tx.commit().await?;
        let _ = self.sessions.delete(session_id).await;

        let mut frontchannel = Vec::new();
        for c in &involved {
            if let Some(fc) = c.frontchannel_logout_uri.as_deref().filter(|s| !s.is_empty()) {
                frontchannel.push(self.build_frontchannel_url(fc, session_id));
            }
            if c.backchannel_logout_uri
                .as_deref()
                .filter(|s| !s.is_empty())
                .is_some()
            {
                self.notifier.notify_client(c, user_id, session_id);
            }
        }

        Ok(LogoutResult {
            terminated: true,
            frontchannel_logout_uris: frontchannel,
            validated_post_logout_redirect_uri: validated_post_logout,
        })
    }

    async fn resolve_client_from_id_token_hint(
        &self,
        id_token_hint: Option<&str>,
    ) -> anyhow::Result<Option<Client>> {
        let Some(token) = id_token_hint.filter(|s| !s.is_empty()) else {
            return Ok(None);
        };
        let Some(claims) = self.jwt_validator.validate(token) else {
            return Ok(None);
        };
        let Some(aud) = claims.get("aud") else {
            return Ok(None);
        };
        let client_id_str = if let Some(arr) = aud.as_array() {
            arr.first()
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        } else {
            aud.as_str().map(|s| s.to_string())
        };
        let Some(cid) = client_id_str.filter(|s| !s.is_empty()) else {
            return Ok(None);
        };
        Ok(self.clients.find_by_client_id(&cid).await?)
    }

    async fn resolve_session_id(
        &self,
        id_token_hint: Option<&str>,
        session_token: Option<&str>,
    ) -> anyhow::Result<Option<Uuid>> {
        // 1. id_token_hint.sid
        if let Some(token) = id_token_hint.filter(|s| !s.is_empty()) {
            if let Some(claims) = self.jwt_validator.validate(token) {
                if let Some(sid) = claims.get("sid").and_then(|v| v.as_str()) {
                    if let Ok(u) = Uuid::parse_str(sid) {
                        return Ok(Some(u));
                    }
                }
            }
        }
        // 2. session cookie / Authorization header
        if let Some(t) = session_token.filter(|s| !s.is_empty()) {
            if let Some(s) = self.session_service.find_active_session(t).await? {
                return Ok(Some(s.session.id));
            }
        }
        Ok(None)
    }

    fn build_frontchannel_url(&self, uri: &str, session_id: Uuid) -> String {
        let sep = if uri.contains('?') { "&" } else { "?" };
        format!(
            "{uri}{sep}iss={}&sid={}",
            urlencoding::encode(&self.issuer_url),
            urlencoding::encode(&session_id.to_string())
        )
    }
}
