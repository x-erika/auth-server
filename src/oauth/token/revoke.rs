//! Port of `RevokeFlow.java` — RFC 7009 token revocation.
//!
//! RFC says 200 OK on success, **including** the "unknown token" case
//! (defence against probing). We only act on refresh tokens — access
//! tokens are short-lived JWTs that can't be revoked centrally, so a
//! `token_type_hint != "refresh_token"` short-circuits to success.

use crate::client::{Client, ClientRepository, ClientSecretHasher};
use crate::common::crypto::sha256;

use super::repository::RefreshTokenRepository;
use super::result::RevokeResult;

#[derive(Clone)]
pub struct RevokeFlow {
    clients: ClientRepository,
    refresh_tokens: RefreshTokenRepository,
}

impl RevokeFlow {
    pub fn new(clients: ClientRepository, refresh_tokens: RefreshTokenRepository) -> Self {
        Self {
            clients,
            refresh_tokens,
        }
    }

    pub async fn revoke(
        &self,
        token: &str,
        token_type_hint: Option<&str>,
        client_id: &str,
        client_secret: Option<&str>,
    ) -> anyhow::Result<RevokeResult> {
        if token.is_empty() || client_id.is_empty() {
            return Ok(RevokeResult::error(
                "invalid_request",
                "token and client_id are required",
            ));
        }
        let Some(client) = self.clients.find_by_client_id(client_id).await? else {
            return Ok(RevokeResult::error(
                "invalid_client",
                "Unknown or disabled client",
            ));
        };
        if !client.enabled {
            return Ok(RevokeResult::error(
                "invalid_client",
                "Unknown or disabled client",
            ));
        }
        if !authenticate_client(&client, client_secret) {
            return Ok(RevokeResult::error(
                "invalid_client",
                "Invalid client credentials",
            ));
        }

        // Non-refresh-token hint → no-op success.
        if let Some(hint) = token_type_hint.filter(|s| !s.is_empty()) {
            if hint != "refresh_token" {
                return Ok(RevokeResult::success());
            }
        }

        let token_hash = sha256::base64_url(token);
        let Some(stored) = self.refresh_tokens.find_by_token_hash(&token_hash).await? else {
            return Ok(RevokeResult::success());
        };
        if stored.client_id != client.id {
            return Ok(RevokeResult::success());
        }
        if !stored.revoked {
            self.refresh_tokens.update_revoked(stored.id, true).await?;
        }
        Ok(RevokeResult::success())
    }
}

fn authenticate_client(client: &Client, presented_secret: Option<&str>) -> bool {
    if client.client_type.as_deref().unwrap_or("").to_ascii_lowercase() != "confidential" {
        return true;
    }
    let Some(presented) = presented_secret.filter(|s| !s.is_empty()) else {
        return false;
    };
    let Some(stored) = client.client_secret.as_deref() else {
        return false;
    };
    ClientSecretHasher::verify(presented, stored)
}
