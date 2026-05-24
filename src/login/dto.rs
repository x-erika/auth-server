//! DTOs for `LoginResource` / `LoginPageResource`. Field naming mirrors the
//! Java records exactly so existing API clients keep working without a
//! renaming sweep.

use serde::{Deserialize, Serialize};

use crate::session::{SessionWithUser, UserSession};

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub identifier: Option<String>,
    pub email: Option<String>,
    pub password: Option<String>,
}

impl LoginRequest {
    /// `identifier` takes precedence; falls back to `email` if not present.
    /// Matches Java `LoginRequest.resolveIdentifier()`.
    pub fn resolve_identifier(&self) -> Option<&str> {
        match self.identifier.as_deref() {
            Some(s) if !s.trim().is_empty() => Some(s),
            _ => self.email.as_deref(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub message: String,
    pub session: SessionPayload,
    pub user: UserPayload,
}

#[derive(Debug, Serialize)]
pub struct MeResponse {
    pub session: SessionPayload,
    pub user: UserPayload,
}

#[derive(Debug, Serialize)]
pub struct SessionPayload {
    #[serde(rename = "sessionToken")]
    pub session_token: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<String>,
    #[serde(rename = "lastAccessedAt")]
    pub last_accessed_at: Option<String>,
}

impl SessionPayload {
    pub fn from_session(s: &UserSession) -> Self {
        Self {
            session_token: s.session_token.clone(),
            expires_at: s.expires_at.map(|t| t.to_string()),
            last_accessed_at: s.last_accessed_at.map(|t| t.to_string()),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct UserPayload {
    pub id: String,
    pub email: String,
    pub username: String,
    #[serde(rename = "emailVerified")]
    pub email_verified: bool,
    pub roles: Vec<String>,
}

impl UserPayload {
    pub fn from_session_with_user(s: &SessionWithUser, roles: Vec<String>) -> Self {
        Self {
            id: s.session.user_id.to_string(),
            email: s.user_email.clone(),
            username: s.user_username.clone(),
            email_verified: s.user_email_verified,
            roles,
        }
    }

    pub fn from_user(
        user_id: uuid::Uuid,
        email: &str,
        username: &str,
        email_verified: bool,
        roles: Vec<String>,
    ) -> Self {
        Self {
            id: user_id.to_string(),
            email: email.to_string(),
            username: username.to_string(),
            email_verified,
            roles,
        }
    }
}
