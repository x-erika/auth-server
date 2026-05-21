//! `UserSession` row + `SessionSnapshot` cache codec. The snapshot
//! flattens the joined user fields the same way Java does so a single
//! `GET session:<hash>` returns everything `LoginService` needs without a
//! follow-up `findById` to `users`.

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct UserSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub session_token: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: Option<NaiveDateTime>,
    pub last_accessed_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
}

/// Cache shape. Carries enough of the owning user that auth checks can
/// short-circuit on `user_enabled`/`email_verified` without a second hop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSnapshot {
    pub id: Uuid,
    pub user_id: Uuid,
    pub user_email: String,
    pub user_username: String,
    pub user_email_verified: bool,
    pub user_enabled: bool,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
}

/// Hydrated session result for callers that need the joined user fields
/// inline (the common case — login/authorize/admin). Pulled together by
/// `SessionRepository::find_by_token` either from cache or via a JOIN.
#[derive(Debug, Clone)]
pub struct SessionWithUser {
    pub session: UserSession,
    pub user_email: String,
    pub user_username: String,
    pub user_email_verified: bool,
    pub user_enabled: bool,
}

impl SessionSnapshot {
    pub fn into_session_with_user(self) -> SessionWithUser {
        SessionWithUser {
            session: UserSession {
                id: self.id,
                user_id: self.user_id,
                // Cache deliberately omits the raw session_token (defense in
                // depth — anyone reading Redis already has the hash). Callers
                // that need the literal token never go through this path.
                session_token: String::new(),
                ip_address: self.ip_address,
                user_agent: self.user_agent,
                expires_at: self.expires_at,
                last_accessed_at: None,
                created_at: self.created_at,
            },
            user_email: self.user_email,
            user_username: self.user_username,
            user_email_verified: self.user_email_verified,
            user_enabled: self.user_enabled,
        }
    }

    pub fn from_session_with_user(s: &SessionWithUser) -> Self {
        Self {
            id: s.session.id,
            user_id: s.session.user_id,
            user_email: s.user_email.clone(),
            user_username: s.user_username.clone(),
            user_email_verified: s.user_email_verified,
            user_enabled: s.user_enabled,
            ip_address: s.session.ip_address.clone(),
            user_agent: s.session.user_agent.clone(),
            expires_at: s.session.expires_at,
            created_at: s.session.created_at,
        }
    }
}
