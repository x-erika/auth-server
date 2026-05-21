//! Port of `com.xerika.auth.session.SessionService`.
//!
//! Wraps `SessionRepository` with the small amount of business logic the
//! Java side has: token minting on create, expiry check + enabled check +
//! last-accessed bump on lookup, "find then delete" on logout.

use chrono::{Duration as ChronoDuration, Utc};
use uuid::Uuid;

use crate::common::crypto::random_tokens;

use super::model::{SessionWithUser, UserSession};
use super::repository::{SessionRepository, SessionRepositoryError};

/// Session TTL — 8 hours, same as Java's `now().plusHours(8)`.
pub const SESSION_TTL_HOURS: i64 = 8;

#[derive(Clone)]
pub struct SessionService {
    repo: SessionRepository,
}

impl SessionService {
    pub fn new(repo: SessionRepository) -> Self {
        Self { repo }
    }

    /// `createSession(user, ip, userAgent)` — mints a fresh session token,
    /// persists the row, and warms the Redis cache in one shot.
    pub async fn create_session(
        &self,
        user_id: Uuid,
        user_email: &str,
        user_username: &str,
        user_email_verified: bool,
        user_enabled: bool,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> sqlx::Result<UserSession> {
        let now = Utc::now().naive_utc();
        let session = UserSession {
            id: Uuid::new_v4(),
            user_id,
            session_token: random_tokens::url_safe(32),
            ip_address,
            user_agent,
            expires_at: Some(now + ChronoDuration::hours(SESSION_TTL_HOURS)),
            last_accessed_at: Some(now),
            created_at: now,
        };
        self.repo
            .persist(
                &session,
                (
                    user_email.to_string(),
                    user_username.to_string(),
                    user_email_verified,
                    user_enabled,
                ),
            )
            .await?;
        Ok(session)
    }

    /// Cache-or-DB lookup followed by expiry/enabled checks and a
    /// last-accessed bump.
    pub async fn find_active_session(
        &self,
        session_token: &str,
    ) -> sqlx::Result<Option<SessionWithUser>> {
        if session_token.trim().is_empty() {
            return Ok(None);
        }
        let Some(hydrated) = self.repo.find_by_token(session_token).await? else {
            return Ok(None);
        };
        if let Some(exp) = hydrated.session.expires_at {
            if exp < Utc::now().naive_utc() {
                return Ok(None);
            }
        }
        if !hydrated.user_enabled {
            return Ok(None);
        }
        let now = Utc::now().naive_utc();
        // Best-effort — the cached entry already drove the auth decision,
        // so a transient PG failure on the bump shouldn't fail the request.
        if let Err(e) = self
            .repo
            .update_last_accessed(hydrated.session.id, now)
            .await
        {
            tracing::warn!(session_id = %hydrated.session.id, error = %e, "last_accessed bump failed");
        }
        Ok(Some(hydrated))
    }

    /// `logout` — Java returns boolean (true if a session was killed).
    /// Errors bubble up because cache invalidation failure must abort.
    pub async fn logout(
        &self,
        session_token: &str,
    ) -> Result<bool, SessionRepositoryError> {
        let Some(hit) = self.find_active_session(session_token).await? else {
            return Ok(false);
        };
        let affected = self.repo.delete(hit.session.id).await?;
        Ok(affected > 0)
    }
}
