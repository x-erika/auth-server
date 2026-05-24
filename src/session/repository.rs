//! Port of `com.xerika.auth.session.SessionRepository`.
//!
//! Reads go through Redis cache keyed by `session:<sha256url(token)>`.
//! Cache read failures degrade to Postgres (logged at WARN).
//!
//! **Critical security invariant**: on logout / single-session delete /
//! bulk delete the Redis DEL happens BEFORE the Postgres DELETE. If Redis
//! is unreachable we abort the whole operation rather than risk a window
//! where the row is gone from Postgres but the session is still served
//! out of cache → bypassed auth. Same fail-safe stance as the Java code.

use std::time::Duration;

use chrono::{NaiveDateTime, Utc};
use redis::AsyncCommands;
use uuid::Uuid;

use crate::common::crypto::sha256;
use crate::common::redis::{json, keys};
use crate::db::Db;
use crate::redis_pool::RedisPool;

use super::model::{SessionSnapshot, SessionWithUser, UserSession};

#[derive(thiserror::Error, Debug)]
pub enum SessionRepositoryError {
    #[error(transparent)]
    Db(#[from] sqlx::Error),

    /// Redis unreachable during a security-critical invalidation. The PG
    /// write is aborted to avoid a stale-cache auth-bypass window.
    #[error("session invalidation aborted: redis unavailable: {0}")]
    RedisUnavailable(String),
}

#[derive(Clone)]
pub struct SessionRepository {
    db: Db,
    redis: RedisPool,
}

impl SessionRepository {
    pub fn new(db: Db, redis: RedisPool) -> Self {
        Self { db, redis }
    }

    pub async fn find_by_id(&self, id: Uuid) -> sqlx::Result<Option<UserSession>> {
        sqlx::query_as::<_, UserSession>("SELECT * FROM user_sessions WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.db)
            .await
    }

    /// Cache-first hydrate by raw token. The cache key is the SHA-256
    /// (base64url) of the token so the raw token never lands in Redis.
    pub async fn find_by_token(
        &self,
        session_token: &str,
    ) -> sqlx::Result<Option<SessionWithUser>> {
        if session_token.is_empty() {
            return Ok(None);
        }
        let token_hash = sha256::base64_url(session_token);

        if let Some(hit) = self.read_cache(&token_hash).await {
            return Ok(Some(hit));
        }

        let row: Option<(
            Uuid,
            Uuid,
            String,
            Option<String>,
            Option<String>,
            Option<NaiveDateTime>,
            Option<NaiveDateTime>,
            NaiveDateTime,
            String,
            String,
            bool,
            bool,
        )> = sqlx::query_as(
            r#"SELECT s.id, s.user_id, s.session_token, s.ip_address, s.user_agent,
                      s.expires_at, s.last_accessed_at, s.created_at,
                      u.email, u.username, u.email_verified, u.enabled
               FROM user_sessions s
               JOIN users u ON u.id = s.user_id
               WHERE s.session_token = $1"#,
        )
        .bind(session_token)
        .fetch_optional(&self.db)
        .await?;

        let Some((
            id,
            user_id,
            token,
            ip_address,
            user_agent,
            expires_at,
            last_accessed_at,
            created_at,
            email,
            username,
            email_verified,
            enabled,
        )) = row
        else {
            return Ok(None);
        };

        let hydrated = SessionWithUser {
            session: UserSession {
                id,
                user_id,
                session_token: token,
                ip_address,
                user_agent,
                expires_at,
                last_accessed_at,
                created_at,
            },
            user_email: email,
            user_username: username,
            user_email_verified: email_verified,
            user_enabled: enabled,
        };

        self.populate_cache(&token_hash, &hydrated).await;
        Ok(Some(hydrated))
    }

    pub async fn find_all_active(&self) -> sqlx::Result<Vec<UserSession>> {
        sqlx::query_as::<_, UserSession>(
            r#"SELECT * FROM user_sessions
               WHERE expires_at IS NULL OR expires_at > $1
               ORDER BY last_accessed_at DESC NULLS LAST
               LIMIT 200"#,
        )
        .bind(Utc::now().naive_utc())
        .fetch_all(&self.db)
        .await
    }

    /// Same as `find_all_active` but eager-joins the owning user's
    /// `username` and `email`. Admin FE renders these in the sessions
    /// table — without the join the column shows `—` because the bare
    /// `UserSession` only carries `user_id`. Matches Java's
    /// `SessionSummary.from(UserSession)` which dereferences `s.user`.
    pub async fn find_all_active_with_user(
        &self,
    ) -> sqlx::Result<Vec<(UserSession, String, String)>> {
        let rows: Vec<(
            Uuid,
            Uuid,
            String,
            Option<String>,
            Option<String>,
            Option<NaiveDateTime>,
            Option<NaiveDateTime>,
            NaiveDateTime,
            String,
            String,
        )> = sqlx::query_as(
            r#"SELECT s.id, s.user_id, s.session_token, s.ip_address, s.user_agent,
                      s.expires_at, s.last_accessed_at, s.created_at,
                      u.username, u.email
               FROM user_sessions s
               JOIN users u ON u.id = s.user_id
               WHERE s.expires_at IS NULL OR s.expires_at > $1
               ORDER BY s.last_accessed_at DESC NULLS LAST
               LIMIT 200"#,
        )
        .bind(Utc::now().naive_utc())
        .fetch_all(&self.db)
        .await?;
        Ok(rows
            .into_iter()
            .map(
                |(
                    id,
                    user_id,
                    session_token,
                    ip_address,
                    user_agent,
                    expires_at,
                    last_accessed_at,
                    created_at,
                    username,
                    email,
                )| {
                    (
                        UserSession {
                            id,
                            user_id,
                            session_token,
                            ip_address,
                            user_agent,
                            expires_at,
                            last_accessed_at,
                            created_at,
                        },
                        username,
                        email,
                    )
                },
            )
            .collect())
    }

    pub async fn find_active_by_user_id(
        &self,
        user_id: Uuid,
    ) -> sqlx::Result<Vec<UserSession>> {
        sqlx::query_as::<_, UserSession>(
            r#"SELECT * FROM user_sessions
               WHERE user_id = $1 AND (expires_at IS NULL OR expires_at > $2)
               ORDER BY last_accessed_at DESC NULLS LAST"#,
        )
        .bind(user_id)
        .bind(Utc::now().naive_utc())
        .fetch_all(&self.db)
        .await
    }

    /// Per-user variant of `find_all_active_with_user`. The admin FE's
    /// "sessions for {userId}" view uses this so the table can still show
    /// username/email columns consistently.
    pub async fn find_active_by_user_id_with_user(
        &self,
        user_id: Uuid,
    ) -> sqlx::Result<Vec<(UserSession, String, String)>> {
        let rows: Vec<(
            Uuid,
            Uuid,
            String,
            Option<String>,
            Option<String>,
            Option<NaiveDateTime>,
            Option<NaiveDateTime>,
            NaiveDateTime,
            String,
            String,
        )> = sqlx::query_as(
            r#"SELECT s.id, s.user_id, s.session_token, s.ip_address, s.user_agent,
                      s.expires_at, s.last_accessed_at, s.created_at,
                      u.username, u.email
               FROM user_sessions s
               JOIN users u ON u.id = s.user_id
               WHERE s.user_id = $1 AND (s.expires_at IS NULL OR s.expires_at > $2)
               ORDER BY s.last_accessed_at DESC NULLS LAST"#,
        )
        .bind(user_id)
        .bind(Utc::now().naive_utc())
        .fetch_all(&self.db)
        .await?;
        Ok(rows
            .into_iter()
            .map(
                |(
                    id,
                    user_id,
                    session_token,
                    ip_address,
                    user_agent,
                    expires_at,
                    last_accessed_at,
                    created_at,
                    username,
                    email,
                )| {
                    (
                        UserSession {
                            id,
                            user_id,
                            session_token,
                            ip_address,
                            user_agent,
                            expires_at,
                            last_accessed_at,
                            created_at,
                        },
                        username,
                        email,
                    )
                },
            )
            .collect())
    }

    pub async fn persist(
        &self,
        session: &UserSession,
        user_snapshot_fields: (String, String, bool, bool),
    ) -> sqlx::Result<()> {
        sqlx::query(
            r#"INSERT INTO user_sessions
               (id, user_id, session_token, ip_address, user_agent,
                expires_at, last_accessed_at, created_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
        )
        .bind(session.id)
        .bind(session.user_id)
        .bind(&session.session_token)
        .bind(&session.ip_address)
        .bind(&session.user_agent)
        .bind(session.expires_at)
        .bind(session.last_accessed_at)
        .bind(session.created_at)
        .execute(&self.db)
        .await?;

        if let Some(expires_at) = session.expires_at {
            let ttl = ttl_seconds(expires_at);
            if ttl > 0 {
                let (email, username, verified, enabled) = user_snapshot_fields;
                let hydrated = SessionWithUser {
                    session: session.clone(),
                    user_email: email,
                    user_username: username,
                    user_email_verified: verified,
                    user_enabled: enabled,
                };
                let token_hash = sha256::base64_url(&session.session_token);
                self.populate_cache_with_ttl(&token_hash, &hydrated, ttl as u64)
                    .await;
            }
        }
        Ok(())
    }

    pub async fn update_last_accessed(
        &self,
        session_id: Uuid,
        at: NaiveDateTime,
    ) -> sqlx::Result<()> {
        sqlx::query("UPDATE user_sessions SET last_accessed_at = $2 WHERE id = $1")
            .bind(session_id)
            .bind(at)
            .execute(&self.db)
            .await
            .map(|_| ())
    }

    /// Delete a single session by id. Cache is invalidated FIRST; if Redis
    /// is down we abort rather than risk a stale-cache auth bypass.
    pub async fn delete(&self, id: Uuid) -> Result<u64, SessionRepositoryError> {
        let token: Option<(String,)> = sqlx::query_as(
            "SELECT session_token FROM user_sessions WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await?;
        if let Some((token,)) = token {
            self.invalidate_now_or_abort(&token).await?;
        }
        // Mark refresh tokens revoked first so reuse detection has a chance
        // to notice replays before the FK cascade purges the rows.
        sqlx::query(
            r#"UPDATE refresh_tokens SET revoked = TRUE
               WHERE session_id = $1 AND revoked = FALSE"#,
        )
        .bind(id)
        .execute(&self.db)
        .await?;
        let res = sqlx::query("DELETE FROM user_sessions WHERE id = $1")
            .bind(id)
            .execute(&self.db)
            .await?;
        Ok(res.rows_affected())
    }

    /// Best-effort cache invalidation across all of a user's sessions (e.g.
    /// password reset or admin disable). Errors are logged but do NOT
    /// short-circuit the PG-side updates that follow.
    pub async fn invalidate_cache_by_user_id(&self, user_id: Uuid) -> sqlx::Result<()> {
        let tokens: Vec<(String,)> =
            sqlx::query_as("SELECT session_token FROM user_sessions WHERE user_id = $1")
                .bind(user_id)
                .fetch_all(&self.db)
                .await?;
        for (token,) in tokens {
            let hash = sha256::base64_url(&token);
            if let Ok(mut conn) = self.redis.get().await {
                let _ = conn.del::<_, ()>(keys::session(&hash)).await;
            }
        }
        Ok(())
    }

    /// Delete every session owned by `user_id`. Mirrors Java semantics
    /// exactly: every Redis DEL must succeed before any Postgres DELETE
    /// runs. If even one Redis op fails we abort.
    pub async fn delete_all_by_user_id(
        &self,
        user_id: Uuid,
    ) -> Result<u64, SessionRepositoryError> {
        let tokens: Vec<(String,)> =
            sqlx::query_as("SELECT session_token FROM user_sessions WHERE user_id = $1")
                .bind(user_id)
                .fetch_all(&self.db)
                .await?;
        let mut failed = Vec::new();
        for (token,) in &tokens {
            let hash = sha256::base64_url(token);
            let mut conn = match self.redis.get().await {
                Ok(c) => c,
                Err(e) => {
                    failed.push(format!("{}: pool: {}", &hash, e));
                    continue;
                }
            };
            if let Err(e) = conn.del::<_, ()>(keys::session(&hash)).await {
                failed.push(format!("{}: del: {}", &hash, e));
            }
        }
        if !failed.is_empty() {
            tracing::error!(
                user = %user_id,
                count = failed.len(),
                "redis DEL failed during delete_all_by_user_id — aborting PG delete"
            );
            return Err(SessionRepositoryError::RedisUnavailable(format!(
                "bulk invalidation failed: {} keys",
                failed.len()
            )));
        }
        // Mark refresh tokens revoked BEFORE the session DELETE. Even though
        // the refresh_tokens.session_id FK is ON DELETE CASCADE (so PG would
        // drop them anyway), an explicit UPDATE keeps the rows around long
        // enough for the reuse-detection sweep in TokenFlow to see them as
        // revoked=true if a stolen copy is replayed before the row is
        // naturally expired. Without this, the cascade would silently delete
        // the row and replay would just return invalid_grant — losing the
        // family-revocation signal.
        sqlx::query(
            r#"UPDATE refresh_tokens SET revoked = TRUE
               WHERE user_id = $1 AND revoked = FALSE"#,
        )
        .bind(user_id)
        .execute(&self.db)
        .await?;
        let res = sqlx::query("DELETE FROM user_sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.db)
            .await?;
        Ok(res.rows_affected())
    }

    /// Delete every session owned by `user_id` except `keep_session_id`.
    /// Same Redis-first invariant as `delete_all_by_user_id`. Used by
    /// self-service password change: kicks every other tab/device but
    /// keeps the current session alive so the user isn't bounced to /login
    /// right after submitting the form.
    pub async fn delete_all_by_user_id_except(
        &self,
        user_id: Uuid,
        keep_session_id: Uuid,
    ) -> Result<u64, SessionRepositoryError> {
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            r#"SELECT id, session_token FROM user_sessions
               WHERE user_id = $1 AND id <> $2"#,
        )
        .bind(user_id)
        .bind(keep_session_id)
        .fetch_all(&self.db)
        .await?;
        let mut failed = Vec::new();
        for (_id, token) in &rows {
            let hash = sha256::base64_url(token);
            let mut conn = match self.redis.get().await {
                Ok(c) => c,
                Err(e) => {
                    failed.push(format!("{}: pool: {}", &hash, e));
                    continue;
                }
            };
            if let Err(e) = conn.del::<_, ()>(keys::session(&hash)).await {
                failed.push(format!("{}: del: {}", &hash, e));
            }
        }
        if !failed.is_empty() {
            tracing::error!(
                user = %user_id,
                keep = %keep_session_id,
                count = failed.len(),
                "redis DEL failed during delete_all_by_user_id_except — aborting PG delete"
            );
            return Err(SessionRepositoryError::RedisUnavailable(format!(
                "selective invalidation failed: {} keys",
                failed.len()
            )));
        }
        // Mirror delete_all_by_user_id: revoke refresh tokens explicitly so
        // reuse detection can see the revoked rows before they're swept.
        sqlx::query(
            r#"UPDATE refresh_tokens SET revoked = TRUE
               WHERE user_id = $1 AND session_id <> $2 AND revoked = FALSE"#,
        )
        .bind(user_id)
        .bind(keep_session_id)
        .execute(&self.db)
        .await?;
        let res = sqlx::query(
            "DELETE FROM user_sessions WHERE user_id = $1 AND id <> $2",
        )
        .bind(user_id)
        .bind(keep_session_id)
        .execute(&self.db)
        .await?;
        Ok(res.rows_affected())
    }

    async fn invalidate_now_or_abort(
        &self,
        session_token: &str,
    ) -> Result<(), SessionRepositoryError> {
        let hash = sha256::base64_url(session_token);
        let key = keys::session(&hash);
        let mut conn = self
            .redis
            .get()
            .await
            .map_err(|e| SessionRepositoryError::RedisUnavailable(e.to_string()))?;
        conn.del::<_, ()>(&key)
            .await
            .map_err(|e| SessionRepositoryError::RedisUnavailable(e.to_string()))?;
        Ok(())
    }

    async fn read_cache(&self, token_hash: &str) -> Option<SessionWithUser> {
        let mut conn = self.redis.get().await.ok()?;
        let raw: Option<String> = conn.get(keys::session(token_hash)).await.ok().flatten();
        let raw = raw?;
        if raw.is_empty() {
            return None;
        }
        match json::parse::<SessionSnapshot>(&raw) {
            Ok(snap) => Some(snap.into_session_with_user()),
            Err(e) => {
                tracing::warn!(token_hash, error = %e, "session cache parse failed");
                None
            }
        }
    }

    async fn populate_cache(&self, token_hash: &str, hydrated: &SessionWithUser) {
        let Some(expires_at) = hydrated.session.expires_at else {
            return;
        };
        let ttl = ttl_seconds(expires_at);
        if ttl <= 0 {
            return;
        }
        self.populate_cache_with_ttl(token_hash, hydrated, ttl as u64)
            .await;
    }

    async fn populate_cache_with_ttl(
        &self,
        token_hash: &str,
        hydrated: &SessionWithUser,
        ttl_seconds: u64,
    ) {
        let snap = SessionSnapshot::from_session_with_user(hydrated);
        let payload = match json::stringify(&snap) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(token_hash, error = %e, "session snapshot serialize failed");
                return;
            }
        };
        let Ok(mut conn) = self.redis.get().await else {
            return;
        };
        if let Err(e) = conn
            .set_ex::<_, _, ()>(keys::session(token_hash), payload, ttl_seconds)
            .await
        {
            tracing::warn!(token_hash, error = %e, "session cache populate failed");
        }
    }
}

fn ttl_seconds(expires_at: NaiveDateTime) -> i64 {
    let diff = expires_at.and_utc().signed_duration_since(Utc::now());
    diff.num_seconds()
}

// Silence unused warning on Duration import while the only TTL we currently
// build comes from a NaiveDateTime difference.
#[allow(dead_code)]
fn _ensure_duration_used(_: Duration) {}
