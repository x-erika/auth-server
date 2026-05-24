//! Port of `com.xerika.auth.password.PasswordFlow`.

use chrono::{Duration as ChronoDuration, Utc};
use uuid::Uuid;

use crate::common::crypto::argon2 as argon2_hasher;
use crate::common::crypto::hmac_sha256::HmacSha256;
use crate::common::crypto::random_tokens;
use crate::session::{SessionRepository, SessionRepositoryError};
use crate::user::{Credential, CredentialRepository, UserRepository};

use super::model::PasswordReset;
use super::repository::PasswordResetRepository;

const RESET_TOKEN_TTL_MINUTES: i64 = 30;
const RESET_TOKEN_BYTES: usize = 32;
const MIN_PASSWORD_LEN: usize = 8;

#[derive(Debug, Clone, Copy)]
pub enum ResetError {
    InvalidToken,
    WeakPassword,
}

#[derive(Debug, Clone, Copy)]
pub enum ChangeError {
    WrongPassword,
    WeakPassword,
}

#[derive(Clone)]
pub struct PasswordFlow {
    users: UserRepository,
    credentials: CredentialRepository,
    password_resets: PasswordResetRepository,
    sessions: SessionRepository,
    hmac: HmacSha256,
}

impl PasswordFlow {
    pub fn new(
        users: UserRepository,
        credentials: CredentialRepository,
        password_resets: PasswordResetRepository,
        sessions: SessionRepository,
        hmac: HmacSha256,
    ) -> Self {
        Self {
            users,
            credentials,
            password_resets,
            sessions,
            hmac,
        }
    }

    /// Issue a password-reset token. Returns `Some(token)` only if the
    /// account exists; the resource always responds identically to defeat
    /// account enumeration. In production the token would go via email —
    /// dev mode keeps it in the JSON body for testing.
    pub async fn request_reset(&self, identifier: &str) -> sqlx::Result<Option<String>> {
        let trimmed = identifier.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        let user = if trimmed.contains('@') {
            self.users.find_by_email(trimmed).await?
        } else {
            match self.users.find_by_username(trimmed).await? {
                Some(u) => Some(u),
                None => self.users.find_by_email(trimmed).await?,
            }
        };
        let user = match user {
            Some(u) if u.enabled => u,
            _ => return Ok(None),
        };

        let token_raw = random_tokens::url_safe(RESET_TOKEN_BYTES);
        let token_hash = self.hmac.compute(&token_raw);
        let now = Utc::now().naive_utc();
        let reset = PasswordReset {
            id: Uuid::new_v4(),
            user_id: user.id,
            token_hash,
            expires_at: now + ChronoDuration::minutes(RESET_TOKEN_TTL_MINUTES),
            consumed_at: None,
            created_at: now,
        };
        self.password_resets.persist(&reset).await?;
        Ok(Some(token_raw))
    }

    /// Consume a reset token + rotate the user's password. On success,
    /// every other session of that user is killed so a thief that set up
    /// a parallel login can't keep using it.
    pub async fn consume_reset(
        &self,
        token_raw: &str,
        new_password: &str,
    ) -> Result<Result<(), ResetError>, ConsumeResetIoError> {
        if new_password.len() < MIN_PASSWORD_LEN {
            return Ok(Err(ResetError::WeakPassword));
        }
        if token_raw.trim().is_empty() {
            return Ok(Err(ResetError::InvalidToken));
        }

        let hash = self.hmac.compute(token_raw);
        let reset = self.password_resets.find_by_token_hash(&hash).await?;
        let reset = match reset {
            Some(r)
                if r.consumed_at.is_none() && r.expires_at >= Utc::now().naive_utc() =>
            {
                r
            }
            _ => return Ok(Err(ResetError::InvalidToken)),
        };

        self.rotate_password(reset.user_id, new_password).await?;
        self.password_resets.mark_consumed(reset.id).await?;

        // Invalidate every other unused reset token for this user so a thief
        // who raced to request a parallel reset can't use their copy after
        // we accepted the legitimate one.
        self.password_resets
            .consume_sibling_tokens(reset.user_id, reset.id)
            .await?;

        // Defence in depth — same as Java. Errors out (500) if Redis is
        // down, refusing to call the reset "successful" while stale
        // sessions might still be alive in cache. FK CASCADE on session_id
        // drops the refresh tokens; SessionRepository.delete_all_by_user_id
        // also marks them revoked first so reuse detection still works.
        self.sessions.delete_all_by_user_id(reset.user_id).await?;
        Ok(Ok(()))
    }

    pub async fn change_password(
        &self,
        user_id: Uuid,
        current_session_id: Option<Uuid>,
        old_password: &str,
        new_password: &str,
    ) -> Result<Result<(), ChangeError>, ConsumeResetIoError> {
        if new_password.len() < MIN_PASSWORD_LEN {
            return Ok(Err(ChangeError::WeakPassword));
        }
        let Some(_user) = self.users.find_by_id(user_id).await? else {
            return Ok(Err(ChangeError::WrongPassword));
        };
        let Some(credential) = self
            .credentials
            .find_first_by_user_id_and_type(user_id, "password")
            .await?
        else {
            return Ok(Err(ChangeError::WrongPassword));
        };
        let secret_data = credential.secret_data.unwrap_or_default();
        let credential_data = credential.credential_data.unwrap_or_default();
        if !argon2_hasher::verify(old_password, &secret_data, &credential_data) {
            return Ok(Err(ChangeError::WrongPassword));
        }
        self.rotate_password(user_id, new_password).await?;

        // Kick every session except the one this request is using. A user
        // who changed their password typically wants other devices/tabs
        // logged out (especially if the trigger was "I think someone else
        // has my account"). The current session keeps working so the user
        // isn't dumped to /login immediately after submitting the form.
        match current_session_id {
            Some(sid) => self.sessions.delete_all_by_user_id_except(user_id, sid).await?,
            None => self.sessions.delete_all_by_user_id(user_id).await?,
        };
        Ok(Ok(()))
    }

    async fn rotate_password(&self, user_id: Uuid, new_password: &str) -> sqlx::Result<()> {
        let hashed = argon2_hasher::hash(new_password);
        let now = Utc::now().naive_utc();
        let existing = self
            .credentials
            .find_first_by_user_id_and_type(user_id, "password")
            .await?;
        match existing {
            Some(mut c) => {
                c.secret_data = Some(hashed.secret_data);
                c.credential_data = Some(hashed.credential_data);
                c.updated_at = now;
                self.credentials.update(&c).await?;
            }
            None => {
                let c = Credential {
                    id: Uuid::new_v4(),
                    credential_type: "password".to_string(),
                    secret_data: Some(hashed.secret_data),
                    credential_data: Some(hashed.credential_data),
                    created_at: now,
                    updated_at: now,
                    user_id,
                };
                self.credentials.persist(&c).await?;
            }
        }
        Ok(())
    }
}

/// `consume_reset` can fail for two reasons that callers handle separately:
/// (a) the user-visible validation errors (wrapped in `Result<(), ResetError>`),
/// and (b) the IO surface — DB unavailable, Redis unavailable. The outer
/// `Result` carries the IO path; the inner `Result` carries the validation
/// path. This split lets the resource map both cleanly to HTTP codes.
#[derive(thiserror::Error, Debug)]
pub enum ConsumeResetIoError {
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    #[error(transparent)]
    Session(#[from] SessionRepositoryError),
}
