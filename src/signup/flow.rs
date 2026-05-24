//! Port of `com.xerika.auth.signup.SignupFlow`.
//!
//! Single transaction wraps:
//!   1. validate + normalize email
//!   2. check email/username uniqueness
//!   3. insert user
//!   4. insert credential (Argon2id hash)
//!   5. assign default "user" role (if seeded)
//!   6. mint + persist email-verification token
//!
//! Postgres' unique constraints on `email`/`username` close the TOCTOU
//! window between the existence check and the INSERT — we catch
//! `unique_violation` (PG SQLSTATE `23505`) and surface a `conflict`
//! result, same as the Java `PersistenceException` branch.

use chrono::{Duration as ChronoDuration, Utc};
use uuid::Uuid;

use crate::common::crypto::argon2 as argon2_hasher;
use crate::common::crypto::hmac_sha256::HmacSha256;
use crate::common::crypto::random_tokens;
use crate::db::Db;
use crate::role::RoleRepository;
use crate::user::{Credential, User};

use super::dto::{SignupError, SignupRequest, VerifyEmailError};
use super::model::EmailVerification;
use super::repository::EmailVerificationRepository;

const VERIFICATION_TOKEN_TTL_HOURS: i64 = 24;
const VERIFICATION_TOKEN_BYTES: usize = 32;
const MIN_PASSWORD_LEN: usize = 8;

#[derive(Clone)]
pub struct SignupFlow {
    db: Db,
    roles: RoleRepository,
    email_verifications: EmailVerificationRepository,
    hmac: HmacSha256,
}

pub struct SignupSuccess {
    pub user_id: Uuid,
    pub verification_token_raw: String,
}

pub struct VerifyEmailSuccess {
    pub user_id: Uuid,
}

impl SignupFlow {
    pub fn new(
        db: Db,
        roles: RoleRepository,
        email_verifications: EmailVerificationRepository,
        hmac: HmacSha256,
    ) -> Self {
        Self {
            db,
            roles,
            email_verifications,
            hmac,
        }
    }

    pub async fn signup(&self, req: &SignupRequest) -> Result<SignupSuccess, SignupError> {
        let email = req.email.as_deref().unwrap_or("");
        let password = req.password.as_deref().unwrap_or("");
        let username = req.username.as_deref().unwrap_or("");
        if email.trim().is_empty() || password.trim().is_empty() || username.trim().is_empty() {
            return Err(SignupError::InvalidRequest(
                "email, password, username are required",
            ));
        }
        if password.len() < MIN_PASSWORD_LEN {
            return Err(SignupError::InvalidRequest(
                "password must be at least 8 characters",
            ));
        }

        let normalized_email = email.trim().to_lowercase();
        let now = Utc::now().naive_utc();

        // Hash before opening the transaction — Argon2 takes ~50ms and we
        // don't want to hold a PG transaction open across that.
        let hashed = argon2_hasher::hash(password);

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|_| SignupError::InvalidRequest("internal"))?;

        // Optimistic existence check inside the tx — the unique constraints
        // still catch racing inserts, but this lets us return a clean
        // "conflict" without a constraint-violation exception in the
        // common case.
        let exists_email: Option<(Uuid,)> =
            sqlx::query_as("SELECT id FROM users WHERE LOWER(email) = $1")
                .bind(&normalized_email)
                .fetch_optional(&mut *tx)
                .await
                .map_err(map_db_err)?;
        if exists_email.is_some() {
            return Err(SignupError::Conflict("email already registered"));
        }
        let exists_username: Option<(Uuid,)> =
            sqlx::query_as("SELECT id FROM users WHERE username = $1")
                .bind(username)
                .fetch_optional(&mut *tx)
                .await
                .map_err(map_db_err)?;
        if exists_username.is_some() {
            return Err(SignupError::Conflict("username already taken"));
        }

        let user = User {
            id: Uuid::new_v4(),
            email: normalized_email,
            email_verified: false,
            username: username.to_string(),
            first_name: req.first_name.clone(),
            last_name: req.last_name.clone(),
            enabled: true,
            created_at: now,
            updated_at: now,
        };

        let insert_user = sqlx::query(
            r#"INSERT INTO users
               (id, email, email_verified, username, first_name, last_name,
                enabled, created_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)"#,
        )
        .bind(user.id)
        .bind(&user.email)
        .bind(user.email_verified)
        .bind(&user.username)
        .bind(&user.first_name)
        .bind(&user.last_name)
        .bind(user.enabled)
        .bind(user.created_at)
        .bind(user.updated_at)
        .execute(&mut *tx)
        .await;
        if let Err(e) = insert_user {
            return Err(map_unique_or_internal(e));
        }

        let credential = Credential {
            id: Uuid::new_v4(),
            credential_type: "password".to_string(),
            secret_data: Some(hashed.secret_data),
            credential_data: Some(hashed.credential_data),
            created_at: now,
            updated_at: now,
            user_id: user.id,
        };
        sqlx::query(
            r#"INSERT INTO credentials
               (id, type, secret_data, credential_data, created_at, updated_at, user_id)
               VALUES ($1,$2,$3,$4,$5,$6,$7)"#,
        )
        .bind(credential.id)
        .bind(&credential.credential_type)
        .bind(&credential.secret_data)
        .bind(&credential.credential_data)
        .bind(credential.created_at)
        .bind(credential.updated_at)
        .bind(credential.user_id)
        .execute(&mut *tx)
        .await
        .map_err(map_db_err)?;

        // Assign default "user" role if it's been seeded. Silently skip if
        // missing — pure Quarkus dev mode the bootstrap does seed it, but
        // a fresh checkout without bootstrap shouldn't break signup.
        if let Ok(Some(role)) = self.roles.find_by_name("user").await {
            let _ = sqlx::query(
                r#"INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)
                   ON CONFLICT DO NOTHING"#,
            )
            .bind(user.id)
            .bind(role.id)
            .execute(&mut *tx)
            .await;
        }

        let token_raw = random_tokens::url_safe(VERIFICATION_TOKEN_BYTES);
        let token_hash = self.hmac.compute(&token_raw);
        let verification = EmailVerification {
            id: Uuid::new_v4(),
            user_id: user.id,
            token_hash,
            expires_at: now + ChronoDuration::hours(VERIFICATION_TOKEN_TTL_HOURS),
            consumed_at: None,
            created_at: now,
        };
        sqlx::query(
            r#"INSERT INTO email_verifications
               (id, user_id, token_hash, expires_at, consumed_at, created_at)
               VALUES ($1,$2,$3,$4,$5,$6)"#,
        )
        .bind(verification.id)
        .bind(verification.user_id)
        .bind(&verification.token_hash)
        .bind(verification.expires_at)
        .bind(verification.consumed_at)
        .bind(verification.created_at)
        .execute(&mut *tx)
        .await
        .map_err(map_db_err)?;

        tx.commit().await.map_err(map_db_err)?;

        Ok(SignupSuccess {
            user_id: user.id,
            verification_token_raw: token_raw,
        })
    }

    pub async fn verify_email(
        &self,
        token_raw: &str,
    ) -> Result<VerifyEmailSuccess, VerifyEmailError> {
        if token_raw.trim().is_empty() {
            return Err(VerifyEmailError::InvalidRequest("token is required"));
        }

        let hash = self.hmac.compute(token_raw);
        let verification = match self
            .email_verifications
            .find_by_token_hash(&hash)
            .await
            .map_err(|_| VerifyEmailError::InvalidToken("verification token not found"))?
        {
            Some(v) => v,
            None => {
                return Err(VerifyEmailError::InvalidToken(
                    "verification token not found",
                ));
            }
        };

        if verification.consumed_at.is_some() {
            return Err(VerifyEmailError::InvalidToken(
                "verification token already used",
            ));
        }
        if verification.expires_at < Utc::now().naive_utc() {
            return Err(VerifyEmailError::InvalidToken(
                "verification token expired",
            ));
        }

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|_| VerifyEmailError::InvalidToken("internal"))?;

        sqlx::query("UPDATE users SET email_verified = TRUE, updated_at = NOW() WHERE id = $1")
            .bind(verification.user_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| VerifyEmailError::InvalidToken("internal"))?;
        sqlx::query("UPDATE email_verifications SET consumed_at = NOW() WHERE id = $1")
            .bind(verification.id)
            .execute(&mut *tx)
            .await
            .map_err(|_| VerifyEmailError::InvalidToken("internal"))?;

        tx.commit()
            .await
            .map_err(|_| VerifyEmailError::InvalidToken("internal"))?;

        Ok(VerifyEmailSuccess {
            user_id: verification.user_id,
        })
    }
}

fn map_db_err(_: sqlx::Error) -> SignupError {
    SignupError::InvalidRequest("internal")
}

fn map_unique_or_internal(e: sqlx::Error) -> SignupError {
    // PG SQLSTATE 23505 = unique_violation. Anything else is unexpected →
    // surface as a 400 with the conservative "conflict" wording (matches
    // Java which catches the umbrella `PersistenceException`).
    if let Some(db_err) = e.as_database_error() {
        if db_err.code().as_deref() == Some("23505") {
            return SignupError::Conflict("email or username already registered");
        }
    }
    SignupError::InvalidRequest("internal")
}
