//! Port of `com.xerika.auth.user.*` — `User`, `Credential`, plus
//! [`UserRepository`] and [`CredentialRepository`].
//!
//! Hibernate's relations (`@OneToMany credentials`, `@OneToMany sessions`,
//! `@ManyToMany roles`) aren't materialized on the `User` struct — Rust
//! handlers fetch them via dedicated repository calls when needed, which
//! also avoids the implicit N+1 traps the JPA mapping invites.

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::db::Db;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub email_verified: bool,
    pub username: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub enabled: bool,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Credential {
    pub id: Uuid,
    #[sqlx(rename = "type")]
    #[serde(rename = "type")]
    pub credential_type: String,
    pub secret_data: Option<String>,
    pub credential_data: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub user_id: Uuid,
}

#[derive(Clone)]
pub struct UserRepository {
    db: Db,
}

impl UserRepository {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    pub async fn find_by_id(&self, id: Uuid) -> sqlx::Result<Option<User>> {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.db)
            .await
    }

    /// Case-insensitive lookup. Java equivalent normalizes via
    /// `LOWER(u.email) = :email`; we do the same so mixed-case rows that
    /// pre-date the lowercase-on-write policy still resolve.
    pub async fn find_by_email(&self, email: &str) -> sqlx::Result<Option<User>> {
        let normalized = email.trim().to_lowercase();
        if normalized.is_empty() {
            return Ok(None);
        }
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE LOWER(email) = $1")
            .bind(normalized)
            .fetch_optional(&self.db)
            .await
    }

    pub async fn find_by_username(&self, username: &str) -> sqlx::Result<Option<User>> {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = $1")
            .bind(username)
            .fetch_optional(&self.db)
            .await
    }

    pub async fn find_all(&self, limit: i64) -> sqlx::Result<Vec<User>> {
        sqlx::query_as::<_, User>("SELECT * FROM users ORDER BY created_at DESC LIMIT $1")
            .bind(limit)
            .fetch_all(&self.db)
            .await
    }

    /// `em.persist(user)` parity: INSERT all columns. `created_at` /
    /// `updated_at` are expected to be set by the caller (matches the Java
    /// signup/admin flows which always populate them).
    pub async fn persist(&self, user: &User) -> sqlx::Result<()> {
        sqlx::query(
            r#"INSERT INTO users
               (id, email, email_verified, username, first_name, last_name,
                enabled, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
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
        .execute(&self.db)
        .await
        .map(|_| ())
    }

    /// `em.merge(user)` parity: UPDATE on existing row.
    pub async fn update(&self, user: &User) -> sqlx::Result<Option<User>> {
        sqlx::query_as::<_, User>(
            r#"UPDATE users SET
                email = $2, email_verified = $3, username = $4,
                first_name = $5, last_name = $6, enabled = $7,
                updated_at = $8
               WHERE id = $1
               RETURNING *"#,
        )
        .bind(user.id)
        .bind(&user.email)
        .bind(user.email_verified)
        .bind(&user.username)
        .bind(&user.first_name)
        .bind(&user.last_name)
        .bind(user.enabled)
        .bind(user.updated_at)
        .fetch_optional(&self.db)
        .await
    }

    pub async fn delete(&self, id: Uuid) -> sqlx::Result<u64> {
        let res = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id)
            .execute(&self.db)
            .await?;
        Ok(res.rows_affected())
    }
}

#[derive(Clone)]
pub struct CredentialRepository {
    db: Db,
}

impl CredentialRepository {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    #[allow(dead_code)]
    pub async fn find_by_id(&self, id: Uuid) -> sqlx::Result<Option<Credential>> {
        sqlx::query_as::<_, Credential>("SELECT * FROM credentials WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.db)
            .await
    }

    #[allow(dead_code)]
    pub async fn find_by_user_id(&self, user_id: Uuid) -> sqlx::Result<Vec<Credential>> {
        sqlx::query_as::<_, Credential>("SELECT * FROM credentials WHERE user_id = $1")
            .bind(user_id)
            .fetch_all(&self.db)
            .await
    }

    pub async fn find_first_by_user_id_and_type(
        &self,
        user_id: Uuid,
        credential_type: &str,
    ) -> sqlx::Result<Option<Credential>> {
        sqlx::query_as::<_, Credential>(
            "SELECT * FROM credentials WHERE user_id = $1 AND type = $2 LIMIT 1",
        )
        .bind(user_id)
        .bind(credential_type)
        .fetch_optional(&self.db)
        .await
    }

    pub async fn persist(&self, credential: &Credential) -> sqlx::Result<()> {
        sqlx::query(
            r#"INSERT INTO credentials
               (id, type, secret_data, credential_data,
                created_at, updated_at, user_id)
               VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
        )
        .bind(credential.id)
        .bind(&credential.credential_type)
        .bind(&credential.secret_data)
        .bind(&credential.credential_data)
        .bind(credential.created_at)
        .bind(credential.updated_at)
        .bind(credential.user_id)
        .execute(&self.db)
        .await
        .map(|_| ())
    }

    pub async fn update(&self, credential: &Credential) -> sqlx::Result<Option<Credential>> {
        sqlx::query_as::<_, Credential>(
            r#"UPDATE credentials SET
                type = $2, secret_data = $3, credential_data = $4,
                updated_at = $5, user_id = $6
               WHERE id = $1
               RETURNING *"#,
        )
        .bind(credential.id)
        .bind(&credential.credential_type)
        .bind(&credential.secret_data)
        .bind(&credential.credential_data)
        .bind(credential.updated_at)
        .bind(credential.user_id)
        .fetch_optional(&self.db)
        .await
    }
}
