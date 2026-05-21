use uuid::Uuid;

use crate::db::Db;

use super::model::EmailVerification;

#[derive(Clone)]
pub struct EmailVerificationRepository {
    db: Db,
}

impl EmailVerificationRepository {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    pub async fn find_by_token_hash(
        &self,
        token_hash: &str,
    ) -> sqlx::Result<Option<EmailVerification>> {
        sqlx::query_as::<_, EmailVerification>(
            "SELECT * FROM email_verifications WHERE token_hash = $1",
        )
        .bind(token_hash)
        .fetch_optional(&self.db)
        .await
    }

    pub async fn persist(&self, v: &EmailVerification) -> sqlx::Result<()> {
        sqlx::query(
            r#"INSERT INTO email_verifications
               (id, user_id, token_hash, expires_at, consumed_at, created_at)
               VALUES ($1,$2,$3,$4,$5,$6)"#,
        )
        .bind(v.id)
        .bind(v.user_id)
        .bind(&v.token_hash)
        .bind(v.expires_at)
        .bind(v.consumed_at)
        .bind(v.created_at)
        .execute(&self.db)
        .await
        .map(|_| ())
    }

    pub async fn mark_consumed(&self, id: Uuid) -> sqlx::Result<()> {
        sqlx::query("UPDATE email_verifications SET consumed_at = NOW() WHERE id = $1")
            .bind(id)
            .execute(&self.db)
            .await
            .map(|_| ())
    }
}
