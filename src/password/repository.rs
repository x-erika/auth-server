use uuid::Uuid;

use crate::db::Db;

use super::model::PasswordReset;

#[derive(Clone)]
pub struct PasswordResetRepository {
    db: Db,
}

impl PasswordResetRepository {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    pub async fn find_by_token_hash(
        &self,
        token_hash: &str,
    ) -> sqlx::Result<Option<PasswordReset>> {
        sqlx::query_as::<_, PasswordReset>(
            "SELECT * FROM password_resets WHERE token_hash = $1",
        )
        .bind(token_hash)
        .fetch_optional(&self.db)
        .await
    }

    pub async fn persist(&self, r: &PasswordReset) -> sqlx::Result<()> {
        sqlx::query(
            r#"INSERT INTO password_resets
               (id, user_id, token_hash, expires_at, consumed_at, created_at)
               VALUES ($1,$2,$3,$4,$5,$6)"#,
        )
        .bind(r.id)
        .bind(r.user_id)
        .bind(&r.token_hash)
        .bind(r.expires_at)
        .bind(r.consumed_at)
        .bind(r.created_at)
        .execute(&self.db)
        .await
        .map(|_| ())
    }

    pub async fn mark_consumed(&self, id: Uuid) -> sqlx::Result<()> {
        sqlx::query("UPDATE password_resets SET consumed_at = NOW() WHERE id = $1")
            .bind(id)
            .execute(&self.db)
            .await
            .map(|_| ())
    }
}
