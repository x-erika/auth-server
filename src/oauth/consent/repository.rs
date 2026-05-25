use uuid::Uuid;

use crate::db::Db;

use super::model::UserConsent;

#[derive(Clone)]
pub struct UserConsentRepository {
    db: Db,
}

impl UserConsentRepository {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    pub async fn find(
        &self,
        user_id: Uuid,
        client_id: Uuid,
    ) -> sqlx::Result<Option<UserConsent>> {
        sqlx::query_as::<_, UserConsent>(
            "SELECT * FROM user_consents WHERE user_id = $1 AND client_id = $2",
        )
        .bind(user_id)
        .bind(client_id)
        .fetch_optional(&self.db)
        .await
    }

    #[allow(dead_code)]
    pub async fn find_by_id(&self, id: Uuid) -> sqlx::Result<Option<UserConsent>> {
        sqlx::query_as::<_, UserConsent>("SELECT * FROM user_consents WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.db)
            .await
    }

    pub async fn find_by_user_id(&self, user_id: Uuid) -> sqlx::Result<Vec<UserConsent>> {
        sqlx::query_as::<_, UserConsent>(
            "SELECT * FROM user_consents WHERE user_id = $1 ORDER BY granted_at DESC",
        )
        .bind(user_id)
        .fetch_all(&self.db)
        .await
    }

    pub async fn delete_by_id(&self, id: Uuid) -> sqlx::Result<u64> {
        let res = sqlx::query("DELETE FROM user_consents WHERE id = $1")
            .bind(id)
            .execute(&self.db)
            .await?;
        Ok(res.rows_affected())
    }

    pub async fn persist(&self, c: &UserConsent) -> sqlx::Result<()> {
        sqlx::query(
            r#"INSERT INTO user_consents
               (id, user_id, client_id, scopes, granted_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6)"#,
        )
        .bind(c.id)
        .bind(c.user_id)
        .bind(c.client_id)
        .bind(&c.scopes)
        .bind(c.granted_at)
        .bind(c.updated_at)
        .execute(&self.db)
        .await
        .map(|_| ())
    }

    pub async fn update(&self, c: &UserConsent) -> sqlx::Result<()> {
        sqlx::query(
            r#"UPDATE user_consents SET scopes = $2, updated_at = $3 WHERE id = $1"#,
        )
        .bind(c.id)
        .bind(&c.scopes)
        .bind(c.updated_at)
        .execute(&self.db)
        .await
        .map(|_| ())
    }

    #[allow(dead_code)]
    pub async fn revoke(&self, user_id: Uuid, client_id: Uuid) -> sqlx::Result<u64> {
        let res = sqlx::query(
            "DELETE FROM user_consents WHERE user_id = $1 AND client_id = $2",
        )
        .bind(user_id)
        .bind(client_id)
        .execute(&self.db)
        .await?;
        Ok(res.rows_affected())
    }
}
