//! Port of `RefreshTokenRepository.java`. The key affordance is
//! [`find_by_token_hash_for_update_in_tx`] — pessimistic row lock used by
//! the refresh-rotation path so two parallel refreshes with the same raw
//! token can't both observe `revoked=false` and fork the token family.

use sqlx::{PgConnection, Postgres, Transaction};
use uuid::Uuid;

use crate::db::Db;

use super::model::RefreshToken;

#[derive(Clone)]
pub struct RefreshTokenRepository {
    db: Db,
}

impl RefreshTokenRepository {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    pub fn db(&self) -> &Db {
        &self.db
    }

    pub async fn find_by_id(&self, id: Uuid) -> sqlx::Result<Option<RefreshToken>> {
        sqlx::query_as::<_, RefreshToken>("SELECT * FROM refresh_tokens WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.db)
            .await
    }

    pub async fn find_by_token_hash(
        &self,
        token_hash: &str,
    ) -> sqlx::Result<Option<RefreshToken>> {
        sqlx::query_as::<_, RefreshToken>(
            "SELECT * FROM refresh_tokens WHERE token_hash = $1",
        )
        .bind(token_hash)
        .fetch_optional(&self.db)
        .await
    }

    /// Row-locking lookup for the refresh-rotation path. Must be called
    /// inside an enclosing transaction so the lock is held across
    /// read/check/revoke. Maps to `SELECT ... FOR UPDATE`.
    pub async fn find_by_token_hash_for_update(
        conn: &mut PgConnection,
        token_hash: &str,
    ) -> sqlx::Result<Option<RefreshToken>> {
        sqlx::query_as::<_, RefreshToken>(
            "SELECT * FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE",
        )
        .bind(token_hash)
        .fetch_optional(conn)
        .await
    }

    pub async fn persist_in_tx(
        tx: &mut Transaction<'_, Postgres>,
        t: &RefreshToken,
    ) -> sqlx::Result<()> {
        sqlx::query(
            r#"INSERT INTO refresh_tokens
               (id, user_id, client_id, session_id, token_hash, expires_at, revoked, created_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8)"#,
        )
        .bind(t.id)
        .bind(t.user_id)
        .bind(t.client_id)
        .bind(t.session_id)
        .bind(&t.token_hash)
        .bind(t.expires_at)
        .bind(t.revoked)
        .bind(t.created_at)
        .execute(&mut **tx)
        .await
        .map(|_| ())
    }

    pub async fn persist(&self, t: &RefreshToken) -> sqlx::Result<()> {
        sqlx::query(
            r#"INSERT INTO refresh_tokens
               (id, user_id, client_id, session_id, token_hash, expires_at, revoked, created_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8)"#,
        )
        .bind(t.id)
        .bind(t.user_id)
        .bind(t.client_id)
        .bind(t.session_id)
        .bind(&t.token_hash)
        .bind(t.expires_at)
        .bind(t.revoked)
        .bind(t.created_at)
        .execute(&self.db)
        .await
        .map(|_| ())
    }

    pub async fn update_revoked(&self, id: Uuid, revoked: bool) -> sqlx::Result<()> {
        sqlx::query("UPDATE refresh_tokens SET revoked = $2 WHERE id = $1")
            .bind(id)
            .bind(revoked)
            .execute(&self.db)
            .await
            .map(|_| ())
    }

    pub async fn update_revoked_in_tx(
        conn: &mut PgConnection,
        id: Uuid,
        revoked: bool,
    ) -> sqlx::Result<()> {
        sqlx::query("UPDATE refresh_tokens SET revoked = $2 WHERE id = $1")
            .bind(id)
            .bind(revoked)
            .execute(conn)
            .await
            .map(|_| ())
    }

    pub async fn revoke_by_session_id_in_tx(
        conn: &mut PgConnection,
        session_id: Uuid,
    ) -> sqlx::Result<u64> {
        let res = sqlx::query(
            r#"UPDATE refresh_tokens SET revoked = TRUE
               WHERE session_id = $1 AND revoked = FALSE"#,
        )
        .bind(session_id)
        .execute(conn)
        .await?;
        Ok(res.rows_affected())
    }

    pub async fn find_client_ids_by_session_id(
        &self,
        session_id: Uuid,
    ) -> sqlx::Result<Vec<Uuid>> {
        let rows: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT DISTINCT client_id FROM refresh_tokens WHERE session_id = $1",
        )
        .bind(session_id)
        .fetch_all(&self.db)
        .await?;
        Ok(rows.into_iter().map(|(c,)| c).collect())
    }
}
