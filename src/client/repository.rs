//! Port of `com.xerika.auth.client.ClientRepository`.
//!
//! Reads go through a Redis cache keyed by `client:<client_id>` (TTL with
//! ±10% jitter to avoid synchronized expiry storms). Cache failures degrade
//! gracefully to Postgres — same as the Java side which logs at WARN and
//! falls through.
//!
//! Writes invalidate the cache AFTER a successful commit. Java did this via
//! transaction synchronization; with sqlx we use explicit transactions and
//! invalidate after `tx.commit()` succeeds.

use std::time::Duration;

use rand::Rng;
use redis::AsyncCommands;
use uuid::Uuid;

use crate::common::redis::{json, keys};
use crate::db::Db;
use crate::redis_pool::RedisPool;

use super::model::{Client, ClientSnapshot, RedirectUri};

#[derive(Clone)]
pub struct ClientRepository {
    db: Db,
    redis: RedisPool,
    cache_ttl_seconds: u64,
}

impl ClientRepository {
    pub fn new(db: Db, redis: RedisPool, cache_ttl: Duration) -> Self {
        Self {
            db,
            redis,
            cache_ttl_seconds: cache_ttl.as_secs().max(1),
        }
    }

    pub async fn find_by_id(&self, id: Uuid) -> sqlx::Result<Option<Client>> {
        let client = sqlx::query_as::<_, Client>("SELECT * FROM clients WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.db)
            .await?;
        match client {
            Some(mut c) => {
                c.redirect_uris = self.fetch_redirect_uris(c.id).await?;
                Ok(Some(c))
            }
            None => Ok(None),
        }
    }

    /// Cached read by external `client_id`. Cache miss falls through to PG.
    pub async fn find_by_client_id(&self, client_id: &str) -> sqlx::Result<Option<Client>> {
        if client_id.is_empty() {
            return Ok(None);
        }
        if let Some(c) = self.read_cache(client_id).await {
            return Ok(Some(c));
        }
        let row = sqlx::query_as::<_, Client>("SELECT * FROM clients WHERE client_id = $1")
            .bind(client_id)
            .fetch_optional(&self.db)
            .await?;
        let mut client = match row {
            Some(c) => c,
            None => return Ok(None),
        };
        client.redirect_uris = self.fetch_redirect_uris(client.id).await?;
        self.populate_cache(&client).await;
        Ok(Some(client))
    }

    pub async fn find_all(&self) -> sqlx::Result<Vec<Client>> {
        let clients =
            sqlx::query_as::<_, Client>("SELECT * FROM clients ORDER BY client_id")
                .fetch_all(&self.db)
                .await?;
        // Single round-trip per client for redirect_uris keeps the port
        // straightforward. The admin "list clients" UI rarely cares about
        // redirect URIs, so callers that don't need them should switch to a
        // lighter projection in Phase 8 if it ever matters.
        let mut out = Vec::with_capacity(clients.len());
        for mut c in clients {
            c.redirect_uris = self.fetch_redirect_uris(c.id).await?;
            out.push(c);
        }
        Ok(out)
    }

    pub async fn is_redirect_uri_allowed(
        &self,
        client_id: Uuid,
        redirect_uri: &str,
    ) -> sqlx::Result<bool> {
        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM redirect_uris WHERE client_id = $1 AND uri = $2",
        )
        .bind(client_id)
        .bind(redirect_uri)
        .fetch_one(&self.db)
        .await?;
        Ok(count > 0)
    }

    pub async fn persist(&self, client: &Client) -> sqlx::Result<()> {
        let mut tx = self.db.begin().await?;
        sqlx::query(
            r#"INSERT INTO clients
               (id, client_id, client_secret, name, type, grant_types, response_types,
                scopes, pkce_required, enabled, base_url, description,
                access_token_ttl, refresh_token_ttl,
                frontchannel_logout_uri, backchannel_logout_uri,
                created_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)"#,
        )
        .bind(client.id)
        .bind(&client.client_id)
        .bind(&client.client_secret)
        .bind(&client.name)
        .bind(&client.client_type)
        .bind(&client.grant_types)
        .bind(&client.response_types)
        .bind(&client.scopes)
        .bind(client.pkce_required)
        .bind(client.enabled)
        .bind(&client.base_url)
        .bind(&client.description)
        .bind(client.access_token_ttl)
        .bind(client.refresh_token_ttl)
        .bind(&client.frontchannel_logout_uri)
        .bind(&client.backchannel_logout_uri)
        .bind(client.created_at)
        .bind(client.updated_at)
        .execute(&mut *tx)
        .await?;
        for r in &client.redirect_uris {
            sqlx::query(
                r#"INSERT INTO redirect_uris (id, client_id, uri, created_at)
                   VALUES ($1, $2, $3, $4)"#,
            )
            .bind(r.id)
            .bind(client.id)
            .bind(&r.uri)
            .bind(r.created_at)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        self.invalidate(&client.client_id).await;
        Ok(())
    }

    pub async fn update(&self, client: &Client) -> sqlx::Result<Option<Client>> {
        let updated = sqlx::query_as::<_, Client>(
            r#"UPDATE clients SET
                client_secret = $2, name = $3, type = $4,
                grant_types = $5, response_types = $6, scopes = $7,
                pkce_required = $8, enabled = $9, base_url = $10,
                description = $11, access_token_ttl = $12, refresh_token_ttl = $13,
                frontchannel_logout_uri = $14, backchannel_logout_uri = $15,
                updated_at = $16
               WHERE id = $1
               RETURNING *"#,
        )
        .bind(client.id)
        .bind(&client.client_secret)
        .bind(&client.name)
        .bind(&client.client_type)
        .bind(&client.grant_types)
        .bind(&client.response_types)
        .bind(&client.scopes)
        .bind(client.pkce_required)
        .bind(client.enabled)
        .bind(&client.base_url)
        .bind(&client.description)
        .bind(client.access_token_ttl)
        .bind(client.refresh_token_ttl)
        .bind(&client.frontchannel_logout_uri)
        .bind(&client.backchannel_logout_uri)
        .bind(client.updated_at)
        .fetch_optional(&self.db)
        .await?;
        if let Some(ref c) = updated {
            self.invalidate(&c.client_id).await;
        }
        Ok(updated)
    }

    pub async fn delete(&self, id: Uuid) -> sqlx::Result<Option<String>> {
        // Capture client_id before delete so we know which cache key to
        // invalidate after the row is gone.
        let existing: Option<(String,)> =
            sqlx::query_as("SELECT client_id FROM clients WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.db)
                .await?;
        let Some((cid,)) = existing else {
            return Ok(None);
        };
        sqlx::query("DELETE FROM clients WHERE id = $1")
            .bind(id)
            .execute(&self.db)
            .await?;
        self.invalidate(&cid).await;
        Ok(Some(cid))
    }

    pub async fn add_redirect_uri(&self, uri: &RedirectUri) -> sqlx::Result<()> {
        sqlx::query(
            r#"INSERT INTO redirect_uris (id, client_id, uri, created_at)
               VALUES ($1, $2, $3, $4)"#,
        )
        .bind(uri.id)
        .bind(uri.client_id)
        .bind(&uri.uri)
        .bind(uri.created_at)
        .execute(&self.db)
        .await?;
        // Invalidate by parent client_id to keep cache snapshot consistent.
        if let Some(cid) = self.client_id_of(uri.client_id).await? {
            self.invalidate(&cid).await;
        }
        Ok(())
    }

    pub async fn remove_redirect_uri(&self, redirect_uri_id: Uuid) -> sqlx::Result<u64> {
        // Same lookup order as Java: read parent client_id BEFORE delete so
        // we have a key to invalidate even after the row is gone.
        let owning: Option<(String,)> = sqlx::query_as(
            r#"SELECT c.client_id
               FROM redirect_uris r
               JOIN clients c ON c.id = r.client_id
               WHERE r.id = $1"#,
        )
        .bind(redirect_uri_id)
        .fetch_optional(&self.db)
        .await?;
        let res = sqlx::query("DELETE FROM redirect_uris WHERE id = $1")
            .bind(redirect_uri_id)
            .execute(&self.db)
            .await?;
        if res.rows_affected() > 0 {
            if let Some((cid,)) = owning {
                self.invalidate(&cid).await;
            }
        }
        Ok(res.rows_affected())
    }

    pub async fn invalidate(&self, client_id: &str) {
        if client_id.is_empty() {
            return;
        }
        let Ok(mut conn) = self.redis.get().await else {
            tracing::warn!(%client_id, "redis invalidate skipped (pool unavailable)");
            return;
        };
        let key = keys::client(client_id);
        if let Err(e) = conn.del::<_, ()>(&key).await {
            tracing::warn!(%client_id, error = %e, "redis DEL failed");
        }
    }

    async fn read_cache(&self, client_id: &str) -> Option<Client> {
        let mut conn = self.redis.get().await.ok()?;
        let raw: Option<String> = conn.get(keys::client(client_id)).await.ok().flatten();
        let raw = raw?;
        if raw.is_empty() {
            return None;
        }
        match json::parse::<ClientSnapshot>(&raw) {
            Ok(snap) => Some(snap.into_entity()),
            Err(e) => {
                tracing::warn!(%client_id, error = %e, "redis cache parse failed");
                None
            }
        }
    }

    async fn populate_cache(&self, client: &Client) {
        let snap = ClientSnapshot::from_entity(client);
        let payload = match json::stringify(&snap) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(client_id = %client.client_id, error = %e, "snapshot serialize failed");
                return;
            }
        };
        let Ok(mut conn) = self.redis.get().await else {
            return;
        };
        let ttl = jittered_ttl(self.cache_ttl_seconds);
        if let Err(e) = conn
            .set_ex::<_, _, ()>(keys::client(&client.client_id), payload, ttl)
            .await
        {
            tracing::warn!(client_id = %client.client_id, error = %e, "redis cache populate failed");
        }
    }

    async fn fetch_redirect_uris(&self, client_id: Uuid) -> sqlx::Result<Vec<RedirectUri>> {
        sqlx::query_as::<_, RedirectUri>(
            "SELECT * FROM redirect_uris WHERE client_id = $1 ORDER BY created_at",
        )
        .bind(client_id)
        .fetch_all(&self.db)
        .await
    }

    async fn client_id_of(&self, id: Uuid) -> sqlx::Result<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as("SELECT client_id FROM clients WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.db)
            .await?;
        Ok(row.map(|(c,)| c))
    }
}

/// ±10% jitter on the base TTL — matches Java's `jitteredTtl`. Spreads
/// expiry so a popular client doesn't cause a thundering herd on the DB.
fn jittered_ttl(base: u64) -> u64 {
    let jitter: f64 = rand::thread_rng().gen_range(-0.1..0.1);
    let scaled = (base as f64 * (1.0 + jitter)).floor() as i64;
    scaled.max(1) as u64
}
