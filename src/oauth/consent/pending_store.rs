//! Port of `PendingAuthorizationStore.java` — Redis SET with TTL +
//! atomic GET+DEL via shared Lua script.

use std::time::Duration;

use chrono::Utc;
use redis::AsyncCommands;

use crate::common::redis::{json, keys, lua};
use crate::redis_pool::RedisPool;

use super::model::PendingAuthorization;

#[derive(Clone)]
pub struct PendingAuthorizationStore {
    redis: RedisPool,
    default_ttl: Duration,
}

impl PendingAuthorizationStore {
    pub fn new(redis: RedisPool, default_ttl: Duration) -> Self {
        Self { redis, default_ttl }
    }

    pub async fn put(&self, pending: &PendingAuthorization) -> anyhow::Result<()> {
        if pending.request_id.is_empty() {
            anyhow::bail!("PendingAuthorization.request_id is required");
        }
        let ttl_from_expires = (pending.expires_at - Utc::now().naive_utc()).num_seconds();
        let ttl = if ttl_from_expires > 0 {
            ttl_from_expires as u64
        } else if pending.expires_at == chrono::NaiveDateTime::UNIX_EPOCH {
            // expires_at unset → fall back to default
            self.default_ttl.as_secs()
        } else {
            return Ok(());
        };
        let payload = json::stringify(pending)?;
        let key = keys::pending_auth(&pending.request_id);
        let mut conn = self.redis.get().await?;
        conn.set_ex::<_, _, ()>(key, payload, ttl).await?;
        Ok(())
    }

    pub async fn get(&self, request_id: &str) -> anyhow::Result<Option<PendingAuthorization>> {
        if request_id.is_empty() {
            return Ok(None);
        }
        let mut conn = self.redis.get().await?;
        let raw: Option<String> = conn.get(keys::pending_auth(request_id)).await?;
        Ok(raw.and_then(|s| Self::decode(&s)))
    }

    /// Atomic GET + DEL — used by `POST /consent` so a double-submit can't
    /// race the same pending into two code issuances.
    pub async fn take(&self, request_id: &str) -> anyhow::Result<Option<PendingAuthorization>> {
        if request_id.is_empty() {
            return Ok(None);
        }
        let key = keys::pending_auth(request_id);
        let mut conn = self.redis.get().await?;
        let raw: Option<String> = lua::GET_AND_DEL.key(key).invoke_async(&mut *conn).await?;
        Ok(raw.and_then(|s| Self::decode(&s)))
    }

    fn decode(raw: &str) -> Option<PendingAuthorization> {
        if raw.is_empty() {
            return None;
        }
        let p: PendingAuthorization = json::parse(raw).ok()?;
        if p.expires_at < Utc::now().naive_utc() {
            return None;
        }
        Some(p)
    }
}
