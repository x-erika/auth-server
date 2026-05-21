//! Port of `DeviceAuthorizationRepository.java`. Stores each device
//! authorization as a Redis hash plus a `user_code → device_code` pointer
//! key (with `SET NX` to detect collisions and trigger a retry).
//!
//! Field encoding is byte-identical with Java — same `ISO_LOCAL_DATE_TIME`
//! format for the timestamps so a single Redis instance can be read by
//! either server.

use chrono::{NaiveDateTime, Utc};
use redis::AsyncCommands;
use uuid::Uuid;

use crate::common::redis::keys;
use crate::redis_pool::RedisPool;

use super::model::DeviceAuthorization;

const FMT: &str = "%Y-%m-%dT%H:%M:%S%.f";
const FMT_NO_FRAC: &str = "%Y-%m-%dT%H:%M:%S";

#[derive(Clone)]
pub struct DeviceAuthorizationRepository {
    redis: RedisPool,
}

impl DeviceAuthorizationRepository {
    pub fn new(redis: RedisPool) -> Self {
        Self { redis }
    }

    pub async fn find_by_device_code(
        &self,
        device_code: &str,
    ) -> anyhow::Result<Option<DeviceAuthorization>> {
        if device_code.is_empty() {
            return Ok(None);
        }
        self.load_hash(&keys::device_by_code(device_code)).await
    }

    /// RFC 8628 §6.1 — case-insensitive, separator-tolerant lookup.
    pub async fn find_by_user_code(
        &self,
        user_code: &str,
    ) -> anyhow::Result<Option<DeviceAuthorization>> {
        if user_code.is_empty() {
            return Ok(None);
        }
        let normalized = normalize_user_code(user_code);
        let mut conn = self.redis.get().await?;
        let ptr: Option<String> = conn.get(keys::device_by_user_code(&normalized)).await?;
        let Some(dc) = ptr.filter(|s| !s.is_empty()) else {
            return Ok(None);
        };
        self.find_by_device_code(&dc).await
    }

    /// Atomic SET NX on the pointer first — collision returns `Ok(false)`
    /// so the caller can regenerate a fresh `user_code`.
    pub async fn persist(&self, auth: &DeviceAuthorization) -> anyhow::Result<bool> {
        let ttl = (auth.expires_at - Utc::now().naive_utc()).num_seconds();
        if ttl <= 0 {
            return Ok(false);
        }
        let main_key = keys::device_by_code(&auth.device_code);
        let pointer_key = keys::device_by_user_code(&normalize_user_code(&auth.user_code));

        let mut conn = self.redis.get().await?;
        // SET NX EX on pointer first — collision == failure.
        let ptr_set: Option<String> = redis::cmd("SET")
            .arg(&pointer_key)
            .arg(&auth.device_code)
            .arg("EX")
            .arg(ttl)
            .arg("NX")
            .query_async(&mut *conn)
            .await?;
        if ptr_set.is_none() {
            return Ok(false);
        }
        let fields = to_fields(auth);
        let pairs: Vec<(String, String)> = fields.into_iter().collect();
        conn.hset_multiple::<_, _, _, ()>(&main_key, &pairs).await?;
        conn.expire::<_, ()>(&main_key, ttl).await?;
        Ok(true)
    }

    pub async fn update(&self, auth: &DeviceAuthorization) -> anyhow::Result<()> {
        let main_key = keys::device_by_code(&auth.device_code);
        let mut conn = self.redis.get().await?;
        let exists: i64 = conn.exists(&main_key).await?;
        if exists == 0 {
            return Ok(());
        }
        let pairs: Vec<(String, String)> = to_fields(auth).into_iter().collect();
        conn.hset_multiple::<_, _, _, ()>(&main_key, &pairs).await?;
        Ok(())
    }

    async fn load_hash(&self, key: &str) -> anyhow::Result<Option<DeviceAuthorization>> {
        let mut conn = self.redis.get().await?;
        let map: std::collections::HashMap<String, String> = conn.hgetall(key).await?;
        if map.is_empty() {
            return Ok(None);
        }
        Ok(Some(from_fields(&map)?))
    }
}

fn normalize_user_code(user_code: &str) -> String {
    user_code
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_uppercase()
}

fn to_fields(auth: &DeviceAuthorization) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    out.push(("id".to_string(), auth.id.to_string()));
    out.push(("deviceCode".to_string(), auth.device_code.clone()));
    out.push(("userCode".to_string(), auth.user_code.clone()));
    out.push(("clientId".to_string(), auth.client_id.clone()));
    if let Some(ref s) = auth.scope {
        out.push(("scope".to_string(), s.clone()));
    }
    out.push(("status".to_string(), auth.status.clone()));
    if let Some(u) = auth.user_id {
        out.push(("userId".to_string(), u.to_string()));
    }
    if let Some(s) = auth.session_id {
        out.push(("sessionId".to_string(), s.to_string()));
    }
    out.push((
        "expiresAt".to_string(),
        auth.expires_at.format(FMT).to_string(),
    ));
    if let Some(c) = auth.created_at {
        out.push(("createdAt".to_string(), c.format(FMT).to_string()));
    }
    out
}

fn from_fields(
    m: &std::collections::HashMap<String, String>,
) -> anyhow::Result<DeviceAuthorization> {
    fn parse_dt(s: &str) -> Option<NaiveDateTime> {
        NaiveDateTime::parse_from_str(s, FMT)
            .or_else(|_| NaiveDateTime::parse_from_str(s, FMT_NO_FRAC))
            .ok()
    }
    Ok(DeviceAuthorization {
        id: Uuid::parse_str(m.get("id").ok_or_else(|| anyhow::anyhow!("missing id"))?)?,
        device_code: m
            .get("deviceCode")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing deviceCode"))?,
        user_code: m
            .get("userCode")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing userCode"))?,
        client_id: m
            .get("clientId")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing clientId"))?,
        scope: m.get("scope").cloned(),
        status: m
            .get("status")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing status"))?,
        user_id: m.get("userId").and_then(|s| Uuid::parse_str(s).ok()),
        session_id: m.get("sessionId").and_then(|s| Uuid::parse_str(s).ok()),
        expires_at: m
            .get("expiresAt")
            .and_then(|s| parse_dt(s))
            .ok_or_else(|| anyhow::anyhow!("missing/invalid expiresAt"))?,
        created_at: m.get("createdAt").and_then(|s| parse_dt(s)),
    })
}
