//! Port of `AuthorizationCode` + `AuthCodeStore` — Redis-only since
//! migration V9 dropped the `auth_codes` table.

use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::common::crypto::sha256;
use crate::common::redis::keys;
use crate::common::redis::lua;
use crate::redis_pool::RedisPool;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    pub code: String,
    pub client_id: String,
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub claims_requested: Option<String>,
    pub expires_at: NaiveDateTime,
    #[serde(default)]
    pub created_at: Option<NaiveDateTime>,
}

#[derive(Clone)]
pub struct AuthCodeStore {
    redis: RedisPool,
}

impl AuthCodeStore {
    pub fn new(redis: RedisPool) -> Self {
        Self { redis }
    }

    pub async fn put(&self, mut code: AuthorizationCode) -> anyhow::Result<()> {
        let now = Utc::now().naive_utc();
        let ttl = (code.expires_at - now).num_seconds();
        if ttl <= 0 {
            return Ok(());
        }
        code.created_at = Some(now);
        let payload = serde_json::to_string(&code)?;
        // Hash the raw code before using it as a Redis key. A Redis dump or
        // KEYS-style scan would otherwise expose live authorization codes
        // verbatim; storing the hash means an attacker who reads the
        // keystore still needs the raw code (delivered only via redirect)
        // to redeem.
        let key = keys::auth_code(&sha256::base64_url(&code.code));
        let mut conn = self.redis.get().await?;
        // SET NX EX <ttl> — matches Java exactly. NX guarantees we never
        // overwrite an existing code (those should be already-consumed or
        // about to expire).
        redis::cmd("SET")
            .arg(&key)
            .arg(payload)
            .arg("NX")
            .arg("EX")
            .arg(ttl)
            .query_async::<()>(&mut *conn)
            .await?;
        Ok(())
    }

    /// Atomic consume: GET then DEL via Lua script (same script Java uses,
    /// byte-identical → same SHA, shared cache).
    pub async fn consume(&self, code: &str) -> anyhow::Result<Option<AuthorizationCode>> {
        if code.is_empty() {
            return Ok(None);
        }
        let key = keys::auth_code(&sha256::base64_url(code));
        let mut conn = self.redis.get().await?;
        let raw: Option<String> = lua::GET_AND_DEL.key(key).invoke_async(&mut *conn).await?;
        let Some(raw) = raw else { return Ok(None) };
        if raw.is_empty() {
            return Ok(None);
        }
        let stored: AuthorizationCode = serde_json::from_str(&raw)?;
        // Redis TTL guarantees expired keys are gone, but a freshly-fetched
        // code with `expires_at` in the past is still safer to reject.
        if stored.expires_at < Utc::now().naive_utc() {
            return Ok(None);
        }
        Ok(Some(stored))
    }
}

