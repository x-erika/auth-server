//! Port of `com.xerika.auth.common.ratelimit.*`.
//!
//! Backed by `INCR + EXPIRE` Lua atomic (see [`crate::common::redis::lua`]).
//! Fails **open** on Redis errors — matches the Java stance: rate limiting
//! is a defense-in-depth knob, not a hard auth gate. Better to let traffic
//! through than to brick login when Redis blips.

use std::time::Duration;

use redis::AsyncCommands;

use crate::common::redis::lua;
use crate::redis_pool::RedisPool;

/// `RateLimitDecision` — direct port of the Java record.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct RateLimitDecision {
    pub allowed: bool,
    pub count: u64,
    pub retry_after_seconds: u64,
}

impl RateLimitDecision {
    pub fn allowed(count: u64) -> Self {
        Self {
            allowed: true,
            count,
            retry_after_seconds: 0,
        }
    }

    pub fn denied(count: u64, retry_after_seconds: u64) -> Self {
        Self {
            allowed: false,
            count,
            retry_after_seconds,
        }
    }

    /// Used when Redis is unreachable or the limit/window is misconfigured.
    /// Matches Java `RateLimitDecision.failOpen()`.
    pub fn fail_open() -> Self {
        Self {
            allowed: true,
            count: 0,
            retry_after_seconds: 0,
        }
    }
}

#[derive(Clone)]
pub struct RateLimiter {
    redis: RedisPool,
}

impl RateLimiter {
    pub fn new(redis: RedisPool) -> Self {
        Self { redis }
    }

    /// `check(key, limit, window)` — atomic INCR + first-hit EXPIRE.
    /// Returns `allowed` when the post-increment count ≤ limit.
    ///
    /// The `Duration` API guards against negative windows on the Rust side
    /// (the Java side keyed on `long` and short-circuits ≤ 0). An empty
    /// `key` or zero limit fail-open the same way Java does.
    pub async fn check(
        &self,
        key: &str,
        limit: u32,
        window: Duration,
    ) -> RateLimitDecision {
        if key.is_empty() || limit == 0 || window.is_zero() {
            return RateLimitDecision::fail_open();
        }
        let window_seconds = window.as_secs();

        let mut conn = match self.redis.get().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(%key, error = %e, "rate limit check skipped (pool unavailable), failing open");
                return RateLimitDecision::fail_open();
            }
        };

        let count: i64 = match lua::INCR_AND_EXPIRE
            .key(key)
            .arg(window_seconds)
            .invoke_async(&mut conn)
            .await
        {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(%key, error = %e, "rate limit script failed, failing open");
                return RateLimitDecision::fail_open();
            }
        };
        let count = count.max(0) as u64;

        if count > limit as u64 {
            let retry_after = read_ttl_or_default(&mut conn, key, window_seconds).await;
            return RateLimitDecision::denied(count, retry_after);
        }
        RateLimitDecision::allowed(count)
    }
}

/// Best-effort `TTL key`. Returns the configured window as fallback when
/// Redis says "no TTL" (`-1`) or the call itself errors — matches Java's
/// `readTtlOrDefault`.
async fn read_ttl_or_default(
    conn: &mut deadpool_redis::Connection,
    key: &str,
    fallback: u64,
) -> u64 {
    match conn.ttl::<_, i64>(key).await {
        Ok(sec) if sec > 0 => sec as u64,
        _ => fallback,
    }
}
