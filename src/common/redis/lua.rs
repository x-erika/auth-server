//! Port of `com.xerika.auth.common.redis.RedisLua`.
//!
//! The `redis` crate's [`Script`] type handles the SHA cache + EVALSHA →
//! EVAL fallback on `NOSCRIPT` internally, so the Rust port is just a set
//! of `Lazy<Script>` constants instead of a `shaCache` map.
//!
//! Script bodies are **byte-identical** to the Java side — running them
//! against the same Redis instance yields the same SHA, so Java and Rust
//! processes share the loaded scripts.

use once_cell::sync::Lazy;
use redis::Script;

/// `GET key; DEL if exists; return value`. Used by `AuthCodeStore`,
/// `PendingAuthorizationStore`, etc. — one-shot stores that need atomic
/// read-and-consume.
pub static GET_AND_DEL: Lazy<Script> = Lazy::new(|| {
    Script::new(
        "local v = redis.call('GET', KEYS[1]) \
         if v then redis.call('DEL', KEYS[1]) end \
         return v",
    )
});

/// `INCR key; EXPIRE if first hit; return count`. Atomic counter used by
/// the rate limiter — guarantees the EXPIRE always fires on the very first
/// increment so a key never lives without a TTL.
pub static INCR_AND_EXPIRE: Lazy<Script> = Lazy::new(|| {
    Script::new(
        "local n = redis.call('INCR', KEYS[1]) \
         if n == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end \
         return n",
    )
});

/// `HGETALL key; DEL if non-empty; return hash`. Companion to GET_AND_DEL
/// for hash-typed one-shot stores (currently only DeviceAuthorization).
#[allow(dead_code)]
pub static HGETALL_AND_DEL: Lazy<Script> = Lazy::new(|| {
    Script::new(
        "local v = redis.call('HGETALL', KEYS[1]) \
         if #v > 0 then redis.call('DEL', KEYS[1]) end \
         return v",
    )
});
