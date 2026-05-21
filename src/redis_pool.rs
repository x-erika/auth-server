//! Redis connection pool.
//!
//! Replaces Quarkus' `quarkus-redis-client`. We use `deadpool-redis` for an
//! async connection pool — the Java side reused Quarkus' built-in pool. All
//! Redis-only stores (auth codes, device authorizations, pending
//! authorizations, client cache, rate-limit counters) talk through this pool.

use anyhow::{Context, Result};
use deadpool_redis::{Config as DpConfig, Pool, Runtime};

use crate::config::RedisConfig;

pub type RedisPool = Pool;

pub fn init(cfg: &RedisConfig) -> Result<RedisPool> {
    let url = cfg.url();
    let dp_cfg = DpConfig::from_url(&url);
    dp_cfg
        .create_pool(Some(Runtime::Tokio1))
        .with_context(|| format!("create redis pool at {url}"))
}
