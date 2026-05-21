//! Redis helpers — direct port of `com.xerika.auth.common.redis.*`.
//!
//! The Java side wraps Quarkus' `RedisDataSource` + Jackson. The Rust side
//! uses `deadpool-redis` (pool) + `serde_json` (codec). Key names are kept
//! identical so a single Redis instance can hold state from both servers
//! during the cutover window (or simply make the migration auditable).

pub mod json;
pub mod keys;
pub mod lua;
