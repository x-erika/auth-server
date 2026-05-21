//! Shared application state. Plays the role of Quarkus' `@ApplicationScoped`
//! beans wired together via CDI — we just bundle everything into a single
//! `Arc<AppState>` that handlers reach into.
//!
//! Fields stay minimal in Phase 1; later phases append the `RsaKeyProvider`,
//! `RoleRepository`, `ClientRepository`, etc.

use std::sync::Arc;

use crate::config::Config;
use crate::db::Db;
use crate::redis_pool::RedisPool;

pub struct AppState {
    pub config: Config,
    pub db: Db,
    pub redis: RedisPool,
}

pub type SharedState = Arc<AppState>;
