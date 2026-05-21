//! Shared application state. Plays the role of Quarkus' `@ApplicationScoped`
//! beans wired together via CDI — we just bundle everything into a single
//! `Arc<AppState>` that handlers reach into.
//!
//! Phase 2 plugs in the RSA key provider + JWT signer/validator. Later
//! phases append the role/client/user repositories, the Redis stores, etc.

use std::sync::Arc;

use crate::common::crypto::jwt::{JwtSigner, JwtValidator};
use crate::common::crypto::rsa_keys::RsaKeyProvider;
use crate::config::Config;
use crate::db::Db;
use crate::redis_pool::RedisPool;

pub struct AppState {
    pub config: Config,
    pub db: Db,
    pub redis: RedisPool,
    pub rsa_keys: Arc<RsaKeyProvider>,
    pub jwt_signer: Arc<JwtSigner>,
    pub jwt_validator: Arc<JwtValidator>,
}

pub type SharedState = Arc<AppState>;
