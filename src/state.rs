//! Shared application state. Plays the role of Quarkus' `@ApplicationScoped`
//! beans wired together via CDI — we just bundle everything into a single
//! `Arc<AppState>` that handlers reach into.

use std::sync::Arc;

use crate::client::ClientRepository;
use crate::common::crypto::jwt::{JwtSigner, JwtValidator};
use crate::common::crypto::rsa_keys::RsaKeyProvider;
use crate::config::Config;
use crate::db::Db;
use crate::redis_pool::RedisPool;
use crate::role::RoleRepository;
use crate::session::{SessionRepository, SessionService};
use crate::user::{CredentialRepository, UserRepository};

pub struct AppState {
    pub config: Config,
    pub db: Db,
    pub redis: RedisPool,

    // Crypto (Phase 2)
    pub rsa_keys: Arc<RsaKeyProvider>,
    pub jwt_signer: Arc<JwtSigner>,
    pub jwt_validator: Arc<JwtValidator>,

    // Repositories + services (Phase 3) — all Clone-able cheaply (they wrap
    // Arc-backed PgPool / RedisPool handles).
    pub users: UserRepository,
    pub credentials: CredentialRepository,
    pub roles: RoleRepository,
    pub clients: ClientRepository,
    pub sessions: SessionRepository,
    pub session_service: SessionService,
}

pub type SharedState = Arc<AppState>;
