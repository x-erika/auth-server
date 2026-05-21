//! Shared application state. Plays the role of Quarkus' `@ApplicationScoped`
//! beans wired together via CDI — we just bundle everything into a single
//! `Arc<AppState>` that handlers reach into.

use std::sync::Arc;

use crate::client::ClientRepository;
use crate::common::crypto::jwt::{JwtSigner, JwtValidator};
use crate::common::crypto::rsa_keys::RsaKeyProvider;
use crate::common::ratelimit::RateLimiter;
use crate::config::Config;
use crate::db::Db;
use crate::login::LoginService;
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

    // Rate limiting (Phase 4)
    pub rate_limiter: RateLimiter,

    // Auth flows (Phase 5)
    pub login_service: LoginService,
    pub signup_flow: crate::signup::SignupFlow,
    pub email_verifications: crate::signup::EmailVerificationRepository,
    pub password_flow: crate::password::PasswordFlow,
    pub password_resets: crate::password::PasswordResetRepository,

    // OAuth core (Phase 6)
    pub authorize_flow: crate::oauth::authorize::AuthorizeFlow,
    pub auth_codes: crate::oauth::authorize::AuthCodeStore,
    pub token_flow: crate::oauth::token::TokenFlow,
    pub token_issuer: crate::oauth::token::TokenIssuer,
    pub refresh_tokens: crate::oauth::token::RefreshTokenRepository,
    pub introspect_flow: crate::oauth::token::IntrospectFlow,
    pub revoke_flow: crate::oauth::token::RevokeFlow,

    // Consent + device + logout (Phase 7)
    pub consent_service: crate::oauth::consent::ConsentService,
    pub user_consents: crate::oauth::consent::UserConsentRepository,
    pub pending_authorizations: crate::oauth::consent::PendingAuthorizationStore,
    pub device_flow: crate::oauth::device::DeviceFlow,
    pub device_repo: crate::oauth::device::DeviceAuthorizationRepository,
    pub logout_flow: crate::oauth::logout::LogoutFlow,
    pub backchannel_notifier: crate::oauth::logout::BackchannelLogoutNotifier,
}

pub type SharedState = Arc<AppState>;
