//! auth-server (Rust / Actix Web port of the Quarkus `auth-server-but-java`).
//!
//! Phase 1 wires the foundation only:
//!   * env-driven config
//!   * Postgres pool + Flyway-equivalent migrations
//!   * Redis pool
//!   * shared `AppState`
//!   * health endpoint
//!   * CORS + Prometheus + request-id middleware
//!
//! Subsequent phases plug in crypto, repositories, OAuth/OIDC, admin, etc.

mod admin;
mod bootstrap;
mod client;
mod common;
mod config;
mod db;
mod error;
mod login;
mod oauth;
mod oidc;
mod password;
mod redis_pool;
mod role;
mod session;
mod signup;
mod state;
mod user;

use std::sync::Arc;

use actix_cors::Cors;
use actix_web::{App, HttpResponse, HttpServer, Responder, get, http::header, web};
use actix_web_prom::PrometheusMetricsBuilder;
use tracing_actix_web::TracingLogger;
use tracing_subscriber::EnvFilter;

use crate::client::ClientRepository;
use crate::common::crypto::hmac_sha256::HmacSha256;
use crate::common::crypto::jwt::{JwtSigner, JwtValidator};
use crate::common::crypto::rsa_keys::RsaKeyProvider;
use crate::common::ratelimit::RateLimiter;
use crate::config::Config;
use crate::login::LoginService;
use crate::oauth::authorize::{AuthCodeStore, AuthorizeFlow};
use crate::oauth::consent::{
    ConsentService, PendingAuthorizationStore, UserConsentRepository,
};
use crate::oauth::device::{DeviceAuthorizationRepository, DeviceFlow};
use crate::oauth::logout::{BackchannelLogoutNotifier, LogoutFlow};
use crate::oauth::token::{
    IntrospectFlow, RefreshTokenRepository, RevokeFlow, TokenFlow, TokenIssuer,
    start_refresh_token_cleanup,
};
use crate::password::{PasswordFlow, PasswordResetRepository};
use crate::role::RoleRepository;
use crate::session::{SessionRepository, SessionService};
use crate::signup::{EmailVerificationRepository, SignupFlow};
use crate::state::{AppState, SharedState};
use crate::user::{CredentialRepository, UserRepository};

#[get("/q/health")]
async fn health() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({ "status": "UP" }))
}

/// SmallRye Health parity: `/q/health/live` & `/q/health/ready` are what the
/// admin FE & docker probes hit.
#[get("/q/health/live")]
async fn health_live() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({ "status": "UP" }))
}

#[get("/q/health/ready")]
async fn health_ready(state: web::Data<SharedState>) -> impl Responder {
    // Cheap readiness check: ping the DB. Redis isn't pinged here because the
    // Java side didn't expose it as a readiness signal either.
    match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "status": "UP" })),
        Err(e) => HttpResponse::ServiceUnavailable()
            .json(serde_json::json!({ "status": "DOWN", "reason": e.to_string() })),
    }
}

#[get("/favicon.png")]
async fn favicon() -> impl Responder {
    HttpResponse::Ok()
        .content_type("image/png")
        .body(&include_bytes!("../assets/favicon.png")[..])
}

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    // tracing init — prefer RUST_LOG, fall back to info.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_target(false)
        .compact()
        .init();

    let cfg = Config::load()?;
    tracing::info!(
        host = %cfg.server.host,
        port = cfg.server.port,
        issuer = %cfg.server.issuer_url,
        "starting auth-server"
    );

    let db = db::init(&cfg.db).await?;
    let redis = redis_pool::init(&cfg.redis)?;

    // RSA key set + JWT signer/validator. Keys land on disk at
    // `$HOME/.xerika/auth/keys/` (or `AUTH_JWT_KEYS_DIR` if set) and survive
    // restarts — matches Quarkus' RsaKeyProvider behavior.
    let rsa_keys = Arc::new(RsaKeyProvider::init(cfg.keys_dir.as_deref())?);
    let jwt_signer = Arc::new(JwtSigner::new(
        rsa_keys.clone(),
        cfg.server.issuer_url.clone(),
        cfg.jwt.access_token_ttl,
        cfg.jwt.id_token_ttl,
    ));
    let jwt_validator = Arc::new(JwtValidator::new(
        rsa_keys.clone(),
        cfg.server.issuer_url.clone(),
    ));
    let token_hmac = HmacSha256::new(cfg.token_hmac_key.clone());

    // Repositories. Pool handles are Arc-backed, so cloning is cheap.
    let users = UserRepository::new(db.clone());
    let credentials = CredentialRepository::new(db.clone());
    let roles = RoleRepository::new(db.clone());
    let clients = ClientRepository::new(db.clone(), redis.clone(), cfg.redis_ttl.client_cache);
    let sessions = SessionRepository::new(db.clone(), redis.clone());
    let session_service = SessionService::new(sessions.clone());
    let rate_limiter = RateLimiter::new(redis.clone());

    // Phase 5 — auth flow services.
    let login_service = LoginService::new(users.clone(), credentials.clone());
    let email_verifications = EmailVerificationRepository::new(db.clone());
    let signup_flow = SignupFlow::new(
        db.clone(),
        roles.clone(),
        email_verifications.clone(),
        token_hmac.clone(),
    );
    let password_resets = PasswordResetRepository::new(db.clone());
    let password_flow = PasswordFlow::new(
        users.clone(),
        credentials.clone(),
        password_resets.clone(),
        sessions.clone(),
        token_hmac.clone(),
    );

    // Phase 6 + 7 — OAuth core + consent + device + logout.
    let auth_codes = AuthCodeStore::new(redis.clone());
    let refresh_tokens = RefreshTokenRepository::new(db.clone());
    let token_issuer = TokenIssuer::new(
        jwt_signer.clone(),
        roles.clone(),
        refresh_tokens.clone(),
        token_hmac.clone(),
    );
    let device_repo = DeviceAuthorizationRepository::new(redis.clone());
    let token_flow = TokenFlow::new(
        db.clone(),
        clients.clone(),
        users.clone(),
        sessions.clone(),
        auth_codes.clone(),
        refresh_tokens.clone(),
        token_issuer.clone(),
        device_repo.clone(),
        token_hmac.clone(),
    );
    let user_consents = UserConsentRepository::new(db.clone());
    let consent_service = ConsentService::new(user_consents.clone());
    let pending_authorizations =
        PendingAuthorizationStore::new(redis.clone(), cfg.redis_ttl.pending_auth);
    let authorize_flow = AuthorizeFlow::new(
        clients.clone(),
        session_service.clone(),
        auth_codes.clone(),
        consent_service.clone(),
        pending_authorizations.clone(),
    );
    let introspect_flow = IntrospectFlow::new(clients.clone(), jwt_validator.clone());
    let revoke_flow = RevokeFlow::new(clients.clone(), refresh_tokens.clone(), token_hmac.clone());
    let device_flow = DeviceFlow::new(
        clients.clone(),
        session_service.clone(),
        device_repo.clone(),
        cfg.server.issuer_url.clone(),
    );
    let backchannel_notifier = BackchannelLogoutNotifier::new(jwt_signer.clone());
    let logout_flow = LogoutFlow::new(
        db.clone(),
        jwt_validator.clone(),
        sessions.clone(),
        session_service.clone(),
        refresh_tokens.clone(),
        clients.clone(),
        backchannel_notifier.clone(),
        cfg.server.issuer_url.clone(),
    );

    // Phase 8 — startup seeders (role + admin + client bootstraps).
    // Run sequentially: `RoleBootstrap` must finish before `AdminBootstrap`
    // tries to assign the `admin` role. Each acquires `pg_advisory_xact_lock`
    // independently so multi-replica deploys converge cleanly.
    bootstrap::ensure_core_roles(&db, &roles).await?;
    bootstrap::ensure_admin_user(&db, &users, &credentials, &roles).await?;
    bootstrap::ensure_bootstrap_clients(&db, &clients).await?;
    tracing::info!("bootstrap routines completed");

    // Spawn refresh-token cleanup loop.
    let _cleanup_handle = start_refresh_token_cleanup(db.clone());

    let state: SharedState = Arc::new(AppState {
        config: cfg.clone(),
        db,
        redis,
        rsa_keys,
        jwt_signer,
        jwt_validator,
        token_hmac: token_hmac.clone(),
        users,
        credentials,
        roles,
        clients,
        sessions,
        session_service,
        rate_limiter,
        login_service,
        signup_flow,
        email_verifications,
        password_flow,
        password_resets,
        authorize_flow,
        auth_codes,
        token_flow,
        token_issuer,
        refresh_tokens,
        introspect_flow,
        revoke_flow,
        consent_service,
        user_consents,
        pending_authorizations,
        device_flow,
        device_repo,
        logout_flow,
        backchannel_notifier,
    });

    let bind = (cfg.server.host.clone(), cfg.server.port);
    let cors_cfg = cfg.cors.clone();

    // Prometheus registry — equivalent to `quarkus-micrometer-registry-prometheus`,
    // exposed at `/q/metrics` to match the Quarkus default.
    let prometheus = PrometheusMetricsBuilder::new("auth_server")
        .endpoint("/q/metrics")
        .build()
        .map_err(|e| anyhow::anyhow!("prometheus build failed: {e}"))?;

    HttpServer::new(move || {
        let mut cors = if cors_cfg.enabled {
            let mut c = Cors::default();
            for o in &cors_cfg.origins {
                c = c.allowed_origin(o);
            }
            c = c
                .allowed_methods(cors_cfg.methods.iter().map(String::as_str).collect::<Vec<_>>())
                .allowed_headers(
                    cors_cfg
                        .headers
                        .iter()
                        .filter_map(|h| h.parse::<header::HeaderName>().ok())
                        .collect::<Vec<_>>(),
                )
                .max_age(3600);
            if cors_cfg.allow_credentials {
                c = c.supports_credentials();
            }
            c
        } else {
            Cors::default()
        };
        // Ensure preflight OPTIONS gets a permissive response when no specific
        // origin matches in dev — Cors::default() already rejects unknown origins.
        cors = cors.block_on_origin_mismatch(false);

        App::new()
            .app_data(web::Data::new(state.clone()))
            .wrap(TracingLogger::default())
            .wrap(prometheus.clone())
            .wrap(cors)
            .service(health)
            .service(health_live)
            .service(health_ready)
            .service(favicon)
            .configure(login::resource::configure)
            .configure(login::page::configure)
            .configure(signup::resource::configure)
            .configure(password::resource::configure)
            .configure(oauth::resource::configure)
            .configure(oauth::consent::resource::configure)
            .configure(oidc::resource::configure)
            .configure(admin::resource::configure)
    })
    .bind(bind)?
    .run()
    .await?;

    Ok(())
}
