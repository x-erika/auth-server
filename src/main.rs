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

mod client;
mod common;
mod config;
mod db;
mod error;
mod redis_pool;
mod role;
mod session;
mod state;
mod user;

use std::sync::Arc;

use actix_cors::Cors;
use actix_web::{App, HttpResponse, HttpServer, Responder, get, http::header, web};
use actix_web_prom::PrometheusMetricsBuilder;
use tracing_actix_web::TracingLogger;
use tracing_subscriber::EnvFilter;

use crate::client::ClientRepository;
use crate::common::crypto::jwt::{JwtSigner, JwtValidator};
use crate::common::crypto::rsa_keys::RsaKeyProvider;
use crate::common::ratelimit::RateLimiter;
use crate::config::Config;
use crate::role::RoleRepository;
use crate::session::{SessionRepository, SessionService};
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

    // Repositories. Pool handles are Arc-backed, so cloning is cheap.
    let users = UserRepository::new(db.clone());
    let credentials = CredentialRepository::new(db.clone());
    let roles = RoleRepository::new(db.clone());
    let clients = ClientRepository::new(db.clone(), redis.clone(), cfg.redis_ttl.client_cache);
    let sessions = SessionRepository::new(db.clone(), redis.clone());
    let session_service = SessionService::new(sessions.clone());
    let rate_limiter = RateLimiter::new(redis.clone());

    let state: SharedState = Arc::new(AppState {
        config: cfg.clone(),
        db,
        redis,
        rsa_keys,
        jwt_signer,
        jwt_validator,
        users,
        credentials,
        roles,
        clients,
        sessions,
        session_service,
        rate_limiter,
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
    })
    .bind(bind)?
    .run()
    .await?;

    Ok(())
}
