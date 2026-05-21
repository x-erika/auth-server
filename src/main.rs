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

mod config;
mod db;
mod error;
mod redis_pool;
mod state;

use std::sync::Arc;

use actix_cors::Cors;
use actix_web::{App, HttpResponse, HttpServer, Responder, get, http::header, web};
use actix_web_prom::PrometheusMetricsBuilder;
use tracing_actix_web::TracingLogger;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::state::{AppState, SharedState};

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

    let state: SharedState = Arc::new(AppState {
        config: cfg.clone(),
        db,
        redis,
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
