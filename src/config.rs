//! Configuration loader. Mirrors `src/main/resources/application.properties`
//! from the Quarkus version. All knobs that the Java code reads via
//! `@ConfigProperty(...)` are surfaced here as fields on [`Config`].
//!
//! Env-var names follow the Quarkus defaults: `DB_USER`, `DB_PASS`, `DB_URL`,
//! `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASS`. Other knobs use the dotted name
//! upper-cased with dots/dashes turned into underscores
//! (e.g. `auth.jwt.access-token-ttl-seconds` -> `AUTH_JWT_ACCESS_TOKEN_TTL_SECONDS`).

use std::env;
use std::time::Duration;

use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub db: DbConfig,
    pub redis: RedisConfig,
    pub jwt: JwtConfig,
    pub cookie: CookieConfig,
    pub cors: CorsConfig,
    pub redis_ttl: RedisTtlConfig,
    pub ratelimit: RateLimitConfig,
    pub keys_dir: Option<String>,
    /// HMAC-SHA256 key for at-rest hashing of refresh / reset / verify
    /// tokens. See `common::crypto::hmac_sha256`. MUST be a long random
    /// value in production; rotating invalidates every live token.
    pub token_hmac_key: String,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub issuer_url: String,
}

#[derive(Debug, Clone)]
pub struct DbConfig {
    /// e.g. `postgres://postgres:erika@localhost:15552/xerika?sslmode=disable`
    pub url: String,
    pub max_connections: u32,
}

#[derive(Debug, Clone)]
pub struct RedisConfig {
    pub host: String,
    pub port: u16,
    pub password: Option<String>,
}

impl RedisConfig {
    pub fn url(&self) -> String {
        match &self.password {
            Some(p) if !p.is_empty() => {
                format!("redis://:{}@{}:{}", p, self.host, self.port)
            }
            _ => format!("redis://{}:{}", self.host, self.port),
        }
    }
}

#[derive(Debug, Clone)]
pub struct JwtConfig {
    pub access_token_ttl: Duration,
    pub id_token_ttl: Duration,
}

#[derive(Debug, Clone)]
pub struct CookieConfig {
    /// `Secure` flag on session_token / csrf_token cookies. Off in dev, on in prod.
    pub secure: bool,
}

#[derive(Debug, Clone)]
pub struct CorsConfig {
    pub enabled: bool,
    pub origins: Vec<String>,
    pub methods: Vec<String>,
    pub headers: Vec<String>,
    pub allow_credentials: bool,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RedisTtlConfig {
    pub authcode: Duration,
    pub device_auth: Duration,
    pub pending_auth: Duration,
    pub client_cache: Duration,
}

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub login_email_max: u32,
    pub login_email_window: Duration,
    pub login_ip_max: u32,
    pub login_ip_window: Duration,
    pub signup_ip_max: u32,
    pub signup_ip_window: Duration,
    pub verify_email_ip_max: u32,
    pub verify_email_ip_window: Duration,
    pub device_auth_client_max: u32,
    pub device_auth_client_window: Duration,
}

impl Config {
    pub fn load() -> Result<Self> {
        // Best-effort .env load (parity with `%dev` profile sane defaults).
        let _ = dotenvy::dotenv();

        Ok(Self {
            server: ServerConfig {
                host: env_or("HTTP_HOST", "0.0.0.0"),
                port: env_or("HTTP_PORT", "8080").parse().context("HTTP_PORT")?,
                issuer_url: env_or("AUTH_ISSUER_URL", "http://localhost:8080"),
            },
            db: DbConfig {
                url: env_or(
                    "DATABASE_URL",
                    // Java default in dev profile was jdbc:postgresql://localhost:15552/xerika-java
                    // — user requested the Rust DB be plain `xerika`.
                    "postgres://postgres:erika@localhost:15552/xerika?sslmode=disable",
                ),
                max_connections: env_or("DB_MAX_CONNECTIONS", "10")
                    .parse()
                    .context("DB_MAX_CONNECTIONS")?,
            },
            redis: RedisConfig {
                host: env_or("REDIS_HOST", "localhost"),
                // Rust port runs Redis on 6380 so it never collides with the
                // Java auth-server-but-java on 6379 — both can share the host
                // during cutover.
                port: env_or("REDIS_PORT", "6380").parse().context("REDIS_PORT")?,
                password: env::var("REDIS_PASS").ok().or(Some("xerika".to_string())),
            },
            jwt: JwtConfig {
                access_token_ttl: Duration::from_secs(
                    env_or("AUTH_JWT_ACCESS_TOKEN_TTL_SECONDS", "900").parse()?,
                ),
                id_token_ttl: Duration::from_secs(
                    env_or("AUTH_JWT_ID_TOKEN_TTL_SECONDS", "3600").parse()?,
                ),
            },
            cookie: CookieConfig {
                secure: env_or("AUTH_COOKIE_SECURE", "false").parse().unwrap_or(false),
            },
            cors: CorsConfig {
                enabled: env_or("CORS_ENABLED", "true").parse().unwrap_or(true),
                origins: env_or(
                    "CORS_ORIGINS",
                    "http://localhost:3000,http://localhost:3001,http://localhost:8081",
                )
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
                methods: env_or("CORS_METHODS", "GET,POST,PUT,DELETE,OPTIONS,PATCH")
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect(),
                headers: env_or(
                    "CORS_HEADERS",
                    "Authorization,Content-Type,X-Session-Token,X-Forwarded-For",
                )
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
                allow_credentials: env_or("CORS_ALLOW_CREDENTIALS", "true")
                    .parse()
                    .unwrap_or(true),
            },
            redis_ttl: RedisTtlConfig {
                authcode: Duration::from_secs(
                    env_or("AUTH_REDIS_AUTHCODE_TTL_SECONDS", "600").parse()?,
                ),
                device_auth: Duration::from_secs(
                    env_or("AUTH_REDIS_DEVICE_AUTH_TTL_SECONDS", "900").parse()?,
                ),
                pending_auth: Duration::from_secs(
                    env_or("AUTH_REDIS_PENDING_AUTH_TTL_SECONDS", "600").parse()?,
                ),
                client_cache: Duration::from_secs(
                    env_or("AUTH_REDIS_CLIENT_CACHE_TTL_SECONDS", "1800").parse()?,
                ),
            },
            ratelimit: RateLimitConfig {
                login_email_max: env_or("AUTH_RATELIMIT_LOGIN_EMAIL_MAX_ATTEMPTS", "5").parse()?,
                login_email_window: Duration::from_secs(
                    env_or("AUTH_RATELIMIT_LOGIN_EMAIL_WINDOW_SECONDS", "900").parse()?,
                ),
                login_ip_max: env_or("AUTH_RATELIMIT_LOGIN_IP_MAX_ATTEMPTS", "20").parse()?,
                login_ip_window: Duration::from_secs(
                    env_or("AUTH_RATELIMIT_LOGIN_IP_WINDOW_SECONDS", "900").parse()?,
                ),
                signup_ip_max: env_or("AUTH_RATELIMIT_SIGNUP_IP_MAX_ATTEMPTS", "3").parse()?,
                signup_ip_window: Duration::from_secs(
                    env_or("AUTH_RATELIMIT_SIGNUP_IP_WINDOW_SECONDS", "3600").parse()?,
                ),
                verify_email_ip_max: env_or("AUTH_RATELIMIT_VERIFY_EMAIL_IP_MAX_ATTEMPTS", "10")
                    .parse()?,
                verify_email_ip_window: Duration::from_secs(
                    env_or("AUTH_RATELIMIT_VERIFY_EMAIL_IP_WINDOW_SECONDS", "60").parse()?,
                ),
                device_auth_client_max: env_or(
                    "AUTH_RATELIMIT_DEVICE_AUTH_CLIENT_MAX_ATTEMPTS",
                    "10",
                )
                .parse()?,
                device_auth_client_window: Duration::from_secs(
                    env_or("AUTH_RATELIMIT_DEVICE_AUTH_CLIENT_WINDOW_SECONDS", "60").parse()?,
                ),
            },
            keys_dir: env::var("AUTH_JWT_KEYS_DIR").ok(),
            token_hmac_key: env_or(
                "AUTH_TOKEN_HMAC_KEY",
                "dev-only-hmac-key-do-not-use-in-production-please-rotate-via-env",
            ),
        })
    }
}

fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}
