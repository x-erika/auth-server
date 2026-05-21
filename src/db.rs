//! Postgres connection pool + migration runner.
//!
//! Replaces Quarkus' `quarkus-jdbc-postgresql` + `quarkus-flyway`. The 10
//! Flyway-style migrations (`V1__init.sql` ... `V10__password_resets.sql`)
//! live in `./migrations` and are applied at startup via `sqlx::migrate!`.

use anyhow::{Context, Result};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

use crate::config::DbConfig;

pub type Db = PgPool;

pub async fn init(cfg: &DbConfig) -> Result<Db> {
    let pool = PgPoolOptions::new()
        .max_connections(cfg.max_connections)
        .connect(&cfg.url)
        .await
        .with_context(|| format!("connect postgres at {}", cfg.url))?;

    // `migrate-at-start=true` parity. The migrator embeds the SQL files at
    // compile time, so the binary is self-contained.
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("apply migrations")?;

    Ok(pool)
}
