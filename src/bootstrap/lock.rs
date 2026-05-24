//! Postgres advisory lock — direct port of `BootstrapLock.java`.
//!
//! Single key shared across bootstraps (cost of serialising is negligible
//! per-process). `pg_advisory_xact_lock` blocks until granted and
//! auto-releases at txn end, so every caller must invoke this inside an
//! open transaction.

use sqlx::{PgConnection, Postgres, Transaction};

/// `"XERKABCO"` interpreted as a big-endian i64. Stable, unlikely to
/// collide with anything else the app does with `pg_advisory_lock` later.
const LOCK_KEY: i64 = 0x5845524B4142434F;

pub async fn acquire(tx: &mut Transaction<'_, Postgres>) -> sqlx::Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(LOCK_KEY)
        .execute(&mut **tx)
        .await
        .map(|_| ())
}

/// Variant that takes a raw `PgConnection` — useful when the caller is
/// already inside a `BEGIN` it owns elsewhere.
pub async fn acquire_on(conn: &mut PgConnection) -> sqlx::Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(LOCK_KEY)
        .execute(conn)
        .await
        .map(|_| ())
}
