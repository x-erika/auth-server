//! Port of `RefreshTokenCleanupJob`.
//!
//! Hourly sweep of `refresh_tokens` rows that are expired or revoked. FK
//! CASCADE handles the common case (logout deletes session → its tokens
//! disappear), but rotated/revoked tokens persist until the parent session
//! is gone, and a user that refreshes often without logging out can
//! accumulate one revoked row per refresh. This job caps that growth.

use std::time::Duration;

use chrono::Utc;
use tokio::time::interval;

use crate::db::Db;

const SWEEP_EVERY: Duration = Duration::from_secs(60 * 60); // 1h, parity with `every = "1h"`.

/// Spawn the periodic sweep on the current tokio runtime. Designed to be
/// dropped — the returned handle is `JoinHandle<()>` so the caller can hold
/// onto it (or let it be detached, which is fine; the loop runs forever).
pub fn start_refresh_token_cleanup(db: Db) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // SKIP-overlap parity: a single task means at-most-one sweep at a
        // time by construction.
        let mut tick = interval(SWEEP_EVERY);
        // First tick fires immediately, then on the interval.
        tick.tick().await;
        loop {
            tick.tick().await;
            match sweep_once(&db).await {
                Ok(n) if n > 0 => {
                    tracing::info!(deleted = n, "refresh token sweep: removed expired/revoked rows");
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "refresh token sweep failed");
                }
            }
        }
    })
}

async fn sweep_once(db: &Db) -> sqlx::Result<u64> {
    let res = sqlx::query(
        r#"DELETE FROM refresh_tokens
           WHERE revoked = TRUE
              OR (expires_at IS NOT NULL AND expires_at < $1)"#,
    )
    .bind(Utc::now().naive_utc())
    .execute(db)
    .await?;
    Ok(res.rows_affected())
}
