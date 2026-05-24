//! Port of `com.xerika.auth.bootstrap.*` — startup-time seeders that run
//! once per process. Each acquires a Postgres `pg_advisory_xact_lock` so
//! multi-replica deploys don't double-write.
//!
//! The Java side observes `StartupEvent` via `@Observes`. In Rust we just
//! `.await` each routine from `main()` after the DB/Redis pools land and
//! before the HTTP server binds — same effect, simpler wiring.

pub mod admin;
pub mod lock;
pub mod role;
pub mod web_app_client;

pub use admin::ensure_admin_user;
pub use role::ensure_core_roles;
pub use web_app_client::ensure_bootstrap_clients;
