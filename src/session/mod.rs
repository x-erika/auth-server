//! Port of `com.xerika.auth.session.*` — `UserSession`, `SessionSnapshot`,
//! [`SessionRepository`] (with Redis cache), and [`SessionService`].

pub mod model;
pub mod repository;
pub mod service;

pub use model::{SessionSnapshot, SessionWithUser, UserSession};
pub use repository::{SessionRepository, SessionRepositoryError};
pub use service::{SESSION_TTL_HOURS, SessionService};
