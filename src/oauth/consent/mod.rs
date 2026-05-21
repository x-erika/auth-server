//! Port of `com.xerika.auth.oauth.consent.*`.

pub mod model;
pub mod pending_store;
pub mod repository;
pub mod resource;
pub mod service;

pub use model::{PendingAuthorization, UserConsent};
pub use pending_store::PendingAuthorizationStore;
pub use repository::UserConsentRepository;
pub use service::ConsentService;
