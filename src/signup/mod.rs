//! Port of `com.xerika.auth.signup.*` — email verification entity +
//! repository, signup flow, JSON resource.

pub mod dto;
pub mod flow;
pub mod model;
pub mod repository;
pub mod resource;

pub use flow::SignupFlow;
pub use model::EmailVerification;
pub use repository::EmailVerificationRepository;
