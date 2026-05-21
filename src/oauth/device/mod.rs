//! Port of `com.xerika.auth.oauth.device.*` — RFC 8628 device authorization.

pub mod flow;
pub mod model;
pub mod repository;
pub mod result;

pub use flow::DeviceFlow;
pub use model::{DeviceAuthorization, DeviceStatus};
pub use repository::DeviceAuthorizationRepository;
pub use result::{DeviceAuthorizationResult, DeviceVerifyResult};
