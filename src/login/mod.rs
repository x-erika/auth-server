//! Port of `com.xerika.auth.login.*` — login JSON API, login HTML page,
//! `LoginService`, and the related DTOs.

pub mod dto;
pub mod page;
pub mod resource;
pub mod service;

pub use service::LoginService;
