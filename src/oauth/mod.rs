//! Port of `com.xerika.auth.oauth.*` — RFC 6749 / OIDC core.
//!
//! Phase 6 wires up: `/oauth/authorize`, `/oauth/token`, `/oauth/introspect`,
//! `/oauth/revoke`. Consent / device / logout / OIDC discovery land in
//! Phase 7.

pub mod authorize;
pub mod pkce;
pub mod resource;
pub mod scopes;
pub mod token;
