//! Port of `com.xerika.auth.admin.*` — admin API + DTOs. The
//! `@RequiresRole("admin")` annotation + `RoleFilter` provider on the
//! Java side is replaced by an inline `require_admin` helper since admin
//! is the only `@RequiresRole` consumer on the auth server.

pub mod dto;
pub mod resource;
