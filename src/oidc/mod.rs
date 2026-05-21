//! Port of `com.xerika.auth.oidc.*` — OIDC discovery, JWKS, and the
//! `/userinfo` endpoint. The scope-filter equivalent (Java's `@RequiresScope`
//! annotation + JAX-RS `ContainerRequestFilter`) is inlined into the
//! `/userinfo` handler since that's currently the only scope-protected
//! resource on the auth server itself.

pub mod resource;
