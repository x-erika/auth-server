//! Port of `com.xerika.auth.common.web.BearerExtractor`.
//!
//! Extracts a session token from one of (in priority order):
//!   1. `Authorization: Bearer <token>` (case-insensitive scheme per RFC 6750 §2.1)
//!   2. `X-Session-Token: <token>` (admin-FE convenience header)
//!   3. `session_token` cookie (browser flow set by login)

use actix_web::HttpRequest;

pub const SESSION_COOKIE: &str = "session_token";
const BEARER_SCHEME_LEN: usize = "Bearer ".len();

pub fn extract(req: &HttpRequest) -> Option<String> {
    if let Some(token) = extract_from_headers(req) {
        if !token.trim().is_empty() {
            return Some(token);
        }
    }
    req.cookie(SESSION_COOKIE)
        .map(|c| c.value().to_string())
        .filter(|s| !s.is_empty())
}

fn extract_from_headers(req: &HttpRequest) -> Option<String> {
    if let Some(auth) = req.headers().get(actix_web::http::header::AUTHORIZATION) {
        if let Ok(s) = auth.to_str() {
            if s.len() > BEARER_SCHEME_LEN && s[..BEARER_SCHEME_LEN].eq_ignore_ascii_case("Bearer ") {
                return Some(s[BEARER_SCHEME_LEN..].trim().to_string());
            }
        }
    }
    req.headers()
        .get("X-Session-Token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}
