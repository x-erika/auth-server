//! Pulls the client IP from `X-Forwarded-For` (first hop), with a fallback
//! to `req.peer_addr()`. Java reads the header directly; we do the same.

use actix_web::HttpRequest;

pub fn client_ip(req: &HttpRequest) -> Option<String> {
    if let Some(xff) = req.headers().get("X-Forwarded-For") {
        if let Ok(s) = xff.to_str() {
            let first = s.split(',').next().unwrap_or("").trim();
            if !first.is_empty() {
                return Some(first.to_string());
            }
        }
    }
    req.peer_addr().map(|addr| addr.ip().to_string())
}
