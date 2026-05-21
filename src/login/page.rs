//! Port of `com.xerika.auth.login.LoginPageResource`.
//!
//! Server-rendered login page used as the OIDC authorization-flow front
//! door. Pairs a hidden CSRF input with a `csrf_token` HttpOnly cookie —
//! double-submit pattern. The token is reused across tabs (if a cookie
//! already exists) so a second open of `/login` doesn't break the first.

use std::time::Duration;

use actix_web::cookie::time::Duration as CookieDuration;
use actix_web::cookie::{Cookie, SameSite};
use actix_web::http::header;
use actix_web::{HttpRequest, HttpResponse, web};
use askama::Template;
use serde::Deserialize;
use subtle::ConstantTimeEq;
use url::Url;

use crate::common::crypto::random_tokens;
use crate::common::web::client_ip;
use crate::error::{AppError, AppResult};
use crate::login::resource::session_cookie;
use crate::session::SESSION_TTL_HOURS;
use crate::state::SharedState;

const CSRF_COOKIE: &str = "csrf_token";
const CSRF_TOKEN_BYTES: usize = 24;
const CSRF_COOKIE_MAX_AGE_SECONDS: i64 = 3600;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/login")
            .route(web::get().to(render_login))
            .route(web::post().to(submit_login)),
    );
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage {
    return_to: String,
    email: String,
    csrf: String,
    error: Option<String>,
}

#[derive(Deserialize)]
struct LoginQuery {
    return_to: Option<String>,
    error: Option<String>,
}

async fn render_login(
    req: HttpRequest,
    query: web::Query<LoginQuery>,
) -> AppResult<HttpResponse> {
    // Reuse existing CSRF cookie if user already has one (multi-tab flow).
    let existing = req.cookie(CSRF_COOKIE).map(|c| c.value().to_string());
    let reusable = existing.as_deref().map(|s| !s.is_empty()).unwrap_or(false);
    let csrf = if reusable {
        existing.unwrap()
    } else {
        random_tokens::url_safe(CSRF_TOKEN_BYTES)
    };

    let page = LoginPage {
        return_to: query.return_to.clone().unwrap_or_default(),
        email: String::new(),
        csrf: csrf.clone(),
        error: normalize_error(query.error.as_deref()),
    };
    let body = page
        .render()
        .map_err(|e| AppError::Other(anyhow::anyhow!("askama: {e}")))?;

    let mut resp = HttpResponse::Ok()
        .content_type(header::ContentType::html())
        .body(body);

    if !reusable {
        // SAFETY: the secure flag depends on profile; in dev we send the
        // cookie over plain HTTP, in prod only over HTTPS — same as Java.
        let cookie = build_csrf_cookie(&csrf, false /* overwritten below */);
        let _ = cookie; // keep cookie variable in scope for clarity
        // Use the actual `cookieSecure` value from config:
        // (we needed `state` for that — see below in submit_login. For the
        // GET path we can't reach AppState without it being injected — and
        // it's not, so we read the config via the request-shared data path.)
        // Practical fix: pull AppState from req extensions.
        if let Some(state) = req.app_data::<web::Data<SharedState>>() {
            resp.add_cookie(&build_csrf_cookie(&csrf, state.config.cookie.secure))
                .ok();
        } else {
            resp.add_cookie(&build_csrf_cookie(&csrf, false)).ok();
        }
    }
    Ok(resp)
}

#[derive(Deserialize)]
struct LoginForm {
    email: Option<String>,
    password: Option<String>,
    return_to: Option<String>,
    csrf_token: Option<String>,
}

async fn submit_login(
    state: web::Data<SharedState>,
    req: HttpRequest,
    form: web::Form<LoginForm>,
) -> AppResult<HttpResponse> {
    let csrf_cookie = req.cookie(CSRF_COOKIE).map(|c| c.value().to_string());

    // Double-submit cookie check. A cross-origin POST can't read/set the
    // cookie, so it can't satisfy this even if it bypasses SameSite=Lax.
    if !csrf_matches(form.csrf_token.as_deref(), csrf_cookie.as_deref()) {
        return Ok(HttpResponse::SeeOther()
            .insert_header((header::LOCATION, "/login?error=session_expired"))
            .finish());
    }

    let user = state
        .login_service
        .authenticate(form.email.as_deref(), form.password.as_deref())
        .await?;

    let user = match user {
        Some(u) => u,
        None => {
            // Re-render with error; preserve the email + reuse the existing
            // CSRF cookie so the resubmit doesn't have to mint a new one.
            let page = LoginPage {
                return_to: form.return_to.clone().unwrap_or_default(),
                email: form.email.clone().unwrap_or_default(),
                csrf: csrf_cookie.unwrap_or_default(),
                error: Some("Invalid email or password".to_string()),
            };
            let body = page
                .render()
                .map_err(|e| AppError::Other(anyhow::anyhow!("askama: {e}")))?;
            return Ok(HttpResponse::Ok()
                .content_type(header::ContentType::html())
                .body(body));
        }
    };

    let ip = client_ip::client_ip(&req);
    let user_agent = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let session = state
        .session_service
        .create_session(
            user.id,
            &user.email,
            &user.username,
            user.email_verified,
            user.enabled,
            ip,
            user_agent,
        )
        .await?;

    let target = safe_redirect(form.return_to.as_deref());
    Ok(HttpResponse::SeeOther()
        .insert_header((header::LOCATION, target))
        .cookie(session_cookie(
            session.session_token,
            state.config.cookie.secure,
            Duration::from_secs((SESSION_TTL_HOURS as u64) * 3600),
        ))
        .finish())
}

fn normalize_error(error: Option<&str>) -> Option<String> {
    match error {
        Some(s) if !s.trim().is_empty() => Some(match s {
            "session_expired" => "Your session expired. Please try again.".to_string(),
            other => other.to_string(),
        }),
        _ => None,
    }
}

fn build_csrf_cookie(value: &str, secure: bool) -> Cookie<'static> {
    Cookie::build(CSRF_COOKIE, value.to_string())
        .path("/login")
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(CSRF_COOKIE_MAX_AGE_SECONDS))
        .finish()
}

fn csrf_matches(form_value: Option<&str>, cookie_value: Option<&str>) -> bool {
    let (Some(a), Some(b)) = (form_value, cookie_value) else {
        return false;
    };
    if a.is_empty() || b.is_empty() {
        return false;
    }
    let a = a.as_bytes();
    let b = b.as_bytes();
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// Open-redirect defense. Accepts only server-relative paths, rejects
/// protocol-relative (`//evil.com`), backslash variants (`/\evil.com`),
/// and anything with a scheme/authority. Mirrors Java `safeRedirect`.
fn safe_redirect(return_to: Option<&str>) -> String {
    let Some(s) = return_to else {
        return "/".to_string();
    };
    if s.trim().is_empty() {
        return "/".to_string();
    }
    if !s.starts_with('/') {
        return "/".to_string();
    }
    // Block `//evil.com` and `/\evil.com`.
    if s.len() > 1 {
        let c = s.as_bytes()[1];
        if c == b'/' || c == b'\\' {
            return "/".to_string();
        }
    }
    // Defense in depth: if it parses as an absolute URL with a host,
    // refuse it — should be unreachable given the prefix checks above.
    if let Ok(parsed) = Url::parse(s) {
        if parsed.has_host() {
            return "/".to_string();
        }
    }
    s.to_string()
}
