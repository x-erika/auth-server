//! Port of `LoginResource.java` — `/auth/login`, `/auth/me`, `/auth/logout`.

use std::time::Duration;

use actix_web::cookie::time::Duration as CookieDuration;
use actix_web::cookie::{Cookie, SameSite};
use actix_web::{HttpRequest, HttpResponse, web};
use serde_json::json;

use crate::common::ratelimit::RateLimitDecision;
use crate::common::redis::keys;
use crate::common::web::bearer::{self, SESSION_COOKIE};
use crate::common::web::client_ip;
use crate::error::{AppError, AppResult};
use crate::session::SESSION_TTL_HOURS;
use crate::state::SharedState;

use super::dto::{LoginRequest, LoginResponse, MeResponse, SessionPayload, UserPayload};

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .route("/login", web::post().to(login))
            .route("/me", web::get().to(me))
            .route("/logout", web::post().to(logout)),
    );
}

async fn login(
    state: web::Data<SharedState>,
    req: HttpRequest,
    body: web::Json<LoginRequest>,
) -> AppResult<HttpResponse> {
    let identifier_owned = body.resolve_identifier().map(|s| s.to_string());
    let ip = client_ip::client_ip(&req);

    // Email-keyed limiter — only when we have an identifier to key on.
    if let Some(ref id) = identifier_owned {
        if !id.trim().is_empty() {
            let key = keys::rl_login_email(&id.trim().to_lowercase());
            apply_limit(
                &state.rate_limiter,
                &key,
                state.config.ratelimit.login_email_max,
                state.config.ratelimit.login_email_window,
            )
            .await?;
        }
    }
    // IP-keyed limiter — only when XFF-derived IP is present.
    if let Some(ref ip_addr) = ip {
        if !ip_addr.is_empty() {
            let key = keys::rl_login_ip(ip_addr);
            apply_limit(
                &state.rate_limiter,
                &key,
                state.config.ratelimit.login_ip_max,
                state.config.ratelimit.login_ip_window,
            )
            .await?;
        }
    }

    let user = state
        .session_service_login_helper(&state, identifier_owned.as_deref(), body.password.as_deref())
        .await?;
    let user = match user {
        Some(u) => u,
        None => {
            return Ok(HttpResponse::Unauthorized()
                .json(json!({"message": "invalid credentials"})));
        }
    };

    let user_agent = req
        .headers()
        .get(actix_web::http::header::USER_AGENT)
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

    let roles = state.roles.find_effective_names_by_user_id(user.id).await?;

    let cookie = session_cookie(
        session.session_token.clone(),
        state.config.cookie.secure,
        Duration::from_secs((SESSION_TTL_HOURS as u64) * 3600),
    );

    Ok(HttpResponse::Ok().cookie(cookie).json(LoginResponse {
        message: "login success".to_string(),
        session: SessionPayload::from_session(&session),
        user: UserPayload::from_user(
            user.id,
            &user.email,
            &user.username,
            user.email_verified,
            roles,
        ),
    }))
}

async fn me(state: web::Data<SharedState>, req: HttpRequest) -> AppResult<HttpResponse> {
    let Some(token) = bearer::extract(&req) else {
        return Ok(HttpResponse::Unauthorized().json(json!({"message": "invalid session"})));
    };
    let Some(hydrated) = state.session_service.find_active_session(&token).await? else {
        return Ok(HttpResponse::Unauthorized().json(json!({"message": "invalid session"})));
    };

    let roles = state
        .roles
        .find_effective_names_by_user_id(hydrated.session.user_id)
        .await?;

    Ok(HttpResponse::Ok().json(MeResponse {
        session: SessionPayload::from_session(&hydrated.session),
        user: UserPayload::from_session_with_user(&hydrated, roles),
    }))
}

async fn logout(state: web::Data<SharedState>, req: HttpRequest) -> AppResult<HttpResponse> {
    let Some(token) = bearer::extract(&req) else {
        return Ok(HttpResponse::Unauthorized().json(json!({"message": "invalid session"})));
    };
    let ok = match state.session_service.logout(&token).await {
        Ok(b) => b,
        Err(crate::session::SessionRepositoryError::RedisUnavailable(_)) => {
            return Err(AppError::Other(anyhow::anyhow!(
                "logout failed: redis unavailable"
            )));
        }
        Err(crate::session::SessionRepositoryError::Db(e)) => return Err(AppError::Db(e)),
    };
    if !ok {
        return Ok(HttpResponse::Unauthorized().json(json!({"message": "invalid session"})));
    }
    // Clear cookie by setting max-age=0.
    let clear = Cookie::build(SESSION_COOKIE, "")
        .path("/")
        .http_only(true)
        .secure(state.config.cookie.secure)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::ZERO)
        .finish();

    Ok(HttpResponse::Ok()
        .cookie(clear)
        .json(json!({"message": "logout success"})))
}

async fn apply_limit(
    limiter: &crate::common::ratelimit::RateLimiter,
    key: &str,
    max: u32,
    window: Duration,
) -> AppResult<RateLimitDecision> {
    let d = limiter.check(key, max, window).await;
    if !d.allowed {
        return Err(AppError::RateLimited {
            retry_after_seconds: d.retry_after_seconds,
        });
    }
    Ok(d)
}

pub fn session_cookie(value: String, secure: bool, ttl: Duration) -> Cookie<'static> {
    Cookie::build(SESSION_COOKIE, value)
        .path("/")
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(ttl.as_secs() as i64))
        .finish()
}

// Tiny indirection on AppState — keeps the route handler tidy and parallels
// `LoginService` injection on the Java side.
impl crate::state::AppState {
    async fn session_service_login_helper(
        &self,
        _shared: &SharedState,
        identifier: Option<&str>,
        password: Option<&str>,
    ) -> sqlx::Result<Option<crate::user::User>> {
        self.login_service.authenticate(identifier, password).await
    }
}
