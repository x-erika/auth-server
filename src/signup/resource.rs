//! Port of `com.xerika.auth.signup.SignupResource` — `/auth/signup` &
//! `/auth/verify-email`.

use std::collections::HashMap;
use std::time::Duration;

use actix_web::{HttpRequest, HttpResponse, web};
use serde_json::json;

use crate::common::ratelimit::RateLimiter;
use crate::common::redis::keys;
use crate::common::web::client_ip;
use crate::error::{AppError, AppResult};
use crate::state::SharedState;

use super::dto::{SignupError, SignupRequest, VerifyEmailError};

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .route("/signup", web::post().to(signup))
            .route("/verify-email", web::post().to(verify_email)),
    );
}

async fn signup(
    state: web::Data<SharedState>,
    req: HttpRequest,
    body: web::Json<SignupRequest>,
) -> AppResult<HttpResponse> {
    if let Some(ip) = client_ip::client_ip(&req).filter(|s| !s.is_empty()) {
        apply_limit(
            &state.rate_limiter,
            &keys::rl_signup_ip(&ip),
            state.config.ratelimit.signup_ip_max,
            state.config.ratelimit.signup_ip_window,
        )
        .await?;
    }

    match state.signup_flow.signup(&body).await {
        Ok(ok) => Ok(HttpResponse::Created().json(json!({
            "message": "signup successful, verify your email",
            "userId": ok.user_id.to_string(),
            "verificationToken": ok.verification_token_raw,
        }))),
        Err(SignupError::Conflict(desc)) => Ok(HttpResponse::Conflict().json(json!({
            "error": "conflict",
            "error_description": desc,
        }))),
        Err(SignupError::InvalidRequest(desc)) => Ok(HttpResponse::BadRequest().json(json!({
            "error": "invalid_request",
            "error_description": desc,
        }))),
    }
}

async fn verify_email(
    state: web::Data<SharedState>,
    req: HttpRequest,
    body: web::Json<HashMap<String, String>>,
) -> AppResult<HttpResponse> {
    if let Some(ip) = client_ip::client_ip(&req).filter(|s| !s.is_empty()) {
        apply_limit(
            &state.rate_limiter,
            &keys::rl_verify_email(&ip),
            state.config.ratelimit.verify_email_ip_max,
            state.config.ratelimit.verify_email_ip_window,
        )
        .await?;
    }

    let token = body.get("token").cloned().unwrap_or_default();
    match state.signup_flow.verify_email(&token).await {
        Ok(ok) => Ok(HttpResponse::Ok().json(json!({
            "message": "email verified",
            "userId": ok.user_id.to_string(),
        }))),
        Err(VerifyEmailError::InvalidRequest(desc)) => {
            Ok(HttpResponse::BadRequest().json(json!({
                "error": "invalid_request",
                "error_description": desc,
            })))
        }
        Err(VerifyEmailError::InvalidToken(desc)) => Ok(HttpResponse::BadRequest().json(json!({
            "error": "invalid_token",
            "error_description": desc,
        }))),
    }
}

async fn apply_limit(
    limiter: &RateLimiter,
    key: &str,
    max: u32,
    window: Duration,
) -> AppResult<()> {
    let d = limiter.check(key, max, window).await;
    if !d.allowed {
        return Err(AppError::RateLimited {
            retry_after_seconds: d.retry_after_seconds,
        });
    }
    Ok(())
}
