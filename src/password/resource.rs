//! Port of `com.xerika.auth.password.PasswordResource`.

use std::collections::HashMap;

use actix_web::{HttpRequest, HttpResponse, web};
use serde_json::json;

use crate::common::web::bearer;
use crate::error::{AppError, AppResult};
use crate::state::SharedState;

use super::flow::{ChangeError, ConsumeResetIoError, ResetError};

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .route("/forgot-password", web::post().to(forgot_password))
            .route("/reset-password", web::post().to(reset_password))
            .route("/change-password", web::put().to(change_password)),
    );
}

async fn forgot_password(
    state: web::Data<SharedState>,
    body: web::Json<HashMap<String, String>>,
) -> AppResult<HttpResponse> {
    // Accept several common identifier field names for compat with the
    // various FEs that have used this endpoint over time.
    let identifier = first_non_blank(&body, &["identifier", "email", "nim", "nip"]);
    let token = state
        .password_flow
        .request_reset(identifier.as_deref().unwrap_or(""))
        .await?;

    // Always respond identically — no enumeration. In dev, include the
    // token for testing; in prod this branch should be removed.
    let mut payload =
        serde_json::Map::from_iter([(
            "message".to_string(),
            json!("if the account exists, a reset token has been issued"),
        )]);
    if let Some(t) = token {
        payload.insert("resetToken".to_string(), json!(t));
    }
    Ok(HttpResponse::Ok().json(serde_json::Value::Object(payload)))
}

async fn reset_password(
    state: web::Data<SharedState>,
    body: web::Json<HashMap<String, String>>,
) -> AppResult<HttpResponse> {
    let token = body.get("token").cloned().unwrap_or_default();
    let new_password = first_non_blank(&body, &["newPassword", "new_password", "password"])
        .unwrap_or_default();

    let outcome = state
        .password_flow
        .consume_reset(&token, &new_password)
        .await;
    match outcome {
        Ok(Ok(())) => Ok(HttpResponse::Ok().json(json!({"message": "password updated"}))),
        Ok(Err(ResetError::InvalidToken)) => Ok(HttpResponse::BadRequest()
            .json(json!({"error": "invalid_token"}))),
        Ok(Err(ResetError::WeakPassword)) => Ok(HttpResponse::BadRequest()
            .json(json!({"error": "weak_password"}))),
        Err(ConsumeResetIoError::Db(e)) => Err(AppError::Db(e)),
        Err(ConsumeResetIoError::Session(e)) => Err(AppError::Other(anyhow::anyhow!(
            "consume_reset failed: {e}"
        ))),
    }
}

async fn change_password(
    state: web::Data<SharedState>,
    req: HttpRequest,
    body: web::Json<HashMap<String, String>>,
) -> AppResult<HttpResponse> {
    let Some(token) = bearer::extract(&req) else {
        return Ok(HttpResponse::Unauthorized().json(json!({"message": "invalid session"})));
    };
    let Some(session) = state.session_service.find_active_session(&token).await? else {
        return Ok(HttpResponse::Unauthorized().json(json!({"message": "invalid session"})));
    };

    let old_password = first_non_blank(
        &body,
        &["oldPassword", "currentPassword", "old_password"],
    )
    .unwrap_or_default();
    let new_password =
        first_non_blank(&body, &["newPassword", "new_password"]).unwrap_or_default();

    let outcome = state
        .password_flow
        .change_password(
            session.session.user_id,
            Some(session.session.id),
            &old_password,
            &new_password,
        )
        .await;
    match outcome {
        Ok(Ok(())) => Ok(HttpResponse::Ok().json(json!({"message": "password changed"}))),
        Ok(Err(ChangeError::WrongPassword)) => {
            Ok(HttpResponse::BadRequest().json(json!({"error": "wrong_password"})))
        }
        Ok(Err(ChangeError::WeakPassword)) => {
            Ok(HttpResponse::BadRequest().json(json!({"error": "weak_password"})))
        }
        Err(ConsumeResetIoError::Db(e)) => Err(AppError::Db(e)),
        Err(ConsumeResetIoError::Session(e)) => Err(AppError::Other(anyhow::anyhow!(
            "change_password failed: {e}"
        ))),
    }
}

fn first_non_blank(body: &HashMap<String, String>, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(v) = body.get(*k) {
            if !v.trim().is_empty() {
                return Some(v.clone());
            }
        }
    }
    None
}
