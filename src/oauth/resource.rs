//! Port of `OAuthResource.java`. Phase 6 wires `/oauth/authorize`,
//! `/oauth/token`, `/oauth/introspect`, `/oauth/revoke`. Logout + device
//! land in Phase 7.

use actix_web::http::header;
use actix_web::{HttpRequest, HttpResponse, web};
use serde::Deserialize;
use serde_json::json;

use crate::common::web::bearer;
use crate::error::{AppError, AppResult};
use crate::oauth::authorize::flow::AuthorizeRequest;
use crate::state::SharedState;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/oauth")
            .route("/authorize", web::get().to(authorize))
            .route("/token", web::post().to(token))
            .route("/revoke", web::post().to(revoke))
            .route("/introspect", web::post().to(introspect)),
    );
}

#[derive(Debug, Deserialize)]
struct AuthorizeQuery {
    client_id: Option<String>,
    redirect_uri: Option<String>,
    response_type: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    nonce: Option<String>,
    prompt: Option<String>,
    max_age: Option<i64>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    request: Option<String>,
    claims: Option<String>,
}

async fn authorize(
    state: web::Data<SharedState>,
    req: HttpRequest,
    query: web::Query<AuthorizeQuery>,
) -> AppResult<HttpResponse> {
    let session_token = bearer::extract(&req);
    let result = state
        .authorize_flow
        .authorize(AuthorizeRequest {
            session_token: session_token.as_deref(),
            client_id: query.client_id.as_deref(),
            redirect_uri: query.redirect_uri.as_deref(),
            response_type: query.response_type.as_deref(),
            scope: query.scope.as_deref(),
            state: query.state.as_deref(),
            nonce: query.nonce.as_deref(),
            prompt: query.prompt.as_deref(),
            max_age: query.max_age,
            code_challenge: query.code_challenge.as_deref(),
            code_challenge_method: query.code_challenge_method.as_deref(),
            request_jwt: query.request.as_deref(),
            claims_json: query.claims.as_deref(),
        })
        .await
        .map_err(|e| AppError::Other(e))?;

    if !result.ok {
        // No active session — bounce to /login with the original /authorize URL
        // as return_to.
        if result.error.as_deref() == Some("invalid_session") {
            let path = req.uri().path();
            let qs = req.query_string();
            let return_to = if qs.is_empty() {
                path.to_string()
            } else {
                format!("{path}?{qs}")
            };
            let location = format!("/login?return_to={}", urlencoding::encode(&return_to));
            return Ok(HttpResponse::SeeOther()
                .insert_header((header::LOCATION, location))
                .finish());
        }
        if result.error.as_deref() == Some("consent_required") {
            if let Some(req_id) = result.consent_request_id {
                let location = format!("/consent?req={}", urlencoding::encode(&req_id));
                return Ok(HttpResponse::SeeOther()
                    .insert_header((header::LOCATION, location))
                    .finish());
            }
        }
        // Post-validation error: redirect_uri trusted, bounce back per RFC.
        if let Some(redirect) = result.redirect {
            return Ok(HttpResponse::SeeOther()
                .insert_header((header::LOCATION, redirect))
                .finish());
        }
        // Pre-validation error: JSON 400 (redirect_uri not trusted).
        return Ok(HttpResponse::BadRequest().json(json!({
            "error": result.error.unwrap_or_else(|| "invalid_request".to_string()),
            "error_description": result.error_description.unwrap_or_default(),
        })));
    }

    Ok(HttpResponse::SeeOther()
        .insert_header((header::LOCATION, result.redirect.unwrap()))
        .finish())
}

#[derive(Debug, Deserialize)]
struct TokenForm {
    grant_type: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    scope: Option<String>,
    device_code: Option<String>,
}

async fn token(
    state: web::Data<SharedState>,
    form: web::Form<TokenForm>,
) -> AppResult<HttpResponse> {
    let result = state
        .token_flow
        .token(crate::oauth::token::flow::TokenRequest {
            grant_type: form.grant_type.as_deref(),
            code: form.code.as_deref(),
            redirect_uri: form.redirect_uri.as_deref(),
            client_id: form.client_id.as_deref(),
            client_secret: form.client_secret.as_deref(),
            code_verifier: form.code_verifier.as_deref(),
            refresh_token: form.refresh_token.as_deref(),
            scope: form.scope.as_deref(),
            device_code: form.device_code.as_deref(),
        })
        .await
        .map_err(|e| AppError::Other(e))?;

    if !result.ok {
        return Ok(oauth_error_response(
            result.error.as_deref().unwrap_or("invalid_request"),
            result.error_description.as_deref(),
        ));
    }
    Ok(HttpResponse::Ok().json(result.payload.unwrap()))
}

#[derive(Debug, Deserialize)]
struct RevokeForm {
    token: Option<String>,
    token_type_hint: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

async fn revoke(
    state: web::Data<SharedState>,
    form: web::Form<RevokeForm>,
) -> AppResult<HttpResponse> {
    let result = state
        .revoke_flow
        .revoke(
            form.token.as_deref().unwrap_or(""),
            form.token_type_hint.as_deref(),
            form.client_id.as_deref().unwrap_or(""),
            form.client_secret.as_deref(),
        )
        .await
        .map_err(|e| AppError::Other(e))?;

    if !result.ok {
        return Ok(oauth_error_response(
            result.error.as_deref().unwrap_or("invalid_request"),
            result.error_description.as_deref(),
        ));
    }
    Ok(HttpResponse::Ok().finish())
}

#[derive(Debug, Deserialize)]
struct IntrospectForm {
    token: Option<String>,
    token_type_hint: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

async fn introspect(
    state: web::Data<SharedState>,
    form: web::Form<IntrospectForm>,
) -> AppResult<HttpResponse> {
    let _ = form.token_type_hint.as_deref(); // accepted but not used
    let result = state
        .introspect_flow
        .introspect(
            form.token.as_deref().unwrap_or(""),
            form.client_id.as_deref().unwrap_or(""),
            form.client_secret.as_deref(),
        )
        .await
        .map_err(|e| AppError::Other(e))?;

    if !result.ok {
        return Ok(oauth_error_response(
            result.error.as_deref().unwrap_or("invalid_request"),
            result.error_description.as_deref(),
        ));
    }
    Ok(HttpResponse::Ok().json(result.payload.unwrap()))
}

/// RFC 6749 §5.2: `invalid_client` → 401, everything else → 400. Centralised
/// so /token, /revoke, /introspect stay consistent.
fn oauth_error_response(error: &str, description: Option<&str>) -> HttpResponse {
    let body = json!({
        "error": error,
        "error_description": description.unwrap_or(""),
    });
    if error == "invalid_client" {
        HttpResponse::Unauthorized().json(body)
    } else {
        HttpResponse::BadRequest().json(body)
    }
}
