//! OIDC discovery (`/.well-known/openid-configuration`), JWKS
//! (`/.well-known/jwks.json`), and `/userinfo`. Port of `OidcResource.java`.

use actix_web::{HttpRequest, HttpResponse, web};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::common::web::bearer;
use crate::error::AppResult;
use crate::oauth::scopes;
use crate::state::SharedState;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/userinfo", web::get().to(userinfo))
        .route(
            "/.well-known/openid-configuration",
            web::get().to(discovery),
        )
        .route("/.well-known/jwks.json", web::get().to(jwks));
}

async fn userinfo(state: web::Data<SharedState>, req: HttpRequest) -> AppResult<HttpResponse> {
    // Inlined RequiresScope("openid") filter equivalent.
    let Some(token) = bearer::extract(&req) else {
        return Ok(invalid_token_response());
    };
    let Some(claims) = state.jwt_validator.validate(&token) else {
        return Ok(invalid_token_response());
    };
    let scope_raw = claims
        .get("scope")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let scope_set = scopes::parse(Some(&scope_raw));
    if !scope_set.contains("openid") {
        return Ok(HttpResponse::Forbidden()
            .insert_header((
                "WWW-Authenticate",
                "Bearer error=\"insufficient_scope\", scope=\"openid\"",
            ))
            .json(json!({
                "error": "insufficient_scope",
                "required_scopes": ["openid"],
            })));
    }

    let sub_str = match claims.get("sub").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return Ok(invalid_token_response()),
    };
    let user_id = match Uuid::parse_str(sub_str) {
        Ok(u) => u,
        Err(_) => return Ok(invalid_token_response()),
    };
    let user = state.users.find_by_id(user_id).await?;
    let Some(user) = user.filter(|u| u.enabled) else {
        return Ok(invalid_token_response());
    };

    let mut info = Map::new();
    info.insert("sub".to_string(), json!(user.id.to_string()));

    let mut requested: Vec<String> = Vec::new();
    if let Some(arr) = claims.get("claims_userinfo").and_then(|v| v.as_array()) {
        for entry in arr {
            if let Some(s) = entry.as_str() {
                requested.push(s.to_string());
            }
        }
    }

    if scope_set.contains("email") || requested.iter().any(|s| s == "email") {
        info.insert("email".to_string(), json!(&user.email));
    }
    if scope_set.contains("email") || requested.iter().any(|s| s == "email_verified") {
        info.insert("email_verified".to_string(), json!(user.email_verified));
    }
    if scope_set.contains("profile") || requested.iter().any(|s| s == "preferred_username") {
        info.insert("preferred_username".to_string(), json!(&user.username));
    }
    if (scope_set.contains("profile") || requested.iter().any(|s| s == "given_name"))
        && user.first_name.is_some()
    {
        info.insert("given_name".to_string(), json!(user.first_name.as_ref().unwrap()));
    }
    if (scope_set.contains("profile") || requested.iter().any(|s| s == "family_name"))
        && user.last_name.is_some()
    {
        info.insert("family_name".to_string(), json!(user.last_name.as_ref().unwrap()));
    }
    if (scope_set.contains("profile") || requested.iter().any(|s| s == "name"))
        && user.first_name.is_some()
        && user.last_name.is_some()
    {
        info.insert(
            "name".to_string(),
            json!(format!(
                "{} {}",
                user.first_name.as_ref().unwrap(),
                user.last_name.as_ref().unwrap()
            )),
        );
    }

    Ok(HttpResponse::Ok().json(Value::Object(info)))
}

async fn discovery(state: web::Data<SharedState>) -> HttpResponse {
    let issuer = state.config.server.issuer_url.clone();
    HttpResponse::Ok().json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth/authorize"),
        "token_endpoint": format!("{issuer}/oauth/token"),
        "userinfo_endpoint": format!("{issuer}/userinfo"),
        "revocation_endpoint": format!("{issuer}/oauth/revoke"),
        "introspection_endpoint": format!("{issuer}/oauth/introspect"),
        "end_session_endpoint": format!("{issuer}/oauth/logout"),
        "frontchannel_logout_supported": true,
        "frontchannel_logout_session_supported": true,
        "backchannel_logout_supported": true,
        "backchannel_logout_session_supported": true,
        "request_parameter_supported": true,
        "request_uri_parameter_supported": false,
        "require_request_uri_registration": false,
        "claims_parameter_supported": true,
        "request_object_signing_alg_values_supported": ["HS256"],
        "device_authorization_endpoint": format!("{issuer}/oauth/device-authorization"),
        "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "grant_types_supported": [
            "authorization_code", "refresh_token", "client_credentials",
            "urn:ietf:params:oauth:grant-type:device_code"
        ],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "claims_supported": [
            "sub", "iss", "aud", "exp", "iat", "jti", "auth_time", "nonce",
            "email", "email_verified", "preferred_username",
            "name", "given_name", "family_name", "roles"
        ],
    }))
}

async fn jwks(state: web::Data<SharedState>) -> HttpResponse {
    let mut keys = Vec::new();
    for entry in state.rsa_keys.all_public_keys() {
        if let Some((n, e)) = state.rsa_keys.jwk_modulus_exponent(&entry.kid) {
            keys.push(json!({
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": entry.kid,
                "n": n,
                "e": e,
            }));
        }
    }
    HttpResponse::Ok().json(json!({ "keys": keys }))
}

fn invalid_token_response() -> HttpResponse {
    HttpResponse::Unauthorized()
        .insert_header((
            "WWW-Authenticate",
            "Bearer realm=\"userinfo\", error=\"invalid_token\"",
        ))
        .json(json!({ "error": "invalid_token" }))
}
