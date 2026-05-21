//! Port of `AdminResource.java`. Every endpoint is gated by `require_admin`
//! — a thin Rust equivalent of Java's `@RequiresRole("admin")` + `RoleFilter`
//! pair. Inlined into this module since admin is currently the only
//! `@RequiresRole` consumer.

use actix_web::{HttpRequest, HttpResponse, web};
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use crate::client::{Client, ClientSecretHasher, RedirectUri};
use crate::common::crypto::argon2 as argon2_hasher;
use crate::common::web::bearer;
use crate::error::{AppError, AppResult};
use crate::oauth::token::RefreshTokenRepository;
use crate::role::RoleError;
use crate::session::SessionWithUser;
use crate::state::SharedState;
use crate::user::{Credential, User};

use super::dto::{
    ClientRequest, ClientSummary, ConsentSummary, RoleSummary, SessionSummary,
    UserCreateRequest, UserSummary, UserUpdateRequest,
};

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/admin")
            .route("/ping", web::get().to(ping))
            .route("/roles", web::get().to(list_roles))
            .route("/users", web::get().to(list_users))
            .route("/users", web::post().to(create_user))
            .route("/users/{user_id}", web::get().to(get_user))
            .route("/users/{user_id}", web::patch().to(update_user))
            .route("/users/{user_id}", web::delete().to(delete_user))
            .route(
                "/users/{user_id}/roles/{role_name}",
                web::post().to(assign_role),
            )
            .route(
                "/users/{user_id}/roles/{role_name}",
                web::delete().to(revoke_role),
            )
            .route(
                "/roles/{child}/parent/{parent}",
                web::post().to(set_role_parent),
            )
            .route(
                "/roles/{child}/parent",
                web::delete().to(clear_role_parent),
            )
            .route("/keys", web::get().to(list_keys))
            .route("/keys/rotate", web::post().to(rotate_key))
            .route("/clients", web::get().to(list_clients))
            .route("/clients", web::post().to(create_client))
            .route("/clients/{id}", web::get().to(get_client))
            .route("/clients/{id}", web::put().to(update_client))
            .route("/clients/{id}", web::delete().to(delete_client))
            .route(
                "/clients/{id}/redirect-uris",
                web::post().to(add_redirect_uri),
            )
            .route(
                "/clients/{id}/redirect-uris/{uri_id}",
                web::delete().to(remove_redirect_uri),
            )
            .route("/sessions", web::get().to(list_sessions))
            .route(
                "/users/{user_id}/sessions",
                web::get().to(list_sessions_for_user),
            )
            .route("/sessions/{id}", web::delete().to(revoke_session))
            .route(
                "/users/{user_id}/consents",
                web::get().to(list_consents_for_user),
            )
            .route("/consents/{id}", web::delete().to(revoke_consent)),
    );
}

/// `RoleFilter` Java parity: lookup session → effective roles → require
/// `admin`. Returns the hydrated session so handlers can read the calling
/// admin's user id (e.g. self-delete guard).
async fn require_admin(
    state: &SharedState,
    req: &HttpRequest,
) -> Result<SessionWithUser, HttpResponse> {
    let token = match bearer::extract(req) {
        Some(t) => t,
        None => {
            return Err(HttpResponse::Unauthorized()
                .json(json!({"message": "authentication required"})));
        }
    };
    let session = match state.session_service.find_active_session(&token).await {
        Ok(Some(s)) => s,
        _ => {
            return Err(HttpResponse::Unauthorized()
                .json(json!({"message": "authentication required"})));
        }
    };
    let roles = match state
        .roles
        .find_effective_names_by_user_id(session.session.user_id)
        .await
    {
        Ok(r) => r,
        Err(_) => {
            return Err(HttpResponse::InternalServerError()
                .json(json!({"message": "role lookup failed"})));
        }
    };
    if !roles.iter().any(|r| r == "admin") {
        return Err(HttpResponse::Forbidden().json(json!({
            "message": "forbidden",
            "required_roles": ["admin"]
        })));
    }
    Ok(session)
}

// ---- helpers ----

fn parse_uuid(s: &str, msg: &str) -> Result<Uuid, HttpResponse> {
    Uuid::parse_str(s).map_err(|_| HttpResponse::BadRequest().json(json!({"message": msg})))
}

// ---- handlers ----

async fn ping(state: web::Data<SharedState>, req: HttpRequest) -> AppResult<HttpResponse> {
    let session = match require_admin(&state, &req).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    Ok(HttpResponse::Ok().json(json!({
        "message": "hello admin",
        "username": session.user_username,
    })))
}

async fn list_roles(state: web::Data<SharedState>, req: HttpRequest) -> AppResult<HttpResponse> {
    if let Err(r) = require_admin(&state, &req).await {
        return Ok(r);
    }
    let roles: Vec<RoleSummary> = state
        .roles
        .find_all()
        .await?
        .iter()
        .map(RoleSummary::from_role)
        .collect();
    Ok(HttpResponse::Ok().json(roles))
}

async fn list_users(state: web::Data<SharedState>, req: HttpRequest) -> AppResult<HttpResponse> {
    if let Err(r) = require_admin(&state, &req).await {
        return Ok(r);
    }
    let users = state.users.find_all(100).await?;
    let mut out = Vec::with_capacity(users.len());
    for u in &users {
        let roles = state.roles.find_names_by_user_id(u.id).await?;
        out.push(UserSummary::from(u, roles));
    }
    Ok(HttpResponse::Ok().json(out))
}

async fn get_user(
    state: web::Data<SharedState>,
    req: HttpRequest,
    path: web::Path<String>,
) -> AppResult<HttpResponse> {
    if let Err(r) = require_admin(&state, &req).await {
        return Ok(r);
    }
    let user_id = match parse_uuid(&path, "invalid userId") {
        Ok(u) => u,
        Err(r) => return Ok(r),
    };
    let user = state.users.find_by_id(user_id).await?;
    let Some(user) = user else {
        return Ok(HttpResponse::NotFound().json(json!({"message": "user not found"})));
    };
    let roles = state.roles.find_names_by_user_id(user.id).await?;
    Ok(HttpResponse::Ok().json(UserSummary::from(&user, roles)))
}

async fn create_user(
    state: web::Data<SharedState>,
    req: HttpRequest,
    body: web::Json<UserCreateRequest>,
) -> AppResult<HttpResponse> {
    if let Err(r) = require_admin(&state, &req).await {
        return Ok(r);
    }

    let email = body.email.as_deref().unwrap_or("").trim().to_string();
    let username = body.username.as_deref().unwrap_or("").trim().to_string();
    let password = body.password.as_deref().unwrap_or("");
    if email.is_empty() || username.is_empty() || password.len() < 8 {
        return Ok(HttpResponse::BadRequest().json(json!({
            "message": "email, username, password (>=8 chars) are required"
        })));
    }
    let normalized_email = email.to_lowercase();
    if state.users.find_by_email(&normalized_email).await?.is_some() {
        return Ok(HttpResponse::Conflict().json(json!({"message": "email already registered"})));
    }
    if state.users.find_by_username(&username).await?.is_some() {
        return Ok(HttpResponse::Conflict().json(json!({"message": "username already taken"})));
    }

    let now = Utc::now().naive_utc();
    let user = User {
        id: Uuid::new_v4(),
        email: normalized_email,
        email_verified: body.email_verified.unwrap_or(false),
        username,
        first_name: body.first_name.clone(),
        last_name: body.last_name.clone(),
        enabled: body.enabled.unwrap_or(true),
        created_at: now,
        updated_at: now,
    };
    state.users.persist(&user).await?;

    let hashed = argon2_hasher::hash(password);
    let credential = Credential {
        id: Uuid::new_v4(),
        credential_type: "password".to_string(),
        secret_data: Some(hashed.secret_data),
        credential_data: Some(hashed.credential_data),
        created_at: now,
        updated_at: now,
        user_id: user.id,
    };
    state.credentials.persist(&credential).await?;

    if let Some(role) = state.roles.find_by_name("user").await? {
        let _ = state.roles.assign_to_user(user.id, role.id).await;
    }

    let roles = state.roles.find_names_by_user_id(user.id).await?;
    Ok(HttpResponse::Created().json(UserSummary::from(&user, roles)))
}

async fn update_user(
    state: web::Data<SharedState>,
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Json<UserUpdateRequest>,
) -> AppResult<HttpResponse> {
    if let Err(r) = require_admin(&state, &req).await {
        return Ok(r);
    }
    let user_id = match parse_uuid(&path, "invalid userId") {
        Ok(u) => u,
        Err(r) => return Ok(r),
    };
    let Some(mut user) = state.users.find_by_id(user_id).await? else {
        return Ok(HttpResponse::NotFound().json(json!({"message": "user not found"})));
    };

    let old_email_verified = user.email_verified;
    let mut kick_sessions = false;
    let mut email_verified_cache_only = false;

    if let Some(ref fn_) = body.first_name {
        user.first_name = Some(fn_.clone());
    }
    if let Some(ref ln) = body.last_name {
        user.last_name = Some(ln.clone());
    }
    if let Some(enabled) = body.enabled {
        user.enabled = enabled;
        if !enabled {
            kick_sessions = true;
        }
    }
    if let Some(ev) = body.email_verified {
        user.email_verified = ev;
        if old_email_verified && !ev {
            kick_sessions = true;
        } else if old_email_verified != ev {
            email_verified_cache_only = true;
        }
    }

    if kick_sessions {
        let _ = state.sessions.delete_all_by_user_id(user_id).await;
    }

    user.updated_at = Utc::now().naive_utc();
    let _ = state.users.update(&user).await?;

    if !kick_sessions && email_verified_cache_only {
        let _ = state.sessions.invalidate_cache_by_user_id(user_id).await;
    }

    if let Some(ref np) = body.new_password {
        if !np.is_empty() {
            if np.len() < 8 {
                return Ok(HttpResponse::BadRequest()
                    .json(json!({"message": "password must be at least 8 characters"})));
            }
            let hashed = argon2_hasher::hash(np);
            let now = Utc::now().naive_utc();
            let existing = state
                .credentials
                .find_first_by_user_id_and_type(user_id, "password")
                .await?;
            match existing {
                Some(mut c) => {
                    c.secret_data = Some(hashed.secret_data);
                    c.credential_data = Some(hashed.credential_data);
                    c.updated_at = now;
                    state.credentials.update(&c).await?;
                }
                None => {
                    let c = Credential {
                        id: Uuid::new_v4(),
                        credential_type: "password".to_string(),
                        secret_data: Some(hashed.secret_data),
                        credential_data: Some(hashed.credential_data),
                        created_at: now,
                        updated_at: now,
                        user_id,
                    };
                    state.credentials.persist(&c).await?;
                }
            }
            let _ = state.sessions.delete_all_by_user_id(user_id).await;
        }
    }

    let roles = state.roles.find_names_by_user_id(user_id).await?;
    Ok(HttpResponse::Ok().json(UserSummary::from(&user, roles)))
}

async fn delete_user(
    state: web::Data<SharedState>,
    req: HttpRequest,
    path: web::Path<String>,
) -> AppResult<HttpResponse> {
    let calling = match require_admin(&state, &req).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let user_id = match parse_uuid(&path, "invalid userId") {
        Ok(u) => u,
        Err(r) => return Ok(r),
    };
    if calling.session.user_id == user_id {
        return Ok(HttpResponse::BadRequest()
            .json(json!({"message": "cannot delete your own account"})));
    }
    let _ = state.sessions.delete_all_by_user_id(user_id).await;
    state.users.delete(user_id).await?;
    Ok(HttpResponse::NoContent().finish())
}

async fn assign_role(
    state: web::Data<SharedState>,
    req: HttpRequest,
    path: web::Path<(String, String)>,
) -> AppResult<HttpResponse> {
    if let Err(r) = require_admin(&state, &req).await {
        return Ok(r);
    }
    let (user_id_str, role_name) = path.into_inner();
    let user_id = match parse_uuid(&user_id_str, "invalid userId") {
        Ok(u) => u,
        Err(r) => return Ok(r),
    };
    let user = state.users.find_by_id(user_id).await?;
    let role = state.roles.find_by_name(&role_name).await?;
    let (Some(_user), Some(role)) = (user, role) else {
        return Ok(HttpResponse::NotFound().json(json!({"message": "user or role not found"})));
    };
    if !state.roles.is_assigned(user_id, role.id).await? {
        let _ = state.roles.assign_to_user(user_id, role.id).await;
    }
    let names = state.roles.find_names_by_user_id(user_id).await?;
    Ok(HttpResponse::Ok().json(json!({"message": "role assigned", "roles": names})))
}

async fn revoke_role(
    state: web::Data<SharedState>,
    req: HttpRequest,
    path: web::Path<(String, String)>,
) -> AppResult<HttpResponse> {
    if let Err(r) = require_admin(&state, &req).await {
        return Ok(r);
    }
    let (user_id_str, role_name) = path.into_inner();
    let user_id = match parse_uuid(&user_id_str, "invalid userId") {
        Ok(u) => u,
        Err(r) => return Ok(r),
    };
    let role = state.roles.find_by_name(&role_name).await?;
    let Some(role) = role else {
        return Ok(HttpResponse::NotFound().json(json!({"message": "role not found"})));
    };
    let _ = state.roles.unassign_from_user(user_id, role.id).await;
    let names = state.roles.find_names_by_user_id(user_id).await?;
    Ok(HttpResponse::Ok().json(json!({"message": "role revoked", "roles": names})))
}

async fn set_role_parent(
    state: web::Data<SharedState>,
    req: HttpRequest,
    path: web::Path<(String, String)>,
) -> AppResult<HttpResponse> {
    if let Err(r) = require_admin(&state, &req).await {
        return Ok(r);
    }
    let (child_name, parent_name) = path.into_inner();
    let child = state.roles.find_by_name(&child_name).await?;
    let parent = state.roles.find_by_name(&parent_name).await?;
    let (Some(child), Some(parent)) = (child, parent) else {
        return Ok(HttpResponse::NotFound().json(json!({"message": "role not found"})));
    };
    match state.roles.set_parent(child.id, Some(parent.id)).await {
        Ok(()) => Ok(HttpResponse::Ok().json(json!({
            "message": "parent set",
            "child": child_name,
            "parent": parent_name,
        }))),
        Err(RoleError::Cycle(msg)) => {
            Ok(HttpResponse::BadRequest().json(json!({"message": msg})))
        }
        Err(RoleError::Db(e)) => Err(AppError::Db(e)),
    }
}

async fn clear_role_parent(
    state: web::Data<SharedState>,
    req: HttpRequest,
    path: web::Path<String>,
) -> AppResult<HttpResponse> {
    if let Err(r) = require_admin(&state, &req).await {
        return Ok(r);
    }
    let child = state.roles.find_by_name(&path).await?;
    let Some(child) = child else {
        return Ok(HttpResponse::NotFound().json(json!({"message": "role not found"})));
    };
    let _ = state.roles.set_parent(child.id, None).await;
    Ok(HttpResponse::Ok().json(json!({
        "message": "parent cleared",
        "child": path.into_inner(),
    })))
}

async fn list_keys(state: web::Data<SharedState>, req: HttpRequest) -> AppResult<HttpResponse> {
    if let Err(r) = require_admin(&state, &req).await {
        return Ok(r);
    }
    let active = state.rsa_keys.key_id();
    let entries: Vec<_> = state
        .rsa_keys
        .all_public_keys()
        .into_iter()
        .map(|e| json!({"kid": e.kid, "active": e.kid == active}))
        .collect();
    Ok(HttpResponse::Ok().json(json!({"active_kid": active, "keys": entries})))
}

async fn rotate_key(state: web::Data<SharedState>, req: HttpRequest) -> AppResult<HttpResponse> {
    if let Err(r) = require_admin(&state, &req).await {
        return Ok(r);
    }
    let previous = state.rsa_keys.key_id();
    let new_kid = state.rsa_keys.rotate().map_err(AppError::Other)?;
    Ok(HttpResponse::Ok().json(json!({
        "message": "key rotated",
        "previous_kid": previous,
        "new_active_kid": new_kid,
    })))
}

async fn list_clients(state: web::Data<SharedState>, req: HttpRequest) -> AppResult<HttpResponse> {
    if let Err(r) = require_admin(&state, &req).await {
        return Ok(r);
    }
    let summaries: Vec<ClientSummary> = state
        .clients
        .find_all()
        .await?
        .iter()
        .map(ClientSummary::from_client)
        .collect();
    Ok(HttpResponse::Ok().json(summaries))
}

async fn get_client(
    state: web::Data<SharedState>,
    req: HttpRequest,
    path: web::Path<String>,
) -> AppResult<HttpResponse> {
    if let Err(r) = require_admin(&state, &req).await {
        return Ok(r);
    }
    let id = match parse_uuid(&path, "invalid id") {
        Ok(u) => u,
        Err(r) => return Ok(r),
    };
    let client = state.clients.find_by_id(id).await?;
    match client {
        Some(c) => Ok(HttpResponse::Ok().json(ClientSummary::from_client(&c))),
        None => Ok(HttpResponse::NotFound().json(json!({"message": "client not found"}))),
    }
}

async fn create_client(
    state: web::Data<SharedState>,
    req: HttpRequest,
    body: web::Json<ClientRequest>,
) -> AppResult<HttpResponse> {
    if let Err(r) = require_admin(&state, &req).await {
        return Ok(r);
    }
    let cid = body.client_id.as_deref().unwrap_or("").trim();
    if cid.is_empty() {
        return Ok(HttpResponse::BadRequest().json(json!({"message": "clientId is required"})));
    }
    if state.clients.find_by_client_id(cid).await?.is_some() {
        return Ok(HttpResponse::Conflict().json(json!({"message": "clientId already exists"})));
    }
    let now = Utc::now().naive_utc();
    let client = Client {
        id: Uuid::new_v4(),
        client_id: cid.to_string(),
        client_secret: body
            .client_secret
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(ClientSecretHasher::hash),
        name: body.name.clone(),
        client_type: Some(body.client_type.clone().unwrap_or_else(|| "public".to_string())),
        grant_types: body.grant_types.clone(),
        response_types: body.response_types.clone(),
        scopes: body.scopes.clone(),
        pkce_required: body.pkce_required.unwrap_or(true),
        enabled: body.enabled.unwrap_or(true),
        base_url: body.base_url.clone(),
        description: body.description.clone(),
        access_token_ttl: None,
        refresh_token_ttl: None,
        frontchannel_logout_uri: body.frontchannel_logout_uri.clone(),
        backchannel_logout_uri: body.backchannel_logout_uri.clone(),
        created_at: now,
        updated_at: now,
        redirect_uris: Vec::new(),
    };
    state.clients.persist(&client).await?;
    let fresh = state
        .clients
        .find_by_id(client.id)
        .await?
        .unwrap_or(client);
    Ok(HttpResponse::Created().json(ClientSummary::from_client(&fresh)))
}

async fn update_client(
    state: web::Data<SharedState>,
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Json<ClientRequest>,
) -> AppResult<HttpResponse> {
    if let Err(r) = require_admin(&state, &req).await {
        return Ok(r);
    }
    let id = match parse_uuid(&path, "invalid id") {
        Ok(u) => u,
        Err(r) => return Ok(r),
    };
    let Some(mut existing) = state.clients.find_by_id(id).await? else {
        return Ok(HttpResponse::NotFound().json(json!({"message": "client not found"})));
    };

    if let Some(ref s) = body.client_secret {
        if !s.is_empty() {
            existing.client_secret = Some(ClientSecretHasher::hash(s));
        }
    }
    if let Some(ref n) = body.name {
        existing.name = Some(n.clone());
    }
    if let Some(ref t) = body.client_type {
        existing.client_type = Some(t.clone());
    }
    if let Some(ref s) = body.scopes {
        existing.scopes = Some(s.clone());
    }
    if let Some(ref g) = body.grant_types {
        existing.grant_types = Some(g.clone());
    }
    if let Some(ref r) = body.response_types {
        existing.response_types = Some(r.clone());
    }
    if let Some(p) = body.pkce_required {
        existing.pkce_required = p;
    }
    if let Some(e) = body.enabled {
        existing.enabled = e;
    }
    if let Some(ref b) = body.base_url {
        existing.base_url = Some(b.clone());
    }
    if let Some(ref d) = body.description {
        existing.description = Some(d.clone());
    }
    if let Some(ref f) = body.frontchannel_logout_uri {
        existing.frontchannel_logout_uri = Some(f.clone());
    }
    if let Some(ref b) = body.backchannel_logout_uri {
        existing.backchannel_logout_uri = Some(b.clone());
    }
    existing.updated_at = Utc::now().naive_utc();
    let _ = state.clients.update(&existing).await?;
    let fresh = state
        .clients
        .find_by_id(id)
        .await?
        .unwrap_or(existing);
    Ok(HttpResponse::Ok().json(ClientSummary::from_client(&fresh)))
}

async fn delete_client(
    state: web::Data<SharedState>,
    req: HttpRequest,
    path: web::Path<String>,
) -> AppResult<HttpResponse> {
    if let Err(r) = require_admin(&state, &req).await {
        return Ok(r);
    }
    let id = match parse_uuid(&path, "invalid id") {
        Ok(u) => u,
        Err(r) => return Ok(r),
    };
    let _ = state.clients.delete(id).await?;
    Ok(HttpResponse::NoContent().finish())
}

#[derive(serde::Deserialize)]
struct AddRedirectBody {
    uri: Option<String>,
}

async fn add_redirect_uri(
    state: web::Data<SharedState>,
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Json<AddRedirectBody>,
) -> AppResult<HttpResponse> {
    if let Err(r) = require_admin(&state, &req).await {
        return Ok(r);
    }
    let id = match parse_uuid(&path, "invalid id") {
        Ok(u) => u,
        Err(r) => return Ok(r),
    };
    let uri = body.uri.as_deref().unwrap_or("").trim().to_string();
    if uri.is_empty() {
        return Ok(HttpResponse::BadRequest().json(json!({"message": "uri is required"})));
    }
    let Some(_client) = state.clients.find_by_id(id).await? else {
        return Ok(HttpResponse::NotFound().json(json!({"message": "client not found"})));
    };
    let redirect = RedirectUri {
        id: Uuid::new_v4(),
        client_id: id,
        uri,
        created_at: Utc::now().naive_utc(),
    };
    state.clients.add_redirect_uri(&redirect).await?;
    let fresh = state.clients.find_by_id(id).await?;
    match fresh {
        Some(c) => Ok(HttpResponse::Ok().json(ClientSummary::from_client(&c))),
        None => Ok(HttpResponse::NotFound().json(json!({"message": "client not found"}))),
    }
}

async fn remove_redirect_uri(
    state: web::Data<SharedState>,
    req: HttpRequest,
    path: web::Path<(String, String)>,
) -> AppResult<HttpResponse> {
    if let Err(r) = require_admin(&state, &req).await {
        return Ok(r);
    }
    let (_client_id_str, uri_id_str) = path.into_inner();
    let uri_id = match parse_uuid(&uri_id_str, "invalid uriId") {
        Ok(u) => u,
        Err(r) => return Ok(r),
    };
    let _ = state.clients.remove_redirect_uri(uri_id).await?;
    Ok(HttpResponse::NoContent().finish())
}

async fn list_sessions(state: web::Data<SharedState>, req: HttpRequest) -> AppResult<HttpResponse> {
    if let Err(r) = require_admin(&state, &req).await {
        return Ok(r);
    }
    let sessions = state.sessions.find_all_active().await?;
    let summaries: Vec<SessionSummary> =
        sessions.iter().map(SessionSummary::from_session_only).collect();
    Ok(HttpResponse::Ok().json(summaries))
}

async fn list_sessions_for_user(
    state: web::Data<SharedState>,
    req: HttpRequest,
    path: web::Path<String>,
) -> AppResult<HttpResponse> {
    if let Err(r) = require_admin(&state, &req).await {
        return Ok(r);
    }
    let user_id = match parse_uuid(&path, "invalid userId") {
        Ok(u) => u,
        Err(r) => return Ok(r),
    };
    let sessions = state.sessions.find_active_by_user_id(user_id).await?;
    let summaries: Vec<SessionSummary> =
        sessions.iter().map(SessionSummary::from_session_only).collect();
    Ok(HttpResponse::Ok().json(summaries))
}

async fn revoke_session(
    state: web::Data<SharedState>,
    req: HttpRequest,
    path: web::Path<String>,
) -> AppResult<HttpResponse> {
    if let Err(r) = require_admin(&state, &req).await {
        return Ok(r);
    }
    let id = match parse_uuid(&path, "invalid id") {
        Ok(u) => u,
        Err(r) => return Ok(r),
    };
    // Revoke refresh tokens bound to this session FIRST, then drop the
    // session row (cache invalidation happens inside `delete`, fail-secure
    // — same Java order).
    let mut tx = state.db.begin().await?;
    let _ = RefreshTokenRepository::revoke_by_session_id_in_tx(&mut *tx, id).await?;
    tx.commit().await?;
    let _ = state.sessions.delete(id).await;
    Ok(HttpResponse::NoContent().finish())
}

async fn list_consents_for_user(
    state: web::Data<SharedState>,
    req: HttpRequest,
    path: web::Path<String>,
) -> AppResult<HttpResponse> {
    if let Err(r) = require_admin(&state, &req).await {
        return Ok(r);
    }
    let user_id = match parse_uuid(&path, "invalid userId") {
        Ok(u) => u,
        Err(r) => return Ok(r),
    };
    let consents = state.user_consents.find_by_user_id(user_id).await?;
    let mut summaries = Vec::with_capacity(consents.len());
    for c in &consents {
        let client = state.clients.find_by_id(c.client_id).await?;
        summaries.push(ConsentSummary::from(c, client.as_ref()));
    }
    Ok(HttpResponse::Ok().json(summaries))
}

async fn revoke_consent(
    state: web::Data<SharedState>,
    req: HttpRequest,
    path: web::Path<String>,
) -> AppResult<HttpResponse> {
    if let Err(r) = require_admin(&state, &req).await {
        return Ok(r);
    }
    let id = match parse_uuid(&path, "invalid id") {
        Ok(u) => u,
        Err(r) => return Ok(r),
    };
    let _ = state.user_consents.delete_by_id(id).await?;
    Ok(HttpResponse::NoContent().finish())
}
