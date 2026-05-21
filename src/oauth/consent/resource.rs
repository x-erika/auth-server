//! Port of `ConsentResource.java` — `GET /consent?req=...` (render) +
//! `POST /consent` (allow/deny).

use actix_web::http::header;
use actix_web::{HttpRequest, HttpResponse, web};
use askama::Template;
use serde::Deserialize;
use url::Url;

use crate::common::web::bearer;
use crate::error::{AppError, AppResult};
use crate::oauth::scopes;
use crate::state::SharedState;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/consent")
            .route(web::get().to(render))
            .route(web::post().to(submit)),
    );
}

#[derive(Template)]
#[template(path = "consent.html")]
struct ConsentPage {
    request_id: String,
    client_name: String,
    client_id: String,
    client_initial: String,
    scopes: Vec<String>,
    user_label: String,
    redirect_host: String,
    error: Option<String>,
}

#[derive(Deserialize)]
struct ConsentQuery {
    req: Option<String>,
}

async fn render(
    state: web::Data<SharedState>,
    req: HttpRequest,
    query: web::Query<ConsentQuery>,
) -> AppResult<HttpResponse> {
    let token = bearer::extract(&req);
    let session = match token {
        Some(t) => state.session_service.find_active_session(&t).await?,
        None => None,
    };
    if session.is_none() {
        return Ok(HttpResponse::SeeOther()
            .insert_header((header::LOCATION, "/login"))
            .finish());
    }
    let session = session.unwrap();

    let request_id = query.req.clone().unwrap_or_default();
    let pending = state.pending_authorizations.get(&request_id).await
        .map_err(AppError::Other)?;
    let Some(pending) = pending else {
        return render_page(ConsentPage {
            request_id: String::new(),
            client_name: String::new(),
            client_id: String::new(),
            client_initial: "?".to_string(),
            scopes: Vec::new(),
            user_label: String::new(),
            redirect_host: String::new(),
            error: Some("Consent request not found or expired.".to_string()),
        });
    };
    if session.session.id != pending.session_id {
        return Ok(HttpResponse::Forbidden().body("session mismatch"));
    }

    let client = state.clients.find_by_client_id(&pending.client_id).await?;
    let client_name = client
        .as_ref()
        .and_then(|c| c.name.as_ref().filter(|n| !n.is_empty()).cloned())
        .unwrap_or_else(|| pending.client_id.clone());
    let mut scope_list: Vec<String> = scopes::parse(pending.scope.as_deref())
        .into_iter()
        .collect();
    scope_list.sort();

    let user_label = if !session.user_email.is_empty() {
        session.user_email.clone()
    } else {
        session.user_username.clone()
    };

    let redirect_host = redirect_host(&pending.redirect_uri);

    let client_initial = client_name
        .chars()
        .next()
        .map(|c| c.to_ascii_uppercase().to_string())
        .unwrap_or_else(|| "?".to_string());

    render_page(ConsentPage {
        request_id: pending.request_id.clone(),
        client_name,
        client_id: pending.client_id.clone(),
        client_initial,
        scopes: scope_list,
        user_label,
        redirect_host,
        error: None,
    })
}

#[derive(Deserialize)]
struct ConsentForm {
    req: Option<String>,
    action: Option<String>,
}

async fn submit(
    state: web::Data<SharedState>,
    req: HttpRequest,
    form: web::Form<ConsentForm>,
) -> AppResult<HttpResponse> {
    let token = bearer::extract(&req);
    let session = match token {
        Some(t) => state.session_service.find_active_session(&t).await?,
        None => None,
    };
    if session.is_none() {
        return Ok(HttpResponse::SeeOther()
            .insert_header((header::LOCATION, "/login"))
            .finish());
    }
    let session = session.unwrap();

    let request_id = form.req.clone().unwrap_or_default();
    let pending = state
        .pending_authorizations
        .take(&request_id)
        .await
        .map_err(AppError::Other)?;
    let Some(pending) = pending else {
        return render_page(ConsentPage {
            request_id: String::new(),
            client_name: String::new(),
            client_id: String::new(),
            client_initial: "?".to_string(),
            scopes: Vec::new(),
            user_label: String::new(),
            redirect_host: String::new(),
            error: Some("Consent request not found or expired.".to_string()),
        });
    };
    if session.session.id != pending.session_id {
        return Ok(HttpResponse::Forbidden().body("session mismatch"));
    }

    let approve = form
        .action
        .as_deref()
        .map(|s| s.eq_ignore_ascii_case("allow"))
        .unwrap_or(false);

    if !approve {
        let sep = if pending.redirect_uri.contains('?') {
            "&"
        } else {
            "?"
        };
        let mut location = format!(
            "{}{sep}error=access_denied&error_description={}",
            pending.redirect_uri,
            urlencoding::encode("user denied consent")
        );
        if let Some(state_param) = pending.state.as_deref().filter(|s| !s.is_empty()) {
            location.push_str("&state=");
            location.push_str(&urlencoding::encode(state_param));
        }
        return Ok(HttpResponse::SeeOther()
            .insert_header((header::LOCATION, location))
            .finish());
    }

    let result = state
        .authorize_flow
        .complete_after_consent(&pending)
        .await
        .map_err(AppError::Other)?;
    if !result.ok {
        return Ok(HttpResponse::BadRequest().content_type("text/plain").body(
            format!(
                "{}: {}",
                result.error.unwrap_or_default(),
                result.error_description.unwrap_or_default()
            ),
        ));
    }
    Ok(HttpResponse::SeeOther()
        .insert_header((header::LOCATION, result.redirect.unwrap()))
        .finish())
}

fn render_page(page: ConsentPage) -> AppResult<HttpResponse> {
    let body = page
        .render()
        .map_err(|e| AppError::Other(anyhow::anyhow!("askama: {e}")))?;
    Ok(HttpResponse::Ok()
        .content_type(header::ContentType::html())
        .body(body))
}

/// Strip query/path so the user only sees scheme://host:port — same shape
/// as Java `redirectHost`.
fn redirect_host(uri: &str) -> String {
    if uri.is_empty() {
        return String::new();
    }
    match Url::parse(uri) {
        Ok(u) => {
            let scheme = u.scheme();
            let host = u.host_str().unwrap_or("");
            if host.is_empty() {
                return uri.to_string();
            }
            match u.port() {
                Some(p) => format!("{scheme}://{host}:{p}"),
                None => format!("{scheme}://{host}"),
            }
        }
        Err(_) => uri.to_string(),
    }
}
