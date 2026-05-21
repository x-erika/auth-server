//! Port of `AuthorizeFlow.java`.
//!
//! Phase 6 note: consent (`ConsentService` + `PendingAuthorizationStore`)
//! lands in Phase 7. For now `has_consent` is force-`true` so the
//! authorize → token round-trip works end-to-end. Phase 7 will replace
//! this with the real Postgres-backed consent check.

use std::collections::HashSet;

use chrono::{Duration as ChronoDuration, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::client::ClientRepository;
use crate::common::crypto::random_tokens;
use crate::oauth::pkce;
use crate::oauth::scopes;
use crate::session::SessionService;

use super::code::{AuthCodeStore, AuthorizationCode};
use super::request_object::RequestObjectParser;
use super::result::AuthorizeResult;

const AUTH_CODE_TTL_MINUTES: i64 = 3;
const AUTH_CODE_BYTES: usize = 48;
/// After re-auth via /login, treat `prompt=login` as already-satisfied for
/// this long. Without the grace, every redirect-back from `/login` would
/// re-trigger the prompt and loop.
const REAUTH_GRACE_SECONDS: i64 = 30;

#[derive(Clone)]
pub struct AuthorizeFlow {
    clients: ClientRepository,
    session_service: SessionService,
    auth_codes: AuthCodeStore,
}

#[allow(clippy::too_many_arguments)]
pub struct AuthorizeRequest<'a> {
    pub session_token: Option<&'a str>,
    pub client_id: Option<&'a str>,
    pub redirect_uri: Option<&'a str>,
    pub response_type: Option<&'a str>,
    pub scope: Option<&'a str>,
    pub state: Option<&'a str>,
    pub nonce: Option<&'a str>,
    pub prompt: Option<&'a str>,
    pub max_age: Option<i64>,
    pub code_challenge: Option<&'a str>,
    pub code_challenge_method: Option<&'a str>,
    pub request_jwt: Option<&'a str>,
    pub claims_json: Option<&'a str>,
}

impl AuthorizeFlow {
    pub fn new(
        clients: ClientRepository,
        session_service: SessionService,
        auth_codes: AuthCodeStore,
    ) -> Self {
        Self {
            clients,
            session_service,
            auth_codes,
        }
    }

    pub async fn authorize(&self, req: AuthorizeRequest<'_>) -> anyhow::Result<AuthorizeResult> {
        if req.response_type != Some("code") {
            return Ok(AuthorizeResult::error(
                "unsupported_response_type",
                "Only response_type=code is supported",
            ));
        }

        let client_id_str = req.client_id.unwrap_or("").trim().to_string();
        let mut redirect_uri = req.redirect_uri.unwrap_or("").to_string();
        if client_id_str.is_empty() || redirect_uri.is_empty() {
            return Ok(AuthorizeResult::error(
                "invalid_request",
                "client_id and redirect_uri are required",
            ));
        }

        let prompts = parse_prompt(req.prompt);
        let prompt_none = prompts.contains("none");
        let prompt_login = prompts.contains("login");
        let _prompt_consent = prompts.contains("consent"); // honoured once consent lands

        let session = match req.session_token {
            Some(t) => self.session_service.find_active_session(t).await?,
            None => None,
        };

        // prompt=login re-prompt with grace window.
        let now = Utc::now().naive_utc();
        let recently_authenticated = session.as_ref().is_some_and(|s| {
            (now - s.session.created_at).num_seconds() < REAUTH_GRACE_SECONDS
        });
        if session.is_none() || (prompt_login && !recently_authenticated) {
            return Ok(AuthorizeResult::error(
                if prompt_none { "login_required" } else { "invalid_session" },
                if prompt_login {
                    "prompt=login requires re-authentication"
                } else {
                    "Login required"
                },
            ));
        }
        let session = session.unwrap();

        // max_age — terminate the session if too old.
        if let Some(max_age) = req.max_age {
            let age = (now - session.session.created_at).num_seconds();
            if age > max_age {
                return Ok(AuthorizeResult::error(
                    if prompt_none { "login_required" } else { "invalid_session" },
                    &format!("Session age {age}s exceeds max_age {max_age}s"),
                ));
            }
        }

        let client = self.clients.find_by_client_id(&client_id_str).await?;
        let Some(client) = client.filter(|c| c.enabled) else {
            return Ok(AuthorizeResult::error(
                "unauthorized_client",
                "Unknown or disabled client",
            ));
        };

        let mut scope = req.scope.map(|s| s.to_string());
        let mut state = req.state.map(|s| s.to_string());
        let mut nonce = req.nonce.map(|s| s.to_string());
        let mut code_challenge = req.code_challenge.map(|s| s.to_string());
        let mut code_challenge_method = req.code_challenge_method.map(|s| s.to_string());
        let mut claims_json = req.claims_json.map(|s| s.to_string());

        // Request object override (HS256 JWS signed by client_secret).
        if let Some(jwt) = req.request_jwt.filter(|s| !s.trim().is_empty()) {
            match RequestObjectParser::parse(jwt, &client) {
                Some(payload) => {
                    if let Some(v) = payload.get("redirect_uri").and_then(|n| n.as_str()) {
                        if !v.is_empty() {
                            redirect_uri = v.to_string();
                        }
                    }
                    override_opt(&mut scope, &payload, "scope");
                    override_opt(&mut state, &payload, "state");
                    override_opt(&mut nonce, &payload, "nonce");
                    override_opt(&mut code_challenge, &payload, "code_challenge");
                    override_opt(&mut code_challenge_method, &payload, "code_challenge_method");
                    if let Some(c) = payload.get("claims") {
                        if !c.is_null() {
                            claims_json = Some(c.to_string());
                        }
                    }
                }
                None => {
                    return Ok(AuthorizeResult::error(
                        "invalid_request_object",
                        "Could not validate request JWT",
                    ));
                }
            }
        }

        // From here on, redirect_uri is checked against registered set.
        if !self
            .clients
            .is_redirect_uri_allowed(client.id, &redirect_uri)
            .await?
        {
            return Ok(AuthorizeResult::error(
                "invalid_request",
                "redirect_uri is not registered",
            ));
        }

        // Scope check — post-validation, so use error_redirect.
        if !scopes::is_subset_of(scope.as_deref(), client.scopes.as_deref()) {
            return Ok(error_redirect(
                &redirect_uri,
                state.as_deref(),
                "invalid_scope",
                "Requested scope is not allowed for this client",
            ));
        }

        // PKCE method validation (whenever a challenge is present).
        let mut resolved_method: Option<String> = None;
        let has_challenge = code_challenge.as_deref().is_some_and(|c| !c.is_empty());
        if has_challenge {
            let method = code_challenge_method
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or("plain")
                .to_string();
            if !pkce::is_method_supported(Some(&method)) {
                return Ok(error_redirect(
                    &redirect_uri,
                    state.as_deref(),
                    "invalid_request",
                    "Unsupported code_challenge_method",
                ));
            }
            resolved_method = Some(method);
        } else if client.pkce_required {
            return Ok(error_redirect(
                &redirect_uri,
                state.as_deref(),
                "invalid_request",
                "code_challenge is required",
            ));
        }

        // TODO(phase-7): real consent check via ConsentService +
        // PendingAuthorizationStore. For now we auto-grant so the e2e
        // authorize → token flow works.
        let has_consent = true;
        if !has_consent {
            // Place-holder: phase 7 will return consent_required + redirect
            // to /consent?req=<id>.
            return Ok(AuthorizeResult::consent_required(
                random_tokens::url_safe(24),
            ));
        }

        Ok(self
            .issue_code(
                session.session.id,
                session.session.user_id,
                &client.client_id,
                &redirect_uri,
                scope.as_deref(),
                state.as_deref(),
                nonce.as_deref(),
                code_challenge.as_deref(),
                resolved_method.as_deref(),
                claims_json.as_deref(),
            )
            .await?)
    }

    #[allow(clippy::too_many_arguments)]
    async fn issue_code(
        &self,
        session_id: Uuid,
        user_id: Uuid,
        client_id: &str,
        redirect_uri: &str,
        scope: Option<&str>,
        state: Option<&str>,
        nonce: Option<&str>,
        code_challenge: Option<&str>,
        code_challenge_method: Option<&str>,
        claims_requested: Option<&str>,
    ) -> anyhow::Result<AuthorizeResult> {
        self.auth_codes.cleanup_expired();
        let code = random_tokens::url_safe(AUTH_CODE_BYTES);
        let expires_at = Utc::now().naive_utc() + ChronoDuration::minutes(AUTH_CODE_TTL_MINUTES);
        let stored = AuthorizationCode {
            code: code.clone(),
            client_id: client_id.to_string(),
            user_id,
            session_id,
            redirect_uri: redirect_uri.to_string(),
            scope: scope.map(String::from),
            state: state.map(String::from),
            nonce: nonce.map(String::from),
            code_challenge: code_challenge.map(String::from),
            code_challenge_method: code_challenge_method.map(String::from),
            claims_requested: claims_requested.map(String::from),
            expires_at,
            created_at: None,
        };
        self.auth_codes.put(stored).await?;

        let mut params: Vec<(&str, String)> = Vec::with_capacity(2);
        params.push(("code", code));
        params.push(("state", state.unwrap_or("").to_string()));
        Ok(AuthorizeResult::success(build_redirect(redirect_uri, &params)))
    }
}

fn parse_prompt(raw: Option<&str>) -> HashSet<String> {
    let Some(s) = raw else { return HashSet::new() };
    s.split_whitespace().map(|s| s.to_string()).collect()
}

fn error_redirect(redirect_uri: &str, state: Option<&str>, error: &str, desc: &str) -> AuthorizeResult {
    let mut params: Vec<(&str, String)> = Vec::with_capacity(3);
    params.push(("error", error.to_string()));
    if !desc.is_empty() {
        params.push(("error_description", desc.to_string()));
    }
    if let Some(s) = state {
        if !s.is_empty() {
            params.push(("state", s.to_string()));
        }
    }
    AuthorizeResult::error_redirect(build_redirect(redirect_uri, &params), error, desc)
}

fn build_redirect(base_uri: &str, params: &[(&str, String)]) -> String {
    let mut out = String::from(base_uri);
    out.push(if base_uri.contains('?') { '&' } else { '?' });
    let mut first = true;
    for (k, v) in params {
        if !first {
            out.push('&');
        }
        first = false;
        out.push_str(&urlencoding::encode(k));
        out.push('=');
        out.push_str(&urlencoding::encode(v));
    }
    out
}

fn override_opt(target: &mut Option<String>, payload: &Value, field: &str) {
    if let Some(v) = payload.get(field).and_then(|n| n.as_str()) {
        if !v.is_empty() {
            *target = Some(v.to_string());
        }
    }
}
