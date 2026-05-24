//! Port of `AuthorizeFlow.java`.

use std::collections::HashSet;

use chrono::{Duration as ChronoDuration, Utc};
use uuid::Uuid;

use crate::client::ClientRepository;
use crate::common::crypto::random_tokens;
use crate::oauth::consent::{
    ConsentService, PendingAuthorization, PendingAuthorizationStore,
};
use crate::oauth::pkce;
use crate::oauth::scopes;
use crate::session::SessionService;

use super::code::{AuthCodeStore, AuthorizationCode};
use super::result::AuthorizeResult;

const AUTH_CODE_TTL_MINUTES: i64 = 3;
const AUTH_CODE_BYTES: usize = 48;
const CONSENT_REQUEST_TTL_MINUTES: i64 = 10;
/// After re-auth via /login, treat `prompt=login` as already-satisfied for
/// this long. Without the grace, every redirect-back from `/login` would
/// re-trigger the prompt and loop. Kept short (~10s) so a phishing flow
/// that tricks a user into a fresh login can't piggyback on the grace
/// window beyond the natural redirect round-trip.
const REAUTH_GRACE_SECONDS: i64 = 10;

#[derive(Clone)]
pub struct AuthorizeFlow {
    clients: ClientRepository,
    session_service: SessionService,
    auth_codes: AuthCodeStore,
    consent_service: ConsentService,
    pending_store: PendingAuthorizationStore,
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
    pub claims_json: Option<&'a str>,
}

impl AuthorizeFlow {
    pub fn new(
        clients: ClientRepository,
        session_service: SessionService,
        auth_codes: AuthCodeStore,
        consent_service: ConsentService,
        pending_store: PendingAuthorizationStore,
    ) -> Self {
        Self {
            clients,
            session_service,
            auth_codes,
            consent_service,
            pending_store,
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
        let redirect_uri = req.redirect_uri.unwrap_or("").to_string();
        if client_id_str.is_empty() || redirect_uri.is_empty() {
            return Ok(AuthorizeResult::error(
                "invalid_request",
                "client_id and redirect_uri are required",
            ));
        }

        let prompts = parse_prompt(req.prompt);
        let prompt_none = prompts.contains("none");
        let prompt_login = prompts.contains("login");
        let prompt_consent = prompts.contains("consent");

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

        let scope = req.scope.map(|s| s.to_string());
        let state = req.state.map(|s| s.to_string());
        let nonce = req.nonce.map(|s| s.to_string());
        let code_challenge = req.code_challenge.map(|s| s.to_string());
        let code_challenge_method = req.code_challenge_method.map(|s| s.to_string());
        let claims_json = req.claims_json.map(|s| s.to_string());

        // JAR (Request Object, RFC 9101) support removed: the previous HS256
        // implementation required client.client_secret as the HMAC key,
        // which is now Argon2-hashed at rest — verification could never
        // succeed for anything but legacy plaintext rows. A correct JAR
        // implementation needs either a separate raw-secret column or
        // RS256 against the client's registered JWKS; we ship neither.

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

        // PKCE method validation (whenever a challenge is present). With
        // `plain` removed (OAuth 2.0 Security BCP §2.1.1.1), a missing
        // `code_challenge_method` is no longer "default to plain" — it's
        // an outright invalid_request.
        let mut resolved_method: Option<String> = None;
        let has_challenge = code_challenge.as_deref().is_some_and(|c| !c.is_empty());
        if has_challenge {
            let Some(method) = code_challenge_method
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
            else {
                return Ok(error_redirect(
                    &redirect_uri,
                    state.as_deref(),
                    "invalid_request",
                    "code_challenge_method is required (only S256 supported)",
                ));
            };
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

        let has_consent = !prompt_consent
            && self
                .consent_service
                .has_consent(session.session.user_id, client.id, scope.as_deref())
                .await?;
        if !has_consent {
            if prompt_none {
                return Ok(error_redirect(
                    &redirect_uri,
                    state.as_deref(),
                    "consent_required",
                    "Consent is required but prompt=none was specified",
                ));
            }
            let request_id = random_tokens::url_safe(24);
            let pending = PendingAuthorization {
                request_id: request_id.clone(),
                session_id: session.session.id,
                user_id: session.session.user_id,
                client_id: client.client_id.clone(),
                redirect_uri: redirect_uri.clone(),
                response_type: "code".to_string(),
                scope: scope.clone(),
                state: state.clone(),
                nonce: nonce.clone(),
                prompt: req.prompt.map(|s| s.to_string()),
                max_age: req.max_age,
                code_challenge: code_challenge.clone(),
                code_challenge_method: resolved_method.clone(),
                claims_requested: claims_json.clone(),
                expires_at: Utc::now().naive_utc()
                    + ChronoDuration::minutes(CONSENT_REQUEST_TTL_MINUTES),
            };
            self.pending_store.put(&pending).await?;
            return Ok(AuthorizeResult::consent_required(request_id));
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

    /// Called from `POST /consent allow`. Re-validates the client + redirect
    /// (in case admin disabled the client while the user was on the consent
    /// screen), persists the grant, then mints the code.
    pub async fn complete_after_consent(
        &self,
        pending: &PendingAuthorization,
    ) -> anyhow::Result<AuthorizeResult> {
        let Some(client) = self.clients.find_by_client_id(&pending.client_id).await? else {
            return Ok(AuthorizeResult::error(
                "unauthorized_client",
                "Unknown or disabled client",
            ));
        };
        if !client.enabled {
            return Ok(AuthorizeResult::error(
                "unauthorized_client",
                "Unknown or disabled client",
            ));
        }
        if !self
            .clients
            .is_redirect_uri_allowed(client.id, &pending.redirect_uri)
            .await?
        {
            return Ok(AuthorizeResult::error(
                "invalid_request",
                "redirect_uri is not registered",
            ));
        }
        self.consent_service
            .grant(pending.user_id, client.id, pending.scope.as_deref())
            .await?;
        self.issue_code(
            pending.session_id,
            pending.user_id,
            &client.client_id,
            &pending.redirect_uri,
            pending.scope.as_deref(),
            pending.state.as_deref(),
            pending.nonce.as_deref(),
            pending.code_challenge.as_deref(),
            pending.code_challenge_method.as_deref(),
            pending.claims_requested.as_deref(),
        )
        .await
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
        // Expired authorization codes are reaped by Redis TTL automatically.
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

