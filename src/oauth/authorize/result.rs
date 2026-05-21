//! `AuthorizeResult` — direct port of the Java record.

#[derive(Debug, Clone)]
pub struct AuthorizeResult {
    pub ok: bool,
    /// Where to send the user-agent next. `Some` on success; also `Some` on
    /// post-validation errors per RFC 6749 §4.1.2.1.
    pub redirect: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
    pub consent_request_id: Option<String>,
}

impl AuthorizeResult {
    pub fn success(redirect: String) -> Self {
        Self {
            ok: true,
            redirect: Some(redirect),
            error: None,
            error_description: None,
            consent_request_id: None,
        }
    }

    /// Pre-validation error (unknown client, unregistered redirect_uri).
    /// `redirect` is `None` because we don't trust the user-supplied URI
    /// yet — caller serves a JSON 400.
    pub fn error(error: &str, description: &str) -> Self {
        Self {
            ok: false,
            redirect: None,
            error: Some(error.to_string()),
            error_description: Some(description.to_string()),
            consent_request_id: None,
        }
    }

    /// Post-validation error — redirect URI is registered + safe, so RFC
    /// says to bounce back with `?error=...&error_description=...&state=...`.
    pub fn error_redirect(redirect: String, error: &str, description: &str) -> Self {
        Self {
            ok: false,
            redirect: Some(redirect),
            error: Some(error.to_string()),
            error_description: Some(description.to_string()),
            consent_request_id: None,
        }
    }

    pub fn consent_required(request_id: String) -> Self {
        Self {
            ok: false,
            redirect: None,
            error: Some("consent_required".to_string()),
            error_description: Some("User consent is required".to_string()),
            consent_request_id: Some(request_id),
        }
    }
}
