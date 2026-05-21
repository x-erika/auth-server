//! Port of `DeviceFlow.java`. RFC 8628 — device authorization grant.

use chrono::{Duration as ChronoDuration, Utc};
use rand::Rng;
use serde_json::json;
use uuid::Uuid;

use crate::client::ClientRepository;
use crate::common::crypto::random_tokens;
use crate::oauth::scopes;
use crate::session::SessionService;

use super::model::{
    DeviceAuthorization, STATUS_APPROVED, STATUS_DENIED, STATUS_PENDING,
};
use super::repository::DeviceAuthorizationRepository;
use super::result::{DeviceAuthorizationResult, DeviceVerifyResult};

const DEVICE_CODE_TTL_SECONDS: i64 = 300;
const POLL_INTERVAL_SECONDS: i64 = 5;
const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ23456789";
const PERSIST_RETRIES: usize = 5;

#[derive(Clone)]
pub struct DeviceFlow {
    clients: ClientRepository,
    session_service: SessionService,
    device_repo: DeviceAuthorizationRepository,
    issuer_url: String,
}

impl DeviceFlow {
    pub fn new(
        clients: ClientRepository,
        session_service: SessionService,
        device_repo: DeviceAuthorizationRepository,
        issuer_url: String,
    ) -> Self {
        Self {
            clients,
            session_service,
            device_repo,
            issuer_url,
        }
    }

    pub async fn request_device_authorization(
        &self,
        client_id: &str,
        scope: Option<&str>,
    ) -> anyhow::Result<DeviceAuthorizationResult> {
        if client_id.trim().is_empty() {
            return Ok(DeviceAuthorizationResult::error(
                "invalid_request",
                "client_id is required",
            ));
        }
        let client = self.clients.find_by_client_id(client_id).await?;
        let Some(client) = client.filter(|c| c.enabled) else {
            return Ok(DeviceAuthorizationResult::error(
                "unauthorized_client",
                "Unknown or disabled client",
            ));
        };
        if !scopes::is_subset_of(scope, client.scopes.as_deref()) {
            return Ok(DeviceAuthorizationResult::error(
                "invalid_scope",
                "Requested scope is not allowed for this client",
            ));
        }

        let now = Utc::now().naive_utc();
        let mut auth = DeviceAuthorization {
            id: Uuid::new_v4(),
            device_code: random_tokens::url_safe(32),
            user_code: String::new(),
            client_id: client.client_id.clone(),
            scope: scope.map(|s| s.to_string()),
            status: STATUS_PENDING.to_string(),
            user_id: None,
            session_id: None,
            expires_at: now + ChronoDuration::seconds(DEVICE_CODE_TTL_SECONDS),
            created_at: Some(now),
        };

        let mut persisted = false;
        for _ in 0..PERSIST_RETRIES {
            auth.user_code = generate_user_code();
            if self.device_repo.persist(&auth).await? {
                persisted = true;
                break;
            }
        }
        if !persisted {
            return Ok(DeviceAuthorizationResult::error(
                "server_error",
                "Could not allocate a unique user_code after retries",
            ));
        }

        Ok(DeviceAuthorizationResult::success(json!({
            "device_code": auth.device_code,
            "user_code": auth.user_code,
            "verification_uri": format!("{}/oauth/device", self.issuer_url),
            "verification_uri_complete": format!(
                "{}/oauth/device?user_code={}", self.issuer_url, auth.user_code
            ),
            "expires_in": DEVICE_CODE_TTL_SECONDS,
            "interval": POLL_INTERVAL_SECONDS,
        })))
    }

    pub async fn verify_user_code(
        &self,
        user_code: &str,
        session_token: Option<&str>,
        approve: bool,
    ) -> anyhow::Result<DeviceVerifyResult> {
        if user_code.trim().is_empty() {
            return Ok(DeviceVerifyResult::error(
                "invalid_request",
                "user_code is required",
            ));
        }
        let session = match session_token {
            Some(t) => self.session_service.find_active_session(t).await?,
            None => None,
        };
        let Some(session) = session else {
            return Ok(DeviceVerifyResult::error("invalid_session", "Login required"));
        };

        let mut auth = match self.device_repo.find_by_user_code(user_code.trim()).await? {
            Some(a) => a,
            None => return Ok(DeviceVerifyResult::error("invalid_user_code", "Unknown user_code")),
        };
        if auth.expires_at < Utc::now().naive_utc() {
            return Ok(DeviceVerifyResult::error("expired_token", "user_code expired"));
        }
        if auth.status != STATUS_PENDING {
            return Ok(DeviceVerifyResult::error("invalid_user_code", "Already resolved"));
        }

        if approve {
            auth.status = STATUS_APPROVED.to_string();
            auth.user_id = Some(session.session.user_id);
            auth.session_id = Some(session.session.id);
        } else {
            auth.status = STATUS_DENIED.to_string();
        }
        self.device_repo.update(&auth).await?;
        Ok(DeviceVerifyResult::success())
    }
}

fn generate_user_code() -> String {
    let mut rng = rand::thread_rng();
    let mut s = String::with_capacity(9);
    for i in 0..8 {
        if i == 4 {
            s.push('-');
        }
        let idx = rng.gen_range(0..USER_CODE_ALPHABET.len());
        s.push(USER_CODE_ALPHABET[idx] as char);
    }
    s
}
