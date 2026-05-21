//! Port of `BackchannelLogoutNotifier.java`. Fire-and-forget POST of a
//! signed `logout_token` JWT to the client's registered backchannel URI.
//! Errors are logged, never bubbled — the user-facing logout must succeed
//! even if downstream clients are offline.

use std::sync::Arc;
use std::time::Duration;

use once_cell::sync::Lazy;
use reqwest::Client as HttpClient;
use uuid::Uuid;

use crate::client::Client;
use crate::common::crypto::jwt::JwtSigner;

static HTTP_CLIENT: Lazy<HttpClient> = Lazy::new(|| {
    HttpClient::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
        .expect("build backchannel HTTP client")
});

#[derive(Clone)]
pub struct BackchannelLogoutNotifier {
    jwt_signer: Arc<JwtSigner>,
}

impl BackchannelLogoutNotifier {
    pub fn new(jwt_signer: Arc<JwtSigner>) -> Self {
        Self { jwt_signer }
    }

    /// Spawn a tokio task to deliver the logout token. Returns immediately;
    /// success/failure is observable only via tracing.
    pub fn notify_client(&self, client: &Client, user_id: Option<Uuid>, session_id: Uuid) {
        let Some(uri) = client
            .backchannel_logout_uri
            .as_deref()
            .filter(|s| !s.is_empty())
        else {
            return;
        };
        let uri = uri.to_string();
        let client_id = client.client_id.clone();
        let signer = self.jwt_signer.clone();
        tokio::spawn(async move {
            let token = match signer.sign_logout_token(
                user_id.map(|u| u.to_string()).as_deref(),
                &client_id,
                &session_id.to_string(),
            ) {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!(error = %e, %client_id, "logout_token sign failed");
                    return;
                }
            };
            let resp = HTTP_CLIENT
                .post(&uri)
                .form(&[("logout_token", token)])
                .send()
                .await;
            match resp {
                Ok(r) if r.status().is_success() => {
                    tracing::info!(
                        target = %uri,
                        %client_id,
                        sid = %session_id,
                        "backchannel logout delivered"
                    );
                }
                Ok(r) => {
                    tracing::warn!(
                        target = %uri,
                        status = r.status().as_u16(),
                        "backchannel logout returned non-2xx"
                    );
                }
                Err(e) => {
                    tracing::warn!(target = %uri, error = %e, "backchannel logout failed");
                }
            }
        });
    }
}
