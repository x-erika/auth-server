//! Port of `IntrospectFlow.java` — RFC 7662 token introspection.

use std::sync::Arc;

use serde_json::{Map, Value, json};

use crate::client::{Client, ClientRepository, ClientSecretHasher};
use crate::common::crypto::jwt::JwtValidator;

use super::result::IntrospectResult;

#[derive(Clone)]
pub struct IntrospectFlow {
    clients: ClientRepository,
    jwt_validator: Arc<JwtValidator>,
}

impl IntrospectFlow {
    pub fn new(clients: ClientRepository, jwt_validator: Arc<JwtValidator>) -> Self {
        Self {
            clients,
            jwt_validator,
        }
    }

    pub async fn introspect(
        &self,
        token: &str,
        client_id: &str,
        client_secret: Option<&str>,
    ) -> anyhow::Result<IntrospectResult> {
        if token.is_empty() || client_id.is_empty() {
            return Ok(IntrospectResult::error(
                "invalid_request",
                "token and client_id are required",
            ));
        }
        let Some(client) = self.clients.find_by_client_id(client_id).await? else {
            return Ok(IntrospectResult::error(
                "invalid_client",
                "Unknown or disabled client",
            ));
        };
        if !client.enabled {
            return Ok(IntrospectResult::error(
                "invalid_client",
                "Unknown or disabled client",
            ));
        }
        if !authenticate_client(&client, client_secret).await {
            return Ok(IntrospectResult::error(
                "invalid_client",
                "Invalid client credentials",
            ));
        }

        let Some(claims) = self.jwt_validator.validate(token) else {
            // RFC 7662 §2.2: invalid/expired token → 200 with `active=false`.
            return Ok(IntrospectResult::success(json!({ "active": false })));
        };

        // Bind introspection to the calling client. RFC 7662 lets each
        // resource server introspect "its own" tokens; without this check,
        // Client A could POST Client B's access_token and read every claim
        // — email, roles, sid. Return the spec-correct "active: false"
        // instead of an error so a malicious caller can't distinguish
        // "token doesn't belong to you" from "token doesn't exist".
        if !audience_matches(claims.get("aud"), &client.client_id) {
            return Ok(IntrospectResult::success(json!({ "active": false })));
        }

        let mut payload = Map::new();
        payload.insert("active".to_string(), json!(true));
        if let Value::Object(obj) = claims {
            for (k, v) in obj {
                payload.insert(k, v);
            }
        }
        Ok(IntrospectResult::success(Value::Object(payload)))
    }
}

fn audience_matches(aud: Option<&Value>, expected: &str) -> bool {
    let Some(aud) = aud else { return false };
    if aud.is_null() {
        return false;
    }
    if let Some(s) = aud.as_str() {
        return s == expected;
    }
    if let Some(arr) = aud.as_array() {
        return arr.iter().any(|v| v.as_str() == Some(expected));
    }
    false
}

async fn authenticate_client(client: &Client, presented_secret: Option<&str>) -> bool {
    if client.client_type.as_deref().unwrap_or("").to_ascii_lowercase() != "confidential" {
        return true;
    }
    let Some(presented) = presented_secret.filter(|s| !s.is_empty()) else {
        return false;
    };
    let Some(stored) = client.client_secret.as_deref() else {
        return false;
    };
    ClientSecretHasher::verify_async(presented, stored).await
}
