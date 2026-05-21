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
        if !authenticate_client(&client, client_secret) {
            return Ok(IntrospectResult::error(
                "invalid_client",
                "Invalid client credentials",
            ));
        }

        let Some(claims) = self.jwt_validator.validate(token) else {
            // RFC 7662 §2.2: invalid/expired token → 200 with `active=false`.
            return Ok(IntrospectResult::success(json!({ "active": false })));
        };

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

fn authenticate_client(client: &Client, presented_secret: Option<&str>) -> bool {
    if client.client_type.as_deref().unwrap_or("").to_ascii_lowercase() != "confidential" {
        return true;
    }
    let Some(presented) = presented_secret.filter(|s| !s.is_empty()) else {
        return false;
    };
    let Some(stored) = client.client_secret.as_deref() else {
        return false;
    };
    ClientSecretHasher::verify(presented, stored)
}
