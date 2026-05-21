//! `Client`, `RedirectUri`, and their `*Snapshot` counterparts used as the
//! Redis cache codec. The snapshot/entity split mirrors the Java code so the
//! JSON written by either server is bidirectionally readable.

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Client {
    pub id: Uuid,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub name: Option<String>,
    /// `confidential` or `public` (enforced by the DB CHECK constraint).
    #[sqlx(rename = "type")]
    #[serde(rename = "type")]
    pub client_type: Option<String>,
    pub grant_types: Option<String>,
    pub response_types: Option<String>,
    pub scopes: Option<String>,
    pub pkce_required: bool,
    pub enabled: bool,
    pub base_url: Option<String>,
    pub description: Option<String>,
    pub access_token_ttl: Option<i32>,
    pub refresh_token_ttl: Option<i32>,
    pub frontchannel_logout_uri: Option<String>,
    pub backchannel_logout_uri: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,

    /// Loaded eagerly by the repository (LEFT JOIN FETCH equivalent). Empty
    /// vec when no rows joined.
    #[sqlx(skip)]
    #[serde(default)]
    pub redirect_uris: Vec<RedirectUri>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct RedirectUri {
    pub id: Uuid,
    pub client_id: Uuid,
    pub uri: String,
    pub created_at: NaiveDateTime,
}

/// Serializable shape of a `Client` for Redis caching. In Rust the entity
/// already serializes cleanly (no Hibernate proxies, no lazy collections),
/// so `ClientSnapshot` is structurally identical to `Client` — it exists
/// for naming parity with `ClientSnapshot.java` and to advertise intent at
/// the call site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientSnapshot {
    pub id: Uuid,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub client_type: Option<String>,
    pub grant_types: Option<String>,
    pub response_types: Option<String>,
    pub scopes: Option<String>,
    pub pkce_required: bool,
    pub enabled: bool,
    pub base_url: Option<String>,
    pub description: Option<String>,
    pub access_token_ttl: Option<i32>,
    pub refresh_token_ttl: Option<i32>,
    pub frontchannel_logout_uri: Option<String>,
    pub backchannel_logout_uri: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    #[serde(default)]
    pub redirect_uris: Vec<RedirectUriSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectUriSnapshot {
    pub id: Uuid,
    pub uri: String,
    pub created_at: NaiveDateTime,
}

impl ClientSnapshot {
    pub fn from_entity(c: &Client) -> Self {
        Self {
            id: c.id,
            client_id: c.client_id.clone(),
            client_secret: c.client_secret.clone(),
            name: c.name.clone(),
            client_type: c.client_type.clone(),
            grant_types: c.grant_types.clone(),
            response_types: c.response_types.clone(),
            scopes: c.scopes.clone(),
            pkce_required: c.pkce_required,
            enabled: c.enabled,
            base_url: c.base_url.clone(),
            description: c.description.clone(),
            access_token_ttl: c.access_token_ttl,
            refresh_token_ttl: c.refresh_token_ttl,
            frontchannel_logout_uri: c.frontchannel_logout_uri.clone(),
            backchannel_logout_uri: c.backchannel_logout_uri.clone(),
            created_at: c.created_at,
            updated_at: c.updated_at,
            redirect_uris: c
                .redirect_uris
                .iter()
                .map(|r| RedirectUriSnapshot {
                    id: r.id,
                    uri: r.uri.clone(),
                    created_at: r.created_at,
                })
                .collect(),
        }
    }

    pub fn into_entity(self) -> Client {
        let parent_id = self.id;
        Client {
            id: self.id,
            client_id: self.client_id,
            client_secret: self.client_secret,
            name: self.name,
            client_type: self.client_type,
            grant_types: self.grant_types,
            response_types: self.response_types,
            scopes: self.scopes,
            pkce_required: self.pkce_required,
            enabled: self.enabled,
            base_url: self.base_url,
            description: self.description,
            access_token_ttl: self.access_token_ttl,
            refresh_token_ttl: self.refresh_token_ttl,
            frontchannel_logout_uri: self.frontchannel_logout_uri,
            backchannel_logout_uri: self.backchannel_logout_uri,
            created_at: self.created_at,
            updated_at: self.updated_at,
            redirect_uris: self
                .redirect_uris
                .into_iter()
                .map(|r| RedirectUri {
                    id: r.id,
                    client_id: parent_id,
                    uri: r.uri,
                    created_at: r.created_at,
                })
                .collect(),
        }
    }
}
