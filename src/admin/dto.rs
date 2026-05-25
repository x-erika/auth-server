//! Direct port of `com.xerika.auth.admin.dto.*`.

use serde::{Deserialize, Serialize};

use crate::client::{Client, RedirectUri};
use crate::oauth::consent::UserConsent;
use crate::role::Role;
use crate::session::UserSession;
use crate::user::User;

// ---- Requests ----

#[derive(Debug, Deserialize)]
pub struct ClientRequest {
    #[serde(rename = "clientId")]
    pub client_id: Option<String>,
    #[serde(rename = "clientSecret")]
    pub client_secret: Option<String>,
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub client_type: Option<String>,
    pub scopes: Option<String>,
    #[serde(rename = "grantTypes")]
    pub grant_types: Option<String>,
    #[serde(rename = "responseTypes")]
    pub response_types: Option<String>,
    #[serde(rename = "pkceRequired")]
    pub pkce_required: Option<bool>,
    pub enabled: Option<bool>,
    #[serde(rename = "baseUrl")]
    pub base_url: Option<String>,
    pub description: Option<String>,
    #[serde(rename = "frontchannelLogoutUri")]
    pub frontchannel_logout_uri: Option<String>,
    #[serde(rename = "backchannelLogoutUri")]
    pub backchannel_logout_uri: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UserCreateRequest {
    pub email: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    #[serde(rename = "firstName")]
    pub first_name: Option<String>,
    #[serde(rename = "lastName")]
    pub last_name: Option<String>,
    pub enabled: Option<bool>,
    #[serde(rename = "emailVerified")]
    pub email_verified: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct UserUpdateRequest {
    #[serde(rename = "firstName")]
    pub first_name: Option<String>,
    #[serde(rename = "lastName")]
    pub last_name: Option<String>,
    pub enabled: Option<bool>,
    #[serde(rename = "emailVerified")]
    pub email_verified: Option<bool>,
    #[serde(rename = "newPassword")]
    pub new_password: Option<String>,
}

// ---- Responses ----

#[derive(Debug, Serialize)]
pub struct RoleSummary {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    #[serde(rename = "parentId")]
    pub parent_id: Option<String>,
}

impl RoleSummary {
    pub fn from_role(r: &Role) -> Self {
        Self {
            id: r.id.to_string(),
            name: r.name.clone(),
            description: r.description.clone(),
            parent_id: r.parent_id.map(|p| p.to_string()),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct UserSummary {
    pub id: String,
    pub email: String,
    pub username: String,
    pub enabled: bool,
    #[serde(rename = "emailVerified")]
    pub email_verified: bool,
    pub roles: Vec<String>,
}

impl UserSummary {
    pub fn from(user: &User, roles: Vec<String>) -> Self {
        Self {
            id: user.id.to_string(),
            email: user.email.clone(),
            username: user.username.clone(),
            enabled: user.enabled,
            email_verified: user.email_verified,
            roles,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ClientSummary {
    pub id: String,
    #[serde(rename = "clientId")]
    pub client_id: String,
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub client_type: Option<String>,
    pub scopes: Option<String>,
    #[serde(rename = "grantTypes")]
    pub grant_types: Option<String>,
    #[serde(rename = "responseTypes")]
    pub response_types: Option<String>,
    #[serde(rename = "pkceRequired")]
    pub pkce_required: bool,
    pub enabled: bool,
    #[serde(rename = "baseUrl")]
    pub base_url: Option<String>,
    pub description: Option<String>,
    #[serde(rename = "frontchannelLogoutUri")]
    pub frontchannel_logout_uri: Option<String>,
    #[serde(rename = "backchannelLogoutUri")]
    pub backchannel_logout_uri: Option<String>,
    #[serde(rename = "redirectUris")]
    pub redirect_uris: Vec<RedirectUriSummary>,
}

#[derive(Debug, Serialize)]
pub struct RedirectUriSummary {
    pub id: String,
    pub uri: String,
}

impl ClientSummary {
    pub fn from_client(client: &Client) -> Self {
        Self {
            id: client.id.to_string(),
            client_id: client.client_id.clone(),
            name: client.name.clone(),
            client_type: client.client_type.clone(),
            scopes: client.scopes.clone(),
            grant_types: client.grant_types.clone(),
            response_types: client.response_types.clone(),
            pkce_required: client.pkce_required,
            enabled: client.enabled,
            base_url: client.base_url.clone(),
            description: client.description.clone(),
            frontchannel_logout_uri: client.frontchannel_logout_uri.clone(),
            backchannel_logout_uri: client.backchannel_logout_uri.clone(),
            redirect_uris: client
                .redirect_uris
                .iter()
                .map(|r| RedirectUriSummary::from_uri(r))
                .collect(),
        }
    }
}

impl RedirectUriSummary {
    pub fn from_uri(r: &RedirectUri) -> Self {
        Self {
            id: r.id.to_string(),
            uri: r.uri.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SessionSummary {
    pub id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    pub username: Option<String>,
    pub email: Option<String>,
    #[serde(rename = "ipAddress")]
    pub ip_address: Option<String>,
    #[serde(rename = "userAgent")]
    pub user_agent: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: Option<String>,
    #[serde(rename = "lastAccessedAt")]
    pub last_accessed_at: Option<String>,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<String>,
}

impl SessionSummary {
    /// Java `SessionSummary.from(UserSession)` joins user fields too — we
    /// don't have an eager-loaded user here, so the caller passes whatever
    /// it has. `from_session_only` matches the no-user case (returns
    /// `null`s for username/email — same shape Java emits when `s.user`
    /// is null).
    #[allow(dead_code)]
    pub fn from_session_only(s: &UserSession) -> Self {
        Self {
            id: s.id.to_string(),
            user_id: s.user_id.to_string(),
            username: None,
            email: None,
            ip_address: s.ip_address.clone(),
            user_agent: s.user_agent.clone(),
            created_at: Some(s.created_at.to_string()),
            last_accessed_at: s.last_accessed_at.map(|t| t.to_string()),
            expires_at: s.expires_at.map(|t| t.to_string()),
        }
    }

    /// Variant that carries the joined username/email so the admin FE can
    /// label sessions. Matches Java's eager-loaded `SessionSummary.from()`.
    pub fn from_session_with_user(
        s: &UserSession,
        username: Option<String>,
        email: Option<String>,
    ) -> Self {
        Self {
            id: s.id.to_string(),
            user_id: s.user_id.to_string(),
            username,
            email,
            ip_address: s.ip_address.clone(),
            user_agent: s.user_agent.clone(),
            created_at: Some(s.created_at.to_string()),
            last_accessed_at: s.last_accessed_at.map(|t| t.to_string()),
            expires_at: s.expires_at.map(|t| t.to_string()),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ConsentSummary {
    pub id: String,
    #[serde(rename = "clientUuid")]
    pub client_uuid: String,
    #[serde(rename = "clientId")]
    pub client_id: Option<String>,
    #[serde(rename = "clientName")]
    pub client_name: Option<String>,
    pub scopes: String,
    #[serde(rename = "grantedAt")]
    pub granted_at: Option<String>,
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<String>,
}

impl ConsentSummary {
    pub fn from(consent: &UserConsent, client: Option<&Client>) -> Self {
        Self {
            id: consent.id.to_string(),
            client_uuid: consent.client_id.to_string(),
            client_id: client.map(|c| c.client_id.clone()),
            client_name: client.and_then(|c| c.name.clone()),
            scopes: consent.scopes.clone(),
            granted_at: Some(consent.granted_at.to_string()),
            updated_at: Some(consent.updated_at.to_string()),
        }
    }
}
