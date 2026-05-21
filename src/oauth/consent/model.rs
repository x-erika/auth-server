use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct UserConsent {
    pub id: Uuid,
    pub user_id: Uuid,
    pub client_id: Uuid,
    pub scopes: String,
    pub granted_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

/// Pending authorization payload kept in Redis while the user is on the
/// consent screen. Field naming mirrors Java exactly so JSON written by
/// either server can be read back by the other.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingAuthorization {
    pub request_id: String,
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub prompt: Option<String>,
    pub max_age: Option<i64>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub claims_requested: Option<String>,
    pub expires_at: NaiveDateTime,
}
