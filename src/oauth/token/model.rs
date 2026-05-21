use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct RefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub client_id: Uuid,
    pub session_id: Uuid,
    pub token_hash: String,
    pub expires_at: Option<NaiveDateTime>,
    pub revoked: bool,
    pub created_at: NaiveDateTime,
}
