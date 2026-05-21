use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const STATUS_PENDING: &str = "pending";
pub const STATUS_APPROVED: &str = "approved";
pub const STATUS_DENIED: &str = "denied";
pub const STATUS_CONSUMED: &str = "consumed";

/// Status enum is kept as a plain string for byte-parity with Java's
/// hash field encoding (`status: "pending"`).
pub type DeviceStatus = String;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthorization {
    pub id: Uuid,
    pub device_code: String,
    pub user_code: String,
    pub client_id: String,
    pub scope: Option<String>,
    pub status: DeviceStatus,
    pub user_id: Option<Uuid>,
    pub session_id: Option<Uuid>,
    pub expires_at: NaiveDateTime,
    pub created_at: Option<NaiveDateTime>,
}
