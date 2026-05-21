use serde_json::Value;

#[derive(Debug, Clone)]
pub struct DeviceAuthorizationResult {
    pub ok: bool,
    pub payload: Option<Value>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

impl DeviceAuthorizationResult {
    pub fn success(payload: Value) -> Self {
        Self {
            ok: true,
            payload: Some(payload),
            error: None,
            error_description: None,
        }
    }
    pub fn error(error: &str, description: &str) -> Self {
        Self {
            ok: false,
            payload: None,
            error: Some(error.to_string()),
            error_description: Some(description.to_string()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeviceVerifyResult {
    pub ok: bool,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

impl DeviceVerifyResult {
    pub fn success() -> Self {
        Self {
            ok: true,
            error: None,
            error_description: None,
        }
    }
    pub fn error(error: &str, description: &str) -> Self {
        Self {
            ok: false,
            error: Some(error.to_string()),
            error_description: Some(description.to_string()),
        }
    }
}
