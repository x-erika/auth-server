use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct SignupRequest {
    pub email: Option<String>,
    pub password: Option<String>,
    pub username: Option<String>,
    #[serde(rename = "firstName")]
    pub first_name: Option<String>,
    #[serde(rename = "lastName")]
    pub last_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SignupSuccess {
    pub message: &'static str,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "verificationToken")]
    pub verification_token: String,
}

#[derive(Debug)]
pub enum SignupError {
    InvalidRequest(&'static str),
    Conflict(&'static str),
}

#[derive(Debug)]
pub enum VerifyEmailError {
    InvalidRequest(&'static str),
    InvalidToken(&'static str),
}
