//! Common error type used by handlers + services. Mirrors how the Quarkus
//! resources throw `WebApplicationException(Response.status(...))` — we
//! convert into HTTP responses via `ResponseError`.

use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use serde_json::json;

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden")]
    Forbidden,

    #[error("not found")]
    NotFound,

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("too many requests")]
    RateLimited { retry_after_seconds: u64 },

    #[error("oauth error: {error}: {description}")]
    OAuth {
        status: StatusCode,
        error: String,
        description: String,
    },

    #[error(transparent)]
    Db(#[from] sqlx::Error),

    #[error(transparent)]
    Redis(#[from] redis::RedisError),

    #[error(transparent)]
    RedisPool(#[from] deadpool_redis::PoolError),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl AppError {
    pub fn oauth(status: StatusCode, error: impl Into<String>, description: impl Into<String>) -> Self {
        Self::OAuth {
            status,
            error: error.into(),
            description: description.into(),
        }
    }
}

impl ResponseError for AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            AppError::Forbidden => StatusCode::FORBIDDEN,
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            AppError::OAuth { status, .. } => *status,
            AppError::Db(_) | AppError::Redis(_) | AppError::RedisPool(_) | AppError::Other(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    fn error_response(&self) -> HttpResponse {
        let status = self.status_code();
        match self {
            AppError::OAuth { error, description, .. } => HttpResponse::build(status).json(json!({
                "error": error,
                "error_description": description,
            })),
            AppError::BadRequest(msg) | AppError::Conflict(msg) => {
                HttpResponse::build(status).json(json!({ "error": msg }))
            }
            AppError::RateLimited { retry_after_seconds } => HttpResponse::build(status)
                .insert_header(("Retry-After", retry_after_seconds.to_string()))
                .json(json!({
                    "error": "rate_limit_exceeded",
                    "retry_after_seconds": retry_after_seconds,
                })),
            _ => HttpResponse::build(status).json(json!({ "error": self.to_string() })),
        }
    }
}

pub type AppResult<T> = Result<T, AppError>;
