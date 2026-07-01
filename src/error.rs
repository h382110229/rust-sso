#![allow(dead_code)]
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

/// All error variants that can occur within the application.
#[derive(Debug, Error)]
pub enum AppError {
    // ── Database ──────────────────────────────────────────────────────────────
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Database migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    // ── Authentication & Authorization ────────────────────────────────────────
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Token has expired")]
    TokenExpired,

    #[error("Token is invalid: {0}")]
    TokenInvalid(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    // ── JWT ───────────────────────────────────────────────────────────────────
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    // ── Password hashing ──────────────────────────────────────────────────────
    #[error("Password hashing error: {0}")]
    Bcrypt(#[from] bcrypt::BcryptError),

    // ── Request validation ────────────────────────────────────────────────────
    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    // ── Generic ───────────────────────────────────────────────────────────────
    #[error("Internal server error: {0}")]
    Internal(String),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

/// Wire format returned to callers on errors.
#[derive(Serialize)]
struct ErrorBody {
    /// Machine-readable error code (snake_case)
    code: &'static str,
    /// Human-readable description
    message: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        use AppError::*;

        let (status, code) = match &self {
            // 400
            Validation(_) => (StatusCode::BAD_REQUEST, "validation_error"),
            // 401
            InvalidCredentials | TokenExpired | Unauthorized(_) => {
                (StatusCode::UNAUTHORIZED, "unauthorized")
            }
            TokenInvalid(_) => (StatusCode::UNAUTHORIZED, "token_invalid"),
            // 403
            Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
            // 404
            NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
            // 409
            Conflict(_) => (StatusCode::CONFLICT, "conflict"),
            // 500
            Database(_)
            | Migration(_)
            | Bcrypt(_)
            | Internal(_)
            | Anyhow(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
            // JWT errors: distinguish client vs server faults
            Jwt(e) => {
                use jsonwebtoken::errors::ErrorKind;
                match e.kind() {
                    ErrorKind::ExpiredSignature => {
                        (StatusCode::UNAUTHORIZED, "token_expired")
                    }
                    ErrorKind::InvalidToken
                    | ErrorKind::InvalidSignature
                    | ErrorKind::InvalidAlgorithm
                    | ErrorKind::InvalidAudience
                    | ErrorKind::InvalidIssuer
                    | ErrorKind::InvalidSubject => {
                        (StatusCode::UNAUTHORIZED, "token_invalid")
                    }
                    _ => (StatusCode::INTERNAL_SERVER_ERROR, "jwt_error"),
                }
            }
        };

        // Log server-side faults at ERROR level; client errors at DEBUG
        if status.is_server_error() {
            tracing::error!(error = %self, "Internal application error");
        } else {
            tracing::debug!(error = %self, status = %status, "Client error");
        }

        let body = ErrorBody {
            code,
            message: self.to_string(),
        };

        (status, Json(body)).into_response()
    }
}

/// Convenience alias so handlers can write `Result<T>` instead of
/// `Result<T, AppError>`.
pub type Result<T, E = AppError> = std::result::Result<T, E>;
