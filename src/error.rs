// =========================================================
// error.rs — EasyWAF
// Unified application error type, convertible to Axum responses.
// =========================================================

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

// ─── AppError ────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Database error: {0}")]
    Db(#[from] sqlx::Error),

    #[error("Template error: {0}")]
    Template(#[from] tera::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// General internal error — not yet wired to any route, kept for future use.
    #[allow(dead_code)]
    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Not found: {0}")]
    NotFound(String),

    /// Used by future auth middleware; not yet constructed in any route.
    #[allow(dead_code)]
    #[error("Unauthorized")]
    Unauthorized,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, msg) = match &self {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::NotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            _ => {
                tracing::error!("Internal error: {}", self);
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
        };
        (status, msg).into_response()
    }
}

// ─── Result alias ────────────────────────────────────────

pub type Result<T> = std::result::Result<T, AppError>;
