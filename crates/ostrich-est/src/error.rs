//! EST error types
//!
//! RFC 7030: Error handling for EST protocol

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// EST error types
#[derive(Debug, Error)]
pub enum Error {
    /// Client authentication required
    #[error("Client authentication required")]
    Unauthorized,

    /// Client certificate not authorized for operation
    #[error("Client not authorized: {0}")]
    Forbidden(String),

    /// Malformed request
    #[error("Malformed request: {0}")]
    BadRequest(String),

    /// CSR parsing failed
    #[error("Invalid CSR: {0}")]
    InvalidCsr(String),

    /// Certificate not found
    #[error("Certificate not found")]
    NotFound,

    /// Internal server error
    #[error("Internal server error: {0}")]
    Internal(String),

    /// Database error
    #[error("Database error: {0}")]
    Database(#[from] ostrich_db::Error),

    /// Common error
    #[error("Common error: {0}")]
    Common(#[from] ostrich_common::Error),
}

/// EST result type
pub type Result<T> = std::result::Result<T, Error>;

/// EST error response (RFC 7030 §4.2.3)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    /// Error type
    pub error: String,
    /// Error description
    pub error_description: String,
}

impl Error {
    /// Get HTTP status code for this error
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::BadRequest(_) | Self::InvalidCsr(_) => StatusCode::BAD_REQUEST,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Internal(_) | Self::Database(_) | Self::Common(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    /// Convert to error response
    pub fn to_response(&self) -> ErrorResponse {
        ErrorResponse {
            error: self.error_type().to_string(),
            error_description: self.to_string(),
        }
    }

    /// Get error type string
    fn error_type(&self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::Forbidden(_) => "forbidden",
            Self::BadRequest(_) => "bad_request",
            Self::InvalidCsr(_) => "invalid_csr",
            Self::NotFound => "not_found",
            Self::Internal(_) => "internal_error",
            Self::Database(_) => "database_error",
            Self::Common(_) => "common_error",
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = self.to_response();

        (status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_status_codes() {
        assert_eq!(Error::Unauthorized.status_code(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            Error::Forbidden("test".to_string()).status_code(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            Error::BadRequest("test".to_string()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(Error::NotFound.status_code(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_error_types() {
        assert_eq!(Error::Unauthorized.error_type(), "unauthorized");
        assert_eq!(Error::Forbidden("".to_string()).error_type(), "forbidden");
        assert_eq!(
            Error::BadRequest("".to_string()).error_type(),
            "bad_request"
        );
    }
}
