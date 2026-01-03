//! SCMS error types
//!
//! Error handling for smartcard management operations

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// SCMS error types
#[derive(Debug, Error)]
pub enum Error {
    /// Token not found
    #[error("Token not found: {0}")]
    TokenNotFound(String),

    /// Token already exists
    #[error("Token already exists: {0}")]
    TokenAlreadyExists(String),

    /// Token is locked
    #[error("Token is locked")]
    TokenLocked,

    /// Invalid PIN
    #[error("Invalid PIN")]
    InvalidPin,

    /// PIN blocked (too many attempts)
    #[error("PIN blocked after too many failed attempts")]
    PinBlocked,

    /// Token operation failed
    #[error("Token operation failed: {0}")]
    TokenOperationFailed(String),

    /// PKCS#11 error
    #[error("PKCS#11 error: {0}")]
    Pkcs11Error(String),

    /// Key not found on token
    #[error("Key not found on token: {0}")]
    KeyNotFound(String),

    /// Invalid request
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// Database error
    #[error("Database error: {0}")]
    Database(#[from] ostrich_db::Error),

    /// Common error
    #[error("Common error: {0}")]
    Common(#[from] ostrich_common::Error),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

/// SCMS result type
pub type Result<T> = std::result::Result<T, Error>;

/// SCMS error response
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
            Self::TokenNotFound(_) | Self::KeyNotFound(_) => StatusCode::NOT_FOUND,
            Self::TokenAlreadyExists(_) => StatusCode::CONFLICT,
            Self::TokenLocked | Self::InvalidPin | Self::PinBlocked => StatusCode::UNAUTHORIZED,
            Self::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            Self::TokenOperationFailed(_)
            | Self::Pkcs11Error(_)
            | Self::Database(_)
            | Self::Common(_)
            | Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
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
            Self::TokenNotFound(_) => "token_not_found",
            Self::TokenAlreadyExists(_) => "token_already_exists",
            Self::TokenLocked => "token_locked",
            Self::InvalidPin => "invalid_pin",
            Self::PinBlocked => "pin_blocked",
            Self::TokenOperationFailed(_) => "token_operation_failed",
            Self::Pkcs11Error(_) => "pkcs11_error",
            Self::KeyNotFound(_) => "key_not_found",
            Self::InvalidRequest(_) => "invalid_request",
            Self::Database(_) => "database_error",
            Self::Common(_) => "common_error",
            Self::Internal(_) => "internal_error",
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
        assert_eq!(
            Error::TokenNotFound("test".to_string()).status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            Error::TokenAlreadyExists("test".to_string()).status_code(),
            StatusCode::CONFLICT
        );
        assert_eq!(Error::InvalidPin.status_code(), StatusCode::UNAUTHORIZED);
        assert_eq!(Error::PinBlocked.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_error_types() {
        assert_eq!(
            Error::TokenNotFound("".to_string()).error_type(),
            "token_not_found"
        );
        assert_eq!(Error::InvalidPin.error_type(), "invalid_pin");
        assert_eq!(Error::PinBlocked.error_type(), "pin_blocked");
    }
}
