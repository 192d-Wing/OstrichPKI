//! ACME error types
//!
//! RFC 8555 §6.7: Error responses

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Account does not exist")]
    AccountDoesNotExist,

    #[error("Already revoked")]
    AlreadyRevoked,

    #[error("Bad CSR: {0}")]
    BadCsr(String),

    #[error("Bad nonce")]
    BadNonce,

    #[error("Bad public key")]
    BadPublicKey,

    #[error("Bad revocation reason")]
    BadRevocationReason,

    #[error("Bad signature algorithm")]
    BadSignatureAlgorithm,

    #[error("CAA error: {0}")]
    Caa(String),

    #[error("Challenge failed: {0}")]
    ChallengeFailed(String),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("DNS error: {0}")]
    Dns(String),

    #[error("External account required")]
    ExternalAccountRequired,

    #[error("Incorrect response: {0}")]
    IncorrectResponse(String),

    #[error("Invalid contact: {0}")]
    InvalidContact(String),

    #[error("Malformed request: {0}")]
    Malformed(String),

    #[error("Order not ready")]
    OrderNotReady,

    #[error("Rate limited")]
    RateLimited,

    #[error("Rejected identifier: {0}")]
    RejectedIdentifier(String),

    #[error("Server internal error: {0}")]
    ServerInternal(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Unsupported contact: {0}")]
    UnsupportedContact(String),

    #[error("Unsupported identifier: {0}")]
    UnsupportedIdentifier(String),

    #[error("User action required: {0}")]
    UserActionRequired(String),

    #[error("Database error: {0}")]
    Database(#[from] ostrich_db::Error),

    #[error("Common error: {0}")]
    Common(#[from] ostrich_common::Error),
}

/// ACME error response
///
/// RFC 8555 §6.7
#[derive(Debug, Serialize, Deserialize)]
pub struct AcmeError {
    /// Error type (URN)
    #[serde(rename = "type")]
    pub error_type: String,

    /// Human-readable error description
    pub detail: String,

    /// HTTP status code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,

    /// Sub-problems
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subproblems: Option<Vec<AcmeError>>,
}

impl Error {
    /// Get ACME error type URN
    pub fn error_type(&self) -> &'static str {
        match self {
            Self::AccountDoesNotExist => "urn:ietf:params:acme:error:accountDoesNotExist",
            Self::AlreadyRevoked => "urn:ietf:params:acme:error:alreadyRevoked",
            Self::BadCsr(_) => "urn:ietf:params:acme:error:badCSR",
            Self::BadNonce => "urn:ietf:params:acme:error:badNonce",
            Self::BadPublicKey => "urn:ietf:params:acme:error:badPublicKey",
            Self::BadRevocationReason => "urn:ietf:params:acme:error:badRevocationReason",
            Self::BadSignatureAlgorithm => "urn:ietf:params:acme:error:badSignatureAlgorithm",
            Self::Caa(_) => "urn:ietf:params:acme:error:caa",
            Self::ChallengeFailed(_) => "urn:ietf:params:acme:error:challengeFailed",
            Self::Connection(_) => "urn:ietf:params:acme:error:connection",
            Self::Dns(_) => "urn:ietf:params:acme:error:dns",
            Self::ExternalAccountRequired => "urn:ietf:params:acme:error:externalAccountRequired",
            Self::IncorrectResponse(_) => "urn:ietf:params:acme:error:incorrectResponse",
            Self::InvalidContact(_) => "urn:ietf:params:acme:error:invalidContact",
            Self::Malformed(_) => "urn:ietf:params:acme:error:malformed",
            Self::OrderNotReady => "urn:ietf:params:acme:error:orderNotReady",
            Self::RateLimited => "urn:ietf:params:acme:error:rateLimited",
            Self::RejectedIdentifier(_) => "urn:ietf:params:acme:error:rejectedIdentifier",
            Self::ServerInternal(_) => "urn:ietf:params:acme:error:serverInternal",
            Self::Tls(_) => "urn:ietf:params:acme:error:tls",
            Self::Unauthorized(_) => "urn:ietf:params:acme:error:unauthorized",
            Self::UnsupportedContact(_) => "urn:ietf:params:acme:error:unsupportedContact",
            Self::UnsupportedIdentifier(_) => "urn:ietf:params:acme:error:unsupportedIdentifier",
            Self::UserActionRequired(_) => "urn:ietf:params:acme:error:userActionRequired",
            Self::Database(_) | Self::Common(_) => "urn:ietf:params:acme:error:serverInternal",
        }
    }

    /// Get HTTP status code
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::AccountDoesNotExist => StatusCode::BAD_REQUEST,
            Self::AlreadyRevoked => StatusCode::BAD_REQUEST,
            Self::BadCsr(_) => StatusCode::BAD_REQUEST,
            Self::BadNonce => StatusCode::BAD_REQUEST,
            Self::BadPublicKey => StatusCode::BAD_REQUEST,
            Self::BadRevocationReason => StatusCode::BAD_REQUEST,
            Self::BadSignatureAlgorithm => StatusCode::BAD_REQUEST,
            Self::Caa(_) => StatusCode::FORBIDDEN,
            Self::ChallengeFailed(_) => StatusCode::BAD_REQUEST,
            Self::Connection(_) => StatusCode::BAD_REQUEST,
            Self::Dns(_) => StatusCode::BAD_REQUEST,
            Self::ExternalAccountRequired => StatusCode::FORBIDDEN,
            Self::IncorrectResponse(_) => StatusCode::BAD_REQUEST,
            Self::InvalidContact(_) => StatusCode::BAD_REQUEST,
            Self::Malformed(_) => StatusCode::BAD_REQUEST,
            Self::OrderNotReady => StatusCode::FORBIDDEN,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::RejectedIdentifier(_) => StatusCode::BAD_REQUEST,
            Self::ServerInternal(_) | Self::Database(_) | Self::Common(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::Tls(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::UnsupportedContact(_) => StatusCode::BAD_REQUEST,
            Self::UnsupportedIdentifier(_) => StatusCode::BAD_REQUEST,
            Self::UserActionRequired(_) => StatusCode::FORBIDDEN,
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let acme_error = AcmeError {
            error_type: self.error_type().to_string(),
            detail: self.to_string(),
            status: Some(self.status_code().as_u16()),
            subproblems: None,
        };

        (self.status_code(), Json(acme_error)).into_response()
    }
}
