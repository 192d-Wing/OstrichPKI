//! OCSP error types

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Malformed request")]
    MalformedRequest,

    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Certificate not found")]
    CertificateNotFound,

    #[error("Signing error: {0}")]
    SigningError(String),

    #[error("Database error: {0}")]
    Database(#[from] ostrich_db::Error),

    #[error("Crypto error: {0}")]
    Crypto(#[from] ostrich_crypto::Error),

    #[error("Common error: {0}")]
    Common(#[from] ostrich_common::Error),

    #[error("DER encoding error: {0}")]
    DerError(#[from] der::Error),
}
