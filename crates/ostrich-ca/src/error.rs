//! CA service error types

use thiserror::Error;

/// CA service errors
#[derive(Debug, Error)]
pub enum Error {
    /// Certificate issuance error
    #[error("Certificate issuance error: {0}")]
    Issuance(String),

    /// Certificate revocation error
    #[error("Certificate revocation error: {0}")]
    Revocation(String),

    /// CRL generation error
    #[error("CRL generation error: {0}")]
    CrlGeneration(String),

    /// CA not initialized
    #[error("CA not initialized")]
    NotInitialized,

    /// CA key not found
    #[error("CA key not found: {0}")]
    KeyNotFound(String),

    /// Profile not found
    #[error("Profile not found: {0}")]
    ProfileNotFound(String),

    /// Invalid request
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// Database error
    #[error("Database error: {0}")]
    Database(#[from] ostrich_db::Error),

    /// Crypto error
    #[error("Crypto error: {0}")]
    Crypto(#[from] ostrich_crypto::Error),

    /// X.509 error
    #[error("X.509 error: {0}")]
    X509(#[from] ostrich_x509::Error),

    /// Audit error
    #[error("Audit error: {0}")]
    Audit(#[from] ostrich_audit::Error),

    /// Common error
    #[error("Common error: {0}")]
    Common(#[from] ostrich_common::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
