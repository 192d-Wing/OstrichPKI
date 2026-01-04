//! X.509 error types

use thiserror::Error;

/// X.509 operation errors
#[derive(Debug, Error)]
pub enum Error {
    /// Certificate parsing error
    #[error("Certificate parsing error: {0}")]
    Parse(String),

    /// Certificate building error
    #[error("Certificate building error: {0}")]
    Build(String),

    /// Invalid certificate field
    #[error("Invalid field: {0}")]
    InvalidField(String),

    /// DER encoding/decoding error
    #[error("DER encoding error: {0}")]
    Der(String),

    /// Encoding error (general)
    #[error("Encoding error: {0}")]
    Encoding(String),

    /// PEM encoding/decoding error
    #[error("PEM encoding error: {0}")]
    Pem(String),

    /// Signature verification error
    #[error("Signature verification failed: {0}")]
    SignatureVerification(String),

    /// Extension error
    #[error("Extension error: {0}")]
    Extension(String),

    /// Profile validation error
    #[error("Profile validation error: {0}")]
    ProfileValidation(String),

    /// Secure defaults validation error
    /// NIAP PP-CA: FMT_MSA.1.2 - Security attribute constraint violation
    #[error("Secure defaults violation: {0}")]
    SecureDefaults(String),

    /// Crypto error
    #[error("Crypto error: {0}")]
    Crypto(#[from] ostrich_crypto::Error),

    /// Common error
    #[error("Common error: {0}")]
    Common(#[from] ostrich_common::Error),

    /// X.509 cert error
    #[error("x509-cert error: {0}")]
    X509Cert(String),
}

// Implement From for various external errors
impl From<der::Error> for Error {
    fn from(e: der::Error) -> Self {
        Error::Der(e.to_string())
    }
}

impl From<x509_cert::builder::Error> for Error {
    fn from(e: x509_cert::builder::Error) -> Self {
        Error::Build(e.to_string())
    }
}

impl From<pem_rfc7468::Error> for Error {
    fn from(e: pem_rfc7468::Error) -> Self {
        Error::Pem(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
