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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = Error::InvalidRequest("bad data".to_string());
        assert_eq!(err.to_string(), "Invalid request: bad data");

        let err = Error::MalformedRequest;
        assert_eq!(err.to_string(), "Malformed request");

        let err = Error::InternalError("server crash".to_string());
        assert_eq!(err.to_string(), "Internal error: server crash");

        let err = Error::Unauthorized;
        assert_eq!(err.to_string(), "Unauthorized");

        let err = Error::CertificateNotFound;
        assert_eq!(err.to_string(), "Certificate not found");

        let err = Error::SigningError("HSM unavailable".to_string());
        assert_eq!(err.to_string(), "Signing error: HSM unavailable");
    }

    #[test]
    fn test_error_variants_exist() {
        // Verify all error types can be constructed
        let errors: Vec<Error> = vec![
            Error::InvalidRequest("test".to_string()),
            Error::MalformedRequest,
            Error::InternalError("test".to_string()),
            Error::Unauthorized,
            Error::CertificateNotFound,
            Error::SigningError("test".to_string()),
        ];

        for err in errors {
            // All errors should have a non-empty display message
            assert!(!err.to_string().is_empty());
        }
    }
}
