// NIST 800-53: AU-3 - Audit record content
// NIST 800-53: SI-10 - Information input validation

use thiserror::Error;

/// Common result type for OstrichPKI operations
pub type Result<T> = std::result::Result<T, Error>;

/// Common error types across all OstrichPKI services
#[derive(Error, Debug)]
pub enum Error {
    // Configuration errors
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Missing required configuration: {0}")]
    MissingConfig(String),

    // Cryptographic errors
    #[error("Cryptographic operation failed: {0}")]
    Crypto(String),

    #[error("Invalid algorithm: {0}")]
    InvalidAlgorithm(String),

    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    #[error("Signature verification failed")]
    SignatureVerification,

    // Encoding/Decoding errors
    #[error("Encoding error: {0}")]
    Encoding(String),

    #[error("Decoding error: {0}")]
    Decoding(String),

    #[error("Invalid PEM format: {0}")]
    InvalidPem(String),

    #[error("Invalid DER format: {0}")]
    InvalidDer(String),

    // Validation errors - NIST 800-53: SI-10
    #[error("Validation failed: {0}")]
    Validation(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    // Time-related errors
    #[error("Invalid timestamp: {0}")]
    InvalidTimestamp(String),

    #[error("Expired: {0}")]
    Expired(String),

    // I/O errors
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    // Serialization errors
    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),

    // Generic internal error
    #[error("Internal error: {0}")]
    Internal(String),

    // Service communication errors
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("gRPC error: {0}")]
    GrpcError(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    // External errors wrapped
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl Error {
    /// Returns true if this error should be logged at ERROR level
    /// NIST 800-53: AU-2 - Auditable events
    pub fn is_security_relevant(&self) -> bool {
        matches!(
            self,
            Error::Crypto(_)
                | Error::SignatureVerification
                | Error::Validation(_)
                | Error::InvalidInput(_)
                | Error::Expired(_)
        )
    }

    /// Returns a safe error message suitable for external display
    /// (without leaking sensitive internal details)
    pub fn public_message(&self) -> &str {
        match self {
            Error::Config(_) | Error::MissingConfig(_) => "Configuration error",
            Error::Crypto(_) | Error::KeyGeneration(_) => "Cryptographic operation failed",
            Error::InvalidAlgorithm(_) => "Unsupported algorithm",
            Error::SignatureVerification => "Signature verification failed",
            Error::Encoding(_) | Error::Decoding(_) => "Encoding error",
            Error::InvalidPem(_) | Error::InvalidDer(_) => "Invalid format",
            Error::Validation(_) | Error::InvalidInput(_) => "Validation failed",
            Error::InvalidTimestamp(_) => "Invalid timestamp",
            Error::Expired(_) => "Expired",
            Error::Io(_) => "I/O error",
            Error::Serialization(_) | Error::Deserialization(_) => "Serialization error",
            Error::Internal(_) => "Internal error",
            Error::ServiceUnavailable(_) => "Service unavailable",
            Error::GrpcError(_) => "Communication error",
            Error::InvalidConfiguration(_) => "Invalid configuration",
            Error::Other(_) => "Operation failed",
        }
    }
}

// Convenience constructors
impl Error {
    pub fn config(msg: impl Into<String>) -> Self {
        Error::Config(msg.into())
    }

    pub fn crypto(msg: impl Into<String>) -> Self {
        Error::Crypto(msg.into())
    }

    pub fn validation(msg: impl Into<String>) -> Self {
        Error::Validation(msg.into())
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Error::Internal(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = Error::Config("test config error".to_string());
        assert_eq!(err.to_string(), "Configuration error: test config error");

        let err = Error::Crypto("crypto failed".to_string());
        assert_eq!(
            err.to_string(),
            "Cryptographic operation failed: crypto failed"
        );
    }

    #[test]
    fn test_error_constructors() {
        let err = Error::config("config issue");
        assert!(matches!(err, Error::Config(_)));

        let err = Error::crypto("crypto issue");
        assert!(matches!(err, Error::Crypto(_)));

        let err = Error::validation("invalid input");
        assert!(matches!(err, Error::Validation(_)));

        let err = Error::internal("internal error");
        assert!(matches!(err, Error::Internal(_)));
    }

    #[test]
    fn test_is_security_relevant() {
        // Security-relevant errors
        assert!(Error::Crypto("test".to_string()).is_security_relevant());
        assert!(Error::SignatureVerification.is_security_relevant());
        assert!(Error::Validation("test".to_string()).is_security_relevant());
        assert!(Error::InvalidInput("test".to_string()).is_security_relevant());
        assert!(Error::Expired("test".to_string()).is_security_relevant());

        // Non-security-relevant errors
        assert!(!Error::Config("test".to_string()).is_security_relevant());
        assert!(!Error::Encoding("test".to_string()).is_security_relevant());
        assert!(!Error::Internal("test".to_string()).is_security_relevant());
        assert!(!Error::ServiceUnavailable("test".to_string()).is_security_relevant());
    }

    #[test]
    fn test_public_message() {
        // Verify public messages don't leak sensitive details
        assert_eq!(
            Error::Config("sensitive details".to_string()).public_message(),
            "Configuration error"
        );
        assert_eq!(
            Error::MissingConfig("DB_PASSWORD".to_string()).public_message(),
            "Configuration error"
        );
        assert_eq!(
            Error::Crypto("private key leak".to_string()).public_message(),
            "Cryptographic operation failed"
        );
        assert_eq!(
            Error::KeyGeneration("HSM error code 0x1234".to_string()).public_message(),
            "Cryptographic operation failed"
        );
        assert_eq!(
            Error::SignatureVerification.public_message(),
            "Signature verification failed"
        );
        assert_eq!(
            Error::InvalidPem("malformed at byte 42".to_string()).public_message(),
            "Invalid format"
        );
        assert_eq!(
            Error::InvalidDer("malformed at byte 42".to_string()).public_message(),
            "Invalid format"
        );
        assert_eq!(
            Error::Validation("SQL injection attempt".to_string()).public_message(),
            "Validation failed"
        );
        assert_eq!(
            Error::Internal("stack trace here".to_string()).public_message(),
            "Internal error"
        );
        assert_eq!(
            Error::GrpcError("connection refused".to_string()).public_message(),
            "Communication error"
        );
    }

    #[test]
    fn test_error_variants() {
        // Test that all error variants can be created
        let errors: Vec<Error> = vec![
            Error::Config("test".to_string()),
            Error::MissingConfig("test".to_string()),
            Error::Crypto("test".to_string()),
            Error::InvalidAlgorithm("test".to_string()),
            Error::KeyGeneration("test".to_string()),
            Error::SignatureVerification,
            Error::Encoding("test".to_string()),
            Error::Decoding("test".to_string()),
            Error::InvalidPem("test".to_string()),
            Error::InvalidDer("test".to_string()),
            Error::Validation("test".to_string()),
            Error::InvalidInput("test".to_string()),
            Error::InvalidTimestamp("test".to_string()),
            Error::Expired("test".to_string()),
            Error::Serialization("test".to_string()),
            Error::Deserialization("test".to_string()),
            Error::Internal("test".to_string()),
            Error::ServiceUnavailable("test".to_string()),
            Error::GrpcError("test".to_string()),
            Error::InvalidConfiguration("test".to_string()),
        ];

        for err in errors {
            // All errors should have a non-empty display message
            assert!(!err.to_string().is_empty());
            // All errors should have a public message
            assert!(!err.public_message().is_empty());
        }
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: Error = io_err.into();
        assert!(matches!(err, Error::Io(_)));
        assert_eq!(err.public_message(), "I/O error");
    }

    #[test]
    fn test_anyhow_error_conversion() {
        let anyhow_err = anyhow::anyhow!("some error");
        let err: Error = anyhow_err.into();
        assert!(matches!(err, Error::Other(_)));
        assert_eq!(err.public_message(), "Operation failed");
    }
}
