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
