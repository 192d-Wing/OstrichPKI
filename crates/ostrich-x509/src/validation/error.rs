//! Validation error types for certificate path validation
//!
//! RFC 5280 §6 - Path validation errors
//!
//! COMPLIANCE MAPPING:
//! - RFC 5280 §6: Path validation algorithm errors
//! - NIST 800-53 SC-17: PKI certificate validation
//! - NIAP PP-CA FDP_CER_EXT.1: Certificate validation errors

use thiserror::Error;

/// Path validation error types
///
/// RFC 5280 §6.1 - Errors that can occur during path validation
#[derive(Debug, Error)]
pub enum ValidationError {
    /// Certificate has expired or is not yet valid
    /// RFC 5280 §6.1.3(b)
    #[error("Certificate validity period violation: {0}")]
    ValidityPeriod(String),

    /// Signature verification failed
    /// RFC 5280 §6.1.3(a)
    #[error("Signature verification failed: {0}")]
    SignatureVerification(String),

    /// No valid certification path found to trust anchor
    /// RFC 5280 §6.1
    #[error("No valid certification path found")]
    PathBuildingFailed,

    /// Certificate contains unknown critical extension
    /// RFC 5280 §6.1.3(g)
    #[error("Unknown critical extension: {0}")]
    UnknownCriticalExtension(String),

    /// Name constraints violation
    /// RFC 5280 §6.1.3(e)
    #[error("Name constraints violation: {0}")]
    NameConstraints(String),

    /// Basic constraints violation (CA flag, pathLenConstraint)
    /// RFC 5280 §6.1.3(j)
    #[error("Basic constraints violation: {0}")]
    BasicConstraints(String),

    /// Key usage violation
    /// RFC 5280 §6.1.3(k)
    #[error("Key usage violation: {0}")]
    KeyUsage(String),

    /// Extended key usage violation
    #[error("Extended key usage violation: {0}")]
    ExtendedKeyUsage(String),

    /// Certificate has been revoked
    /// RFC 5280 - Revocation checking
    #[error("Certificate revoked: {0}")]
    Revoked(String),

    /// Certificate policy processing failed
    /// RFC 5280 §6.1.3(f)
    #[error("Policy processing failed: {0}")]
    PolicyProcessing(String),

    /// Path length constraint exceeded
    /// RFC 5280 §6.1.3(m)
    #[error("Path length constraint exceeded")]
    PathLengthExceeded,

    /// Issuer name does not match
    /// RFC 5280 §6.1.3(d)
    #[error("Issuer name mismatch: {0}")]
    IssuerNameMismatch(String),

    /// Certificate parsing error
    #[error("Certificate parsing error: {0}")]
    ParseError(String),

    /// Trust anchor not found
    #[error("Trust anchor not found for certificate")]
    TrustAnchorNotFound,

    /// Database error during validation
    #[error("Database error: {0}")]
    DatabaseError(String),

    /// Cryptographic operation error
    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    /// Revocation status unknown
    #[error("Revocation status unknown: {0}")]
    RevocationStatusUnknown(String),

    /// Invalid certificate chain
    #[error("Invalid certificate chain: {0}")]
    InvalidChain(String),

    /// Configuration error
    #[error("Validation configuration error: {0}")]
    ConfigError(String),
}

/// Result type for path validation operations
pub type Result<T> = std::result::Result<T, ValidationError>;
