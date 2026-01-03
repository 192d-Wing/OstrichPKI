//! Error types for cryptographic operations
//!
//! NIST 800-53: AU-3 - Audit content (error classification)

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("PKCS#11 error: {0}")]
    Pkcs11(String),

    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    #[error("Signing failed: {0}")]
    Signing(String),

    #[error("Verification failed: {0}")]
    Verification(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Invalid key type: {0}")]
    InvalidKeyType(String),

    #[error("Invalid key handle: {0}")]
    InvalidKeyHandle(String),

    #[error("Operation not implemented: {0}")]
    NotImplemented(String),

    #[error("Encoding error: {0}")]
    Encoding(String),

    #[error("Decoding error: {0}")]
    Decoding(String),

    #[error("HSM slot not found: {0}")]
    SlotNotFound(u64),

    #[error("HSM session error: {0}")]
    SessionError(String),

    #[error("Invalid PIN")]
    InvalidPin,

    #[error("Common error: {0}")]
    Common(#[from] ostrich_common::Error),

    #[error("Cryptoki error: {0}")]
    Cryptoki(#[from] cryptoki::error::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl Error {
    /// Returns true if this is a security-relevant error
    /// NIST 800-53: AU-2 - Auditable events
    pub fn is_security_relevant(&self) -> bool {
        matches!(
            self,
            Error::InvalidPin
                | Error::KeyNotFound(_)
                | Error::SessionError(_)
                | Error::Verification(_)
        )
    }
}
