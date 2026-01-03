//! Audit logging error types

use thiserror::Error;

/// Audit logging errors
#[derive(Debug, Error)]
pub enum Error {
    /// Database error
    #[error("Database error: {0}")]
    Database(#[from] ostrich_db::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Hash computation error
    #[error("Hash computation error: {0}")]
    HashComputation(String),

    /// Common error
    #[error("Common error: {0}")]
    Common(#[from] ostrich_common::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
