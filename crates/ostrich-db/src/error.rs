//! Database error types
//!
//! NIST 800-53: SI-11 - Error handling

use thiserror::Error;

/// Database operation errors
#[derive(Debug, Error)]
pub enum Error {
    /// Database connection error
    #[error("Database connection error: {0}")]
    Connection(String),

    /// SQL query error
    #[error("Database query error: {0}")]
    Query(String),

    /// Migration error
    #[error("Database migration error: {0}")]
    Migration(String),

    /// Transaction error
    #[error("Transaction error: {0}")]
    Transaction(String),

    /// Record not found
    #[error("Record not found: {0}")]
    NotFound(String),

    /// Duplicate record
    #[error("Duplicate record: {0}")]
    Duplicate(String),

    /// Constraint violation
    #[error("Constraint violation: {0}")]
    ConstraintViolation(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// SQLx error
    #[error("SQLx error: {0}")]
    Sqlx(#[from] sqlx::Error),

    /// Common error
    #[error("Common error: {0}")]
    Common(#[from] ostrich_common::Error),
}

impl Error {
    /// Check if this error is security-relevant and should be audited
    ///
    /// NIST 800-53: AU-2 - Auditable events
    pub fn is_security_relevant(&self) -> bool {
        matches!(self, Error::ConstraintViolation(_) | Error::Transaction(_))
    }

    /// Get a user-safe error message (without sensitive details)
    ///
    /// NIST 800-53: SI-11 - Error message sanitization
    pub fn public_message(&self) -> String {
        match self {
            Error::Connection(_) => "Database connection failed".to_string(),
            Error::Query(_) => "Database query failed".to_string(),
            Error::Migration(_) => "Database migration failed".to_string(),
            Error::Transaction(_) => "Transaction failed".to_string(),
            Error::NotFound(entity) => format!("{} not found", entity),
            Error::Duplicate(entity) => format!("{} already exists", entity),
            Error::ConstraintViolation(_) => "Operation violates database constraints".to_string(),
            Error::Serialization(_) => "Data serialization failed".to_string(),
            Error::Config(_) => "Database configuration error".to_string(),
            Error::Sqlx(_) => "Database operation failed".to_string(),
            Error::Common(e) => e.public_message().to_string(),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
