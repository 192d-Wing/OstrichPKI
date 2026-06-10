//! Audit logging error types
//!
//! This module defines error types for audit logging operations.
//!
//! # Compliance Mapping
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - **FAU_STG.4**: Error types support detection and reporting of audit failures
//!   - HashComputation errors indicate potential integrity issues
//!   - Database errors may indicate storage protection failures

use thiserror::Error;

/// Audit logging errors
///
/// NIAP PP-CA: FAU_STG.4 - Error conditions that may indicate audit trail issues
#[derive(Debug, Error)]
pub enum Error {
    /// Database error
    ///
    /// NIAP PP-CA: FAU_STG.1 - May indicate protected storage failure
    #[error("Database error: {0}")]
    Database(#[from] ostrich_db::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Hash computation error
    ///
    /// NIAP PP-CA: FAU_STG.4 - Hash errors may indicate integrity issues
    #[error("Hash computation error: {0}")]
    HashComputation(String),

    /// Common error
    #[error("Common error: {0}")]
    Common(#[from] ostrich_common::Error),

    /// Record signing / signature verification error (AU-10)
    #[error("Audit signing error: {0}")]
    Signing(String),
}

pub type Result<T> = std::result::Result<T, Error>;
