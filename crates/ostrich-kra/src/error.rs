//! KRA error types
//!
//! Error types for Key Recovery Authority operations. These errors support
//! proper audit logging and access control enforcement.
//!
//! # Compliance Mapping
//!
//! ## NIAP PP-CA v2.1 SFRs
//!
//! - **FAU_GEN.1**: Error types include sufficient context for audit logging
//! - **FDP_ACC.1**: Unauthorized error supports access control enforcement
//! - **FCS_CKM.2**: InsufficientShares error enforces threshold policy
//!
//! ## NIST 800-53 Rev 5 Controls
//!
//! - **AU-3**: Error messages provide audit-relevant details
//! - **SI-11**: Error handling generates safe, auditable messages

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Escrow error: {0}")]
    EscrowError(String),

    #[error("Recovery error: {0}")]
    RecoveryError(String),

    #[error("Insufficient shares: need {required}, got {provided}")]
    InsufficientShares { required: usize, provided: usize },

    #[error("Invalid share")]
    InvalidShare,

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Agent not found: {0}")]
    AgentNotFound(String),

    #[error("Database error: {0}")]
    Database(#[from] ostrich_db::Error),

    #[error("Crypto error: {0}")]
    Crypto(#[from] ostrich_crypto::Error),

    #[error("Common error: {0}")]
    Common(#[from] ostrich_common::Error),

    #[error("Audit error: {0}")]
    Audit(#[from] ostrich_audit::Error),
}
