//! KRA error types

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
