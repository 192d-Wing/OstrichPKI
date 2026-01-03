//! KRA database models
//!
//! Key Recovery Authority models

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

/// Escrowed Key
///
/// Private keys wrapped and stored by KRA
#[derive(Debug, Clone, FromRow)]
pub struct EscrowedKey {
    pub id: Uuid,
    pub certificate_id: Uuid,
    pub wrapped_key: Vec<u8>,
    pub wrapping_key_id: Uuid,
    pub key_type: String,
    pub algorithm: String,
    pub escrow_time: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Recovery Agent
///
/// Authorized agents for M-of-N key recovery
#[derive(Debug, Clone, FromRow)]
pub struct RecoveryAgent {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub public_key_der: Vec<u8>,
    pub active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Recovery Request
///
/// Tracks key recovery requests
#[derive(Debug, Clone, FromRow)]
pub struct RecoveryRequest {
    pub id: Uuid,
    pub escrowed_key_id: Uuid,
    pub requestor: String,
    pub justification: String,
    pub status: String,
    pub required_shares: i32,
    pub total_agents: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Recovery Share
///
/// Encrypted shares for M-of-N recovery
#[derive(Debug, Clone, FromRow)]
pub struct RecoveryShare {
    pub id: Uuid,
    pub recovery_request_id: Uuid,
    pub agent_id: Uuid,
    pub encrypted_share: Vec<u8>,
    pub submitted_at: Option<DateTime<Utc>>,
}
