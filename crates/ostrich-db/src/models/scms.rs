//! SCMS database models
//!
//! Smartcard Management System models

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::FromRow;
use uuid::Uuid;

/// Token Model
///
/// Supported smartcard token types
#[derive(Debug, Clone, FromRow)]
pub struct TokenModel {
    pub id: Uuid,
    pub manufacturer: String,
    pub model: String,
    pub atr: Option<String>,
    pub supported_key_types: Vec<String>,
    pub max_pin_length: i32,
    pub min_pin_length: i32,
    pub supports_puk: bool,
    pub created_at: DateTime<Utc>,
}

/// Token
///
/// Physical smartcard token inventory
#[derive(Debug, Clone, FromRow)]
pub struct Token {
    pub id: Uuid,
    pub serial_number: String,
    pub token_model_id: Uuid,
    pub status: String,
    pub assigned_to: Option<String>,
    pub pin_attempts_remaining: i32,
    pub puk_attempts_remaining: i32,
    pub assigned_at: Option<DateTime<Utc>>,
    pub blocked_at: Option<DateTime<Utc>>,
    pub retired_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Token Key
///
/// Keys stored on tokens
#[derive(Debug, Clone, FromRow)]
pub struct TokenKey {
    pub id: Uuid,
    pub token_id: Uuid,
    pub label: String,
    pub key_type: String,
    pub algorithm: String,
    pub certificate_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// Token Event
///
/// Audit trail for token lifecycle
#[derive(Debug, Clone, FromRow)]
pub struct TokenEvent {
    pub id: Uuid,
    pub token_id: Uuid,
    pub event_type: String,
    pub actor: String,
    pub details: Option<JsonValue>,
    pub timestamp: DateTime<Utc>,
}
