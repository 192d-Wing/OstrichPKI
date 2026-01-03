//! ACME database models
//!
//! RFC 8555: Automatic Certificate Management Environment

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::FromRow;
use uuid::Uuid;

/// ACME Account
///
/// RFC 8555 §7.1.2 - Account objects
#[derive(Debug, Clone, FromRow)]
pub struct AcmeAccount {
    pub id: Uuid,
    pub account_id: String,
    pub jwk_thumbprint: String,
    pub public_key_jwk: JsonValue,
    pub contact: Vec<String>,
    pub status: String,
    pub terms_of_service_agreed: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// ACME Order
///
/// RFC 8555 §7.1.3 - Order objects
#[derive(Debug, Clone, FromRow)]
pub struct AcmeOrder {
    pub id: Uuid,
    pub order_id: String,
    pub account_id: Uuid,
    pub status: String,
    pub identifiers: JsonValue,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub expires: DateTime<Utc>,
    pub certificate_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// ACME Authorization
///
/// RFC 8555 §7.1.4 - Authorization objects
#[derive(Debug, Clone, FromRow)]
pub struct AcmeAuthorization {
    pub id: Uuid,
    pub authorization_id: String,
    pub order_id: Uuid,
    pub identifier_type: String,
    pub identifier_value: String,
    pub status: String,
    pub expires: DateTime<Utc>,
    pub wildcard: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// ACME Challenge
///
/// RFC 8555 §8 - Challenge types
#[derive(Debug, Clone, FromRow)]
pub struct AcmeChallenge {
    pub id: Uuid,
    pub challenge_id: String,
    pub authorization_id: Uuid,
    pub challenge_type: String,
    pub token: String,
    pub status: String,
    pub validated_at: Option<DateTime<Utc>>,
    pub error_detail: Option<JsonValue>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// ACME Nonce
///
/// RFC 8555 §6.5 - Replay protection
#[derive(Debug, Clone, FromRow)]
pub struct AcmeNonce {
    pub nonce: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}
