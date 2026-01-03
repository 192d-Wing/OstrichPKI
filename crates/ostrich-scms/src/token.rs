//! Smartcard token management
//!
//! Token lifecycle, inventory, and operations

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Token status in lifecycle
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TokenStatus {
    /// Token manufactured but not initialized
    Uninitialized,
    /// Token initialized and ready for personalization
    Initialized,
    /// Token personalized and ready for use
    Active,
    /// Token temporarily suspended
    Suspended,
    /// Token blocked (e.g., PIN blocked)
    Blocked,
    /// Token expired
    Expired,
    /// Token revoked/destroyed
    Revoked,
}

/// Token model/type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenModel {
    /// Model ID
    pub id: Uuid,

    /// Manufacturer name
    pub manufacturer: String,

    /// Model name
    pub model_name: String,

    /// Firmware version
    pub firmware_version: String,

    /// Supported algorithms
    pub supported_algorithms: Vec<String>,

    /// Storage capacity (number of key pairs)
    pub key_capacity: u32,

    /// Certificate storage capacity
    pub cert_capacity: u32,

    /// Supports PKCS#11
    pub pkcs11_support: bool,

    /// Created timestamp
    pub created_at: DateTime<Utc>,
}

/// Smartcard token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    /// Token ID
    pub id: Uuid,

    /// Serial number (from hardware)
    pub serial_number: String,

    /// Token model ID
    pub model_id: Uuid,

    /// Token label/name
    pub label: String,

    /// Current status
    pub status: TokenStatus,

    /// Assigned to user/entity
    pub assigned_to: Option<String>,

    /// PIN retry counter
    pub pin_retry_count: u8,

    /// Maximum PIN retries before blocking
    pub max_pin_retries: u8,

    /// SO-PIN retry counter (Security Officer PIN)
    pub so_pin_retry_count: u8,

    /// Maximum SO-PIN retries
    pub max_so_pin_retries: u8,

    /// Manufacturer date
    pub manufactured_at: DateTime<Utc>,

    /// Initialization date
    pub initialized_at: Option<DateTime<Utc>>,

    /// Personalization date
    pub personalized_at: Option<DateTime<Utc>>,

    /// Expiration date
    pub expires_at: Option<DateTime<Utc>>,

    /// Revocation date
    pub revoked_at: Option<DateTime<Utc>>,

    /// Created timestamp
    pub created_at: DateTime<Utc>,

    /// Updated timestamp
    pub updated_at: DateTime<Utc>,
}

impl Token {
    /// Create new uninitialized token
    pub fn new(serial_number: String, model_id: Uuid, label: String) -> Self {
        let now = Utc::now();

        Self {
            id: Uuid::new_v4(),
            serial_number,
            model_id,
            label,
            status: TokenStatus::Uninitialized,
            assigned_to: None,
            pin_retry_count: 3,
            max_pin_retries: 3,
            so_pin_retry_count: 3,
            max_so_pin_retries: 3,
            manufactured_at: now,
            initialized_at: None,
            personalized_at: None,
            expires_at: None,
            revoked_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Initialize token
    pub fn initialize(&mut self) {
        self.status = TokenStatus::Initialized;
        self.initialized_at = Some(Utc::now());
        self.updated_at = Utc::now();
    }

    /// Personalize token (set user data, keys, certs)
    pub fn personalize(&mut self, assigned_to: String) {
        self.status = TokenStatus::Active;
        self.assigned_to = Some(assigned_to);
        self.personalized_at = Some(Utc::now());
        self.updated_at = Utc::now();
    }

    /// Suspend token
    pub fn suspend(&mut self) {
        self.status = TokenStatus::Suspended;
        self.updated_at = Utc::now();
    }

    /// Resume token
    pub fn resume(&mut self) {
        if self.status == TokenStatus::Suspended {
            self.status = TokenStatus::Active;
            self.updated_at = Utc::now();
        }
    }

    /// Block token (e.g., PIN blocked)
    pub fn block(&mut self) {
        self.status = TokenStatus::Blocked;
        self.updated_at = Utc::now();
    }

    /// Unblock token (SO-PIN recovery)
    pub fn unblock(&mut self) {
        if self.status == TokenStatus::Blocked {
            self.status = TokenStatus::Active;
            self.pin_retry_count = self.max_pin_retries;
            self.updated_at = Utc::now();
        }
    }

    /// Revoke token
    pub fn revoke(&mut self) {
        self.status = TokenStatus::Revoked;
        self.revoked_at = Some(Utc::now());
        self.updated_at = Utc::now();
    }

    /// Decrement PIN retry counter
    pub fn decrement_pin_retries(&mut self) -> bool {
        if self.pin_retry_count > 0 {
            self.pin_retry_count -= 1;
            self.updated_at = Utc::now();

            if self.pin_retry_count == 0 {
                self.block();
                return false;
            }
            true
        } else {
            false
        }
    }

    /// Reset PIN retry counter on successful auth
    pub fn reset_pin_retries(&mut self) {
        self.pin_retry_count = self.max_pin_retries;
        self.updated_at = Utc::now();
    }
}

/// Token key object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenKey {
    /// Key ID
    pub id: Uuid,

    /// Token ID
    pub token_id: Uuid,

    /// Key label on token
    pub label: String,

    /// Key type (RSA, ECDSA, EdDSA)
    pub key_type: String,

    /// Key size in bits
    pub key_size: u32,

    /// Key algorithm
    pub algorithm: String,

    /// Certificate ID (if associated)
    pub certificate_id: Option<Uuid>,

    /// Key usage flags
    pub usage: Vec<String>,

    /// Created timestamp
    pub created_at: DateTime<Utc>,
}

/// Token event for audit trail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenEvent {
    /// Event ID
    pub id: Uuid,

    /// Token ID
    pub token_id: Uuid,

    /// Event type
    pub event_type: String,

    /// Actor (user/system)
    pub actor: String,

    /// Event details
    pub details: Option<serde_json::Value>,

    /// Event timestamp
    pub occurred_at: DateTime<Utc>,
}

impl TokenEvent {
    /// Create new token event
    pub fn new(token_id: Uuid, event_type: String, actor: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            token_id,
            event_type,
            actor,
            details: None,
            occurred_at: Utc::now(),
        }
    }

    /// Add event details
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_creation() {
        let token = Token::new(
            "SN12345".to_string(),
            Uuid::new_v4(),
            "User Token".to_string(),
        );

        assert_eq!(token.status, TokenStatus::Uninitialized);
        assert_eq!(token.serial_number, "SN12345");
        assert!(token.assigned_to.is_none());
        assert_eq!(token.pin_retry_count, 3);
    }

    #[test]
    fn test_token_lifecycle() {
        let mut token = Token::new(
            "SN12345".to_string(),
            Uuid::new_v4(),
            "User Token".to_string(),
        );

        // Initialize
        token.initialize();
        assert_eq!(token.status, TokenStatus::Initialized);
        assert!(token.initialized_at.is_some());

        // Personalize
        token.personalize("user@example.com".to_string());
        assert_eq!(token.status, TokenStatus::Active);
        assert_eq!(token.assigned_to, Some("user@example.com".to_string()));
        assert!(token.personalized_at.is_some());

        // Suspend
        token.suspend();
        assert_eq!(token.status, TokenStatus::Suspended);

        // Resume
        token.resume();
        assert_eq!(token.status, TokenStatus::Active);

        // Revoke
        token.revoke();
        assert_eq!(token.status, TokenStatus::Revoked);
        assert!(token.revoked_at.is_some());
    }

    #[test]
    fn test_pin_retry_mechanism() {
        let mut token = Token::new(
            "SN12345".to_string(),
            Uuid::new_v4(),
            "User Token".to_string(),
        );

        // First failed attempt
        assert!(token.decrement_pin_retries());
        assert_eq!(token.pin_retry_count, 2);

        // Second failed attempt
        assert!(token.decrement_pin_retries());
        assert_eq!(token.pin_retry_count, 1);

        // Third failed attempt - token blocked
        assert!(!token.decrement_pin_retries());
        assert_eq!(token.pin_retry_count, 0);
        assert_eq!(token.status, TokenStatus::Blocked);

        // Unblock
        token.unblock();
        assert_eq!(token.status, TokenStatus::Active);
        assert_eq!(token.pin_retry_count, 3);
    }

    #[test]
    fn test_token_event() {
        let token_id = Uuid::new_v4();
        let event = TokenEvent::new(token_id, "initialize".to_string(), "admin".to_string())
            .with_details(serde_json::json!({"note": "Initial setup"}));

        assert_eq!(event.token_id, token_id);
        assert_eq!(event.event_type, "initialize");
        assert_eq!(event.actor, "admin");
        assert!(event.details.is_some());
    }
}
