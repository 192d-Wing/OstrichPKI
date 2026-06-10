//! SCMS database models
//!
//! Smartcard Management System models

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::FromRow;
use uuid::Uuid;

/// Token Model
///
/// Supported smartcard token types. Phase 1c migration 00005 added
/// `firmware_version`, `key_capacity`, `cert_capacity`, and `pkcs11_support`.
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
    pub firmware_version: Option<String>,
    pub key_capacity: Option<i32>,
    pub cert_capacity: Option<i32>,
    pub pkcs11_support: bool,
    pub created_at: DateTime<Utc>,
}

/// Token
///
/// Physical smartcard token inventory. Phase 1c migration 00005 added
/// `label`, `so_pin_attempts_remaining`, `initialized_at`, and `expires_at`.
#[derive(Debug, Clone, FromRow)]
pub struct Token {
    pub id: Uuid,
    pub serial_number: String,
    pub token_model_id: Uuid,
    pub status: String,
    pub assigned_to: Option<String>,
    pub pin_attempts_remaining: i32,
    pub puk_attempts_remaining: i32,
    /// SO-PIN retry counter (NIAP FMT_SMR.1 - distinct from User PIN counter)
    pub so_pin_attempts_remaining: i32,
    /// Operator-facing display label (mutable; distinct from serial_number)
    pub label: Option<String>,
    pub assigned_at: Option<DateTime<Utc>>,
    pub blocked_at: Option<DateTime<Utc>>,
    pub retired_at: Option<DateTime<Utc>>,
    /// Timestamp of first transition from uninitialized to initialized
    pub initialized_at: Option<DateTime<Utc>>,
    /// Token expiration (battery, contract end, etc.) - None = no limit
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Token Key
///
/// Keys stored on tokens. Phase 1c migration 00005 added `key_size` and `usage`.
#[derive(Debug, Clone, FromRow)]
pub struct TokenKey {
    pub id: Uuid,
    pub token_id: Uuid,
    pub label: String,
    pub key_type: String,
    pub algorithm: String,
    /// Key size in bits (modulus for RSA, curve size for ECDSA)
    pub key_size: Option<i32>,
    /// Permitted X.509 KeyUsage flags (RFC 5280 §4.2.1.3)
    pub usage: Vec<String>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_model_structure() {
        let now = Utc::now();
        let model = TokenModel {
            id: Uuid::new_v4(),
            manufacturer: "YubiKey".to_string(),
            model: "5 NFC".to_string(),
            atr: Some("3B:8D:80:01:00".to_string()),
            supported_key_types: vec!["RSA2048".to_string(), "EC-P256".to_string()],
            max_pin_length: 8,
            min_pin_length: 6,
            supports_puk: true,
            firmware_version: Some("5.4.3".to_string()),
            key_capacity: Some(24),
            cert_capacity: Some(24),
            pkcs11_support: true,
            created_at: now,
        };

        assert_eq!(model.manufacturer, "YubiKey");
        assert_eq!(model.model, "5 NFC");
        assert!(model.supports_puk);
        assert!(model.min_pin_length <= model.max_pin_length);
        assert_eq!(model.supported_key_types.len(), 2);
    }

    #[test]
    fn test_token_model_without_atr() {
        let now = Utc::now();
        let model = TokenModel {
            id: Uuid::new_v4(),
            manufacturer: "SoftHSM".to_string(),
            model: "v2".to_string(),
            atr: None,
            supported_key_types: vec![
                "RSA2048".to_string(),
                "RSA4096".to_string(),
                "EC-P384".to_string(),
            ],
            max_pin_length: 64,
            min_pin_length: 4,
            supports_puk: false,
            firmware_version: None,
            key_capacity: None,
            cert_capacity: None,
            pkcs11_support: true,
            created_at: now,
        };

        assert!(model.atr.is_none());
        assert!(!model.supports_puk);
    }

    #[test]
    fn test_token_structure() {
        let now = Utc::now();
        let token = Token {
            id: Uuid::new_v4(),
            serial_number: "YK-1234567890".to_string(),
            token_model_id: Uuid::new_v4(),
            status: "active".to_string(),
            assigned_to: Some("john.doe@example.com".to_string()),
            pin_attempts_remaining: 3,
            puk_attempts_remaining: 10,
            so_pin_attempts_remaining: 3,
            label: Some("Engineering laptop token".to_string()),
            assigned_at: Some(now),
            blocked_at: None,
            retired_at: None,
            initialized_at: Some(now),
            expires_at: None,
            created_at: now,
            updated_at: now,
        };

        assert_eq!(token.serial_number, "YK-1234567890");
        assert_eq!(token.status, "active");
        assert!(token.assigned_to.is_some());
        assert_eq!(token.pin_attempts_remaining, 3);
    }

    #[test]
    fn test_token_unassigned() {
        let now = Utc::now();
        let token = Token {
            id: Uuid::new_v4(),
            serial_number: "YK-NEW-00001".to_string(),
            token_model_id: Uuid::new_v4(),
            status: "available".to_string(),
            assigned_to: None,
            pin_attempts_remaining: 3,
            puk_attempts_remaining: 10,
            so_pin_attempts_remaining: 3,
            label: None,
            assigned_at: None,
            blocked_at: None,
            retired_at: None,
            initialized_at: None,
            expires_at: None,
            created_at: now,
            updated_at: now,
        };

        assert_eq!(token.status, "available");
        assert!(token.assigned_to.is_none());
        assert!(token.assigned_at.is_none());
    }

    #[test]
    fn test_token_blocked() {
        let now = Utc::now();
        let token = Token {
            id: Uuid::new_v4(),
            serial_number: "YK-BLOCKED-001".to_string(),
            token_model_id: Uuid::new_v4(),
            status: "blocked".to_string(),
            assigned_to: Some("user@example.com".to_string()),
            pin_attempts_remaining: 0,
            puk_attempts_remaining: 0,
            so_pin_attempts_remaining: 3,
            label: None,
            assigned_at: Some(now - chrono::Duration::days(30)),
            blocked_at: Some(now),
            retired_at: None,
            initialized_at: Some(now - chrono::Duration::days(30)),
            expires_at: None,
            created_at: now - chrono::Duration::days(60),
            updated_at: now,
        };

        assert_eq!(token.status, "blocked");
        assert_eq!(token.pin_attempts_remaining, 0);
        assert_eq!(token.puk_attempts_remaining, 0);
        assert!(token.blocked_at.is_some());
    }

    #[test]
    fn test_token_retired() {
        let now = Utc::now();
        let token = Token {
            id: Uuid::new_v4(),
            serial_number: "YK-RETIRED-001".to_string(),
            token_model_id: Uuid::new_v4(),
            status: "retired".to_string(),
            assigned_to: None,
            pin_attempts_remaining: 0,
            puk_attempts_remaining: 0,
            so_pin_attempts_remaining: 3,
            label: None,
            assigned_at: None,
            blocked_at: None,
            retired_at: Some(now),
            initialized_at: Some(now - chrono::Duration::days(365)),
            expires_at: Some(now - chrono::Duration::days(1)),
            created_at: now - chrono::Duration::days(365),
            updated_at: now,
        };

        assert_eq!(token.status, "retired");
        assert!(token.retired_at.is_some());
    }

    #[test]
    fn test_token_key_structure() {
        let now = Utc::now();
        let key = TokenKey {
            id: Uuid::new_v4(),
            token_id: Uuid::new_v4(),
            label: "Signing Key".to_string(),
            key_type: "EC".to_string(),
            algorithm: "ECDSA-P256".to_string(),
            key_size: Some(256),
            usage: vec!["digital_signature".to_string(), "non_repudiation".to_string()],
            certificate_id: Some(Uuid::new_v4()),
            created_at: now,
        };

        assert_eq!(key.label, "Signing Key");
        assert_eq!(key.key_type, "EC");
        assert!(key.certificate_id.is_some());
    }

    #[test]
    fn test_token_key_without_certificate() {
        let now = Utc::now();
        let key = TokenKey {
            id: Uuid::new_v4(),
            token_id: Uuid::new_v4(),
            label: "Encryption Key".to_string(),
            key_type: "RSA".to_string(),
            algorithm: "RSA-2048".to_string(),
            key_size: Some(2048),
            usage: vec!["key_encipherment".to_string()],
            certificate_id: None,
            created_at: now,
        };

        assert!(key.certificate_id.is_none());
    }

    #[test]
    fn test_token_event_structure() {
        let now = Utc::now();
        let event = TokenEvent {
            id: Uuid::new_v4(),
            token_id: Uuid::new_v4(),
            event_type: "key_generated".to_string(),
            actor: "admin@example.com".to_string(),
            details: Some(serde_json::json!({
                "key_type": "EC-P256",
                "label": "Signing Key"
            })),
            timestamp: now,
        };

        assert_eq!(event.event_type, "key_generated");
        assert!(event.details.is_some());
    }

    #[test]
    fn test_token_event_types() {
        let now = Utc::now();
        let token_id = Uuid::new_v4();

        // Test various token event types
        let event_types = [
            "token_registered",
            "token_assigned",
            "pin_changed",
            "pin_blocked",
            "puk_used",
            "key_generated",
            "certificate_loaded",
            "token_retired",
        ];

        for event_type in event_types {
            let event = TokenEvent {
                id: Uuid::new_v4(),
                token_id,
                event_type: event_type.to_string(),
                actor: "system".to_string(),
                details: None,
                timestamp: now,
            };
            assert_eq!(event.event_type, event_type);
        }
    }

    #[test]
    fn test_token_lifecycle() {
        let now = Utc::now();
        let token_id = Uuid::new_v4();
        let model_id = Uuid::new_v4();

        // New token
        let mut token = Token {
            id: token_id,
            serial_number: "YK-LIFECYCLE-001".to_string(),
            token_model_id: model_id,
            status: "available".to_string(),
            assigned_to: None,
            pin_attempts_remaining: 3,
            puk_attempts_remaining: 10,
            so_pin_attempts_remaining: 3,
            label: None,
            assigned_at: None,
            blocked_at: None,
            retired_at: None,
            initialized_at: None,
            expires_at: None,
            created_at: now,
            updated_at: now,
        };

        assert_eq!(token.status, "available");

        // Assign token
        token.status = "active".to_string();
        token.assigned_to = Some("user@example.com".to_string());
        token.assigned_at = Some(now);
        token.updated_at = now;

        assert_eq!(token.status, "active");
        assert!(token.assigned_to.is_some());

        // Block token (too many PIN attempts)
        token.status = "blocked".to_string();
        token.pin_attempts_remaining = 0;
        token.blocked_at = Some(now);
        token.updated_at = now;

        assert_eq!(token.status, "blocked");
        assert_eq!(token.pin_attempts_remaining, 0);

        // Retire token
        token.status = "retired".to_string();
        token.assigned_to = None;
        token.retired_at = Some(now);
        token.updated_at = now;

        assert_eq!(token.status, "retired");
        assert!(token.retired_at.is_some());
    }
}
